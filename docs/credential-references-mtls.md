# Governed Credential References and Optional mTLS

> Extends the **existing** governed HTTPS egress path (PR #26) with secure
> credential-reference resolution and optional mutual TLS. No parallel executor,
> no duplicated governance — the same gateway / coordinator / gate / consensus /
> approval / mandate / nonce / idempotency / velocity / audit path decides, and
> the same `HTTPEgressExecutor` performs the call.

## Problem

An agent must be able to call an authenticated upstream (a bearer token, an API
key, or mutual TLS) without ever holding or proposing the raw secret. Secrets
must be resolved **only inside the trusted execution boundary, only after
governance authorization succeeds**, and must never appear in proposals, tokens,
logs, audits, exceptions, or API responses.

## Credential-reference model

The agent proposes a **reference identifier**, never raw secret material:

- `credential_ref` — a secret HTTP header (e.g. `Authorization: Bearer …`, an API key);
- `client_identity_ref` — a client certificate + private key (mTLS);
- `ca_bundle_ref` — a CA bundle to trust for the destination.

References are part of the **governed canonical action** (bound by the payload
hash; evaluated by authority / consensus / approval), so the reference a request
will use is governed and audited like every other field. A proposal carrying a
secret-bearing header (`authorization`, `cookie`, `x-api-key`, …) is **rejected**
— secrets come only from references resolved inside the executor.

## Credential provider interface

`egress_proxy/credentials.py` defines `CredentialProvider.resolve(ref, *, scope,
expected_type)`. An implementation must verify the reference exists, authorize
the **scope**, verify the **type**, return typed material, and fail closed
(raise `CredentialError`, never with a secret in the message). Resolved material
(`SecretHeaderCredential` / `ClientIdentityCredential` / `CABundleCredential`)
has a `repr`/`str` that never reveals the value.

Two safe implementations ship; neither adds a production secret-manager
dependency:

- **`InMemoryCredentialProvider`** — deterministic, for tests.
- **`EnvCredentialProvider`** — local/pilot: scope and types come from a
  committed, **secret-free** JSON config; raw values come from environment
  variables named by that config. **Not for production.**

Future adapters (Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key
Vault, Kubernetes Secrets) implement the same `resolve` interface — the executor
does not change.

## Scope binding

A reference is bound to an explicit scope (`CredentialBinding`); resolution fails
closed unless **every** dimension matches the final action (empty allow-lists
deny by default):

- allowed hostname / pattern (`*.stripe.com`), port, HTTP method, action,
  environment, optional path prefix, optional actor/tenant.

`ALLOW` from governance is **not** permission to use any credential — the
reference must be explicitly authorized for *this* destination and operation.
Fail-closed cases: unknown reference; host/port/method/action/environment/path
out of scope; type mismatch; redirect target out of scope.

## Trusted execution boundary & secret-resolution order

Secrets are resolved only inside `HTTPEgressExecutor` (reached only via
`coordinator.enforce`, i.e. after governance + durable audit). The order:

```
Agent proposal with credential_ref (no raw secret)
  ↓ governance evaluation (authority / consensus / approval / mandate)
  ↓ ALLOW / DENY / ESCALATE / CONSTRAIN
  ↓ final canonical action hash verified at the gate
  ↓ durable pre-execution audit (coordinator)
  ↓ credential scope authorization against the final action  ─┐
  ↓ credential resolution inside the trusted executor          │ inside the
  ↓ optional mTLS context construction                         │ executor
  ↓ pinned-IP, peer-verified HTTPS execution (PR #26)          ┘
  ↓ redacted post-execution audit
```

Invariants:

> No verified decision — no execution.
> No authorized credential reference — no secret resolution.
> No durable audit — no actuation.
> No approved destination — no credential forwarding.

## HTTP auth injection

A resolved `secret_header` credential is injected **inside the executor**, per
hop, after authorization. The agent cannot supply or override it (a secret-bearing
header in a proposal is rejected). The injected header always wins over any
same-named header.

## Optional mTLS

A `client_identity_ref` (cert + key) enables mTLS; an optional `ca_bundle_ref`
sets the server trust roots. The client cert/key are loaded into the SSL context
via a **0600 temp file removed immediately after load** (on success and failure);
the CA bundle is loaded in-memory (`cadata`). mTLS **preserves every PR #26
protection**: hostname + chain verification, correct SNI (against the original
hostname), pinned-IP connection + peer-IP validation, SSRF, and redirect safety.
Fail-closed: missing cert/key, cert/key mismatch, invalid/expired material, or an
invalid CA bundle — all before any network I/O (surfaced as a credential denial,
never as ALLOW).

## Redirect credential behavior

Building on PR #26's safe redirects: a header credential is forwarded **only
same-origin** as the original request; a **cross-origin redirect strips it**. Every
redirect destination **re-validates** credential scope; an unauthorized target
receives no credential, and a reference is **never automatically reused** across
origins.

## Redaction guarantees

Never logged/audited/returned/in-exceptions: Authorization values, API keys,
passwords, cookies, private keys, client key material, raw certificate private
material, environment secret values, secret-bearing query params/bodies. Audit
records only **safe metadata**: `credential_ref`, `credential_type`,
`credential_resolved`, `mtls_requested`, `client_identity_loaded`, `ca_bundle_ref`,
a safe `client_cert_fingerprint` (sha256), and `credential_policy_result`.

## Configuration

| Setting (`MCC_EGRESS_*`) | Meaning |
|---|---|
| `CREDENTIAL_PROVIDER` | `none` (default) \| `env` \| `memory` |
| `CREDENTIAL_CONFIG` | path to a **secret-free** JSON config (refs → type/scope/env-var names) |
| *(env vars named by the config)* | the raw secret values (in a git-ignored `.env`, never the config) |

A selected provider with a missing/invalid config **refuses startup** (fail-closed,
no silent fallback). See `deploy/pilot/credentials.example.json` (placeholders
only). Never commit real API keys, tokens, private keys, certificates, `.env`, or
generated client identities.

## Local deterministic testing

`tests/test_egress_credentials.py` (scope binding, resolution, injection,
redaction, redirect stripping), `tests/examples/test_egress_credentials_governed.py`
(resolution only after authorization + durable audit; secret never in
response/audit), and `tests/test_egress_mtls.py` (valid mTLS; missing/mismatched
cert+key; invalid CA; server-trust/SSRF still enforced; temp cleanup) use a local
CA + cert minter and a stdlib mTLS server — **no public internet**.

## Known limitations

- The shipped providers are local/test only (in-memory, env-backed). Production
  uses an external secret-manager adapter of the same interface.
- mTLS client material is loaded via a short-lived 0600 temp file (Python's `ssl`
  has no in-memory client-cert load); it is removed immediately after load.
- The single-internal-CA model is used in tests; the executor supports a separate
  server CA via `ca_bundle_ref`.

## Future secret-manager integration points

Implement `CredentialProvider.resolve` for Vault / AWS Secrets Manager / GCP
Secret Manager / Azure Key Vault / Kubernetes Secrets and select it via
`MCC_EGRESS_CREDENTIAL_PROVIDER`. Nothing else in the executor or the governance
path changes — scope binding, resolution order, injection, mTLS, and redaction
are provider-independent.
