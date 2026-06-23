# Governance HTTP API & Trust Configuration

The production HTTP and trust layer over the governance primitives (signed
mandates, the ESCALATE approval loop). The HTTP layer is **thin transport**: it
validates schemas, resolves trust, and routes governed execution through the one
existing path. It contains no governance decision logic and creates **no second
execution path** — every governed execution still runs:

```
gateway → coordinator → authority verification → decision token → gate
        → audit-before-actuation → upstream execution
```

## Authentication & authorization boundary

| Boundary | Header | Used by | Endpoints |
|---|---|---|---|
| **agent** | `X-API-Key` | the proposing agent | verify, execute, create approval, execute approval, read status |
| **operator** | `X-Operator-Key` | a human operator | approve, deny, invalidate, revoke mandate, trust admin |

An empty operator key (`MCC_GATEWAY_OPERATOR_API_KEY` unset) disables **all**
operator actions (fail closed → 403). Operator and agent credentials are
distinct; an agent can never approve or revoke.

## Mandate endpoints

### `POST /mandates/verify` (agent)
```json
{ "mandate": { /* signed mandate */ }, "subject": "agent/x",
  "action": "scale_cluster", "resource": "cluster-prod-1", "policy_hash": null }
```
→ `{ "verified": true, "reason": "MANDATE_VERIFIED", "mandate_id": "mdt-…",
     "issuer_id": "axlogiq-mandates", "constraints": { "max_replicas": 10 } }`

Pure verification (trust resolution + `MandateVerifier`). No execution.

### `POST /mandates/execute` (agent)
```json
{ "mandate": { /* signed mandate */ }, "actor": "agent/x", "action": "scale_cluster",
  "resource": "cluster-prod-1", "context": { "target": "cluster-prod-1",
  "environment": "prod", "replicas": 5 }, "transaction_id": "txn-1",
  "idempotency_key": "op-1" }
```
→ `{ "status": "EXECUTED", "reason": "executed", "decision": "ALLOW",
     "audit_ref": "…", "execution": { /* upstream result */ } }`

Runs trust → `MandateAuthority` → decision token → `EnforcementCoordinator`
(gate + binding + nonce, revocation re-check, idempotency, velocity,
audit-before-actuation) → upstream. Any failure → `status: "BLOCKED"` (or
`"EXECUTION_FAILED"` if the executor raised after authorization) and the
upstream is never reached.

### `GET /mandates/{mandate_id}/revocation` (agent)
→ `{ "mandate_id": "mdt-…", "status": "ACTIVE" | "REVOKED" | "UNAVAILABLE" }`

### `POST /mandates/{mandate_id}/revoke` (operator)
→ `{ "ok": true }`

### Trust admin (operator)
* `GET /trust` → issuer/key summary (**no key material**).
* `POST /trust/issuers/{issuer_id}/disable` → `{ "ok": true }`
* `POST /trust/keys/{kid}/revoke` → `{ "ok": true }`

## ESCALATE approval endpoints

| Method | Endpoint | Boundary |
|---|---|---|
| `POST` | `/approvals` | agent — create a `PENDING` request |
| `GET` | `/approvals/{id}` | agent — status (non-sensitive) |
| `POST` | `/approvals/{id}/approve` | operator — mints the signed single-use mandate |
| `POST` | `/approvals/{id}/deny` | operator — terminal |
| `POST` | `/approvals/{id}/invalidate` | operator |
| `POST` | `/approvals/{id}/execute` | agent — consume single-use + execute |

Operator workflow:

1. The agent's proposal evaluates to `ESCALATE` → `POST /approvals` with the
   operation's `actor/action/resource/transaction_id/policy_hash/payload_hash`.
2. An operator reviews and `approve`s (returns a scoped, signed, single-use
   approval mandate) or `deny`s (terminal). **Approval does not execute.**
3. The agent calls `/approvals/{id}/execute` with the mandate; the coordinator
   consumes the approval single-use at actuation and executes.

States: `PENDING → APPROVED → CONSUMED`; `DENIED`/`EXPIRED`/`INVALIDATED`
terminal. Reuse, substitution, mutation, timeout, policy drift, and actor/
resource/action-hash mismatch all fail closed; concurrent execution has a single
winner (atomic consume).

## Multi-issuer trust set

`MCC_TRUST_CONFIG` points at a JSON file (see `config/trust.pilot.example.json`)
holding **only public keys**:

```json
{ "issuers": [ { "issuer_id": "axlogiq-mandates", "enabled": true,
  "keys": [ { "kid": "axlogiq-mandates-2026a",
              "public_key_b64": "<32-byte raw Ed25519, base64>",
              "not_after": null } ] } ] }
```

* **Issuer IDs and key IDs** — each `kid` is globally unique; `resolve(kid)`
  returns a distinct status (`OK` / `UNKNOWN_KID` / `DISABLED_ISSUER` /
  `EXPIRED_KEY` / `REVOKED_KEY`).
* **Multiple keys per issuer** — for rotation; all active keys verify.
* The gateway's own **approver** key is trusted by construction (issuer
  `mcc/approvals`), not via this file.

### Key-rotation procedure
1. Generate a new issuer key (`scripts/generate_signing_key.py`); keep the
   private key in the issuer's secret store.
2. Add a new `{kid, public_key_b64}` entry to the issuer's `keys` and reload.
3. Switch the issuer to sign new mandates with the new `kid`.
4. After all old mandates expire, set `not_after` on (or remove) the old key.

### Issuer-revocation procedure
* Disable an issuer: `POST /trust/issuers/{id}/disable` (runtime) or
  `enabled: false` in config (durable). All its mandates stop verifying.
* Revoke a single key: `POST /trust/keys/{kid}/revoke` (runtime) or
  `revoked: true` in config.

### Startup validation (fail-closed)
`MCC_ENV=pilot` **requires** a valid, non-empty `MCC_TRUST_CONFIG` and refuses
to start otherwise (`TrustConfigError`) — there is **no silent fallback to a
development key**. `dev`/`test` default to an empty trust set. Malformed config
(bad JSON, non-32-byte key, duplicate kid, empty keys) refuses startup in pilot.

## Deployment architecture

```
agent ──X-API-Key──► MCC gateway (HTTP) ──► GovernanceService
operator ─X-Operator-Key─►              │      trust set (public keys, config)
                                        │      MandateVerifier / MandateAuthority
                                        │      EnforcementCoordinator
                                        │        gate (Ed25519 + binding + nonce)
                                        │        revocation / idempotency / velocity / approvals (Redis)
                                        │        audit-before-actuation (hash chain)
                                        └────────► upstream (MCC_UPSTREAM_BASE)
```

Backends are env-selected and fail-closed with no silent fallback:
`MCC_NONCE_BACKEND`, `MCC_IDEMPOTENCY_BACKEND`, `MCC_VELOCITY_BACKEND`,
`MCC_REVOCATION_BACKEND`, `MCC_APPROVAL_BACKEND` (`memory` | `redis`, each needs
`MCC_REDIS_URL` for `redis`). See `RUNTIME_DEPLOYMENT.md`.

## Threat model additions

| Attack | Defense |
|---|---|
| forged mandate / approval | Ed25519 signature over all claims; untrusted kid → `UNKNOWN_KID` |
| mandate / approval substitution | `mandate_id` / `approval_id` bound into the token; consume binds action_hash/transaction/payload |
| actor / resource / action substitution | mandate subject & scopes; gate binding; payload_hash |
| transaction substitution | `transaction_id` in token + approval record |
| policy drift | mandate `policy_hash` binding → `POLICY_BINDING_MISMATCH` |
| replay / double-consume | nonce (token) + idempotency (operation) + single-use approval (atomic `SET NX`) |
| race conditions | atomic reservations; exactly-one consume winner |
| expired / revoked authority | validity window; revocation at decision **and** actuation |
| disabled issuer / unknown kid | trust resolution with distinct status |
| unavailable Redis / revocation / approval store | fail closed (DENY / BLOCKED), never silent fallback |
| malformed HTTP payload | strict (extra-forbid) schemas → 422 |
| bypassing coordinator/gate; direct upstream | no endpoint reaches the upstream except via `coordinator.enforce` |
| key/trust material exposure | only public keys held; summaries omit key material; private keys never returned or logged |

## Migration / backward compatibility

Purely additive. No existing endpoint, token field, or behavior changed; the
governance HTTP routes are new paths. The new env vars (`MCC_ENV`,
`MCC_TRUST_CONFIG`, `MCC_APPROVER_SIGNING_KEY_PATH`, `MCC_GATEWAY_OPERATOR_API_KEY`,
`MCC_UPSTREAM_BASE`, `MCC_REVOCATION_BACKEND`, `MCC_APPROVAL_BACKEND`) all default
to safe dev values; the only startup-affecting one is `MCC_ENV=pilot`, which
deliberately refuses an invalid trust root. See `docs/MIGRATION_NOTES.md`.
