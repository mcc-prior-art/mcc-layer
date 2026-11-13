# Signed, Revocable Mandates

A **mandate** is a cryptographically verifiable authority object — distinct from
identity and distinct from the execution decision token. It answers *"may this
subject take this action on this resource, within these bounds, for this
window?"* and is the input from which the decision engine derives authority.

> Identity says who you are. A mandate says what you were granted. The decision
> token says what was authorized *now*. Three different artifacts.

## Object

A mandate is an Ed25519-signed claims object (`mcc_core.issue_mandate`):

| Field | Meaning |
|---|---|
| `mandate_id` | unique id; bound into the decision token and the revocation list |
| `issuer` | granting authority (the signing key's `kid` is the trust anchor) |
| `subject` | the delegate the mandate is issued to |
| `action_scope` | glob patterns of permitted actions |
| `resource_scope` | glob patterns of permitted resources |
| `constraints` | bounds in the supported constraint contract (e.g. `{"max_amount": 5000}`; see below) |
| `nbf` / `exp` | validity window |
| `iat` | issuance timestamp |
| `revocation_required` | whether a live revocation check is mandatory |
| `policy_hash` | optional trust-set / policy-version binding |
| `tenant_id` | the tenant / security domain the mandate is valid in. **Required in strict tenant mode (the default; V05).** See *Tenant binding* below |
| `kid` / `sig` | Ed25519 signature metadata |

The object is **domain-neutral**: only generic scopes and an opaque constraints
map. It carries no payment/robotics/infra vocabulary.

### Constraint contract (R3)

The constraints map is domain-neutral, but it is **not** free-form. Exactly
three operators exist. They are exact and lowercase, and the same
`mcc_core.authority` code evaluates them on every route:

| Key | Bound | Meaning |
|---|---|---|
| `max_<field>` | finite number | `context[field] <= bound` (CONSTRAIN clamps to it) |
| `min_<field>` | finite number | `context[field] >= bound` (CONSTRAIN raises to it) |
| `allowed_<field>` | list of JSON scalars | `context[field] in bound` (no rewrite; outside → DENY) |

`<field>` is a dotted path of `[A-Za-z0-9_-]` segments, matched literally
against the (flat, canonical) context key, for example `amount` or the egress
proxy's `body.amount`. Profiles extend the contract with **new fields**, never
with new operators.

Every other key is an **invalid constraint set** and is rejected, never
skipped, corrected or partially evaluated. That includes:

- misspelled, suffix-form or wrong-case operators (`max-amount`, `amount_max`,
  `MAX_amount`, `maxAmount`);
- unsupported operators (`denied_<field>`) and bare fields (`currency`);
- malformed paths;
- wrong-typed bounds, including a string `allowed_` bound;
- a number outside the IEEE-754 double range, such as the JSON integer
  literal `10**400`, as a `max_`/`min_` bound or an `allowed_` value. It is
  unsupported rather than finite: `math.isfinite()` raises `OverflowError` on
  such an int, which used to escape as an HTTP 500 on `POST /approvals`.
  Huge but representable values, such as `10**300`, stay valid bounds;
- an unsatisfiable `min_` > `max_`;
- a non-object `constraints` claim.

Before R3, such keys were silently skipped, so the intended restriction did not
exist. `MandateVerifier` now rejects them as `MALFORMED_MANDATE_CONSTRAINTS`,
which also covers mandates signed before the fix or by an issuer that never
validated. `issue_mandate()` still signs whatever it is given: it is the
low-level primitive any issuer uses. Issuers can pre-check with
`mcc_core.authority.validate_constraints()`.

## Trust model

* The verifier holds a **trust set** of issuer public keys keyed by `kid`. A
  mandate signed by a `kid` outside the trust set is `UNTRUSTED_ISSUER`.
* Removing an issuer's `kid` from the trust set revokes *every* mandate it
  issued (a coarse, key-level revocation), independent of the revocation list.
* `policy_hash` optionally pins a mandate to a policy version, so a mandate
  cannot be carried across a policy change it was not issued under.

## Tenant binding (V05 remediation)

A gateway authenticates a **tenant**: one agent API key per mount, mapped to
a server-side `tenant_id` that is never a request field. A signed mandate
must therefore say which tenant it is valid in.

**Strict mode** (`MCC_MANDATE_TENANT_MODE` unset or `strict`; the default for
`build_governance_service` and for `GovernanceService`):
- **Required claim:** after the signature is verified, the signed `tenant_id`
  must be a non-empty string without surrounding whitespace, exactly equal to
  the executing gateway's tenant.
- **Refusal codes:**
  - `MANDATE_TENANT_MISSING` when the claim is absent;
  - `MANDATE_TENANT_MALFORMED` when it is empty, padded, `null` or not a
    string;
  - `MANDATE_TENANT_MISMATCH` when it names another tenant.

  Each refusal is `BLOCKED`/`DENY` before any decision token, idempotency
  reservation, audit `pre_actuation` record or actuator call.
- **Tampering:** changing, adding or removing the claim breaks the signature
  (`INVALID_MANDATE_SIGNATURE`).
- **Approval-minted mandates** carry the tenant the approval was requested
  under. `ApprovalService.consume()` also refuses another tenant's approval
  (`TENANT_MISMATCH`) without consuming it. Before this, gateways sharing an
  approval store and approver key could execute, and so burn, each other's
  human approvals.
- **Routes:** both mandate-consuming routes, `POST /mandates/execute` and
  `POST /approvals/{id}/execute`. Delegations already required a signed
  `tenant_id`.

**Legacy mode** (`MCC_MANDATE_TENANT_MODE=legacy-unscoped`) is server-side
configuration only:
- **No tenant isolation:** a mandate **without** a `tenant_id` is accepted in
  any tenant. It exists only to keep pre-V05 mandates working during
  migration.
- **Present claims still checked:** a mandate that carries the claim is
  enforced exactly as in strict mode.
- **Startup:** any other value refuses startup.

**Issuers:** pass `tenant_id=` to `issue_mandate()`.

**What tenant binding alone does NOT provide:**
- **No per-agent identity.** Within one tenant, any holder of the tenant's
  shared agent API key could present a copied mandate by naming its `subject`
  as `actor`.
- **The mandate is still a bearer credential inside its tenant.**

**V05 part 2 (per-agent identity, `docs/AGENT_IDENTITY.md`)** closes the first
point on the HTTP mandate and approval routes: the caller's own registered
credential resolves server-side to a principal, which must equal both `actor`
and the signed `subject`; the shared tenant key cannot act as an agent there.
The mandate remains usable by **its own subject's** credential: there is still
no proof-of-possession contract, so theft of that agent's credential is not
prevented.

## Verification order (fail-closed)

`MandateVerifier.verify` runs, and denies on the first failure:

1. **signature & trusted issuer** — `INVALID_MANDATE_SIGNATURE` / `UNTRUSTED_ISSUER`
2. **structural completeness** — `MALFORMED_MANDATE`
3. **validity window** — `MANDATE_NOT_YET_VALID` / `MANDATE_EXPIRED`
4. **subject** — `SUBJECT_MISMATCH` (prevents subject substitution)
5. **action scope** — `ACTION_SCOPE_MISMATCH` (prevents scope widening)
6. **resource scope** — `RESOURCE_SCOPE_MISMATCH` (prevents resource substitution)
7. **policy binding** — `POLICY_BINDING_MISMATCH`
8. **revocation** — `MANDATE_REVOKED` / `REVOCATION_UNAVAILABLE` / `REVOCATION_REQUIRED`

Any exception anywhere resolves to deny (`MANDATE_ERROR: fail-closed`).

The execution routes then apply the **tenant binding** above, after the
mandate authorizes and before any token exists.

## Binding the authority to the decision token

When a token is issued under a verified mandate, the mandate's `mandate_id` is
written into the decision token (`issue_token(..., mandate_id=...)`) and the
mandate's `constraints` flow into the verdict (`MandateAuthority`: within bounds
→ ALLOW; clampable breach → CONSTRAIN with a rewritten body; otherwise DENY).
The token therefore records *which* authority justified it.

**Substitution resistance.** The mandate is signed (cannot be edited); the
subject/action/resource are checked against the operation; the token binds the
`mandate_id`, the exact `action_hash`, the `payload_hash`, and (via the gate's
binding check) actor/resource/transaction. Swapping the mandate, the subject,
the resource, or widening the scope all fail closed.

## Revocation lifecycle

```
issue ──► ACTIVE ──(revoke)──► REVOKED   (terminal for that mandate_id)
```

* `RevocationRegistry.check(mandate_id)` returns `ACTIVE`, `REVOKED`, or
  `UNAVAILABLE`. `UNAVAILABLE` (Redis down/timeout) is treated as a denial for
  any `revocation_required` mandate — **never** "assume active".
* `InMemoryRevocationRegistry` for dev/tests; `RedisRevocationRegistry`
  (a Redis set) for durable, multi-instance deployments.
* **Actuation-time re-check.** The `EnforcementCoordinator`, when given a
  revocation registry, re-checks a token's `mandate_id` immediately before
  execution, so a mandate revoked *after* the token was issued still blocks.

## Operational deployment

| Env | Default | Notes |
|---|---|---|
| `MCC_REVOCATION_BACKEND` | `memory` | `memory` or `redis` |
| `MCC_REDIS_URL` | *(unset)* | required when backend is `redis` |

Selecting `redis` without `MCC_REDIS_URL` raises `RevocationConfigError` at
startup — no silent fallback to in-memory revocation. A revocation-required
mandate with an unreachable revocation service is denied at request time.

Issuer key management mirrors the signing-key guidance in
`RUNTIME_DEPLOYMENT.md`: distribute issuer **public** keys to verifier trust
sets; rotate by adding a new issuer `kid` and retiring the old one (retiring a
`kid` revokes its mandates wholesale).

## Backward compatibility

**V05 (breaking for claimless mandates):** under the default strict tenant
mode, a mandate issued without `tenant_id` no longer executes. Either re-issue
it with `tenant_id=<the gateway's MCC_GATEWAY_TENANT_ID>`, or set
`MCC_MANDATE_TENANT_MODE=legacy-unscoped` explicitly for the migration. That
setting provides no tenant isolation for claimless mandates.

Mandate support is additive. `mandate_id` is a new optional, nullable token
claim; existing tokens (and the config-driven `AuthorityModel`) are unaffected.
The coordinator's revocation re-check is a no-op unless a revocation registry is
configured and a token carries a `mandate_id`.
