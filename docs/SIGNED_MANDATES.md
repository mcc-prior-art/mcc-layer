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
| `constraints` | opaque bounds (e.g. `{"max_amount": 5000}`) |
| `nbf` / `exp` | validity window |
| `iat` | issuance timestamp |
| `revocation_required` | whether a live revocation check is mandatory |
| `policy_hash` | optional trust-set / policy-version binding |
| `kid` / `sig` | Ed25519 signature metadata |

The object is **domain-neutral**: only generic scopes and an opaque constraints
map. It carries no payment/robotics/infra vocabulary.

## Trust model

* The verifier holds a **trust set** of issuer public keys keyed by `kid`. A
  mandate signed by a `kid` outside the trust set is `UNTRUSTED_ISSUER`.
* Removing an issuer's `kid` from the trust set revokes *every* mandate it
  issued (a coarse, key-level revocation), independent of the revocation list.
* `policy_hash` optionally pins a mandate to a policy version, so a mandate
  cannot be carried across a policy change it was not issued under.

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

Mandate support is additive. `mandate_id` is a new optional, nullable token
claim; existing tokens (and the config-driven `AuthorityModel`) are unaffected.
The coordinator's revocation re-check is a no-op unless a revocation registry is
configured and a token carries a `mandate_id`.
