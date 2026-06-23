# Migration & Backward-Compatibility Notes — Governance Layers

The three governance layers (signed mandates, ESCALATE approval loop,
infrastructure profile) are **additive**. Existing deployments keep working with
no changes. This note records what changed, what is opt-in, and the one
non-breaking token-shape change.

## Token shape

`DecisionEngine.issue_token` gained one new claim: **`mandate_id`** (optional,
defaults to `null`). This is the only change to the token envelope and it is
backward-compatible:

* Existing callers that do not pass `mandate_id` produce tokens with
  `mandate_id: null` — semantically identical to "no mandate bound".
* The execution gate does not require `mandate_id`; a token without it verifies
  exactly as before.
* The signature covers `mandate_id` like every other claim, so it cannot be
  added or altered after issuance.

> **Not a breaking change**, but noted explicitly: tokens minted after this
> change carry an extra `mandate_id` field. Any consumer that validates the
> token by re-checking the Ed25519 signature (the only supported method) is
> unaffected. Any consumer that hard-codes an exact claim allow-list should add
> `mandate_id` (and the previously-added `transaction_id`, `idempotency_key`,
> `actor_id`, `resource_id`, `auth_claims`).

No other token fields changed. `nonce`, `payload_hash`, `action_hash`,
`policy_hash`, `aud`, `nbf`, `exp`, `decision`, `constraints` are unchanged.

## Opt-in features (no-op unless configured)

| Capability | Enabled by | Default behavior |
|---|---|---|
| Signed mandates | presenting a mandate + a `MandateVerifier` with a trust set | unused; config `AuthorityModel` path unchanged |
| Actuation-time revocation re-check | `EnforcementCoordinator(revocation_registry=...)` | no-op unless set *and* token has `mandate_id` |
| ESCALATE approval consume | `EnforcementCoordinator(approvals=...)` | no-op unless set *and* token has `auth_claims.approval_id` |
| Infrastructure profile | `ProfileRegistry.default_pilot()` routing | generic profile for unmapped actions, as before |

## New backends (all fail-closed, no silent fallback)

Three new env-selectable backends join the existing nonce/idempotency/velocity
ones. Each defaults to `memory`; selecting `redis` requires `MCC_REDIS_URL` or
raises at startup (never a silent downgrade):

| Env | Backends |
|---|---|
| `MCC_REVOCATION_BACKEND` | `memory` \| `redis` |
| `MCC_APPROVAL_BACKEND` | `memory` \| `redis` |

(Existing: `MCC_NONCE_BACKEND`, `MCC_IDEMPOTENCY_BACKEND`,
`MCC_VELOCITY_BACKEND`.)

## Preserved invariants

Ed25519 verification, nonce replay protection, action/payload/policy-hash
binding, operation binding (actor/resource/transaction), audit-before-actuation,
the a–h execution order, fail-closed-by-default, the egress proxy behavior, and
all CI invariants (no HMAC, no fail-open, fsync, rego↔yaml thresholds) are
unchanged. The coordinator's a–h order gains two fail-closed pre-execution
checks (revocation re-check, approval consume) that run only when their
registries are configured.

## Migration steps (for an enforcement deployment adopting the new layers)

1. **Mandates** — stand up issuer keys; distribute issuer *public* keys to
   verifier trust sets; set `MCC_REVOCATION_BACKEND=redis` + `MCC_REDIS_URL`.
2. **Approvals** — set `MCC_APPROVAL_BACKEND=redis`; give the coordinator an
   `ApprovalService`; route `ESCALATE` to the approval queue.
3. **New domains** — add a profile to `ProfileRegistry`; no core change.

Each step is independent and reversible (unset the backend / drop the registry).
