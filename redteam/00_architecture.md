# MCC-Core enforcement path — red-team recon (Phase 1)

Target: `mcc-prior-art/mcc-layer` at `e600349` (main, merge of PR #128). Read-only: no source file
was changed. Internal adversarial testing by an AI model on the author's instruction — not an
independent audit.

## What was and was not exercised

| Layer | Exercised how |
|---|---|
| `src/mcc_core` (gate, engine, coordinator, mandate, approvals, velocity, idempotency, nonce, audit) | Real code, in-process, in-memory backends |
| `gateway/governance_service.py` (`execute_with_mandate / _approval / _delegation / _consensus`) | Real code, in-process |
| `gateway/governance_api.py`, `gateway/app.py`, `main.py` (FastAPI routes) | **Read only.** FastAPI, httpx and redis are not installed in this sandbox and package installs are disabled |
| `egress_proxy/` (governed HTTPS executor) | **Read only**, one predicate extracted and executed unchanged |
| Redis backends, Lua scripts | **Read only** |
| Docker network segmentation, OPA/Rego | **Not run** |

Consequence: every runtime result below is at the service boundary the HTTP routes call into.
The routes add request-shape validation (`extra="forbid"`) and a shared API key; they do not add
any authorization check that would change a result in `01_results.md` (each route body is a direct
call into the service method tested). That statement comes from reading the routes, not running them.

## Enforcement path

```
agent ──HTTP──> gateway/governance_api.py        X-API-Key (one shared key) -> tenant_id
                  │  actor, action, resource, context, mandate, idempotency_key  (all caller-supplied)
                  ▼
        GovernanceService.execute_with_mandate          gateway/governance_service.py:242
          1. TrustSet.resolve(mandate.kid)              gateway/trust.py:98      issuer key trust
          2. profile.canonical_payload(context)         mcc_core/profiles.py     type coercion
          3. MandateAuthority.authorize                 mcc_core/mandate.py:113
               MandateVerifier._verify  : sig, window, subject, action/resource scope, policy, revocation
               _constraint_violations   : max_/min_/allowed_ keys only   mcc_core/authority.py:160
               apply_constraints        : clamp -> CONSTRAIN
          4. PreExecutionControl (attestation)          optional
          5. DecisionEngine.issue_token                 mcc_core/core.py:54      Ed25519, payload_hash
          6. EnforcementCoordinator.enforce             mcc_core/coordinator.py:185
               ExecutionGate.verify   : kid, sig, aud, nbf/exp, verdict, policy_hash,
                                        action_hash, payload_hash, binding, evidence, nonce (last)
               idempotency_key + tenant_id mandatory
               consensus / challenge                     only if required by config
               revocation re-check                       if token.mandate_id
               approvals.consume                         ONLY if token.auth_claims.approval_id
               idempotency.reserve -> velocity.reserve -> audit(pre_actuation)
               time re-check -> idempotency.commit_dispatch
               executor()  ───────────────────────────────> upstream(action, forward_context)
               idempotency.mark_executed / mark_unknown -> audit(actuation_result)
```

`upstream` in the pilot is `_httpx_upstream` (`governance_api.py:358`): `POST {MCC_UPSTREAM_BASE}/{action}`
with the authorized payload as JSON. The alternative actuator is `egress_proxy.HTTPEgressExecutor`.

A second, separate surface is the decision service (`main.py` / `gateway/app.py` `/evaluate`): it
returns a signed token to the caller and runs no actuator itself.

## What is logged

Hash-chained JSONL (`AuditLog`, `fcntl.flock` + `fsync` per append). Records written by the
coordinator: `actuation_rejected`, `idempotency_block`, `velocity_block`, `consensus_verified`,
`challenge_consumed`, `pre_actuation` (mandatory — failure blocks), `actuation_result`,
`actuation_unknown`. Entries are linked by SHA-256, not signed. Records after dispatch are
best-effort (`_record` swallows errors).

Not logged: anything `GovernanceService` rejects **before** a token exists (bad signature, wrong
subject, out-of-scope action, constraint DENY, profile error). Those return a `BLOCKED` outcome
and leave no trace in the chain.

## Trust boundaries

| # | Boundary | What crosses it | Who is trusted |
|---|---|---|---|
| B1 | Agent → gateway | everything in the request body | nothing in the body; only the API key (maps to tenant, not to an agent) |
| B2 | Mandate issuer → gateway | signed mandate | issuer key in `TrustSet` |
| B3 | Human approver → gateway | operator key on `/approvals/{id}/approve` | operator key holder; gateway signs the approval mandate itself |
| B4 | Engine → gate | decision token | gateway signing key; same process in the pilot |
| B5 | Gate/coordinator → actuator | `executor()` closure | whoever built the closure; the actuator receives no token (`_httpx_upstream`) or an unverified one (`HTTPEgressExecutor`) |
| B6 | Gateway → state stores | nonce, idempotency, velocity, approval, revocation | Redis (or process memory) |
| B7 | Gateway → audit file | append-only by convention | filesystem permissions |
| B8 | Agent network → actuator network | nothing | Docker networks `agent_edge` / `gov_internal` |

## Assumptions the system makes

1. **The caller's `actor` string is true.** Subject binding compares `mandate.subject` to a value
   the caller typed. There is no per-agent credential and no proof of possession.
2. **A mandate that verifies is a standing authority.** Nothing in the mandate path distinguishes
   an approval-minted, payload-bound, `single_use` mandate from an ordinary one; that distinction
   lives only in which route the caller picks.
3. **Constraint keys are spelled `max_<f>`, `min_<f>` or `allowed_<f>`.** Anything else is skipped
   without error.
4. **Numbers are finite and non-negative.** `max_` is checked as `value > bound`; NaN and negatives
   satisfy it. Only the velocity layer validates finiteness, and only where an amount limit exists.
5. **Cumulative limits exist where they matter.** A mandate bounds one transaction; totals are
   bounded only by `PILOT_VELOCITY`, which covers `send_payment` alone.
6. **The action name is an identifier.** It is matched with `fnmatch` and then placed into the
   upstream URL path unescaped.
7. **The actuator can only be reached through the coordinator.** True for the gateway code path;
   enforced on the network by compose, not by the actuator (it authenticates nothing).
8. **Idempotency keys are chosen honestly.** Exactly-once holds per caller-chosen key.
9. **Volatile state is acceptable outside `MCC_DEPLOYMENT_MODE=enforcement`.** Memory backends
   are the default for nonce, idempotency, velocity, approvals and revocation.
10. **The audit file is not writable by an adversary.** `verify_chain` proves internal consistency
    only; truncation and full rewrite need the external checkpoint anchoring in `mcc_checkpoint`.
11. **Agent-supplied approval parameters are benign.** `ttl_seconds`, `policy_hash` and
    `constraints` on `POST /approvals` come from the requesting agent.
12. **Gate nonce TTL cap ≥ token lifetime.** Documented in a comment, not checked.
13. **Token-signing key and policy file are provisioned correctly.** An unset key path yields an
    ephemeral key with a warning; the policy bundle is hashed at load but not compared to a pin.
14. **No hostile code runs inside the gateway process.** Signing keys, the executor object and
    payload dicts are plain Python objects there.

## Read-only observations (not runtime-verified here)

- `main.py:697` — the `/evaluate` idempotency cache is keyed on `tenant:idempotency_key` only. A
  second request with the same key and different `intent`/`args` gets the first response back,
  `decision: ALLOW` and token included. The token still carries the first payload's hash, so a gate
  that checks `payload_hash` rejects it; a client that acts on the `decision` field alone does not.
- `main.py:343` — `LocalFallbackPolicy` allows `send_payment` when `float(amount) <= 5000`;
  negative amounts and a missing amount (defaults to 0) are allowed.
- `main.py:89` — `api_key` defaults to `demo-key`; comparisons use `!=`, not a constant-time check.
- `egress_proxy/executor.py:464` — see V11 in the results.
- `governance_api.py:311` — `/approvals/{request_id}/execute` never uses its `request_id` path
  parameter; the approval is identified by the mandate in the body.

## Findings by root cause

Details and evidence per case are in `01_results.md`. Four root causes account for all 22
`bypass` cases:

| ID | Root cause | Severity | Cases |
|---|---|---|---|
| R1 | Approval-minted mandate is accepted on `/mandates/execute`, where `approval_id` never reaches the token, so payload binding, single-use and invalidation are all skipped | critical | V05 ×1, V16 ×3 |
| R2 | `max_`/`min_` comparison lets NaN, −inf and negative values through | high | V02 ×8 |
| R3 | Unknown constraint keys are ignored instead of denying | high | V08 ×6 |
| R4 | Action name reaches the upstream URL unvalidated when the mandate scope is a wildcard | medium | V02 ×4 |
| — | (R2 for `send_payment` is caught by the pilot velocity limits; it is open for every action without an amount limit, e.g. `discount_offer`, `priority_mark`, `send_notification`) | | |

No bypass was found in: signature verification, token binding, canonical hashing, nonce handling
on one instance, concurrency, dependency failure handling, prompt-injection surfaces, or
policy-hash binding.
