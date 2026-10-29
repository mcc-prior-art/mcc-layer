# PR #122 — Post-Merge Addendum

**Document type:** Post-merge status addendum (NOT a new security review)
**Addendum date:** 29 October 2026
**Addends to:**
- [`MCC_CORE_STRATEGIC_ROADMAP_v1.2.md`](./MCC_CORE_STRATEGIC_ROADMAP_v1.2.md) (approved 28 October 2026)
- [`MCC_CORE_THREAT_MODEL_v1.0.md`](./MCC_CORE_THREAT_MODEL_v1.0.md) (proposed 28 October 2026)

**Scope of this document:** this addendum updates the factual status of PR #122 from "draft/unmerged at checked HEAD `bfc6ec1`" (as stated throughout the two documents above) to its actual, final, merged state. It does **not** modify, renumber, re-date, or retract anything in either source document — both remain published exactly as approved, as a historical record of the state of the work and the open questions at the time they were written. This addendum does not conduct, authorize, or substitute for independent third-party review; it reports already-established facts from PR #122's own commit history, test suite, and CI results.

**No runtime changes.** This addendum, and the branch/PR that carries it, touch only files under `docs/`. **No new security review round was performed for PR #122 to produce this document** — PR #122 is closed and merged; everything below is a documentation record of work that already happened, was already tested, and was already reviewed in the six rounds that preceded the merge.

---

## 1. Actual final status of PR #122

| | Roadmap v1.2 / Threat Model v1.0 statement (28 Oct 2026, HEAD `bfc6ec1`) | Actual final status (this addendum, 29 Oct 2026) |
| --- | --- | --- |
| PR state | "remains open/Draft/not merged" | **Merged.** Merge commit [`fdd7fe0`](https://github.com/mcc-prior-art/mcc-layer/commit/fdd7fe0d4457f60a2816ca76ee08b2bc5f6de4b0) into `main`, merged by the repository owner (`mcc-prior-art`) on 29 October 2026. |
| Final reviewed head | `bfc6ec1` | `ee896c1` (three more hardening commits landed after `bfc6ec1`: `5b2f134`, `108677b`, `ee896c1` — see §2). |
| CI | "10/10 GitHub Actions workflows successful" (at `bfc6ec1`) | All 76 check runs green at the final head `ee896c1`, including both long-running `tests` jobs, `independent-assurance-core`, and all 6 real Docker Compose E2E deployments (`docker-e2e`, `pilot-e2e`, `clinic-pilot-e2e`, `notify-pilot-e2e`, `reference-agent-e2e`, `pilot-reference-integration`). |
| "Clock-trust coverage of consensus, attestation, challenge and final-actuation paths requires explicit closure evidence before owner-approved merge" | Open requirement | **Closed** — see §3. Owner reviewed and merged at `ee896c1`. |

This table is the entirety of the status update. Everything else in the two source documents — the threat register, the trust boundaries, the acceptance-gate table, the non-goals, the residual-risk disclosures — stands as originally written and is **not** superseded by this addendum except where explicitly stated below.

## 2. What changed between the reviewed HEAD (`bfc6ec1`) and the final merged HEAD (`ee896c1`)

The roadmap's P0 gate required: *"Complete TrustedTime integration across approvals, mandates, decision tokens, Gate, consensus, attestation, challenge and final actuation. Prove fault handling, replay/expiry/race safety."* At `bfc6ec1`, the threat model itself stated this was not yet true: *"time paths for consensus, challenge and attestation still require complete trust-boundary review, as do final actuation entry points."* Three further commits closed exactly that gap:

| Commit | What it closed |
| --- | --- |
| `5b2f134` | Extended the `TrustedTime` boundary (introduced at `bfc6ec1` for `ApprovalService`/`MandateVerifier`/`ExecutionGate`) to `ConsensusVerifier.verify()`, `ChallengeService.issue()/get()/consume()`, and `PreExecutionControl.evaluate()` (attestation). Reproduced the pre-fix gap first (a lagging-clock gateway instance accepting an already-expired consensus vote set / challenge), then confirmed it closed. |
| `108677b` | Added an opt-in `max_dispatch_staleness_seconds` bound on `EnforcementCoordinator.enforce()`, checked once between audit-before-actuation and the durable dispatch commit, to catch excessive real-time elapsed between authorization and actual dispatch. Also fixed `RedisTimeSource.now()`'s own round-trip/freshness measurement, which had used wall-clock `time.time()` (vulnerable to NTP-step jumps mid-call) instead of `time.monotonic()`. Also replaced a vacuous unit test of `PreExecutionControl`'s clock-trust fail-closed path with a non-vacuous one that actually exercises it. |
| `ee896c1` | Closed two further gaps found by continued adversarial review: (a) the staleness bound from `108677b` only checked the *elapsed gap* against a fixed threshold — it never re-checked the token's own, possibly much shorter, signed `exp`/`nbf`, so a short-TTL token could still reach the actuator after it had genuinely expired, provided the gap stayed under the configured bound. Fixed by making a token-exp/nbf recheck against a fresh `dispatch_now` sample unconditional (never gated behind the staleness-bound feature). (b) A newly issued decision token's `exp` was not clamped to the remaining validity of the mandate or approval that authorized it, so a mandate with (say) 10 seconds left could still justify a token valid for the server's full default TTL. Fixed by clamping the issued token's `exp` to the verified mandate's own `exp` (never the other direction). Also rejected non-finite (`NaN`/`Infinity`) values for the dispatch-staleness configuration, which had silently disabled that check while still looking "configured." |

Each of these three commits reproduced its own finding before fixing it, added regression tests proven to fail against the pre-fix code and pass after (via `git stash` comparison), and was validated against the full local test suite, `make verify-assurance` (independent-assurance workstreams, TLA+ model checking, mutation testing), and the complete GitHub Actions matrix before being pushed. This is the same evidence discipline the original roadmap required in its P0 acceptance gate; none of it is new in kind, only in having actually been completed.

## 3. Updated Trusted Time Assurance status (addends §"P0 trusted time assurance specification" in the Roadmap and §3 of the Threat Model)

The Roadmap's required-architecture item 1 was: *"Enumerate every protected time decision across approval, attestation, consensus, challenge, mandate, token issuance, Gate, and final actuator entry."* At the final merged head:

| Protected time decision | Trusted-time coverage at `ee896c1` |
| --- | --- |
| Approval (request/approve/deny/invalidate/consume) | Closed at `bfc6ec1` |
| Mandate verification | Closed at `bfc6ec1` |
| Decision token issuance (`nbf`/`exp`) | Closed at `bfc6ec1`; **additionally**, at `ee896c1`, the issued token's `exp` is now clamped to never exceed its source mandate/approval's own `exp` |
| Execution Gate (`ExecutionGate.verify()`) | Closed at `bfc6ec1` |
| Consensus (`ConsensusVerifier.verify()`) | Closed at `5b2f134` |
| Challenge (`ChallengeService`) | Closed at `5b2f134` |
| Attestation (`PreExecutionControl.evaluate()`) | Closed at `5b2f134`; residual note carried forward below |
| Final actuator entry (the real-time gap between authorization and the durable dispatch commit) | Closed at `108677b` (elapsed-gap bound) and `ee896c1` (unconditional token-exp recheck at the dispatch point itself) |

Every item the Roadmap's P0 gate listed by name is now covered by code and by a regression test that was confirmed to fail pre-fix and pass post-fix. This closes the specific, named requirement. It does **not** change anything else the Roadmap or Threat Model said about trusted time, and in particular does **not** change these carried-forward facts, stated identically in both source documents and still true today:

- `RedisTimeSource` remains a **shared clock plus drift detector**, not an independently authenticated UTC source. Two clocks agreeing cannot rule out a common-mode compromise of both.
- No authenticated NTP (NTS, RFC 8915), PTP, HSM-backed time, or Google TrueTime-equivalent service is implemented. These remain future deployment-design items, exactly as the Roadmap's "Non-goals" section states.
- `LocalTimeSource` deployments (the default; `MCC_TIME_TRUST_BACKEND` unset) still depend on operationally NTP-disciplined gateway clocks — a deployment assumption, not a code guarantee.

**One residual finding surfaced during this work, documented but not a vulnerability:** `PreExecutionControl.evaluate()`'s own internal clock-resolution branch (reached only when a caller passes no explicit `now`) is, in the actual production call graph, never reached — its one caller (`GovernanceService._attestation_gate()`) always pre-resolves and forwards an explicit `now`. The same fail-closed outcome is enforced one step earlier, at `GovernanceService._now()`, so this is not a gap in practice, but it is dead code worth tightening if this boundary is ever extended with a caller that omits `now`.

## 4. Updated Failure Modes / Recovery Matrix (addends the Roadmap's "P0 failure modes and recovery matrix" and the Threat Model's §4)

The original matrix's row *"After Gate but before dispatch ownership: ... BLOCKED, fail closed"* now has two additional, specifically named, tested mechanisms that did not exist at `bfc6ec1`:

| New reason code (introduced `108677b`/`ee896c1`) | Fires when | Classification |
| --- | --- | --- |
| `AUTHORIZATION_STALE` | The real-time gap between authorization (`trusted_now`) and dispatch (`dispatch_now`) exceeds the configured `max_dispatch_staleness_seconds` bound (default 30s; opt-in; disabled by default behavior preserved for callers that configure `None`). | `BLOCKED`, fail-closed, reservations released, safe to retry with fresh authorization. |
| `TOKEN_EXPIRED_BEFORE_DISPATCH` / `TOKEN_NOT_YET_VALID_AT_DISPATCH` | The token's own signed `exp`/`nbf` claim, rechecked against a fresh `dispatch_now` sample immediately before the durable dispatch commit, no longer holds — independent of whether the elapsed-gap bound above was configured or tripped. | `BLOCKED`, fail-closed, reservations released, safe to retry with a freshly issued token (never a second consumption of the original token's nonce). |

Both mechanisms strictly precede the durable dispatch-ownership commit (the matrix's documented point of no return), so the existing row's classification (`BLOCKED`, not `UNKNOWN`, zero actuator invocations) applies unchanged — these are concrete instances of that row, not a new row or a new classification. The matrix's other rows (post-dispatch `UNKNOWN`/`DISPATCH_OWNED`, confirmed `EXECUTED`, network-partition handling) are unaffected and still accurately describe the merged code.

**One new operational note, not in the original matrix:** because the token-exp recheck in `ee896c1` is unconditional (it always resolves a second `time_source.now()` sample when the coordinator is using its own trusted-time resolution), every production `enforce()` call now depends on two successful trusted-time-source reads instead of one. This is a deliberate trade-off — it fails closed exactly like every other time-source failure in the matrix — but it is worth recording as a residual operational consideration for capacity planning around the chosen time source's availability.

## 5. Threat-to-control-to-test traceability (requested addition; extends the Threat Model's §5 PR-mapping table with concrete code and test references)

The Threat Model's §5 maps threat IDs to *PRs*. The table below maps each ID one level deeper, to the actual control code path and the actual test file(s) that exercise it, as merged at `ee896c1`. Status values follow the Threat Model's own proposed vocabulary (§5): `CLOSED (evidence-linked)`, `PARTIAL`, `OPEN`, `ACCEPTED RISK`, `PLANNED`.

| ID | Primary control (code) | Test evidence (file) | Status at `ee896c1` |
| --- | --- | --- | --- |
| T-01 | — (owner→agent signed delegation not yet implemented) | — | `PLANNED` (#123) |
| T-02 | `src/mcc_core/mandate.py` (`MandateVerifier`), `src/mcc_core/authority.py`, `gateway/governance_api.py` (`AuthorityPolicy` wiring) | `tests/test_mandate.py`, `tests/test_authority.py`, `tests/test_independent_authority_decision_adversarial.py`, `tests/test_pilot_compose_authority_policy_wiring.py` | `PARTIAL` — key/credential/operator-separation controls are evidence-linked; mutual-TLS/workload-identity at the transport layer is deployment-dependent and not verified by this repository's own tests |
| T-03 | `src/mcc_core/coordinator.py` (exact action/resource/payload_hash binding), `src/mcc_core/gate.py` | `tests/test_post_pr121_operation_binding_matrix.py`, `tests/test_transaction_binding.py`, `tests/test_egress_canonical.py` | `CLOSED (evidence-linked)` for the reviewed proposer→Gate→actuator path |
| T-04 | `src/mcc_core/trusted_time.py` (`TrustedTimeSource`/`LocalTimeSource`/`RedisTimeSource`), wired into `src/mcc_core/coordinator.py`, `gateway/governance_service.py`, `src/mcc_core/mandate.py`, `src/mcc_core/challenge.py`, `gateway/pre_execution_control.py` | `tests/test_trusted_time.py`, `tests/test_trusted_time_round4.py`, `tests/test_trusted_time_monotonic.py`, `tests/test_dispatch_staleness.py`, `tests/test_round6_mandate_exp_clamp.py`, `tests/test_round6_staleness_config_validation.py` | `PARTIAL` — every enumerated code path is evidence-linked and fail-closed; authenticated-UTC assurance (NTS/HSM/TrueTime-equivalent) remains unimplemented, an explicitly `ACCEPTED RISK` pending future deployment-design work, not a code defect |
| T-05 | Ed25519 signing (`src/mcc_core/signing.py`), append-only audit (`src/mcc_core/audit.py`) | existing audit-chain tests (see `docs/AUDIT_MODEL.md`) | `PARTIAL` — signature/audit integrity evidence-linked; human-consent non-repudiation requires PR #123's owner-signed delegation, `PLANNED` |
| T-06 | — (selective disclosure / ZKP not implemented) | — | `PLANNED` (P3) |
| T-07 | Fail-closed bounded operations throughout `src/mcc_core/coordinator.py`; no HA/rate-limiting layer yet | targeted fail-closed tests across `tests/test_coordinator.py`, `tests/test_velocity.py` | `PARTIAL` — fail-closed evidence-linked; HA, chaos, and load testing remain `PLANNED` |
| T-08 | `gateway/governance_api.py` (`AuthorityPolicy` required on `ApprovalService.approve()`), `deploy/pilot/authority_policy.*.json` | `tests/test_independent_authority_decision_adversarial.py`, `tests/test_pilot_compose_authority_policy_wiring.py` (5/5 pilot deployments) | `CLOSED (evidence-linked)` for the 5 reviewed pilot Compose deployments |
| T-09 | — (owner-signed delegation + atomic global cumulative budget not yet implemented) | — | `PLANNED` (#123) |
| T-10 | `src/mcc_core/approvals.py` (`_CONSUME_LUA`/`_SET_STATE_LUA` atomic Redis CAS) | `tests/test_redis_approval_consume_atomicity.py`, `tests/test_approval_adversarial_round2.py`, `tests/test_approval_ttl_expiry.py` | `CLOSED (evidence-linked)` |
| T-11 | `src/mcc_core/coordinator.py` (`DISPATCH_OWNED`/`UNKNOWN` durable semantics, idempotency) | `tests/test_coordinator.py`, `tests/test_governed_executor_pilot.py` | `CLOSED (evidence-linked)` for the single-gateway coordinator path; cross-region/HA durability under real partition is `PLANNED` (HA track) |
| T-12 | `pilot_notify/governed_upstream.py` (`receipt_verifying_upstream`), hash-chained `src/mcc_core/audit.py` | `tests/test_governed_executor_pilot.py` (mismatched receipt never reports `EXECUTED`) | `PARTIAL` — pilot-scope receipt binding evidence-linked; external, independent checkpoint/anchor stores remain an Enterprise-adoption-gate item |

This table is a documentation cross-reference built from PR #122's own already-merged code and already-passing tests. It does not introduce, run, or claim any new test; where a cell says `PLANNED`, no code or test exists yet in this repository for that cell, consistent with the Roadmap's P1–P3 sequencing.

## 6. What remains open after this merge (unchanged from, or newly carried forward by, the source documents)

- **PR #123 (Verifiable Delegation & Intent Binding)** has not started. T-01, T-06, and T-09 remain fully open, exactly as both source documents state. The PR number remains provisional until GitHub allocates it.
- **Authenticated UTC / NTS / HSM-backed time / TrueTime-equivalent** is not implemented. This is an explicit, accepted residual risk per the Roadmap's own "Non-goals," not a defect introduced or left by PR #122.
- **High availability, chaos/partition testing, and measured RTO/RPO/SLO** are not yet done; the Roadmap's P2 track remains fully open.
- **Zero-knowledge / selective-disclosure proofs** are not implemented; P3, fully open.
- **`ApprovalService.consume()` runs before the coordinator's durable dispatch-ownership commit** — a pre-existing availability quirk (an approval can be burned without the underlying action executing, if a later step fails) — documented in PR #122 itself as out of scope, unchanged by this addendum.
- **Formal-model (TLA+) coverage of the approval state machine, the Lua CAS transitions, and TTL/logical-expiry mechanics** does not exist. This gap was identified, not closed, during PR #122's review; recommended follow-up, not actioned here.
- **This remains Claude's own fix-and-review work across six rounds, not an independent third-party audit.** Green CI, a clean mutation score, and passing regression tests demonstrate the absence of every specific defect that was looked for; they are not a formal proof of the absence of all vulnerabilities, and neither source document nor this addendum claims otherwise.

---

*Generated as part of a documentation-only handoff. No source code, configuration, or test file was modified to produce this addendum.*
