# Constitution Compliance Matrix

Nothing in this table is marked complete unless an automated test in
`tests/constitution/` actually proves it, and that test is named
explicitly here so the claim is checkable against real code, not this
document's own prose. See `docs/MCC-CORE-CONSTITUTION.md` for the
principles and `docs/CONSTITUTION-INVARIANTS.md` for the full
principle → invariant → enforcement-point mapping this table summarizes.

| Principle | Invariant | Enforcement | Test | Status |
|---|---|---|---|---|
| Data remains with its owner | See "Architectural gaps" below | — | — | **NOT COVERED BY THIS SUITE** |
| Authority remains with the owner | INV-01 No self-authorization; INV-02 No execution without authorization | `ExecutionGate.verify`, `EnforcementCoordinator.enforce`, `DecisionEngine.issue_token` | `tests/constitution/test_inv01_no_self_authorization.py` (6), `test_inv02_fail_closed_without_authorization.py` (6) | **PROVEN** — 12/12 passing |
| Execution remains within boundaries | INV-03 Exact-action authorization; INV-09 MCC-Core boundary | `ExecutionGate.verify` scope-binding checks; static import guards over agent packages | `tests/constitution/test_inv03_exact_action_authorization.py` (8), `test_inv09_mcc_core_boundary.py` (5) | **PROVEN** — 13/13 passing |
| Intelligence proposes; authority verifies; execution enforces | INV-01, INV-06, INV-10.a/c/e | `ExecutionGate`, `EnforcementCoordinator`, actuator signatures, `.sign_token(` call-site scan | `test_inv01_no_self_authorization.py`, `test_inv06_executor_cannot_authorize.py` (5), `test_inv10_no_plane_usurpation.py` (7, sub-claims a/c/e) | **PROVEN** — 18/18 passing (counting INV-01 once) |
| Growth of intelligence does not imply growth of authority | INV-05 Intelligence cannot increase authority | `AuthorityModel.evaluate` signature; `Mandate`/`ActionPolicy` field sets; token `actor_id` informational-only | `tests/constitution/test_inv05_intelligence_cannot_increase_authority.py` (5) | **PROVEN** — 5/5 passing |
| Authority is verifiable, not merely trusted | INV-07 Audit-before-execution; INV-08 Replay protection | `AuditLog` hash chain + a-h ordering; `NonceRegistry.consume` | `tests/constitution/test_inv07_audit_before_execution.py` (5), `test_inv08_replay_protection.py` (5) | **PROVEN** — 10/10 passing |
| No plane may usurp the role of another | INV-04 Memory cannot authorize (partial); INV-10 No plane usurpation (partial) | `AuthorityModel.evaluate` context handling; `.sign_token(` call-site scan | `tests/constitution/test_inv04_memory_cannot_authorize.py` (4), `test_inv10_no_plane_usurpation.py` (7) | **PARTIALLY PROVEN** — 11/11 passing tests, but 2 of the 5 INV-10 sub-claims and all of INV-04's real-world scope are **IMPLEMENTATION GAP** (see below) |

**Total: 56/56 constitution tests passing** (`pytest tests/constitution/`).
See section "Full validation" below for the whole-repository run this was
part of.

## IMPLEMENTATION GAP — stated explicitly, not hidden

1. **"Data remains with its owner"** is not covered by this suite at
   all. MCC-Core's existing architecture (per `CLAUDE.md` and
   `docs/*` PHI/compliance material) already keeps raw customer data out
   of the audit chain and out of MCC-Core's own storage — but this task
   was scoped to invariants expressible from the existing
   Decision/Gate/Authority/Audit/Coordinator components, and there is no
   single "data ownership" enforcement point in that set to write an
   automated test against. A real test for this principle would need to
   target wherever customer data actually lives (a future/separate data
   plane), which is out of scope for "formalize and prove the existing
   authority model" — this task's own stated boundary. Flagging this
   explicitly rather than fabricating a test that would not actually
   prove data ownership.

2. **INV-04 (Memory cannot authorize) — partial.** This repository has
   no first-class agent-memory subsystem. What is proven:
   `AuthorityModel.evaluate` cannot be made to grant authority from
   free-form context content shaped like a memory claim, and its
   signature carries no memory/history channel at all. What is NOT
   proven: an actual memory component's integration path, because none
   exists to test. `tests/constitution/test_inv10_no_plane_usurpation.py::test_b_memory_cannot_authorize_gap_is_explicitly_documented`
   makes this gap a checked fact — it fails the moment a memory package
   is added, forcing this document to be revisited rather than silently
   drifting out of date.

3. **INV-10.d (UI cannot directly authorize) — gap.** This repository
   has no UI/frontend code at all (it is a backend governance engine).
   There is no real UI boundary to test against.
   `tests/constitution/test_inv10_no_plane_usurpation.py::test_d_ui_cannot_authorize_is_an_implementation_gap`
   makes this gap a checked fact for the same reason as above.

## Architectural gaps discovered during this work

- **`EnforcementCoordinator.enforce` does not itself catch exceptions
  from `idempotency.reserve()`/`velocity.reserve()`.** Fail-closed
  behavior for those two steps depends entirely on the specific registry
  implementation (`RedisIdempotencyRegistry`/`RedisVelocityRegistry`)
  catching its own backend errors and returning a failure result — a
  registry implementation that does NOT do this (e.g. a naive custom
  backend that lets a raw `ConnectionError` propagate) would raise out
  of `coordinator.enforce()` as an unhandled exception rather than
  returning `ActuationResult(BLOCKED, ...)`. This is not a defect in the
  two registries MCC-Core actually ships (both are correctly
  fail-closed, confirmed by INV-02's tests using the real classes), but
  it is a coupling worth naming: INV-02's fail-closed guarantee for
  those two steps is currently a property of the registry
  implementations in use, not an independent guarantee `enforce()`
  itself enforces regardless of what backend is plugged in. Not fixed as
  part of this task (explicitly out of scope: "do not weaken or redesign
  existing security controls" — and this is not a weakening, it is an
  existing coupling, not a hole any current registry exposes).

## Full validation

Run from `feat/mcc-core-constitution-invariants`, branched from `main`
at `b3214c21b47be4b59ffb47ebdaadb78b8a214b67` (PR #115's merge commit).

| Metric | Before this PR | After this PR |
|---|---|---|
| Full suite (`pytest tests/`) | 3269 passed, 18 skipped, 0 failed | 3325 passed, 18 skipped, 0 failed |
| Assurance suite (`pytest assurance/tests`) | 165 passed, 15 skipped | 165 passed, 15 skipped (unaffected) |
| `tests/constitution/` | 0 (did not exist) | 56 passed, 0 failed |

The full-suite delta is exactly +56 (3325 - 3269), matching the 56 new
constitution tests one-for-one — no other test count moved, and nothing
regressed.

Mutation/TLA+ were not re-run: this PR adds no file under `src/mcc_core/`
(only new tests and docs), consistent with this repository's established
convention that those target `src/mcc_core/`'s own invariants
specifically and are re-run when that code changes.
