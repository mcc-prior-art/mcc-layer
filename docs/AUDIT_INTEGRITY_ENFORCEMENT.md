# Automated Audit Integrity & Fail-Closed Enforcement (P2-A3)

## Problem this closes

PR #128 made `AuditLog.append()`/`AuditLog.__init__` O(tail) instead of
O(file size), by reading only the backward-seeked **last** non-blank line
rather than scanning the whole file. That was a deliberate, disclosed
trade-off (see `docs/AUDITLOG_OPTIMIZATION.md`): the hot path no longer
incidentally notices corruption in an **earlier** record, because it never
reads earlier records at all. `AuditLog.verify_chain()` — a full, explicit,
O(file size) scan — still exists and still catches it, but nothing was
calling it automatically, and nothing stopped the system from issuing
executable authority or dispatching an action while the chain was, in
fact, broken.

This PR implements the control `AUDITLOG_OPTIMIZATION.md` §7 proposed but
explicitly did not build: automatic startup + periodic full-chain
verification, a small fail-closed state machine, and mandatory enforcement
of that state at the two places executable authority actually leaves the
system.

## State machine

```
UNVERIFIED --(verify_once)--> VERIFYING --(pass completes)--> HEALTHY or UNHEALTHY
                                                                    |
                                                        (grace window elapses,
                                                         or next pass fails)
                                                                    v
                                                               UNHEALTHY
```

* **UNVERIFIED** — no verification pass has completed yet. The real
  startup default before `run_startup_verification()` returns.
* **VERIFYING** — a pass is in flight, *in this process*. Local/transient
  only (see "Why VERIFYING is not shared" below) — never written to the
  shared registry.
* **HEALTHY** — the most recently completed pass found the chain intact,
  **and** that result is still fresh (see Freshness below).
* **UNHEALTHY** — the most recent pass failed, OR the last known-HEALTHY
  result has gone stale, OR the shared state backend cannot currently be
  read.

Only `HEALTHY` ever satisfies a gate check (`is_healthy()` in
`src/mcc_core/audit_integrity.py`). Every other state blocks — deliberately
boolean-shaped, so no gate can accidentally treat an unrecognized or
ambiguous state as "probably fine."

### Why `VERIFYING` is not shared across workers

`VERIFYING` is reported only for the lifetime of a `verify_once()` call in
*this* process. It is never written to the shared registry. The only
state another worker needs to make a correct fail-closed decision is the
last **completed** outcome (`HEALTHY`/`UNHEALTHY`) plus its freshness — a
remote `VERIFYING` flag would need its own liveness/expiry tracking to
avoid being indistinguishable from a wedged verifier, adding complexity
without closing any bypass this task's adversarial requirements name.

## The one invariant every caller must understand

`HEALTHY` proves the chain was intact **as of `last_verified_at`**. It is
**not** a real-time, per-request guarantee — a full-chain scan is O(file
size) and is deliberately never run inline with a governed request (that
would reintroduce exactly the cost PR #128 removed). This is why:

* **periodic re-verification is required, not optional**, for `HEALTHY` to
  keep meaning anything over time, and
* **`freshness_grace_seconds` exists at all** — a stored `HEALTHY` older
  than this bound is reported as `UNHEALTHY`, specifically to catch a
  periodic verifier that silently died (crashed, wedged, or was never
  started) without anyone noticing a stale green light.

**Honest detection-latency bound:** a corruption introduced between two
passes is detected no later than `(periodic interval + one pass's own run
time)` after it occurs — not instantaneously. A corruption introduced and
then reverted between two passes is invisible to this control; it only
ever observes point-in-time snapshots. Never claim continuous, real-time
protection this design does not provide.

## Explicit trusted-bootstrap policy

A missing or empty audit file is `UNHEALTHY` by **default** — "never
silently accept corrupted audit data" applies equally to "there is no
audit data at all." `AuditIntegrityMonitor(..., allow_empty_bootstrap=True)`
is the only way to treat a genuinely fresh start as trusted; it is never
the default, and it is a one-time, explicit construction-time decision, not
something a corrupted deployment can trigger on its own.

## Two independent fail-closed enforcement boundaries

The task requires enforcement "at actual issuance and execution boundaries,
not only `/ready`." This PR implements **two**, independently configured,
neither a substitute for the other:

1. **Issuance boundary** — `gateway/governance_service.py`'s
   `GovernanceService._integrity_gate()`, called at the top of
   `execute_with_mandate`, `execute_with_delegation`, and
   `execute_with_consensus`, before `DecisionEngine.issue_token` is ever
   called. Mirrors the existing PR-2 `_attestation_gate` pattern exactly.
   `execute_with_approval` needs no separate call: it delegates to
   `execute_with_mandate` (enforced by an existing architecture-guard
   test), so it is covered automatically.
2. **Dispatch boundary** — `EnforcementCoordinator.enforce()`'s **first
   statement**, before even `trusted_now` resolution. This is what blocks
   the "direct API bypass" scenario: any caller that reaches
   `enforce()` directly — skipping `GovernanceService` entirely — is still
   blocked, because this check does not depend on ever having gone through
   the issuance gate.

Both default to `None` (disabled) and are fully backward compatible: no
existing caller or test that does not explicitly configure an
`integrity_monitor` sees any behavior change.

## Multi-worker / cross-process consistency

Each worker's local, in-process state is never the source of truth. A
dual-backend `IntegrityStateRegistry` — mirroring this codebase's existing
nonce/idempotency/velocity/challenge/approval/revocation registry pattern
exactly — is:

* `InMemoryIntegrityStateRegistry` — single-process (dev/tests).
* `RedisIntegrityStateRegistry` — shared by every worker/instance in a real
  deployment. Every write is a **monotonic-generation compare-and-set**
  (one atomic Lua script, the same `EVAL`-based CAS style
  `idempotency.py`'s `_RESERVE_LUA` family already uses): a write is only
  applied if its generation is strictly greater than whatever generation is
  currently stored, so a crashed-and-restarted verifier (or a delayed write
  racing a newer one) can never resurrect a stale result over a newer one.

`integrity_state_registry_from_env()` selects the backend from
`MCC_AUDIT_INTEGRITY_BACKEND` (`memory` default, `redis` opt-in) and
**never silently falls back** — `redis` without a usable `MCC_REDIS_URL`
raises `IntegrityConfigError`, exactly like `nonce_registry_from_env`.

## Concurrency with `append()`

A full-chain verification pass reuses `AuditLog`'s **own** existing
inter-process lock. The only new addition to `audit.py` is one small public
method:

```python
def verify_chain_safe(self) -> bool:
    with self._locked():
        return self.verify_chain(self.path)
```

No new locking primitive is introduced. `append()` itself is completely
unmodified — its hot path stays exactly O(tail), as PR #128 established.
The blocking file I/O inside a verification pass is offloaded to a worker
thread (`asyncio.to_thread`) so it never blocks the event loop, and the
whole pass is further serialized within one process by an `asyncio.Lock`
so two concurrent `verify_once()` calls in the same process never race each
other's registry writes.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `MCC_REQUIRE_AUDIT_INTEGRITY` | off | Mandatory enforcement at both boundaries. Refuses fail-open startup if the monitor cannot be built, **and** if the startup verification pass itself does not report `HEALTHY`. |
| `MCC_AUDIT_INTEGRITY_BACKEND` | `memory` | `memory` or `redis` (shared, multi-worker). |
| `MCC_AUDIT_INTEGRITY_ALLOW_EMPTY_BOOTSTRAP` | off | Explicit trusted-bootstrap opt-in. |
| `MCC_AUDIT_INTEGRITY_FRESHNESS_GRACE_SECONDS` | 180 | Staleness bound before a stored `HEALTHY` is reported `UNHEALTHY`. |
| `MCC_AUDIT_INTEGRITY_INTERVAL_SECONDS` | 60 | Periodic background verification cadence. |

`build_governance_service()` constructs the monitor and runs
`run_startup_verification()` **synchronously** (it runs before any event
loop exists), so no executable authority is ever issued before the first
pass completes. `gateway/app.py`'s FastAPI `startup`/`shutdown` hooks arm
and tear down the periodic background loop, since that needs a running
event loop that does not yet exist inside `build_governance_service()`
itself.

`/ready` additionally reports `audit_integrity_state` (and, when
`MCC_REQUIRE_AUDIT_INTEGRITY` is set, folds it into overall readiness) —
purely for **operational visibility**. This is additive; it does **not**
replace the two mandatory enforcement boundaries above, which run on every
governed call regardless of whether anything ever reads `/ready`.

## Known limitations

* **Detection latency is bounded, not instantaneous** — see "The one
  invariant" above.
* **The empty-file/missing-file race at the start of `verify_once()`** is
  checked outside `AuditLog`'s lock (a plain `os.path.exists`/`getsize`
  check) for simplicity. The only possible skew this introduces is in the
  *safe* direction: a file that becomes non-empty a moment after the check
  is then correctly verified by the *next* pass, never mistaken for
  corruption; a genuinely corrupted, non-empty file can never be mistaken
  for "empty."
* **`VERIFYING` is per-process, not cluster-wide** (see above) — a
  deliberate scope choice, not an oversight.
* **TLA+/mutation coverage**: see the PR's own assurance report for exactly
  what was and was not modeled/mutated for this change.
