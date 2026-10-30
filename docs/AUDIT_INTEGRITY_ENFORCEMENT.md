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

### Why `VERIFYING` is not shared across workers, and never blocks gating

`VERIFYING` is reported only for the lifetime of a `verify_once()` call in
*this* process. It is never written to the shared registry, and — since
the hardening round below — it is also never consulted by
`current_state()`'s gating decision. The only state another worker (or a
live request on the SAME worker) needs for a correct fail-closed decision
is the last **completed** outcome (`HEALTHY`/`UNHEALTHY`) plus its
freshness: a pass happening to be in flight right now does not make the
last durably-recorded result any less trustworthy, so blocking on it would
only ever cost availability, never buy security. `VERIFYING` remains
available as *diagnostic-only* information via
`AuditIntegrityMonitor.verification_in_progress` (e.g. for `/ready`).

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
the default.

**This grant is ONE-TIME, not a standing permission (hardening round,
Finding 1).** The moment this audit log is observed genuinely non-empty —
by this process's own `AuditLog.prev_hash` advancing off `GENESIS` (zero
delay), or by a durable, cross-worker, one-way registry latch
(`mark_initialized`/`is_initialized`) — `allow_empty_bootstrap` stops
mattering: an empty/missing file from that point on is **always**
`UNHEALTHY`, with a distinct reason
(`AUDIT_FILE_MISSING_OR_EMPTY_AFTER_INITIALIZATION`), regardless of how
`allow_empty_bootstrap` was configured. Without this latch, a journal
deleted or truncated to zero *after* legitimate history already existed
would otherwise be silently re-accepted as "a fresh bootstrap" — exactly
the total-audit-destruction event this control exists to catch, being
absorbed as normal.

There is no method anywhere in this module that clears that latch. A
confirmed-corrupted deployment's recovery is always an explicit,
out-of-band operator action — see "Hardening round" → "Disaster recovery"
below — never something a code path here does automatically.

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

**Deployment invariant, mechanically checked (hardening round, Finding
3):** every worker sharing one integrity-state registry key MUST point at
the exact same physical audit log, on shared, consistent storage. This is
no longer only documented — `current_state()` compares the registry's
recorded `log_identity` (an `AuditLog.genesis_fingerprint_safe()`
fingerprint, computed once from the log's first record and cached) against
THIS worker's own most recently observed identity, and fails closed on a
mismatch. A worker that is, via misconfiguration or a corrupted/replaced
local file, actually looking at a *different* audit log can never silently
inherit another worker's `HEALTHY` result for itself.

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

## Hardening round (independent review follow-up)

Four findings from an independent review of the original P2-A3 design, all
fixed on top of it without weakening any existing control.

### Finding 1 (P1) — trusted-bootstrap was reusable, not one-time

Fixed above ("Explicit trusted-bootstrap policy"): a durable, one-way
`IntegrityStateRegistry.mark_initialized()`/`is_initialized()` latch (an
atomic Redis `SET ... NX`, or an equivalent lock-guarded boolean
in-process) plus a zero-delay, process-local `AuditLog.prev_hash` fast
path. **Residual, disclosed limitation:** the durable latch converges
across *other* workers (ones that did not themselves perform the append)
only as fast as their own next periodic pass — bounded by
`MCC_AUDIT_INTEGRITY_INTERVAL_SECONDS`, the same bound this design already
accepts everywhere else. The worker that is itself appending is protected
with **zero** delay via its own `prev_hash`, and every worker's own
periodic pass also opportunistically re-latches on every non-empty
observation, so the durable latch converges as soon as *any* worker's pass
sees non-emptiness, not only the one that performed the write.

**Disaster recovery (explicit, out-of-band, never in-band):** once
latched, nothing in this module clears it. A genuinely authorized reset —
e.g. after deliberately reprovisioning audit storage — requires an
operator to directly delete the registry's bootstrap key (for the Redis
backend: `DEL <key>:bootstrap`, where `<key>` is the configured
`MCC_AUDIT_INTEGRITY_BACKEND=redis` key from `redis_keys.singleton_key`)
*after* independently re-establishing trust in the replacement audit log.
There is no API call, flag, or environment variable that does this from
inside the governed runtime.

### Finding 2 — Redis async client reused across event loops

`build_governance_service()` runs the mandatory startup verification pass
synchronously via a throwaway `asyncio.run()`, before any ASGI event loop
exists. For the `redis` backend, that is the *first* use of the
`redis.asyncio.Redis` client — which binds real socket connections to
whichever event loop is running at that moment. Reusing that same client
afterward from a *different* loop (the real server loop that runs
`start_periodic_verification()` and every live request's
`current_state()` call) raises `RuntimeError: Event loop is closed` (or
equivalent) on every subsequent Redis operation, confirmed against a real
`redis-server`, not a mock (see
`tests/test_audit_integrity_redis_event_loop.py`).

This resolves safely rather than dangerously — the existing broad
`except Exception: ... -> IntegrityBackendUnavailable -> UNHEALTHY`
handling converts the cross-loop error into a clean fail-closed
`UNHEALTHY`, never a crash, a hang, or a false `HEALTHY` — but left
unfixed it would turn into a **permanent, self-inflicted integrity-service
outage** the moment the first periodic cycle (or the first live request)
touches the stale connection, under `MCC_REQUIRE_AUDIT_INTEGRITY=1`
blocking every governed action in the process forever after. Fixed by a
new `AuditIntegrityMonitor.reset_connections_for_new_event_loop()` /
`RedisIntegrityStateRegistry.aclose()`, called inside the *same*
`asyncio.run()` invocation as the startup check, immediately before that
throwaway loop tears down — the registry's client then lazily establishes
brand-new connections, bound to whichever loop next uses it, on its next
operation. `build_governance_service()` remains fully synchronous and its
fail-closed-at-startup guarantee is unchanged for every caller (ASGI or
not); only the connection lifecycle changed.

### Finding 3 — no shared-audit-file identity check

Fixed above ("Multi-worker / cross-process consistency").

### Finding 4 — local `VERIFYING` caused avoidable recurring outages

Fixed above ("Why `VERIFYING` is not shared across workers, and never
blocks gating"). Before this fix, `current_state()` blocked gating for the
*entire duration* of every periodic verification pass — including every
routine one, not only the first — even though the durable, already-fresh
`HEALTHY` result from the *previous* pass remained perfectly trustworthy.
At the measured full-chain-scan cost of ~350–430ms for a 50k-entry log
(see `docs/AUDITLOG_OPTIMIZATION.md`), this meant a real, entirely
avoidable mini-outage on whichever worker happened to be running the pass,
once per `MCC_AUDIT_INTEGRITY_INTERVAL_SECONDS`, forever — with no
corresponding security benefit, since blocking during a scan does not make
the already-completed prior result any more or less trustworthy.

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
* **`VERIFYING` is per-process, not cluster-wide**, and (since the
  hardening round) purely diagnostic — never consulted for gating. A
  deliberate scope choice, not an oversight.
* **Finding 1's cross-worker latch-convergence bound** — see "Hardening
  round" above: zero delay for the appending worker, bounded by the
  periodic interval for every other worker.
* **Finding 3's identity check has a narrow startup window**: a worker
  that has never yet completed its own first verification pass has no
  local identity to compare against, so it reads the shared registry's
  `HEALTHY` verbatim until its own first pass completes. Every production
  deployment path runs a mandatory synchronous startup verification before
  a monitor is ever wired into a gate, so this window is not reachable
  from a real enforcement decision in practice.
* **TLA+/mutation coverage**: see the PR's own assurance report for exactly
  what was and was not modeled/mutated for this change. No dedicated TLA+
  model exists for the 4-state integrity machine, including after the
  hardening round's bootstrap-latch addition — this is explicitly **NOT
  PROVEN** by formal methods; only by the unit/adversarial/non-vacuity test
  suite and mutation testing.
