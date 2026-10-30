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
  **and** that result is still fresh (see Freshness below), **and** no
  cross-worker identity conflict has ever been latched for this key (see
  "Third hardening round" below).
* **UNHEALTHY** — the most recent pass failed, OR the last known-HEALTHY
  result has gone stale, OR the shared state backend cannot currently be
  read, OR a cross-worker identity conflict has ever been latched for
  this key — for EVERY worker sharing it, not only the one whose write
  triggered the latch.

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

**Deployment invariant, mechanically checked (hardening round, Finding 3;
strengthened in the second hardening round):** every worker sharing one
integrity-state registry key MUST point at the exact same physical audit
log — in this repository's actual shared-storage model, a single Docker
volume bind-mounted into every worker container on one host (see
`docker-compose.*.yml`'s shared `/data/*.jsonl` volumes). This is
mechanically enforced, not merely documented, by TWO layers:

* **The write path is the primary, airtight enforcement.**
  `AuditLog.physical_identity_safe()` (device+inode — a genuine
  physical-storage proof, not a content fingerprint two *different* files
  can trivially share) is recorded alongside every `set_if_newer` write.
  Once a registry key has ever recorded a non-empty physical identity, any
  later write whose own physical identity *differs* is **rejected outright
  — independent of generation ordering.** A worker whose own write is
  vetoed this way resolves its own pass to `UNHEALTHY` too, regardless of
  what its local scan found: it cannot prove it is looking at the log this
  key actually represents, so it must not claim `HEALTHY` for itself
  either. See "Second hardening round" below for the exact vulnerability
  this closes — a content fingerprint alone (`AuditLog.genesis_fingerprint_safe()`,
  which hashes only the first record) is **not sufficient**, since two
  genuinely different files cloned/bootstrapped from the same initial
  record share it.
* **The read-side check in `current_state()` is defense in depth** on top
  of the write-path veto (e.g. for any record written before this fix was
  deployed): it independently compares the registry's recorded physical
  identity (primary) and content fingerprint (secondary) against this
  worker's own most recently observed values, and fails closed on either
  mismatch.

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

## Second hardening round — cross-worker identity-COLLISION fail-open

Independent review of the first hardening round's own Finding 3 fix found
it insufficient: `AuditLog.genesis_fingerprint_safe()` hashes only the
audit file's **first line**. Two **physically different** files — e.g.
cloned/bootstrapped from the same initial record, such as two workers
provisioned from the same deployment template, or a corrupted/replaced
local file that happened to start with the same bytes — share this
fingerprint even though their tails have since diverged. Reproduced
exactly: Worker B detects a corrupted/divergent tail and records
`UNHEALTHY`; Worker A subsequently verifies its own (genuinely intact, but
**different**) log and records a **newer** `HEALTHY`. On the first
hardening round's logic (generation-only write-path CAS; content-
fingerprint-only read check, which *collides by construction here*), A's
write silently overwrote B's correctly-detected, unresolved failure, and
B's own `current_state()` incorrectly inherited it — fail-open, confirmed
by a deterministic reproduction before any fix (`tests/test_audit_integrity_enforcement.py::test_reproduction_cloned_genesis_collision_was_a_real_fail_open_pre_fix`).

**Fix — identity is now a genuine physical-storage proof, enforced at the
write path, not a content fingerprint checked only on read:**

* `AuditLog.physical_identity_safe()` (new; device+inode via one
  `os.stat()` call) is the **primary** cross-worker identity signal — see
  "Multi-worker / cross-process consistency" above. `genesis_fingerprint_safe()`
  remains a **secondary**, defense-in-depth signal only.
* `_SET_IF_NEWER_LUA` (and `InMemoryIntegrityStateRegistry`'s equivalent)
  now check physical-identity conflict **first, before generation
  ordering**: once a key has recorded a non-empty physical identity, a
  write bearing a *different* one is rejected outright — `return -1` in
  the Lua script, distinct from `return 0` (the pre-existing, still-benign
  "stale generation" no-op) — and `RedisIntegrityStateRegistry.set_if_newer`
  coerces this via `int(res) == 1`, not `bool(res)` (since `bool(-1)` is
  `True` in Python, which would have silently treated a vetoed write as
  applied).
* `AuditIntegrityMonitor._verify_once_locked()` distinguishes the two
  "not applied" cases by reading back the registry's stored physical
  identity after a rejected write: a genuine conflict forces this
  worker's own pass to `UNHEALTHY` (reason surfaced via the diagnostic
  `identity_conflict_detected` property), regardless of this worker's own
  locally-computed result — the benign "a newer result from the SAME
  identity already exists" case is unchanged from before.
* `current_state()`'s read-side check now compares physical identity
  first (primary), then content fingerprint (secondary) — both remain
  skipped only during the narrow pre-first-pass startup window already
  disclosed for Finding 3 below.

**Why device+inode, and why not `st_dev` alone across hosts:** `st_ino` is
invariant for the life of a physical file and — for THIS repository's
actual deployment model (a single Docker volume bind-mounted into every
worker container on one host) — identical across every worker genuinely
sharing that file. `st_dev` is included for extra same-host confidence but
is never relied on as a cross-HOST signal (e.g. over NFS, where a
client-local device number can legitimately differ even for a truly
shared file); only `st_ino` is required to carry meaning across hosts.

**No silent recovery, exactly like Finding 1's bootstrap latch:** nothing
in any normal code path clears an established physical identity or
resolves a conflict automatically. Retrying with the same conflicting
identity changes nothing
(`tests/test_audit_integrity_enforcement.py::test_recovery_after_identity_conflict_requires_explicit_out_of_band_reset`).
**Disaster recovery (explicit, out-of-band, never in-band):** once an
operator has independently confirmed which physical log is actually
authoritative, recovery is provisioning a *fresh* integrity-state key (for
the Redis backend: a new `MCC_AUDIT_INTEGRITY_*` key prefix, or `DEL
<key>` / `DEL <key>:gen` on the old one) — never a method call anywhere in
this module.

**Verified against real Redis**, not only the in-memory/faithful-double
unit tests: `tests/test_audit_integrity_identity_collision_redis.py`
reproduces the identical scenario (sequential and, separately, genuinely
concurrent via `asyncio.gather`) against a real `redis-server` subprocess,
and a healthy-path regression confirms two workers that genuinely DO share
one physical file converge on `HEALTHY` normally — the veto never fires
against itself.

## Third hardening round — the conflict is GLOBAL, not per-loser

Independent review correctly identified a residual gap in the second
round's own fix: the write-path veto only protects the worker whose write
gets *rejected*. If worker A's genuinely intact result is written FIRST
(establishing the identity for this key) and worker B's later, genuinely
different, corrupted write is the one that gets vetoed, worker A's own
`current_state()` — unaffected by B's rejected write, since nothing about
A's own read touches B's write at all — keeps reporting `HEALTHY`.
Reproduced exactly, against the pre-this-round logic, by
`tests/test_audit_integrity_enforcement.py::test_non_vacuity_a_first_ordering_pre_this_round_a_would_stay_healthy`.

The mere *existence* of a cross-worker physical-identity conflict is
itself the signal that this key's own deployment invariant ("every worker
sharing it points at the same physical log") is violated for *some*
worker — and nothing in this module can tell which one is actually
correct. Letting the worker that merely won the race to write first keep
operating as if nothing happened, while only the "loser" is blocked, was
not a safe response to that signal.

**Fix — a durable, GLOBAL, one-way conflict latch, atomic with the veto
itself:**

* When `set_if_newer`'s identity-veto branch fires (either backend), it
  now ALSO atomically latches a durable, global conflict marker — a
  sibling key (`<key>:conflict` for Redis; a one-way boolean for the
  in-memory registry) — in the exact SAME atomic operation as the veto
  decision (the Redis Lua script's own atomicity; the in-memory
  registry's own lock). There is therefore no window between "a conflict
  was detected" and "every reader can observe it," and the result is
  order-independent: whichever of the two possible race orderings trips
  the branch first latches the identical marker (`SET ... NX` —
  idempotent; the first conflicting write to ever trip it wins).
* `AuditIntegrityMonitor.current_state()` checks this latch FIRST,
  unconditionally, before reading anything else — so EVERY worker sharing
  the key, including the one whose write was never vetoed, reports
  `UNHEALTHY` while it stands.
* `_verify_once_locked()` also short-circuits on an already-latched
  conflict (a pure efficiency optimization on top of `current_state()`'s
  own unconditional check, which is what actually enforces the
  invariant) — skipping a pointless full-chain scan once the outcome is
  already fixed.
* **Nothing clears it automatically** — not a later `HEALTHY`
  verification, not a higher generation, not a process restart, not any
  concurrent write (`tests/test_audit_integrity_enforcement.py::test_global_conflict_latch_never_cleared_by_later_healthy_higher_generation_or_restart`).
  Recovery is the SAME explicit, out-of-band operator action as the
  second round's own identity conflict (see below), extended to also
  clear this marker — never an in-band method call anywhere in this
  module.

**Disaster recovery (explicit, out-of-band, never in-band) — updated for
this round:** once an operator has independently confirmed which
physical log is actually authoritative, recovery is provisioning a
*fresh* integrity-state key (for the Redis backend: a new
`MCC_AUDIT_INTEGRITY_*` key prefix, or `DEL <key>` / `DEL <key>:gen` /
`DEL <key>:conflict` on the old one, all three — the conflict marker is a
separate key from the main status hash and must be cleared too, or the
latch stays set even against a freshly re-established identity) — never
a method call anywhere in this module.

**Verified against real Redis, both race orderings and genuine
concurrency**: `tests/test_audit_integrity_identity_collision_redis.py`
adds `test_real_redis_a_first_then_b_global_latch_blocks_a_too` (the
exact residual-gap ordering), `test_real_redis_b_first_then_a_global_latch_blocks_both`
(the other ordering), and `test_real_redis_concurrent_race_always_latches_global_conflict_regardless_of_winner`
(5 repeated genuinely-concurrent runs via `asyncio.gather`) — in every
case, BOTH workers end up `UNHEALTHY` and zero actuator calls occur on
either side through both enforcement boundaries
(`tests/test_audit_integrity_enforcement.py::test_fix_global_conflict_latch_blocks_every_worker_regardless_of_race_ordering`,
parametrized over both orderings). The healthy-shared-file regression is
re-confirmed to never spuriously trip the new latch.

**An existing test's own assumption was deliberately updated, not
weakened**: `test_worker_with_different_audit_log_does_not_inherit_shared_healthy`
previously asserted the second round's own ("undisturbed winner")
behavior as correct — that assertion is now wrong under this round's
stricter, correct semantics, and was updated (with its reasoning stated
explicitly in the test's own docstring) to expect both workers blocked.

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
  from a real enforcement decision in practice. This same window applies
  to the second hardening round's physical-identity read-side check.
* **The second hardening round's write-path veto is per-registry-key, not
  per-file-content-change**: once a key's physical identity is
  established, it is fixed for that key's lifetime (barring the explicit,
  out-of-band disaster-recovery procedure above) — a legitimate,
  authorized replacement of the underlying file (same path, genuinely new
  inode, e.g. after restoring from a trusted backup) is, correctly,
  treated as a new identity and requires that same explicit recovery
  step, never an automatic one.
* **`st_dev`/`st_ino` are not meaningful across every possible storage
  backend** — they are the right primitive for this repository's actual
  deployment model (a single Docker volume on one host; see above) and for
  standard NFS (`st_ino` is preserved across clients), but an operator
  deploying onto a storage layer with different inode-stability semantics
  (e.g. certain overlay/union filesystems, or object storage mounted as a
  filesystem) should verify that assumption before relying on this check.
* **The GLOBAL conflict latch (third hardening round) is per-registry-key,
  irreversible by design, and does not identify which side was actually
  correct** — it is a deliberately conservative "stop everything sharing
  this key" response to a detected conflict, not a diagnosis. An operator
  must independently determine which physical log is authoritative before
  recovering (see the updated disaster-recovery procedure above); this
  module makes no attempt to decide that automatically, by design — doing
  so would require trusting ONE of the two conflicting results, which is
  exactly what a conflict means neither side can be trusted to do for
  itself.
* **TLA+/mutation coverage**: see the PR's own assurance report for exactly
  what was and was not modeled/mutated for this change. No dedicated TLA+
  model exists for the 4-state integrity machine, including after the
  hardening rounds' bootstrap-latch, identity-veto, and global-conflict-latch
  additions — this is explicitly **NOT PROVEN** by formal methods; only by
  the unit/adversarial/non-vacuity test suite (including real-Redis
  concurrency tests covering both race orderings) and mutation testing.
