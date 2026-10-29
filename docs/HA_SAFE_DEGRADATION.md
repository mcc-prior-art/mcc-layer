# High Availability & Safe Degradation (P2-B)

**Status: engineering workstream evidence, not an HA certification.** This
document records what was actually built and actually exercised in this
PR's fault-injection lab (`tests/ha/`), against this repository's real
durable-state primitives (`src/mcc_core/idempotency.py`, `velocity.py`,
`mandate.py`'s revocation registry, `trusted_time.py`). Per the Strategic
Roadmap v1.2 execution handoff: **active-active is a target to prove, not
an assumed present feature.** Nothing below claims a multi-zone,
split-brain-safe, production active-active deployment — that remains
future work, listed under "Known limits" below.

Threats referenced: STRIDE T-04 (Denial of Service), T-07 (Repudiation of
infrastructure events), T-10 (availability/fail-closed boundary), T-11
(tampering with durable state) per `docs/security/MCC_CORE_THREAT_MODEL_v1.0.md`.

## 1. Where globally consistent state is actually required

Tracing `coordinator.py`'s `enforce()` (the one execution path every
authority source — mandate, delegation, consensus — routes through) against
`idempotency.py`, `velocity.py`, `mandate.py`'s `RevocationRegistry`, and
`trusted_time.py`:

| Concern | Primitive | Consistency requirement | Safe-with-Redis-replicated-failover condition |
| --- | --- | --- | --- |
| Nonce / decision-token replay | `nonce.py`'s `NonceRegistry` (consumed inside `gate.verify()`) | Exactly-once claim, globally, for the token's lifetime | Needs a single logical Redis endpoint every instance writes through (a Sentinel/Cluster failover that briefly serves TWO masters — split brain — would let a nonce be claimed on each side; this PR does **not** demonstrate fencing against that, see "Known limits") |
| Operator revocation visibility | `mandate.py`'s `RedisRevocationRegistry` (a Redis `SADD`/`SISMEMBER` set) | Every instance's NEXT check must see a revoke from ANY instance, with no caching window | Demonstrated in this PR (§4) across two independent client connections to one real Redis; **not** demonstrated across a real failover/replica promotion |
| Delegation/mandate aggregate budget | `velocity.py`'s sliding-window ZSET | Atomic compare-and-reserve across every concurrent writer | Demonstrated in this PR (§5) across two independent connections; relies on the SAME single logical endpoint property as above |
| Logical-operation identity (idempotency) | `idempotency.py`'s fenced state machine (`RESERVED → DISPATCH_OWNED → EXECUTED/UNKNOWN`) | Exactly-one admission, durable ownership that survives a crash, generation-fenced mutation | Demonstrated in this PR (§2) via a REAL process crash at two distinct points, against one real Redis instance |
| Dispatch ownership / no double-actuate | Same as above, specifically the `DISPATCH_OWNED`→terminal transition | Once committed, must never be releasable by anyone but `resolve_unknown` with independently verified evidence | Demonstrated in this PR (§2) |

**Split-brain safety is explicitly NOT demonstrated or claimed by this PR.**
Every scenario below shares exactly ONE real Redis logical endpoint (one
process, or one process that is killed-and-restarted-in-place). A genuine
Redis Sentinel/Cluster failover that produces two masters answering writes
simultaneously is a distinct, harder problem (it requires client-side
fencing tokens or `WAIT`-style durability guarantees this codebase does not
yet implement) and is listed under "Known limits", not claimed solved.

## 2. The fault-injection lab (`tests/ha/`)

* `tests/ha/_redis_lab.py` — `RealRedisServer` (a genuine `redis-server` OS
  process, started/killed/restarted via real signals, own ephemeral port
  and data dir), `KillRedisOnFirstCall` (a proxy around a REAL redis client
  that kills the REAL redis-server process as a side effect of its first
  call, then genuinely attempts the real now-failing call), and
  `ForgedClockRedisClient` (the one deliberately-mocked primitive in this
  lab — see §6).
* `tests/ha/_crash_worker.py` — a genuine OS subprocess
  (`python -m tests.ha._crash_worker`) that builds its own real governed
  stack against a given real Redis URL, issues one payment token, and
  SIGKILLs itself either right after a real `idempotency.reserve()`
  succeeds (`--crash-point reserve`) or inside the executor callback that
  `EnforcementCoordinator.enforce()` only ever invokes after durable
  dispatch ownership is committed (`--crash-point dispatch`).
* `tests/ha/test_fault_matrix.py` — the matrix itself, twelve tests, all
  requiring a real `redis-server` binary on `PATH` (skipped, not silently
  passed, otherwise — see `REDIS_AVAILABLE`).

Every "must never execute" assertion counts the actual number of actuator
invocations (`seen == []`), never just a status string; every "must execute
exactly once" assertion counts it too (`seen == ["executed"]`).

## 3. Fault matrix — real vs. simulated

| # | Scenario | Real or simulated? | Result |
| --- | --- | --- | --- |
| 1 | Gateway process crashes between admission and dispatch-ownership commit | **Real**: genuine OS subprocess, genuine SIGKILL, genuine Redis state | Immediate retry sees the surviving `RESERVED` record → BLOCKED, zero actuator calls (`test_pre_dispatch_crash_blocks_immediate_retry_with_zero_actuator_calls`) |
| 2 | Pre-dispatch reservation TTL recovery | **Real** (direct registry call against real Redis, short TTL) | Expired, never-committed reservation becomes admittable again (`test_pre_dispatch_reservation_ttl_is_the_documented_crash_recovery_mechanism`) — proves the *mechanism*; the specific 120s production default duration is unverified by this fast test |
| 3 | Gateway process crashes exactly as/after it begins actuating (post dispatch-ownership commit) | **Real**: genuine OS subprocess, genuine SIGKILL inside the executor | Retry → BLOCKED, zero actuator calls; operator reconciliation (`resolve_unknown` with the live generation read from durable state) → `RESOLVED`; a THIRD attempt after reconciliation → still BLOCKED, zero actuator calls (never double-dispatched); a genuinely fresh operation still executes normally (`test_post_dispatch_ownership_crash_never_double_dispatches_and_recovers_via_reconciliation`) |
| 4 | Audit chain integrity after crash/retry/reconciliation/fresh-execution | Real Redis, in-process sequence (the cross-process crash property is proven in #3; this isolates the audit-integrity question) | `AuditLog.verify_chain()` still `True` (`test_audit_chain_integrity_survives_crash_and_reconciliation`) |
| 5 | Redis genuinely dies mid-operation (between idempotency admission and velocity reservation) | **Real**: actual `SIGKILL` of the real `redis-server` process, triggered as a real side effect, hitting the real redis-py client's real connection-failure path | BLOCKED, zero actuator calls; after a real restart, a fresh attempt for the SAME key succeeds (`test_real_redis_killed_mid_velocity_reserve_fails_closed_then_recovers`) |
| 6 | `get_state` during a real outage | **Real** | Raises `IdempotencyBackendUnavailable` — never "not found" (`test_redis_outage_get_state_fails_closed_not_not_found`) |
| 7 | Redis kill + restart, fresh operation | **Real** | Executes normally; old data is gone by design (no AOF/RDB — see `RealRedisServer.restart`'s docstring) (`test_real_redis_restart_recovers_fresh_operations`) |
| 8 | Revocation race across two gateway instances | **Real**: two independent Redis client CONNECTIONS to one real Redis (see "Known limits" — not two OS processes) | A mandate revoked via connection A is seen by connection B's very next check — no caching window (`test_revocation_via_one_connection_is_immediately_visible_to_another`) |
| 9 | Concurrent cross-instance aggregate spend | **Real**: two independent Redis client connections, 10 concurrent reservations | Exactly 5 of 10 admitted against a 500/100 ceiling, every interleaving (`test_concurrent_cross_connection_spend_never_exceeds_aggregate_ceiling`) — extends the same property PR #124 already proved for delegation budgets |
| 10 | Stale / rolled-back Redis clock | **Partially simulated**: real Redis, but the single `TIME` reply is forged (see §6) | `RedisTimeSource` raises `TimeTrustError`; coordinator BLOCKED before touching idempotency/velocity at all, zero actuator calls, nothing reserved (`test_stale_redis_clock_blocks_before_any_reservation_zero_actuator_calls`) |
| 11 | Audit-write failure | **Simulated** (a real disk-full condition is impractical/unsafe to construct safely in a shared sandbox — see §6) | BLOCKED, zero actuator calls, reservation released; retry with a fresh authorization succeeds once the backend is healthy (`test_audit_write_failure_blocks_pre_dispatch_and_releases_reservation`) |
| 12 | Network partition | **Approximation** (single host; see §6) — a real `iptables DROP` on the real redis-server's loopback port; **capability-gated** — skipped (not silently passed) on any runner where `iptables` is absent or usable-but-permission-denied (e.g. a standard GitHub Actions job container without `CAP_NET_ADMIN`/root), detected by a real read-only probe call, never by catching and ignoring the permission error | Where runnable (this PR's own dev sandbox, root): bounded client timeout → BLOCKED, zero actuator calls; rule removed and connectivity + a fresh operation verified afterward regardless of test outcome (`test_network_partition_approximation_blocks_closed_and_fully_recovers`) |

Every "zero actuator calls" and "exactly once" claim above is a literal
`assert seen == []` / `assert seen == ["executed"]` in the test file, not a
status-string check.

## 4. Reproduction

```bash
# From a clean checkout, with a real redis-server binary on PATH:
source /path/to/venv/bin/activate   # or use the venv's python directly
PYTHONPATH=src:.:sdk/python/src python -m pytest tests/ha/ -v
```

No Docker is required or used by this suite (see §6 — the Docker daemon
was not available in the environment this PR was built in, so Docker
Compose multi-container HA scenarios were not exercised at all; this is a
real gap, not a simplification choice).

## 5. What this PR does NOT change

No modification to `src/mcc_core/coordinator.py`, `idempotency.py`,
`velocity.py`, `mandate.py`, `trusted_time.py`, `gate.py`, or
`gateway/governance_service.py`/`governance_api.py`. This PR is evidence
and a reusable fault-injection lab (`tests/ha/`) against the EXISTING
fail-closed/durable-dispatch contract — it found no defect requiring a
code change. (Contrast with the companion Verifiable Delegation PR #124,
which found and fixed a real pre-existing velocity-release defect while
building its own evidence; no equivalent defect surfaced here.)

* No offline/cached-ALLOW fallback was added anywhere.
* No new Gate verdict was added; nothing here introduces degraded/queued
  handling inside the Gate itself.
* No loss of single-use nonce/idempotency semantics.
* No silent downgrade of `TrustedTime`'s guarantees — the stale-clock test
  (§3, row 10) exercises the EXISTING fail-closed contract, it does not
  relax it.

## 6. Known limits — read before relying on anything above

* **No true multi-host network partition.** This sandbox is single-host;
  "partition" (row 12) is a real `iptables DROP` on loopback traffic to one
  port, with a bounded client timeout. It proves "an unreachable backend
  fails closed", not "this system is safe under an asymmetric network
  partition between two real hosts, each still able to reach some but not
  all peers." Those are different failure classes.
* **The iptables-based test is itself environment-capability-gated, and
  will be skipped (not silently passed) on most CI runners.** A standard
  GitHub Actions job container runs unprivileged and without
  `CAP_NET_ADMIN`: `iptables` is present on `PATH` but every real
  invocation fails with a permission error. `tests/ha/test_fault_matrix.py`
  detects this with a real, read-only, side-effect-free probe call
  (`iptables -L -n`) before the test runs — not by catching the permission
  error inside the test and treating that as success — and skips with an
  explicit reason when the probe fails. This PR's own dev sandbox ran as
  root, so the test executed for real there (§3's "where runnable" note);
  expect it to report as skipped on most CI infrastructure, which is the
  honest outcome, not a gap this PR papers over.
* **No Docker Compose multi-container exercise.** The Docker daemon was not
  running in the sandbox this PR was built in (`/var/run/docker.sock`
  absent). Every "two gateway instances" scenario in this PR is either two
  independent Redis client connections within one test process, or (for
  the crash scenarios specifically) one real OS subprocess plus the test
  process itself — genuine separate processes, but not genuine separate
  containers/hosts on a real Docker network. The existing
  `docker-compose.pilot.yml`/`docker-compose.pilot-voltagent.yml` family in
  this repository was not exercised by this PR at all.
* **Split-brain / Redis Sentinel or Cluster failover is unproven.** §1
  explains exactly why: every scenario here shares one logical Redis
  endpoint. A real failover that briefly serves two masters is a distinct
  and harder problem (needs fencing tokens or equivalent); this PR neither
  claims nor demonstrates safety under it.
* **RTO/RPO/SLO are not measured or claimed.** The durations observed in
  this PR's own test runs (sub-5-second for the whole 12-test suite,
  sub-1.5-second for the crash+reconciliation sequence specifically) are
  informal observations from one laptop-class sandbox, not benchmarked,
  repeated-run, or production-topology measurements, and must not be read
  as a performance or recovery-time commitment.
* **Audit-write failure is simulated, not real.** A real disk-full or
  filesystem-fault condition was judged impractical and unsafe to
  construct reliably in this shared sandbox without risking the sandbox
  itself; the existing exception-double pattern already used elsewhere in
  this codebase's own test suite (`tests/test_coordinator.py`'s
  `_RaisingAudit`) was reused instead.
* **The stale-clock scenario forges one RPC reply, not a second real Redis
  instance with a genuinely skewed system clock.** Constructing a second
  real Redis instance on a deliberately mis-set system clock was judged
  out of proportion to what it would additionally prove, given
  `RedisTimeSource`'s skew/rollback/freshness logic is already covered by
  `tests/test_trusted_time*.py`'s existing unit coverage; this PR's
  contribution is proving that failure propagates through the FULL
  coordinator path to a zero-actuator-call BLOCKED outcome, which the
  forged-reply approach demonstrates just as validly.
* **Operator reconciliation evidence verification is out of scope.**
  `resolve_unknown()` performs only the state transition; this PR's tests
  supply the "independently verified positive evidence" synthetically
  (a literal string). The actual external verification step (checking a
  real receipt, a real bank statement, a real upstream API) that a real
  operator runbook would perform before calling `resolve_unknown()` is not
  built or tested here — it is, by design, outside this module's
  responsibility (see `idempotency.py`'s own docstring on `resolve_unknown`).
* **No active-active topology, load balancer, or automatic failover
  orchestration was built.** This PR proves durable-state properties that
  an active-active deployment would DEPEND on; it does not build or test
  the deployment topology itself.

## 7. Operational evidence still required (per the Roadmap/handoff)

Authenticated time source (NTS / a trusted NTP chain, not just
`RedisTimeSource`'s internal skew checks against this process's own
possibly-wrong clock), independent key custody review, a genuine
multi-host Redis Sentinel/Cluster deployment exercised end-to-end
(including a real failover event), a genuine Docker/Kubernetes multi-
instance deployment exercise, and third-party review of this fault matrix
and its coverage. None of these exist yet; this PR does not claim them.
