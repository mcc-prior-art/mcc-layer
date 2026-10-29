# P2-A — Low-Latency Authority Plane: benchmark harness and baseline evidence

**Status: baseline measurement only. No optimization is implemented or claimed
by this document or by `benchmarks/`.** Every number below was measured in
this sandbox on one shared-tenancy host, not dedicated hardware, and is
**not a service-level agreement**.

## 1. The protected path this harness measures (and never bypasses)

Traced directly from source, not from memory, for this document:

| Step | Location | What it enforces |
| --- | --- | --- |
| Signature + key trust | `src/mcc_core/gate.py:120-125` | Ed25519 signature under a trusted `kid` |
| Time window (nbf/exp) | `gate.py:130-143` | token validity at verification time |
| Policy hash binding | `gate.py:148-149` | token issued under the trusted policy version |
| Action/payload hash binding | `gate.py:151-155` | exact signed-payload binding — the proposed action/payload must match what was authorized |
| Generic operation binding | `gate.py:163-176` | actor/resource/transaction/idempotency-key binding |
| Nonce single-use consumption | `gate.py:229-232` | replay rejection — consumed last, so a static failure never burns it |
| Mandatory logical-operation identity | `src/mcc_core/coordinator.py:243-271` | a token with no usable `idempotency_key`/`tenant_id` is refused before any stateful step |
| Actuation-time revocation re-check | `coordinator.py:322-330` | a mandate revoked after issuance still blocks |
| Approval single-use consumption | `coordinator.py:334-346` | the ESCALATE loop's approval mandate is consumed once, bound to the exact operation |
| Atomic logical-operation admission | `coordinator.py:368` (`idempotency.reserve`) | duplicate/replayed operations denied |
| Atomic aggregate/velocity reservation | `coordinator.py:402-421` (`velocity.reserve`) | global/cumulative budget, anti-splitting |
| Audit-before-actuation | `coordinator.py:430-451` | durable pre-record before any dispatch |
| Dispatch-staleness + token-expiry re-check | `coordinator.py:466-530` | a token that went stale between authorization and dispatch is re-checked against a FRESH trusted clock sample, immediately before the point of no return |
| **Durable dispatch ownership (point of no return)** | `coordinator.py:539` (`idempotency.commit_dispatch`) | after this, failure is never "safe to release" |
| Execute | `coordinator.py:552` | the only call to the actuator |
| Durable outcome | `coordinator.py:578-607` | `EXECUTED` only on a *confirmed* durable write; otherwise `UNKNOWN`, never released |

Delegation's own exact-binding checks (`src/mcc_core/delegation.py`) and its
atomic cumulative ceiling (reusing `velocity.reserve`/`release`, scoped by
`delegation_id`) sit in front of this same path via
`GovernanceService.execute_with_delegation` — see
`docs/VERIFIABLE_DELEGATION.md`. The benchmark harness and the negative
tests below exercise both the mandate path (`execute_with_mandate`) and the
delegation path (`execute_with_delegation`); neither harness code nor any
change in this PR touches `coordinator.py`, `gate.py`, `idempotency.py`,
`velocity.py`, or `trusted_time.py`.

## 2. Reproducing every measurement

```bash
source /path/to/venv/bin/activate   # must have cryptography/cffi built
PYTHONPATH=src:.:sdk/python/src:. python benchmarks/run_benchmark.py \
    --mode auth --backend memory --samples 2000 --warmup 200 \
    --output benchmarks/results/auth_memory.json

PYTHONPATH=src:.:sdk/python/src:. python benchmarks/run_benchmark.py \
    --mode e2e --authority mandate --backend memory --samples 2000 --warmup 200 \
    --output benchmarks/results/e2e_mandate_memory.json

PYTHONPATH=src:.:sdk/python/src:. python benchmarks/run_benchmark.py \
    --mode e2e --authority delegation --backend memory --samples 2000 --warmup 200 \
    --output benchmarks/results/e2e_delegation_memory.json

# Real Redis (not a mock): start your own instance first.
redis-server --port 6399 --daemonize yes --dir /tmp/bench-redis --dbfilename bench.rdb
MCC_REDIS_URL=redis://127.0.0.1:6399/0 PYTHONPATH=src:.:sdk/python/src:. \
    python benchmarks/run_benchmark.py --mode e2e --authority mandate --backend redis \
    --samples 500 --warmup 50 --output benchmarks/results/e2e_mandate_redis.json
```

The raw JSON this produced is committed at `benchmarks/results/*.json` —
regenerate it any time to confirm; numbers will differ by host.

## 3. Measured results (this sandbox; see each JSON file's `environment` block)

All runs: single process, `--concurrency 1` (sequential), git commit `357dfdd` (parent main; this PR's own commit is on top). CPU count reported by the host: 4 (shared, not dedicated — see caveats below).

### 3a. Pure authority overhead (`--mode auth`) — in-memory only, no I/O

Token issuance + `MandateAuthority.authorize()` + `ExecutionGate.verify()`, no idempotency/velocity/audit/dispatch.

| Backend | Samples | p50 | p95 | p99 | Throughput |
| --- | --- | --- | --- | --- | --- |
| memory | 2000 | 0.47 ms | 0.74 ms | 0.83 ms | ~1884 ops/s |

### 3b. Full end-to-end (`--mode e2e`) — decision → Gate → idempotency → velocity → audit → dispatch → receipt

| Authority | Backend | Samples | p50 | p95 | p99 | Throughput | Actuator calls |
| --- | --- | --- | --- | --- | --- | --- | --- |
| mandate | memory | 2000 | 3.94 ms | 6.46 ms | 9.15 ms | ~245 ops/s | 2000 (== samples) |
| delegation | memory | 2000 | 3.36 ms | 6.46 ms | 11.13 ms | ~269 ops/s | 2000 (== samples) |
| mandate | **real Redis** | 500 | 3.46 ms | 5.28 ms | 8.17 ms | ~271 ops/s | 500 (== samples) |

**In-memory and real-Redis numbers are never conflated** — they are separate
rows above and separate JSON files, exactly per the brief's requirement.
`p99` is reported for every row above because every row has ≥500 samples
(the harness refuses to print `p99` below 100 samples — see
`MIN_SAMPLES_FOR_P99` in `run_benchmark.py` — rather than print a
statistically meaningless tail estimate).

### 3c. A real, profiled bottleneck — not conflated into the numbers above, reported separately

Running a `cProfile` session over 1500 sequential `execute_with_mandate` calls
against the in-memory backend (not part of the committed JSON results; a
one-off diagnostic, reproducible with `python -m cProfile` wrapping the same
call) attributes the dominant cost to `AuditLog.append()` →
`AuditLog._read_last_entry()` (`src/mcc_core/audit.py:86`): **~46% of total
wall time**, plus the `posix.fsync` call inside `append()`
(`audit.py:202`): **~23%** — together roughly **two-thirds of total
end-to-end latency** in this profiling run.

The reason, confirmed by reading the code (not guessed): `_read_last_entry()`
does a full linear scan of the **entire** audit file on every single
`append()` call, specifically so the hash-chain's `prev_hash` is never
trusted from an in-memory cache that another process could have raced past
(`audit.py`'s own class docstring: *"No in-memory `prev_hash` is ever
authoritative"*). This is a deliberate, documented correctness/tamper-safety
choice, not an oversight — but it does make each `append()` cost `O(current
file size)`, so a long-lived audit log makes every *subsequent* operation
proportionally slower. This was also directly observable in this harness: a
2000-sample run measured a noticeably higher p50 (3.9 ms) than an earlier,
smaller 100-sample sanity run of the identical code path (~1.2 ms) taken
while building this harness — consistent with `O(n)`-per-append growth, not
noise.

**This PR does not attempt to fix or optimize this.** The audit hash-chain
is the most security-critical correctness mechanism in the codebase, its
current behavior is deliberate and documented, and any change to it (e.g.
caching the last hash in-process when single-writer, falling back to a real
re-read only when cross-process contention is possible, or an efficient
tail-read instead of a full scan) needs its own careful, separately
reviewed design and adversarial test — exactly the "profile first, optimize
second" and "if safe optimization not demonstrated, deliver the baseline
and do not make an optimization claim" instructions this workstream was
given. **No optimization is shipped in this PR.**

## 4. Adversarial / negative-control coverage (latency-adjacent, not latency measurement)

`tests/test_p2a_authority_plane_negative_controls.py` (16 tests, all
asserting the **exact** actuator-call count via the real `Stack.seen`
counter — never just a status string): non-vacuity baselines for both
mandate and delegation; DENY on out-of-scope action and on an unclampable
constraint breach; CONSTRAIN executing only the clamped payload (never the
originally-proposed one); the full ESCALATE loop (create → approve →
execute) plus replay-of-a-consumed-approval denial; revocation between
issuance and actuation; mandate and delegation expiry; delegation payload
substitution (recipient, currency); double-spend via transaction splitting
against a delegation's own cumulative ceiling; concurrent contended spend
under `asyncio.gather` never exceeding the ceiling; identical-token nonce
replay; an untrusted/failing clock source blocking closed. Every case above
asserts zero (or the exact expected nonzero) actuator invocations.

While building this suite, two real bugs were found and fixed —
**both in the benchmark/test harness, neither in production code**:

1. `benchmarks/workload.py`'s `build_stack()` initially constructed the
   `EnforcementCoordinator` and the `GovernanceService` with **two separate**
   `ApprovalService` instances. The coordinator never saw the service's
   minted approvals, so single-use consumption was silently skipped and an
   approval replayed successfully — caught by
   `test_escalate_approval_replay_denied_zero_additional_actuator_calls`
   failing. Fixed by sharing one `ApprovalService` instance between both
   (exactly how `gateway/governance_api.py`'s real
   `build_governance_service()` already wires it).
2. The benchmark CLI's real-Redis mode reused a fixed-pattern idempotency
   key (`bench-e2e-mandate-1`, `-2`, ...) that collides across **separate
   process invocations** against the same persistent Redis instance — the
   coordinator correctly refused to re-actuate an already-`EXECUTED` key
   from a prior run. This was the governed stack's idempotency protection
   working as designed, not a defect; fixed by prefixing every key with a
   fresh `uuid4` per invocation.

## 5. What was NOT implemented, and why

No caching, memoization, or any other optimization of the authority/gate
path is implemented in this PR. The brief permits a narrowly-scoped cache
*only* for immutable signature-verification facts, with a demonstrated
invalidation model and a test proving the final actuation boundary still
independently re-checks policy version, time, nonce, revocation, aggregate
budget, tenant, exact payload hash, and the operation's logical identity.
Building and proving that safely was judged to need its own dedicated,
carefully reviewed change — not something to bundle into a baseline
measurement PR under time pressure. **Baseline only; "optimized" is not
claimed anywhere in this PR.**

## 6. Exit gates (from the P2-A brief) — honest status

- [x] Runnable, reproducible harness (`benchmarks/run_benchmark.py`), raw JSON results committed, documented topology (single-process, this sandbox host), exact commit SHA in every result file's `environment` block.
- [x] Measured p50/p95/p99 and throughput for the specified workload, with the caveats in §3 above (shared/non-dedicated host, `p99` suppressed below 100 samples, throughput is summed-per-op wall time, not a dedicated total-run clock).
- [x] In-memory and real-Redis results explicitly distinguished (separate rows, separate files; real-Redis section never averaged into memory numbers).
- [x] Zero unauthorized actuator calls in every adversarial test (§4); no bypass of any mandatory authority check.
- [ ] Full regression and independent assurance pass on exact code under review — **run and reported in the PR description** (this doc does not restate exact pass/fail counts; see the PR body for the authoritative numbers at the exact commit merged).
- [x] Small, scoped PR; AX decides merge. Optimizations actually implemented: **none** — baseline only, stated explicitly, not implied.

## 7. What remains unproven / explicit gaps

- **No dedicated hardware.** This sandbox is a shared-tenancy container (`cpu_count=4` reported, not a guarantee of 4 dedicated cores); absolute numbers will differ, likely substantially, on real deployment hardware.
- **No sustained/soak load.** All runs are short (500–2000 sequential operations); no measurement of behavior under sustained multi-minute load, memory growth, or GC pressure.
- **No concurrency sweep beyond the adversarial contention test.** The benchmark CLI supports `--concurrency`, but no systematic concurrency-vs-latency curve was measured for this PR — only `concurrency=1` numbers are reported above, plus one adversarial correctness test at concurrency=12 (§4), which is NOT a throughput measurement.
- **No Docker/multi-instance topology.** The Docker daemon is unavailable in this sandbox; no containerized or multi-process-across-hosts measurement was attempted here (that is P2-B's explicit concern in any case).
- **The audit-log bottleneck identified in §3c is unresolved.** It is documented, not fixed; any fix needs its own dedicated, reviewed PR.
- **No production SLA is claimed, implied, or should be inferred from any number in this document.**
