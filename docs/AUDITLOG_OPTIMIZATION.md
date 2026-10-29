# P2-A2 — Production AuditLog Performance Optimization

**Status: production code change.** Unlike the companion P2-A (`docs/LOW_LATENCY_AUTHORITY_PLANE.md`,
baseline-only, no optimization) and P2-B (`docs/HA_SAFE_DEGRADATION.md`,
evidence-only, no source change) workstreams, this PR DOES change
`src/mcc_core/audit.py` — the append-only hash-chain audit log, the single
most safety-critical correctness mechanism in the codebase. Every claim
below is backed by a real measurement or a real test in this repository;
see §7 for what remains genuinely unproven.

## 1. The verified bottleneck (PR #126)

`AuditLog._read_last_entry()` did a full forward linear scan of the
**entire** audit file on every single `append()` call, specifically to
re-read the authoritative on-disk chain head (the class's own `prev_hash`
in-memory field is documented as a non-authoritative local cache that must
never be trusted for a real write — see the class docstring, unchanged by
this PR). PR #126's `cProfile` run attributed ~46% of end-to-end latency to
this scan and ~23% to the subsequent mandatory `fsync`, together ~2/3 of
total latency, with the scan's cost growing with file size (`O(n)` per
append → `O(n²)` total over `n` appends), while `fsync`'s cost does not.

## 2. The fix

`_read_last_entry()` now calls a new helper, `_tail_last_nonblank_line()`,
which finds the last non-blank line by seeking from the end of the file and
reading backward in growing chunks (4 KiB, doubling, capped at 1 MiB) —
the standard `tail`-style technique — instead of reading the whole file
forward. This is **O(size of the last entry + trailing blank lines)**, not
`O(file size)`.

Everything else is unchanged:

- Still called under the exact same `fcntl.flock` cross-process lock, at
  the exact same point in `append()`'s critical section.
- `self.prev_hash` is still never trusted for a real write — every
  `append()` still re-reads the true on-disk head from disk while holding
  the lock; the only thing that changed is *how much of the file* that
  re-read touches.
- `verify_chain()` is **untouched** — it is a one-time, on-demand, full
  offline integrity check (not a hot path; PR #126's own profile confirmed
  this), and remains a full forward scan on purpose.
- `append()`'s write/flush/`fsync`/rollback-on-failure sequence is
  **untouched**. `fsync` is never disabled, skipped, or made conditional.
- `AuditLog.__init__`'s best-effort constructor-time read and `append()`'s
  authoritative read both go through the SAME new helper — one
  implementation, two call sites, exactly as before.

### 2.1 Exception-behavior parity (why this is safe to trust)

The old implementation's text-mode line iterator decoded each line lazily
as it scanned; a `UnicodeDecodeError` on *any* line — including the last
one — was never actually caught by `_read_last_entry()`'s own
`except (json.JSONDecodeError, UnicodeDecodeError)` block (that block
wraps `json.loads(str)`, which cannot itself raise `UnicodeDecodeError` —
decoding had already happened, or already failed raw, by the time that
line ran). The new implementation preserves this exactly: the tail-read
helper returns raw bytes, and `_read_last_entry()` decodes the chosen
candidate line at the exact point the old line-iterator would have, so a
bad-UTF-8 *last* line still raises the same raw `UnicodeDecodeError`, and a
JSON-invalid-but-valid-UTF-8 *last* line still raises the same
`AuditCorruptionError`. See `tests/test_audit_tail_read.py`'s
`test_corrupted_last_line_invalid_utf8_raises_identically` and
`test_corrupted_last_line_invalid_json_but_valid_utf8`.

### 2.2 The one disclosed, deliberate scope difference

The old implementation, as an unavoidable side effect of reading every
byte of the file, would also raise on invalid UTF-8 in lines **other
than** the last one — crashing every future `append()` on a historical,
otherwise-irrelevant byte-level defect, forever, even though
`AuditCorruptionError`'s own docstring frames the guarantee specifically in
terms of **the last record** ("must never be silently treated as 'no
entries yet'"). This was never a documented contract of
`_read_last_entry()`; it was incidental. The optimized tail-read does not
read those earlier bytes and therefore does not detect that case — hot-path
`append()`s and startup both succeed normally even with old, irrelevant
corruption earlier in the file; whole-file integrity, including that exact
case, remains `verify_chain()`'s job, unaffected by this change. This is
pinned down by an exact test, not left as prose:
`tests/test_audit_tail_read.py::test_corrupted_non_last_line_is_not_detected_by_tail_read_but_is_by_verify_chain`.

This is judged the more conservative choice available, not a weaker one:
the alternative (keep reading the whole file, just to preserve an
undocumented side effect) would defeat the entire optimization.

## 3. Non-vacuity: proving the replacement is equivalent

`tests/test_audit_tail_read.py` keeps the OLD forward-scan algorithm as a
test-only reference implementation (never shipped in production code,
clearly labeled) and differentially compares it against the new tail-read
over: empty files; blank-only files; single entries with/without a
trailing newline; many entries with 0/1/2/5/20 trailing blank lines;
non-ASCII UTF-8 content (including content deliberately sized to straddle
the tail-read's chunk-size boundary at ±1/2/3 bytes); a corrupted last line
(invalid JSON, and separately invalid UTF-8); files from 1 KB to ~2 MB; and
a 200-trial randomized fuzz corpus. A separate test instruments actual
bytes read from disk against a ~2 MB, 200,000-entry file and asserts the
tail-read pulls under 200 KB total — proving the read pattern is genuinely
bounded, not just "fast in practice." **27/27 of these tests pass.**

## 4. Before/after measurement

Methodology: `benchmarks/run_audit_benchmark.py` (new; extends the P2-A
harness, does not duplicate it) seeds a fresh audit file with N prior
entries, then measures, on that fixed-size file: (a) `N` isolated calls to
`AuditLog._read_last_entry()` alone; (b) `N` real end-to-end
`AuditLog.append()` calls; (c) `N` isolated raw write+flush+`fsync` cycles
with no `AuditLog` involved at all (the irreducible durability floor this
PR never touches). The exact same script was run twice on the same host,
back to back: once against the genuine pre-optimization `audit.py` (byte
for byte, via `git show <before-SHA>:src/mcc_core/audit.py` — never
reconstructed from memory), once against the optimized version. Raw JSON
for every run is committed under `benchmarks/results/audit_*.json`.

**Before:** commit `6f71950` (`main`, pre-optimization). **After:** this
PR's own HEAD commit (see the PR description for the exact SHA merged).
Host: the same shared, non-dedicated sandbox as PR #126 (`cpu_count=4`
reported, not a guarantee of 4 dedicated cores) — not a production SLA.

| Seeded entries | File size | Metric | Before (p50) | After (p50) | Speedup (p50) | Before (p95) | After (p95) | Speedup (p95) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 100 | 26.8 KB | `_read_last_entry` alone | 41.8 µs | 12.1 µs | **3.4×** | 70.7 µs | 22.9 µs | 3.1× |
| 100 | 26.8 KB | full `append()` | 328.3 µs | 236.8 µs | **1.4×** | 529.6 µs | 406.1 µs | 1.3× |
| 5,000 | 1.35 MB | `_read_last_entry` alone | 957.7 µs | 11.9 µs | **80.4×** | 1344.0 µs | 17.2 µs | 78.1× |
| 5,000 | 1.35 MB | full `append()` | 2046.1 µs | 274.8 µs | **7.4×** | 3044.4 µs | 469.4 µs | 6.5× |
| 50,000 | 13.6 MB | `_read_last_entry` alone | 9289.7 µs | 19.6 µs | **473.2×** | 14160.8 µs | 27.7 µs | 511.0× |
| 50,000 | 13.6 MB | full `append()` | 9919.5 µs | 298.7 µs | **33.2×** | 12778.5 µs | 433.2 µs | 29.5× |

`raw_fsync` (no `AuditLog` involved): 129.1–195.0 µs before, 171.7–198.9 µs
after across all three sizes — statistically the same regardless of file
size or implementation, as expected, confirming the fix touches only the
read path and the mandatory durability floor is unchanged.

**Growth rate directly confirms the complexity-class change.** Reading the
`_read_last_entry` column alone: the OLD implementation's p50 grows
roughly linearly with file size (41.8 µs → 957.7 µs → 9289.7 µs as the file
grows ~26 KB → 1.35 MB → 13.6 MB, a ~500× size growth tracked by a ~220×
time growth — consistent with `O(n)`, not exact only because smaller files
have proportionally more fixed overhead). The NEW implementation's p50
stays flat within measurement noise (12.1 µs → 11.9 µs → 19.6 µs) across
that same ~500× file-size growth — the defining signature of `O(tail)`
rather than `O(file size)`. A separate instrumented test
(`test_tail_read_does_not_read_whole_large_file` in
`tests/test_audit_tail_read.py`) independently confirms this by counting
actual bytes read from disk, not just timing.

This was also observed directly while producing this document: seeding
the 50,000-entry file through the OLD implementation (every one of the
50,000 seed appends itself re-scanning the file-so-far) took **over four
minutes of wall-clock time** before the measurement loop above even began
— consistent with `O(n²)` total cost for `n` sequential appends — while
the identical seed operation against the OPTIMIZED implementation
completed in a few seconds.

`append()`'s smaller overall speedup (33.2× vs. 473.2× for the read alone
at 50,000 entries) is expected and correct — it reflects the mandatory,
unavoidable, and UNCHANGED `fsync` floor (~130–200 µs) increasingly
dominating total latency as the scan cost is removed, not a limitation of
the fix.

## 5. Adversarial regression coverage

`tests/test_audit_optimization_regression.py` (10 tests, all using real OS
processes where the property being tested is cross-process, never an
in-process simulation of a cross-process concern):

| Test | Proves |
| --- | --- |
| `test_concurrent_real_process_appends_never_corrupt_the_chain` | 12 real separate OS processes appending concurrently → the `fcntl.flock` lock still fully serializes them; `verify_chain()` passes |
| `test_concurrent_appends_plus_concurrent_reads_stay_consistent` | Fresh `AuditLog` construction (which tail-reads) during concurrent real writes never observes a hash that isn't genuinely in the final valid chain |
| `test_crash_before_fsync_leaves_a_recoverable_consistent_file` | A real `SIGKILL` exactly at the `fsync()` call leaves only whole, parseable lines; a fresh instance recovers and appends cleanly afterward |
| `test_crash_while_holding_lock_auto_releases_for_the_next_writer` | A real process `SIGKILL`ed while holding the lock does not deadlock the next writer (OS-level `flock` release on process death) |
| `test_corrupted_last_line_fails_closed_on_append_not_a_silent_chain_restart` | A corrupted last line still raises `AuditCorruptionError` on `append()`, never silently restarts the chain |
| `test_verify_chain_detects_a_broken_link_anywhere_in_the_file` | Tampering with `prev_hash` anywhere in the file is still caught by `verify_chain()` |
| `test_write_failure_rolls_back_and_reraises_file_unchanged` | A simulated `ENOSPC` at `fsync()` still rolls back to the exact pre-attempt file size and re-raises; a retry still succeeds |
| `test_lock_timeout_behavior_unchanged` | `AuditLockError`'s timeout is unchanged by this PR |
| `test_stale_in_memory_prev_hash_is_never_used_for_a_real_append` | A deliberately-staled in-memory cache is proven, by actual chain content, never to leak into a real write |
| `test_governed_stack_actuator_call_counts_unaffected_by_the_optimization` | A DENY still yields zero actuator calls and an ALLOW still yields exactly one, through the real coordinator, with the optimized `AuditLog` backing it |

All 10 pass. Combined with the 27 differential tests in §3, this PR adds
**37 new tests**, all passing.

## 6. Exit-gate matrix

| Item | Status |
| --- | --- |
| Separate scan vs. fsync overhead measurement | **PASS** — §4 |
| Safe production optimization preserving hash-chain integrity | **PASS** — §2, §3 |
| Cross-process write serialization preserved | **PASS** — `test_concurrent_real_process_appends_never_corrupt_the_chain` |
| Crash durability and `fsync` preserved (never disabled) | **PASS** — §2, `test_crash_before_fsync_leaves_a_recoverable_consistent_file`, raw-fsync floor unchanged in §4 |
| Atomic append semantics preserved | **PASS** — `append()` body untouched |
| Fail-closed behavior preserved | **PASS** — `test_corrupted_last_line_fails_closed_on_append_not_a_silent_chain_restart`, `test_write_failure_rolls_back_and_reraises_file_unchanged`, `test_lock_timeout_behavior_unchanged` |
| Independent execution authority unaffected | **PASS** — `test_governed_stack_actuator_call_counts_unaffected_by_the_optimization`; no file under `gate.py`/`coordinator.py`/`authority.py`/`delegation.py`/`mandate.py` touched |
| No unsafe authorization cache introduced | **PASS** — `self.prev_hash` still never authoritative; `test_stale_in_memory_prev_hash_is_never_used_for_a_real_append` |
| Benchmark harness extended with before/after comparison | **PASS** — §4, `benchmarks/run_audit_benchmark.py` |
| Adversarial regression tests (concurrency, crash, corruption, storage errors, lock contention, stale state) | **PASS** — §5 |
| Zero unauthorized actuator calls | **PASS** — §5 last row |
| Full regression suite unaffected | **PASS** — see PR description for the exact run on this PR's head |
| `make verify-assurance` (independent-assurance + TLA+ + mutation) unaffected | **PASS** — see PR description |
| True power-loss-before-fsync durability (not just process death) | **NOT PROVEN** — this sandbox cannot safely simulate real power loss / page-cache eviction; `test_crash_before_fsync_leaves_a_recoverable_consistent_file` proves process-death recovery, which is a real but narrower guarantee (see §7) |
| Dedicated-hardware / production-scale throughput numbers | **NOT PROVEN** — shared sandbox host only, explicitly not an SLA (§4, §7) |

## 7. Residual risks and what remains genuinely unproven

- **Real power loss is not simulated.** Every crash test here uses a real
  `SIGKILL`, which reliably exercises process-death semantics (lock
  auto-release, no in-process cleanup handlers run) but the OS page cache
  survives process death — only an actual power/hardware failure, or a
  kernel-level crash, would test whether `fsync`'s durability guarantee
  itself holds on the underlying storage. That guarantee is `fsync`'s
  documented contract, not something this PR introduces or could prove
  from user space; this PR's job was to never weaken or bypass it, which
  it does not (§2, §4's unchanged raw-fsync floor).
- **No multi-host / genuinely separate-filesystem concurrent-writer test.**
  All concurrency tests in §5 use real, separate OS processes, but on one
  host sharing one filesystem. `fcntl.flock` is a local, POSIX advisory
  lock; this PR makes no change to, and no new claim about, any
  network-filesystem or multi-host locking semantics (out of scope —
  consistent with the existing `AuditLog` design, which was never
  described as multi-host-safe).
- **Benchmark numbers are from one shared, non-dedicated sandbox host** and
  are relative-improvement evidence, not an absolute production latency
  guarantee.
- **The `_TAIL_INITIAL_CHUNK_BYTES`/`_TAIL_MAX_CHUNK_BYTES` tuning
  (4 KiB → 1 MiB, doubling) is a reasonable default, not something swept
  across values and benchmarked for an optimum** — a real production audit
  entry is typically well under 1 KB, so the common case needs at most one
  read; this was judged sufficient rather than over-engineered for this PR.
- **No change was made to, or benchmark taken of, `verify_chain()`** — it
  remains a full scan by design (an on-demand, offline integrity check, not
  a hot path), and this PR does not claim anything about its performance.
