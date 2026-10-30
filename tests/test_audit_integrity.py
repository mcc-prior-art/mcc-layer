"""P2-A3 -- AuditIntegrityMonitor unit tests: state machine, the explicit
trusted-bootstrap policy, freshness/staleness, registry backend-down
fail-closed behavior, multi-worker (shared Redis) visibility, and the
hard O(tail)-preserving guarantee that ``AuditLog.append()`` never
triggers a full-chain scan.

Complements ``tests/test_audit_integrity_enforcement.py`` (the two
enforcement boundaries, end-to-end, through the real
EnforcementCoordinator/GovernanceService).
"""

from __future__ import annotations

import asyncio
import tempfile
import threading
import time
from pathlib import Path

import pytest

from mcc_core.audit import GENESIS, AuditLog
from mcc_core.audit_integrity import (
    AuditIntegrityMonitor,
    IntegrityBackendUnavailable,
    IntegrityConfigError,
    IntegrityState,
    InMemoryIntegrityStateRegistry,
    RedisIntegrityStateRegistry,
    integrity_state_registry_from_env,
    is_healthy,
)
from mcc_core.trusted_time import TimeTrustError, TrustedTimeSource

run = asyncio.run


def _audit(tmp_path: Path) -> AuditLog:
    return AuditLog(str(tmp_path / "audit.jsonl"))


class _FixedTime(TrustedTimeSource):
    def __init__(self, t: int) -> None:
        self.t = t

    async def now(self) -> int:
        return self.t


class _FailingTime(TrustedTimeSource):
    async def now(self) -> int:
        raise TimeTrustError("CLOCK_UNTRUSTED", "test-injected failure")


# ---------------------------------------------------------------------------
# is_healthy / state machine basics
# ---------------------------------------------------------------------------


def test_is_healthy_only_true_for_healthy():
    assert is_healthy(IntegrityState.HEALTHY) is True
    for s in (IntegrityState.UNVERIFIED, IntegrityState.VERIFYING, IntegrityState.UNHEALTHY):
        assert is_healthy(s) is False


def test_unverified_before_any_pass(tmp_path):
    mon = AuditIntegrityMonitor(_audit(tmp_path), InMemoryIntegrityStateRegistry())
    assert run(mon.current_state()) == IntegrityState.UNVERIFIED


def test_healthy_after_intact_chain(tmp_path):
    log = _audit(tmp_path)
    for i in range(10):
        log.append({"i": i})
    mon = AuditIntegrityMonitor(log, InMemoryIntegrityStateRegistry())
    assert run(mon.verify_once()) == IntegrityState.HEALTHY
    assert run(mon.current_state()) == IntegrityState.HEALTHY


@pytest.mark.parametrize("corruption", ["broken_hash_link", "malformed_json", "truncated"])
def test_unhealthy_after_genuine_corruption(tmp_path, corruption):
    log = _audit(tmp_path)
    for i in range(5):
        log.append({"i": i})

    if corruption == "broken_hash_link":
        with open(log.path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
        import json as _json

        mid = _json.loads(lines[2])
        mid["prev_hash"] = "deadbeef" * 8
        lines[2] = _json.dumps(mid) + "\n"
        with open(log.path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
    elif corruption == "malformed_json":
        with open(log.path, "a", encoding="utf-8") as fh:
            fh.write("{not valid json\n")
    elif corruption == "truncated":
        size = Path(log.path).stat().st_size
        with open(log.path, "r+b") as fh:
            fh.truncate(size - 5)

    mon = AuditIntegrityMonitor(log, InMemoryIntegrityStateRegistry())
    assert run(mon.verify_once()) == IntegrityState.UNHEALTHY
    assert run(mon.current_state()) == IntegrityState.UNHEALTHY


def _slow_verify_harness(log, monkeypatch):
    """Shared fixture logic: monkeypatch AuditLog.verify_chain_safe to block
    on ``release`` so a test can observe current_state() mid-pass."""
    release = threading.Event()
    entered = threading.Event()
    real = AuditLog.verify_chain_safe

    def slow_verify(self):
        entered.set()
        release.wait(timeout=5)
        return real(self)

    monkeypatch.setattr(AuditLog, "verify_chain_safe", slow_verify)
    return release, entered


def test_first_ever_pass_is_unverified_while_in_flight(tmp_path, monkeypatch):
    """No durable record exists yet, so a concurrent in-flight FIRST pass
    must still report UNVERIFIED (never VERIFYING as a gating answer, and
    never a premature HEALTHY) -- unaffected by the Finding 4 fix below,
    which only changes behavior once a fresh HEALTHY record already
    exists."""
    log = _audit(tmp_path)
    log.append({"i": 0})
    mon = AuditIntegrityMonitor(log, InMemoryIntegrityStateRegistry())
    release, entered = _slow_verify_harness(log, monkeypatch)

    async def observe_during_pass():
        task = asyncio.create_task(mon.verify_once())
        await asyncio.get_event_loop().run_in_executor(None, entered.wait, 5)
        state_during = await mon.current_state()
        release.set()
        final_state = await task
        return state_during, final_state

    during, final = run(observe_during_pass())
    assert during == IntegrityState.UNVERIFIED
    assert final == IntegrityState.HEALTHY
    assert mon.verification_in_progress is False  # pass has completed


def test_routine_periodic_pass_does_not_block_gating_when_prior_result_is_fresh(
    tmp_path, monkeypatch,
):
    """Finding 4 (hardening round): once a fresh HEALTHY result is already
    durably recorded, a NEW (e.g. routine periodic) pass running
    concurrently must NOT cause current_state() to block gating -- the
    last COMPLETED result is still trustworthy and fresh, so blocking here
    would be a pure, avoidable, self-inflicted outage with no security
    benefit. ``verification_in_progress`` still observes the in-flight
    pass, but only as diagnostic information, never for gating."""
    log = _audit(tmp_path)
    log.append({"i": 0})
    mon = AuditIntegrityMonitor(log, InMemoryIntegrityStateRegistry())
    assert run(mon.verify_once()) == IntegrityState.HEALTHY  # establishes the prior HEALTHY

    release, entered = _slow_verify_harness(log, monkeypatch)

    async def observe_during_second_pass():
        task = asyncio.create_task(mon.verify_once())
        await asyncio.get_event_loop().run_in_executor(None, entered.wait, 5)
        state_during = await mon.current_state()
        in_progress_during = mon.verification_in_progress
        release.set()
        final_state = await task
        return state_during, in_progress_during, final_state

    during, in_progress_during, final = run(observe_during_second_pass())
    assert during == IntegrityState.HEALTHY, (
        "a routine periodic pass must not block an otherwise-authorized "
        "request while the prior, still-fresh HEALTHY result stands"
    )
    assert in_progress_during is True  # diagnostic signal still observable
    assert final == IntegrityState.HEALTHY


def test_non_vacuity_local_verifying_flag_would_have_blocked(tmp_path, monkeypatch):
    """Non-vacuity companion: reproduces the PRE-FIX behavior directly
    (gating on the local ``_verifying`` flag) to prove Finding 4's bug was
    real and that the test above would have caught its absence."""
    log = _audit(tmp_path)
    log.append({"i": 0})
    mon = AuditIntegrityMonitor(log, InMemoryIntegrityStateRegistry())
    assert run(mon.verify_once()) == IntegrityState.HEALTHY

    release, entered = _slow_verify_harness(log, monkeypatch)

    async def pre_fix_current_state() -> IntegrityState:
        # The exact pre-fix short-circuit this hardening round removed.
        if mon.verification_in_progress:
            return IntegrityState.VERIFYING
        return await mon.current_state()

    async def observe():
        task = asyncio.create_task(mon.verify_once())
        await asyncio.get_event_loop().run_in_executor(None, entered.wait, 5)
        state_during = await pre_fix_current_state()
        release.set()
        await task
        return state_during

    during = run(observe())
    assert during == IntegrityState.VERIFYING, (
        "expected the reproduced pre-fix logic to incorrectly block here -- "
        "if it no longer does, this non-vacuity check itself needs revisiting"
    )


# ---------------------------------------------------------------------------
# Explicit trusted-bootstrap policy
# ---------------------------------------------------------------------------


def test_missing_file_unhealthy_by_default(tmp_path):
    mon = AuditIntegrityMonitor(_audit(tmp_path), InMemoryIntegrityStateRegistry())
    # The file genuinely does not exist on disk yet (AuditLog's constructor
    # only reads, never creates it).
    assert not Path(mon._audit.path).exists()
    assert run(mon.verify_once()) == IntegrityState.UNHEALTHY


def test_missing_file_healthy_only_with_explicit_bootstrap_flag(tmp_path):
    mon = AuditIntegrityMonitor(
        _audit(tmp_path), InMemoryIntegrityStateRegistry(), allow_empty_bootstrap=True,
    )
    assert run(mon.verify_once()) == IntegrityState.HEALTHY


def test_empty_file_unhealthy_by_default(tmp_path):
    log = _audit(tmp_path)
    Path(log.path).write_text("", encoding="utf-8")
    mon = AuditIntegrityMonitor(log, InMemoryIntegrityStateRegistry())
    assert run(mon.verify_once()) == IntegrityState.UNHEALTHY


def test_empty_file_healthy_with_explicit_bootstrap_flag(tmp_path):
    log = _audit(tmp_path)
    Path(log.path).write_text("", encoding="utf-8")
    mon = AuditIntegrityMonitor(
        log, InMemoryIntegrityStateRegistry(), allow_empty_bootstrap=True,
    )
    assert run(mon.verify_once()) == IntegrityState.HEALTHY


# ---------------------------------------------------------------------------
# Freshness / staleness -- the "verifier silently died" bypass
# ---------------------------------------------------------------------------


def test_stale_healthy_reports_unhealthy():
    clock = _FixedTime(1_000_000)
    registry = InMemoryIntegrityStateRegistry()
    run(registry.set_if_newer(generation=1, state=IntegrityState.HEALTHY,
                               reason="was fine", verified_at=1_000_000))
    mon = AuditIntegrityMonitor(
        AuditLog(str(tempfile.mkdtemp()) + "/a.jsonl"), registry,
        freshness_grace_seconds=100, time_source=clock,
    )
    assert run(mon.current_state()) == IntegrityState.HEALTHY
    clock.t = 1_000_000 + 101  # just past the grace window
    assert run(mon.current_state()) == IntegrityState.UNHEALTHY


def test_fresh_healthy_within_grace_window_stays_healthy():
    clock = _FixedTime(1_000_000)
    registry = InMemoryIntegrityStateRegistry()
    run(registry.set_if_newer(generation=1, state=IntegrityState.HEALTHY,
                               reason="was fine", verified_at=1_000_000))
    mon = AuditIntegrityMonitor(
        AuditLog(str(tempfile.mkdtemp()) + "/a.jsonl"), registry,
        freshness_grace_seconds=100, time_source=clock,
    )
    clock.t = 1_000_000 + 99
    assert run(mon.current_state()) == IntegrityState.HEALTHY


def test_untrusted_clock_during_verify_once_fails_closed(tmp_path):
    log = _audit(tmp_path)
    log.append({"i": 0})
    mon = AuditIntegrityMonitor(
        log, InMemoryIntegrityStateRegistry(), time_source=_FailingTime(),
    )
    assert run(mon.verify_once()) == IntegrityState.UNHEALTHY


def test_untrusted_clock_during_current_state_fails_closed():
    registry = InMemoryIntegrityStateRegistry()
    run(registry.set_if_newer(generation=1, state=IntegrityState.HEALTHY,
                               reason="fine", verified_at=1))
    mon = AuditIntegrityMonitor(
        AuditLog(str(tempfile.mkdtemp()) + "/a.jsonl"), registry,
        time_source=_FailingTime(),
    )
    assert run(mon.current_state()) == IntegrityState.UNHEALTHY


# ---------------------------------------------------------------------------
# Trusted recovery -- explicit, deliberate, never silent
# ---------------------------------------------------------------------------


def test_recovery_from_unhealthy_requires_an_explicit_new_pass(tmp_path):
    log = _audit(tmp_path)
    log.append({"i": 0})
    mon = AuditIntegrityMonitor(log, InMemoryIntegrityStateRegistry())
    with open(log.path, "a", encoding="utf-8") as fh:
        fh.write("garbage\n")
    assert run(mon.verify_once()) == IntegrityState.UNHEALTHY
    # Still unhealthy on a plain read -- no silent self-healing.
    assert run(mon.current_state()) == IntegrityState.UNHEALTHY

    # Operator action: restore a genuinely intact file, then an explicit
    # new pass is required to move back to HEALTHY.
    Path(log.path).write_text("", encoding="utf-8")
    fresh = AuditLog(log.path)
    fresh.append({"i": 0})
    mon2 = AuditIntegrityMonitor(fresh, InMemoryIntegrityStateRegistry())
    assert run(mon2.verify_once()) == IntegrityState.HEALTHY


# ---------------------------------------------------------------------------
# Hardening round, Finding 1 (P1): one-time, not reusable, trusted bootstrap
# ---------------------------------------------------------------------------


def test_bootstrap_latch_blocks_reuse_even_across_a_fresh_process_restart(tmp_path):
    """The durable, cross-process latch (not just this process's own
    prev_hash fast path) must independently close the race: simulate a
    process restart by constructing a BRAND NEW AuditLog + AuditIntegrityMonitor
    (fresh ``prev_hash`` == GENESIS, as a real restarted process would have)
    against the SAME registry that already recorded "ever initialized"."""
    log = _audit(tmp_path)
    log.append({"seed": "real-history"})
    registry = InMemoryIntegrityStateRegistry()
    first_process_monitor = AuditIntegrityMonitor(log, registry, allow_empty_bootstrap=True)
    assert run(first_process_monitor.verify_once()) == IntegrityState.HEALTHY
    assert run(registry.is_initialized()) is True

    Path(log.path).unlink()

    # A fresh AuditLog instance against the now-deleted path has prev_hash
    # == GENESIS (it never itself appended anything) -- the ONLY thing that
    # can still catch this is the durable registry latch, not the
    # process-local fast path.
    restarted_log = AuditLog(log.path)
    assert restarted_log.prev_hash == GENESIS
    restarted_monitor = AuditIntegrityMonitor(
        restarted_log, registry, allow_empty_bootstrap=True,
    )
    assert run(restarted_monitor.verify_once()) == IntegrityState.UNHEALTHY


def test_bootstrap_latch_is_one_way_no_method_clears_it(tmp_path):
    log = _audit(tmp_path)
    log.append({"seed": "x"})
    registry = InMemoryIntegrityStateRegistry()
    mon = AuditIntegrityMonitor(log, registry, allow_empty_bootstrap=True)
    assert run(mon.verify_once()) == IntegrityState.HEALTHY
    assert run(registry.is_initialized()) is True
    # No public method on either registry clears this latch.
    public_methods = {n for n in dir(registry) if not n.startswith("_")}
    forbidden = {"clear_initialized", "reset_initialized", "unset_initialized", "clear", "reset"}
    assert not (public_methods & forbidden), public_methods & forbidden


def test_genesis_fingerprint_differs_for_different_logs_and_is_stable(tmp_path):
    log_a = AuditLog(str(tmp_path / "a.jsonl"))
    log_a.append({"seed": "A"})
    log_b = AuditLog(str(tmp_path / "b.jsonl"))
    log_b.append({"seed": "B"})

    fp_a1 = log_a.genesis_fingerprint_safe()
    fp_a2 = log_a.genesis_fingerprint_safe()
    fp_b = log_b.genesis_fingerprint_safe()

    assert fp_a1 is not None and fp_b is not None
    assert fp_a1 == fp_a2  # stable/deterministic for the same file
    assert fp_a1 != fp_b  # different for genuinely different logs

    log_a.append({"more": "entries"})
    fp_a3 = log_a.genesis_fingerprint_safe()
    assert fp_a3 == fp_a1  # identity is the GENESIS record, unaffected by later appends


def test_genesis_fingerprint_is_none_for_missing_or_empty_file(tmp_path):
    missing = _audit(tmp_path)
    assert missing.genesis_fingerprint_safe() is None
    Path(missing.path).write_text("", encoding="utf-8")
    assert missing.genesis_fingerprint_safe() is None


# ---------------------------------------------------------------------------
# Registry: InMemory generation CAS semantics
# ---------------------------------------------------------------------------


def test_inmemory_registry_rejects_stale_generation():
    reg = InMemoryIntegrityStateRegistry()
    assert run(reg.set_if_newer(generation=5, state=IntegrityState.HEALTHY,
                                 reason="a", verified_at=100)) is True
    # A write with a generation <= the stored one must never overwrite.
    assert run(reg.set_if_newer(generation=5, state=IntegrityState.UNHEALTHY,
                                 reason="stale-equal", verified_at=200)) is False
    assert run(reg.set_if_newer(generation=3, state=IntegrityState.UNHEALTHY,
                                 reason="stale-lower", verified_at=300)) is False
    status = run(reg.get())
    assert status.state == IntegrityState.HEALTHY
    assert status.reason == "a"

    assert run(reg.set_if_newer(generation=6, state=IntegrityState.UNHEALTHY,
                                 reason="genuinely newer", verified_at=400)) is True
    assert run(reg.get()).state == IntegrityState.UNHEALTHY


def test_inmemory_registry_generations_monotonic_across_concurrent_allocation():
    reg = InMemoryIntegrityStateRegistry()

    async def allocate_many():
        return await asyncio.gather(*[reg.allocate_generation() for _ in range(50)])

    gens = run(allocate_many())
    assert sorted(gens) == list(range(1, 51))
    assert len(set(gens)) == 50  # no two callers got the same generation


# ---------------------------------------------------------------------------
# Registry: modelled Redis -- CAS, malformed records, multi-worker sharing
# ---------------------------------------------------------------------------


class _FakeRedis:
    """Enough of the async redis surface (HGET/HSET/EVAL/INCR/HGETALL) to
    exercise RedisIntegrityStateRegistry's real Lua CAS script faithfully,
    mirroring the modelled-Redis style already used by
    tests/test_nonce.py / tests/test_challenge_redis.py. A shared ``store``
    models multiple registries talking to the SAME Redis instance."""

    def __init__(self, store=None):
        self.store = store if store is not None else {}  # key -> dict | int

    async def incr(self, key):
        self.store[key] = int(self.store.get(key, 0)) + 1
        return self.store[key]

    async def hgetall(self, key):
        val = self.store.get(key)
        return dict(val) if isinstance(val, dict) else {}

    async def eval(self, script, numkeys, key, *argv):
        assert script is not None and numkeys == 1
        generation, state, verified_at, reason, log_identity = argv
        cur = self.store.get(key)
        if isinstance(cur, dict) and int(cur.get("generation", -1)) >= int(generation):
            return 0
        prior = cur.get("log_identity") if isinstance(cur, dict) else None
        self.store[key] = {
            "generation": generation, "state": state,
            "last_verified_at": verified_at, "reason": reason,
            "log_identity": log_identity if log_identity else (prior or ""),
        }
        return 1

    async def set(self, key, value, nx=False):
        # Models Redis SET ... NX -- the bootstrap-latch primitive.
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    async def get(self, key):
        val = self.store.get(key)
        return val if isinstance(val, str) else None

    async def aclose(self):
        return None


class _BrokenRedis(_FakeRedis):
    async def incr(self, key):
        raise ConnectionError("redis unreachable (test double)")

    async def hgetall(self, key):
        raise ConnectionError("redis unreachable (test double)")

    async def eval(self, *a, **kw):
        raise ConnectionError("redis unreachable (test double)")

    async def set(self, *a, **kw):
        raise ConnectionError("redis unreachable (test double)")

    async def get(self, *a, **kw):
        raise ConnectionError("redis unreachable (test double)")


def test_redis_registry_cas_rejects_stale_write():
    redis = _FakeRedis()
    reg = RedisIntegrityStateRegistry(redis, key="mcc:test:integrity")
    assert run(reg.set_if_newer(generation=2, state=IntegrityState.HEALTHY,
                                 reason="ok", verified_at=10)) is True
    assert run(reg.set_if_newer(generation=1, state=IntegrityState.UNHEALTHY,
                                 reason="late/stale", verified_at=20)) is False
    status = run(reg.get())
    assert status.state == IntegrityState.HEALTHY and status.generation == 2


def test_redis_registry_backend_down_raises_backend_unavailable():
    reg = RedisIntegrityStateRegistry(_BrokenRedis(), key="mcc:test:integrity")
    with pytest.raises(IntegrityBackendUnavailable):
        run(reg.allocate_generation())
    with pytest.raises(IntegrityBackendUnavailable):
        run(reg.get())
    with pytest.raises(IntegrityBackendUnavailable):
        run(reg.set_if_newer(generation=1, state=IntegrityState.HEALTHY, reason="x", verified_at=1))


def test_monitor_current_state_unhealthy_when_redis_backend_down(tmp_path):
    log = _audit(tmp_path)
    log.append({"i": 0})
    mon = AuditIntegrityMonitor(log, RedisIntegrityStateRegistry(_BrokenRedis(), key="mcc:test:x"))
    # Backend down -> cannot even confirm "no record yet" vs "healthy" ->
    # fail closed, never silently treated as "skip the check".
    assert run(mon.current_state()) == IntegrityState.UNHEALTHY
    assert run(mon.verify_once()) == IntegrityState.UNHEALTHY


def test_multi_worker_corruption_visible_across_shared_redis(tmp_path):
    """Two independent AuditIntegrityMonitor instances (modelling two
    gateway worker processes), sharing one Redis (modelled) registry.
    Worker A's corruption detection must be immediately visible to
    worker B, which never itself ran a verification pass."""
    log = _audit(tmp_path)
    log.append({"i": 0})
    shared_store: dict = {}
    reg_a = RedisIntegrityStateRegistry(_FakeRedis(shared_store), key="mcc:test:shared")
    reg_b = RedisIntegrityStateRegistry(_FakeRedis(shared_store), key="mcc:test:shared")
    mon_a = AuditIntegrityMonitor(log, reg_a)
    mon_b = AuditIntegrityMonitor(log, reg_b)

    assert run(mon_a.verify_once()) == IntegrityState.HEALTHY
    assert run(mon_b.current_state()) == IntegrityState.HEALTHY  # B never ran a pass

    with open(log.path, "a", encoding="utf-8") as fh:
        fh.write("corrupt\n")
    assert run(mon_a.verify_once()) == IntegrityState.UNHEALTHY
    assert run(mon_b.current_state()) == IntegrityState.UNHEALTHY  # visible to B immediately


def test_redis_bootstrap_latch_is_atomic_first_writer_wins():
    shared_store: dict = {}
    reg_a = RedisIntegrityStateRegistry(_FakeRedis(shared_store), key="mcc:test:latch")
    reg_b = RedisIntegrityStateRegistry(_FakeRedis(shared_store), key="mcc:test:latch")
    assert run(reg_a.is_initialized()) is False
    assert run(reg_b.is_initialized()) is False

    run(reg_a.mark_initialized())
    # Visible to reg_b immediately (same underlying store -- models the
    # same real Redis instance).
    assert run(reg_b.is_initialized()) is True

    # A later caller's mark_initialized() is a durable no-op, never an
    # error and never any kind of "re-latch"/reset.
    run(reg_b.mark_initialized())
    assert run(reg_a.is_initialized()) is True


def test_redis_bootstrap_latch_backend_down_raises_backend_unavailable():
    reg = RedisIntegrityStateRegistry(_BrokenRedis(), key="mcc:test:latch-down")
    with pytest.raises(IntegrityBackendUnavailable):
        run(reg.mark_initialized())
    with pytest.raises(IntegrityBackendUnavailable):
        run(reg.is_initialized())


def test_malformed_redis_record_raises_backend_unavailable():
    redis = _FakeRedis({"mcc:test:bad": {"state": "HEALTHY"}})  # missing fields
    reg = RedisIntegrityStateRegistry(redis, key="mcc:test:bad")
    with pytest.raises(IntegrityBackendUnavailable):
        run(reg.get())


# ---------------------------------------------------------------------------
# integrity_state_registry_from_env -- no silent fallback
# ---------------------------------------------------------------------------


def test_from_env_defaults_to_in_memory():
    reg = integrity_state_registry_from_env({})
    assert isinstance(reg, InMemoryIntegrityStateRegistry)


def test_from_env_redis_without_url_raises_not_falls_back():
    with pytest.raises(IntegrityConfigError):
        integrity_state_registry_from_env({"MCC_AUDIT_INTEGRITY_BACKEND": "redis"})


def test_from_env_unknown_backend_raises():
    with pytest.raises(IntegrityConfigError):
        integrity_state_registry_from_env({"MCC_AUDIT_INTEGRITY_BACKEND": "carrier-pigeon"})


def test_from_env_redis_with_url_builds_redis_registry():
    reg = integrity_state_registry_from_env(
        {"MCC_AUDIT_INTEGRITY_BACKEND": "redis", "MCC_REDIS_URL": "redis://127.0.0.1:6379/0"}
    )
    assert isinstance(reg, RedisIntegrityStateRegistry)


# ---------------------------------------------------------------------------
# PR #128 invariant: append()'s hot path must NEVER trigger a full scan
# ---------------------------------------------------------------------------


def test_append_never_calls_verify_chain_or_verify_chain_safe(tmp_path, monkeypatch):
    log = _audit(tmp_path)

    def _boom(*a, **kw):
        raise AssertionError("append() must never trigger a full-chain verification")

    monkeypatch.setattr(AuditLog, "verify_chain", staticmethod(_boom))
    monkeypatch.setattr(AuditLog, "verify_chain_safe", _boom)
    for i in range(20):
        log.append({"i": i})  # would raise immediately if either were called


def test_periodic_verification_runs_off_the_hot_path_and_uses_a_worker_thread(tmp_path, monkeypatch):
    """verify_once() must not block the event loop: the blocking
    AuditLog.verify_chain_safe() call happens on a worker thread
    (asyncio.to_thread), never directly on the loop's own thread."""
    log = _audit(tmp_path)
    log.append({"i": 0})
    mon = AuditIntegrityMonitor(log, InMemoryIntegrityStateRegistry())

    loop_thread = threading.current_thread()
    seen_thread = {}

    real = AuditLog.verify_chain_safe

    def capture(self):
        seen_thread["thread"] = threading.current_thread()
        return real(self)

    monkeypatch.setattr(AuditLog, "verify_chain_safe", capture)
    assert run(mon.verify_once()) == IntegrityState.HEALTHY
    assert seen_thread["thread"] is not loop_thread


# ---------------------------------------------------------------------------
# Concurrency: verify_once() racing real append() calls (thread + real
# inter-process lock), proving AuditLog._locked() reuse is genuinely safe.
# ---------------------------------------------------------------------------


def test_verify_once_concurrent_with_real_appends_never_corrupts_or_raises(tmp_path):
    log = _audit(tmp_path)
    log.append({"i": -1})
    mon = AuditIntegrityMonitor(log, InMemoryIntegrityStateRegistry())

    stop = threading.Event()
    errors = []

    def writer():
        i = 0
        writer_log = AuditLog(log.path)
        while not stop.is_set():
            try:
                writer_log.append({"i": i})
                i += 1
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
            time.sleep(0.001)

    threads = [threading.Thread(target=writer) for _ in range(4)]
    for t in threads:
        t.start()

    results = []
    try:
        for _ in range(15):
            results.append(run(mon.verify_once()))
            time.sleep(0.01)
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=5)

    assert not errors, f"concurrent append() raised: {errors}"
    # Every pass that ran must have seen a genuinely intact chain -- a
    # verification racing a writer must never observe a half-written
    # record (that's exactly what AuditLog._locked() reuse guarantees).
    assert all(r == IntegrityState.HEALTHY for r in results), results
    assert AuditLog.verify_chain(log.path) is True
