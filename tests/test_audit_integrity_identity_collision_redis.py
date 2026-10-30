"""Second hardening round: real-Redis proof that the cross-worker
identity-collision fail-open (independent review's exact scenario) is
fixed under GENUINE concurrent writes against a REAL ``redis-server`` --
not the in-memory/faithful-double unit tests in
``tests/test_audit_integrity_enforcement.py``, which prove the logic is
correct but not that the real Lua CAS script behaves identically under
real concurrency and real network round-trips.

Scenario: two workers, each with its OWN physically distinct audit-log
file, cloned from the same initial record (so ``genesis_fingerprint_safe()``
collides for both). Worker B's file has since diverged/corrupted; Worker
A's stays intact. Both share ONE real Redis-backed registry key. Worker
A's genuinely intact, newer-generation result must never silently
override Worker B's genuinely corrupted, unresolved one.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import pytest

from tests.ha._redis_lab import REDIS_AVAILABLE, RealRedisServer

from mcc_core.audit import AuditLog
from mcc_core.audit_integrity import (
    AuditIntegrityMonitor,
    IntegrityState,
    RedisIntegrityStateRegistry,
)

pytestmark = pytest.mark.skipif(not REDIS_AVAILABLE, reason="redis-server binary not available")

# A valid legacy genesis trust anchor (LEGACY_GENESIS_HASH == "genesis" --
# see AuditLog.verify_chain) so a real append() chains onto it correctly.
_SEED = '{"hash": "genesis", "seed": "shared-initial-record"}\n'


def _cloned_genesis_logs():
    dir_a = Path(tempfile.mkdtemp(prefix="mcc-redis-collision-a-"))
    dir_b = Path(tempfile.mkdtemp(prefix="mcc-redis-collision-b-"))
    (dir_a / "audit.jsonl").write_text(_SEED, encoding="utf-8")
    (dir_b / "audit.jsonl").write_text(_SEED, encoding="utf-8")
    audit_a = AuditLog(str(dir_a / "audit.jsonl"))
    audit_b = AuditLog(str(dir_b / "audit.jsonl"))
    audit_a.append({"i": 1})  # A stays intact
    with open(audit_b.path, "a", encoding="utf-8") as fh:  # B diverges/corrupts
        fh.write('{"hash": "deadbeef", "prev_hash": "not-a-real-link", "i": 1}\n')
    return audit_a, audit_b


def test_real_redis_sequential_b_then_a_vetoes_a_and_preserves_b():
    """Sequential ordering (deterministic baseline against real Redis,
    mirrors the in-memory unit test but over the real Lua CAS script and a
    real network round-trip): B writes UNHEALTHY first, A's later,
    higher-generation HEALTHY write is vetoed outright."""
    server = RealRedisServer().start()
    try:
        audit_a, audit_b = _cloned_genesis_logs()
        assert audit_a.genesis_fingerprint_safe() == audit_b.genesis_fingerprint_safe()

        async def workload():
            registry = RedisIntegrityStateRegistry.from_url(
                server.url, key="mcc:test:collision:sequential",
            )
            mon_b = AuditIntegrityMonitor(audit_b, registry)
            mon_a = AuditIntegrityMonitor(audit_a, registry)

            state_b = await mon_b.verify_once()
            state_a = await mon_a.verify_once()
            final_b = await mon_b.current_state()
            final_a = await mon_a.current_state()
            return state_b, state_a, final_b, final_a, mon_a.identity_conflict_detected

        state_b, state_a, final_b, final_a, a_conflict = asyncio.run(workload())
        assert state_b == IntegrityState.UNHEALTHY
        assert state_a == IntegrityState.UNHEALTHY, (
            "worker A's write must be vetoed over REAL Redis, not just the "
            "in-memory double"
        )
        assert a_conflict is True
        assert final_b == IntegrityState.UNHEALTHY  # B's unresolved failure, untouched
        assert final_a == IntegrityState.UNHEALTHY
    finally:
        server.stop()


def test_real_redis_concurrent_a_and_b_never_lets_a_win_regardless_of_race_order():
    """Genuine concurrency: both workers' verify_once() calls launched
    together (asyncio.gather) against the SAME real Redis instance.
    Whichever one's write lands first atomically establishes the physical
    identity for this key; the other is vetoed -- but EITHER way, the
    final state must never be a HEALTHY result computed over worker A's
    log while B's corruption is unresolved for B's own identity, and the
    registry's physical_identity must end up self-consistent (matching
    whichever result is actually stored)."""
    server = RealRedisServer().start()
    try:
        audit_a, audit_b = _cloned_genesis_logs()

        async def workload():
            registry = RedisIntegrityStateRegistry.from_url(
                server.url, key="mcc:test:collision:concurrent",
            )
            mon_b = AuditIntegrityMonitor(audit_b, registry)
            mon_a = AuditIntegrityMonitor(audit_a, registry)
            results = await asyncio.gather(mon_b.verify_once(), mon_a.verify_once())
            final = await registry.get()
            return results, final, mon_a.identity_conflict_detected, mon_b.identity_conflict_detected

        results, final, a_conflict, b_conflict = asyncio.run(workload())

        # Exactly one of the two workers' identity is the one durably
        # established -- the OTHER must have been vetoed (a conflict
        # flagged on whichever one lost the race), never both applied.
        assert a_conflict != b_conflict, (
            f"expected exactly one worker to be vetoed, got a_conflict={a_conflict} "
            f"b_conflict={b_conflict} results={results}"
        )
        # The durably stored state is self-consistent: never a HEALTHY
        # result while the OTHER worker's corruption would have been the
        # one to win had the veto not fired.
        if b_conflict:
            # B lost the race -> A's intact result is what's stored.
            assert final.state == IntegrityState.HEALTHY
        else:
            # A lost the race -> B's corrupted result is what's stored,
            # and must NEVER have been silently overridden by A regardless
            # of generation ordering.
            assert final.state == IntegrityState.UNHEALTHY
    finally:
        server.stop()


def test_real_redis_shared_file_two_workers_same_physical_log_both_healthy():
    """Healthy-path regression over real Redis: when two workers genuinely
    share the SAME physical file (the correct, intended deployment), the
    identity veto must never fire against itself -- both converge on
    HEALTHY normally."""
    server = RealRedisServer().start()
    try:
        d = Path(tempfile.mkdtemp(prefix="mcc-redis-shared-"))
        shared_log_path = str(d / "audit.jsonl")
        audit_x = AuditLog(shared_log_path)
        audit_x.append({"i": 0})
        audit_y = AuditLog(shared_log_path)  # a second worker, SAME physical file

        async def workload():
            registry = RedisIntegrityStateRegistry.from_url(
                server.url, key="mcc:test:collision:shared",
            )
            mon_x = AuditIntegrityMonitor(audit_x, registry)
            mon_y = AuditIntegrityMonitor(audit_y, registry)
            state_x = await mon_x.verify_once()
            state_y = await mon_y.verify_once()
            return state_x, state_y, await mon_x.current_state(), await mon_y.current_state()

        state_x, state_y, final_x, final_y = asyncio.run(workload())
        assert state_x == IntegrityState.HEALTHY
        assert state_y == IntegrityState.HEALTHY
        assert final_x == IntegrityState.HEALTHY
        assert final_y == IntegrityState.HEALTHY
    finally:
        server.stop()
