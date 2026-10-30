"""Hardening round, Finding 2: real-Redis proof that the audit-integrity
Redis registry's async client survives the exact event-loop handoff
``gateway/governance_api.py``'s ``build_governance_service()`` performs --
a one-off, synchronous ``asyncio.run()`` startup check (no ASGI loop exists
yet) followed by a DIFFERENT, long-lived event loop (the real server's)
that runs periodic verification and every live request's
``current_state()`` call.

Uses a genuine ``redis-server`` OS subprocess (``tests.ha._redis_lab``) --
never a mock -- because this bug is specifically about redis-py's asyncio
connection objects being bound to the event loop that created them; a
mocked client cannot reproduce or disprove that.
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


def _audit() -> AuditLog:
    d = tempfile.mkdtemp(prefix="mcc-p2a3-evloop-")
    log = AuditLog(str(Path(d) / "audit.jsonl"))
    log.append({"seed": "real-history"})
    return log


def test_without_the_fix_a_second_event_loop_hits_a_real_cross_loop_error():
    """Non-vacuity companion, reproduced against the RAW redis.asyncio
    client (not the registry's own exception-wrapping) so the exact
    underlying failure is visible: a connection first used inside one
    ``asyncio.run()`` call raises when reused from a second, later one."""
    import redis.asyncio as redis_asyncio

    server = RealRedisServer().start()
    try:
        client = redis_asyncio.from_url(server.url, decode_responses=True)

        async def bump():
            return await client.incr("mcc:test:evloop:raw")

        first = asyncio.run(bump())
        assert first == 1

        with pytest.raises(RuntimeError, match="[Ee]vent loop is closed"):
            asyncio.run(bump())
    finally:
        server.stop()


def test_startup_check_then_real_server_loop_survives_with_the_fix():
    """The FIXED pattern ``build_governance_service()`` now uses: the
    mandatory synchronous startup check calls
    ``reset_connections_for_new_event_loop()`` before its throwaway loop
    tears down. A SEPARATE, later event loop (modelling the real ASGI
    server's) then runs MULTIPLE periodic-verification cycles AND repeated
    ``current_state()`` calls (modelling live requests at both enforcement
    boundaries) -- none of them must raise a cross-loop error."""
    server = RealRedisServer().start()
    try:
        log = _audit()
        registry = RedisIntegrityStateRegistry.from_url(
            server.url, key="mcc:test:evloop:fixed",
        )
        monitor = AuditIntegrityMonitor(log, registry)

        async def startup_and_release():
            state = await monitor.run_startup_verification()
            await monitor.reset_connections_for_new_event_loop()
            return state

        startup_state = asyncio.run(startup_and_release())
        assert startup_state == IntegrityState.HEALTHY

        async def real_server_loop_workload():
            results = []
            for _ in range(8):
                results.append(await monitor.verify_once())  # periodic pass
                results.append(await monitor.current_state())  # live request
                results.append(await monitor.current_state())  # another live request
            return results

        results = asyncio.run(real_server_loop_workload())
        assert all(r == IntegrityState.HEALTHY for r in results), results
    finally:
        server.stop()


def test_reset_without_the_fix_would_have_failed_closed_not_crashed_or_hung():
    """Even WITHOUT the fix, the pre-existing broad
    ``except Exception: ... -> IntegrityBackendUnavailable -> UNHEALTHY``
    handling already in ``AuditIntegrityMonitor``/``RedisIntegrityStateRegistry``
    converts the cross-loop RuntimeError into a clean, fail-closed
    UNHEALTHY -- never a crash, never a hang, and never (this is the part
    that matters for "no fail-open paths") a false HEALTHY. This is why
    Finding 2 is an AVAILABILITY bug (a self-inflicted, permanent
    integrity-service outage once the loop mismatch strikes) rather than a
    security one -- but still worth fixing, and the fix above does."""
    server = RealRedisServer().start()
    try:
        log = _audit()
        registry = RedisIntegrityStateRegistry.from_url(
            server.url, key="mcc:test:evloop:unfixed",
        )
        monitor = AuditIntegrityMonitor(log, registry)

        state1 = asyncio.run(monitor.run_startup_verification())
        assert state1 == IntegrityState.HEALTHY

        # Deliberately WITHOUT reset_connections_for_new_event_loop() --
        # the pre-fix pattern.
        state2 = asyncio.run(monitor.verify_once())
        assert state2 == IntegrityState.UNHEALTHY, (
            "expected the cross-loop failure to resolve to a clean, "
            "fail-closed UNHEALTHY -- if it no longer does, re-examine "
            "whether this non-vacuity check still reproduces the original "
            "condition"
        )
    finally:
        server.stop()


def test_fail_closed_when_redis_dies_mid_workload_no_crash_no_hang():
    """A real process kill (not a mocked exception) mid-workload, on the
    FIXED pattern, must resolve cleanly to UNHEALTHY -- never crash, never
    hang the event loop, never silently report HEALTHY."""
    server = RealRedisServer().start()
    log = _audit()
    registry = RedisIntegrityStateRegistry.from_url(
        server.url, key="mcc:test:evloop:killmidway", op_timeout_seconds=1.0,
    )
    monitor = AuditIntegrityMonitor(log, registry)

    async def startup_and_release():
        state = await monitor.run_startup_verification()
        await monitor.reset_connections_for_new_event_loop()
        return state

    startup_state = asyncio.run(startup_and_release())
    assert startup_state == IntegrityState.HEALTHY

    server.kill()

    async def post_kill_workload():
        return [await monitor.verify_once(), await monitor.current_state()]

    results = asyncio.run(post_kill_workload())
    assert all(r == IntegrityState.UNHEALTHY for r in results), results
    server.stop()  # best-effort cleanup of the (already-dead) process/tempdir
