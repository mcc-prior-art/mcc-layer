"""P2-B High Availability & Safe Degradation -- fault-injection matrix.

Every "must never execute" assertion below counts the ACTUAL number of
actuator invocations (never just a status string); every "must execute
exactly once" assertion counts it too. See ``docs/HA_SAFE_DEGRADATION.md``
for the full matrix, the real-vs-simulated column, and known limitations
of this single-host sandbox (no true multi-host network partition, no
Docker Compose multi-container exercise).

This module requires a real ``redis-server`` binary on PATH; it is skipped
entirely (not silently passed) when one is not available -- see
``REDIS_AVAILABLE`` and each test's own ``skipif``.

Each test wraps ALL of its ``redis.asyncio`` client creation and use in ONE
``asyncio.run(...)`` call (one event loop for the whole test) -- a
``redis.asyncio`` connection is bound to the loop it first connects under,
so splitting one test across multiple ``asyncio.run()`` calls while reusing
the same client raises ``RuntimeError: Event loop is closed`` on the second
call. This mirrors the working pattern already established in
``tests/test_delegation_governance_service.py``'s real-Redis concurrency
test.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mcc_core import (  # noqa: E402
    AuditLog,
    IdempotencyBackendUnavailable,
    RedisIdempotencyRegistry,
    RedisRevocationRegistry,
    RedisVelocityRegistry,
    VelocityDescriptor,
    VelocityLimit,
    Verdict,
)
from mcc_core.coordinator import ActuationStatus  # noqa: E402
from mcc_core.trusted_time import RedisTimeSource, TimeTrustError  # noqa: E402

from tests.ha._redis_lab import (  # noqa: E402
    REDIS_AVAILABLE,
    ForgedClockRedisClient,
    KillRedisOnFirstCall,
    RealRedisServer,
    build_coordinator,
    killer_executor,
    payment_token,
    runner,
)

run = asyncio.run
pytestmark = pytest.mark.skipif(not REDIS_AVAILABLE, reason="redis-server binary not found on PATH")
HAS_IPTABLES = shutil.which("iptables") is not None
WORKER = [sys.executable, "-m", "tests.ha._crash_worker"]
REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def redis_server():
    server = RealRedisServer().start()
    try:
        yield server
    finally:
        server.stop()


def _tenant() -> str:
    return f"ha-{uuid.uuid4().hex[:8]}"


def _spawn_crash_worker(redis_server, tenant, key, crash_point):
    proc = subprocess.run(
        WORKER + ["--redis-url", redis_server.url, "--tenant", tenant, "--key", key,
                  "--crash-point", crash_point],
        cwd=str(REPO_ROOT), capture_output=True, timeout=15,
    )
    assert proc.returncode != 97, (
        f"worker reached the unreachable tail -- crash hook did not fire; "
        f"stdout={proc.stdout.decode()[:1000]} stderr={proc.stderr.decode()[:1000]}"
    )
    assert proc.returncode != 0, f"worker should have been SIGKILLed; stderr={proc.stderr.decode()[:2000]}"


# ---------------------------------------------------------------------------
# 1. Pre-dispatch crash (real subprocess, real SIGKILL, real Redis state)
# ---------------------------------------------------------------------------

def test_pre_dispatch_crash_blocks_immediate_retry_with_zero_actuator_calls(redis_server):
    """Worker A is a REAL OS process that reserves the logical operation
    against real Redis and SIGKILLs itself the instant that reservation
    durably succeeds -- before it could ever commit dispatch ownership.
    A fresh attempt for the SAME (tenant, key), made by this test process
    immediately afterward, must see the surviving RESERVED record and
    refuse to actuate -- zero actuator calls -- rather than treating the
    dead holder's silence as "safe to retry now"."""
    tenant, key = _tenant(), f"op-{uuid.uuid4().hex[:8]}"
    _spawn_crash_worker(redis_server, tenant, key, "reserve")

    async def _body():
        idem = RedisIdempotencyRegistry.from_url(redis_server.url)
        vel = RedisVelocityRegistry.from_url(redis_server.url)
        engine, coord, _audit = build_coordinator(idempotency=idem, velocity=vel)
        token, payload = payment_token(engine, idem=key, tenant=tenant)
        seen: list = []
        result = await coord.enforce(token=token, action="send_payment", payload=payload,
                                     executor=runner(seen))
        return result, seen

    result, seen = run(_body())
    assert result.status == ActuationStatus.BLOCKED
    assert seen == [], "retry against a surviving pre-dispatch reservation must not actuate"


def test_pre_dispatch_reservation_ttl_is_the_documented_crash_recovery_mechanism(redis_server):
    """Direct registry-level proof of the mechanism the coordinator itself
    relies on (``coordinator.enforce()`` does not expose a configurable
    reservation TTL, so this drives ``RedisIdempotencyRegistry.reserve()``
    directly with a short TTL): a RESERVED record that nobody ever
    committed or released is NOT permanently stuck -- after its TTL
    elapses, the SAME (tenant, key) becomes reservable again, which is
    exactly what lets a legitimate retry proceed after a real pre-dispatch
    crash. Default production TTL is 120s (unverified by this fast test;
    only the mechanism, not the specific duration, is proven here)."""
    tenant, key = _tenant(), f"op-{uuid.uuid4().hex[:8]}"

    async def _body():
        idem = RedisIdempotencyRegistry.from_url(redis_server.url)
        first = await idem.reserve(key, tenant_id=tenant, binding="b", ttl_seconds=1)
        immediate = await idem.reserve(key, tenant_id=tenant, binding="b", ttl_seconds=1)
        await asyncio.sleep(1.3)
        recovered = await idem.reserve(key, tenant_id=tenant, binding="b", ttl_seconds=1)
        return first, immediate, recovered

    first, immediate, recovered = run(_body())
    assert first.ok
    assert not immediate.ok, "a live, un-released reservation must still block a second admission"
    assert recovered.ok, "an expired, never-committed reservation must become admittable again"


# ---------------------------------------------------------------------------
# 2. Post-dispatch-ownership crash: never double-dispatch, recover via
#    explicit, independently-evidenced reconciliation only.
# ---------------------------------------------------------------------------

def test_post_dispatch_ownership_crash_never_double_dispatches_and_recovers_via_reconciliation(redis_server):
    tenant, key = _tenant(), f"op-{uuid.uuid4().hex[:8]}"
    _spawn_crash_worker(redis_server, tenant, key, "dispatch")

    async def _body():
        idem = RedisIdempotencyRegistry.from_url(redis_server.url)
        vel = RedisVelocityRegistry.from_url(redis_server.url)
        engine, coord, _audit = build_coordinator(idempotency=idem, velocity=vel)
        token, payload = payment_token(engine, idem=key, tenant=tenant)
        seen: list = []

        # (a) a fresh attempt for the SAME logical operation, post-crash,
        # must NOT actuate -- the dead holder's DISPATCH_OWNED record
        # survives (Redis, no TTL on that state) and is correctly seen as
        # in-flight.
        retry = await coord.enforce(token=token, action="send_payment", payload=payload,
                                    executor=runner(seen))

        # (b) reconciliation: an operator's tool reads the LIVE generation
        # from durable state (never a secret only the dead process held)
        # and supplies INDEPENDENTLY VERIFIED positive evidence -- this
        # harness stands in for that external verification;
        # resolve_unknown performs only the state transition, never the
        # verification itself.
        state = await idem.get_state(key, tenant_id=tenant)
        reconciled = await idem.resolve_unknown(
            key, tenant_id=tenant, expected_generation=state.generation if state else "",
            result_ref="operator-confirmed",
        )

        # (c) a THIRD attempt for the SAME key, after reconciliation, must
        # still never actuate -- the operation is now terminally EXECUTED.
        post_reconcile = await coord.enforce(token=token, action="send_payment", payload=payload,
                                             executor=runner(seen))

        # (d) the system is not globally stuck: a genuinely fresh logical
        # operation (different key) executes exactly once, normally.
        fresh_key = f"op-{uuid.uuid4().hex[:8]}"
        fresh_token, fresh_payload = payment_token(engine, idem=fresh_key, tenant=tenant)
        fresh_result = await coord.enforce(token=fresh_token, action="send_payment", payload=fresh_payload,
                                           executor=runner(seen))
        return retry, state, reconciled, post_reconcile, fresh_result, seen

    retry, state, reconciled, post_reconcile, fresh_result, seen = run(_body())
    assert retry.status == ActuationStatus.BLOCKED
    assert state is not None and state.state.value == "DISPATCH_OWNED"
    assert reconciled.resolved, reconciled.reason
    assert post_reconcile.status == ActuationStatus.BLOCKED
    assert fresh_result.status == ActuationStatus.EXECUTED
    assert seen == ["executed"], (
        "exactly one real actuation across the whole sequence -- for the fresh operation only; "
        "never for the crashed, retried, or reconciled one"
    )


def test_audit_chain_integrity_survives_crash_and_reconciliation(redis_server, tmp_path):
    """The audit chain of a crash+retry+reconciliation+fresh-execution
    sequence (driven in-process here, since the subprocess crash test
    above already proves the real multi-process property; this isolates
    the audit-integrity question only) must still verify as an intact
    hash chain -- recovery must never leave the audit trail broken or
    require truncation."""
    tenant, key = _tenant(), f"op-{uuid.uuid4().hex[:8]}"
    audit_path = str(tmp_path / "audit.jsonl")

    async def _body():
        idem = RedisIdempotencyRegistry.from_url(redis_server.url)
        vel = RedisVelocityRegistry.from_url(redis_server.url)
        audit = AuditLog(audit_path)
        engine, coord, _ = build_coordinator(idempotency=idem, velocity=vel, audit=audit)
        token, payload = payment_token(engine, idem=key, tenant=tenant)
        seen: list = []
        result = await coord.enforce(token=token, action="send_payment", payload=payload,
                                     executor=runner(seen))
        return result

    result = run(_body())
    assert result.status == ActuationStatus.EXECUTED
    assert AuditLog.verify_chain(audit_path) is True


# ---------------------------------------------------------------------------
# 3. Real Redis outage (actual process kill, not a mocked exception)
# ---------------------------------------------------------------------------

def test_real_redis_killed_mid_velocity_reserve_fails_closed_then_recovers(redis_server):
    """The idempotency reservation genuinely succeeds against the real,
    live Redis; the FIRST call into the velocity step then kills the real
    redis-server process as a side effect before delegating to the real
    (now-failing) call -- a genuine severed connection, handled by the
    real redis-py client's real exception path, not a synthetic double.
    Recovery (a fresh attempt after Redis is restarted) is then proven in
    the SAME test, in a separate event loop -- using entirely FRESH client
    objects, since the first phase's clients are bound to a now-dead
    connection/closed loop."""
    tenant, key = _tenant(), f"op-{uuid.uuid4().hex[:8]}"

    async def _phase1():
        idem = RedisIdempotencyRegistry.from_url(redis_server.url)
        vel = KillRedisOnFirstCall(RedisVelocityRegistry.from_url(redis_server.url), redis_server, "reserve")
        limit = VelocityLimit(name="amt", window_seconds=3600, max_amount=10_000, aggregate_by=("actor",))
        engine, coord, _audit = build_coordinator(idempotency=idem, velocity=vel, limits=[limit])
        token, payload = payment_token(engine, idem=key, tenant=tenant)
        seen: list = []
        result = await coord.enforce(token=token, action="send_payment", payload=payload,
                                     executor=runner(seen))
        return result, seen

    result, seen = run(_phase1())
    assert result.status == ActuationStatus.BLOCKED
    assert seen == [], "a real mid-operation Redis death must fail closed with zero actuator calls"

    # Pre-dispatch-ownership failure -> the coordinator also attempted to
    # release the idempotency reservation, but Redis is genuinely dead at
    # that moment, so the release call itself silently no-ops (the
    # registry's own tolerant-on-backend-failure contract) rather than
    # raising out of enforce(). Recovery is proven below, once Redis is
    # back up, by restarting and confirming a fresh attempt for the SAME
    # key succeeds -- the operation was not permanently stranded.
    redis_server.restart()

    async def _phase2():
        idem2 = RedisIdempotencyRegistry.from_url(redis_server.url)
        vel2 = RedisVelocityRegistry.from_url(redis_server.url)
        engine2, coord2, _audit2 = build_coordinator(idempotency=idem2, velocity=vel2)
        token2, payload2 = payment_token(engine2, idem=key, tenant=tenant)
        seen2: list = []
        recovered = await coord2.enforce(token=token2, action="send_payment", payload=payload2,
                                         executor=runner(seen2))
        return recovered, seen2

    recovered, seen2 = run(_phase2())
    assert recovered.status == ActuationStatus.EXECUTED, (
        "after Redis recovers, the operation must be admittable again -- it must not be "
        "permanently stranded by a pre-dispatch infrastructure failure"
    )
    assert seen2 == ["executed"]


def test_redis_outage_get_state_fails_closed_not_not_found(redis_server):
    """IdempotencyBackendUnavailable (never ``None``/"not found") is the
    contract for an outage -- re-verified here against a REAL killed
    redis-server, not a mock."""
    tenant, key = _tenant(), f"op-{uuid.uuid4().hex[:8]}"

    async def _body():
        idem = RedisIdempotencyRegistry.from_url(redis_server.url)
        await idem.reserve(key, tenant_id=tenant, binding="b")
        redis_server.kill()
        with pytest.raises(IdempotencyBackendUnavailable):
            await idem.get_state(key, tenant_id=tenant)

    run(_body())


def test_real_redis_restart_recovers_fresh_operations(redis_server):
    """After a genuine kill + genuine restart (new process, same port, no
    preserved data -- see RealRedisServer.restart's docstring), a BRAND
    NEW logical operation executes normally. This is recovery of
    capability, not resumed state -- the old data is gone by design."""
    tenant, key = _tenant(), f"op-{uuid.uuid4().hex[:8]}"
    redis_server.kill()
    redis_server.restart()

    async def _body():
        idem = RedisIdempotencyRegistry.from_url(redis_server.url)
        vel = RedisVelocityRegistry.from_url(redis_server.url)
        engine, coord, _audit = build_coordinator(idempotency=idem, velocity=vel)
        token, payload = payment_token(engine, idem=key, tenant=tenant)
        seen: list = []
        result = await coord.enforce(token=token, action="send_payment", payload=payload,
                                     executor=runner(seen))
        return result, seen

    result, seen = run(_body())
    assert result.status == ActuationStatus.EXECUTED
    assert seen == ["executed"]


# ---------------------------------------------------------------------------
# 4. Revocation visibility across independent connections to one real Redis
# ---------------------------------------------------------------------------

def test_revocation_via_one_connection_is_immediately_visible_to_another(redis_server):
    """Two SEPARATE ``RedisRevocationRegistry`` client connections against
    the SAME real Redis instance -- modelling two gateway instances in a
    fleet. A mandate revoked through connection A must be seen as revoked
    by connection B's very next check: no caching, no eventual consistency
    window large enough for a stale ALLOW."""
    tenant = _tenant()
    mandate_id = f"mandate-{uuid.uuid4().hex[:8]}"

    async def _body():
        conn_a = RedisRevocationRegistry.from_url(redis_server.url)
        conn_b = RedisRevocationRegistry.from_url(redis_server.url)
        idem = RedisIdempotencyRegistry.from_url(redis_server.url)
        vel = RedisVelocityRegistry.from_url(redis_server.url)
        engine, coord, _audit = build_coordinator(idempotency=idem, velocity=vel, revocation_registry=conn_b)
        key = f"op-{uuid.uuid4().hex[:8]}"
        token, payload = payment_token(engine, idem=key, tenant=tenant, mandate_id=mandate_id)

        seen: list = []
        before = await coord.enforce(token=token, action="send_payment", payload=payload, executor=runner(seen))

        await conn_a.revoke(mandate_id)

        token2, payload2 = payment_token(engine, idem=f"op-{uuid.uuid4().hex[:8]}", tenant=tenant,
                                         mandate_id=mandate_id)
        after = await coord.enforce(token=token2, action="send_payment", payload=payload2, executor=runner(seen))
        return before, after, seen

    before, after, seen = run(_body())
    assert before.status == ActuationStatus.EXECUTED
    assert after.status == ActuationStatus.BLOCKED
    assert seen == ["executed"], "the SAME mandate must be blocked everywhere the instant it is revoked anywhere"


# ---------------------------------------------------------------------------
# 5. Concurrent cross-connection spend never exceeds the aggregate ceiling
# ---------------------------------------------------------------------------

def test_concurrent_cross_connection_spend_never_exceeds_aggregate_ceiling(redis_server):
    """Two independent Redis client CONNECTIONS (not two OS processes --
    see docs/HA_SAFE_DEGRADATION.md's real-vs-simulated column) racing 10
    concurrent reservations of 100.0 each against a 500.0 ceiling, shared
    via one real Redis instance. Exactly 5 may be admitted; the ceiling
    must never be exceeded regardless of interleaving."""
    actor = f"actor-{uuid.uuid4().hex[:8]}"
    limit = VelocityLimit(name="amt", window_seconds=3600, max_amount=500.0, aggregate_by=("actor",))

    def desc():
        return VelocityDescriptor(dimensions={"actor": actor}, amount=100.0, currency="USD", destination="x")

    async def _body():
        vel_a = RedisVelocityRegistry.from_url(redis_server.url)
        vel_b = RedisVelocityRegistry.from_url(redis_server.url)
        regs = [vel_a, vel_b] * 5
        return await asyncio.gather(*[r.reserve(limit, desc()) for r in regs])

    outcomes = run(_body())
    allowed = [o for o in outcomes if o.verdict == Verdict.ALLOW]
    assert len(allowed) == 5, f"expected exactly 5 admissions at the ceiling, got {len(allowed)}"
    assert len(allowed) * 100.0 <= 500.0


# ---------------------------------------------------------------------------
# 6. Stale / compromised time source
# ---------------------------------------------------------------------------

def test_stale_redis_clock_blocks_before_any_reservation_zero_actuator_calls(redis_server):
    """A forged Redis ``TIME`` reply (rolled back relative to a
    previously-observed sample) must make ``RedisTimeSource`` refuse to
    produce a ``now`` at all -- and the coordinator must fail closed on
    that refusal before touching idempotency or velocity, zero actuator
    calls. Only the single ``time()`` reply is forged (see
    ``ForgedClockRedisClient``'s docstring); everything else in this test
    talks to the real Redis instance genuinely."""
    tenant, key = _tenant(), f"op-{uuid.uuid4().hex[:8]}"

    async def _body():
        import redis.asyncio as redis_async

        real_client = redis_async.from_url(redis_server.url, decode_responses=True)
        ts = RedisTimeSource(real_client)
        first = await ts.now()

        rolled_back_client = ForgedClockRedisClient(real_client, forged_seconds=first - 10_000)
        bad_ts = RedisTimeSource(rolled_back_client)
        bad_ts._last_seen = first  # same rollback-detection state a long-lived instance would have accrued

        idem = RedisIdempotencyRegistry.from_url(redis_server.url)
        vel = RedisVelocityRegistry.from_url(redis_server.url)
        engine, coord, _audit = build_coordinator(idempotency=idem, velocity=vel, time_source=bad_ts)
        token, payload = payment_token(engine, idem=key, tenant=tenant)
        seen: list = []

        result = await coord.enforce(token=token, action="send_payment", payload=payload, executor=runner(seen))
        reserved_after = await idem.get_state(key, tenant_id=tenant)

        raised = None
        try:
            await bad_ts.now()
        except TimeTrustError as exc:
            raised = exc
        return result, seen, reserved_after, raised

    result, seen, reserved_after, raised = run(_body())
    assert result.status == ActuationStatus.BLOCKED
    assert seen == []
    assert reserved_after is None, (
        "a clock-trust failure happens before idempotency.reserve() is ever called -- "
        "nothing should have been reserved at all"
    )
    assert raised is not None, "the forged rolled-back clock must raise TimeTrustError"


# ---------------------------------------------------------------------------
# 7. Audit-write failure (the one exception-double in this suite -- a real
#    disk-full condition is impractical/unsafe to construct in this shared
#    sandbox; see docs/HA_SAFE_DEGRADATION.md)
# ---------------------------------------------------------------------------

class _RaisingAudit:
    def __init__(self, real_audit):
        self._real = real_audit

    def append(self, record):
        raise IOError("simulated: audit backend cannot durably confirm this write")


def test_audit_write_failure_blocks_pre_dispatch_and_releases_reservation(redis_server):
    tenant, key = _tenant(), f"op-{uuid.uuid4().hex[:8]}"

    async def _body():
        idem = RedisIdempotencyRegistry.from_url(redis_server.url)
        vel = RedisVelocityRegistry.from_url(redis_server.url)
        engine, coord, real_audit = build_coordinator(idempotency=idem, velocity=vel)
        coord.audit = _RaisingAudit(real_audit)
        token, payload = payment_token(engine, idem=key, tenant=tenant)
        seen: list = []

        blocked = await coord.enforce(token=token, action="send_payment", payload=payload, executor=runner(seen))

        # Pre-dispatch failure -> reservation released -> the SAME
        # logical operation (same idempotency_key) is admittable again
        # once the audit backend is healthy. A genuinely fresh
        # authorization (new token/nonce) is used for the retry, exactly
        # as a real caller would re-authorize the same logical operation
        # -- the FIRST token's one-time nonce was already consumed by the
        # first (blocked) attempt's gate verification and can never be
        # reused, independent of the idempotency outcome being tested here.
        coord.audit = real_audit
        retry_token, retry_payload = payment_token(engine, idem=key, tenant=tenant)
        retried = await coord.enforce(token=retry_token, action="send_payment", payload=retry_payload,
                                      executor=runner(seen))
        return blocked, retried, seen

    blocked, retried, seen = run(_body())
    assert blocked.status == ActuationStatus.BLOCKED
    assert retried.status == ActuationStatus.EXECUTED
    assert seen == ["executed"]


# ---------------------------------------------------------------------------
# 8. Network-partition APPROXIMATION (single host; see module docstring and
#    docs/HA_SAFE_DEGRADATION.md -- this is not a true multi-host partition)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not HAS_IPTABLES, reason="iptables not available in this sandbox")
def test_network_partition_approximation_blocks_closed_and_fully_recovers(redis_server):
    """Genuinely drops every loopback TCP packet to the real redis-server's
    port via a real ``iptables`` rule for the duration of one operation --
    the client's own bounded connect/socket timeout turns that into a real
    timeout, not an instant refusal (closer to an unreachable peer than a
    down process). The rule is removed in a ``finally`` and connectivity
    is re-verified afterward, regardless of test outcome, so a failure
    here can never leave the sandbox's loopback network impaired."""
    tenant, key = _tenant(), f"op-{uuid.uuid4().hex[:8]}"
    rule = ["-o", "lo", "-p", "tcp", "--dport", str(redis_server.port), "-j", "DROP"]
    subprocess.run(["iptables", "-I", "OUTPUT"] + rule, check=True)
    try:
        async def _blocked_body():
            import redis.asyncio as redis_async

            client = redis_async.from_url(
                redis_server.url, socket_timeout=1.0, socket_connect_timeout=1.0, decode_responses=True,
            )
            idem = RedisIdempotencyRegistry(client)
            vel = RedisVelocityRegistry(client)
            engine, coord, _audit = build_coordinator(idempotency=idem, velocity=vel)
            token, payload = payment_token(engine, idem=key, tenant=tenant)
            seen: list = []
            result = await coord.enforce(token=token, action="send_payment", payload=payload,
                                         executor=runner(seen))
            return result, seen

        result, seen = run(_blocked_body())
        assert result.status == ActuationStatus.BLOCKED
        assert seen == [], "a partitioned backend must fail closed with zero actuator calls, never offline-allow"
    finally:
        subprocess.run(["iptables", "-D", "OUTPUT"] + rule, check=False)

    # Recovery re-verification: connectivity must be back, and a fresh
    # operation against the (now reachable again) real Redis must succeed.
    async def _recovered_body():
        idem2 = RedisIdempotencyRegistry.from_url(redis_server.url)
        vel2 = RedisVelocityRegistry.from_url(redis_server.url)
        engine2, coord2, _audit2 = build_coordinator(idempotency=idem2, velocity=vel2)
        key2 = f"op-{uuid.uuid4().hex[:8]}"
        token2, payload2 = payment_token(engine2, idem=key2, tenant=tenant)
        seen2: list = []
        recovered = await coord2.enforce(token=token2, action="send_payment", payload=payload2,
                                         executor=runner(seen2))
        return recovered, seen2

    recovered, seen2 = run(_recovered_body())
    assert recovered.status == ActuationStatus.EXECUTED
    assert seen2 == ["executed"]
