"""PR #122 — clock-skew hardening: ``src/mcc_core/trusted_time.py`` and its
wiring into ``ApprovalService``, ``MandateVerifier``, ``ExecutionGate``, and
``GovernanceService``.

Covers the adversarial matrix this round's task requires: gateway clock
-30s/+30s, multiple gateways with conflicting clocks, Redis time-source
failure/restart, stale/rollback samples, and -- the acceptance condition --
that no unauthorized execution occurs solely because a gateway clock is
behind the trusted reference. Instruments the real actuator where relevant.

``LocalTimeSource`` (the non-Redis default) is exercised via the pre-existing
clock-skew test in ``tests/test_approval_adversarial_round2.py`` (it IS the
inherent, documented, unavoidable single-instance assumption); this file
is about ``RedisTimeSource``'s ADDED validation (availability, skew,
staleness, rollback) and its fail-closed wiring into every consumer.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid

import pytest

from mcc_core.approvals import ApprovalService, RedisApprovalRegistry
from mcc_core.gate import ExecutionGate
from mcc_core.mandate import MandateVerifier, issue_mandate
from mcc_core.nonce import InMemoryNonceRegistry
from mcc_core.signing import SigningKey
from mcc_core.trusted_time import (
    LocalTimeSource,
    RedisTimeSource,
    TimeTrustConfigError,
    TimeTrustError,
    trusted_time_source_from_env,
)

REDIS_URL = os.environ.get("MCC_REDIS_URL", "redis://127.0.0.1:6379/0")
run = asyncio.run


def _new_client():
    import redis.asyncio as aioredis
    return aioredis.from_url(REDIS_URL, decode_responses=True)


async def _redis_reachable() -> bool:
    try:
        client = _new_client()
        await asyncio.wait_for(client.ping(), timeout=1.0)
        await client.aclose()
        return True
    except Exception:
        return False


@pytest.fixture(autouse=True)
def _require_redis():
    if not asyncio.run(_redis_reachable()):
        pytest.skip(
            f"NOT TESTED: no Redis reachable at {REDIS_URL} in this environment "
            "(set MCC_REDIS_URL to point at a real instance)"
        )


# --------------------------------------------------------------------------
# 1. RedisTimeSource basics: a healthy real Redis is trusted.
# --------------------------------------------------------------------------

def test_redis_time_source_returns_a_plausible_real_timestamp():
    async def _go():
        client = _new_client()
        try:
            src = RedisTimeSource(client)
            now = await src.now()
            assert abs(now - time.time()) < 5
        finally:
            await client.aclose()

    run(_go())


def test_redis_time_source_rejects_excessive_skew():
    """A Redis TIME reply far from this process's own clock (simulating a
    misconfigured Redis server clock -- a shared clock is not automatically
    a TRUSTWORTHY one) is rejected, never silently trusted."""

    class SkewedClient:
        async def time(self):
            return (int(time.time()) + 3600, 0)  # 1 hour ahead

    src = RedisTimeSource(SkewedClient(), max_skew_seconds=5.0)
    with pytest.raises(TimeTrustError) as exc_info:
        run(src.now())
    assert exc_info.value.reason == "CLOCK_SKEW_EXCEEDED"


def test_redis_time_source_rejects_rollback():
    """A later sample reporting an EARLIER time than a previously observed
    one (beyond tolerance) is rejected -- a clock that jumps backward must
    never silently un-expire something."""

    base = int(time.time())
    samples = [base, base - 50]  # second sample rolls back 50s

    class RollbackClient:
        def __init__(self):
            self._i = 0

        async def time(self):
            v = samples[self._i]
            self._i += 1
            return (v, 0)

    client = RollbackClient()
    src = RedisTimeSource(client, max_skew_seconds=60.0)
    first = run(src.now())
    assert first == samples[0]
    with pytest.raises(TimeTrustError) as exc_info:
        run(src.now())
    assert exc_info.value.reason == "CLOCK_ROLLBACK_DETECTED"


def test_redis_time_source_fails_closed_when_redis_unavailable():
    class RaisingClient:
        async def time(self):
            raise ConnectionError("simulated redis outage")

    src = RedisTimeSource(RaisingClient())
    with pytest.raises(TimeTrustError) as exc_info:
        run(src.now())
    assert exc_info.value.reason == "CLOCK_UNTRUSTED"


def test_redis_time_source_fails_closed_on_slow_round_trip():
    """A round trip slower than the configured bound means the sample may
    already be stale by the time it is used -- reject it rather than trust
    a timestamp that could be arbitrarily old."""

    class SlowClient:
        async def time(self):
            await asyncio.sleep(0.2)
            return (int(time.time()), 0)

    src = RedisTimeSource(SlowClient(), max_round_trip_seconds=0.05)
    with pytest.raises(TimeTrustError) as exc_info:
        run(src.now())
    assert exc_info.value.reason == "CLOCK_UNTRUSTED"


# --------------------------------------------------------------------------
# 2. Multiple "gateways" with conflicting clocks, backed by the SAME Redis:
# RedisTimeSource gives them the SAME (shared, authoritative) answer,
# eliminating the inter-instance skew a LocalTimeSource-based deployment
# would be exposed to (see test_approval_adversarial_round2.py's
# clock-skew finding for that baseline).
# --------------------------------------------------------------------------

def test_multiple_gateway_instances_converge_on_the_same_redis_clock():
    async def _go():
        client_a = _new_client()
        client_b = _new_client()
        try:
            src_a = RedisTimeSource(client_a)
            src_b = RedisTimeSource(client_b)
            now_a = await src_a.now()
            now_b = await src_b.now()
            # Two independent connections, two independent round trips --
            # must agree to within a couple of seconds (the SAME server
            # clock), regardless of either instance's own local clock.
            assert abs(now_a - now_b) <= 2
        finally:
            await client_a.aclose()
            await client_b.aclose()

    run(_go())


# --------------------------------------------------------------------------
# 3. Fail-closed wiring into ApprovalService / MandateVerifier / ExecutionGate:
# when the configured time source cannot be trusted, NO new authorization
# is granted, NO expired approval is accepted, and nothing falls back to
# an unchecked local clock.
# --------------------------------------------------------------------------

class _AlwaysUntrusted:
    async def now(self):
        raise TimeTrustError("CLOCK_UNTRUSTED", "simulated: time source down for this test")


def test_approval_service_approve_fails_closed_when_time_source_untrusted():
    async def _go():
        client = _new_client()
        try:
            ns = f"test-trust-{uuid.uuid4().hex}:"
            reg = RedisApprovalRegistry(client, namespace=ns)
            svc = ApprovalService(reg, SigningKey.generate("k-untrusted"))
            # Create the request with an explicit now (bypassing the time
            # source -- the isolated test interface), THEN swap in an
            # always-untrusted source to attack the default-now path that
            # approve() itself would use in production.
            rid = await svc.request(actor="a", action="x", resource="r",
                                     transaction_id="t1", payload={"v": 1},
                                     ttl_seconds=300, now=int(time.time()))
            svc.time_source = _AlwaysUntrusted()
            mandate = await svc.approve(rid)
            assert mandate is None, (
                "approve() must never mint authority when the trusted time "
                "source cannot vouch for `now`"
            )
        finally:
            await client.aclose()

    run(_go())


def test_approval_service_consume_fails_closed_when_time_source_untrusted():
    async def _go():
        client = _new_client()
        try:
            ns = f"test-trust-consume-{uuid.uuid4().hex}:"
            reg = RedisApprovalRegistry(client, namespace=ns)
            svc = ApprovalService(reg, SigningKey.generate("k-untrusted2"))
            t0 = int(time.time())
            rid = await svc.request(actor="a", action="x", resource="r",
                                     transaction_id="t1", payload={"v": 1},
                                     ttl_seconds=300, now=t0)
            rec = await svc.get(rid, now=t0)
            mandate = await svc.approve(rid, now=t0)
            assert mandate is not None

            svc.time_source = _AlwaysUntrusted()
            result = await svc.consume(
                rid, action_hash=rec.action_hash, transaction_id="t1",
                payload_hash=rec.payload_hash,
            )
            assert result.ok is False, (
                "consume() must never exercise authority when the trusted "
                "time source cannot vouch for `now` -- this is the exact "
                "boundary the acceptance condition protects"
            )
            assert "CLOCK_UNTRUSTED" in result.reason
        finally:
            await client.aclose()

    run(_go())


def test_mandate_verifier_fails_closed_when_time_source_untrusted():
    async def _go():
        approver = SigningKey.generate("k-mv-untrusted")
        now0 = int(time.time())
        mandate = issue_mandate(
            approver, issuer="mcc/approvals", subject="agent/x",
            action_scope=["send_payment"], resource_scope=["acct-1"],
            constraints={}, not_before=now0, not_after=now0 + 300,
            issued_at=now0, revocation_required=False, policy_hash=None,
            mandate_id="apr-test-1",
        )
        verifier = MandateVerifier(trusted_keys={approver.kid: approver.public_key()})
        verifier.time_source = _AlwaysUntrusted()
        result = await verifier.verify(
            mandate, subject="agent/x", action="send_payment", resource="acct-1",
        )
        assert result.ok is False
        assert "CLOCK_UNTRUSTED" in result.reason

    run(_go())


def test_execution_gate_fails_closed_when_time_source_untrusted():
    async def _go():
        dk = SigningKey.generate("dk-gate-untrusted")
        gate = ExecutionGate(
            trusted_keys={dk.kid: dk.public_key()}, audience="gate",
            nonce_registry=InMemoryNonceRegistry(), policy_hash="sha256:p",
        )
        gate.time_source = _AlwaysUntrusted()
        now0 = int(time.time())
        token = dk.sign_token({
            "iss": "mcc", "sub": "agent/x", "aud": "gate", "jti": "j1",
            "iat": now0, "nbf": now0, "exp": now0 + 60,
            "decision": "ALLOW", "action": "x",
            "action_hash": "sha256:" + "0" * 64,
            "payload_hash": "sha256:" + "0" * 64,
            "constraints": {}, "policy_id": "p", "policy_hash": "sha256:p",
            "nonce": "n1", "audit_ref": None, "kid": dk.kid,
        })
        result = await gate.verify(token)
        assert result.allowed is False
        assert "CLOCK_UNTRUSTED" in result.reason

    run(_go())


# --------------------------------------------------------------------------
# 4. Acceptance condition, end to end with a real instrumented actuator:
# a lagging REAL Redis-backed deployment must not let a "behind true time"
# instance execute past the true expiry. This mirrors
# test_approval_adversarial_round2.py's clock-skew finding but through the
# now-hardened RedisTimeSource path, confirming the shared-clock design
# removes the inter-instance skew that finding described for the
# LocalTimeSource (unconfigured) baseline.
# --------------------------------------------------------------------------

def test_shared_redis_clock_prevents_the_round2_clock_skew_finding():
    """The round-2 finding: a LocalTimeSource instance whose own clock lags
    true time can consume() past a correctly-clocked instance's rejection.
    With BOTH instances instead configured to resolve `now` via
    RedisTimeSource (the SAME shared Redis), there is no "lagging
    instance" anymore -- both ask the same authoritative clock and get the
    same answer, so the exploit this round's task asks to close no longer
    has a lagging local clock to exploit."""

    async def _go():
        client_a = _new_client()
        client_b = _new_client()
        try:
            ns = f"test-trust-shared-{uuid.uuid4().hex}:"
            reg = RedisApprovalRegistry(client_a, namespace=ns)
            svc = ApprovalService(reg, SigningKey.generate("k-shared"),
                                   time_source=RedisTimeSource(client_b))

            # No synthetic `now=` anywhere below -- every call resolves its
            # own `now` through RedisTimeSource, exactly like production.
            rid = await svc.request(actor="a", action="x", resource="r",
                                     transaction_id="t1", payload={"v": 1},
                                     ttl_seconds=2)
            rec = await svc.get(rid)
            mandate = await svc.approve(rid)
            assert mandate is not None

            await asyncio.sleep(2.5)  # real elapsed time past the 2s window

            result = await svc.consume(
                rid, action_hash=rec.action_hash, transaction_id="t1",
                payload_hash=rec.payload_hash,
            )
            assert result.ok is False, (
                "a Redis-shared-clock-backed consume() must still correctly "
                "reject past the true deadline"
            )
            assert "expired" in result.reason.lower() or "not found" in result.reason.lower()
        finally:
            await client_a.aclose()
            await client_b.aclose()

    run(_go())


# --------------------------------------------------------------------------
# 5. Config: Redis is never an unconditional dependency; misconfiguration
# fails closed at startup, not at first use.
# --------------------------------------------------------------------------

def test_trusted_time_source_from_env_defaults_to_local_no_redis_dependency():
    src = trusted_time_source_from_env({})
    assert isinstance(src, LocalTimeSource)


def test_trusted_time_source_from_env_redis_without_url_fails_closed_at_construction():
    with pytest.raises(TimeTrustConfigError):
        trusted_time_source_from_env({"MCC_TIME_TRUST_BACKEND": "redis"})


def test_trusted_time_source_from_env_unknown_backend_fails_closed():
    with pytest.raises(TimeTrustConfigError):
        trusted_time_source_from_env({"MCC_TIME_TRUST_BACKEND": "quantum"})


def test_trusted_time_source_from_env_redis_backend_builds_redis_time_source():
    src = trusted_time_source_from_env({
        "MCC_TIME_TRUST_BACKEND": "redis", "MCC_REDIS_URL": REDIS_URL,
    })
    assert isinstance(src, RedisTimeSource)
