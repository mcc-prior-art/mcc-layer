"""PR #122 Section 1/2 regression: the TTL-extension / logical-expiry defect
in ``src/mcc_core/approvals.py``.

Root cause (pre-fix, at HEAD 362611d): both ``_SET_STATE_LUA`` and
``_CONSUME_LUA`` recomputed the record's FULL ORIGINAL duration
(``expires_at - created_at``) and reapplied it as a fresh relative Redis
``EX`` at TRANSITION time, instead of preserving the remaining time until the
original absolute deadline. This both (a) let the physical Redis key survive
longer than its intended ``expires_at`` whenever a transition happened after
some real time had elapsed, and (b) meant APPROVED records were never
re-checked against ``expires_at`` at all (only PENDING was, in ``get()``),
so an APPROVED-but-logically-expired record could still be consumed as long
as its (bugged, extended) physical key happened to still exist.

Empirically confirmed via three ad-hoc scripts before this fix (not
committed; see the PR #122 report): the physical PTTL extension itself, the
registry-level ``consume()`` succeeding past logical expiry, and -- the
decisive negative result -- that this did NOT translate into an end-to-end
executable bypass, because ``MandateVerifier._verify()``'s own independent,
Ed25519-signed ``exp`` check (copied from the correct ``expires_at`` at
``approve()``-time) is always evaluated before the coordinator ever reaches
``ApprovalService.consume()`` (the only production call site,
``coordinator.py:257``). The fix below closes the registry-level gap anyway
(defense-in-depth, and because Section 2 of the PR #122 task requires fixing
a confirmed defect unconditionally on exploitability), and this file proves
both: the transition-time TTL preservation and the explicit expiry gate,
against BOTH registries, plus a real end-to-end E2E re-confirmation that the
mandate-expiry backstop still independently blocks actuation either way.

Deterministic unit tests below use a SYNTHETIC epoch clock, exactly like the
rest of this repo's test suite (e.g. ``tests/test_approvals.py``'s
``NOW = 1_780_000_000``) -- never tied to real wall-clock time. This is
deliberate and load-bearing: it lets a test assert "logically expired but
the physical Redis key has not yet died" without any real ``sleep()``,
simply by creating a record with a synthetic ``now`` and then calling
``consume()``/``set_state()`` with a LATER synthetic ``now`` while almost no
real time has passed (so the real-wall-clock-driven physical TTL is still
very much alive) -- the exact scenario the pre-fix code handled wrong. One
test (``test_real_redis_ttl_tracks_original_deadline_not_full_duration``)
additionally uses real (short) sleeps against a real Redis PTTL, because
that is the only way to observe the *physical* key lifetime the bug
actually corrupted.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid

import pytest

from mcc_core.approvals import (
    ApprovalService,
    ApprovalState,
    InMemoryApprovalRegistry,
    RedisApprovalRegistry,
)
from mcc_core.signing import SigningKey

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


def _redis_service(ns_prefix: str):
    client = _new_client()
    ns = f"test-ttl-{ns_prefix}-{uuid.uuid4().hex}:"
    reg = RedisApprovalRegistry(client, namespace=ns)
    svc = ApprovalService(reg, SigningKey.generate(f"k-{ns_prefix}"))
    return client, reg, svc


# --------------------------------------------------------------------------
# 1. Physical TTL must track the ORIGINAL deadline, never be extended by a
#    transition (the root-cause defect, measured directly via real PTTL).
# --------------------------------------------------------------------------

def test_real_redis_ttl_tracks_original_deadline_not_full_duration():
    """A transition (here: approve()) that happens partway through the
    window must LEAVE THE PHYSICAL KEY'S REMAINING TTL ALONE (modulo the
    elapsed real time) -- never reset it to "now + the full original
    duration". Pre-fix, PTTL after approve() stayed close to the FULL
    TTL_SECONDS*1000 regardless of how much real time had already elapsed;
    post-fix it must be close to the REMAINING time until the original
    deadline."""

    async def _go():
        client, reg, svc = _redis_service("pttl")
        try:
            ttl_seconds = 6
            delay_before_approve = 2.5
            t0 = time.time()
            rid = await svc.request(actor="a", action="x", resource="r",
                                     transaction_id="t1", payload={"v": 1},
                                     ttl_seconds=ttl_seconds)
            pttl_after_create = await client.pttl(reg._k(rid))
            assert pttl_after_create > 0

            await asyncio.sleep(delay_before_approve)
            elapsed = time.time() - t0
            mandate = await svc.approve(rid)
            assert mandate is not None

            pttl_after_approve = await client.pttl(reg._k(rid))
            expected_remaining_ms = max(0.0, (ttl_seconds - elapsed) * 1000)

            # Generous tolerance for test-process scheduling jitter, but far
            # tighter than the bug's effect: the bug would re-extend PTTL to
            # ~ttl_seconds*1000 (6000ms) regardless of elapsed time, i.e. an
            # overshoot of ~elapsed*1000 (~2500ms) beyond the correct value.
            overshoot_ms = pttl_after_approve - expected_remaining_ms
            assert overshoot_ms < 1500, (
                f"TTL-extension regression: PTTL after approve()={pttl_after_approve}ms, "
                f"expected remaining~={expected_remaining_ms:.0f}ms (overshoot={overshoot_ms:.0f}ms). "
                "A transition must preserve the original absolute deadline, "
                "never reapply the full original duration."
            )
            # And it must not have been extended PAST the original deadline
            # either (small clock-rounding slack only).
            assert pttl_after_approve <= expected_remaining_ms + 1500
        finally:
            await client.aclose()

    run(_go())


def test_real_redis_ttl_preserved_through_deny_too():
    """Same preservation property for deny() (the other ``_SET_STATE_LUA``
    caller besides approve()'s half-step)."""

    async def _go():
        client, reg, svc = _redis_service("pttl-deny")
        try:
            ttl_seconds = 5
            delay = 2.0
            t0 = time.time()
            rid = await svc.request(actor="a", action="x", resource="r",
                                     transaction_id="t1", payload={"v": 1},
                                     ttl_seconds=ttl_seconds)
            await asyncio.sleep(delay)
            elapsed = time.time() - t0
            assert await svc.deny(rid) is True

            pttl_after_deny = await client.pttl(reg._k(rid))
            expected_remaining_ms = max(0.0, (ttl_seconds - elapsed) * 1000)
            assert pttl_after_deny - expected_remaining_ms < 1500
        finally:
            await client.aclose()

    run(_go())


# --------------------------------------------------------------------------
# 2. consume() must fail-closed, with a distinct "expired" reason, for a
#    record that is logically past expires_at -- regardless of whether the
#    physical Redis key happens to still exist. Synthetic clock: the record
#    is created and approved with an early synthetic ``now``, then consume()
#    is called with a LATER synthetic ``now`` (>= expires_at) while almost
#    no real time has passed, so the real physical TTL is still alive --
#    isolating the logical-expiry check from the physical-key lifetime.
# --------------------------------------------------------------------------

def test_redis_consume_rejects_logically_expired_approved_record():
    async def _go():
        client, reg, svc = _redis_service("consume-expired")
        try:
            t0 = 1_000_000
            ttl_seconds = 10
            rid = await svc.request(actor="a", action="x", resource="r",
                                     transaction_id="t1", payload={"v": 1},
                                     ttl_seconds=ttl_seconds, now=t0)
            rec0 = await svc.get(rid, now=t0)
            mandate = await svc.approve(rid, now=t0 + 1)
            assert mandate is not None

            # Logical "now" is well past expires_at (t0+10); real wall-clock
            # time elapsed is ~0 -- the physical key is still present.
            t_future = t0 + 10_000
            result = await svc.consume(
                rid, action_hash=rec0.action_hash, transaction_id="t1",
                payload_hash=rec0.payload_hash, now=t_future,
            )
            assert result.ok is False, (
                "consume() must reject a record whose LOGICAL expires_at has "
                "passed, independent of the physical Redis key's TTL"
            )
            assert "expired" in result.reason.lower()
        finally:
            await client.aclose()

    run(_go())


def test_inmemory_consume_rejects_logically_expired_approved_record():
    """Same property, in-memory backend (no Redis TTL involved at all --
    this isolates the logical-expiry check itself)."""

    async def _go():
        reg = InMemoryApprovalRegistry()
        svc = ApprovalService(reg, SigningKey.generate("k-mem-expired"))
        t0 = 2_000_000
        ttl_seconds = 10
        rid = await svc.request(actor="a", action="x", resource="r",
                                 transaction_id="t1", payload={"v": 1},
                                 ttl_seconds=ttl_seconds, now=t0)
        rec0 = await svc.get(rid, now=t0)
        mandate = await svc.approve(rid, now=t0 + 1)
        assert mandate is not None

        t_future = t0 + 10_000
        result = await svc.consume(
            rid, action_hash=rec0.action_hash, transaction_id="t1",
            payload_hash=rec0.payload_hash, now=t_future,
        )
        assert result.ok is False
        assert "expired" in result.reason.lower()

    run(_go())


def test_redis_consume_replay_reported_before_expired():
    """A record that was CONSUMED, and is ALSO now long past its original
    expires_at, must still report "replay", never "expired" -- replay is
    the more specific, already-decided outcome and must take priority
    (mirrors the existing already-consumed-vs-wrong-state priority)."""

    async def _go():
        client, reg, svc = _redis_service("consume-replay-vs-expired")
        try:
            t0 = 3_000_000
            ttl_seconds = 10
            rid = await svc.request(actor="a", action="x", resource="r",
                                     transaction_id="t1", payload={"v": 1},
                                     ttl_seconds=ttl_seconds, now=t0)
            rec0 = await svc.get(rid, now=t0)
            mandate = await svc.approve(rid, now=t0 + 1)
            assert mandate is not None

            first = await svc.consume(
                rid, action_hash=rec0.action_hash, transaction_id="t1",
                payload_hash=rec0.payload_hash, now=t0 + 2,
            )
            assert first.ok is True

            replay = await svc.consume(
                rid, action_hash=rec0.action_hash, transaction_id="t1",
                payload_hash=rec0.payload_hash, now=t0 + 10_000,
            )
            assert replay.ok is False
            assert "replay" in replay.reason.lower()
            assert "expired" not in replay.reason.lower()
        finally:
            await client.aclose()

    run(_go())


# --------------------------------------------------------------------------
# 3. approve()/deny()/invalidate() must all refuse against a logically
#    expired PENDING/APPROVED record -- never silently succeed, and never
#    "restore" an expired record to a usable state.
# --------------------------------------------------------------------------

def test_redis_approve_rejects_logically_expired_pending_record():
    async def _go():
        client, reg, svc = _redis_service("approve-expired")
        try:
            t0 = 4_000_000
            rid = await svc.request(actor="a", action="x", resource="r",
                                     transaction_id="t1", payload={"v": 1},
                                     ttl_seconds=5, now=t0)
            mandate = await svc.approve(rid, now=t0 + 10_000)
            assert mandate is None, (
                "approve() must refuse a PENDING record whose expires_at "
                "has already passed"
            )
            rec = await svc.get(rid, now=t0 + 10_000)
            assert rec.state == ApprovalState.EXPIRED.value
        finally:
            await client.aclose()

    run(_go())


def test_redis_deny_rejects_logically_expired_pending_record():
    async def _go():
        client, reg, svc = _redis_service("deny-expired")
        try:
            t0 = 5_000_000
            rid = await svc.request(actor="a", action="x", resource="r",
                                     transaction_id="t1", payload={"v": 1},
                                     ttl_seconds=5, now=t0)
            denied = await svc.deny(rid, now=t0 + 10_000)
            assert denied is False, (
                "deny() must not be able to act on a record that has "
                "already logically expired"
            )
        finally:
            await client.aclose()

    run(_go())


def test_redis_invalidate_rejects_logically_expired_approved_record():
    async def _go():
        client, reg, svc = _redis_service("invalidate-expired")
        try:
            t0 = 6_000_000
            rid = await svc.request(actor="a", action="x", resource="r",
                                     transaction_id="t1", payload={"v": 1},
                                     ttl_seconds=5, now=t0)
            mandate = await svc.approve(rid, now=t0 + 1)
            assert mandate is not None

            invalidated = await svc.invalidate(rid, now=t0 + 10_000)
            assert invalidated is False, (
                "invalidate() must not be able to 'act' on an APPROVED "
                "record that has already logically expired -- it is "
                "already unusable, and this must never be reported as a "
                "live state transition"
            )
        finally:
            await client.aclose()

    run(_go())


def test_inmemory_approve_deny_invalidate_reject_expired_record():
    """Same three refusals, in-memory backend, in one test."""

    async def _go():
        t0 = 7_000_000

        reg1 = InMemoryApprovalRegistry()
        svc1 = ApprovalService(reg1, SigningKey.generate("k-mem1"))
        rid1 = await svc1.request(actor="a", action="x", resource="r",
                                   transaction_id="t1", payload={"v": 1},
                                   ttl_seconds=5, now=t0)
        assert await svc1.approve(rid1, now=t0 + 10_000) is None

        reg2 = InMemoryApprovalRegistry()
        svc2 = ApprovalService(reg2, SigningKey.generate("k-mem2"))
        rid2 = await svc2.request(actor="a", action="x", resource="r",
                                   transaction_id="t1", payload={"v": 1},
                                   ttl_seconds=5, now=t0)
        assert await svc2.deny(rid2, now=t0 + 10_000) is False

        reg3 = InMemoryApprovalRegistry()
        svc3 = ApprovalService(reg3, SigningKey.generate("k-mem3"))
        rid3 = await svc3.request(actor="a", action="x", resource="r",
                                   transaction_id="t1", payload={"v": 1},
                                   ttl_seconds=5, now=t0)
        assert await svc3.approve(rid3, now=t0 + 1) is not None
        assert await svc3.invalidate(rid3, now=t0 + 10_000) is False

    run(_go())


# --------------------------------------------------------------------------
# 3b. Expiration vs. concurrent state transition (PR #122 Section 3): the
#     expiry check lives INSIDE the same atomic Lua CAS that already
#     resolves state-vs-state races (Finding 1's fix), so there is no new
#     interleaving window to race -- a single Redis Lua execution either
#     observes the record as expired or it does not; it can never be
#     "half-expired". This is verified here, not just asserted, by firing
#     several concurrent consume() attempts at the exact expiry boundary
#     and checking the outcomes are fully consistent (never more than one
#     success, and every non-winning attempt reports a coherent reason).
# --------------------------------------------------------------------------

def test_concurrent_consume_attempts_at_expiry_boundary_are_consistent():
    async def _go():
        client, reg, svc = _redis_service("concurrent-boundary")
        try:
            t0 = 9_000_000
            ttl_seconds = 5
            rid = await svc.request(actor="a", action="x", resource="r",
                                     transaction_id="t1", payload={"v": 1},
                                     ttl_seconds=ttl_seconds, now=t0)
            rec0 = await svc.get(rid, now=t0)
            mandate = await svc.approve(rid, now=t0 + 1)
            assert mandate is not None

            # now == expires_at exactly: _logically_expired() treats this as
            # expired (`now >= expires_at`), deliberately on the closed side
            # of the boundary (an approval is valid only strictly before its
            # deadline, consistent with ApprovalRecord.is_expired()).
            boundary_now = t0 + ttl_seconds
            results = await asyncio.gather(*[
                svc.consume(rid, action_hash=rec0.action_hash, transaction_id="t1",
                            payload_hash=rec0.payload_hash, now=boundary_now)
                for _ in range(8)
            ])

            successes = [r for r in results if r.ok]
            assert len(successes) == 0, (
                "at exactly expires_at, consume() must never succeed -- got "
                f"{len(successes)} success(es) out of {len(results)} concurrent attempts"
            )
            for r in results:
                assert "expired" in r.reason.lower(), (
                    f"inconsistent concurrent outcome at the expiry boundary: {r}"
                )
        finally:
            await client.aclose()

    run(_go())


# --------------------------------------------------------------------------
# 4. End-to-end re-confirmation: the real governed execute path (gateway +
#    EnforcementCoordinator + MandateVerifier) must still correctly BLOCK,
#    with zero actuator invocations, for an operation past its approval's
#    logical expiry -- now enforced at TWO independent layers (the signed
#    mandate's own exp claim, AND the approval registry itself), not one.
# --------------------------------------------------------------------------

def test_e2e_execute_blocked_past_logical_expiry_with_zero_actuator_calls():
    """Real-gateway re-confirmation of the PR #122 Section 1 finding, now
    captured as a committed, reproducible regression test (previously only
    an ad-hoc scratch script: ``ttl_bug_end_to_end_execute.py``).

    ``GovernanceService.execute_with_mandate`` always uses the REAL wall
    clock internally (``self._now()`` -- there is no injectable ``now`` at
    this layer, by design: it is the production entrypoint), so this test
    uses real short sleeps, exactly like the original scratch
    reproduction, rather than the synthetic-clock pattern used by the
    unit tests above. Everything runs inside ONE ``asyncio.run()`` so the
    real ``redis.asyncio`` client stays bound to a single event loop
    across every request (an ``httpx.AsyncClient`` over ``ASGITransport``,
    never the synchronous ``TestClient``, which does not guarantee a
    stable loop across separate calls against a real async backend)."""

    async def _go():
        import httpx
        from fastapi import FastAPI

        from mcc_core import (
            AuditLog,
            DecisionEngine,
            EnforcementCoordinator,
            ExecutionGate,
            InMemoryIdempotencyRegistry,
            InMemoryNonceRegistry,
            InMemoryRevocationRegistry,
            InMemoryVelocityRegistry,
            ProfileRegistry,
            SigningKey as SK,
        )
        import tempfile
        from pathlib import Path

        from gateway.governance_api import mount_approval_routes, mount_mandate_routes
        from gateway.governance_service import GovernanceService
        from gateway.trust import TrustSet

        policy_hash = "sha256:p"
        agent_headers = {"x-api-key": "agent-key"}
        op_headers = {"x-operator-key": "op-key"}
        ttl_seconds = 6
        delay_before_approve = 2
        delay_after_approve_before_execute = 4

        approver = SK.generate("apr-ttl-e2e")
        trust = TrustSet()
        trust.add_runtime_issuer("mcc/approvals", approver.kid, approver.public_key())
        dk = SK.generate("dk-ttl-e2e")
        engine = DecisionEngine(signing_key=dk, issuer="mcc", audience="gate",
                                 policy_id="p", policy_hash=policy_hash, token_ttl_seconds=600)
        gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                              nonce_registry=InMemoryNonceRegistry(), policy_hash=policy_hash)
        revocation = InMemoryRevocationRegistry()
        client, reg, _unused = _redis_service("e2e")
        approvals = ApprovalService(reg, approver)
        audit = AuditLog(str(Path(tempfile.mkdtemp(prefix="mcc-ttl-e2e-")) / "a.jsonl"))
        coord = EnforcementCoordinator(
            gate=gate, idempotency=InMemoryIdempotencyRegistry(),
            velocity=InMemoryVelocityRegistry(), audit=audit,
            profiles=ProfileRegistry.default_pilot(), revocation_registry=revocation,
            approvals=approvals)

        calls = []

        async def upstream(action, payload):
            calls.append((action, payload))
            return {"ok": True, "action": action}

        svc = GovernanceService(engine=engine, coordinator=coord, trust_set=trust,
                                 revocation_registry=revocation, approvals=approvals,
                                 upstream=upstream, policy_hash=policy_hash)
        app = FastAPI()
        mount_mandate_routes(app, svc, api_key="agent-key", operator_key="op-key")
        mount_approval_routes(app, svc, api_key="agent-key", operator_key="op-key")

        try:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
                payload = {"amount": 100}

                r = await http.post("/approvals", headers=agent_headers, json={
                    "actor": "agent/x", "action": "generic_op", "resource": "res-1",
                    "transaction_id": "txn-1", "policy_hash": policy_hash,
                    "payload": payload, "ttl_seconds": ttl_seconds})
                assert r.status_code == 200, r.text
                rid = r.json()["request_id"]

                await asyncio.sleep(delay_before_approve)
                r = await http.post(f"/approvals/{rid}/approve", headers=op_headers)
                assert r.status_code == 200, r.text
                mandate = r.json()["mandate"]
                assert mandate is not None

                await asyncio.sleep(delay_after_approve_before_execute)
                # total elapsed (delay_before_approve + delay_after_approve_
                # before_execute) now exceeds ttl_seconds: logically expired.
                out = await http.post(f"/approvals/{rid}/execute", headers=agent_headers, json={
                    "mandate": mandate, "actor": "agent/x", "action": "generic_op",
                    "resource": "res-1", "context": payload, "transaction_id": "txn-1",
                    "idempotency_key": "op-ttl-e2e-1"})
                body = out.json()

            assert body.get("status") != "EXECUTED", (
                "EXPLOIT: the governed execute path invoked the actuator for "
                f"an operation past its approval's logical expiry: {body}"
            )
            assert len(calls) == 0, f"actuator was invoked {len(calls)} time(s); expected 0"
        finally:
            await client.aclose()

    run(_go())
