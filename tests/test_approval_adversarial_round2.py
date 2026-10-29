"""PR #122 — second, independent adversarial pass requested after the TTL-fix
commit (12c1b3f) landed. Develops NEW adversarial tests distinct from
``tests/test_approval_ttl_expiry.py`` and ``tests/test_redis_approval_
consume_atomicity.py``, per that task's explicit instruction not to merely
re-run existing coverage. Three angles, none previously tested in this repo:

1. Clock skew between gateway instances (Section 2 of the task: "clock skew
   between gateway instances").
2. A genuine four-way simultaneous race on a single fresh record (previous
   coverage was pairwise: approve-vs-deny, consume-vs-invalidate).
3. Fault injection on ``set_state()`` specifically (the approve-half-step /
   deny / invalidate CAS) -- the existing fault-injection tests
   (``test_consume_fails_closed_when_eval_raises`` /
   ``..._on_malformed_eval_reply``) only ever targeted ``consume()``'s
   ``_CONSUME_LUA`` eval call, never ``set_state()``'s ``_SET_STATE_LUA``
   eval call.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest

from mcc_core.approvals import (
    ApprovalService,
    ApprovalState,
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
    ns = f"test-adv2-{ns_prefix}-{uuid.uuid4().hex}:"
    reg = RedisApprovalRegistry(client, namespace=ns)
    svc = ApprovalService(reg, SigningKey.generate(f"k-{ns_prefix}"))
    return client, reg, svc


# --------------------------------------------------------------------------
# 1. Clock skew between gateway instances.
#
# Finding (reported, NOT a code defect in this fix's scope -- see the PR
# report): every wall-clock expiry check in this codebase -- this registry's
# `now >= expires_at`, AND the independent signed mandate's own `ts >= exp`
# check in `MandateVerifier._verify()` -- uses whichever gateway instance's
# LOCAL `time.time()` happens to handle the request. If one instance's clock
# genuinely lags true time, a request routed to THAT instance will compute
# `now` as still-before `expires_at` even after the true deadline has
# passed, and the Lua CAS (which only ever sees the `now` value it was
# handed) has no way to detect this -- it is not a Redis/Lua bug, it is an
# inherent property of ANY wall-clock-based TTL check evaluated locally per
# instance. This test empirically demonstrates the dependency: a "lagging"
# instance (one that always computes `now` as a fixed offset BEHIND a
# "true" reference clock) can still successfully consume() an approval at a
# true-time point after which a correctly-clocked instance would have
# correctly rejected it as expired.
# --------------------------------------------------------------------------

def test_clock_skew_lagging_instance_can_consume_past_true_expiry():
    async def _go():
        client, reg, svc = _redis_service("skew")
        try:
            true_t0 = 10_000_000
            ttl_seconds = 10
            skew_seconds = 30  # the lagging instance's clock reads 30s behind true time

            rid = await svc.request(actor="a", action="x", resource="r",
                                     transaction_id="t1", payload={"v": 1},
                                     ttl_seconds=ttl_seconds, now=true_t0)
            rec0 = await svc.get(rid, now=true_t0)
            mandate = await svc.approve(rid, now=true_t0 + 1)
            assert mandate is not None

            true_now_at_consume = true_t0 + ttl_seconds + 5  # 5s past the TRUE deadline
            lagging_instance_now = true_now_at_consume - skew_seconds  # this instance's clock

            # Sanity: a correctly-clocked instance (using the true time) is
            # correctly rejected -- this is the already-fixed, correct behavior.
            correct_result = await svc.consume(
                rid, action_hash=rec0.action_hash, transaction_id="t1",
                payload_hash=rec0.payload_hash, now=true_now_at_consume,
            )
            assert correct_result.ok is False
            assert "expired" in correct_result.reason.lower()

            # The SAME durable record, consumed again (replay aside -- this
            # is a FRESH record for the lagging-instance half of the test;
            # correct_result above must not have mutated state since it was
            # rejected before any write).
            lagging_result = await svc.consume(
                rid, action_hash=rec0.action_hash, transaction_id="t1",
                payload_hash=rec0.payload_hash, now=lagging_instance_now,
            )
            assert lagging_result.ok is True, (
                "expected finding: a gateway instance whose clock lags true "
                "time by more than the margin can still successfully "
                "consume() an approval that a correctly-clocked instance "
                "would reject -- confirms wall-clock TTL enforcement here "
                "(and in MandateVerifier's own `exp` check, which has the "
                "identical dependency) requires synchronized clocks across "
                "every instance; this is an operational/NTP requirement, "
                "not a Lua/Redis logic defect, and is unchanged by this "
                "fix's TTL-preservation correction"
            )
        finally:
            await client.aclose()

    run(_go())


# --------------------------------------------------------------------------
# 2. Four-way simultaneous race on a single fresh PENDING record: approve,
# deny, invalidate, AND an opportunistic consume all launched together
# (previous coverage was strictly pairwise). Exactly one of
# {approve, deny, invalidate} may win (consume cannot win from PENDING --
# it requires APPROVED, so it must always lose here), and the final
# durable state must be exactly one of the three terminal/transitional
# outcomes, never corrupted, never a hybrid, never silently lost.
# --------------------------------------------------------------------------

def test_four_way_simultaneous_race_exactly_one_winner_no_corruption():
    async def _go():
        client, reg, svc = _redis_service("fourway")
        try:
            rid = await svc.request(actor="a", action="x", resource="r",
                                     transaction_id="t1", payload={"v": 1},
                                     ttl_seconds=300)
            rec0 = await svc.get(rid)

            approve_task = svc.approve(rid)
            deny_task = svc.deny(rid)
            invalidate_task = svc.invalidate(rid)
            consume_task = svc.consume(
                rid, action_hash=rec0.action_hash, transaction_id="t1",
                payload_hash=rec0.payload_hash,
            )

            approve_res, deny_res, invalidate_res, consume_res = await asyncio.gather(
                approve_task, deny_task, invalidate_task, consume_task,
            )

            winners = []
            if approve_res is not None:
                winners.append("approve")
            if deny_res is True:
                winners.append("deny")
            if invalidate_res is True:
                winners.append("invalidate")

            # invalidate()'s `expect` set deliberately includes APPROVED (an
            # already-approved-but-not-yet-executed mandate must stay
            # revocable), so {"approve", "invalidate"} is a LEGITIMATE
            # sequential outcome (approve wins the PENDING slot; invalidate
            # then wins the following APPROVED->INVALIDATED transition) --
            # not corruption. approve and deny are mutually exclusive (both
            # only ever match PENDING, so whichever CAS consumes it first
            # permanently excludes the other); deny and invalidate are
            # mutually exclusive (DENIED is terminal and never in
            # invalidate's expect set, so deny winning excludes invalidate
            # entirely, and vice versa).
            assert winners in (["approve"], ["deny"], ["invalidate"], ["approve", "invalidate"]), (
                f"impossible/corrupted combination of winners: {winners} "
                f"(approve={approve_res!r} deny={deny_res!r} invalidate={invalidate_res!r})"
            )
            # consume() can never win here: it requires APPROVED, and even
            # if approve() wins the three-way race, consume()'s own eval is
            # a fully separate, independently-ordered Redis round trip that
            # was fired at the same instant approve()'s CAS had not
            # necessarily landed yet -- it may race-win against a
            # just-approved record (a legitimate "approved and immediately
            # consumed" linearization) or lose; both are permitted outcomes
            # of the no-invented-precedence contract. What must NEVER
            # happen is consume() succeeding when the winner was deny or
            # invalidate.
            if consume_res.ok:
                assert winners == ["approve"], (
                    f"consume() succeeded ({consume_res}) but the state-CAS "
                    f"winner was {winners}, not approve -- this would mean "
                    f"actuation proceeded without a legitimate APPROVED "
                    f"authorization"
                )

            final = await svc.get(rid)
            assert final.state in {
                ApprovalState.APPROVED.value, ApprovalState.DENIED.value,
                ApprovalState.INVALIDATED.value, ApprovalState.CONSUMED.value,
            }, f"corrupted/unexpected final state: {final.state!r}"
            # The final state must be consistent with exactly one winner:
            # if deny or invalidate won, the final state can ONLY be that
            # (never APPROVED, never CONSUMED -- this is the Finding-1
            # property, re-verified under 4-way rather than 2-way contention).
            if winners == ["deny"]:
                assert final.state == ApprovalState.DENIED.value
            elif winners == ["invalidate"]:
                assert final.state == ApprovalState.INVALIDATED.value
        finally:
            await client.aclose()

    run(_go())


def test_four_way_race_repeated_20_rounds_no_corruption():
    """Same race, repeated with fresh records, to surface any low-probability
    interleaving a single run might miss (mirrors the existing engagement's
    20-round convention for 2-way races)."""

    async def _go():
        client, reg, svc = _redis_service("fourway-repeat")
        try:
            for _ in range(20):
                rid = await svc.request(actor="a", action="x", resource="r",
                                         transaction_id="t1", payload={"v": 1},
                                         ttl_seconds=300)
                rec0 = await svc.get(rid)

                approve_res, deny_res, invalidate_res, consume_res = await asyncio.gather(
                    svc.approve(rid), svc.deny(rid), svc.invalidate(rid),
                    svc.consume(rid, action_hash=rec0.action_hash, transaction_id="t1",
                                payload_hash=rec0.payload_hash),
                )
                winners = [n for n, v in (
                    ("approve", approve_res is not None),
                    ("deny", deny_res is True),
                    ("invalidate", invalidate_res is True),
                ) if v]
                assert winners in (["approve"], ["deny"], ["invalidate"], ["approve", "invalidate"]), (
                    f"impossible/corrupted combination of winners: {winners}"
                )
                if consume_res.ok:
                    assert winners == ["approve"]
        finally:
            await client.aclose()

    run(_go())


# --------------------------------------------------------------------------
# 3. Fault injection on set_state() specifically (approve's half-step /
# deny() / invalidate()'s shared CAS) -- not previously covered; the
# existing fault-injection tests only ever targeted consume()'s eval call.
# --------------------------------------------------------------------------

def test_set_state_fails_closed_when_eval_raises():
    class RaisingClient:
        async def eval(self, *a, **k):
            raise ConnectionError("simulated mid-operation backend failure")

    reg = RedisApprovalRegistry(RaisingClient())
    ok = run(reg.set_state(
        "req-x", expect=[ApprovalState.PENDING], to=ApprovalState.APPROVED, now=0,
    ))
    assert ok is False, "set_state() must fail closed (return False) when eval() raises"


def test_set_state_fails_closed_on_malformed_eval_reply():
    class WeirdReplyClient:
        async def eval(self, *a, **k):
            return "not-an-int"  # malformed: Lua always returns 0/1 for this script

    reg = RedisApprovalRegistry(WeirdReplyClient())
    ok = run(reg.set_state(
        "req-x", expect=[ApprovalState.PENDING], to=ApprovalState.APPROVED, now=0,
    ))
    assert ok is False, "set_state() must fail closed on an unexpected/malformed eval reply"


def test_set_state_fails_closed_when_eval_returns_none():
    class NoneReplyClient:
        async def eval(self, *a, **k):
            return None

    reg = RedisApprovalRegistry(NoneReplyClient())
    ok = run(reg.set_state(
        "req-x", expect=[ApprovalState.PENDING], to=ApprovalState.APPROVED, now=0,
    ))
    assert ok is False, "set_state() must fail closed when eval() returns None"
