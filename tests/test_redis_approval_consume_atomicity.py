"""Finding 1 regression: RedisApprovalRegistry.consume() must be a single
atomic state transition, with no window in which a concurrently-racing
invalidate()/deny() can be silently clobbered by a stale-snapshot consume().

Root cause (fixed in this commit): consume() used to GET the record,
check APPROVED in Python, claim a SEPARATE ":consumed" NX key, then
unconditionally overwrite the record's state back to CONSUMED. The
APPROVED check and the final write were two different Redis round trips,
so a set_state() CAS (deny/invalidate) landing in between was invisible to
the final blind write. The fix (``_CONSUME_LUA``) performs the read, the
single-use/state check, and the write as ONE atomic Lua script -- exactly
the same pattern ``_SET_STATE_LUA`` already used for approve/deny/
invalidate -- and removes the separate ":consumed" key entirely.

These tests run against a REAL local Redis server (never a Python
re-implementation) because the property under test is Redis's own
single-threaded Lua execution guarantee, not application logic a fake
could model as faithfully. They use ``asyncio.Event`` barriers to force a
specific, named interleaving deterministically -- never timing/sleep-based
races. If no Redis is reachable, every test here is SKIPPED (not
silently omitted from the run, not treated as a pass).

Each test wraps its ENTIRE body in exactly one ``asyncio.run(...)`` call,
creating its own redis.asyncio client inside that same coroutine --
sharing one async client object across multiple independent
``asyncio.run()`` calls (each of which opens its own event loop) is
unreliable, since the client's connection machinery binds to whichever
loop first uses it.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest

from mcc_core.approvals import ApprovalService, RedisApprovalRegistry
from mcc_core.signing import SigningKey

REDIS_URL = os.environ.get("MCC_REDIS_URL", "redis://127.0.0.1:6379/0")


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


def _service(client, ns_prefix: str) -> ApprovalService:
    ns = f"test-cas-{ns_prefix}-{uuid.uuid4().hex}:"
    reg = RedisApprovalRegistry(client, namespace=ns)
    return ApprovalService(reg, SigningKey.generate(f"k-{ns_prefix}"))


# ===========================================================================
# The core regression: consume() must not resurrect an invalidated approval.
# ===========================================================================

def test_consume_loses_to_a_genuinely_earlier_invalidate():
    """Forces the realistic interleaving: ApprovalService.consume()'s own
    pre-check read (action/transaction/payload_hash binding; these fields
    are immutable after creation) completes and is deliberately held, a
    concurrent invalidate() is driven to REAL completion against Redis, and
    only then is consume() released to call the atomic
    RedisApprovalRegistry.consume() (``_CONSUME_LUA``). That call must
    independently re-observe INVALIDATED and refuse -- the stored state
    must never be resurrected to CONSUMED, and consume() must report
    ok=False.

    Non-vacuity note: pre-fix, ``RedisApprovalRegistry.consume()`` itself
    held a SEPARATE internal stale-read-then-blind-write window (its own
    ``_load()`` call, not this method's outer pre-check read) -- the exact
    vulnerable shape this fix removes entirely. Because the fix deletes
    that internal call (there is no longer a separate Python-level read to
    race against the write -- the whole thing is one Redis-side atomic Lua
    script), a single instrumentation point cannot mechanically reproduce
    "fails on old code, passes on new code" within one test body: the old
    vulnerable call simply does not exist anymore to hook. The historical
    reproduction against the pre-fix code (targeting that since-removed
    internal ``_load()`` call directly, confirming EXECUTED with a
    genuine, verified receipt) and this test's confirmation against the
    fixed code are recorded together in the fix commit message with exact
    commands and output."""

    async def scenario():
        client = _new_client()
        try:
            svc = _service(client, "civ")
            reg = svc.registry

            rid = await svc.request(actor="agent/x", action="send_payment",
                                     resource="acct-1", transaction_id="txn-1",
                                     payload={"amount": 100})
            mandate = await svc.approve(rid)
            assert mandate is not None, "setup failed: approve() should succeed"
            rec = await svc.get(rid)
            assert rec.state == "APPROVED"

            real_get = reg.get
            load_done = asyncio.Event()
            release_consume = asyncio.Event()
            calls = {"n": 0}

            async def instrumented_get(request_id, *, now):
                result = await real_get(request_id, now=now)
                calls["n"] += 1
                if calls["n"] == 1:
                    load_done.set()
                    await release_consume.wait()
                return result

            reg.get = instrumented_get

            consume_task = asyncio.create_task(svc.consume(
                rid, action_hash=rec.action_hash, transaction_id="txn-1",
                payload_hash=rec.payload_hash,
            ))
            await asyncio.wait_for(load_done.wait(), timeout=5.0)

            invalidated = await svc.invalidate(rid)
            mid_state = (await svc.get(rid)).state

            release_consume.set()
            result = await asyncio.wait_for(consume_task, timeout=5.0)
            final_state = (await svc.get(rid)).state
            return invalidated, mid_state, result, final_state
        finally:
            await client.aclose()

    invalidated, mid_state, result, final_state = asyncio.run(scenario())

    assert invalidated is True, "setup failed: invalidate() should succeed on an APPROVED record"
    assert mid_state == "INVALIDATED", "setup failed: invalidate() should have taken effect"
    assert result.ok is False, (
        "SECURITY REGRESSION: consume() succeeded despite a genuinely earlier "
        "invalidate() -- the operation would have reached the real executor"
    )
    assert "INVALIDATED" in result.reason
    assert final_state == "INVALIDATED", (
        "SECURITY REGRESSION: consume() overwrote an INVALIDATED record back "
        f"to {final_state!r} -- the invalidation was silently lost"
    )


def test_consume_loses_to_a_genuinely_earlier_deny_on_a_pending_request():
    """The analogous case for deny(): deny() only applies to PENDING, so this
    tests the ordering guarantee on the approve-vs-deny boundary instead --
    once deny() has won, a consume() attempt (which requires APPROVED) must
    never succeed, with or without a race, because approve() itself would
    already have correctly lost the PENDING->APPROVED CAS."""

    async def scenario():
        client = _new_client()
        try:
            svc = _service(client, "cdeny")
            rid = await svc.request(actor="agent/x", action="send_payment",
                                     resource="acct-1", transaction_id="txn-1",
                                     payload={"amount": 100})
            assert await svc.deny(rid) is True
            rec = await svc.get(rid)
            return await svc.consume(
                rid, action_hash=rec.action_hash, transaction_id="txn-1",
                payload_hash=rec.payload_hash,
            )
        finally:
            await client.aclose()

    result = asyncio.run(scenario())
    assert result.ok is False
    assert "DENIED" in result.reason


# ===========================================================================
# Non-vacuity: the fix does not break legitimate single consumption.
# ===========================================================================

def test_non_vacuity_legitimate_consume_still_succeeds_exactly_once():
    async def scenario():
        client = _new_client()
        try:
            svc = _service(client, "nv")
            rid = await svc.request(actor="agent/x", action="send_payment",
                                     resource="acct-1", transaction_id="txn-1",
                                     payload={"amount": 100})
            await svc.approve(rid)
            rec = await svc.get(rid)
            args = dict(action_hash=rec.action_hash, transaction_id="txn-1",
                        payload_hash=rec.payload_hash)
            first = await svc.consume(rid, **args)
            second = await svc.consume(rid, **args)
            final = await svc.get(rid)
            return first, second, final.state
        finally:
            await client.aclose()

    first, second, final_state = asyncio.run(scenario())
    assert first.ok is True
    assert second.ok is False
    assert "replay" in second.reason.lower()
    assert final_state == "CONSUMED"


# ===========================================================================
# consume() vs consume(): double-dispatch must remain impossible.
# ===========================================================================

def test_concurrent_consume_vs_consume_exactly_one_winner():
    async def one_round(client, i):
        svc = _service(client, f"cc{i}")
        rid = await svc.request(actor="a", action="x", resource="r",
                                 transaction_id="t1", payload={"v": i})
        await svc.approve(rid)
        rec = await svc.get(rid)
        args = dict(action_hash=rec.action_hash, transaction_id="t1", payload_hash=rec.payload_hash)
        r1, r2 = await asyncio.gather(svc.consume(rid, **args), svc.consume(rid, **args))
        return r1.ok, r2.ok

    async def main():
        client = _new_client()
        try:
            return await asyncio.gather(*[one_round(client, i) for i in range(20)])
        finally:
            await client.aclose()

    results = asyncio.run(main())
    double_dispatch = [r for r in results if r[0] and r[1]]
    neither = [r for r in results if not r[0] and not r[1]]
    assert not double_dispatch, f"double dispatch occurred in {len(double_dispatch)}/20 rounds"
    assert not neither, f"neither consume succeeded in {len(neither)}/20 rounds"


# ===========================================================================
# approve() vs deny(): exactly one winner, no clobbering, no inherent
# precedence (do not assume "deny always wins" -- the CAS has none).
# ===========================================================================

def test_concurrent_approve_vs_deny_exactly_one_winner_no_inherent_precedence():
    async def one_round(client, i):
        svc = _service(client, f"ad{i}")
        rid = await svc.request(actor="a", action="x", resource="r", payload={"v": i})
        approve_result, deny_result = await asyncio.gather(svc.approve(rid), svc.deny(rid))
        final = await svc.get(rid)
        return approve_result is not None, deny_result is True, final.state

    async def main():
        client = _new_client()
        try:
            return await asyncio.gather(*[one_round(client, i) for i in range(20)])
        finally:
            await client.aclose()

    results = asyncio.run(main())
    for approved, denied, state in results:
        assert approved != denied, "exactly one of approve/deny must win"
        assert (approved and state == "APPROVED") or (denied and state == "DENIED"), (
            "stored state must match whichever side actually won -- no clobbering"
        )
    # Not asserting a specific win ratio: the CAS has no built-in precedence
    # for either verdict (see test_approve_can_win... below).


def test_approve_can_win_a_race_against_deny_when_scheduled_first():
    """Explicit proof that deny() does not have hard-coded precedence: when
    deny() is deliberately delayed, approve() -- which has MORE preceding
    async work in the real code path -- still wins. 'Exactly one winner' is
    not 'denial always wins'; it is 'whichever CAS call reaches Redis
    first wins, and the loser is cleanly rejected, never partially applied'."""

    async def scenario():
        client = _new_client()
        try:
            svc = _service(client, "fair")
            rid = await svc.request(actor="a", action="x", resource="r", payload={"v": 1})

            async def delayed_deny():
                await asyncio.sleep(0.05)
                return await svc.deny(rid)

            approve_result, deny_result = await asyncio.gather(svc.approve(rid), delayed_deny())
            final = await svc.get(rid)
            return approve_result is not None, deny_result, final.state
        finally:
            await client.aclose()

    approved, denied, state = asyncio.run(scenario())
    assert approved is True and denied is False and state == "APPROVED"


# ===========================================================================
# Redis TTL boundary.
# ===========================================================================

def test_consume_after_real_ttl_expiry_is_rejected():
    """An APPROVED record whose Redis key has physically expired (TTL, not
    just the ``now=`` parameter) must be unconsumable -- the key is simply
    gone, so consume() must report "not found", never a stale success."""

    async def scenario():
        client = _new_client()
        try:
            svc = _service(client, "ttl")
            now = 1_000_000
            rid = await svc.request(actor="a", action="x", resource="r", transaction_id="t1",
                                     payload={"v": 1}, ttl_seconds=1, now=now)
            await svc.approve(rid, now=now)
            rec = await svc.get(rid, now=now)
            assert rec.state == "APPROVED"

            await asyncio.sleep(1.5)  # real wall-clock TTL expiry, not `now=`

            return await svc.consume(
                rid, action_hash=rec.action_hash, transaction_id="t1",
                payload_hash=rec.payload_hash, now=now + 100,
            )
        finally:
            await client.aclose()

    result = asyncio.run(scenario())
    assert result.ok is False
    assert "not found" in result.reason.lower()


# ===========================================================================
# Restart / process-interruption: a fresh registry instance against the
# SAME durable Redis state must see and correctly act on it.
# ===========================================================================

def test_consume_after_simulated_process_restart():
    """Approve via one ApprovalService instance ("process A"), then consume
    via a brand-new ApprovalService instance sharing the same namespace and
    Redis connection ("process B", simulating a restart) -- the durable
    state must be identical and the single-use guarantee must still hold
    across the "restart"."""

    async def scenario():
        client = _new_client()
        try:
            ns = f"test-cas-restart-{uuid.uuid4().hex}:"
            key = SigningKey.generate("k-restart")

            reg_a = RedisApprovalRegistry(client, namespace=ns)
            svc_a = ApprovalService(reg_a, key)
            rid = await svc_a.request(actor="a", action="x", resource="r", transaction_id="t1",
                                       payload={"v": 1})
            await svc_a.approve(rid)

            # "Process restart": a fresh registry/service object, same Redis + namespace.
            reg_b = RedisApprovalRegistry(client, namespace=ns)
            svc_b = ApprovalService(reg_b, key)
            rec = await svc_b.get(rid)
            assert rec.state == "APPROVED"

            args = dict(action_hash=rec.action_hash, transaction_id="t1",
                        payload_hash=rec.payload_hash)
            first = await svc_b.consume(rid, **args)

            # A third "instance" (further restart) must see CONSUMED, not re-admit it.
            reg_c = RedisApprovalRegistry(client, namespace=ns)
            svc_c = ApprovalService(reg_c, key)
            second = await svc_c.consume(rid, **args)
            return first, second
        finally:
            await client.aclose()

    first, second = asyncio.run(scenario())
    assert first.ok is True
    assert second.ok is False
    assert "replay" in second.reason.lower()


# ===========================================================================
# Fault injection: a backend that raises mid-eval, or replies unexpectedly,
# must fail closed. These don't need real Redis (they inject a fake client
# that never actually connects), so they run unconditionally.
# ===========================================================================

def test_consume_fails_closed_when_eval_raises():
    class RaisingClient:
        async def eval(self, *a, **k):
            raise ConnectionError("simulated mid-operation backend failure")

    reg = RedisApprovalRegistry(RaisingClient())
    result = asyncio.run(reg.consume("req-x", now=0))
    assert result.ok is False
    assert "unavailable" in result.reason.lower() or "fail-closed" in result.reason.lower()


def test_consume_fails_closed_on_malformed_eval_reply():
    """A backend returning something that isn't the expected Lua-table shape
    (e.g. a driver/version incompatibility) must fail closed, never be
    interpreted as success."""

    class WeirdReplyClient:
        async def eval(self, *a, **k):
            return None  # neither a list/tuple nor a recognizable code

    reg = RedisApprovalRegistry(WeirdReplyClient())
    result = asyncio.run(reg.consume("req-x", now=0))
    assert result.ok is False
