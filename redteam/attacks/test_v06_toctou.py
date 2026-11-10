"""V06 - Race conditions / TOCTOU between check and execution."""
import asyncio

from _harness import *


@attack(vector=6, severity="critical", title="25 concurrent executes with one idempotency key")
def test_concurrent_same_idempotency_key_executes_once():
    s = Stack()
    m = s.mandate()

    async def go():
        await asyncio.gather(*[s.execute(m, idempotency_key="same") for _ in range(25)],
                             return_exceptions=True)
    run(go())
    assert len(s.executed) == 1, f"{len(s.executed)} executions for one logical operation"


@attack(vector=6, severity="critical", title="25 concurrent replays of one decision token")
def test_concurrent_token_replay_executes_once():
    s = Stack()
    toks = spy_tokens(s)
    run(s.execute(s.mandate(), idempotency_key="first"))
    tok = toks[0]
    n = len(s.executed)

    async def ex():
        await asyncio.sleep(0)
        s.executed.append(("REPLAY", {}))

    async def go():
        await asyncio.gather(*[s.coordinator.enforce(token=tok, action=ACTION, payload=payment(),
                                                     executor=ex) for _ in range(25)],
                             return_exceptions=True)
    run(go())
    assert len(s.executed) == n, f"{len(s.executed) - n} replays executed"


@attack(vector=6, severity="high", title="Mandate revoked between authorization and actuation")
def test_revocation_between_check_and_execution():
    s = Stack()
    m = s.mandate(revocation_required=True)
    # The revoke lands mid-enforce: after the gate verified, before dispatch.
    real_consume = s.nonces.consume

    async def consume_then_revoke(*a, **kw):
        ok = await real_consume(*a, **kw)
        await s.revocation.revoke(m["mandate_id"])
        return ok
    s.nonces.consume = consume_then_revoke
    out = run(s.execute(m, idempotency_key="k"))
    assert s.executed == [], f"executed after revocation landed mid-flight ({out.reason})"


@attack(vector=6, severity="high", title="Approval invalidated while its execution is in flight")
def test_invalidate_races_approval_execute():
    s = Stack()
    req = run(s.service.create_approval(actor=ACTOR, action=ACTION, resource=RESOURCE,
                                        transaction_id="tx-1", policy_hash=POLICY_HASH,
                                        tenant_id=TENANT, payload=payment()))
    rid = req["request_id"]
    mandate = run(s.service.approve(rid))
    real_consume = s.nonces.consume

    async def consume_then_invalidate(*a, **kw):
        ok = await real_consume(*a, **kw)
        await s.service.invalidate(rid)
        return ok
    s.nonces.consume = consume_then_invalidate
    out = run(s.service.execute_with_approval(mandate=mandate, actor=ACTOR, action=ACTION,
                                              resource=RESOURCE, context=payment(),
                                              transaction_id="tx-1", idempotency_key="k",
                                              tenant_id=TENANT))
    assert s.executed == [], f"executed after invalidation ({out.reason})"


@attack(vector=6, severity="medium", title="Concurrent velocity reservations cannot jointly exceed the limit")
def test_concurrent_velocity_reservations():
    s = Stack(velocity_limits_for=pilot_limits_for())
    m = s.mandate()

    async def go():
        await asyncio.gather(*[s.execute(m, idempotency_key=f"c-{i}", context=payment(amount=4500))
                               for i in range(20)], return_exceptions=True)
    run(go())
    total = sum(p["amount"] for _, p in s.executed)
    assert total <= 10000 and len(s.executed) <= 3, f"{len(s.executed)} executed, total {total}"
