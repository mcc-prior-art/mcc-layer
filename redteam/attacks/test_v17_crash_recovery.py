"""V17 - Crash recovery: IN_FLIGHT action executed twice or executed after DENY."""
from _harness import *
from mcc_core import ExecutionGate, InMemoryNonceRegistry


@attack(vector=17, severity="critical", title="Indeterminate (crashed) operation is not re-dispatched for the same key")
def test_unknown_outcome_not_redispatched():
    s = Stack(upstream_raises=True)
    m = s.mandate()
    first = run(s.execute(m, idempotency_key="op-1"))
    s.upstream_raises = False
    for _ in range(3):
        run(s.execute(m, idempotency_key="op-1"))
    assert first.status == "EXECUTION_FAILED" and len(s.executed) == 1, s.executed


@attack(vector=17, severity="critical", title="Crash after dispatch + gate restart: same operation key still blocked")
def test_unknown_outcome_survives_gate_restart():
    s = Stack(upstream_raises=True)
    toks = spy_tokens(s)
    m = s.mandate()
    run(s.execute(m, idempotency_key="op-1"))
    s.upstream_raises = False
    s.coordinator.gate = ExecutionGate(                      # nonce memory lost; idempotency store kept
        trusted_keys={s.signing_key.kid: s.signing_key.public_key()}, audience="pilot",
        nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH)

    async def ex():
        s.executed.append(("REPLAY", {}))
    run(s.coordinator.enforce(token=toks[0], action=ACTION, payload=payment(), executor=ex))
    assert len(s.executed) == 1, s.executed


@attack(vector=17, severity="critical", title="Same idempotency key cannot be rebound to a different payload")
def test_idempotency_key_rebinding():
    s = Stack()
    m = s.mandate()
    run(s.execute(m, idempotency_key="op-1", context=payment(amount=10)))
    run(s.execute(m, idempotency_key="op-1", context=payment(amount=4999, beneficiary_id="attacker")))
    assert len(s.executed) == 1, s.executed


@attack(vector=17, severity="critical", title="Single-use approval is not re-executable after a crashed dispatch")
def test_crashed_approval_execution_not_repeatable():
    s = Stack(upstream_raises=True)
    req = run(s.service.create_approval(actor=ACTOR, action=ACTION, resource=RESOURCE, transaction_id="tx-1",
                                        policy_hash=POLICY_HASH, tenant_id=TENANT, payload=payment()))
    m = run(s.service.approve(req["request_id"]))
    kw = dict(mandate=m, actor=ACTOR, action=ACTION, resource=RESOURCE, context=payment(),
              transaction_id="tx-1", tenant_id=TENANT)
    run(s.service.execute_with_approval(idempotency_key="k1", **kw))
    s.upstream_raises = False
    run(s.service.execute_with_approval(idempotency_key="k2", **kw))     # fresh key, same approval
    assert len(s.executed) == 1, s.executed


@attack(vector=17, severity="medium", kind="design-gap",
        title="Exactly-once is per caller-chosen idempotency key: a crashed op is re-sent under a new key")
def test_crashed_operation_resent_under_new_key():
    s = Stack(upstream_raises=True)
    m = s.mandate()
    run(s.execute(m, idempotency_key="op-1", transaction_id="tx-1"))     # outcome UNKNOWN, needs reconciliation
    s.upstream_raises = False
    out = run(s.execute(m, idempotency_key="op-1-retry", transaction_id="tx-1"))
    assert len(s.executed) == 1, \
        f"same transaction_id dispatched twice ({out.status}) while the first outcome is still UNKNOWN"


@attack(vector=17, severity="critical", title="A denied request leaves nothing executable behind")
def test_nothing_executable_after_deny():
    s = Stack()
    toks = spy_tokens(s)
    run(s.execute(s.mandate(), idempotency_key="k", action="wire_swift"))
    run(s.execute(s.mandate(constraints={"allowed_currency": ["USD"]}), idempotency_key="k2"))
    assert toks == [] and s.executed == []
