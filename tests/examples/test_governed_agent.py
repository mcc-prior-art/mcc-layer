"""Deterministic tests for the governed-agent example.

Proves the security invariants end-to-end through the real MCC-Core runtime:
no verified decision -> no execution; the executor is reached only via the gate;
replay/idempotency/velocity/approval all fail closed; Redis-backed state is one
state across two instances; Redis-required execution fails closed when Redis is
down; malformed/unknown verdicts never execute; audit linkage exists.
"""

import asyncio
import json
import os
from pathlib import Path

import pytest

from mcc_core import (
    AuditLog,
    RedisIdempotencyRegistry,
    RedisNonceRegistry,
    SigningKey,
    VelocityLimit,
    build_redis_client,
    redis_keys,
)

from examples.governed_agent.agent import Agent
from examples.governed_agent.mcc_client import GovernedMCCClient
from examples.governed_agent.mock_executor import MockExecutor, UnauthorizedExecution
from tests._fakeredis import DownRedis, FakeRedis

run = asyncio.run


def _client(executor, **kw):
    return GovernedMCCClient(executor=executor, **kw)


# ---- ALLOW / DENY / ESCALATE / CONSTRAIN ----

def test_allow_executes_once():
    ex = MockExecutor(); c = _client(ex)
    r = run(c.submit(Agent("agent/ops").propose("transfer_resource", resource="a", payload={"amount": 1000})))
    assert r.verdict == "ALLOW" and r.executed and ex.count() == 1


def test_deny_never_executes():
    ex = MockExecutor(); c = _client(ex)
    r = run(c.submit(Agent("agent/ops").propose("delete_resource", resource="a", payload={})))
    assert r.verdict == "DENY" and not r.executed and ex.count() == 0


def test_unresolved_escalate_never_executes():
    ex = MockExecutor(); c = _client(ex)
    r = run(c.submit(Agent("agent/intern").propose("transfer_resource", resource="a", payload={"amount": 100})))
    assert r.verdict == "ESCALATE" and not r.executed and ex.count() == 0


def test_constrain_executes_constrained_payload_only():
    ex = MockExecutor(); c = _client(ex)
    r = run(c.submit(Agent("agent/ops").propose("transfer_resource", resource="a", payload={"amount": 9000})))
    assert r.verdict == "CONSTRAIN" and r.executed
    assert r.proposed_payload == {"amount": 9000}
    assert r.authorized_payload == {"amount": 5000}
    assert ex.last().authorized_payload == {"amount": 5000}  # original 9000 never executed


# ---- ESCALATE approval loop ----

def test_escalate_then_valid_approval_executes_once():
    ex = MockExecutor(); c = _client(ex)
    a = Agent("agent/intern")
    p = a.propose("transfer_resource", resource="a", payload={"amount": 100})
    assert not run(c.submit(p)).executed
    aid = run(c.request_approval(p))
    assert run(c.approve(aid))
    r = run(c.execute_with_approval(p, aid))
    assert r.executed and ex.count() == 1


def test_forged_approval_rejected():
    ex = MockExecutor(); c = _client(ex)
    p = Agent("agent/intern").propose("transfer_resource", resource="a", payload={"amount": 100})
    r = run(c.execute_with_approval(p, "req-forged-nonexistent"))
    assert not r.executed and ex.count() == 0


def test_replayed_approval_rejected():
    ex = MockExecutor(); c = _client(ex)
    a = Agent("agent/intern")
    p = a.propose("transfer_resource", resource="a", payload={"amount": 100})
    run(c.submit(p)); aid = run(c.request_approval(p)); run(c.approve(aid))
    assert run(c.execute_with_approval(p, aid)).executed
    assert not run(c.execute_with_approval(p, aid)).executed  # single-use
    assert ex.count() == 1


def test_mismatched_approval_payload_rejected():
    ex = MockExecutor(); c = _client(ex)
    a = Agent("agent/intern")
    p = a.propose("transfer_resource", resource="a", payload={"amount": 100})
    run(c.submit(p)); aid = run(c.request_approval(p)); run(c.approve(aid))
    # Same approval, different payload than was approved -> bound consume fails closed.
    tampered = a.propose("transfer_resource", resource="a", payload={"amount": 999},
                         transaction_id=p.transaction_id)
    assert not run(c.execute_with_approval(tampered, aid)).executed
    assert ex.count() == 0


# ---- Replay / idempotency / velocity ----

def test_replay_same_nonce_blocked():
    ex = MockExecutor(); c = _client(ex)
    a = Agent("agent/ops")
    p = a.propose("transfer_resource", resource="a", payload={"amount": 100}, nonce="n-1")
    assert run(c.submit(p)).executed
    assert not run(c.submit(p)).executed  # nonce consumed
    assert ex.count() == 1


def test_idempotency_prevents_double_execution():
    ex = MockExecutor(); c = _client(ex)
    a = Agent("agent/ops")
    first = run(c.submit(a.propose("transfer_resource", resource="a", payload={"amount": 100}, idempotency_key="k1")))
    dup = run(c.submit(a.propose("transfer_resource", resource="a", payload={"amount": 100}, idempotency_key="k1")))
    assert first.executed and not dup.executed and ex.count() == 1


def test_conflicting_idempotency_binding_fails_closed():
    ex = MockExecutor(); c = _client(ex)
    a = Agent("agent/ops")
    run(c.submit(a.propose("transfer_resource", resource="a", payload={"amount": 100}, idempotency_key="k2")))
    conflict = run(c.submit(a.propose("transfer_resource", resource="a", payload={"amount": 200}, idempotency_key="k2")))
    assert not conflict.executed and ex.count() == 1


def test_velocity_threshold_blocks_with_runtime_verdict():
    ex = MockExecutor()
    limit = VelocityLimit(name="c2", window_seconds=3600, max_count=2, aggregate_by=("actor",))
    c = _client(ex, velocity_limits=[limit])
    a = Agent("agent/ops")
    results = [run(c.submit(a.propose("transfer_resource", resource="a", payload={"amount": 1}))) for _ in range(3)]
    assert [r.executed for r in results] == [True, True, False]
    assert results[2].verdict == "DENY"  # runtime-defined velocity verdict
    assert ex.count() == 2


# ---- Multi-instance shared Redis state ----

def _redis_client(executor, redis_client, signing_key, ns):
    return _client(
        executor, signing_key=signing_key,
        nonce_registry=RedisNonceRegistry(redis_client, namespace=redis_keys.prefix("nonce", ns)),
        idempotency_registry=RedisIdempotencyRegistry(redis_client, namespace=redis_keys.prefix("idem", ns)))


def test_redis_nonce_shared_across_two_instances_fakeredis():
    shared = FakeRedis()
    key = SigningKey.generate("shared")
    ns = {"MCC_ENV": "test"}
    ex_a, ex_b = MockExecutor(), MockExecutor()
    a = _redis_client(ex_a, shared, key, ns)
    b = _redis_client(ex_b, shared, key, ns)
    p = Agent("agent/ops").propose("transfer_resource", resource="a", payload={"amount": 10}, nonce="shared-n")
    assert run(a.submit(p)).executed          # instance A
    assert not run(b.submit(p)).executed       # instance B sees the consumed nonce
    assert ex_a.count() == 1 and ex_b.count() == 0


def test_redis_idempotency_shared_across_two_instances_fakeredis():
    shared = FakeRedis()
    key = SigningKey.generate("shared")
    ns = {"MCC_ENV": "test"}
    ex_a, ex_b = MockExecutor(), MockExecutor()
    a = _redis_client(ex_a, shared, key, ns)
    b = _redis_client(ex_b, shared, key, ns)
    agent = Agent("agent/ops")
    assert run(a.submit(agent.propose("transfer_resource", resource="a", payload={"amount": 10}, idempotency_key="op"))).executed
    # Different nonce so idempotency (not nonce) is what blocks on instance B.
    assert not run(b.submit(agent.propose("transfer_resource", resource="a", payload={"amount": 10}, idempotency_key="op"))).executed


# ---- Redis required but unavailable -> fail closed ----

def test_redis_unavailable_fails_closed():
    ex = MockExecutor()
    c = _client(ex, nonce_registry=RedisNonceRegistry(DownRedis(), namespace="x:"))
    r = run(c.submit(Agent("agent/ops").propose("transfer_resource", resource="a", payload={"amount": 10})))
    assert not r.executed and ex.count() == 0


# ---- Malformed / unknown verdict -> fail closed ----

def test_unknown_verdict_fails_closed():
    class _Bogus:
        def evaluate(self, **_):
            class _V: value = "MAYBE"
            class _D:
                verdict = _V(); reason = "x"; forward_context = {}; constraints = {}; applied_changes = []
            return _D()

    ex = MockExecutor(); c = _client(ex, authority=_Bogus())
    r = run(c.submit(Agent("agent/ops").propose("transfer_resource", resource="a", payload={"amount": 10})))
    assert not r.executed and r.verdict == "ERROR" and ex.count() == 0


def test_runtime_error_fails_closed():
    class _Boom:
        def evaluate(self, **_):
            raise RuntimeError("authority unavailable")

    ex = MockExecutor(); c = _client(ex, authority=_Boom())
    r = run(c.submit(Agent("agent/ops").propose("transfer_resource", resource="a", payload={"amount": 10})))
    assert not r.executed and ex.count() == 0


def test_missing_required_field_fails_closed():
    ex = MockExecutor(); c = _client(ex)
    p = Agent("agent/ops").propose("transfer_resource", resource="a", payload={"amount": 10}, nonce="")
    # empty nonce -> missing required field
    object.__setattr__(p, "nonce", "")
    r = run(c.submit(p))
    assert not r.executed and ex.count() == 0


# ---- Audit linkage + direct-bypass ----

def test_audit_linkage_for_successful_execution():
    ex = MockExecutor(); c = _client(ex)
    r = run(c.submit(Agent("agent/ops").propose("transfer_resource", resource="a", payload={"amount": 100})))
    assert r.executed and r.audit_ref
    assert AuditLog.verify_chain(c.audit.path)
    entries = [json.loads(l) for l in Path(c.audit.path).read_text().splitlines() if l.strip()]
    kinds = [e.get("kind") for e in entries]
    assert "pre_actuation" in kinds and "actuation_result" in kinds


def test_direct_executor_invocation_refused():
    ex = MockExecutor()
    with pytest.raises(UnauthorizedExecution):
        run(ex.execute("transfer_resource", {"amount": 100}))  # no authorization
    # An ungoverned token shape is also refused.
    with pytest.raises(UnauthorizedExecution):
        run(ex.execute("transfer_resource", {"amount": 100}, authorization={"decision": "DENY"}))
    assert ex.count() == 0


def test_agent_has_no_executor_reference():
    a = Agent("agent/ops")
    assert not any("exec" in attr.lower() for attr in vars(a))


# ---- Real Redis (only when CI provides it) ----

@pytest.mark.skipif(not os.environ.get("MCC_REDIS_URL"), reason="requires a real Redis (MCC_REDIS_URL)")
def test_real_redis_nonce_shared_across_two_instances():
    import uuid

    url = os.environ["MCC_REDIS_URL"]
    ns = {"MCC_ENV": "gademo-" + uuid.uuid4().hex[:8]}
    key = SigningKey.generate("shared")
    ex_a, ex_b = MockExecutor(), MockExecutor()
    a = _redis_client(ex_a, build_redis_client(url), key, ns)
    b = _redis_client(ex_b, build_redis_client(url), key, ns)
    p = Agent("agent/ops").propose("transfer_resource", resource="a", payload={"amount": 10},
                                   nonce="real-" + uuid.uuid4().hex)
    assert run(a.submit(p)).executed
    assert not run(b.submit(p)).executed
    assert ex_a.count() == 1 and ex_b.count() == 0
