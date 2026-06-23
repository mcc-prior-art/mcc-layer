"""EnforcementCoordinator tests: the explicit a-h execution order and the
cross-cutting guarantees that depend on it.
"""

import asyncio
import json
from pathlib import Path

from mcc_core import (
    ActuationStatus,
    AuditLog,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryVelocityRegistry,
    PaymentProfile,
    ProfileRegistry,
    RedisIdempotencyRegistry,
    SigningKey,
    VelocityLimit,
    Verdict,
)

run = asyncio.run
NOW = 1_780_000_000
PROFILE = PaymentProfile()


class DownRedis:
    def __getattr__(self, _n):
        async def boom(*a, **k):
            raise ConnectionError("down")
        return boom


def build(tmp_path, *, limits=None, idempotency=None, velocity=None):
    key = SigningKey.generate("k1")
    engine = DecisionEngine(
        signing_key=key, issuer="mcc/test", audience="gate",
        policy_id="pilot/v1", policy_hash="sha256:p", token_ttl_seconds=60,
    )
    gate = ExecutionGate(
        trusted_keys={key.kid: key.public_key()}, audience="gate",
        nonce_registry=InMemoryNonceRegistry(), policy_hash="sha256:p",
    )
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    coord = EnforcementCoordinator(
        gate=gate,
        idempotency=idempotency or InMemoryIdempotencyRegistry(),
        velocity=velocity or InMemoryVelocityRegistry(),
        audit=audit,
        profiles=ProfileRegistry.default_pilot(),
        velocity_limits_for=lambda action: (limits or []),
    )
    return engine, coord, audit


def payment(engine, *, idem, amount=1000, actor="actor-1", txn=None, beneficiary="ben-1"):
    ctx = {"source": "acct-1", "beneficiary_id": beneficiary, "amount": amount, "currency": "usd"}
    payload = PROFILE.canonical_payload(ctx)
    token = engine.issue_token(
        verdict="ALLOW", subject=actor, action="send_payment", payload=payload,
        transaction_id=txn or idem, idempotency_key=idem, actor_id=actor,
        resource_id="acct-1", auth_claims=PROFILE.auth_claims(ctx), now=NOW,
    )
    return token, payload


def runner(record):
    async def executor():
        record.append("executed")
        return "upstream-ok"
    return executor


# ---- Happy path + ordering ----

def test_happy_path_executes_and_finalizes(tmp_path):
    engine, coord, audit = build(tmp_path)
    token, payload = payment(engine, idem="op-1")
    seen = []
    res = run(coord.enforce(token=token, action="send_payment", payload=payload,
                            executor=runner(seen), now=NOW))
    assert res.status == ActuationStatus.EXECUTED
    assert res.execution == "upstream-ok"
    assert seen == ["executed"]
    assert run(coord.idempotency.get_state("op-1")).value == "EXECUTED"


def test_audit_before_actuation_ordering(tmp_path):
    engine, coord, audit = build(tmp_path)
    token, payload = payment(engine, idem="op-1")
    run(coord.enforce(token=token, action="send_payment", payload=payload,
                      executor=runner([]), now=NOW))
    entries = [json.loads(l) for l in Path(audit.path).read_text().splitlines() if l.strip()]
    kinds = [e.get("kind") for e in entries]
    assert "pre_actuation" in kinds and "actuation_result" in kinds
    assert kinds.index("pre_actuation") < kinds.index("actuation_result")


# ---- Replay / shared idempotency key ----

def test_same_token_replay_blocked(tmp_path):
    engine, coord, audit = build(tmp_path)
    token, payload = payment(engine, idem="op-1")
    first = run(coord.enforce(token=token, action="send_payment", payload=payload,
                              executor=runner([]), now=NOW))
    second = run(coord.enforce(token=token, action="send_payment", payload=payload,
                               executor=runner([]), now=NOW))
    assert first.status == ActuationStatus.EXECUTED
    assert second.status == ActuationStatus.BLOCKED  # nonce already consumed


def test_different_tokens_same_idempotency_key_blocked(tmp_path):
    engine, coord, audit = build(tmp_path)
    t1, p1 = payment(engine, idem="op-shared", txn="txn-A")
    t2, p2 = payment(engine, idem="op-shared", txn="txn-B")  # distinct token, same idem key
    first = run(coord.enforce(token=t1, action="send_payment", payload=p1,
                              executor=runner([]), now=NOW))
    second = run(coord.enforce(token=t2, action="send_payment", payload=p2,
                               executor=runner([]), now=NOW))
    assert first.status == ActuationStatus.EXECUTED
    assert second.status == ActuationStatus.BLOCKED
    assert "executed" in second.reason.lower()


def test_concurrent_duplicate_exactly_one_winner(tmp_path):
    engine, coord, audit = build(tmp_path)
    tokens = [payment(engine, idem="op-shared", txn=f"txn-{i}") for i in range(8)]
    seen = []

    async def race():
        return await asyncio.gather(*[
            coord.enforce(token=t, action="send_payment", payload=p,
                          executor=runner(seen), now=NOW)
            for t, p in tokens
        ])

    results = run(race())
    executed = [r for r in results if r.status == ActuationStatus.EXECUTED]
    assert len(executed) == 1
    assert seen == ["executed"]  # the side effect ran exactly once


# ---- Velocity / anti-splitting through the coordinator ----

def test_four_tokens_cannot_bypass_cumulative_ceiling(tmp_path):
    limit = VelocityLimit(name="amt", window_seconds=3600, max_amount=10000,
                          aggregate_by=("actor",))
    engine, coord, audit = build(tmp_path, limits=[limit])
    statuses = []
    for i in range(4):
        token, payload = payment(engine, idem=f"op-{i}", amount=3000, beneficiary=f"ben-{i}")
        res = run(coord.enforce(token=token, action="send_payment", payload=payload,
                                executor=runner([]), now=NOW))
        statuses.append(res.status)
    assert statuses[:3] == [ActuationStatus.EXECUTED] * 3
    assert statuses[3] == ActuationStatus.BLOCKED


def test_concurrent_aggregate_race_never_overspends(tmp_path):
    limit = VelocityLimit(name="amt", window_seconds=3600, max_amount=10000,
                          aggregate_by=("actor",))
    engine, coord, audit = build(tmp_path, limits=[limit])
    tokens = [payment(engine, idem=f"op-{i}", amount=3000, beneficiary=f"ben-{i}")
              for i in range(12)]

    async def race():
        return await asyncio.gather(*[
            coord.enforce(token=t, action="send_payment", payload=p,
                          executor=runner([]), now=NOW)
            for t, p in tokens
        ])

    results = run(race())
    executed = [r for r in results if r.status == ActuationStatus.EXECUTED]
    assert len(executed) * 3000 <= 10000  # ceiling never bypassed


# ---- Fail-closed ----

def test_idempotency_outage_fails_closed(tmp_path):
    engine, coord, audit = build(
        tmp_path, idempotency=RedisIdempotencyRegistry(DownRedis())
    )
    token, payload = payment(engine, idem="op-1")
    res = run(coord.enforce(token=token, action="send_payment", payload=payload,
                            executor=runner([]), now=NOW))
    assert res.status == ActuationStatus.BLOCKED
    assert "fail-closed" in res.reason.lower()


def test_binding_mismatch_blocks_before_execution(tmp_path):
    engine, coord, audit = build(tmp_path)
    token, payload = payment(engine, idem="op-1", actor="actor-1")
    seen = []
    res = run(coord.enforce(token=token, action="send_payment", payload=payload,
                            executor=runner(seen),
                            request_binding={"actor_id": "actor-EVIL"}, now=NOW))
    assert res.status == ActuationStatus.BLOCKED
    assert seen == []  # never executed


# ---- Execution failure frees the key for retry ----

def test_execution_failure_frees_key_for_retry(tmp_path):
    engine, coord, audit = build(tmp_path)
    token, payload = payment(engine, idem="op-1")

    async def boom():
        raise RuntimeError("upstream 500")

    res = run(coord.enforce(token=token, action="send_payment", payload=payload,
                            executor=boom, now=NOW))
    assert res.status == ActuationStatus.EXECUTION_FAILED
    # The idempotency key is freed (FAILED), so a deliberate retry is possible.
    assert run(coord.idempotency.get_state("op-1")) is None
