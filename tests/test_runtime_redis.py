"""Multi-instance runtime tests: two MCC instances sharing one Redis enforce one
coherent governance state.

A shared FakeRedis behind two registries / two runtime instances models two MCC
processes pointed at the same Redis server. Proves the cross-instance guarantees
the production deployment depends on, plus fail-closed on Redis outage and that
the live /evaluate entrypoint uses the Redis-backed implementation when
configured.
"""

import asyncio
import json
import os
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import main
from mcc_core import (
    ExecutionGate,
    RedisIdempotencyRegistry,
    RedisNonceRegistry,
    RedisVelocityRegistry,
    SigningKey,
    VelocityDescriptor,
    VelocityLimit,
    issue_vote,
    redis_keys,
)
from mcc_core.idempotency import ReserveStatus

from tests._fakeredis import DownRedis, FakeRedis

run = asyncio.run
FUTURE = 4_000_000_000


# ---------- shared-Redis runtime fixture ----------

def _trust_file(tmp_path, evals):
    cfg = {"issuers": [
        {"issuer_id": f"e{i}", "enabled": True,
         "keys": [{"kid": e.kid, "public_key_b64": e.public_key_b64(), "not_after": None}]}
        for i, e in enumerate(evals)]}
    p = tmp_path / "evaluators.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    return p


def _shared_key_pem(tmp_path):
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    p = tmp_path / "signing.pem"
    p.write_bytes(pem)
    return p


def _two_instances(tmp_path, monkeypatch, *, redis_client, threshold=3):
    """Build two MCC instances that share one Redis client and one signing key —
    i.e. two runtime processes against the same Redis."""
    evals = [SigningKey.generate(f"eval-{i}") for i in range(3)]
    monkeypatch.setattr(main, "redis_client_from_env", lambda env=None: redis_client)
    monkeypatch.setattr(main.settings, "use_opa", False)
    monkeypatch.setattr(main.settings, "consensus_trust_config", str(_trust_file(tmp_path, evals)))
    monkeypatch.setattr(main.settings, "consensus_threshold", threshold)
    monkeypatch.setattr(main.settings, "governance_backend", "redis")
    monkeypatch.setattr(main.settings, "signing_key_path", str(_shared_key_pem(tmp_path)))
    monkeypatch.setattr(main.settings, "audit_log_path", str(tmp_path / "audit.jsonl"))
    a = main.MCC()
    b = main.MCC()
    assert a.governance is not None and b.governance is not None
    return a, b, evals


def _challenge(mcc, *, amount=100, resource="res-1", sid="s1"):
    return run(mcc.issue_challenge("t", main.ChallengeRequest(
        session_id=sid, intent="send_payment", args={"amount": amount}, resource=resource)))


def _votes(evals, ch, *, amount=100):
    return [issue_vote(evals[i], evaluator_id=f"eval-{i}", verdict="ALLOW", action=ch.action,
                       payload={"amount": amount}, actor=ch.actor, not_before=0, not_after=FUTURE,
                       resource=ch.resource, policy_hash=ch.policy_hash, nonce=ch.nonce)
            for i in range(3)]


def _decide(mcc, ch, votes, *, amount=100, resource="res-1", sid="s1"):
    return run(mcc.evaluate("t", main.EvaluateRequest(
        session_id=sid, intent="send_payment", args={"amount": amount}, resource=resource,
        challenge_id=ch.challenge_id if ch else None, votes=votes)))


# ---------- 5. live entrypoint uses Redis when configured ----------

def test_live_entrypoint_uses_redis_backed_state(tmp_path, monkeypatch):
    shared = FakeRedis()
    a, _b, _evals = _two_instances(tmp_path, monkeypatch, redis_client=shared)
    assert a.governance.replay_scope == "shared-redis"


# ---------- E2E: two instances share challenge/nonce state ----------

def test_two_instances_share_challenge_state_replay_denied(tmp_path, monkeypatch):
    shared = FakeRedis()
    a, b, evals = _two_instances(tmp_path, monkeypatch, redis_client=shared)
    # Instance A: issue challenge -> votes -> execute (ALLOW). Consumes the
    # challenge + nonce in the SHARED Redis.
    ch = _challenge(a)
    votes = _votes(evals, ch)
    out_a = _decide(a, ch, votes)
    assert out_a.decision.value == "ALLOW" and out_a.decision_token is not None
    # Instance B: the same challenge_id + votes is now spent in shared Redis.
    out_b = _decide(b, ch, votes)
    assert out_b.decision.value == "DENY"


# ---------- 1. nonce consumed on A is rejected on B (gate level) ----------

def test_nonce_consumed_on_A_rejected_on_B(tmp_path, monkeypatch):
    shared = FakeRedis()
    a, b, _ = _two_instances(tmp_path, monkeypatch, redis_client=shared)
    # A token signed by the shared key, verifiable by both gates.
    token = a.governance.engine.issue_token(
        verdict="ALLOW", subject="agent/x", action="send_payment", payload={"amount": 100},
        nonce="shared-nonce-1", actor_id="agent/x", resource_id="res-1")
    first = run(a.governance.gate.verify(token, action="send_payment", payload={"amount": 100}))
    second = run(b.governance.gate.verify(token, action="send_payment", payload={"amount": 100}))
    assert first.allowed is True
    assert second.allowed is False  # nonce consumed by A, visible to B


# ---------- 2. idempotency binding can't be inconsistently rebound on B ----------

def test_idempotency_cross_instance(tmp_path):
    shared = FakeRedis()
    ns = redis_keys.prefix("idem", {"MCC_ENV": "test"})
    reg_a = RedisIdempotencyRegistry(shared, namespace=ns)
    reg_b = RedisIdempotencyRegistry(shared, namespace=ns)
    first = run(reg_a.reserve("op-1", binding="payload-hash-A"))
    assert first.status == ReserveStatus.RESERVED
    # B sees the in-flight reservation; a conflicting binding cannot win.
    conflict = run(reg_b.reserve("op-1", binding="payload-hash-B"))
    assert conflict.status in (ReserveStatus.DUPLICATE_INFLIGHT, ReserveStatus.DUPLICATE_EXECUTED)
    assert not conflict.ok


def test_idempotency_concurrent_single_winner_cross_instance(tmp_path):
    shared = FakeRedis()
    ns = redis_keys.prefix("idem", {"MCC_ENV": "test"})
    a = RedisIdempotencyRegistry(shared, namespace=ns)
    b = RedisIdempotencyRegistry(shared, namespace=ns)

    async def race():
        return await asyncio.gather(*[
            (a if i % 2 == 0 else b).reserve("op-x", binding=f"b{i}") for i in range(12)])

    results = run(race())
    winners = [r for r in results if r.status == ReserveStatus.RESERVED]
    assert len(winners) == 1


# ---------- 3. velocity usage on A affects the verdict on B ----------

def test_velocity_cross_instance(tmp_path):
    shared = FakeRedis()
    ns = redis_keys.prefix("vel", {"MCC_ENV": "test"})
    a = RedisVelocityRegistry(shared, namespace=ns)
    b = RedisVelocityRegistry(shared, namespace=ns)
    limit = VelocityLimit(name="count1", window_seconds=3600, max_count=1, aggregate_by=("actor",))
    desc = VelocityDescriptor(dimensions={"actor": "agent/x"})
    first = run(a.reserve(limit, desc))
    second = run(b.reserve(limit, desc))  # shared counter already at 1
    assert first.ok and not second.ok


def test_velocity_aggregate_cross_instance_no_split_bypass(tmp_path):
    shared = FakeRedis()
    ns = redis_keys.prefix("vel", {"MCC_ENV": "test"})
    a = RedisVelocityRegistry(shared, namespace=ns)
    b = RedisVelocityRegistry(shared, namespace=ns)
    limit = VelocityLimit(name="amt", window_seconds=3600, max_amount=100.0, aggregate_by=("actor",))
    d1 = VelocityDescriptor(dimensions={"actor": "agent/x"}, amount=60.0)
    d2 = VelocityDescriptor(dimensions={"actor": "agent/x"}, amount=60.0)
    assert run(a.reserve(limit, d1)).ok            # 60 ok
    assert not run(b.reserve(limit, d2)).ok         # 120 > 100 across instances


# ---------- 4. Redis outage prevents execution (fail-closed) ----------

def test_runtime_redis_outage_fails_closed(tmp_path, monkeypatch):
    a, b, evals = _two_instances(tmp_path, monkeypatch, redis_client=DownRedis())
    ch_args = main.ChallengeRequest(session_id="s1", intent="send_payment",
                                    args={"amount": 100}, resource="res-1")
    # Issuing a challenge needs Redis -> fails closed (no challenge minted).
    with pytest.raises(Exception):
        run(a.issue_challenge("t", ch_args))


def test_registry_outage_fails_closed():
    down = DownRedis()
    nonce = RedisNonceRegistry(down, namespace="x:")
    idem = RedisIdempotencyRegistry(down, namespace="x:")
    vel = RedisVelocityRegistry(down, namespace="x:")
    assert run(nonce.consume("n", ttl_seconds=60)) is False
    assert run(idem.reserve("k")).status == ReserveStatus.ERROR
    limit = VelocityLimit(name="c", window_seconds=60, max_count=1)
    assert not run(vel.reserve(limit, VelocityDescriptor(dimensions={"actor": "a"}))).ok
