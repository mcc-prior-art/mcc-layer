"""Challenge consumption at the coordinator.

A token issued against a gateway challenge carries ``challenge_id`` in its
auth_claims. The coordinator consumes the challenge exactly once, bound to the
token's exact operation, before any reservation or execution. Unknown, expired,
reused, or mismatched challenges fail closed and never actuate.
"""

import asyncio
import json
from pathlib import Path

from mcc_core import (
    ActuationStatus,
    AuditLog,
    ChallengeService,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryChallengeRegistry,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryVelocityRegistry,
    ProfileRegistry,
    SigningKey,
    hash_payload,
)

run = asyncio.run
NOW = 1_780_000_000
ACTION = "generic_op"
PAYLOAD = {"value": 1}
ACTOR = "agent/ops"
RESOURCE = "res-1"
POLICY_HASH = "sha256:p"


def build(tmp_path):
    challenges = ChallengeService(InMemoryChallengeRegistry())
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc/test", audience="gate",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH, token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH)
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=audit,
        profiles=ProfileRegistry.default_pilot(), challenges=challenges)
    return challenges, engine, coord, audit


def a_challenge(challenges, *, action=ACTION, actor=ACTOR, resource=RESOURCE,
                payload=PAYLOAD, policy_hash=POLICY_HASH, ttl=120):
    return run(challenges.issue(action=action, actor=actor, resource=resource,
                                payload_hash=hash_payload(payload), policy_hash=policy_hash,
                                ttl_seconds=ttl, now=NOW))


def token_for(engine, rec, *, nonce=None, idem="op-1", actor=ACTOR, resource=RESOURCE):
    return engine.issue_token(
        verdict="ALLOW", subject=actor, action=ACTION, payload=PAYLOAD,
        idempotency_key=idem, actor_id=actor, resource_id=resource,
        nonce=nonce if nonce is not None else rec.nonce,
        auth_claims={"challenge_id": rec.challenge_id}, now=NOW)


def runner(record):
    async def executor():
        record.append("executed")
        return "ok"
    return executor


def enforce(coord, token, seen=None, *, now=NOW):
    seen = [] if seen is None else seen
    res = run(coord.enforce(token=token, action=ACTION, payload=PAYLOAD,
                            executor=runner(seen), now=now))
    return res, seen


# ---- Valid challenge actuates and is consumed once ----

def test_valid_challenge_executes(tmp_path):
    challenges, engine, coord, _ = build(tmp_path)
    rec = a_challenge(challenges)
    res, seen = enforce(coord, token_for(engine, rec))
    assert res.status == ActuationStatus.EXECUTED and seen == ["executed"]
    # The challenge is now consumed.
    assert run(challenges.get(rec.challenge_id, now=NOW)).state == "CONSUMED"


def test_challenge_consumed_recorded_before_actuation(tmp_path):
    challenges, engine, coord, audit = build(tmp_path)
    rec = a_challenge(challenges)
    enforce(coord, token_for(engine, rec))
    kinds = [json.loads(l)["kind"] for l in Path(audit.path).read_text().splitlines() if l.strip()]
    assert "challenge_consumed" in kinds
    assert kinds.index("challenge_consumed") < kinds.index("pre_actuation") < kinds.index("actuation_result")


# ---- Fail-closed paths ----

def test_reused_challenge_blocks_second(tmp_path):
    # The challenge nonce is also the token's one-time nonce, so a replay is
    # caught (defense in depth: the gate's nonce-consume and the challenge's
    # single-use consume both reject it). Either way: blocked, never forwarded.
    challenges, engine, coord, _ = build(tmp_path)
    rec = a_challenge(challenges)
    first, seen1 = enforce(coord, token_for(engine, rec, idem="op-1"))
    second, seen2 = enforce(coord, token_for(engine, rec, idem="op-2"))
    assert first.status == ActuationStatus.EXECUTED
    assert second.status == ActuationStatus.BLOCKED and seen2 == []
    # The challenge itself is spent.
    assert run(challenges.get(rec.challenge_id, now=NOW)).state == "CONSUMED"


def test_unknown_challenge_blocks(tmp_path):
    challenges, engine, coord, _ = build(tmp_path)
    rec = a_challenge(challenges)
    token = token_for(engine, rec)
    token["auth_claims"]["challenge_id"] = "chal-unknown"  # tamper is irrelevant; sig re-bind below
    # Re-sign so the gate accepts the token, then the challenge lookup fails.
    token = engine.issue_token(
        verdict="ALLOW", subject=ACTOR, action=ACTION, payload=PAYLOAD, idempotency_key="op-1",
        actor_id=ACTOR, resource_id=RESOURCE, nonce=rec.nonce,
        auth_claims={"challenge_id": "chal-unknown"}, now=NOW)
    res, seen = enforce(coord, token)
    assert res.status == ActuationStatus.BLOCKED and seen == []


def test_expired_challenge_blocks(tmp_path):
    challenges, engine, coord, _ = build(tmp_path)
    rec = a_challenge(challenges, ttl=60)
    res, seen = enforce(coord, token_for(engine, rec), now=NOW + 61)
    assert res.status == ActuationStatus.BLOCKED and seen == []


def test_nonce_mismatch_blocks(tmp_path):
    challenges, engine, coord, _ = build(tmp_path)
    rec = a_challenge(challenges)
    # Token carries a different nonce than the issued challenge.
    res, seen = enforce(coord, token_for(engine, rec, nonce="some-other-nonce"))
    assert res.status == ActuationStatus.BLOCKED and seen == []


def test_actor_mismatch_blocks(tmp_path):
    challenges, engine, coord, _ = build(tmp_path)
    rec = a_challenge(challenges, actor="agent/ops")
    # Token actor differs from the challenge's actor.
    res, seen = enforce(coord, token_for(engine, rec, actor="agent/evil"))
    assert res.status == ActuationStatus.BLOCKED and seen == []


def test_resource_mismatch_blocks(tmp_path):
    challenges, engine, coord, _ = build(tmp_path)
    rec = a_challenge(challenges, resource="res-1")
    res, seen = enforce(coord, token_for(engine, rec, resource="res-evil"))
    assert res.status == ActuationStatus.BLOCKED and seen == []
