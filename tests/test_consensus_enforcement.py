"""Mandatory consensus at the coordinator: when ``require_consensus`` is set, no
governed action reaches actuation unless a valid N-of-M consensus, bound to the
token's exact action/actor/payload/resource/policy_hash/nonce, is supplied.

These tests exercise the coordinator gate directly (one layer below the HTTP
e2e in test_consensus_enforcement_http.py): every missing or invalid consensus
input fails closed *before* the executor runs, and the executor side effect
never fires on a block.
"""

import asyncio
from pathlib import Path

from mcc_core import (
    ActuationStatus,
    AuditLog,
    ConsensusPolicy,
    ConsensusVerifier,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryVelocityRegistry,
    ProfileRegistry,
    SigningKey,
    Verdict,
    issue_vote,
)

run = asyncio.run
NOW = 1_780_000_000
ACTION = "generic_op"
PAYLOAD = {"value": 1}
ACTOR = "agent/ops"
RESOURCE = "res-1"
POLICY_HASH = "sha256:p"
NONCE = "nonce-fixed-1"


def build(tmp_path, *, threshold=3, require_consensus=True):
    keys = [SigningKey.generate(f"eval-{i}") for i in range(3)]
    trusted = {k.kid: k.public_key() for k in keys}
    verifier = ConsensusVerifier(trusted_keys=trusted, policy=ConsensusPolicy(threshold=threshold))
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc/test", audience="gate",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH, token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH)
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=audit,
        profiles=ProfileRegistry.default_pilot(),
        consensus_verifier=verifier, require_consensus=require_consensus,
    )
    return keys, engine, coord, audit


def token_for(engine, *, nonce=NONCE, idem="op-1", actor=ACTOR, resource=RESOURCE):
    return engine.issue_token(
        verdict="ALLOW", subject=actor, action=ACTION, payload=PAYLOAD,
        idempotency_key=idem, actor_id=actor, resource_id=resource, nonce=nonce, now=NOW)


def votes_for(keys, *, verdicts=("ALLOW", "ALLOW", "ALLOW"), actor=ACTOR, payload=PAYLOAD,
              resource=RESOURCE, policy_hash=POLICY_HASH, nonce=NONCE, action=ACTION):
    return [issue_vote(keys[i], evaluator_id=f"eval-{i}", verdict=verdicts[i], action=action,
                       payload=payload, actor=actor, not_before=NOW - 10, not_after=NOW + 3600,
                       issued_at=NOW, resource=resource, policy_hash=policy_hash, nonce=nonce)
            for i in range(len(verdicts))]


def runner(record):
    async def executor():
        record.append("executed")
        return "upstream-ok"
    return executor


def enforce(coord, engine, votes, *, token=None, seen=None):
    seen = [] if seen is None else seen
    token = token or token_for(engine)
    res = run(coord.enforce(token=token, action=ACTION, payload=PAYLOAD,
                            executor=runner(seen), consensus_votes=votes, now=NOW))
    return res, seen


# ---- Valid 3-of-3 actuates ----

def test_valid_3_of_3_executes(tmp_path):
    keys, engine, coord, _ = build(tmp_path)
    res, seen = enforce(coord, engine, votes_for(keys))
    assert res.status == ActuationStatus.EXECUTED
    assert seen == ["executed"]


def test_consensus_verified_recorded_before_actuation(tmp_path):
    import json
    keys, engine, coord, audit = build(tmp_path)
    enforce(coord, engine, votes_for(keys))
    kinds = [json.loads(l)["kind"] for l in Path(audit.path).read_text().splitlines() if l.strip()]
    assert "consensus_verified" in kinds
    assert kinds.index("consensus_verified") < kinds.index("pre_actuation") < kinds.index("actuation_result")


# ---- Fail-closed: every invalid / incomplete input blocks and never executes ----

def test_missing_consensus_blocks(tmp_path):
    keys, engine, coord, _ = build(tmp_path)
    res, seen = enforce(coord, engine, None)
    assert res.status == ActuationStatus.BLOCKED and seen == []
    assert "consensus" in res.reason.lower()


def test_empty_votes_block(tmp_path):
    keys, engine, coord, _ = build(tmp_path)
    res, seen = enforce(coord, engine, [])
    assert res.status == ActuationStatus.BLOCKED and seen == []


def test_fewer_than_three_blocks(tmp_path):
    keys, engine, coord, _ = build(tmp_path)
    res, seen = enforce(coord, engine, votes_for(keys)[:2])
    assert res.status == ActuationStatus.BLOCKED and seen == []


def test_veto_blocks(tmp_path):
    keys, engine, coord, _ = build(tmp_path)
    res, seen = enforce(coord, engine, votes_for(keys, verdicts=("ALLOW", "ALLOW", "DENY")))
    assert res.status == ActuationStatus.BLOCKED and seen == []


def test_duplicate_evaluator_blocks(tmp_path):
    keys, engine, coord, _ = build(tmp_path)
    # eval-0 casts all three ballots -> counted once -> below threshold.
    votes = [issue_vote(keys[0], evaluator_id="eval-0", verdict="ALLOW", action=ACTION,
                        payload=PAYLOAD, actor=ACTOR, not_before=NOW - 10, not_after=NOW + 3600,
                        issued_at=NOW, resource=RESOURCE, policy_hash=POLICY_HASH, nonce=NONCE)
             for _ in range(3)]
    res, seen = enforce(coord, engine, votes)
    assert res.status == ActuationStatus.BLOCKED and seen == []


def test_untrusted_evaluator_blocks(tmp_path):
    keys, engine, coord, _ = build(tmp_path)
    rogue = SigningKey.generate("rogue")
    votes = votes_for(keys)[:2] + [
        issue_vote(rogue, evaluator_id="eval-2", verdict="ALLOW", action=ACTION, payload=PAYLOAD,
                   actor=ACTOR, not_before=NOW - 10, not_after=NOW + 3600, issued_at=NOW,
                   resource=RESOURCE, policy_hash=POLICY_HASH, nonce=NONCE)]
    res, seen = enforce(coord, engine, votes)
    assert res.status == ActuationStatus.BLOCKED and seen == []


def test_tampered_signature_blocks(tmp_path):
    keys, engine, coord, _ = build(tmp_path)
    votes = votes_for(keys)
    votes[2]["verdict"] = "DENY"  # mutate signed claim -> signature breaks
    res, seen = enforce(coord, engine, votes)
    assert res.status == ActuationStatus.BLOCKED and seen == []


def test_expired_vote_blocks(tmp_path):
    keys, engine, coord, _ = build(tmp_path)
    votes = votes_for(keys)
    votes[2] = issue_vote(keys[2], evaluator_id="eval-2", verdict="ALLOW", action=ACTION,
                          payload=PAYLOAD, actor=ACTOR, not_before=NOW - 100, not_after=NOW - 1,
                          issued_at=NOW - 100, resource=RESOURCE, policy_hash=POLICY_HASH, nonce=NONCE)
    res, seen = enforce(coord, engine, votes)
    assert res.status == ActuationStatus.BLOCKED and seen == []


def test_action_mismatch_blocks(tmp_path):
    keys, engine, coord, _ = build(tmp_path)
    votes = votes_for(keys)[:2] + votes_for(keys, action="other_op")[2:]
    res, seen = enforce(coord, engine, votes)
    assert res.status == ActuationStatus.BLOCKED and seen == []


def test_actor_mismatch_blocks(tmp_path):
    keys, engine, coord, _ = build(tmp_path)
    # Votes bound to a different actor than the token's actor_id.
    votes = votes_for(keys, actor="agent/someone-else")
    res, seen = enforce(coord, engine, votes)
    assert res.status == ActuationStatus.BLOCKED and seen == []


def test_resource_mismatch_blocks(tmp_path):
    keys, engine, coord, _ = build(tmp_path)
    votes = votes_for(keys, resource="res-EVIL")
    res, seen = enforce(coord, engine, votes)
    assert res.status == ActuationStatus.BLOCKED and seen == []


def test_payload_mismatch_blocks(tmp_path):
    keys, engine, coord, _ = build(tmp_path)
    votes = votes_for(keys, payload={"value": 999})
    res, seen = enforce(coord, engine, votes)
    assert res.status == ActuationStatus.BLOCKED and seen == []


def test_policy_hash_mismatch_blocks(tmp_path):
    keys, engine, coord, _ = build(tmp_path)
    votes = votes_for(keys, policy_hash="sha256:other-policy")
    res, seen = enforce(coord, engine, votes)
    assert res.status == ActuationStatus.BLOCKED and seen == []


def test_nonce_mismatch_blocks(tmp_path):
    keys, engine, coord, _ = build(tmp_path)
    # Votes bound to a different nonce than the token carries.
    votes = votes_for(keys, nonce="nonce-other")
    res, seen = enforce(coord, engine, votes)
    assert res.status == ActuationStatus.BLOCKED and seen == []


def test_replayed_evidence_onto_new_token_blocks(tmp_path):
    keys, engine, coord, _ = build(tmp_path)
    # A valid 3-of-3 executes once, bound to NONCE.
    res1, seen1 = enforce(coord, engine, votes_for(keys))
    assert res1.status == ActuationStatus.EXECUTED
    # Re-submitting the *same* evidence with a fresh token (new nonce) is rejected:
    # the votes are bound to the old nonce, which no longer matches.
    fresh_token = token_for(engine, nonce="nonce-fresh", idem="op-2")
    res2, seen2 = enforce(coord, engine, votes_for(keys), token=fresh_token, seen=[])
    assert res2.status == ActuationStatus.BLOCKED and seen2 == []


def test_no_verifier_configured_blocks(tmp_path):
    # require_consensus set but no verifier -> fail closed even with votes present.
    keys, engine, coord, _ = build(tmp_path)
    coord.consensus_verifier = None
    res, seen = enforce(coord, engine, votes_for(keys))
    assert res.status == ActuationStatus.BLOCKED and seen == []


# ---- When not required, the coordinator path is unchanged ----

def test_not_required_executes_without_votes(tmp_path):
    keys, engine, coord, _ = build(tmp_path, require_consensus=False)
    res, seen = enforce(coord, engine, None)
    assert res.status == ActuationStatus.EXECUTED and seen == ["executed"]
