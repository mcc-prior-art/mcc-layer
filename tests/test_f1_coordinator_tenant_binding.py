"""F1 defense in depth at the actuation boundary.

``GovernanceService`` already refuses consensus votes for another tenant and
challenges issued to another tenant/principal before it issues a token. The
coordinator re-checks both against the token's SIGNED tenant when
``bind_consensus_tenant`` is on -- the setting every ``GovernanceService``
forces on its coordinator -- so a token that somehow carries foreign consensus
material still never actuates. These tests drive the coordinator directly
with genuinely signed tokens (no service in front) and pair each negative
with a positive control on the same coordinator.
"""
import asyncio

from mcc_core import (
    ActuationStatus,
    AuditLog,
    ChallengeService,
    ConsensusPolicy,
    ConsensusVerifier,
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
    issue_vote,
)

run = asyncio.run
NOW = 1_780_000_000
ACTION = "generic_op"
PAYLOAD = {"value": 1}
ACTOR = "agent/ops"
RESOURCE = "res-1"
POLICY_HASH = "sha256:p"
TENANT = "tenant-1"


def build(tmp_path, *, bind=True):
    evals = [SigningKey.generate(f"e{i}") for i in range(3)]
    verifier = ConsensusVerifier(trusted_keys={e.kid: e.public_key() for e in evals},
                                 policy=ConsensusPolicy(threshold=3))
    challenges = ChallengeService(InMemoryChallengeRegistry())
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc/test", audience="gate",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH, token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH)
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(), velocity=InMemoryVelocityRegistry(),
        audit=AuditLog(str(tmp_path / "audit.jsonl")), profiles=ProfileRegistry.default_pilot(),
        consensus_verifier=verifier, require_consensus=True, challenges=challenges,
        require_challenge=True, bind_consensus_tenant=bind)
    return evals, challenges, engine, coord


def challenge(challenges, *, tenant=TENANT, principal=ACTOR):
    return run(challenges.issue(action=ACTION, actor=ACTOR, resource=RESOURCE,
                                payload_hash=hash_payload(PAYLOAD), policy_hash=POLICY_HASH,
                                now=NOW, tenant_id=tenant, principal_id=principal))


def votes(evals, nonce, *, tenant=TENANT):
    return [issue_vote(e, evaluator_id=e.kid, verdict="ALLOW", action=ACTION, payload=PAYLOAD,
                       actor=ACTOR, not_before=0, not_after=NOW + 3600, resource=RESOURCE,
                       policy_hash=POLICY_HASH, nonce=nonce, tenant_id=tenant) for e in evals]


def token(engine, rec, *, idem, tenant=TENANT):
    return engine.issue_token(
        verdict="ALLOW", subject=ACTOR, action=ACTION, payload=PAYLOAD, idempotency_key=idem,
        actor_id=ACTOR, resource_id=RESOURCE, nonce=rec.nonce,
        auth_claims={"challenge_id": rec.challenge_id}, now=NOW, tenant_id=tenant)


def enforce(coord, tok, vs):
    seen = []

    async def executor():
        seen.append("executed")
        return "ok"
    res = run(coord.enforce(token=tok, action=ACTION, payload=PAYLOAD, executor=executor,
                            consensus_votes=vs, now=NOW))
    return res, seen


def test_bound_coordinator_executes_tenant_bound_material(tmp_path):
    evals, challenges, engine, coord = build(tmp_path)
    rec = challenge(challenges)
    res, seen = enforce(coord, token(engine, rec, idem="op-1"), votes(evals, rec.nonce))
    assert res.status == ActuationStatus.EXECUTED and seen == ["executed"]


def test_bound_coordinator_refuses_votes_for_another_or_no_tenant(tmp_path):
    for vote_tenant in ("tenant-other", None):
        evals, challenges, engine, coord = build(tmp_path)
        rec = challenge(challenges)
        res, seen = enforce(coord, token(engine, rec, idem="op-1"),
                            votes(evals, rec.nonce, tenant=vote_tenant))
        assert res.status == ActuationStatus.BLOCKED and seen == []
        assert "consensus required" in res.reason
        assert run(challenges.get(rec.challenge_id, now=NOW)).state == "ISSUED"   # not consumed


def test_bound_coordinator_refuses_a_challenge_issued_to_another_tenant(tmp_path):
    evals, challenges, engine, coord = build(tmp_path)
    rec = challenge(challenges, tenant="tenant-other")
    res, seen = enforce(coord, token(engine, rec, idem="op-1"), votes(evals, rec.nonce))
    assert res.status == ActuationStatus.BLOCKED and seen == []
    assert "CHALLENGE_TENANT_MISMATCH" in res.reason


def test_coordinator_refuses_a_challenge_issued_to_another_principal(tmp_path):
    evals, challenges, engine, coord = build(tmp_path)
    rec = challenge(challenges, principal="agent/someone-else")
    res, seen = enforce(coord, token(engine, rec, idem="op-1"), votes(evals, rec.nonce))
    assert res.status == ActuationStatus.BLOCKED and seen == []
    assert "CHALLENGE_PRINCIPAL_MISMATCH" in res.reason


def test_unscoped_coordinator_never_consumes_a_tenant_scoped_challenge(tmp_path):
    # An embedder without tenant binding (egress proxy runtime, MVP
    # interceptor, main.py) keeps the pre-F1 vote binding, but a challenge the
    # gateway scoped to a tenant is not consumable there.
    evals, challenges, engine, coord = build(tmp_path, bind=False)
    rec = challenge(challenges)
    res, seen = enforce(coord, token(engine, rec, idem="op-1"), votes(evals, rec.nonce))
    assert res.status == ActuationStatus.BLOCKED and seen == []
    assert "CHALLENGE_TENANT_MISMATCH" in res.reason
    # Positive control: an unscoped challenge on the unscoped coordinator.
    rec2 = challenge(challenges, tenant=None, principal=None)
    res, seen = enforce(coord, token(engine, rec2, idem="op-2"), votes(evals, rec2.nonce, tenant=None))
    assert res.status == ActuationStatus.EXECUTED and seen == ["executed"]


def test_governance_service_forces_tenant_binding_on_its_coordinator(tmp_path):
    from mcc_core import ApprovalService, InMemoryApprovalRegistry, InMemoryRevocationRegistry

    from gateway.governance_service import GovernanceService
    from gateway.trust import TrustSet

    evals, challenges, engine, coord = build(tmp_path, bind=False)
    assert coord.bind_consensus_tenant is False
    GovernanceService(engine=engine, coordinator=coord, trust_set=TrustSet(),
                      revocation_registry=InMemoryRevocationRegistry(),
                      approvals=ApprovalService(InMemoryApprovalRegistry(), SigningKey.generate("a")),
                      policy_hash=POLICY_HASH, consensus_verifier=coord.consensus_verifier,
                      challenge_service=challenges)
    assert coord.bind_consensus_tenant is True
    rec = challenge(challenges)
    res, seen = enforce(coord, token(engine, rec, idem="op-1"),
                        votes(evals, rec.nonce, tenant="tenant-other"))
    assert res.status == ActuationStatus.BLOCKED and seen == []
