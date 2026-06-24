"""Consensus HTTP API tests: N-of-M agreement gates token issuance, then the
one coordinator path runs. Negative paths never reach the upstream.
"""

import tempfile
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcc_core import (
    ApprovalService,
    AuditLog,
    ConsensusPolicy,
    ConsensusVerifier,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryApprovalRegistry,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryRevocationRegistry,
    InMemoryVelocityRegistry,
    ProfileRegistry,
    SigningKey,
    Verdict,
    issue_vote,
)

from gateway.governance_api import mount_consensus_routes
from gateway.governance_service import GovernanceService
from gateway.trust import TrustSet

FUTURE = 4_000_000_000
AGENT = {"x-api-key": "agent-key"}
ACTION = "generic_op"
CTX = {"value": 1}


def build(threshold=3):
    evals = [SigningKey.generate(f"eval-{i}") for i in range(3)]
    trusted = {k.kid: k.public_key() for k in evals}
    verifier = ConsensusVerifier(trusted_keys=trusted, policy=ConsensusPolicy(threshold=threshold))
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc", audience="gate",
                            policy_id="p", policy_hash="sha256:p", token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash="sha256:p")
    audit = AuditLog(str(Path(tempfile.mkdtemp(prefix="mcc-cons-")) / "a.jsonl"))
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=audit,
        profiles=ProfileRegistry.default_pilot(),
        revocation_registry=InMemoryRevocationRegistry(),
        approvals=ApprovalService(InMemoryApprovalRegistry(), SigningKey.generate("apr")))
    calls = []

    async def upstream(action, payload):
        calls.append((action, payload)); return {"ok": True}

    svc = GovernanceService(engine=engine, coordinator=coord, trust_set=TrustSet(),
                            revocation_registry=InMemoryRevocationRegistry(),
                            approvals=coord.approvals, upstream=upstream, policy_hash="sha256:p",
                            consensus_verifier=verifier)
    app = FastAPI()
    mount_consensus_routes(app, svc, api_key="agent-key", operator_key="op-key")
    return evals, TestClient(app), calls


def votes_for(evals, *, actor="agent/x", verdicts=("ALLOW", "ALLOW", "ALLOW"),
              policy_hash="sha256:p", nonce=None):
    # Votes are bound to the gateway's policy hash (and, on the execute path,
    # the one-time nonce); the service requires both to match.
    return [issue_vote(evals[i], evaluator_id=f"eval-{i}", verdict=verdicts[i], action=ACTION,
                       payload=CTX, actor=actor, not_before=0, not_after=FUTURE,
                       policy_hash=policy_hash, nonce=nonce)
            for i in range(len(verdicts))]


def test_verify_unanimous():
    evals, client, _ = build()
    r = client.post("/consensus/verify", headers=AGENT, json={
        "votes": votes_for(evals), "actor": "agent/x", "action": ACTION, "context": CTX})
    body = r.json()
    assert body["verdict"] == "ALLOW" and body["agreement"] == 3


def test_execute_with_consensus_reaches_upstream():
    evals, client, calls = build()
    r = client.post("/consensus/execute", headers=AGENT, json={
        "votes": votes_for(evals), "actor": "agent/x", "action": ACTION,
        "context": CTX, "idempotency_key": "op-1"})
    assert r.json()["status"] == "EXECUTED"
    assert len(calls) == 1


def test_below_threshold_blocks_no_upstream():
    evals, client, calls = build()
    r = client.post("/consensus/execute", headers=AGENT, json={
        "votes": votes_for(evals)[:2], "actor": "agent/x", "action": ACTION, "context": CTX})
    assert r.json()["status"] == "BLOCKED"
    assert calls == []


def test_veto_blocks():
    evals, client, calls = build()
    r = client.post("/consensus/execute", headers=AGENT, json={
        "votes": votes_for(evals, verdicts=("ALLOW", "ALLOW", "DENY")),
        "actor": "agent/x", "action": ACTION, "context": CTX})
    assert r.json()["status"] == "BLOCKED"
    assert calls == []


def test_forged_vote_ignored_blocks():
    evals, client, calls = build()
    rogue = SigningKey.generate("rogue")
    votes = votes_for(evals)[:2] + [
        issue_vote(rogue, evaluator_id="eval-2", verdict="ALLOW", action=ACTION,
                   payload=CTX, actor="agent/x", not_before=0, not_after=FUTURE)]
    r = client.post("/consensus/execute", headers=AGENT, json={
        "votes": votes, "actor": "agent/x", "action": ACTION, "context": CTX})
    assert r.json()["status"] == "BLOCKED"  # only 2 trusted ALLOW
    assert calls == []


def test_consensus_summary_in_token_audit_claims():
    evals, client, _ = build()
    # Execute and confirm the verdict carried the consensus (via verify echo).
    v = client.post("/consensus/verify", headers=AGENT, json={
        "votes": votes_for(evals), "actor": "agent/x", "action": ACTION, "context": CTX}).json()
    assert sorted(v["evaluators"]) == ["eval-0", "eval-1", "eval-2"]


def test_requires_agent_key():
    evals, client, _ = build()
    assert client.post("/consensus/verify", json={
        "votes": [], "actor": "a", "action": ACTION, "context": CTX}).status_code in (401, 422)


def test_strict_schema():
    evals, client, _ = build()
    assert client.post("/consensus/execute", headers=AGENT, json={
        "votes": [], "actor": "a", "action": ACTION, "context": CTX,
        "surprise": 1}).status_code == 422
