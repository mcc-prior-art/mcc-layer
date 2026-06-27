"""Tests for the supported pilot HTTP SDK (pilot.client.MCCGatewayClient).

The SDK is transport only: it talks to the real gateway app (in-process via the
FastAPI test client). It can read the four verdicts, drive the consensus path to a
governed EXECUTED, and inspect the audit chain — and it has NO method that reaches
a side effect except the governed /…/execute endpoints.
"""

import tempfile
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

import gateway.app as gw
from mcc_core import (
    ApprovalService,
    AuditLog,
    ConsensusPolicy,
    ConsensusVerifier,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryApprovalRegistry,
    InMemoryChallengeRegistry,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryRevocationRegistry,
    InMemoryVelocityRegistry,
    ChallengeService,
    ProfileRegistry,
    SigningKey,
    issue_vote,
)
from gateway.governance_api import mount_consensus_routes
from gateway.governance_service import GovernanceService
from gateway.trust import TrustSet
from pilot.client import Decision, MCCGatewayClient

FAR_FUTURE = 4_000_000_000


def _sdk(app, *, api_key="demo-key", operator_key=None):
    return MCCGatewayClient("http://testserver", api_key=api_key,
                            operator_key=operator_key, client=TestClient(app))


# ---------------- propose: the four verdicts (real pilot policy) ----------------

def test_propose_allow():
    c = _sdk(gw.app)
    r = c.propose(identity="agent/payments-bot", action="send_payment", context={"amount": 1000})
    assert r.decision == Decision.ALLOW and r.executable and r.decision_token is not None


def test_propose_constrain_clamps_body():
    c = _sdk(gw.app)
    r = c.propose(identity="agent/payments-bot", action="send_payment", context={"amount": 99000})
    assert r.decision == Decision.CONSTRAIN
    assert r.forward_context.get("amount") == 5000        # clamped to the mandate cap
    assert r.applied_constraints and r.decision_token is not None


def test_propose_escalate():
    c = _sdk(gw.app)
    r = c.propose(identity="agent/nobody", action="send_payment", context={"amount": 10})
    assert r.decision == Decision.ESCALATE and r.needs_approval and r.decision_token is None


def test_propose_deny():
    c = _sdk(gw.app)
    r = c.propose(identity="agent/ops-bot", action="delete_database", context={})
    assert r.decision == Decision.DENY and not r.executable and r.decision_token is None


def test_bad_api_key_is_transport_error():
    import pytest

    from pilot.client import MCCGatewayError
    c = _sdk(gw.app, api_key="wrong-key")
    with pytest.raises(MCCGatewayError):
        c.propose(identity="agent/payments-bot", action="send_payment", context={"amount": 1})


# ---------------- health / readiness / audit ----------------

def test_health_and_ready():
    c = _sdk(gw.app)
    assert c.health()["status"] == "ok"
    body = c.ready()
    # Default test env uses in-memory backends -> Redis not required -> ready.
    assert body["ready"] is True and c.is_ready() is True


def test_verify_chain():
    c = _sdk(gw.app)
    c.propose(identity="agent/payments-bot", action="send_payment", context={"amount": 1000})
    chain = c.verify_chain()
    assert chain["valid"] is True and chain["entries"] >= 1


def test_request_approval_creates_pending():
    c = _sdk(gw.app)
    out = c.request_approval(actor="agent/nobody", action="send_payment",
                             resource="acct-1", payload_hash="sha256:deadbeef")
    assert out["state"] == "PENDING" and out["request_id"]


def test_no_direct_execute_method():
    # The SDK exposes no way to run a side effect except governed /…/execute.
    names = [n for n in dir(MCCGatewayClient) if "execute" in n]
    assert set(names) == {"execute_with_approval", "execute_with_consensus", "execute_with_mandate"}


# ---------------- consensus path through the SDK ----------------

def _consensus_app(threshold=3):
    evals = [SigningKey.generate(f"eval-{i}") for i in range(3)]
    trusted = {k.kid: k.public_key() for k in evals}
    verifier = ConsensusVerifier(trusted_keys=trusted, policy=ConsensusPolicy(threshold=threshold))
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc", audience="gate",
                            policy_id="p", policy_hash="sha256:p", token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash="sha256:p")
    audit = AuditLog(str(Path(tempfile.mkdtemp(prefix="mcc-sdk-")) / "a.jsonl"))
    challenges = ChallengeService(InMemoryChallengeRegistry())
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=audit,
        profiles=ProfileRegistry.default_pilot(),
        revocation_registry=InMemoryRevocationRegistry(),
        approvals=ApprovalService(InMemoryApprovalRegistry(), SigningKey.generate("apr")),
        consensus_verifier=verifier, challenges=challenges)
    calls = []

    async def upstream(action, payload):
        calls.append((action, payload)); return {"ok": True}

    svc = GovernanceService(engine=engine, coordinator=coord, trust_set=TrustSet(),
                            revocation_registry=InMemoryRevocationRegistry(),
                            approvals=coord.approvals, upstream=upstream, policy_hash="sha256:p",
                            consensus_verifier=verifier, challenge_service=challenges)
    app = FastAPI()
    mount_consensus_routes(app, svc, api_key="agent-key", operator_key="op-key")
    return evals, app, calls


def _votes(evals, *, action, payload, actor, nonce, policy_hash="sha256:p",
           verdicts=("ALLOW", "ALLOW", "ALLOW")):
    return [issue_vote(evals[i], evaluator_id=f"eval-{i}", verdict=verdicts[i], action=action,
                       payload=payload, actor=actor, not_before=0, not_after=FAR_FUTURE,
                       policy_hash=policy_hash, nonce=nonce) for i in range(len(verdicts))]


def test_consensus_execute_through_sdk_reaches_upstream():
    evals, app, calls = _consensus_app()
    c = _sdk(app, api_key="agent-key", operator_key="op-key")
    ch = c.issue_challenge(actor="agent/x", action="generic_op", context={"value": 1})
    votes = _votes(evals, action="generic_op", payload={"value": 1}, actor="agent/x",
                   nonce=ch["nonce"])
    out = c.execute_with_consensus(votes=votes, actor="agent/x", action="generic_op",
                                   context={"value": 1}, nonce=ch["nonce"],
                                   challenge_id=ch["challenge_id"], idempotency_key="op-1")
    assert out.executed and len(calls) == 1


def test_consensus_verify_through_sdk():
    evals, app, _ = _consensus_app()
    c = _sdk(app, api_key="agent-key", operator_key="op-key")
    ch = c.issue_challenge(actor="agent/x", action="generic_op", context={"value": 1})
    votes = _votes(evals, action="generic_op", payload={"value": 1}, actor="agent/x",
                   nonce=ch["nonce"])
    out = c.verify_consensus(votes=votes, actor="agent/x", action="generic_op",
                             context={"value": 1}, nonce=ch["nonce"])
    assert out["verdict"] == "ALLOW" and out["agreement"] == 3


def test_consensus_below_threshold_blocks_no_upstream():
    evals, app, calls = _consensus_app()
    c = _sdk(app, api_key="agent-key", operator_key="op-key")
    ch = c.issue_challenge(actor="agent/x", action="generic_op", context={"value": 1})
    votes = _votes(evals, action="generic_op", payload={"value": 1}, actor="agent/x",
                   nonce=ch["nonce"])[:2]
    out = c.execute_with_consensus(votes=votes, actor="agent/x", action="generic_op",
                                   context={"value": 1}, nonce=ch["nonce"],
                                   challenge_id=ch["challenge_id"])
    assert not out.executed and calls == []
