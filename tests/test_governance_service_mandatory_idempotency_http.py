"""Round 25 remediation — HTTP/service-layer regression coverage for the
mandatory logical_operation_id invariant.

These drive ``/mandates/execute``, ``/approvals/{request_id}/execute``, and
``/consensus/execute`` through the REAL ``GovernanceService`` (in-process
FastAPI ``TestClient``, no mocks) with an otherwise genuinely valid,
authorized request that simply omits (or blanks) ``idempotency_key``, and
prove: BLOCKED, zero upstream calls. The transport schema still accepts a
missing/blank value (see ``gateway/governance_api.py`` — deliberately left
optional so unrelated earlier rejections keep their own BLOCKED business
reason instead of an opaque HTTP 422); the real, unavoidable rejection comes
from ``GovernanceService`` (defense-in-depth) and, underneath it,
``EnforcementCoordinator.enforce()`` itself (authoritative — see
``tests/test_coordinator_mandatory_logical_operation_id.py`` for the direct,
non-HTTP proof of that layer).
"""

import tempfile
from pathlib import Path

import pytest
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
    issue_mandate,
    issue_vote,
)

from gateway.governance_api import mount_approval_routes, mount_consensus_routes, mount_mandate_routes
from gateway.governance_service import GovernanceService
from gateway.trust import Issuer, IssuerKey, TrustSet

FUTURE = 4_000_000_000
PAST = 1
POLICY = "sha256:p"
AGENT = {"x-api-key": "agent-key"}
OP = {"x-operator-key": "op-key"}
ACTION = "generic_op"
RESOURCE = "res-1"
CTX = {"value": 1}


def _build():
    issuer_key = SigningKey.generate("iss-1")
    approver_key = SigningKey.generate("apr")
    trust = TrustSet([Issuer("axlogiq", [IssuerKey("iss-1", issuer_key.public_key())])])
    # The gateway is itself the approval issuer: trust its approver public key
    # so a mandate minted by ApprovalService.approve() resolves through the
    # SAME _authority_for() trust path as any other mandate.
    trust.add_runtime_issuer("mcc/approvals", approver_key.kid, approver_key.public_key())
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc", audience="gate",
                            policy_id="p", policy_hash=POLICY, token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY)
    revocation = InMemoryRevocationRegistry()
    approvals = ApprovalService(InMemoryApprovalRegistry(), approver_key)
    evaluators = [SigningKey.generate(f"eval-{i}") for i in range(3)]
    consensus_verifier = ConsensusVerifier(
        trusted_keys={k.kid: k.public_key() for k in evaluators},
        policy=ConsensusPolicy(threshold=3),
    )
    audit = AuditLog(str(Path(tempfile.mkdtemp(prefix="mcc-idem-http-")) / "a.jsonl"))
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=audit,
        profiles=ProfileRegistry.default_pilot(), revocation_registry=revocation,
        approvals=approvals,
    )
    calls = []

    async def upstream(action, payload):
        calls.append((action, payload))
        return {"ok": True, "action": action}

    svc = GovernanceService(engine=engine, coordinator=coord, trust_set=trust,
                            revocation_registry=revocation, approvals=approvals,
                            upstream=upstream, policy_hash=POLICY,
                            consensus_verifier=consensus_verifier)
    app = FastAPI()
    mount_mandate_routes(app, svc, api_key="agent-key", operator_key="op-key")
    mount_approval_routes(app, svc, api_key="agent-key", operator_key="op-key")
    mount_consensus_routes(app, svc, api_key="agent-key", operator_key="op-key")
    return svc, issuer_key, evaluators, TestClient(app), calls


def _mandate(issuer_key, **over):
    kw = dict(issuer="axlogiq", subject="agent/x", action_scope=[ACTION],
              resource_scope=[RESOURCE], constraints={}, not_before=PAST,
              not_after=FUTURE, revocation_required=False)
    kw.update(over)
    return issue_mandate(issuer_key, **kw)


def _votes(evaluators, *, nonce=None):
    return [issue_vote(evaluators[i], evaluator_id=f"eval-{i}", verdict="ALLOW", action=ACTION,
                       payload=CTX, actor="agent/x", not_before=0, not_after=FUTURE,
                       resource=RESOURCE, policy_hash=POLICY, nonce=nonce)
            for i in range(len(evaluators))]


# ---- /mandates/execute ----

@pytest.mark.parametrize("bad_key", [None, "", "   "])
def test_mandate_execute_without_logical_operation_id_blocks(bad_key):
    _svc, ik, _evals, client, calls = _build()
    body = {"mandate": _mandate(ik), "actor": "agent/x", "action": ACTION,
            "resource": RESOURCE, "context": CTX}
    if bad_key is not None:
        body["idempotency_key"] = bad_key
    r = client.post("/mandates/execute", headers=AGENT, json=body)
    assert r.status_code == 200  # a normal BLOCKED business response, not a schema 422
    out = r.json()
    assert out["status"] == "BLOCKED"
    assert "MISSING_LOGICAL_OPERATION_ID" in out["reason"]
    assert calls == []


def test_mandate_execute_with_logical_operation_id_still_executes():
    """Positive control: the otherwise-identical, correctly-keyed request
    actuates -- proving the block above is specific to the missing key, not
    an unrelated regression in this test's own mandate/authority setup."""
    _svc, ik, _evals, client, calls = _build()
    r = client.post("/mandates/execute", headers=AGENT, json={
        "mandate": _mandate(ik), "actor": "agent/x", "action": ACTION,
        "resource": RESOURCE, "context": CTX, "idempotency_key": "op-mandate-1"})
    assert r.json()["status"] == "EXECUTED"
    assert len(calls) == 1


# ---- /approvals/{request_id}/execute ----

@pytest.mark.parametrize("bad_key", [None, "", "   "])
def test_approval_execute_without_logical_operation_id_blocks(bad_key):
    svc, _ik, _evals, client, calls = _build()
    rid = client.post("/approvals", headers=AGENT, json={
        "actor": "agent/x", "action": ACTION, "resource": RESOURCE,
        "policy_hash": POLICY}).json()["request_id"]
    mandate = client.post(f"/approvals/{rid}/approve", headers=OP).json()["mandate"]
    body = {"mandate": mandate, "actor": "agent/x", "action": ACTION,
            "resource": RESOURCE, "context": CTX}
    if bad_key is not None:
        body["idempotency_key"] = bad_key
    r = client.post(f"/approvals/{rid}/execute", headers=AGENT, json=body)
    assert r.status_code == 200
    out = r.json()
    assert out["status"] == "BLOCKED"
    assert "MISSING_LOGICAL_OPERATION_ID" in out["reason"]
    assert calls == []


def test_approval_execute_with_logical_operation_id_still_executes():
    svc, _ik, _evals, client, calls = _build()
    rid = client.post("/approvals", headers=AGENT, json={
        "actor": "agent/x", "action": ACTION, "resource": RESOURCE,
        "policy_hash": POLICY, "payload": CTX}).json()["request_id"]
    mandate = client.post(f"/approvals/{rid}/approve", headers=OP).json()["mandate"]
    r = client.post(f"/approvals/{rid}/execute", headers=AGENT, json={
        "mandate": mandate, "actor": "agent/x", "action": ACTION,
        "resource": RESOURCE, "context": CTX, "idempotency_key": "op-approval-1"})
    assert r.json()["status"] == "EXECUTED"
    assert len(calls) == 1


# ---- /consensus/execute ----

@pytest.mark.parametrize("bad_key", [None, "", "   "])
def test_consensus_execute_without_logical_operation_id_blocks(bad_key):
    _svc, _ik, evals, client, calls = _build()
    body = {"votes": _votes(evals), "actor": "agent/x", "action": ACTION,
            "resource": RESOURCE, "context": CTX}
    if bad_key is not None:
        body["idempotency_key"] = bad_key
    r = client.post("/consensus/execute", headers=AGENT, json=body)
    assert r.status_code == 200
    out = r.json()
    assert out["status"] == "BLOCKED"
    assert "MISSING_LOGICAL_OPERATION_ID" in out["reason"]
    assert calls == []


def test_consensus_execute_with_logical_operation_id_still_executes():
    _svc, _ik, evals, client, calls = _build()
    r = client.post("/consensus/execute", headers=AGENT, json={
        "votes": _votes(evals), "actor": "agent/x", "action": ACTION,
        "resource": RESOURCE, "context": CTX, "idempotency_key": "op-consensus-1"})
    assert r.json()["status"] == "EXECUTED"
    assert len(calls) == 1
