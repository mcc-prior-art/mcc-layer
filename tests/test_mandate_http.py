"""Mandate HTTP API tests: contract, verification, governed execution, trust
admin, auth boundary, strict validation, and the no-bypass guarantee.

A controlled GovernanceService is built with in-memory backends and an injected
upstream, so we can assert exactly when (and whether) the upstream is reached —
proving governed execution only happens through the coordinator + gate.
"""

import tempfile
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcc_core import (
    ApprovalService,
    AuditLog,
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
)

from gateway.governance_api import mount_mandate_routes
from gateway.governance_service import GovernanceService
from gateway.trust import Issuer, IssuerKey, TrustSet

FUTURE = 4_000_000_000  # ~2096, well past real wall-clock now
PAST = 1
POLICY = "sha256:p"


def build(upstream_ok=True):
    issuer_key = SigningKey.generate("iss-1")
    trust = TrustSet([Issuer("axlogiq", [IssuerKey("iss-1", issuer_key.public_key())])])
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc", audience="gate",
                            policy_id="p", policy_hash=POLICY, token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY)
    revocation = InMemoryRevocationRegistry()
    approvals = ApprovalService(InMemoryApprovalRegistry(), SigningKey.generate("apr"))
    audit = AuditLog(str(Path(tempfile.mkdtemp(prefix="mcc-mht-")) / "a.jsonl"))
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=audit,
        profiles=ProfileRegistry.default_pilot(), revocation_registry=revocation,
        approvals=approvals,
    )
    calls = []

    async def upstream(action, payload):
        calls.append((action, payload))
        if not upstream_ok:
            raise RuntimeError("upstream 500")
        return {"ok": True, "action": action}

    svc = GovernanceService(engine=engine, coordinator=coord, trust_set=trust,
                            revocation_registry=revocation, approvals=approvals,
                            upstream=upstream, policy_hash=POLICY)
    app = FastAPI()
    mount_mandate_routes(app, svc, api_key="agent-key", operator_key="op-key")
    return svc, issuer_key, TestClient(app), calls


def mandate(issuer_key, **over):
    kw = dict(issuer="axlogiq", subject="agent/x", action_scope=["generic_op"],
              resource_scope=["res-1"], constraints={}, not_before=PAST,
              not_after=FUTURE, revocation_required=False)
    kw.update(over)
    return issue_mandate(issuer_key, **kw)


AGENT = {"x-api-key": "agent-key"}
OP = {"x-operator-key": "op-key"}


# ---- Contract / verification ----

def test_verify_valid_mandate():
    _, ik, client, _ = build()
    r = client.post("/mandates/verify", headers=AGENT, json={
        "mandate": mandate(ik), "subject": "agent/x", "action": "generic_op",
        "resource": "res-1"})
    assert r.status_code == 200 and r.json()["verified"] is True
    assert r.json()["issuer_id"] == "axlogiq"


def test_verify_unknown_issuer():
    _, ik, client, _ = build()
    rogue = SigningKey.generate("rogue-kid")
    r = client.post("/mandates/verify", headers=AGENT, json={
        "mandate": mandate(rogue), "subject": "agent/x", "action": "generic_op",
        "resource": "res-1"})
    assert r.json()["verified"] is False
    assert "UNKNOWN_KID" in r.json()["reason"]


def test_verify_requires_agent_key():
    _, ik, client, _ = build()
    r = client.post("/mandates/verify", json={
        "mandate": mandate(ik), "subject": "agent/x", "action": "generic_op"})
    assert r.status_code in (401, 422)


def test_strict_schema_rejects_unknown_fields():
    _, ik, client, _ = build()
    r = client.post("/mandates/verify", headers=AGENT, json={
        "mandate": mandate(ik), "subject": "agent/x", "action": "generic_op",
        "surprise": "field"})
    assert r.status_code == 422


# ---- Governed execution (E2E scenario 1) ----

def test_execute_valid_mandate_reaches_upstream():
    _, ik, client, calls = build()
    r = client.post("/mandates/execute", headers=AGENT, json={
        "mandate": mandate(ik), "actor": "agent/x", "action": "generic_op",
        "resource": "res-1", "context": {"value": 1}, "idempotency_key": "op-1"})
    assert r.status_code == 200
    assert r.json()["status"] == "EXECUTED"
    assert len(calls) == 1  # upstream reached exactly once, through the coordinator


# ---- Negative execution: nothing reaches upstream (E2E scenarios 2, 3) ----

def test_execute_revoked_mandate_blocked(scenario="revoked"):
    svc, ik, client, calls = build()
    m = mandate(ik, revocation_required=True)
    client.post(f"/mandates/{m['mandate_id']}/revoke", headers=OP)
    r = client.post("/mandates/execute", headers=AGENT, json={
        "mandate": m, "actor": "agent/x", "action": "generic_op",
        "resource": "res-1", "context": {"value": 1}})
    assert r.json()["status"] == "BLOCKED"
    assert calls == []  # upstream never reached


def test_execute_unknown_issuer_blocked():
    _, ik, client, calls = build()
    rogue = SigningKey.generate("rogue-kid")
    r = client.post("/mandates/execute", headers=AGENT, json={
        "mandate": mandate(rogue), "actor": "agent/x", "action": "generic_op",
        "resource": "res-1", "context": {}})
    assert r.json()["status"] == "BLOCKED"
    assert "UNKNOWN_KID" in r.json()["reason"]
    assert calls == []


def test_execute_expired_mandate_blocked():
    _, ik, client, calls = build()
    r = client.post("/mandates/execute", headers=AGENT, json={
        "mandate": mandate(ik, not_after=PAST), "actor": "agent/x",
        "action": "generic_op", "resource": "res-1", "context": {}})
    assert r.json()["status"] == "BLOCKED"
    assert calls == []


def test_execute_actor_substitution_blocked():
    _, ik, client, calls = build()
    r = client.post("/mandates/execute", headers=AGENT, json={
        "mandate": mandate(ik, subject="agent/x"), "actor": "agent/ATTACKER",
        "action": "generic_op", "resource": "res-1", "context": {}})
    assert r.json()["status"] == "BLOCKED"
    assert calls == []


def test_execute_out_of_scope_action_blocked():
    _, ik, client, calls = build()
    r = client.post("/mandates/execute", headers=AGENT, json={
        "mandate": mandate(ik, action_scope=["generic_op"]), "actor": "agent/x",
        "action": "delete_everything", "resource": "res-1", "context": {}})
    assert r.json()["status"] == "BLOCKED"
    assert calls == []


def test_execution_failure_reported_not_finalized():
    _, ik, client, calls = build(upstream_ok=False)
    r = client.post("/mandates/execute", headers=AGENT, json={
        "mandate": mandate(ik), "actor": "agent/x", "action": "generic_op",
        "resource": "res-1", "context": {}, "idempotency_key": "op-x"})
    assert r.json()["status"] == "EXECUTION_FAILED"
    assert len(calls) == 1  # the executor ran but the outcome is indeterminate


# ---- Revocation status + operator boundary ----

def test_revocation_status_and_operator_boundary():
    svc, ik, client, _ = build()
    m = mandate(ik)
    # Agent cannot revoke (operator boundary).
    assert client.post(f"/mandates/{m['mandate_id']}/revoke", headers=AGENT).status_code == 403
    # Operator can.
    assert client.post(f"/mandates/{m['mandate_id']}/revoke", headers=OP).json()["ok"] is True
    status = client.get(f"/mandates/{m['mandate_id']}/revocation", headers=AGENT).json()
    assert status["status"] == "REVOKED"


def test_trust_admin_requires_operator():
    _, ik, client, _ = build()
    assert client.get("/trust", headers=AGENT).status_code == 403
    summary = client.get("/trust", headers=OP).json()
    assert summary[0]["issuer_id"] == "axlogiq"
    assert "public_key_b64" not in str(summary)
