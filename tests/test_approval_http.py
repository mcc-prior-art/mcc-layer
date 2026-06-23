"""ESCALATE approval HTTP API tests + the required end-to-end scenarios.

Human approval never executes; it mints a single-use signed mandate that the
agent then executes through the one coordinator path. Negative scenarios assert
the upstream is never reached.
"""

import asyncio
import tempfile
import time
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
    hash_payload,
)

from gateway.governance_api import mount_approval_routes, mount_mandate_routes
from gateway.governance_service import GovernanceService
from gateway.trust import TrustSet

POLICY = "sha256:p"
AGENT = {"x-api-key": "agent-key"}
OP = {"x-operator-key": "op-key"}
CTX = {"value": 1}


def build(upstream_ok=True):
    approver = SigningKey.generate("apr-1")
    trust = TrustSet()
    trust.add_runtime_issuer("mcc/approvals", approver.kid, approver.public_key())
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc", audience="gate",
                            policy_id="p", policy_hash=POLICY, token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY)
    revocation = InMemoryRevocationRegistry()
    approvals = ApprovalService(InMemoryApprovalRegistry(), approver)
    audit = AuditLog(str(Path(tempfile.mkdtemp(prefix="mcc-aht-")) / "a.jsonl"))
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=audit,
        profiles=ProfileRegistry.default_pilot(), revocation_registry=revocation,
        approvals=approvals)
    calls = []

    async def upstream(action, payload):
        calls.append((action, payload))
        if not upstream_ok:
            raise RuntimeError("upstream 500")
        return {"ok": True}

    svc = GovernanceService(engine=engine, coordinator=coord, trust_set=trust,
                            revocation_registry=revocation, approvals=approvals,
                            upstream=upstream, policy_hash=POLICY)
    app = FastAPI()
    mount_mandate_routes(app, svc, api_key="agent-key", operator_key="op-key")
    mount_approval_routes(app, svc, api_key="agent-key", operator_key="op-key")
    return svc, TestClient(app), calls


def create(client, *, policy_hash=POLICY, actor="agent/x", action="generic_op",
           resource="res-1", transaction_id="txn-1"):
    r = client.post("/approvals", headers=AGENT, json={
        "actor": actor, "action": action, "resource": resource,
        "transaction_id": transaction_id, "policy_hash": policy_hash,
        "payload_hash": hash_payload(CTX)})
    assert r.status_code == 200
    return r.json()["request_id"]


def execute(client, request_id, mandate, *, actor="agent/x", action="generic_op",
            resource="res-1", transaction_id="txn-1", idem=None):
    return client.post(f"/approvals/{request_id}/execute", headers=AGENT, json={
        "mandate": mandate, "actor": actor, "action": action, "resource": resource,
        "context": CTX, "transaction_id": transaction_id, "idempotency_key": idem})


# ---- Scenario 4: approve -> single successful execution ----

def test_escalate_approve_then_execute():
    _, client, calls = build()
    rid = create(client)
    assert client.get(f"/approvals/{rid}", headers=AGENT).json()["state"] == "PENDING"
    mandate = client.post(f"/approvals/{rid}/approve", headers=OP).json()["mandate"]
    assert mandate is not None  # approval minted authority, did not execute
    assert calls == []
    out = execute(client, rid, mandate, idem="op-1").json()
    assert out["status"] == "EXECUTED"
    assert len(calls) == 1
    assert client.get(f"/approvals/{rid}", headers=AGENT).json()["state"] == "CONSUMED"


# ---- Scenario 5: deny -> terminal ----

def test_escalate_deny_is_terminal():
    _, client, calls = build()
    rid = create(client)
    assert client.post(f"/approvals/{rid}/deny", headers=OP).json()["state"] == "DENIED"
    # Cannot approve a denied request.
    assert client.post(f"/approvals/{rid}/approve", headers=OP).status_code == 409
    assert calls == []


# ---- Scenario 7: single-use; second execution denied ----

def test_approval_single_use_second_execute_blocked():
    _, client, calls = build()
    rid = create(client)
    mandate = client.post(f"/approvals/{rid}/approve", headers=OP).json()["mandate"]
    first = execute(client, rid, mandate, idem="op-a").json()
    second = execute(client, rid, mandate, idem="op-b").json()
    assert first["status"] == "EXECUTED"
    assert second["status"] == "BLOCKED"
    assert len(calls) == 1  # upstream reached only once


# ---- Scenario 8: actor / resource substitution after approval ----

def test_actor_substitution_after_approval_blocked():
    _, client, calls = build()
    rid = create(client, actor="agent/x")
    mandate = client.post(f"/approvals/{rid}/approve", headers=OP).json()["mandate"]
    out = execute(client, rid, mandate, actor="agent/ATTACKER").json()
    assert out["status"] == "BLOCKED"
    assert calls == []


def test_resource_substitution_after_approval_blocked():
    _, client, calls = build()
    rid = create(client, resource="res-1")
    mandate = client.post(f"/approvals/{rid}/approve", headers=OP).json()["mandate"]
    out = execute(client, rid, mandate, resource="res-EVIL").json()
    assert out["status"] == "BLOCKED"
    assert calls == []


# ---- Scenario 9: policy drift -> fail closed (re-approval required) ----

def test_policy_drift_after_approval_blocked():
    _, client, calls = build()
    rid = create(client, policy_hash="sha256:OLD-POLICY")  # differs from service POLICY
    mandate = client.post(f"/approvals/{rid}/approve", headers=OP).json()["mandate"]
    out = execute(client, rid, mandate).json()
    assert out["status"] == "BLOCKED"  # POLICY_BINDING_MISMATCH
    assert calls == []


# ---- Scenario 6: expiry before use ----

def test_approval_expires_before_use():
    _, client, calls = build()
    rid = create(client)
    # Force expiry by approving an already-expired request.
    client.post(f"/approvals/{rid}/approve", headers=OP)  # APPROVED
    # A short-TTL request that lapses before consumption:
    r2 = client.post("/approvals", headers=AGENT, json={
        "actor": "agent/x", "action": "generic_op", "resource": "res-1",
        "transaction_id": "txn-2", "policy_hash": POLICY,
        "payload_hash": hash_payload(CTX), "ttl_seconds": 1})
    rid2 = r2.json()["request_id"]
    time.sleep(1.2)
    assert client.post(f"/approvals/{rid2}/approve", headers=OP).status_code == 409  # expired


# ---- Operator boundary ----

def test_approve_requires_operator():
    _, client, _ = build()
    rid = create(client)
    assert client.post(f"/approvals/{rid}/approve", headers=AGENT).status_code == 403


def test_strict_schema_on_create():
    _, client, _ = build()
    assert client.post("/approvals", headers=AGENT, json={
        "actor": "a", "action": "x", "unexpected": 1}).status_code == 422


# ---- Scenario: concurrent consumption single winner (service level) ----

def test_concurrent_execute_single_winner():
    svc, client, calls = build()
    rid = create(client)
    mandate = client.post(f"/approvals/{rid}/approve", headers=OP).json()["mandate"]

    async def race():
        return await asyncio.gather(*[
            svc.execute_with_approval(mandate=mandate, actor="agent/x", action="generic_op",
                                      resource="res-1", context=CTX, transaction_id="txn-1",
                                      idempotency_key=f"op-{i}")
            for i in range(8)])

    outcomes = asyncio.run(race())
    executed = [o for o in outcomes if o.status == "EXECUTED"]
    assert len(executed) == 1
    assert len(calls) == 1


# ---- Scenario 10: approval backend unavailable -> fail closed ----

def test_backend_unavailable_blocks_execution():
    from mcc_core import RedisApprovalRegistry

    class DownRedis:
        def __getattr__(self, _n):
            async def boom(*a, **k):
                raise ConnectionError("down")
            return boom

    approver = SigningKey.generate("apr-1")
    trust = TrustSet()
    trust.add_runtime_issuer("mcc/approvals", approver.kid, approver.public_key())
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc", audience="gate",
                            policy_id="p", policy_hash=POLICY, token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY)
    # The approval registry used by the COORDINATOR consume is down.
    down_approvals = ApprovalService(RedisApprovalRegistry(DownRedis()), approver)
    audit = AuditLog(str(Path(tempfile.mkdtemp(prefix="mcc-aht-down-")) / "a.jsonl"))
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=audit,
        profiles=ProfileRegistry.default_pilot(), approvals=down_approvals)
    calls = []

    async def upstream(a, p):
        calls.append((a, p)); return {"ok": True}

    # Mint a valid approval mandate out-of-band (so trust/authority pass) but the
    # coordinator's consume against the down backend must fail closed.
    from mcc_core import issue_mandate
    mandate = issue_mandate(approver, issuer="mcc/approvals", subject="agent/x",
                            action_scope=["generic_op"], resource_scope=["res-1"],
                            constraints={}, not_before=1, not_after=4_000_000_000,
                            mandate_id="apr-req-x",
                            extra={"approval_id": "req-x", "action_hash": "h",
                                   "transaction_id": "txn-1", "payload_hash": None,
                                   "single_use": True})
    svc = GovernanceService(engine=engine, coordinator=coord, trust_set=trust,
                            revocation_registry=InMemoryRevocationRegistry(),
                            approvals=down_approvals, upstream=upstream, policy_hash=POLICY)
    out = asyncio.run(svc.execute_with_approval(
        mandate=mandate, actor="agent/x", action="generic_op", resource="res-1",
        context=CTX, transaction_id="txn-1"))
    assert out.status == "BLOCKED"
    assert calls == []
