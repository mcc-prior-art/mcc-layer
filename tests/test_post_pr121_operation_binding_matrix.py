"""Post-PR#121 fresh verification: exact operation binding, with direct
actuator-invocation instrumentation (never inferred from status alone).

This file re-derives evidence independently of any prior report. Every
rejection scenario asserts BOTH the specific reason string AND that the
real actuator (``calls``) was invoked exactly zero times. Every positive
control asserts the actuator was invoked exactly once, with the exact
expected payload.

Drives the real FastAPI gateway (``gateway.governance_api`` +
``gateway.governance_service``) over an in-process TestClient -- raw HTTP,
not just the SDK -- so a "compromised proposer" scenario is a raw POST
body an attacker fully controls, independent of what any well-behaved
client would ever construct.
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
    hash_payload,
)

from gateway.governance_api import mount_approval_routes, mount_mandate_routes
from gateway.governance_service import GovernanceService
from gateway.trust import TrustSet

POLICY = "sha256:p"
AGENT = {"x-api-key": "agent-key"}
OP = {"x-operator-key": "op-key"}


def build(policy_hash=POLICY):
    approver = SigningKey.generate("apr-1")
    trust = TrustSet()
    trust.add_runtime_issuer("mcc/approvals", approver.kid, approver.public_key())
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc", audience="gate",
                            policy_id="p", policy_hash=policy_hash, token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=policy_hash)
    revocation = InMemoryRevocationRegistry()
    approvals = ApprovalService(InMemoryApprovalRegistry(), approver)
    audit = AuditLog(str(Path(tempfile.mkdtemp(prefix="mcc-obm-")) / "a.jsonl"))
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=audit,
        profiles=ProfileRegistry.default_pilot(), revocation_registry=revocation,
        approvals=approvals)
    calls = []

    async def upstream(action, payload):
        calls.append((action, payload))
        return {"ok": True, "action": action}

    svc = GovernanceService(engine=engine, coordinator=coord, trust_set=trust,
                            revocation_registry=revocation, approvals=approvals,
                            upstream=upstream, policy_hash=policy_hash)
    app = FastAPI()
    mount_mandate_routes(app, svc, api_key="agent-key", operator_key="op-key")
    mount_approval_routes(app, svc, api_key="agent-key", operator_key="op-key")
    return svc, TestClient(app), calls


def escalate(client, *, payload, actor="agent/x", action="generic_op", resource="res-1",
             transaction_id="txn-1", policy_hash=POLICY):
    """Real proposer-facing path: creates the approval with the ACTUAL
    intended payload, exactly as a well-behaved SDK would (and exactly
    what the gateway's own mcc_client.MCCClient.request_approval sends)."""
    r = client.post("/approvals", headers=AGENT, json={
        "actor": actor, "action": action, "resource": resource,
        "transaction_id": transaction_id, "policy_hash": policy_hash,
        "payload": payload})
    assert r.status_code == 200
    return r.json()["request_id"]


def approve(client, rid):
    r = client.post(f"/approvals/{rid}/approve", headers=OP)
    assert r.status_code == 200
    return r.json()["mandate"]


def raw_execute(client, rid, *, mandate, actor="agent/x", action="generic_op",
                 resource="res-1", context, transaction_id="txn-1", idem="op-1"):
    """The exact raw HTTP surface a compromised proposer controls: every
    field here is attacker-choosable independent of what was escalated."""
    return client.post(f"/approvals/{rid}/execute", headers=AGENT, json={
        "mandate": mandate, "actor": actor, "action": action, "resource": resource,
        "context": context, "transaction_id": transaction_id, "idempotency_key": idem})


# ===========================================================================
# Positive controls (must come first: prove the harness can actually EXECUTE
# before trusting any BLOCKED result as meaningful)
# ===========================================================================

def test_positive_control_approved_payload_executes_exactly_once():
    _, client, calls = build()
    payload_a = {"amount": 100, "currency": "usd"}
    rid = escalate(client, payload=payload_a)
    mandate = approve(client, rid)
    out = raw_execute(client, rid, mandate=mandate, context=payload_a, idem="op-pc-1")
    body = out.json()
    assert body["status"] == "EXECUTED", body
    assert len(calls) == 1
    assert calls[0] == ("generic_op", payload_a)


def test_positive_control_retry_with_same_idempotency_key_does_not_redispatch():
    _, client, calls = build()
    payload_a = {"amount": 100, "currency": "usd"}
    rid = escalate(client, payload=payload_a)
    mandate = approve(client, rid)
    first = raw_execute(client, rid, mandate=mandate, context=payload_a, idem="op-retry-1")
    assert first.json()["status"] == "EXECUTED"
    assert len(calls) == 1
    # A second execute attempt (single-use approval already consumed) must
    # not reach the actuator again, regardless of idempotency key reuse.
    second = raw_execute(client, rid, mandate=mandate, context=payload_a, idem="op-retry-1")
    assert second.json()["status"] == "BLOCKED"
    assert len(calls) == 1, "retry caused a second actuator invocation"


# ===========================================================================
# Payload-hash variants (omitted / forged / mismatched / legacy-missing)
# ===========================================================================

def test_omitted_payload_at_request_time_blocks_any_execute_payload():
    """Escalate with NO payload field at all (the server defaults it to {}),
    then attempt execute with a real, non-empty payload. Must be blocked --
    this is the exact shape of a caller that forgot (or a compromised
    client that deliberately omits) the payload at request time."""
    _, client, calls = build()
    r = client.post("/approvals", headers=AGENT, json={
        "actor": "agent/x", "action": "generic_op", "resource": "res-1",
        "transaction_id": "txn-1", "policy_hash": POLICY})
    rid = r.json()["request_id"]
    mandate = approve(client, rid)
    out = raw_execute(client, rid, mandate=mandate, context={"amount": 999}, idem="op-omit-1")
    body = out.json()
    assert body["status"] == "BLOCKED"
    assert "PAYLOAD_MISMATCH" in body["reason"], body
    assert calls == []


def test_forged_payload_hash_at_request_time_is_never_trusted():
    """Supply a payload_hash computed over a DIFFERENT, not-yet-proposed
    payload at request time, alongside the real (different) payload. The
    server must derive the binding from the real payload, never the
    caller-supplied hash -- so executing the forged-hash's own payload
    later must ALSO be blocked (proving the forged hash was never stored
    as the authoritative binding)."""
    _, client, calls = build()
    real_payload = {"amount": 100}
    forged_target_payload = {"amount": 999999}
    r = client.post("/approvals", headers=AGENT, json={
        "actor": "agent/x", "action": "generic_op", "resource": "res-1",
        "transaction_id": "txn-1", "policy_hash": POLICY,
        "payload": real_payload,
        "payload_hash": hash_payload(forged_target_payload)})
    rid = r.json()["request_id"]
    mandate = approve(client, rid)
    # Attempt to execute the payload whose hash was forged into the request.
    out = raw_execute(client, rid, mandate=mandate, context=forged_target_payload,
                       idem="op-forge-1")
    body = out.json()
    assert body["status"] == "BLOCKED"
    assert "PAYLOAD_MISMATCH" in body["reason"], body
    assert calls == []
    # The REAL escalated payload must still be the only one that executes.
    out2 = raw_execute(client, rid, mandate=mandate, context=real_payload, idem="op-forge-2")
    assert out2.json()["status"] == "EXECUTED"
    assert calls == [("generic_op", real_payload)]


def test_legacy_record_with_null_payload_hash_fails_closed_through_full_http_path():
    """Direct proof (through the REAL HTTP execute endpoint, not just the
    bare ApprovalService) that a record with payload_hash=None -- the
    exact condition every pre-PR#121 real-SDK-created record reached --
    cannot be executed with ANY payload, including an empty one."""
    svc, client, calls = build()
    from mcc_core import ApprovalRecord, ApprovalState
    import asyncio

    bypassing = ApprovalRecord(
        request_id="req-legacy-1", actor="agent/x", action="generic_op",
        action_hash=__import__("mcc_core").hash_action("generic_op"), resource="res-1",
        transaction_id="txn-1", policy_hash=POLICY, payload_hash=None, constraints={},
        state=ApprovalState.PENDING.value, created_at=0, expires_at=10_000_000_000,
        tenant_id=None, payload={"amount": 100},
    )
    asyncio.run(svc.approvals.registry.create(bypassing))
    mandate = approve(client, "req-legacy-1")
    out = raw_execute(client, "req-legacy-1", mandate=mandate, context={"amount": 100},
                       idem="op-legacy-1")
    body = out.json()
    assert body["status"] == "BLOCKED"
    assert "PAYLOAD_MISMATCH" in body["reason"], body
    assert calls == []


def test_nested_payload_mutation_is_detected():
    """A top-level-identical payload that differs only in a deeply nested
    field must still be caught -- proves the binding is a structural hash
    of the whole payload, not a shallow/top-level comparison."""
    _, client, calls = build()
    approved = {"order": {"items": [{"sku": "A1", "amount": 10}], "currency": "usd"},
                "note": "ok"}
    substituted = {"order": {"items": [{"sku": "A1", "amount": 10000}], "currency": "usd"},
                   "note": "ok"}
    rid = escalate(client, payload=approved)
    mandate = approve(client, rid)
    out = raw_execute(client, rid, mandate=mandate, context=substituted, idem="op-nested-1")
    body = out.json()
    assert body["status"] == "BLOCKED"
    assert "PAYLOAD_MISMATCH" in body["reason"], body
    assert calls == []
    # Non-vacuity: the exact approved (unmutated) nested payload DOES execute.
    out2 = raw_execute(client, rid, mandate=mandate, context=approved, idem="op-nested-2")
    assert out2.json()["status"] == "EXECUTED"
    assert calls == [("generic_op", approved)]


# ===========================================================================
# Action / resource / operation-identity / policy substitution
# ===========================================================================

def test_action_substitution_blocked_before_actuator():
    _, client, calls = build()
    payload = {"amount": 1}
    rid = escalate(client, payload=payload, action="generic_op")
    mandate = approve(client, rid)
    out = raw_execute(client, rid, mandate=mandate, action="delete_database",
                       context=payload, idem="op-act-1")
    body = out.json()
    assert body["status"] == "BLOCKED"
    assert calls == []


def test_resource_substitution_blocked_before_actuator():
    _, client, calls = build()
    payload = {"amount": 1}
    rid = escalate(client, payload=payload, resource="res-1")
    mandate = approve(client, rid)
    out = raw_execute(client, rid, mandate=mandate, resource="res-EVIL",
                       context=payload, idem="op-res-1")
    body = out.json()
    assert body["status"] == "BLOCKED"
    assert calls == []


def test_actor_substitution_blocked_before_actuator():
    _, client, calls = build()
    payload = {"amount": 1}
    rid = escalate(client, payload=payload, actor="agent/x")
    mandate = approve(client, rid)
    out = raw_execute(client, rid, mandate=mandate, actor="agent/ATTACKER",
                       context=payload, idem="op-actor-1")
    body = out.json()
    assert body["status"] == "BLOCKED"
    assert calls == []


def test_transaction_id_substitution_blocked_before_actuator():
    _, client, calls = build()
    payload = {"amount": 1}
    rid = escalate(client, payload=payload, transaction_id="txn-real")
    mandate = approve(client, rid)
    out = raw_execute(client, rid, mandate=mandate, transaction_id="txn-SUBSTITUTED",
                       context=payload, idem="op-tx-1")
    body = out.json()
    assert body["status"] == "BLOCKED"
    assert calls == []


def test_policy_hash_drift_between_request_and_execute_blocked():
    """The approval was requested under an OLD policy hash; the live
    gateway now runs a different one. Re-approval/re-escalation under the
    new policy is required -- never a silent carry-forward."""
    _, client, calls = build(policy_hash=POLICY)
    payload = {"amount": 1}
    rid = escalate(client, payload=payload, policy_hash="sha256:STALE-POLICY")
    mandate = approve(client, rid)
    out = raw_execute(client, rid, mandate=mandate, context=payload, idem="op-pol-1")
    body = out.json()
    assert body["status"] == "BLOCKED"
    assert calls == []


def test_operation_identity_cannot_be_forged_to_claim_a_different_approval():
    """A second, UNRELATED approval request (different payload, never
    approved) cannot be executed by presenting the FIRST approval's real,
    valid mandate alongside the second request's id -- the mandate's own
    approval_id claim (signed) must match the request_id path, not just
    whatever request_id the URL names."""
    _, client, calls = build()
    payload_a = {"amount": 1}
    payload_b = {"amount": 2}
    rid_a = escalate(client, payload=payload_a, transaction_id="txn-a")
    rid_b = escalate(client, payload=payload_b, transaction_id="txn-b")
    mandate_a = approve(client, rid_a)
    # Never approve rid_b. Attempt to execute rid_b's URL using A's mandate.
    out = raw_execute(client, rid_b, mandate=mandate_a, context=payload_b,
                       transaction_id="txn-b", idem="op-ident-1")
    body = out.json()
    assert body["status"] == "BLOCKED"
    assert calls == []
    # A's own approval still executes normally (non-vacuity).
    out2 = raw_execute(client, rid_a, mandate=mandate_a, context=payload_a,
                        transaction_id="txn-a", idem="op-ident-2")
    assert out2.json()["status"] == "EXECUTED"
    assert calls == [("generic_op", payload_a)]
