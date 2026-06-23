"""ESCALATE human-in-the-loop tests: the full approval loop and its negatives.

proposal -> ESCALATE -> request -> approve -> signed single-use approval mandate
-> re-evaluation (MandateAuthority) -> decision token -> gate -> coordinator
(consume single-use) -> execute. Plus denial, timeout, replay, substitution,
actor/action/resource/policy mismatch, and backend failure.
"""

import asyncio

import pytest

from mcc_core import (
    ActuationStatus,
    ApprovalService,
    ApprovalState,
    AuditLog,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryApprovalRegistry,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryVelocityRegistry,
    MandateAuthority,
    MandateVerifier,
    RedisApprovalRegistry,
    SigningKey,
    Verdict,
    hash_action,
    hash_payload,
)

run = asyncio.run
NOW = 1_780_000_000
POLICY_HASH = "sha256:policy-v1"


def approver():
    return SigningKey.generate("approver-key-1")


def service(reg=None, key=None):
    return ApprovalService(reg or InMemoryApprovalRegistry(), key or approver())


# ---- State machine basics ----

def test_request_is_pending():
    svc = service()
    rid = run(svc.request(actor="agent/x", action="send_payment", resource="acct-1", now=NOW))
    rec = run(svc.get(rid, now=NOW))
    assert rec.state == ApprovalState.PENDING.value


def test_deny_is_terminal():
    svc = service()
    rid = run(svc.request(actor="agent/x", action="send_payment", now=NOW))
    assert run(svc.deny(rid))
    assert run(svc.get(rid, now=NOW)).state == ApprovalState.DENIED.value
    assert run(svc.approve(rid, now=NOW)) is None  # cannot approve a denied request


def test_expired_request_cannot_be_approved():
    svc = service()
    rid = run(svc.request(actor="agent/x", action="send_payment", ttl_seconds=100, now=NOW))
    assert run(svc.approve(rid, now=NOW + 200)) is None
    assert run(svc.get(rid, now=NOW + 200)).state == ApprovalState.EXPIRED.value


def test_approve_mints_scoped_single_use_mandate():
    key = approver()
    svc = service(key=key)
    rid = run(svc.request(actor="agent/x", action="send_payment", resource="acct-1",
                          transaction_id="txn-1", policy_hash=POLICY_HASH,
                          constraints={"max_amount": 5000}, now=NOW))
    mandate = run(svc.approve(rid, now=NOW))
    assert mandate is not None
    assert mandate["subject"] == "agent/x"
    assert mandate["action_scope"] == ["send_payment"]
    assert mandate["approval_id"] == rid
    assert mandate["single_use"] is True
    assert mandate["kid"] == key.kid


# ---- Full end-to-end loop ----

def _e2e(tmp_path, approval_registry=None):
    appr_key = approver()
    reg = approval_registry or InMemoryApprovalRegistry()
    svc = ApprovalService(reg, appr_key)
    verifier = MandateVerifier(trusted_keys={appr_key.kid: appr_key.public_key()})
    authority = MandateAuthority(verifier)

    dk = SigningKey.generate("decision-key")
    engine = DecisionEngine(signing_key=dk, issuer="mcc", audience="gate",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH, token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH)
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=AuditLog(str(tmp_path / "a.jsonl")),
        approvals=svc,
    )
    return svc, authority, engine, coord


def _token_from_mandate(engine, authority, mandate, *, actor, action, resource, context,
                        transaction_id, approval_id, now=NOW):
    decision = run(authority.authorize(mandate, subject=actor, action=action, resource=resource,
                                       context=context, now=now, policy_hash=POLICY_HASH))
    if decision.verdict not in (Verdict.ALLOW, Verdict.CONSTRAIN):
        return None, decision
    payload = decision.forward_context or context
    token = engine.issue_token(
        verdict=decision.verdict.value, subject=actor, action=action, payload=payload,
        transaction_id=transaction_id, actor_id=actor, resource_id=resource,
        mandate_id=mandate["mandate_id"], auth_claims={"approval_id": approval_id}, now=now,
    )
    return token, decision


def test_full_escalate_loop_executes(tmp_path):
    svc, authority, engine, coord = _e2e(tmp_path)
    actor, action, resource = "agent/x", "send_payment", "acct-1"
    context = {"amount": 100}
    # proposal -> ESCALATE -> request approval
    rid = run(svc.request(actor=actor, action=action, resource=resource, transaction_id="txn-1",
                          policy_hash=POLICY_HASH, payload_hash=hash_payload(context),
                          constraints={"max_amount": 5000}, now=NOW))
    mandate = run(svc.approve(rid, now=NOW))
    token, _ = _token_from_mandate(engine, authority, mandate, actor=actor, action=action,
                                   resource=resource, context=context, transaction_id="txn-1",
                                   approval_id=rid)
    ran = []

    async def ex():
        ran.append(1)
        return "ok"

    res = run(coord.enforce(token=token, action=action, payload=context, executor=ex, now=NOW))
    assert res.status == ActuationStatus.EXECUTED
    assert ran == [1]
    assert run(svc.get(rid, now=NOW)).state == ApprovalState.CONSUMED.value


def test_approval_is_single_use_replay_blocked(tmp_path):
    svc, authority, engine, coord = _e2e(tmp_path)
    context = {"amount": 100}
    rid = run(svc.request(actor="agent/x", action="send_payment", resource="acct-1",
                          transaction_id="txn-1", policy_hash=POLICY_HASH,
                          payload_hash=hash_payload(context), now=NOW))
    mandate = run(svc.approve(rid, now=NOW))

    async def ex():
        return "ok"

    # First execution consumes the approval; a second distinct token replays it.
    t1, _ = _token_from_mandate(engine, authority, mandate, actor="agent/x", action="send_payment",
                                resource="acct-1", context=context, transaction_id="txn-1", approval_id=rid)
    t2, _ = _token_from_mandate(engine, authority, mandate, actor="agent/x", action="send_payment",
                                resource="acct-1", context=context, transaction_id="txn-1", approval_id=rid)
    first = run(coord.enforce(token=t1, action="send_payment", payload=context, executor=ex, now=NOW))
    second = run(coord.enforce(token=t2, action="send_payment", payload=context, executor=ex, now=NOW))
    assert first.status == ActuationStatus.EXECUTED
    assert second.status == ActuationStatus.BLOCKED
    assert "consum" in second.reason.lower()


def test_denied_request_yields_no_authority(tmp_path):
    svc, authority, engine, coord = _e2e(tmp_path)
    rid = run(svc.request(actor="agent/x", action="send_payment", resource="acct-1", now=NOW))
    run(svc.deny(rid))
    assert run(svc.approve(rid, now=NOW)) is None  # denial is terminal


def test_actor_mismatch_denied_at_reevaluation(tmp_path):
    svc, authority, engine, coord = _e2e(tmp_path)
    rid = run(svc.request(actor="agent/x", action="send_payment", resource="acct-1",
                          policy_hash=POLICY_HASH, now=NOW))
    mandate = run(svc.approve(rid, now=NOW))
    token, decision = _token_from_mandate(engine, authority, mandate, actor="agent/ATTACKER",
                                          action="send_payment", resource="acct-1",
                                          context={"amount": 1}, transaction_id=None, approval_id=rid)
    assert token is None
    assert decision.verdict == Verdict.DENY  # SUBJECT_MISMATCH


def test_action_substitution_denied_at_reevaluation(tmp_path):
    svc, authority, engine, coord = _e2e(tmp_path)
    rid = run(svc.request(actor="agent/x", action="send_payment", resource="acct-1",
                          policy_hash=POLICY_HASH, now=NOW))
    mandate = run(svc.approve(rid, now=NOW))
    token, decision = _token_from_mandate(engine, authority, mandate, actor="agent/x",
                                          action="delete_database", resource="acct-1",
                                          context={}, transaction_id=None, approval_id=rid)
    assert token is None
    assert decision.verdict == Verdict.DENY  # ACTION_SCOPE_MISMATCH


def test_resource_substitution_denied_at_reevaluation(tmp_path):
    svc, authority, engine, coord = _e2e(tmp_path)
    rid = run(svc.request(actor="agent/x", action="send_payment", resource="acct-1",
                          policy_hash=POLICY_HASH, now=NOW))
    mandate = run(svc.approve(rid, now=NOW))
    token, decision = _token_from_mandate(engine, authority, mandate, actor="agent/x",
                                          action="send_payment", resource="acct-EVIL",
                                          context={"amount": 1}, transaction_id=None, approval_id=rid)
    assert token is None
    assert decision.verdict == Verdict.DENY  # RESOURCE_SCOPE_MISMATCH


def test_policy_drift_denied_at_reevaluation(tmp_path):
    svc, authority, engine, coord = _e2e(tmp_path)
    rid = run(svc.request(actor="agent/x", action="send_payment", resource="acct-1",
                          policy_hash=POLICY_HASH, now=NOW))
    mandate = run(svc.approve(rid, now=NOW))
    # Re-evaluate under a different policy version.
    decision = run(authority.authorize(mandate, subject="agent/x", action="send_payment",
                                       resource="acct-1", context={"amount": 1}, now=NOW,
                                       policy_hash="sha256:policy-v2"))
    assert decision.verdict == Verdict.DENY


def test_consume_action_hash_mismatch_fails_closed():
    svc = service()
    rid = run(svc.request(actor="agent/x", action="send_payment", resource="acct-1",
                          transaction_id="txn-1", now=NOW))
    run(svc.approve(rid, now=NOW))
    res = run(svc.consume(rid, action_hash=hash_action("delete_database"),
                          transaction_id="txn-1", payload_hash=None, now=NOW))
    assert not res.ok
    assert "ACTION_HASH_MISMATCH" in res.reason


def test_backend_failure_consume_fails_closed():
    class DownRedis:
        def __getattr__(self, _n):
            async def boom(*a, **k):
                raise ConnectionError("down")
            return boom

    reg = RedisApprovalRegistry(DownRedis())
    svc = ApprovalService(reg, approver())
    res = run(svc.consume("req-x", action_hash="h", transaction_id=None, payload_hash=None, now=NOW))
    assert not res.ok
