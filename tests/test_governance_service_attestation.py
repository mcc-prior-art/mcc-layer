"""PR-2 — Pre-Execution Attestation Control Integration: end-to-end tests
through the REAL ``GovernanceService.execute_with_mandate`` /
``execute_with_consensus`` paths (the same code the ``/mandates/execute``,
``/approvals/{id}/execute``, and ``/consensus/execute`` HTTP routes call).

Complements ``tests/test_pre_execution_control.py`` (unit-level Control
decisions in isolation). These tests prove the wiring itself: that a real
signed mandate / real consensus quorum plus a real PR-1 EvidenceAttestation
together determine whether ``DecisionEngine.issue_token`` is ever reached, in
both directions (authority alone is not enough; attestation alone is not
enough), and that a mandate's CONSTRAIN rewrite is exactly what the
attestation must bind to.
"""

from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path

import pytest

from gateway.governance_service import GovernanceService
from gateway.pre_execution_control import (
    AttestationRequirement,
    AttestationRequirementRegistry,
    PreExecutionControl,
)
from mcc_attestation import AttesterTrustAnchor, AttesterTrustStore, LocalAttester
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
    MandateAuthority,
    MandateVerifier,
    ProfileRegistry,
    SigningKey,
    hash_action,
    hash_document,
    hash_payload,
    issue_mandate,
    issue_vote,
)
from gateway.trust import TrustSet

run = asyncio.run

def _now() -> int:
    """Real wall-clock now, evaluated at the CALL site (never cached at
    module-import time). ``GovernanceService._now()`` and
    ``PreExecutionControl.evaluate()`` both default to ``time.time()`` (no
    injectable clock), so mandate/attestation validity windows must be
    anchored to the actual moment each test runs -- a module-level constant
    captured once at collection time would drift stale (and expire a short
    attestation window) if the full suite takes minutes to reach this file."""
    return int(time.time())


ACTION = "send_payment"
RESOURCE = "vendor-1"
POLICY_HASH = "sha256:" + "0" * 64


def _tmp_audit() -> AuditLog:
    d = tempfile.mkdtemp(prefix="mcc-pr2-test-")
    return AuditLog(str(Path(d) / "audit.jsonl"))


def _raw_context(**overrides) -> dict:
    ctx = {"source": "acct-1", "beneficiary_id": RESOURCE, "amount": 100, "currency": "eur"}
    ctx.update(overrides)
    return ctx


def _canonical(context: dict) -> dict:
    """The exact canonicalization ``send_payment`` (PaymentProfile) applies --
    what actually becomes ``forward_context`` inside GovernanceService, and
    therefore what an attestation must bind its payload_hash to."""
    return ProfileRegistry.default_pilot().for_action(ACTION).canonical_payload(context)


def _attester_key() -> SigningKey:
    return SigningKey.generate("attester.payment-risk.v1-key-01")


def _requirement(**overrides) -> AttestationRequirement:
    kw = dict(
        action_pattern=ACTION, evidence_type="risk_assessment",
        scope_template="payment:{resource}", required_claims={"risk_class": ("low",)},
    )
    kw.update(overrides)
    return AttestationRequirement(**kw)


def _pre_execution_control(attester_key: SigningKey, requirement=None) -> PreExecutionControl:
    return PreExecutionControl(
        requirements=AttestationRequirementRegistry([requirement or _requirement()]),
        trust_store=AttesterTrustStore([
            AttesterTrustAnchor("attester.payment-risk.v1", attester_key.kid,
                                attester_key.public_key(), frozenset({"risk_assessment"})),
        ]),
        nonce_registry=InMemoryNonceRegistry(),
    )


def _valid_attestation(attester_key: SigningKey, *, forward_context: dict, nonce="nonce-1",
                       claims=None, **overrides):
    attester = LocalAttester("attester.payment-risk.v1", attester_key)
    now = _now()
    kw = dict(
        evidence_type="risk_assessment", claims=claims or {"risk_class": "low"},
        action_hash=hash_action(ACTION), scope=f"payment:{RESOURCE}",
        provenance={"model": "payment-risk-v3"}, payload_hash=hash_payload(forward_context),
        issued_at=now, not_before=now, expires_at=now + 900, nonce=nonce,
    )
    kw.update(overrides)
    return attester.attest(**kw)


def _governance_service(*, pre_execution_control=None, mandate_key: SigningKey,
                        mandate_constraints=None, wire_approvals: bool = False) -> GovernanceService:
    signing_key = SigningKey.generate("gw-signing-1")
    engine = DecisionEngine(
        signing_key=signing_key, issuer="mcc/core", audience="pilot", policy_id="pilot/v1",
        policy_hash=POLICY_HASH,
    )
    gate = ExecutionGate(
        trusted_keys={signing_key.kid: signing_key.public_key()}, audience="pilot",
        nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH,
    )
    audit = _tmp_audit()
    trust_set = TrustSet()
    trust_set.add_runtime_issuer("axlogiq/pilot", mandate_key.kid, mandate_key.public_key())
    approver_key = SigningKey.generate("approver-1")
    # The gateway is itself the approval issuer (mirrors build_governance_service):
    # trust its approver public key so a mandate minted by ApprovalService.approve()
    # resolves through the SAME _authority_for() trust path as any other mandate.
    trust_set.add_runtime_issuer("mcc/approvals", approver_key.kid, approver_key.public_key())
    approvals = ApprovalService(InMemoryApprovalRegistry(), approver_key)
    # R1: an approval-minted mandate is only executable when the coordinator can
    # consume the approval single-use (opt-in here so every other test's setup
    # is unchanged; only the approval-path test needs it).
    coordinator = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=audit,
        profiles=ProfileRegistry.default_pilot(), revocation_registry=InMemoryRevocationRegistry(),
        approvals=approvals if wire_approvals else None,
    )

    async def upstream(action, payload):
        return {"ok": True, "action": action, "payload": payload}

    service = GovernanceService(
        engine=engine, coordinator=coordinator, trust_set=trust_set,
        revocation_registry=InMemoryRevocationRegistry(), approvals=approvals,
        profiles=ProfileRegistry.default_pilot(), upstream=upstream, policy_hash=POLICY_HASH,
        pre_execution_control=pre_execution_control,
    )
    service._test_audit = audit  # test-only introspection hook, not part of the real API
    return service


def _last_pre_actuation_record(audit) -> dict:
    """Test-only helper (PR-3): scan the JSONL audit log for the last
    ``pre_actuation`` record, to confirm the durable audit trail carries the
    token's exact evidence_digest (or lack of one)."""
    import json as _json

    last = None
    with open(audit.path, "r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            record = _json.loads(line)
            if record.get("kind") == "pre_actuation":
                last = record
    assert last is not None, "no pre_actuation record found in audit log"
    return last


def _mandate(mandate_key: SigningKey, *, constraints=None):
    now = _now()
    return issue_mandate(
        mandate_key, issuer="axlogiq/pilot", subject="agent/payments-bot",
        action_scope=[ACTION], resource_scope=[RESOURCE],
        constraints=constraints or {}, not_before=now - 10, not_after=now + 3600,
        issued_at=now,
        tenant_id="tenant-gsa-1",  # V05: strict tenant mode
    )


# ---------------------------------------------------------------------------
# 1. valid mandate + required valid attestation -> executable token may be
#    issued
# ---------------------------------------------------------------------------


def test_01_valid_mandate_and_valid_attestation_issues_token():
    mandate_key = SigningKey.generate("issuer-1")
    attester_key = _attester_key()
    service = _governance_service(
        pre_execution_control=_pre_execution_control(attester_key), mandate_key=mandate_key,
    )
    mandate = _mandate(mandate_key)
    context = _raw_context()
    att = _valid_attestation(attester_key, forward_context=_canonical(context))

    out = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=att.to_dict(), idempotency_key="op-test01",
        tenant_id="tenant-gsa-1",
    ))
    assert out.status == "EXECUTED"
    assert out.decision == "ALLOW"


# ---------------------------------------------------------------------------
# 2. valid mandate + missing required attestation -> no token
# ---------------------------------------------------------------------------


def test_02_valid_mandate_missing_attestation_blocks():
    mandate_key = SigningKey.generate("issuer-1")
    attester_key = _attester_key()
    service = _governance_service(
        pre_execution_control=_pre_execution_control(attester_key), mandate_key=mandate_key,
    )
    mandate = _mandate(mandate_key)
    context = _raw_context()

    out = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=None,
        tenant_id="tenant-gsa-1",
    ))
    assert out.status == "BLOCKED"
    assert out.decision == "DENY"
    assert "ATTESTATION_REQUIRED" in out.reason


# ---------------------------------------------------------------------------
# 3. valid attestation + no valid mandate -> no token
# ---------------------------------------------------------------------------


def test_03_valid_attestation_invalid_mandate_blocks():
    mandate_key = SigningKey.generate("issuer-1")
    rogue_key = SigningKey.generate("rogue-issuer")  # NOT trusted by the service
    attester_key = _attester_key()
    service = _governance_service(
        pre_execution_control=_pre_execution_control(attester_key), mandate_key=mandate_key,
    )
    bad_mandate = _mandate(rogue_key)  # signed by an untrusted issuer
    context = _raw_context()
    att = _valid_attestation(attester_key, forward_context=_canonical(context))

    out = run(service.execute_with_mandate(
        mandate=bad_mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=att.to_dict(),
        tenant_id="tenant-gsa-1",
    ))
    assert out.status == "BLOCKED"
    assert out.decision == "DENY"
    # Never even reaches attestation evaluation -- authority failure short-circuits first.


# ---------------------------------------------------------------------------
# 22. mandate CONSTRAIN rewrites the payload, but supplied attestation is
#     bound to original payload -> no token
# ---------------------------------------------------------------------------


def test_22_constrain_rewrite_invalidates_attestation_bound_to_original_payload():
    mandate_key = SigningKey.generate("issuer-1")
    attester_key = _attester_key()
    service = _governance_service(
        pre_execution_control=_pre_execution_control(attester_key), mandate_key=mandate_key,
    )
    mandate = _mandate(mandate_key, constraints={"max_amount": 50})
    original_context = _raw_context(amount=999)  # will be clamped to 50

    # Attestation is bound to the ORIGINAL (pre-constraint) canonical payload.
    att = _valid_attestation(attester_key, forward_context=_canonical(original_context))

    out = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=original_context, attestation=att.to_dict(),
        tenant_id="tenant-gsa-1",
    ))
    assert out.status == "BLOCKED"
    assert out.decision == "DENY"
    assert "ATTESTATION_PAYLOAD_MISMATCH" in out.reason


# ---------------------------------------------------------------------------
# 23. fresh attestation bound to the constrained final payload -> token may
#     be issued
# ---------------------------------------------------------------------------


def test_23_attestation_bound_to_constrained_payload_issues_token():
    mandate_key = SigningKey.generate("issuer-1")
    attester_key = _attester_key()
    service = _governance_service(
        pre_execution_control=_pre_execution_control(attester_key), mandate_key=mandate_key,
    )
    mandate = _mandate(mandate_key, constraints={"max_amount": 50})
    original_context = _raw_context(amount=999)
    # What MandateAuthority.authorize() actually rewrites forward_context to:
    # the canonical payload with "amount" clamped to the exact constraint bound
    # value (apply_constraints() assigns the bound literal itself, not a
    # re-normalized float) -- this is what the fresh attestation must bind to.
    constrained_context = dict(_canonical(original_context))
    constrained_context["amount"] = 50

    # Attestation is bound to the EXACT constrained/final payload.
    att = _valid_attestation(attester_key, forward_context=constrained_context)

    out = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=original_context, attestation=att.to_dict(), idempotency_key="op-test23",
        tenant_id="tenant-gsa-1",
    ))
    assert out.status == "EXECUTED"
    assert out.decision == "CONSTRAIN"


# ---------------------------------------------------------------------------
# 24. action with no AttestationRequirement -> existing behavior remains
#     backward compatible
# ---------------------------------------------------------------------------


def test_24_unrelated_action_unaffected_by_attestation_requirement():
    mandate_key = SigningKey.generate("issuer-1")
    attester_key = _attester_key()
    # Requirement only governs "send_payment" -- this mandate/action pair
    # ("check_balance") has no matching requirement.
    service = _governance_service(
        pre_execution_control=_pre_execution_control(attester_key), mandate_key=mandate_key,
    )
    now = _now()
    mandate = issue_mandate(
        mandate_key, issuer="axlogiq/pilot", subject="agent/payments-bot",
        action_scope=["check_balance"], resource_scope=[RESOURCE], constraints={},
        not_before=now - 10, not_after=now + 3600, issued_at=now,
        tenant_id="tenant-gsa-1",  # V05: strict tenant mode
    )
    out = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action="check_balance", resource=RESOURCE,
        context={}, attestation=None,  # no attestation supplied, and none required
        idempotency_key="op-test24",
        tenant_id="tenant-gsa-1",
    ))
    assert out.status == "EXECUTED"
    assert out.decision == "ALLOW"


def test_24b_no_pre_execution_control_configured_is_fully_backward_compatible():
    mandate_key = SigningKey.generate("issuer-1")
    # No PreExecutionControl at all -- must behave exactly as pre-PR-2.
    service = _governance_service(pre_execution_control=None, mandate_key=mandate_key)
    mandate = _mandate(mandate_key)
    context = _raw_context()
    out = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=None, idempotency_key="op-test24b",
        tenant_id="tenant-gsa-1",
    ))
    assert out.status == "EXECUTED"
    assert out.decision == "ALLOW"


# ---------------------------------------------------------------------------
# 27. all governed runtime issuance paths requiring attestation go through
#     the new Control boundary (mandate execute AND consensus execute)
# ---------------------------------------------------------------------------


def test_27_consensus_execute_path_is_also_gated_by_attestation():
    mandate_key = SigningKey.generate("issuer-1")  # unused by consensus path
    attester_key = _attester_key()
    evaluator_keys = [SigningKey.generate(f"evaluator-{i}") for i in range(3)]
    consensus_verifier = ConsensusVerifier(
        trusted_keys={k.kid: k.public_key() for k in evaluator_keys},
        policy=ConsensusPolicy(threshold=3),
    )
    service = _governance_service(
        pre_execution_control=_pre_execution_control(attester_key), mandate_key=mandate_key,
    )
    service.consensus_verifier = consensus_verifier

    context = _raw_context()
    canonical = service.profiles.for_action(ACTION).canonical_payload(context)

    def _votes(nonce: str):
        now = _now()
        return [
            issue_vote(
                k, evaluator_id=k.kid, verdict="ALLOW", action=ACTION, payload=canonical,
                actor="agent/payments-bot", resource=RESOURCE, policy_hash=POLICY_HASH,
                nonce=nonce, not_before=now - 10, not_after=now + 3600, issued_at=now,
            )
            for k in evaluator_keys
        ]

    votes = _votes("consensus-nonce-1")

    # (a) without attestation -> blocked, even though consensus itself is valid.
    out_missing = run(service.execute_with_consensus(
        votes=votes, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, nonce="consensus-nonce-1",
        tenant_id="tenant-gsa-1",
    ))
    assert out_missing.status == "BLOCKED"
    assert "ATTESTATION_REQUIRED" in out_missing.reason

    # (b) with a valid attestation bound to the exact canonical payload -> issues.
    att = _valid_attestation(attester_key, forward_context=canonical, nonce="att-nonce-consensus")
    votes2 = _votes("consensus-nonce-2")
    out_ok = run(service.execute_with_consensus(
        votes=votes2, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, nonce="consensus-nonce-2", attestation=att.to_dict(),
        idempotency_key="op-test27",
        tenant_id="tenant-gsa-1",
    ))
    assert out_ok.status == "EXECUTED"


# ---------------------------------------------------------------------------
# PR-3 -- Evidence-Bound Execution Ticket: end-to-end coverage through the
# real GovernanceService.execute_with_mandate / execute_with_consensus /
# execute_with_approval paths and the real EnforcementCoordinator. Complements
# tests/test_evidence_bound_execution_ticket.py's unit-level Gate/Control/
# DecisionEngine coverage.
# ---------------------------------------------------------------------------


def test_13_mandate_e2e_required_verified_attestation_yields_evidence_bound_execution():
    """13. Mandate E2E: required verified attestation -> evidence-bound
    token -> real EnforcementCoordinator -> execution, with the token's
    evidence_digest recorded in the durable pre_actuation audit entry."""
    mandate_key = SigningKey.generate("issuer-1")
    attester_key = _attester_key()
    service = _governance_service(
        pre_execution_control=_pre_execution_control(attester_key), mandate_key=mandate_key,
    )
    mandate = _mandate(mandate_key)
    context = _raw_context()
    att = _valid_attestation(attester_key, forward_context=_canonical(context))
    raw = att.to_dict()

    out = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=raw, idempotency_key="op-test13",
        tenant_id="tenant-gsa-1",
    ))
    assert out.status == "EXECUTED"
    assert out.decision == "ALLOW"

    record = _last_pre_actuation_record(service._test_audit)
    assert record["evidence_digest"] == hash_document(raw)


def test_14_consensus_e2e_required_verified_attestation_yields_evidence_bound_execution():
    """14. Same invariant through execute_with_consensus()."""
    mandate_key = SigningKey.generate("issuer-1")  # unused by consensus path
    attester_key = _attester_key()
    evaluator_keys = [SigningKey.generate(f"evaluator-evd-{i}") for i in range(3)]
    consensus_verifier = ConsensusVerifier(
        trusted_keys={k.kid: k.public_key() for k in evaluator_keys},
        policy=ConsensusPolicy(threshold=3),
    )
    service = _governance_service(
        pre_execution_control=_pre_execution_control(attester_key), mandate_key=mandate_key,
    )
    service.consensus_verifier = consensus_verifier

    context = _raw_context()
    canonical = service.profiles.for_action(ACTION).canonical_payload(context)
    att = _valid_attestation(attester_key, forward_context=canonical, nonce="evd-consensus-nonce")
    raw = att.to_dict()

    now = _now()
    votes = [
        issue_vote(
            k, evaluator_id=k.kid, verdict="ALLOW", action=ACTION, payload=canonical,
            actor="agent/payments-bot", resource=RESOURCE, policy_hash=POLICY_HASH,
            nonce="evd-consensus-op-nonce", not_before=now - 10, not_after=now + 3600,
            issued_at=now,
        )
        for k in evaluator_keys
    ]

    out = run(service.execute_with_consensus(
        votes=votes, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, nonce="evd-consensus-op-nonce", attestation=raw,
        idempotency_key="op-test14",
        tenant_id="tenant-gsa-1",
    ))
    assert out.status == "EXECUTED"

    record = _last_pre_actuation_record(service._test_audit)
    assert record["evidence_digest"] == hash_document(raw)


def test_15_approval_path_delegation_retains_evidence_binding():
    """15. execute_with_approval() delegates to execute_with_mandate(), so
    the same evidence-binding wiring applies -- there is exactly one place
    that calls issue_token for either path. Drives the REAL ESCALATE loop
    (create_approval -> approve -> a genuine signed, single-use approval
    mandate) rather than hand-editing a mandate dict, since a mandate's
    fields are themselves signature-covered."""
    mandate_key = SigningKey.generate("issuer-1")  # unused; approval mandates
    attester_key = _attester_key()                 # come from the approver key
    service = _governance_service(
        pre_execution_control=_pre_execution_control(attester_key), mandate_key=mandate_key,
        wire_approvals=True,
    )
    context = _raw_context()
    canonical = _canonical(context)

    # R1: the human approves the EXACT payload this test then executes.
    request_id = run(service.create_approval(
        actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        payload_hash=hash_payload(canonical), payload=canonical,
        tenant_id="tenant-gsa-1",  # V05: requested in the tenant it executes in
    ))["request_id"]
    approved_mandate = run(service.approve(request_id))
    assert approved_mandate is not None

    att = _valid_attestation(attester_key, forward_context=canonical)
    raw = att.to_dict()

    out = run(service.execute_with_approval(
        mandate=approved_mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=raw, idempotency_key="op-test15",
        tenant_id="tenant-gsa-1",
    ))
    assert out.status == "EXECUTED"

    record = _last_pre_actuation_record(service._test_audit)
    assert record["evidence_digest"] == hash_document(raw)


def test_16_valid_evidence_alone_still_cannot_produce_executable_authority():
    """16. A valid, verifiable attestation cannot substitute for valid
    mandate/consensus authority -- mirrors test_03, restated explicitly for
    the PR-3 evidence-binding numbering. The authority check fails BEFORE
    Control (and therefore before any evidence_digest) is ever reached, so
    no evidence-bound token is issued regardless of how strong the evidence
    is on its own."""
    mandate_key = SigningKey.generate("issuer-1")
    rogue_key = SigningKey.generate("rogue-issuer-evd")  # untrusted issuer
    attester_key = _attester_key()
    service = _governance_service(
        pre_execution_control=_pre_execution_control(attester_key), mandate_key=mandate_key,
    )
    bad_mandate = _mandate(rogue_key)
    context = _raw_context()
    att = _valid_attestation(attester_key, forward_context=_canonical(context))

    out = run(service.execute_with_mandate(
        mandate=bad_mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=att.to_dict(),
        tenant_id="tenant-gsa-1",
    ))
    assert out.status == "BLOCKED"
    assert out.decision == "DENY"


def test_17_constrain_rewrite_plus_evidence_binding_together_hold_exactly():
    """17. The PR-2 exact-post-CONSTRAIN-payload invariant remains intact
    when combined with PR-3 evidence binding: a mandate CONSTRAIN rewrites
    the payload, a fresh attestation is bound to the EXACT constrained
    payload (per test_23), and the resulting token is evidence-bound to
    that same attestation -- proving the two invariants compose correctly
    rather than one silently overriding the other."""
    mandate_key = SigningKey.generate("issuer-1")
    attester_key = _attester_key()
    service = _governance_service(
        pre_execution_control=_pre_execution_control(attester_key), mandate_key=mandate_key,
    )
    mandate = _mandate(mandate_key, constraints={"max_amount": 50})
    original_context = _raw_context(amount=999)
    constrained_context = dict(_canonical(original_context))
    constrained_context["amount"] = 50

    att = _valid_attestation(attester_key, forward_context=constrained_context)
    raw = att.to_dict()

    out = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=original_context, attestation=raw, idempotency_key="op-test17",
        tenant_id="tenant-gsa-1",
    ))
    assert out.status == "EXECUTED"
    assert out.decision == "CONSTRAIN"

    record = _last_pre_actuation_record(service._test_audit)
    assert record["evidence_digest"] == hash_document(raw)


def test_17b_attestation_bound_to_original_payload_is_still_rejected_pr2_invariant():
    """The PR-2 exact-payload rule (test_22) is unaffected by PR-3: an
    attestation bound to the pre-CONSTRAIN payload is still rejected at
    Control, before any evidence-bound token could ever be issued."""
    mandate_key = SigningKey.generate("issuer-1")
    attester_key = _attester_key()
    service = _governance_service(
        pre_execution_control=_pre_execution_control(attester_key), mandate_key=mandate_key,
    )
    mandate = _mandate(mandate_key, constraints={"max_amount": 50})
    original_context = _raw_context(amount=999)
    att = _valid_attestation(attester_key, forward_context=_canonical(original_context))

    out = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=original_context, attestation=att.to_dict(),
        tenant_id="tenant-gsa-1",
    ))
    assert out.status == "BLOCKED"
    assert "ATTESTATION_PAYLOAD_MISMATCH" in out.reason


def test_action_with_no_requirement_issues_a_token_with_no_evidence_digest():
    """Backward compatibility, end-to-end: an action with no configured
    AttestationRequirement gets a token carrying no evidence_digest at all
    (not merely None) -- the pre_actuation audit record's evidence_digest is
    therefore also None/absent, exactly matching pre-PR-3 behavior."""
    mandate_key = SigningKey.generate("issuer-1")
    attester_key = _attester_key()
    service = _governance_service(
        pre_execution_control=_pre_execution_control(attester_key), mandate_key=mandate_key,
    )
    now = _now()
    mandate = issue_mandate(
        mandate_key, issuer="axlogiq/pilot", subject="agent/payments-bot",
        action_scope=["check_balance"], resource_scope=[RESOURCE], constraints={},
        not_before=now - 10, not_after=now + 3600, issued_at=now,
        tenant_id="tenant-gsa-1",  # V05: strict tenant mode
    )
    out = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action="check_balance", resource=RESOURCE,
        context={}, attestation=None, idempotency_key="op-no-requirement",
        tenant_id="tenant-gsa-1",
    ))
    assert out.status == "EXECUTED"
    record = _last_pre_actuation_record(service._test_audit)
    assert record.get("evidence_digest") is None
