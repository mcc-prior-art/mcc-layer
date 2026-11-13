"""PR-4 — Independent Attester Service: end-to-end tests through the REAL
governed execution path.

Covers required items I, J, K:

* I. END-TO-END GOVERNED EXECUTION -- Independent Attester -> raw signed
  EvidenceAttestation -> the real GovernanceService.execute_with_mandate ->
  the real PreExecutionControl (PR-2, unmodified) -> evidence_digest ->
  DecisionEngine signed token (PR-3, unmodified) -> ExecutionGate exact
  evidence binding (PR-3, unmodified) -> EnforcementCoordinator ->
  execution. Proves PR-2 and PR-3 remain fully in force with the artifact
  now sourced from the new independent service instead of an in-line
  LocalAttester call.
* J. SUBSTITUTION FAILURE -- a token issued against attestation A rejects
  attestation B at the Gate, evidence digest mismatch, before nonce
  consumption -- even when B is independently obtained from the SAME real
  service and is independently well-formed/valid for the same action.
* K. MUTATION FAILURE -- mutating any signed/bound field of a
  service-issued attestation is rejected, both by the existing PR-1
  verifier (inside PreExecutionControl) and, downstream, by the PR-3 Gate's
  evidence-digest binding.

This file's AttesterService instances run IN-PROCESS (fast, deterministic,
matches the existing PR-2/PR-3 end-to-end test style in
tests/test_governance_service_attestation.py). The genuine cross-process
proof (a real, separate OS process holding the private key) lives in
tests/test_attester_service_process_isolation.py -- this file is about
governed-execution correctness, that one is about the trust boundary.
"""

from __future__ import annotations

import asyncio
import tempfile
import time
from pathlib import Path

from gateway.governance_service import GovernanceService
from gateway.pre_execution_control import (
    AttestationRequirement,
    AttestationRequirementRegistry,
    PreExecutionControl,
)
from gateway.trust import TrustSet
from mcc_attestation import AttesterTrustAnchor, AttesterTrustStore
from mcc_attester_service import AssessmentResult, AttesterService, AttesterServiceConfig, DeterministicTestProvider
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

run = asyncio.run

ACTION = "send_payment"
RESOURCE = "vendor-1"
POLICY_HASH = "sha256:" + "0" * 64
ATTESTER_ID = "attester.payment-risk.v1"
SCOPE_TEMPLATE = "payment:{resource}"
AUTH_SECRET = "attester-service-e2e-auth-secret-01"


def _now() -> int:
    return int(time.time())


def _tmp_audit() -> AuditLog:
    d = tempfile.mkdtemp(prefix="mcc-pr4-e2e-test-")
    return AuditLog(str(Path(d) / "audit.jsonl"))


def _raw_context(**overrides) -> dict:
    ctx = {"source": "acct-1", "beneficiary_id": RESOURCE, "amount": 100, "currency": "eur"}
    ctx.update(overrides)
    return ctx


def _canonical(context: dict) -> dict:
    return ProfileRegistry.default_pilot().for_action(ACTION).canonical_payload(context)


def _attester_key() -> SigningKey:
    return SigningKey.generate("attester.payment-risk.v1-key-01")


def _requirement(**overrides) -> AttestationRequirement:
    kw = dict(
        action_pattern=ACTION, evidence_type="risk_assessment",
        scope_template=SCOPE_TEMPLATE, required_claims={"risk_class": ("low",)},
    )
    kw.update(overrides)
    return AttestationRequirement(**kw)


def _pre_execution_control(attester_key: SigningKey, requirement=None) -> PreExecutionControl:
    return PreExecutionControl(
        requirements=AttestationRequirementRegistry([requirement or _requirement()]),
        trust_store=AttesterTrustStore([
            AttesterTrustAnchor(ATTESTER_ID, attester_key.kid, attester_key.public_key(),
                                frozenset({"risk_assessment"})),
        ]),
        nonce_registry=InMemoryNonceRegistry(),
    )


def _attester_service(attester_key: SigningKey, *, claims=None, nonce_provider_key=ACTION,
                      validity_seconds=900) -> AttesterService:
    """The Independent Attester Service, configured to bind to the SAME
    scope template PreExecutionControl's AttestationRequirement expects, so
    an artifact this service issues satisfies PR-2's binding checks exactly
    as a hand-built LocalAttester call would have."""
    config = AttesterServiceConfig(
        attester_id=ATTESTER_ID, signing_key=attester_key, auth_secret=AUTH_SECRET,
        scope_template=SCOPE_TEMPLATE, validity_seconds=validity_seconds,
    )
    provider = DeterministicTestProvider({
        nonce_provider_key: AssessmentResult(
            evidence_type="risk_assessment", claims=claims or {"risk_class": "low"},
            provenance={"model": "payment-risk-v3"},
        ),
    })
    return AttesterService(config=config, provider=provider)


def _obtain_attestation(service: AttesterService, *, resource=RESOURCE, payload) -> dict:
    return run(service.attest(action=ACTION, resource=resource, payload=payload))


def _governance_service(*, pre_execution_control, mandate_key: SigningKey):
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
    coordinator = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=audit,
        profiles=ProfileRegistry.default_pilot(), revocation_registry=InMemoryRevocationRegistry(),
    )
    trust_set = TrustSet()
    trust_set.add_runtime_issuer("axlogiq/pilot", mandate_key.kid, mandate_key.public_key())
    approver_key = SigningKey.generate("approver-1")
    trust_set.add_runtime_issuer("mcc/approvals", approver_key.kid, approver_key.public_key())
    approvals = ApprovalService(InMemoryApprovalRegistry(), approver_key)

    async def upstream(action, payload):
        return {"ok": True, "action": action, "payload": payload}

    return GovernanceService(
        engine=engine, coordinator=coordinator, trust_set=trust_set,
        revocation_registry=InMemoryRevocationRegistry(), approvals=approvals,
        profiles=ProfileRegistry.default_pilot(), upstream=upstream, policy_hash=POLICY_HASH,
        pre_execution_control=pre_execution_control,
    )


def _mandate(mandate_key: SigningKey, *, constraints=None):
    now = _now()
    return issue_mandate(
        mandate_key, issuer="axlogiq/pilot", subject="agent/payments-bot",
        action_scope=[ACTION], resource_scope=[RESOURCE],
        constraints=constraints or {}, not_before=now - 10, not_after=now + 3600,
        issued_at=now,
        tenant_id="tenant-attester-e2e",  # V05: strict tenant mode
    )


# ---------------------------------------------------------------------------
# I. END-TO-END GOVERNED EXECUTION.
# ---------------------------------------------------------------------------


def test_i_e2e_independent_attester_through_real_governance_to_execution():
    mandate_key = SigningKey.generate("issuer-1")
    attester_key = _attester_key()
    service = _governance_service(
        pre_execution_control=_pre_execution_control(attester_key), mandate_key=mandate_key,
    )
    attester_service = _attester_service(attester_key)

    context = _raw_context()
    canonical = _canonical(context)
    raw_attestation = _obtain_attestation(attester_service, payload=canonical)

    out = run(service.execute_with_mandate(
        mandate=_mandate(mandate_key), actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=raw_attestation, idempotency_key="op-i-e2e-1",
        tenant_id="tenant-attester-e2e",
    ))
    assert out.status == "EXECUTED", out.reason
    assert out.decision == "ALLOW"


def test_i_e2e_audit_pre_actuation_record_carries_the_evidence_digest():
    import json as _json

    mandate_key = SigningKey.generate("issuer-1")
    attester_key = _attester_key()
    service = _governance_service(
        pre_execution_control=_pre_execution_control(attester_key), mandate_key=mandate_key,
    )
    attester_service = _attester_service(attester_key)
    context = _raw_context()
    canonical = _canonical(context)
    raw_attestation = _obtain_attestation(attester_service, payload=canonical)

    audit = service.coordinator.audit
    out = run(service.execute_with_mandate(
        mandate=_mandate(mandate_key), actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=raw_attestation, idempotency_key="op-i-e2e-2",
        tenant_id="tenant-attester-e2e",
    ))
    assert out.status == "EXECUTED"

    last = None
    with open(audit.path, "r", encoding="utf-8") as fh:
        for line in fh:
            record = _json.loads(line)
            if record.get("kind") == "pre_actuation":
                last = record
    assert last is not None
    assert last.get("evidence_digest") is not None


def test_i_e2e_missing_required_attestation_still_blocks():
    """PR-2 remains fully in force: no attestation, no execution, even
    though an Independent Attester service is configured and available."""
    mandate_key = SigningKey.generate("issuer-1")
    attester_key = _attester_key()
    service = _governance_service(
        pre_execution_control=_pre_execution_control(attester_key), mandate_key=mandate_key,
    )
    out = run(service.execute_with_mandate(
        mandate=_mandate(mandate_key), actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=_raw_context(), attestation=None,
        tenant_id="tenant-attester-e2e",
    ))
    assert out.status == "BLOCKED"


# ---------------------------------------------------------------------------
# J. SUBSTITUTION FAILURE.
# ---------------------------------------------------------------------------


def test_j_substitution_attestation_b_rejected_at_the_gate_for_a_token_bound_to_a():
    mandate_key = SigningKey.generate("issuer-1")
    attester_key = _attester_key()
    attester_service = _attester_service(attester_key)
    context = _raw_context()
    canonical = _canonical(context)

    att_a = _obtain_attestation(attester_service, payload=canonical)
    att_b = _obtain_attestation(attester_service, payload=canonical)  # independently valid, same action
    assert att_a["nonce"] != att_b["nonce"]
    assert att_a["attestation_id"] != att_b["attestation_id"]

    from mcc_core.signing import hash_document
    assert hash_document(att_a) != hash_document(att_b)

    signing_key = SigningKey.generate("gw-1")
    engine = DecisionEngine(signing_key=signing_key, issuer="mcc/core", audience="pilot",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH)
    token = engine.issue_token(
        verdict="ALLOW", subject="agent/x", action=ACTION, payload=canonical,
        evidence_digest=hash_document(att_a),
    )
    registry = InMemoryNonceRegistry()
    gate = ExecutionGate(trusted_keys={signing_key.kid: signing_key.public_key()}, audience="pilot",
                         nonce_registry=registry, policy_hash=POLICY_HASH)

    denied = run(gate.verify(token, action=ACTION, payload=canonical, evidence=att_b))
    assert not denied.allowed
    assert "EVIDENCE_DIGEST_MISMATCH" in denied.reason

    # Nonce not burned by the substitution attempt.
    allowed = run(gate.verify(token, action=ACTION, payload=canonical, evidence=att_a))
    assert allowed.allowed, allowed.reason


# ---------------------------------------------------------------------------
# K. MUTATION FAILURE.
# ---------------------------------------------------------------------------


def test_k_mutated_service_artifact_rejected_by_pre_execution_control():
    mandate_key = SigningKey.generate("issuer-1")
    attester_key = _attester_key()
    control = _pre_execution_control(attester_key)
    attester_service = _attester_service(attester_key)
    context = _raw_context()
    canonical = _canonical(context)
    raw = _obtain_attestation(attester_service, payload=canonical)

    mutated = {**raw, "claims": {**raw["claims"], "risk_class": "high"}}
    result = run(control.evaluate(
        action=ACTION, forward_context=canonical, resource=RESOURCE,
        raw_attestation=mutated, policy_hash=POLICY_HASH,
    ))
    assert not result.ok
    assert result.evidence_digest is None


def test_k_mutated_service_artifact_rejected_by_the_gate_evidence_binding():
    attester_key = _attester_key()
    attester_service = _attester_service(attester_key)
    context = _raw_context()
    canonical = _canonical(context)
    raw = _obtain_attestation(attester_service, payload=canonical)

    signing_key = SigningKey.generate("gw-1")
    engine = DecisionEngine(signing_key=signing_key, issuer="mcc/core", audience="pilot",
                            policy_id="pilot/v1", policy_hash=POLICY_HASH)
    from mcc_core.signing import hash_document
    token = engine.issue_token(
        verdict="ALLOW", subject="agent/x", action=ACTION, payload=canonical,
        evidence_digest=hash_document(raw),
    )
    gate = ExecutionGate(trusted_keys={signing_key.kid: signing_key.public_key()}, audience="pilot",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH)

    mutated = {**raw, "provenance": {**raw["provenance"], "model": "different-model"}}
    result = run(gate.verify(token, action=ACTION, payload=canonical, evidence=mutated))
    assert not result.allowed
    assert "EVIDENCE_DIGEST_MISMATCH" in result.reason


# ---------------------------------------------------------------------------
# Production Trust Hardening Phase 1, Workstream 1, R5 (fast/offline double).
#
# The genuine, real-Redis proof lives in scripts/redis_restart_replay_smoke.py
# (run by the nonce-redis-smoke CI job against an actual Redis service). This
# is the same property -- a RedisNonceRegistry-backed shared nonce registry
# rejects replay after every Python object is torn down and rebuilt from
# scratch -- reproduced fast/offline with the SAME in-process Redis double
# tests/test_nonce.py already uses, so the invariant is checked on every
# ordinary `pytest tests/ -q` run, not only in the dedicated Redis CI job.
# ---------------------------------------------------------------------------


class _FakeRedis:
    """Atomic SET NX (ignores ex); shareable across registries -- the exact
    double tests/test_nonce.py uses, duplicated here rather than imported
    (test files intentionally do not import from one another)."""

    def __init__(self):
        self.store = {}

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True


def test_r5_restart_replay_rejected_after_full_object_teardown_and_rebuild():
    from mcc_core import RedisNonceRegistry

    mandate_key = SigningKey.generate("issuer-r5")
    attester_key = _attester_key()
    shared_backend = _FakeRedis()  # the persistent "Redis" surviving the restart

    def build_service():
        # A fresh RedisNonceRegistry object each time (as a real restart
        # would create), but pointed at the SAME backend -- exactly what
        # RedisNonceRegistry.from_url(same_url) gives you after a real
        # process restart against a real, persistent Redis.
        shared_nonce_registry = RedisNonceRegistry(shared_backend)
        control = _pre_execution_control_shared(attester_key, shared_nonce_registry)
        return _governance_service_shared(
            pre_execution_control=control, mandate_key=mandate_key,
            nonce_registry=shared_nonce_registry,
        )

    attester_service = _attester_service(attester_key)
    context = _raw_context()
    canonical = _canonical(context)
    raw_attestation = _obtain_attestation(attester_service, payload=canonical)
    mandate = _mandate(mandate_key)

    # Instance A: first, legitimate use.
    service_a = build_service()
    first = run(service_a.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=raw_attestation, idempotency_key="op-r5-restart",
        tenant_id="tenant-attester-e2e",
    ))
    assert first.status == "EXECUTED", first.reason

    # Simulated restart: destroy instance A entirely.
    del service_a

    # Instance B: brand-new objects, same backend, same artifacts.
    service_b = build_service()
    replay = run(service_b.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=raw_attestation, idempotency_key="op-r5-restart",
        tenant_id="tenant-attester-e2e",
    ))
    assert replay.status != "EXECUTED", "replay was EXECUTED after simulated restart"
    assert replay.status == "BLOCKED"


def _pre_execution_control_shared(attester_key: SigningKey, nonce_registry) -> PreExecutionControl:
    return PreExecutionControl(
        requirements=AttestationRequirementRegistry([_requirement()]),
        trust_store=AttesterTrustStore([
            AttesterTrustAnchor(ATTESTER_ID, attester_key.kid, attester_key.public_key(),
                                frozenset({"risk_assessment"})),
        ]),
        nonce_registry=nonce_registry,
    )


def _governance_service_shared(*, pre_execution_control, mandate_key: SigningKey, nonce_registry):
    signing_key = SigningKey.generate("gw-signing-r5")
    engine = DecisionEngine(
        signing_key=signing_key, issuer="mcc/core", audience="pilot", policy_id="pilot/v1",
        policy_hash=POLICY_HASH,
    )
    gate = ExecutionGate(
        trusted_keys={signing_key.kid: signing_key.public_key()}, audience="pilot",
        nonce_registry=nonce_registry, policy_hash=POLICY_HASH,
    )
    audit = _tmp_audit()
    coordinator = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=audit,
        profiles=ProfileRegistry.default_pilot(), revocation_registry=InMemoryRevocationRegistry(),
    )
    trust_set = TrustSet()
    trust_set.add_runtime_issuer("axlogiq/pilot", mandate_key.kid, mandate_key.public_key())
    approver_key = SigningKey.generate("approver-r5")
    trust_set.add_runtime_issuer("mcc/approvals", approver_key.kid, approver_key.public_key())
    approvals = ApprovalService(InMemoryApprovalRegistry(), approver_key)

    async def upstream(action, payload):
        return {"ok": True, "action": action, "payload": payload}

    return GovernanceService(
        engine=engine, coordinator=coordinator, trust_set=trust_set,
        revocation_registry=InMemoryRevocationRegistry(), approvals=approvals,
        profiles=ProfileRegistry.default_pilot(), upstream=upstream, policy_hash=POLICY_HASH,
        pre_execution_control=pre_execution_control,
    )
