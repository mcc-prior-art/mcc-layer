"""Compromised-Intelligence adversarial proof (Production Trust Hardening
Phase 1, Workstream 3).

Models the Intelligence/agent caller as FULLY HOSTILE and drives 14 named
attack scenarios through the real chain:

    INTELLIGENCE -> ATTESTATION -> CONTROL -> SIGNED EXECUTION AUTHORITY
        -> AUTHORITY VERIFICATION -> GATE -> EXECUTION

The invariant under test, throughout: an untrusted Intelligence layer may
ask the configured AssessmentProvider to assess a proposed action (that is
allowed by design -- an EvidenceAttestation is evidence, not authority), but
it can never dictate a trusted attestation's output fields, forge or
self-sign one, bypass the configured AssessmentProvider, or turn a genuine
attestation into execution authority without independent Control
verification, a validly signed execution token, and the Gate's own checks.

Dual oracle wherever practical: the reported MCC outcome (ExecOutcome.status
/ ControlAttestationResult.ok) AND an independent actuation counter that is
incremented only by the simulated upstream executor -- so a false "blocked"
report cannot hide a real side effect.
"""

from __future__ import annotations

import asyncio
import copy
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
# V05 (part 2): direct library callers pass the trusted authenticated agent
# explicitly (library trust boundary; see docs/AGENT_IDENTITY.md).
from tests._agent_credentials import agent as _agent  # noqa: E402

run = asyncio.run

ACTION = "send_payment"
RESOURCE = "vendor-1"
POLICY_HASH = "sha256:" + "0" * 64
ATTESTER_ID = "attester.adversarial.v1"
SCOPE_TEMPLATE = "payment:{resource}"
AUTH_SECRET = "adversarial-test-auth-secret-0123456789"


def _now() -> int:
    return int(time.time())


def _tmp_audit() -> AuditLog:
    d = tempfile.mkdtemp(prefix="mcc-adversarial-test-")
    return AuditLog(str(Path(d) / "audit.jsonl"))


def _context(**overrides) -> dict:
    ctx = {"source": "acct-1", "beneficiary_id": RESOURCE, "amount": 100, "currency": "eur"}
    ctx.update(overrides)
    return ctx


def _canonical(context: dict) -> dict:
    return ProfileRegistry.default_pilot().for_action(ACTION).canonical_payload(context)


def _requirement(**overrides) -> AttestationRequirement:
    kw = dict(
        action_pattern=ACTION, evidence_type="risk_assessment",
        scope_template=SCOPE_TEMPLATE, required_claims={"risk_class": ("low",)},
    )
    kw.update(overrides)
    return AttestationRequirement(**kw)


class Actuator:
    """The independent, dual-oracle side of every scenario below."""

    def __init__(self):
        self.calls = 0

    async def __call__(self, action, payload):
        self.calls += 1
        return {"ok": True, "action": action, "payload": payload}


def _stack(*, trusted_attester_key, actuator, mandate_key):
    control = PreExecutionControl(
        requirements=AttestationRequirementRegistry([_requirement()]),
        trust_store=AttesterTrustStore([
            AttesterTrustAnchor(ATTESTER_ID, trusted_attester_key.kid, trusted_attester_key.public_key(),
                                frozenset({"risk_assessment"})),
        ]),
        nonce_registry=InMemoryNonceRegistry(),
    )
    signing_key = SigningKey.generate("gw-signing-adv")
    engine = DecisionEngine(
        signing_key=signing_key, issuer="mcc/core", audience="pilot", policy_id="pilot/v1",
        policy_hash=POLICY_HASH,
    )
    gate = ExecutionGate(
        trusted_keys={signing_key.kid: signing_key.public_key()}, audience="pilot",
        nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH,
    )
    coordinator = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=_tmp_audit(),
        profiles=ProfileRegistry.default_pilot(), revocation_registry=InMemoryRevocationRegistry(),
    )
    trust_set = TrustSet()
    trust_set.add_runtime_issuer("axlogiq/pilot", mandate_key.kid, mandate_key.public_key())
    approver_key = SigningKey.generate("approver-adv")
    trust_set.add_runtime_issuer("mcc/approvals", approver_key.kid, approver_key.public_key())
    approvals = ApprovalService(InMemoryApprovalRegistry(), approver_key)

    return GovernanceService(
        engine=engine, coordinator=coordinator, trust_set=trust_set,
        revocation_registry=InMemoryRevocationRegistry(), approvals=approvals,
        profiles=ProfileRegistry.default_pilot(), upstream=actuator, policy_hash=POLICY_HASH,
        pre_execution_control=control,
    ), control


def _mandate(mandate_key: SigningKey):
    now = _now()
    return issue_mandate(
        mandate_key, issuer="axlogiq/pilot", subject="agent/payments-bot",
        action_scope=[ACTION], resource_scope=[RESOURCE], constraints={},
        not_before=now - 10, not_after=now + 3600, issued_at=now,
        tenant_id="tenant-adv-1",  # V05: strict tenant mode
    )


def _trusted_attester_key() -> SigningKey:
    return SigningKey.generate(f"{ATTESTER_ID}-key-01")


def _genuine_attestation(attester_key: SigningKey, *, payload) -> dict:
    """A genuinely obtained attestation from the real, configured
    AssessmentProvider -- the artifact a well-behaved caller would have."""
    config = AttesterServiceConfig(
        attester_id=ATTESTER_ID, signing_key=attester_key, auth_secret=AUTH_SECRET,
        scope_template=SCOPE_TEMPLATE, validity_seconds=900,
    )
    provider = DeterministicTestProvider({
        ACTION: AssessmentResult(evidence_type="risk_assessment", claims={"risk_class": "low"},
                                 provenance={"model": "adversarial-fixture"}),
    })
    service = AttesterService(config=config, provider=provider)
    return run(service.attest(action=ACTION, resource=RESOURCE, payload=payload))


def _assert_no_actuation_and_blocked(outcome, actuator: Actuator):
    assert outcome.status != "EXECUTED", f"hostile input was EXECUTED: {outcome.status} / {outcome.reason}"
    assert actuator.calls == 0, "actuator ran despite a blocked/rejected outcome (dual-oracle failure)"


# ---------------------------------------------------------------------------
# Scenarios 1-9: hostile Intelligence injects/forges trusted-output fields
# directly into the raw attestation document it hands to Control, having
# never gone through the real Attester's signing at all for the injected
# value (or having reused a genuine artifact's key material dishonestly).
# Each of these is submitted straight to Control -- the actual verification
# boundary -- not merely to the Attester's own HTTP request schema (which
# tests/test_attester_service.py already covers exhaustively at 17 fields).
# ---------------------------------------------------------------------------


def _forge_full_document(hostile_key: SigningKey, **field_overrides) -> dict:
    """A fully self-fabricated attestation-shaped document: hostile
    Intelligence writes every field itself, including a self-chosen
    ``attester_id``/``kid`` and a signature from a key it controls -- not
    signed by anything in Control's trust store."""
    from mcc_attestation import LocalAttester

    now = _now()
    base = dict(
        evidence_type="risk_assessment", claims={"risk_class": "low"},
        action_hash="sha256:" + "a" * 64,
        scope=SCOPE_TEMPLATE.format(resource=RESOURCE), provenance={}, issued_at=now,
        not_before=now, expires_at=now + 900, nonce="hostile-nonce-" + str(now),
        payload_hash=None, policy_hash=None, policy_version=None,
    )
    base.update(field_overrides)
    forger = LocalAttester(field_overrides.get("attester_id", ATTESTER_ID), hostile_key)
    attestation = forger.attest(**{k: v for k, v in base.items() if k != "attester_id"})
    return attestation.to_dict()


@pytest.mark.parametrize("scenario,mutate", [
    ("1_fake_verified_true", lambda d: {**d, "verified": True}),
    ("2_supplies_claims", lambda d: {**d, "claims": {"risk_class": "low", "extra": "hostile"}}),
    ("3_supplies_provenance", lambda d: {**d, "provenance": {"model": "hostile-model"}}),
    ("4_supplies_risk_class_top_level", lambda d: {**d, "risk_class": "low"}),
])
def test_scenarios_1_to_4_extraneous_or_self_declared_fields_do_not_grant_trust(scenario, mutate):
    """A hostile document carrying extra/self-declared fields alongside a
    genuinely bad signature (signed by a key never in the trust store) is
    still rejected -- these fields carry no independent weight; only trust
    resolution + signature verification decide."""
    mandate_key = SigningKey.generate("issuer-adv")
    trusted_key = _trusted_attester_key()
    hostile_key = SigningKey.generate("hostile-key")
    actuator = Actuator()
    service, _ = _stack(trusted_attester_key=trusted_key, actuator=actuator, mandate_key=mandate_key)

    context = _context()
    forged = _forge_full_document(hostile_key)
    hostile_doc = mutate(forged)

    out = run(service.execute_with_mandate(
        mandate=_mandate(mandate_key), actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=hostile_doc,
        tenant_id="tenant-adv-1", agent=_agent("tenant-adv-1", "agent/payments-bot")
    ))
    _assert_no_actuation_and_blocked(out, actuator)


def test_scenario_5_supplies_trusted_attester_id_but_signs_with_untrusted_key():
    mandate_key = SigningKey.generate("issuer-adv")
    trusted_key = _trusted_attester_key()
    hostile_key = SigningKey.generate("hostile-key")
    actuator = Actuator()
    service, _ = _stack(trusted_attester_key=trusted_key, actuator=actuator, mandate_key=mandate_key)

    context = _context()
    # Declares the REAL attester_id, but the document is signed by a key
    # never registered under (ATTESTER_ID, hostile_key.kid) in the trust store.
    forged = _forge_full_document(hostile_key, attester_id=ATTESTER_ID)

    out = run(service.execute_with_mandate(
        mandate=_mandate(mandate_key), actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=forged,
        tenant_id="tenant-adv-1", agent=_agent("tenant-adv-1", "agent/payments-bot")
    ))
    _assert_no_actuation_and_blocked(out, actuator)


def test_scenario_6_supplies_a_kid_never_registered_to_the_trusted_attester():
    mandate_key = SigningKey.generate("issuer-adv")
    trusted_key = _trusted_attester_key()
    actuator = Actuator()
    service, _ = _stack(trusted_attester_key=trusted_key, actuator=actuator, mandate_key=mandate_key)

    context = _context()
    canonical = _canonical(context)
    genuine = _genuine_attestation(trusted_key, payload=canonical)
    # Declares a kid this trust store has never seen for this attester_id.
    hostile_doc = {**genuine, "kid": "kid-never-registered"}

    out = run(service.execute_with_mandate(
        mandate=_mandate(mandate_key), actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=hostile_doc,
        tenant_id="tenant-adv-1", agent=_agent("tenant-adv-1", "agent/payments-bot")
    ))
    _assert_no_actuation_and_blocked(out, actuator)


def test_scenario_7_supplies_a_self_crafted_signature():
    mandate_key = SigningKey.generate("issuer-adv")
    trusted_key = _trusted_attester_key()
    actuator = Actuator()
    service, _ = _stack(trusted_attester_key=trusted_key, actuator=actuator, mandate_key=mandate_key)

    context = _context()
    canonical = _canonical(context)
    genuine = _genuine_attestation(trusted_key, payload=canonical)
    hostile_doc = {**genuine, "sig": "aGVsbG8gd29ybGQ"}  # garbage, base64-shaped

    out = run(service.execute_with_mandate(
        mandate=_mandate(mandate_key), actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=hostile_doc,
        tenant_id="tenant-adv-1", agent=_agent("tenant-adv-1", "agent/payments-bot")
    ))
    _assert_no_actuation_and_blocked(out, actuator)


def test_scenario_8_supplies_forged_action_and_payload_hashes():
    mandate_key = SigningKey.generate("issuer-adv")
    trusted_key = _trusted_attester_key()
    hostile_key = SigningKey.generate("hostile-key")
    actuator = Actuator()
    service, _ = _stack(trusted_attester_key=trusted_key, actuator=actuator, mandate_key=mandate_key)

    context = _context()
    # A fully self-fabricated document that declares hashes matching the
    # attacker's OWN fabricated action/payload, not the real one being
    # executed -- rejected both on signature (untrusted key) and, even
    # hypothetically past that, on binding.
    forged = _forge_full_document(
        hostile_key, action_hash="sha256:" + "f" * 64, payload_hash="sha256:" + "e" * 64,
    )
    out = run(service.execute_with_mandate(
        mandate=_mandate(mandate_key), actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=forged,
        tenant_id="tenant-adv-1", agent=_agent("tenant-adv-1", "agent/payments-bot")
    ))
    _assert_no_actuation_and_blocked(out, actuator)


def test_scenario_9_supplies_self_chosen_nonce_and_backdated_timestamps():
    mandate_key = SigningKey.generate("issuer-adv")
    trusted_key = _trusted_attester_key()
    hostile_key = SigningKey.generate("hostile-key")
    actuator = Actuator()
    service, _ = _stack(trusted_attester_key=trusted_key, actuator=actuator, mandate_key=mandate_key)

    context = _context()
    forged = _forge_full_document(
        hostile_key, nonce="attacker-chosen-nonce", issued_at=_now() - 10_000,
        not_before=_now() - 10_000, expires_at=_now() + 10_000,
    )
    out = run(service.execute_with_mandate(
        mandate=_mandate(mandate_key), actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=forged,
        tenant_id="tenant-adv-1", agent=_agent("tenant-adv-1", "agent/payments-bot")
    ))
    _assert_no_actuation_and_blocked(out, actuator)


# ---------------------------------------------------------------------------
# Scenario 10: attempts to bypass the configured AssessmentProvider.
# ---------------------------------------------------------------------------


def test_scenario_10_cannot_bypass_the_configured_assessment_provider():
    """There is no code path from a caller's request straight to signing --
    AttesterService.attest() always calls the configured provider first
    (service.py's own _assess()), and an action with no configured entry
    fails closed with no signature ever produced."""
    trusted_key = _trusted_attester_key()
    config = AttesterServiceConfig(
        attester_id=ATTESTER_ID, signing_key=trusted_key, auth_secret=AUTH_SECRET,
        scope_template=SCOPE_TEMPLATE, validity_seconds=900,
    )
    # Deliberately empty: no provider entry for ACTION at all.
    provider = DeterministicTestProvider({})
    service = AttesterService(config=config, provider=provider)

    from mcc_attester_service.errors import AssessmentProviderError

    with pytest.raises(AssessmentProviderError):
        run(service.attest(action=ACTION, resource=RESOURCE, payload=_canonical(_context())))
    # No bypass surface exists to call LocalAttester directly through this
    # service without going through _assess() first -- there is exactly one
    # call site (service.py's attest()), and it always awaits _assess()
    # before touching the signing key. This is a structural guarantee
    # checked by tests/test_attester_service_architecture_guards.py, not a
    # runtime branch this test could toggle.


# ---------------------------------------------------------------------------
# Scenario 11: fabricates its own EvidenceAttestation entirely.
# ---------------------------------------------------------------------------


def test_scenario_11_fully_self_fabricated_attestation_is_rejected():
    mandate_key = SigningKey.generate("issuer-adv")
    trusted_key = _trusted_attester_key()
    hostile_key = SigningKey.generate("hostile-key")
    actuator = Actuator()
    service, _ = _stack(trusted_attester_key=trusted_key, actuator=actuator, mandate_key=mandate_key)

    context = _context()
    forged = _forge_full_document(hostile_key)  # attester_id=ATTESTER_ID by default, wrong key
    out = run(service.execute_with_mandate(
        mandate=_mandate(mandate_key), actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=forged,
        tenant_id="tenant-adv-1", agent=_agent("tenant-adv-1", "agent/payments-bot")
    ))
    _assert_no_actuation_and_blocked(out, actuator)


# ---------------------------------------------------------------------------
# Scenario 12: genuine attestation, no valid execution authority.
# ---------------------------------------------------------------------------


def test_scenario_12_genuine_attestation_without_valid_mandate_is_blocked():
    """A valid attestation does not itself grant execution authority --
    without a valid mandate, GovernanceService rejects before any question
    of attestation policy even matters for actuation."""
    mandate_key = SigningKey.generate("issuer-adv")
    other_issuer_key = SigningKey.generate("untrusted-issuer")  # never registered in trust_set
    trusted_key = _trusted_attester_key()
    actuator = Actuator()
    service, _ = _stack(trusted_attester_key=trusted_key, actuator=actuator, mandate_key=mandate_key)

    context = _context()
    canonical = _canonical(context)
    genuine = _genuine_attestation(trusted_key, payload=canonical)

    forged_mandate = issue_mandate(
        other_issuer_key, issuer="axlogiq/pilot", subject="agent/payments-bot",
        action_scope=[ACTION], resource_scope=[RESOURCE], constraints={},
        not_before=_now() - 10, not_after=_now() + 3600, issued_at=_now(),
        tenant_id="tenant-adv-1",  # V05: strict tenant mode
    )
    out = run(service.execute_with_mandate(
        mandate=forged_mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=genuine,
        tenant_id="tenant-adv-1", agent=_agent("tenant-adv-1", "agent/payments-bot")
    ))
    _assert_no_actuation_and_blocked(out, actuator)


# ---------------------------------------------------------------------------
# Scenario 13: valid authority, evidence substituted for a different action/payload.
# ---------------------------------------------------------------------------


def test_scenario_13_valid_mandate_but_substituted_evidence_payload_is_blocked():
    mandate_key = SigningKey.generate("issuer-adv")
    trusted_key = _trusted_attester_key()
    actuator = Actuator()
    service, _ = _stack(trusted_attester_key=trusted_key, actuator=actuator, mandate_key=mandate_key)

    genuine_context = _context(amount=100)
    genuine_canonical = _canonical(genuine_context)
    genuine = _genuine_attestation(trusted_key, payload=genuine_canonical)

    # A DIFFERENT context/payload is what's actually about to be executed.
    substituted_context = _context(amount=999999)
    out = run(service.execute_with_mandate(
        mandate=_mandate(mandate_key), actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=substituted_context, attestation=genuine,
        tenant_id="tenant-adv-1", agent=_agent("tenant-adv-1", "agent/payments-bot")
    ))
    _assert_no_actuation_and_blocked(out, actuator)


# ---------------------------------------------------------------------------
# Scenario 14: replays evidence/authority after successful use.
# ---------------------------------------------------------------------------


def test_scenario_14_replay_after_successful_use_cannot_actuate_again():
    mandate_key = SigningKey.generate("issuer-adv")
    trusted_key = _trusted_attester_key()
    actuator = Actuator()
    service, _ = _stack(trusted_attester_key=trusted_key, actuator=actuator, mandate_key=mandate_key)

    context = _context()
    canonical = _canonical(context)
    genuine = _genuine_attestation(trusted_key, payload=canonical)
    mandate = _mandate(mandate_key)

    first = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=copy.deepcopy(genuine), idempotency_key="op-scenario14-a",
        tenant_id="tenant-adv-1", agent=_agent("tenant-adv-1", "agent/payments-bot")
    ))
    assert first.status == "EXECUTED", first.reason
    assert actuator.calls == 1

    replay = run(service.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=copy.deepcopy(genuine), idempotency_key="op-scenario14-b",
        tenant_id="tenant-adv-1", agent=_agent("tenant-adv-1", "agent/payments-bot")
    ))
    assert replay.status != "EXECUTED", f"replay was EXECUTED: {replay.reason}"
    assert actuator.calls == 1, "replay incremented the actuator -- dual-oracle failure"
