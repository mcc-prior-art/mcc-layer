"""Attestation-aware full-chain reference pilot tests (PR-6).

Real-process-boundary tests driving the PARTNER-FACING pilot code itself
(``pilot.reference_python.attestation_integration.AttestationChainPilot``,
``pilot.reference_python.attester_client.AttesterClient``, and the
newly-exposed ``attestation`` parameter on
``pilot.client.MCCGatewayClient.execute_with_mandate``) against a real,
separate Independent Attester Service subprocess and a real Gateway
subprocess -- reusing ``assurance.sut.attestation_harness`` (PR-5) for
provisioning ONLY (its two real OS subprocesses + attacker tooling); every
assertion here is against the PILOT'S OWN code, not the harness's own
convenience methods (``asut.execute_with_mandate_and_attestation`` is used
only in the one test that deliberately drives the raw HTTP surface to
prove attestation replay -- see test_08).

Every negative case is dual-oracle: the reported outcome AND the
independently observed Gateway notification-receipt counter (never trust a
self-reported status alone).

This module does not re-derive PR-1 through PR-5's own adversarial
coverage (already exhaustively proven in ``assurance/tests/test_attestation_chain.py``
and ``tests/test_pre_execution_control.py`` etc.) -- it proves the NEW
surface PR-6 actually added: that the pilot's own client-side code
correctly reaches, and correctly fails closed against, that existing
chain.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from assurance.sut.attestation_harness import (
    ATTESTED_ACTION,
    ATTESTER_AUTH_SECRET,
    AttestationSystemUnderTest,
    build_attestation_system_under_test,
)
from pilot.client import MCCGatewayClient
from pilot.reference_python.attestation_config import AttestationChainConfig
from pilot.reference_python.attestation_integration import AttestationChainPilot
from pilot.reference_python.attester_client import AttesterClientError

ACTOR = "agent/pr6-pilot-test-partner"


def _agent_key(sut) -> str:
    """V05 (part 2): ACTOR's OWN registered credential on the gateway's
    identity routes (the shared tenant key cannot act as an agent there)."""
    return sut.sut.agent_key(ACTOR)
RESOURCE = "notifications"
OTHER_RESOURCE = "other-resource"


def _context(**overrides: Any) -> dict[str, Any]:
    import uuid

    base = {"recipient": "demo@example.invalid", "message": "pr6-probe",
            "priority": 2, "channel": "email", "correlation_id": str(uuid.uuid4())}
    base.update(overrides)
    return base


@pytest.fixture(scope="module")
def asut():
    with build_attestation_system_under_test() as a:
        yield a


@pytest.fixture()
def mandate(asut: AttestationSystemUnderTest) -> dict[str, Any]:
    return asut.issue_mandate(subject=ACTOR, action_scope=[ATTESTED_ACTION],
                               resource_scope=[RESOURCE, OTHER_RESOURCE])


def _observe_config(asut: AttestationSystemUnderTest) -> AttestationChainConfig:
    return AttestationChainConfig(
        gateway_url=asut.gateway_url, attester_url=asut.attester_url,
        attester_auth_secret=ATTESTER_AUTH_SECRET, gateway_api_key=_agent_key(asut),
        mode="observe", action=ATTESTED_ACTION, resource=RESOURCE,
    )


def _enforced_config(asut: AttestationSystemUnderTest) -> AttestationChainConfig:
    from dataclasses import replace

    return replace(_observe_config(asut), mode="enforced")


# ---------------------------------------------------------------------------
# 1. Positive control: valid attestation, valid authority, valid Gate path.
# ---------------------------------------------------------------------------


def test_01_valid_full_chain_succeeds(asut, mandate):
    before = asut.gateway_notification_receipt_count()
    with AttestationChainPilot(_enforced_config(asut), evidence_dir="unused") as pilot:
        outcome = pilot.submit(actor=ACTOR, context=_context(), mandate=mandate,
                               idempotency_key="op-test01-full-chain")

    assert outcome.execution.status == "EXECUTED", outcome.execution
    assert outcome.execution.decision == "ALLOW"
    assert outcome.actuated is True
    assert asut.gateway_notification_receipt_count() == before + 1
    assert outcome.evidence["status"] == "PASS"
    assert outcome.evidence["independent_invocations"] == {
        "attester_service_calls": 1, "gateway_calls": 1,
    }
    assert outcome.evidence["attestation"]["attestation_id"]
    assert outcome.evidence["attestation"]["evidence_digest_client_computed"].startswith("sha256:")
    # Never a raw secret, claim, provenance, or signature FIELD in the
    # evidence bundle -- checked as actual dict keys (not a substring scan
    # over the whole serialized JSON, which would also match innocuous
    # prose like "mcc_core.signing.hash_document" in known_limitations).
    attestation_summary = outcome.evidence["attestation"]
    for forbidden_key in ("sig", "claims", "provenance"):
        assert forbidden_key not in attestation_summary
    serialized = json.dumps(outcome.evidence)
    assert ATTESTER_AUTH_SECRET not in serialized
    assert asut.api_key not in serialized
    assert _agent_key(asut) not in serialized


# ---------------------------------------------------------------------------
# 2. Missing attestation fails closed.
# ---------------------------------------------------------------------------


def test_02_missing_attestation_fails_closed(asut, mandate):
    before = asut.gateway_notification_receipt_count()
    with MCCGatewayClient(asut.gateway_url, api_key=_agent_key(asut)) as client:
        outcome = client.execute_with_mandate(
            mandate=mandate, actor=ACTOR, action=ATTESTED_ACTION, resource=RESOURCE,
            context=_context(), attestation=None,
        )
    assert outcome.status == "BLOCKED", outcome.raw
    assert asut.gateway_notification_receipt_count() == before


# ---------------------------------------------------------------------------
# 3. Forged attestation signature fails closed.
# ---------------------------------------------------------------------------


def test_03_forged_attestation_signature_fails_closed(asut, mandate):
    before = asut.gateway_notification_receipt_count()
    ctx = _context()
    forged = asut.forge_attestation(context=ctx)
    with MCCGatewayClient(asut.gateway_url, api_key=_agent_key(asut)) as client:
        outcome = client.execute_with_mandate(
            mandate=mandate, actor=ACTOR, action=ATTESTED_ACTION, resource=RESOURCE,
            context=ctx, attestation=forged,
        )
    assert outcome.status == "BLOCKED", outcome.raw
    assert "ATTESTER_UNTRUSTED" in outcome.reason
    assert asut.gateway_notification_receipt_count() == before


# ---------------------------------------------------------------------------
# 4. Tampered attestation payload fails closed.
# ---------------------------------------------------------------------------


def test_04_tampered_attestation_payload_fails_closed(asut, mandate):
    before = asut.gateway_notification_receipt_count()
    ctx = _context()
    att = asut.get_attestation(context=ctx)
    tampered = asut.tamper_attestation(att, claims={**att["claims"], "risk_class": "high"})
    with MCCGatewayClient(asut.gateway_url, api_key=_agent_key(asut)) as client:
        outcome = client.execute_with_mandate(
            mandate=mandate, actor=ACTOR, action=ATTESTED_ACTION, resource=RESOURCE,
            context=ctx, attestation=tampered,
        )
    assert outcome.status == "BLOCKED", outcome.raw
    assert asut.gateway_notification_receipt_count() == before


# ---------------------------------------------------------------------------
# 5. Wrong action binding fails closed.
# ---------------------------------------------------------------------------


def test_05_wrong_action_binding_fails_closed(asut, mandate):
    before = asut.gateway_notification_receipt_count()
    ctx = _context()
    # A GENUINE, trusted attestation -- but attested for a different action
    # than the one actually being executed.
    att = asut.get_attestation(action="a_completely_different_action", context=ctx)
    with MCCGatewayClient(asut.gateway_url, api_key=_agent_key(asut)) as client:
        outcome = client.execute_with_mandate(
            mandate=mandate, actor=ACTOR, action=ATTESTED_ACTION, resource=RESOURCE,
            context=ctx, attestation=att,
        )
    assert outcome.status == "BLOCKED", outcome.raw
    assert asut.gateway_notification_receipt_count() == before


# ---------------------------------------------------------------------------
# 6. Wrong scope binding fails closed.
# ---------------------------------------------------------------------------


def test_06_wrong_scope_binding_fails_closed(asut, mandate):
    before = asut.gateway_notification_receipt_count()
    ctx = _context()
    # A GENUINE, trusted attestation scoped to a DIFFERENT resource than
    # the one actually being executed against (the mandate itself is scoped
    # to both resources, isolating PreExecutionControl's own scope check
    # from a mandate-level resource-scope rejection).
    att = asut.get_attestation(resource=OTHER_RESOURCE, context=ctx)
    with MCCGatewayClient(asut.gateway_url, api_key=_agent_key(asut)) as client:
        outcome = client.execute_with_mandate(
            mandate=mandate, actor=ACTOR, action=ATTESTED_ACTION, resource=RESOURCE,
            context=ctx, attestation=att,
        )
    assert outcome.status == "BLOCKED", outcome.raw
    assert asut.gateway_notification_receipt_count() == before


# ---------------------------------------------------------------------------
# 7. Expired attestation fails closed.
# ---------------------------------------------------------------------------


def test_07_expired_attestation_fails_closed():
    """A dedicated short-validity SUT and a real wall-clock sleep past the
    window -- not a tampered-field simulation (which would only re-exercise
    signature tamper-detection, not the time-window check specifically)."""
    with build_attestation_system_under_test(validity_seconds=2) as short_asut:
        m = short_asut.issue_mandate(subject=ACTOR, action_scope=[ATTESTED_ACTION],
                                      resource_scope=[RESOURCE])
        before = short_asut.gateway_notification_receipt_count()
        ctx = _context()
        att = short_asut.get_attestation(context=ctx)
        time.sleep(3)

        with MCCGatewayClient(short_asut.gateway_url, api_key=_agent_key(short_asut)) as client:
            outcome = client.execute_with_mandate(
                mandate=m, actor=ACTOR, action=ATTESTED_ACTION, resource=RESOURCE,
                context=ctx, attestation=att,
            )
        assert outcome.status == "BLOCKED", outcome.raw
        assert short_asut.gateway_notification_receipt_count() == before


# ---------------------------------------------------------------------------
# 8. Replayed attestation fails closed on the second use.
# ---------------------------------------------------------------------------


def test_08_replayed_attestation_second_use_blocked(asut, mandate):
    ctx = _context(correlation_id="pr6-replay-probe")
    att = asut.get_attestation(context=ctx)

    with MCCGatewayClient(asut.gateway_url, api_key=_agent_key(asut)) as client:
        before = asut.gateway_notification_receipt_count()
        first = client.execute_with_mandate(
            mandate=mandate, actor=ACTOR, action=ATTESTED_ACTION, resource=RESOURCE,
            context=ctx, attestation=att, idempotency_key="pr6-replay-first",
        )
        assert first.status == "EXECUTED", first.raw
        assert asut.gateway_notification_receipt_count() == before + 1

        second = client.execute_with_mandate(
            mandate=mandate, actor=ACTOR, action=ATTESTED_ACTION, resource=RESOURCE,
            context=ctx, attestation=att, idempotency_key="pr6-replay-second",
        )
        assert second.status == "BLOCKED", second.raw
        assert asut.gateway_notification_receipt_count() == before + 1


# ---------------------------------------------------------------------------
# 9. Evidence substitution (attestation for a different payload than the
#    one actually being submitted) fails closed.
# ---------------------------------------------------------------------------


def test_09_evidence_for_different_payload_is_substitution_rejected(asut, mandate):
    before = asut.gateway_notification_receipt_count()
    attested_for = _context(message="original-evidence-payload")
    actually_submitted = _context(message="swapped-payload-after-the-fact")
    att = asut.get_attestation(context=attested_for)

    with MCCGatewayClient(asut.gateway_url, api_key=_agent_key(asut)) as client:
        outcome = client.execute_with_mandate(
            mandate=mandate, actor=ACTOR, action=ATTESTED_ACTION, resource=RESOURCE,
            context=actually_submitted, attestation=att,
        )
    assert outcome.status == "BLOCKED", outcome.raw
    assert asut.gateway_notification_receipt_count() == before


# ---------------------------------------------------------------------------
# 10. A fabricated, never-issued pseudo-attestation (bypassing the real
#     Attester entirely) does not execute.
# ---------------------------------------------------------------------------


def test_10_fabricated_pseudo_attestation_does_not_execute(asut, mandate):
    before = asut.gateway_notification_receipt_count()
    ctx = _context()
    fabricated = {
        "schema_version": "mcc-attestation/1", "attestation_id": "fake-001",
        "attester_id": "assurance-attester.risk.v1", "evidence_type": "risk_assessment",
        "claims": {"risk_class": "low"}, "action_hash": "0" * 64, "scope": f"notify:{RESOURCE}",
        "provenance": {}, "issued_at": int(time.time()), "not_before": int(time.time()),
        "expires_at": int(time.time()) + 900, "nonce": "fake-nonce",
        "payload_hash": "sha256:" + "0" * 64, "kid": asut.attester_kid, "sig": "not-a-real-signature",
    }
    with MCCGatewayClient(asut.gateway_url, api_key=_agent_key(asut)) as client:
        outcome = client.execute_with_mandate(
            mandate=mandate, actor=ACTOR, action=ATTESTED_ACTION, resource=RESOURCE,
            context=ctx, attestation=fabricated,
        )
    assert outcome.status == "BLOCKED", outcome.raw
    assert asut.gateway_notification_receipt_count() == before


# ---------------------------------------------------------------------------
# 11. Attester unavailable fails closed -- the Gateway is never even
#     called.
# ---------------------------------------------------------------------------


class _PoisonedGatewayClient:
    """A gateway client double that raises if ANY method is called --
    proves ``AttestationChainPilot`` never reaches the Gateway when the
    Attester step already failed."""

    def execute_with_mandate(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the Gateway must never be called when the Attester is unavailable")

    def close(self) -> None:
        pass


def test_11_attester_unavailable_fails_closed(asut, mandate):
    unreachable = AttestationChainConfig(
        gateway_url=asut.gateway_url, attester_url="http://127.0.0.1:1",
        attester_auth_secret=ATTESTER_AUTH_SECRET, gateway_api_key=_agent_key(asut),
        mode="enforced", action=ATTESTED_ACTION, resource=RESOURCE, timeout_seconds=2.0,
    )
    before = asut.gateway_notification_receipt_count()
    pilot = AttestationChainPilot(
        unreachable, gateway_client=_PoisonedGatewayClient(), evidence_dir="unused",
    )
    with pytest.raises(AttesterClientError):
        pilot.submit(actor=ACTOR, context=_context(), mandate=mandate)
    assert asut.gateway_notification_receipt_count() == before


# ---------------------------------------------------------------------------
# 12. Gateway dependency (transport-level) failure fails closed client-side.
#     The deeper server-side proofs (Redis/audit-backend outage) already
#     exist in tests/test_nonce.py, tests/test_mandate.py,
#     assurance/tests/test_attestation_chain.py etc. -- not re-derived here.
# ---------------------------------------------------------------------------


def test_12_gateway_unreachable_fails_closed_client_side(asut):
    from pilot.client import MCCGatewayError

    # Nested (not parenthesized-combined) `with` deliberately: this repo's
    # ruff target-version is py39, which does not support parenthesized
    # multi-context-manager `with` statements (3.10+ syntax).
    with MCCGatewayClient("http://127.0.0.1:1", api_key=asut.api_key, timeout=2.0) as client:  # noqa: SIM117
        with pytest.raises(MCCGatewayError):
            client.execute_with_mandate(
                mandate={"kid": "x"}, actor=ACTOR, action=ATTESTED_ACTION, resource=RESOURCE,
                context=_context(), attestation={"attester_id": "x"},
            )


# ---------------------------------------------------------------------------
# 13. Observe-mode creates evidence but causes no real external side
#     effect -- and never even calls the Gateway.
# ---------------------------------------------------------------------------


def test_13_observe_mode_creates_evidence_no_side_effect(asut):
    before = asut.gateway_notification_receipt_count()
    pilot = AttestationChainPilot(
        _observe_config(asut), gateway_client=_PoisonedGatewayClient(), evidence_dir="unused",
    )
    outcome = pilot.submit(actor=ACTOR, context=_context())

    assert outcome.mode == "observe"
    assert outcome.execution is None
    assert outcome.actuated is False
    assert outcome.evidence["mode"] == "observe"
    assert outcome.evidence["actuated"] is False
    assert outcome.evidence["independent_invocations"] == {
        "attester_service_calls": 1, "gateway_calls": 0,
    }
    assert outcome.evidence["attestation"]["attestation_id"]
    assert asut.gateway_notification_receipt_count() == before


# ---------------------------------------------------------------------------
# 14. Existing evaluate-only pilot behavior remains fully compatible, even
#     on a Gateway process that also has attestation requirements
#     configured for a DIFFERENT (mandate/execute) path.
# ---------------------------------------------------------------------------


def test_14_legacy_evaluate_only_pilot_remains_compatible(asut):
    from mcc_sdk import EvaluateRequest, MCCClient

    with MCCClient(base_url=asut.gateway_url, api_key=asut.api_key) as client:
        resp = client.evaluate(EvaluateRequest(
            # The identity/action/context combination already proven to
            # produce ALLOW under the Gateway's default pilot policy (see
            # pilot/reference_python/runner.py's DEMO_SCENARIOS and
            # tests/pilot/test_pilot_acceptance.py's ALLOW_SCENARIO).
            identity="agent/payments-bot", action="send_payment", context={"amount": 1000},
        ))
    assert resp.decision.value == "ALLOW", resp
    assert resp.decision_token is not None
