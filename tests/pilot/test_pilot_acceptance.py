"""Pilot acceptance tests (PR #82) for pilot/reference_python.

Two kinds of fixtures are used, deliberately:

* the REAL gateway (via the module-scoped ``gateway_url`` fixture in
  conftest.py) for the four-verdict / mode-gating scenarios, reusing the
  exact identity/action/context combinations already proven in
  tests/mcc_sdk/test_integration.py to produce each verdict under the
  gateway's default pilot policy;
* ``httpx.MockTransport`` (deterministic, no network) for the failure-mode
  scenarios (malformed/timeout/unavailable/unknown-decision), matching the
  established pattern in tests/mcc_sdk/test_client.py.

Every test that writes evidence passes pytest's ``tmp_path`` as
``evidence_dir`` -- never the repository, and never a tracked path.
"""

from __future__ import annotations

import json

import httpx
import pytest
from mcc_sdk import EvaluateRequest, MCCClient, MCCContractError, MCCTimeoutError, MCCTransportError

from tests._agent_credentials import module_key
from pilot.reference_python import (
    DirectActuationRejected,
    PilotConfig,
    PilotIntegration,
    SimulatedActuator,
    validate_evidence,
)

# --------------------------------------------------------------------------
# Real-gateway scenarios: exact identity/action/context combinations proven
# in tests/mcc_sdk/test_integration.py to produce each verdict.
# --------------------------------------------------------------------------

ALLOW_SCENARIO = {"identity": "agent/payments-bot", "action": "send_payment", "context": {"amount": 1000}}
DENY_SCENARIO = {"identity": "agent/ops-bot", "action": "delete_database", "context": {}}
ESCALATE_SCENARIO = {"identity": "agent/nobody", "action": "send_payment", "context": {"amount": 1}}
CONSTRAIN_SCENARIO = {
    "identity": "agent/payments-bot", "action": "send_payment", "context": {"amount": 99999},
}


# F1b: a strict Gateway refuses the shared key on /evaluate for every
# identity; each scenario identity presents its OWN registered credential.
AGENT_KEYS = {i: module_key(i) for i in ("agent/payments-bot", "agent/ops-bot", "agent/nobody")}


def _config(gateway_url, tmp_path, *, mode, **overrides) -> PilotConfig:
    url, api_key = gateway_url
    kwargs = {
        "gateway_url": url, "api_key": api_key, "agent_keys": AGENT_KEYS, "mode": mode,
        "evidence_dir": str(tmp_path), "pilot_id": "acceptance-test", "integration_id": "reference-python-v1",
    }
    kwargs.update(overrides)
    return PilotConfig(**kwargs)


# --------------------------------------------------------------------------
# Mode gating
# --------------------------------------------------------------------------


def test_allow_actuates_only_in_enforced_mode(gateway_url, tmp_path):
    cfg = _config(gateway_url, tmp_path, mode="enforced")
    with PilotIntegration(cfg) as pilot:
        outcome = pilot.submit(**ALLOW_SCENARIO)
    assert outcome.actuated is True
    assert outcome.receipt is not None
    assert outcome.receipt.executed is True


def test_allow_does_not_actuate_in_observe_mode(gateway_url, tmp_path):
    cfg = _config(gateway_url, tmp_path, mode="observe")
    with PilotIntegration(cfg) as pilot:
        outcome = pilot.submit(**ALLOW_SCENARIO)
    assert outcome.actuated is False
    assert outcome.receipt is not None
    assert outcome.receipt.executed is False


def test_deny_never_actuates(gateway_url, tmp_path):
    cfg = _config(gateway_url, tmp_path, mode="enforced")
    with PilotIntegration(cfg) as pilot:
        outcome = pilot.submit(**DENY_SCENARIO)
    assert outcome.actuated is False
    assert outcome.receipt is None


def test_escalate_never_actuates(gateway_url, tmp_path):
    cfg = _config(gateway_url, tmp_path, mode="enforced")
    with PilotIntegration(cfg) as pilot:
        outcome = pilot.submit(**ESCALATE_SCENARIO)
    assert outcome.actuated is False
    assert outcome.receipt is None


def test_constrain_cannot_actuate_outside_returned_constraints(gateway_url, tmp_path):
    cfg = _config(gateway_url, tmp_path, mode="enforced")
    with PilotIntegration(cfg) as pilot:
        outcome = pilot.submit(**CONSTRAIN_SCENARIO)
    assert outcome.decision.constrained is True
    assert outcome.actuated is True
    assert outcome.receipt is not None
    # The actuator only ever acts on the Gateway's own forward_context -- the
    # originally-requested (unconstrained) payload must NOT be what was acted on.
    assert outcome.receipt.payload == outcome.decision.forward_context
    assert outcome.receipt.payload != CONSTRAIN_SCENARIO["context"]


# --------------------------------------------------------------------------
# Fail-closed on malformed/timeout/unavailable/unknown-decision
# --------------------------------------------------------------------------


def _pilot_with_mock(handler, tmp_path, *, mode="enforced") -> PilotIntegration:
    client = MCCClient(base_url="http://gw.test", transport=httpx.MockTransport(handler))
    cfg = PilotConfig(
        gateway_url="http://gw.test", mode=mode, evidence_dir=str(tmp_path),
        pilot_id="acceptance-test", integration_id="reference-python-v1",
    )
    return PilotIntegration(cfg, client=client)


def test_malformed_gateway_response_fails_closed(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json at all {{{")

    with _pilot_with_mock(handler, tmp_path) as pilot:
        with pytest.raises(MCCContractError):
            pilot.submit(**ALLOW_SCENARIO)
        assert pilot.evidence.finalize()["malformed_count"] == 1
        assert pilot.evidence.finalize()["total_evaluated"] == 0


def test_unknown_decision_fails_closed(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "decision": "MAYBE", "reason": "not a real verdict", "audit_id": "a1",
                "forward_context": {}, "constraints": {}, "applied_constraints": [],
            },
        )

    with _pilot_with_mock(handler, tmp_path) as pilot:
        with pytest.raises(MCCContractError):
            pilot.submit(**ALLOW_SCENARIO)
        assert pilot.evidence.finalize()["malformed_count"] == 1


def test_gateway_timeout_fails_closed(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    with _pilot_with_mock(handler, tmp_path) as pilot:
        with pytest.raises(MCCTimeoutError):
            pilot.submit(**ALLOW_SCENARIO)
        assert pilot.evidence.finalize()["timeout_count"] == 1


def test_gateway_unavailable_fails_closed(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with _pilot_with_mock(handler, tmp_path) as pilot:
        with pytest.raises(MCCTransportError):
            pilot.submit(**ALLOW_SCENARIO)
        assert pilot.evidence.finalize()["unavailable_count"] == 1


def test_no_actuation_follows_any_failed_submit(tmp_path):
    """A failed submit() must never leave a receipt behind -- fail-closed
    means no side effect, not a partial one."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with _pilot_with_mock(handler, tmp_path) as pilot:
        with pytest.raises(MCCTransportError):
            pilot.submit(**ALLOW_SCENARIO)
        assert pilot.actuator.log == []


# --------------------------------------------------------------------------
# Direct actuator invocation: rejected / structurally unavailable
# --------------------------------------------------------------------------


def test_direct_actuator_invocation_rejected_for_deny_decision(gateway_url, tmp_path):
    url, _shared_key = gateway_url
    with MCCClient(base_url=url, api_key=module_key("agent/ops-bot")) as client:
        decision = client.evaluate(EvaluateRequest(**DENY_SCENARIO, mode="inline"))
    actuator = SimulatedActuator()
    with pytest.raises(DirectActuationRejected):
        actuator.execute(action=DENY_SCENARIO["action"], actor_id="agent/ops-bot", decision=decision)


def test_direct_actuator_invocation_rejected_without_decision_token():
    from mcc_sdk import EvaluateResponse, Verdict

    forged = EvaluateResponse(
        decision=Verdict.ALLOW, reason="forged", audit_id="forged-audit",
        decision_token=None, forward_context={"amount": 1_000_000},
    )
    actuator = SimulatedActuator()
    with pytest.raises(DirectActuationRejected):
        actuator.execute(action="send_payment", actor_id="agent/attacker", decision=forged)


def test_pilot_integration_exposes_no_execute_without_a_decision():
    """Structural guard: PilotIntegration has no public method that performs
    the simulated action without going through submit() -> the real
    Gateway's decision first."""
    public_methods = {name for name in dir(PilotIntegration) if not name.startswith("_")}
    assert public_methods == {"submit", "close"}


# --------------------------------------------------------------------------
# Evidence: correlation, schema validation, secrets, no silent overwrite
# --------------------------------------------------------------------------


def test_correlation_identifiers_reach_evidence_records(gateway_url, tmp_path):
    cfg = _config(gateway_url, tmp_path, mode="observe")
    with PilotIntegration(cfg) as pilot:
        outcome = pilot.submit(**ALLOW_SCENARIO)
    evidence = pilot.evidence.finalize()
    assert len(evidence["correlation_refs"]) == 1
    ref = evidence["correlation_refs"][0]
    assert ref["audit_id"] == outcome.decision.audit_id
    assert ref["trace_id"] == outcome.decision.trace_id
    assert ref["decision"] == "ALLOW"


def test_evidence_output_validates_against_schema(gateway_url, tmp_path):
    cfg = _config(gateway_url, tmp_path, mode="observe")
    with PilotIntegration(cfg) as pilot:
        pilot.submit(**ALLOW_SCENARIO)
        pilot.submit(**DENY_SCENARIO)
    path = pilot.evidence.finalize_and_export()
    data = json.loads(path.read_text())
    validate_evidence(data)  # raises on failure


def test_no_secret_values_appear_in_exported_evidence(gateway_url, tmp_path):
    url, _shared_key = gateway_url
    secret = "super-secret-pilot-api-key-do-not-leak"
    agent_secret = "super-secret-pilot-agent-key-do-not-leak"
    cfg = PilotConfig(
        gateway_url=url, api_key=secret, agent_keys={"agent/payments-bot": agent_secret},
        mode="observe", evidence_dir=str(tmp_path),
        pilot_id="acceptance-test", integration_id="reference-python-v1",
    )
    with PilotIntegration(cfg, client=MCCClient(base_url=url,
                                                api_key=module_key("agent/payments-bot"))) as pilot:
        pilot.submit(**ALLOW_SCENARIO)
    path = pilot.evidence.finalize_and_export()
    raw = path.read_text()
    assert secret not in raw
    assert agent_secret not in raw
    assert "api_key" not in json.loads(raw)
    assert "agent_keys" not in raw


def test_repeated_runs_do_not_overwrite_evidence_silently(gateway_url, tmp_path):
    cfg = _config(gateway_url, tmp_path, mode="observe")
    with PilotIntegration(cfg) as pilot:
        pilot.submit(**ALLOW_SCENARIO)
        pilot.evidence.finalize_and_export()
        with pytest.raises(FileExistsError):
            pilot.evidence.finalize_and_export()


def test_attempted_bypass_is_recorded_and_fails_the_run(gateway_url, tmp_path):
    cfg = _config(gateway_url, tmp_path, mode="observe")
    with PilotIntegration(cfg) as pilot:
        pilot.submit(**ALLOW_SCENARIO)
        pilot.evidence.record_attempted_bypass()
    evidence = pilot.evidence.finalize()
    assert evidence["attempted_bypass_count"] == 1
    assert evidence["status"] == "FAIL"
    validate_evidence(evidence)


# --------------------------------------------------------------------------
# F1b: per-identity credentials
# --------------------------------------------------------------------------


def test_f1b_shared_key_alone_obtains_no_decision(gateway_url, tmp_path):
    """The pre-F1b configuration (one shared key for every identity) is
    refused by a strict Gateway -- no decision, nothing actuated."""
    from mcc_sdk import MCCAuthenticationError
    cfg = _config(gateway_url, tmp_path, mode="enforced", agent_keys=None)
    with PilotIntegration(cfg) as pilot:
        with pytest.raises(MCCAuthenticationError):
            pilot.submit(**ALLOW_SCENARIO)
        assert pilot.actuator.log == []


def test_f1b_identity_without_a_configured_key_fails_closed(gateway_url, tmp_path):
    from mcc_sdk import MCCConfigurationError
    cfg = _config(gateway_url, tmp_path, mode="enforced",
                  agent_keys={"agent/ops-bot": module_key("agent/ops-bot")})
    with PilotIntegration(cfg) as pilot:
        with pytest.raises(MCCConfigurationError):
            pilot.submit(**ALLOW_SCENARIO)   # agent/payments-bot has no key -> no shared fallback
        assert pilot.actuator.log == []


def test_f1b_another_identitys_key_cannot_evaluate_as_it(gateway_url, tmp_path):
    from mcc_sdk import MCCAuthenticationError
    cfg = _config(gateway_url, tmp_path, mode="enforced",
                  agent_keys={"agent/payments-bot": module_key("agent/ops-bot")})
    with PilotIntegration(cfg) as pilot:
        with pytest.raises(MCCAuthenticationError):
            pilot.submit(**ALLOW_SCENARIO)
        assert pilot.actuator.log == []
