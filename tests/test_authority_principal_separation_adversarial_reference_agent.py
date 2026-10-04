"""Adversarial runtime proof for ``docker-compose.reference-agent.yml``'s
agent/operator split, against the REAL gateway + governance_service +
receipt-verifying upstream (via ``tests/_notify_harness.NotifyPilotHarness``)
-- and, unlike the generic SDK-level proof in
``test_authority_principal_separation_adversarial_notify.py``, exercising
the ACTUAL shipped scripts (loaded by path, since ``deploy/pilot`` is a
deploy directory, not a package -- see ``tests/test_pilot_driver.py`` for
the same loading pattern) rather than just the SDK primitives they're built
from. This is the strongest available non-vacuity proof that the real
container entrypoints -- not just the underlying library -- hold the
credential-separation property.
"""

from __future__ import annotations

import importlib.util
import json
import threading
from pathlib import Path

import pytest

from mcc_client import MCCClient

from pilot_notify import recorded_receipts, reset_receipts
from tests._notify_harness import API_KEY, OPERATOR_KEY, NotifyPilotHarness

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, rel_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def hz():
    harness = NotifyPilotHarness()
    try:
        yield harness
    finally:
        harness.close()


@pytest.fixture(autouse=True)
def _reset():
    reset_receipts()
    yield


@pytest.fixture()
def runner(tmp_path, monkeypatch):
    """The REAL deploy/pilot/reference_agent_runner.py, loaded fresh per test
    with its state directory pointed at an isolated tmp_path."""
    monkeypatch.setenv("MCC_PILOT_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("MCC_APPROVAL_WAIT_TIMEOUT_S", "6")
    monkeypatch.setenv("MCC_APPROVAL_POLL_INTERVAL_S", "0.2")
    return _load("reference_agent_runner", "deploy/pilot/reference_agent_runner.py")


@pytest.fixture()
def operator_module(hz, tmp_path, monkeypatch):
    """The REAL deploy/pilot/gateway_approval_operator.py, loaded fresh per
    test, pointed at the SAME tmp_path state directory and the harness's
    real gateway."""
    monkeypatch.setenv("MCC_PILOT_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("MCC_GATEWAY_OPERATOR_API_KEY", OPERATOR_KEY)
    monkeypatch.setenv("MCC_GATEWAY_API_KEY", API_KEY)
    monkeypatch.setenv("MCC_GATEWAY_URL", hz.base_url)
    monkeypatch.setenv("MCC_OPERATOR_POLL_INTERVAL_S", "0.2")
    return _load("gateway_approval_operator", "deploy/pilot/gateway_approval_operator.py")


def _agent_client(hz: NotifyPilotHarness) -> MCCClient:
    return MCCClient(hz.base_url, api_key=API_KEY, timeout=15.0)


class TestCaseA_CompromisedAgentCannotSelfApprove:
    """A: the real runner script's own agent-side function, driven with a
    client that holds no operator key, cannot complete an ESCALATE on its
    own -- even waiting its full timeout, it never executes, because
    nothing in its own code path can grant the approval."""

    def test_runner_alone_never_executes(self, hz, runner):
        client = _agent_client(hz)
        result = runner._escalate_with_separated_operator(client, "notify customer-1")

        assert result.execution_status != "EXECUTED"
        assert recorded_receipts() == []


class TestCaseB_SeparatedAuthoritySucceedsExactlyOnce:
    """B: the REAL operator sidecar script, running in its own thread with
    ONLY the operator key, processes the REAL agent script's pending
    approval and the agent's own (operator-key-less) client then reaches
    genuine EXECUTED -- exactly once."""

    def test_real_agent_and_real_operator_scripts_cooperate_exactly_once(
        self, hz, runner, operator_module
    ):
        op_thread = threading.Thread(
            target=lambda: operator_module.main(), daemon=True)
        op_thread.start()

        client = _agent_client(hz)
        result = runner._escalate_with_separated_operator(client, "notify customer-2")

        assert result.verdict == "ESCALATE"
        assert result.approval_status == "APPROVED"
        assert result.execution_status == "EXECUTED"
        assert result.receipt and result.receipt.get("receipt_verified")
        assert result.audit_valid is True
        assert len(recorded_receipts()) == 1


class TestCaseC_StolenOrWrongCredentialRejected:
    """C: the real operator script, misconfigured with a wrong operator
    key, has its approve() call rejected server-side; it reports no
    mandate. The operator script ALSO never executes anything now (it holds
    no api key and calls no execute route), so this proves the approval
    half fails closed, not merely that execution happened to fail too."""

    def test_operator_script_with_wrong_key_cannot_approve(self, hz, tmp_path, monkeypatch):
        monkeypatch.setenv("MCC_PILOT_STATE_DIR", str(tmp_path))
        monkeypatch.setenv("MCC_GATEWAY_OPERATOR_API_KEY", "stolen-or-guessed-key")
        monkeypatch.setenv("MCC_GATEWAY_URL", hz.base_url)
        bad_operator = _load("gateway_approval_operator_badkey",
                             "deploy/pilot/gateway_approval_operator.py")

        agent_client = _agent_client(hz)
        d = agent_client.evaluate(actor_id="agent/unknown", action="send_notification",
                                  resource="notification-service",
                                  payload={"recipient": "cust-1", "message": "hi",
                                          "correlation_id": "corr-case-c", "priority": 2,
                                          "channel": "email"},
                                  idempotency_key="corr-case-c")
        approval = agent_client.request_approval(d)

        state = {"requestId": approval.request_id}
        with bad_operator.httpx.Client(timeout=15.0) as hc:
            result = bad_operator._process_one(hc, state)

        assert result["mandate"] is None
        assert recorded_receipts() == []


class TestCaseD_StateFileContentIsNeverTrustedForTheDecision:
    """D: the agent-written state file carries ONLY a request_id pointer --
    the real operator script reads no other field from it at all. Tampering
    the file to claim a different actor/resource/payload therefore has NO
    EFFECT on the operator's behavior one way or the other: approve() still
    evaluates (and the mandate it mints is still bound to) the gateway's
    own stored record for that request_id, never anything the file claims.
    This is a STRONGER property than "the gate rejects a mismatched
    execute": the operator never had a chance to be misled in the first
    place. Mandate-granting alone is still not execution -- this test
    performs no execute call, so zero actuation either way."""

    def test_tampered_state_fields_are_never_read(self, hz, operator_module):
        agent_client = _agent_client(hz)
        d = agent_client.evaluate(actor_id="agent/unknown", action="send_notification",
                                  resource="notification-service",
                                  payload={"recipient": "cust-1", "message": "hi",
                                          "correlation_id": "corr-case-d", "priority": 2,
                                          "channel": "email"},
                                  idempotency_key="corr-case-d")
        approval = agent_client.request_approval(d)

        # Tampered: claims a different actor/resource/action/payload than
        # the one MCC-Core actually evaluated for this request_id. Only
        # requestId is real.
        tampered_state = {"requestId": approval.request_id, "actor": "agent/ATTACKER",
                          "resource": "attacker-resource", "context": {"forged": True},
                          "action": "send_payment", "correlationId": "corr-case-d"}
        with operator_module.httpx.Client(timeout=15.0) as hc:
            result = operator_module._process_one(hc, tampered_state)

        # The approval succeeds -- but bound to the REAL stored record
        # (agent/unknown, send_notification, notification-service), which is
        # exactly what the independent AuthorityPolicy (when configured) or
        # bare operator-trust (when not) evaluates. The tampered fields were
        # never consulted at all, not merely "rejected".
        assert result["mandate"] is not None
        assert result["mandate"]["subject"] == "agent/unknown"
        assert result["mandate"]["action_scope"] == ["send_notification"]
        # No execute call happens anywhere in this test -- zero actuation.
        assert recorded_receipts() == []


class TestCaseE_AuthorityUnavailableFailsClosed:
    """E: if the operator sidecar never runs at all (down/unreachable),
    the real agent script's bounded wait times out without ever
    executing. No actuation without an independently-granted approval."""

    def test_no_operator_running_means_timeout_not_execution(self, hz, runner):
        client = _agent_client(hz)
        result = runner._escalate_with_separated_operator(client, "notify customer-3")

        assert result.execution_status == "BLOCKED"
        assert result.approval_status in ("PENDING", None)
        assert recorded_receipts() == []
