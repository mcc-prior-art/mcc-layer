"""Adversarial runtime proof that the agent (proposer) and the operator
(authority) are genuinely separate principals for the gateway/SDK-based
governed-agent pilots (``docker-compose.notify-pilot.yml`` /
``docker-compose.reference-agent.yml``), against the REAL gateway +
governance_service + receipt-verifying upstream (via
``tests/_notify_harness.NotifyPilotHarness``) -- not a mock.

This exercises the same two credential sets the refactored compose services
hold: an "agent" ``MCCClient`` (``api_key`` only, matching ``pilot-agent`` /
``reference-agent`` after the credential-separation fixes) and an "operator"
``MCCClient`` (``api_key`` + ``operator_key``, matching the new
``pilot-operator`` / ``gateway_approval_operator.py`` sidecar). No test here
constructs an agent client with an operator key, because no refactored
service holds one either.

Security property under proof: COMPROMISE(AGENT) != COMPROMISE(AUTHORITY).
Holding the agent's credentials must never be sufficient to grant an
approval; holding the operator's credentials must never be sufficient to
execute a DIFFERENT action than the one actually approved.
"""

from __future__ import annotations

import pytest

from mcc_client import (
    Approval,
    MCCAuthenticationError,
    MCCError,
    MCCInvalidDecisionError,
    MCCClient,
    Verdict,
)

from pilot_notify import recorded_receipts, reset_receipts
from tests._notify_harness import API_KEY, OPERATOR_KEY, NotifyPilotHarness


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


def _agent_client(harness: NotifyPilotHarness) -> MCCClient:
    """No operator key -- matches pilot-agent / reference-agent after the fix."""
    return MCCClient(harness.base_url, api_key=API_KEY)


def _operator_client(harness: NotifyPilotHarness) -> MCCClient:
    """Matches the separate pilot-operator sidecar."""
    return MCCClient(harness.base_url, api_key=API_KEY, operator_key=OPERATOR_KEY)


def _payload(corr: str) -> dict:
    return {"recipient": "cust-1", "message": "Hi", "correlation_id": corr,
            "priority": 1, "channel": "email"}


def _escalate(agent: MCCClient, idem: str):
    d = agent.evaluate(actor_id="agent/unknown", action="send_notification",
                       resource="crm", payload=_payload(idem), idempotency_key=idem)
    assert d.verdict == Verdict.ESCALATE, d
    approval = agent.request_approval(d)
    return d, approval


class TestCaseA_CompromisedAgentCannotSelfApprove:
    """A: an agent client that never held an operator key cannot grant its
    own approval -- it cannot even construct the request (no key to send),
    let alone have it accepted. Zero actuation."""

    def test_agent_without_operator_key_cannot_approve(self, hz):
        agent = _agent_client(hz)
        d, approval = _escalate(agent, "sep2-a-1")

        with pytest.raises(MCCAuthenticationError):
            agent.approve(approval)

        assert recorded_receipts() == []


class TestCaseB_SeparatedAuthoritySucceedsExactlyOnce:
    """B: the legitimate, separated operator (a DIFFERENT MCCClient, holding
    the operator key) grants the approval; the agent's own client (holding
    only its api key) then executes -- exactly once."""

    def test_operator_approves_agent_executes_exactly_once(self, hz):
        agent = _agent_client(hz)
        operator = _operator_client(hz)
        d, approval = _escalate(agent, "sep2-b-1")

        granted = operator.approve(approval)
        result = agent.execute_after_approval(d, granted)
        assert result.executed
        assert len(recorded_receipts()) == 1

        # Idempotent replay of the same execute must not actuate a second
        # time (whether it raises or returns, the external side effect
        # count must not move).
        try:
            agent.execute_after_approval(d, granted)
        except MCCError:
            pass
        assert len(recorded_receipts()) == 1


class TestCaseC_StolenOrWrongCredentialRejected:
    """C: a wrong/forged operator credential is rejected by the server; zero
    actuation."""

    def test_wrong_operator_key_rejected(self, hz):
        agent = _agent_client(hz)
        wrong_operator = MCCClient(hz.base_url, api_key=API_KEY,
                                   operator_key="stolen-or-guessed-key")
        d, approval = _escalate(agent, "sep2-c-1")

        with pytest.raises(MCCAuthenticationError):
            wrong_operator.approve(approval)

        assert recorded_receipts() == []


class TestCaseD_WrongBindingRejected:
    """D: a mandate granted for one actor/action/resource scope does not
    authorize executing under a DIFFERENT principal -- the gate must bind
    the granted mandate to the exact original actor, not just honor
    whatever actor the caller submits at execute time. (A mandate's scope
    is actor+action+resource, re-evaluated against the submitted context
    at execution time -- see tests/test_approvals.py's own substitution
    tests; this proves that same server-side binding still holds when the
    approval is driven by a genuinely separate operator client rather than
    one combined client.)"""

    def test_granted_mandate_does_not_cover_a_different_actor(self, hz):
        agent = _agent_client(hz)
        operator = _operator_client(hz)
        d, approval = _escalate(agent, "sep2-d-1")
        granted = operator.approve(approval)

        # Re-evaluate for a DIFFERENT actor under the same action/resource,
        # then try to execute it against the first actor's granted mandate.
        d2 = agent.evaluate(actor_id="agent/ATTACKER", action="send_notification",
                            resource="crm", payload=_payload("sep2-d-2"),
                            idempotency_key="sep2-d-2")

        with pytest.raises(MCCError):
            agent.execute_after_approval(d2, granted)

        assert recorded_receipts() == []


class TestCaseE_AuthorityUnavailableFailsClosed:
    """E: if the separated authority (operator) never acts at all --
    simulating it being down/unreachable -- the agent's own bounded retries
    against the still-pending approval never execute anything."""

    def test_no_approval_ever_granted_means_zero_actuation_after_retries(self, hz):
        agent = _agent_client(hz)
        d, approval = _escalate(agent, "sep2-e-1")
        pending = Approval(request_id=approval.request_id, state="PENDING", mandate=None)

        for _ in range(3):
            with pytest.raises(MCCInvalidDecisionError):
                agent.execute_after_approval(d, pending)

        assert recorded_receipts() == []
