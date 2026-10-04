"""Adversarial runtime proof for ``src/mcc_agent/agent.py``'s ``GovernedAgent``
-- the sixth and final known instance of the combined-proposer/authority
defect class, discovered during this audit (flagged in
``docs/CONSTITUTION-INVARIANTS.md`` as a not-yet-closed finding until this
test file and the accompanying fix landed).

``GovernedAgent.client`` (the ``GovernanceClient`` Protocol: submit /
execute_after_approval / verify_audit_chain) has no approve/deny_approval
method. Granting a pending ESCALATE requires a SEPARATE ``operator``
object (an ``OperatorClient``: approve / deny_approval only), passed in at
construction. Without one, ``GovernedAgent`` cannot complete its own
authorization path -- it reports PENDING_APPROVAL and stops.

Against the real MCC-Core runtime (``EmbeddedGovernanceClient``) and a real
loopback pilot API -- not mocks.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from examples._demo_server import DemoServer
import pilot_api.app as pilot_app
from pilot_api import recorded_operations, reset_state

from mcc_agent import DeterministicPlanner, EmbeddedGovernanceClient, GovernedAgent

run = asyncio.run
PORT = None


@pytest.fixture(scope="module", autouse=True)
def _pilot_server():
    global PORT
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    PORT = s.getsockname()[1]
    s.close()
    server = DemoServer(pilot_app.app, PORT)
    server.start()
    try:
        yield
    finally:
        server.stop()


@pytest.fixture(autouse=True)
def _reset():
    reset_state()
    yield


def _base() -> str:
    return f"http://127.0.0.1:{PORT}"


ESCALATE_GOAL = "Increase campaign budget to 5000 EUR"


def _agent_no_operator(**kw):
    """The agent side, holding ONLY its own client -- no operator at all."""
    base = _base()
    client = EmbeddedGovernanceClient(pilot_api_base=base, **kw)
    agent = GovernedAgent(client=client, planner=DeterministicPlanner(pilot_api_base=base))
    return client, agent


def _agent_with_operator(**kw):
    """The agent side, wired with its paired SEPARATE operator object."""
    base = _base()
    client = EmbeddedGovernanceClient(pilot_api_base=base, **kw)
    agent = GovernedAgent(client=client, planner=DeterministicPlanner(pilot_api_base=base),
                          operator=client.operator)
    return client, agent


class TestCaseA_CompromisedAgentCannotSelfApprove:
    """A: a GovernedAgent with no operator configured cannot complete its
    own ESCALATE, no matter how it is driven -- it has no approve method
    to call, and auto_approve=True is a no-op without a separate
    operator. Zero actuation."""

    def test_no_operator_configured_blocks_not_executes(self):
        client, agent = _agent_no_operator()
        r = agent.run(ESCALATE_GOAL, idempotency_key="case-a-1")
        assert r.decision == "ESCALATE"
        assert r.execution_status == "PENDING_APPROVAL"
        assert recorded_operations() == []

    def test_client_object_itself_has_no_approve_method(self):
        client, _ = _agent_no_operator()
        assert not hasattr(client, "approve")
        assert not hasattr(client, "deny_approval")
        assert hasattr(client.operator, "approve")


class TestCaseB_SeparatedOperatorExecutesExactlyOnce:
    """B: a GovernedAgent wired with its SEPARATE operator object (not
    itself) completes the ESCALATE -> approve -> execute loop -- exactly
    once."""

    def test_wired_operator_executes_once(self):
        client, agent = _agent_with_operator()
        r = agent.run(ESCALATE_GOAL, idempotency_key="case-b-1")
        assert r.decision == "ESCALATE" and r.execution_status == "EXECUTED"
        assert len(recorded_operations()) == 1

        # A second run with the SAME idempotency key must not actuate again.
        r2 = agent.run(ESCALATE_GOAL, idempotency_key="case-b-1")
        assert r2.execution_status != "EXECUTED" or len(recorded_operations()) == 1
        assert len(recorded_operations()) == 1


class TestCaseC_ForgedApprovalRejected:
    """C: resubmitting with an unknown/forged approval id is rejected by
    the real runtime; zero actuation."""

    def test_forged_approval_id_rejected(self):
        client, _ = _agent_no_operator()
        proposal = DeterministicPlanner(pilot_api_base=_base()).plan(
            ESCALATE_GOAL, idempotency_key="case-c-1")
        run(client.submit(proposal))
        out = run(client.execute_after_approval(proposal, "approval-does-not-exist"))
        assert not out.executed and recorded_operations() == []


class TestCaseD_WrongBindingRejected:
    """D: an approval granted for ONE logical operation does not
    authorize executing a DIFFERENT one (different idempotency_key/
    payload) -- the real runtime's bound consume fails closed."""

    def test_approval_does_not_cover_a_different_operation(self):
        base = _base()
        client = EmbeddedGovernanceClient(pilot_api_base=base)
        plan = DeterministicPlanner(pilot_api_base=base).plan

        a = plan(ESCALATE_GOAL, idempotency_key="case-d-a")
        out_a = run(client.submit(a))
        rid = out_a.approval_request_id
        assert rid
        assert run(client.operator.approve(rid)) is True

        # A DIFFERENT logical operation (different idempotency_key) must
        # not be authorized by an approval minted for operation `a`.
        b = plan(ESCALATE_GOAL, idempotency_key="case-d-b")
        out = run(client.execute_after_approval(b, rid))
        assert not out.executed and recorded_operations() == []


class TestCaseE_AuthorityUnavailableFailsClosed:
    """E: if the separated operator never acts at all, the agent's own
    repeated runs never execute -- no actuation without an
    independently-granted approval."""

    def test_no_operator_action_means_zero_execution_after_retries(self):
        client, agent = _agent_no_operator()
        for i in range(3):
            r = agent.run(ESCALATE_GOAL, idempotency_key=f"case-e-{i}")
            assert r.execution_status != "EXECUTED"
        assert recorded_operations() == []
