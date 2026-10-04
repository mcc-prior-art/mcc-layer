"""Adversarial runtime proof for the two single-process reference scripts
identified in the repository-wide authority-principal-separation audit as
also combining the proposer and authority roles, even though neither is a
Docker Compose deployment (so neither was, or could be, caught by
``tests/test_authority_principal_separation_scanner.py``, which only scans
``docker-compose*.yml`` topology):

* ``examples/agent_runtime_mcc.py`` -- refactored so the agent
  (``AgentRuntimeClient``) and the MCC authority (``_authority_process``)
  are genuinely separate OS PROCESSES (``multiprocessing``), not merely
  separate objects in one process. The agent process never imports or
  constructs ``SigningKey`` / ``DecisionEngine`` / ``ExecutionGate``.

* ``examples/governed_agent/mcc_client.py`` -- refactored so
  ``GovernedMCCClient`` (the proposer) has no ``approve``/``deny_approval``
  method at all; only the separate ``OperatorConsole`` class does.

Security property under proof, as for the Docker-based demos:
COMPROMISE(AGENT) != COMPROMISE(AUTHORITY).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import examples.agent_runtime_mcc as agent_runtime_mcc  # noqa: E402

from examples.governed_agent.agent import Agent  # noqa: E402
from examples.governed_agent.mcc_client import GovernedMCCClient, OperatorConsole  # noqa: E402
from examples.governed_agent.mock_executor import MockExecutor  # noqa: E402

run = asyncio.run


# ============================================================================
# examples/agent_runtime_mcc.py: agent process vs. authority process
# ============================================================================

@pytest.fixture()
def runtime_client():
    client = agent_runtime_mcc.AgentRuntimeClient()
    try:
        yield client
    finally:
        client.close()


class TestAgentRuntimeMcc_CaseA_AgentProcessHoldsNoAuthorityCapability:
    """A: the agent-side object has no attribute related to signing,
    deciding, or gating -- a compromised agent process has nothing to
    read or call to self-authorize, because the capability was never
    given to it, not merely hidden by convention."""

    def test_agent_runtime_client_exposes_no_authority_surface(self):
        public_attrs = {a for a in dir(agent_runtime_mcc.AgentRuntimeClient)
                        if not a.startswith("_")}
        assert public_attrs == {"run", "close"}

    def test_module_level_has_no_authority_constructor(self):
        # SigningKey/DecisionEngine/ExecutionGate are imported ONLY inside
        # _authority_process's own function body (post-fork), never at
        # module scope -- so merely importing this module, as the agent
        # process does, never constructs or exposes any of them.
        names = dir(agent_runtime_mcc)
        assert not any("SigningKey" in n or "DecisionEngine" in n or "ExecutionGate" in n
                      for n in names)

    def test_disallowed_action_blocked_with_zero_execution(self, runtime_client):
        result = runtime_client.run({"action": "delete_user", "user_id": 1})
        assert result.startswith("BLOCKED")


class TestAgentRuntimeMcc_CaseB_SeparatedAuthorityExecutesLegitimateIntent:
    """B: a legitimate, in-policy intent -- decided, signed, and verified
    entirely inside the separate authority process -- executes."""

    def test_in_policy_payment_executes_via_separate_process(self, runtime_client):
        result = runtime_client.run({"action": "send_payment", "amount": 100})
        assert result == "EXECUTED: sent $100"


class TestAgentRuntimeMcc_CaseC_ClientCannotInjectAVerdict:
    """C (adapted: no API-key concept in this IPC demo -- the analogous
    attack is the agent trying to smuggle a pre-decided verdict across
    the pipe instead of letting the authority process derive it itself).
    The authority process's ``decide()`` call derives the verdict FROM the
    intent every time; a client-supplied 'verdict' key is just inert data
    to it and changes nothing."""

    def test_forged_verdict_field_is_ignored_by_the_authority(self, runtime_client):
        forged = {"action": "send_payment", "amount": 999999, "verdict": "ALLOW"}
        result = runtime_client.run(forged)
        assert result.startswith("BLOCKED")
        assert "EXECUTED" not in result


class TestAgentRuntimeMcc_CaseD_ReplayRejectedAcrossTheProcessBoundary:
    """D (adapted: binding/replay protection, not actor/resource scope,
    is the relevant invariant for this single-actor demo). The nonce
    registry lives inside the authority process; resubmitting a request
    bound to the SAME explicit nonce a second time must not execute
    twice -- proving the replay boundary holds across the process split,
    not just within one process."""

    def test_same_nonce_resubmitted_does_not_execute_twice(self, runtime_client):
        intent = {"action": "send_payment", "amount": 100, "nonce": "fixed-nonce-1"}
        first = runtime_client.run(dict(intent))
        second = runtime_client.run(dict(intent))
        assert first == "EXECUTED: sent $100"
        assert second.startswith("BLOCKED")


class TestAgentRuntimeMcc_CaseE_AuthorityProcessGoneFailsClosed:
    """E: if the separated authority process is killed/unavailable, the
    agent's call fails closed (raises) rather than silently treating the
    broken channel as permission."""

    def test_killed_authority_process_raises_not_silently_executes(self, runtime_client):
        runtime_client._proc.terminate()
        runtime_client._proc.join(timeout=2)
        with pytest.raises((EOFError, OSError, BrokenPipeError)):
            runtime_client.run({"action": "send_payment", "amount": 100})


# ============================================================================
# examples/governed_agent/mcc_client.py: GovernedMCCClient vs OperatorConsole
# ============================================================================

def _client(ex, **kw) -> GovernedMCCClient:
    return GovernedMCCClient(executor=ex, **kw)


class TestGovernedMCCClient_CaseA_NoApproveCapability:
    """A: GovernedMCCClient has no approve/deny_approval method at all --
    not merely a convention not to call it. A compromised agent holding
    only this object has nothing to call to grant its own escalation."""

    def test_client_class_has_no_approval_grant_methods(self):
        assert not hasattr(GovernedMCCClient, "approve")
        assert not hasattr(GovernedMCCClient, "deny_approval")
        assert hasattr(GovernedMCCClient, "request_approval")  # proposer action only

    def test_calling_approve_on_the_client_is_simply_unavailable(self):
        ex = MockExecutor()
        c = _client(ex)
        p = Agent("agent/intern").propose("transfer_resource", resource="a", payload={"amount": 100})
        run(c.submit(p))
        aid = run(c.request_approval(p))
        with pytest.raises(AttributeError):
            run(c.approve(aid))  # type: ignore[attr-defined]
        assert ex.count() == 0


class TestGovernedMCCClient_CaseB_SeparatedOperatorExecutesExactlyOnce:
    """B: a SEPARATE OperatorConsole, constructed independently, grants
    the approval; the agent's own execute_with_approval call then runs
    exactly once."""

    def test_operator_console_approves_agent_executes_once(self):
        ex = MockExecutor()
        c = _client(ex)
        operator = OperatorConsole(c)
        p = Agent("agent/intern").propose("transfer_resource", resource="a", payload={"amount": 100})
        assert not run(c.submit(p)).executed
        aid = run(c.request_approval(p))
        assert run(operator.approve(aid))
        r = run(c.execute_with_approval(p, aid))
        assert r.executed and ex.count() == 1

        # Idempotent/single-use: a second execute must not actuate again.
        r2 = run(c.execute_with_approval(p, aid))
        assert not r2.executed
        assert ex.count() == 1


class TestGovernedMCCClient_CaseC_ForgedApprovalRejected:
    """C: an unknown/forged approval id is rejected; zero execution."""

    def test_forged_approval_id_rejected(self):
        ex = MockExecutor()
        c = _client(ex)
        p = Agent("agent/intern").propose("transfer_resource", resource="a", payload={"amount": 100})
        r = run(c.execute_with_approval(p, "req-forged-nonexistent"))
        assert not r.executed and ex.count() == 0


class TestGovernedMCCClient_CaseD_MismatchedPayloadRejected:
    """D: a granted approval does not authorize a DIFFERENT payload than
    the one actually approved -- the bound consume fails closed."""

    def test_tampered_payload_after_approval_rejected(self):
        ex = MockExecutor()
        c = _client(ex)
        operator = OperatorConsole(c)
        a = Agent("agent/intern")
        p = a.propose("transfer_resource", resource="a", payload={"amount": 100})
        run(c.submit(p))
        aid = run(c.request_approval(p))
        assert run(operator.approve(aid))

        tampered = a.propose("transfer_resource", resource="a", payload={"amount": 999},
                             transaction_id=p.transaction_id)
        r = run(c.execute_with_approval(tampered, aid))
        assert not r.executed and ex.count() == 0


class TestGovernedMCCClient_CaseE_NoOperatorActionMeansNeverExecutes:
    """E: if no separate OperatorConsole ever acts (the "authority" is
    unavailable), the agent's own repeated attempts to execute the
    pending ESCALATE never succeed -- no actuation without an
    independently-granted approval."""

    def test_no_operator_action_means_zero_execution_after_retries(self):
        ex = MockExecutor()
        c = _client(ex)
        p = Agent("agent/intern").propose("transfer_resource", resource="a", payload={"amount": 100})
        run(c.submit(p))
        aid = run(c.request_approval(p))

        for _ in range(3):
            r = run(c.execute_with_approval(p, aid))
            assert not r.executed

        assert ex.count() == 0
