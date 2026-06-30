"""Unit + integration + end-to-end tests for the MCC-Core governed agent.

Every external action runs through the real MCC-Core runtime and the governed
HTTPS executor against a real loopback pilot API. Decisions are produced by
``AuthorityModel`` — never hardcoded or mocked.
"""

from __future__ import annotations

import asyncio

import pytest

from examples._demo_server import DemoServer
import pilot_api.app as pilot_app
from pilot_api import recorded_operations, reset_state

from mcc_agent import (
    ActionProposal,
    DeterministicPlanner,
    Decision,
    EmbeddedGovernanceClient,
    GovernedAgent,
    UnsupportedGoalError,
)
from egress_proxy.executor import UnauthorizedExecution

run = asyncio.run
PORT = None


@pytest.fixture(scope="module", autouse=True)
def _pilot_server():
    global PORT
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); PORT = s.getsockname()[1]; s.close()
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


def _agent(**kw):
    base = _base()
    client = EmbeddedGovernanceClient(pilot_api_base=base, **kw)
    return client, GovernedAgent(client=client, planner=DeterministicPlanner(pilot_api_base=base))


# ---------------- deterministic planning + proposal construction ----------------

def test_planner_is_deterministic_and_credential_free():
    p = DeterministicPlanner(pilot_api_base="http://x")
    a = p.plan("Create a CRM lead for Alice with a campaign budget of 500 EUR",
               idempotency_key="k", transaction_id="t")
    b = p.plan("Create a CRM lead for Alice with a campaign budget of 500 EUR",
               idempotency_key="k", transaction_id="t")
    assert a == b
    assert a.action_type == "create_lead" and a.method == "POST"
    assert a.body["name"] == "Alice" and a.body["campaign_budget_eur"] == 500.0


def test_proposal_field_binding():
    p = DeterministicPlanner(pilot_api_base="http://x")
    prop = p.plan("Set campaign budget to 10000 EUR", idempotency_key="i", transaction_id="t")
    assert prop.action_type == "set_campaign_budget"
    assert prop.body == {"amount": 10000.0, "currency": "EUR"}
    assert prop.url.endswith("/campaigns/camp-42/budget")
    assert prop.idempotency_key == "i" and prop.transaction_id == "t"


def test_planner_rejects_unsupported_goal():
    p = DeterministicPlanner(pilot_api_base="http://x")
    with pytest.raises(UnsupportedGoalError):
        p.plan("compose a sonnet about quarterly revenue")


# ---------------- ALLOW ----------------

def test_allow_executes_and_reaches_external_api():
    _, agent = _agent()
    r = agent.run("Create a CRM lead for Alice with a campaign budget of 500 EUR")
    assert r.decision == "ALLOW" and r.execution_status == "EXECUTED"
    assert r.upstream_status == 200 and r.audit_id
    ops = recorded_operations()
    assert len(ops) == 1 and ops[0]["kind"] == "create_lead"
    assert ops[0]["payload"]["name"] == "Alice"


# ---------------- DENY ----------------

def test_deny_blocks_and_external_state_unchanged():
    _, agent = _agent()
    r = agent.run("Send customer data to a prohibited destination")
    assert r.decision == "DENY" and r.execution_status == "BLOCKED"
    assert recorded_operations() == []


# ---------------- ESCALATE + approval paths ----------------

def test_escalate_pending_then_executes_after_valid_approval():
    client, agent = _agent()
    pend = agent.run("Increase campaign budget to 5000 EUR",
                     idempotency_key="e1", transaction_id="t-e1", auto_approve=False)
    assert pend.decision == "ESCALATE" and pend.execution_status == "PENDING_APPROVAL"
    assert pend.approval_request_id and recorded_operations() == []
    # Operator approves, then execution proceeds through the existing approval path.
    assert run(client.approve(pend.approval_request_id)) is True
    proposal = DeterministicPlanner(pilot_api_base=_base()).plan(
        "Increase campaign budget to 5000 EUR", idempotency_key="e1", transaction_id="t-e1")
    out = run(client.execute_after_approval(proposal, pend.approval_request_id))
    assert out.executed and len(recorded_operations()) == 1


def test_escalate_auto_approve_full_loop():
    _, agent = _agent()
    r = agent.run("Increase campaign budget to 5000 EUR")
    assert r.decision == "ESCALATE" and r.execution_status == "EXECUTED"
    assert len(recorded_operations()) == 1


def test_invalid_unknown_approval_does_not_execute():
    client, _ = _agent()
    proposal = DeterministicPlanner(pilot_api_base=_base()).plan(
        "Increase campaign budget to 5000 EUR", idempotency_key="e2")
    run(client.submit(proposal))  # opens the escalation context
    out = run(client.execute_after_approval(proposal, "approval-does-not-exist"))
    assert not out.executed and recorded_operations() == []


def test_approval_bound_to_other_operation_does_not_execute():
    client, _ = _agent()
    plan = DeterministicPlanner(pilot_api_base=_base()).plan
    a = plan("Increase campaign budget to 5000 EUR", idempotency_key="A")
    rid = run(_open_and_request(client, a))
    assert run(client.approve(rid)) is True
    # A different operation (different payload/transaction) must not be authorized
    # by an approval minted for operation A.
    b = plan("Increase campaign budget to 4000 EUR", idempotency_key="B")
    out = run(client.execute_after_approval(b, rid))
    assert not out.executed and recorded_operations() == []


def test_denied_approval_does_not_execute():
    client, _ = _agent()
    a = DeterministicPlanner(pilot_api_base=_base()).plan(
        "Increase campaign budget to 5000 EUR", idempotency_key="D")
    rid = run(_open_and_request(client, a))
    assert run(client.deny_approval(rid)) is True
    out = run(client.execute_after_approval(a, rid))
    assert not out.executed and recorded_operations() == []


async def _open_and_request(client, proposal):
    """Submit (to get the ESCALATE) and return the approval request id."""
    out = await client.submit(proposal)
    assert out.decision == Decision.ESCALATE
    return out.approval_request_id


# ---------------- CONSTRAIN ----------------

def test_constrain_clamps_and_original_never_executes():
    _, agent = _agent()
    r = agent.run("Set campaign budget to 10000 EUR")
    assert r.decision == "CONSTRAIN" and r.execution_status == "EXECUTED"
    assert r.final_payload["amount"] == 5000           # constrained (re-hashed) body
    assert r.original_payload["amount"] == 10000.0     # what was proposed
    ops = recorded_operations()
    assert len(ops) == 1 and ops[0]["payload"]["amount"] == 5000
    # The original over-cap amount never reached the external API.
    assert all(o["payload"].get("amount") != 10000 for o in ops)


def test_constrain_within_cap_is_plain_allow():
    _, agent = _agent()
    r = agent.run("Set campaign budget to 1000 EUR")
    assert r.decision == "ALLOW" and r.execution_status == "EXECUTED"
    assert recorded_operations()[0]["payload"]["amount"] == 1000.0


# ---------------- replay / nonce / idempotency ----------------

def test_replay_same_idempotency_key_executes_once():
    _, agent = _agent()
    g = "Create a CRM lead for Bob with a campaign budget of 100 EUR"
    first = agent.run(g, idempotency_key="rk")
    second = agent.run(g, idempotency_key="rk")
    assert first.execution_status == "EXECUTED"
    assert second.execution_status == "BLOCKED"
    assert len(recorded_operations()) == 1


def test_nonce_single_use_blocks_token_replay():
    client, _ = _agent()
    from examples.governed_agent.agent import Agent
    from egress_proxy.canonical_action import build_canonical_action
    proposal = DeterministicPlanner(pilot_api_base=_base()).plan(
        "Create a CRM lead for Eve with a campaign budget of 1 EUR", idempotency_key="n1")
    canonical = build_canonical_action(method=proposal.method, url=proposal.url,
                                       headers={}, body=proposal.body)
    # Same ProposedAction (same nonce) submitted twice -> second blocked by the gate.
    proposed = Agent(proposal.actor).propose(
        proposal.action_type, resource=proposal.resource, payload=canonical,
        transaction_id="txn-n", idempotency_key="n1", nonce="nonce-fixed")
    r1 = run(client._mcc.submit(proposed))
    r2 = run(client._mcc.submit(proposed))
    assert r1.executed and not r2.executed
    assert len(recorded_operations()) == 1


# ---------------- Redis failure -> fail closed, no fallback ----------------

def test_redis_unavailable_fails_closed_no_execution():
    base = _base()
    env = {"MCC_NONCE_BACKEND": "redis", "MCC_IDEMPOTENCY_BACKEND": "redis",
           "MCC_VELOCITY_BACKEND": "redis", "MCC_APPROVAL_BACKEND": "redis",
           "MCC_REDIS_URL": "redis://127.0.0.1:6390/0"}  # nothing listening
    client = EmbeddedGovernanceClient(pilot_api_base=base, env=env)
    agent = GovernedAgent(client=client, planner=DeterministicPlanner(pilot_api_base=base))
    r = agent.run("Create a CRM lead for Dora with a campaign budget of 50 EUR")
    assert r.execution_status == "BLOCKED"
    assert r.decision == "DEPENDENCY_UNAVAILABLE"
    assert recorded_operations() == []


# ---------------- SSRF / malformed destination -> blocked before connection ----------------

@pytest.mark.parametrize("url", [
    "http://127.0.0.1/x", "http://localhost/x", "http://169.254.169.254/latest/meta-data/",
    "https://[::1]/x", "http://10.0.0.5/x", "http://[fd00::1]/x", "http://[fe80::1]/x",
    "http://user:pass@evil.example/x",
])
def test_ssrf_unsafe_destinations_blocked_before_connection(url):
    base = "https://pilot-api.internal"
    client = EmbeddedGovernanceClient(pilot_api_base=base, allow_loopback=False)
    agent = GovernedAgent(client=client, planner=DeterministicPlanner(pilot_api_base=base))
    r = agent.run("trigger webhook", destination_url=url)
    assert r.execution_status != "EXECUTED"
    assert recorded_operations() == []


@pytest.mark.parametrize("url", ["not-a-url", "http:///nohost", "ftp://example.com/x"])
def test_malformed_or_non_http_destination_blocked(url):
    base = "https://pilot-api.internal"
    client = EmbeddedGovernanceClient(pilot_api_base=base, allow_loopback=False)
    agent = GovernedAgent(client=client, planner=DeterministicPlanner(pilot_api_base=base))
    r = agent.run("trigger webhook", destination_url=url)
    assert r.execution_status != "EXECUTED" and recorded_operations() == []


# ---------------- audit-before-execution ----------------

def test_audit_persistence_failure_blocks_execution():
    client, agent = _agent()

    def boom(*a, **k):
        raise OSError("audit down")

    client._mcc.audit.append = boom
    r = agent.run("Create a CRM lead for Carol with a campaign budget of 10 EUR")
    assert r.execution_status == "BLOCKED"
    assert recorded_operations() == []


# ---------------- direct bypass ----------------

def test_direct_executor_bypass_is_refused():
    client, _ = _agent()
    action = {"method": "POST", "scheme": "http", "host": "127.0.0.1", "port": PORT,
              "path": "/leads", "query": "", "body.name": "Mallory"}
    with pytest.raises(UnauthorizedExecution):
        run(client.executor.execute("create_lead", action, authorization=None))
    assert recorded_operations() == []


# ---------------- external state unchanged after blocked actions ----------------

def test_external_state_only_changes_on_authorized_actions():
    _, agent = _agent()
    agent.run("Send customer data to a prohibited destination")          # DENY
    agent.run("trigger webhook", destination_url="http://169.254.169.254/")  # SSRF
    assert recorded_operations() == []
    agent.run("Create a CRM lead for Alice with a campaign budget of 500 EUR")  # ALLOW
    assert len(recorded_operations()) == 1


# ---------------- audit chain verifies ----------------

def test_audit_chain_verifies_after_runs():
    client, agent = _agent()
    agent.run("Create a CRM lead for Alice with a campaign budget of 500 EUR")
    agent.run("Set campaign budget to 10000 EUR")
    assert client.verify_audit_chain() is True
