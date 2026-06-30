"""MCC-Core Pilot v0.1 — release-baseline validation.

Covers the release matrix on top of tests/test_mcc_agent.py: version metadata,
clean vs fail-closed startup, the four verdicts with re-evaluation, audit
evidence completeness, audit-before-execution, audit-chain verification, no
external execution before authorization, the constrained payload being the one
actually executed, and Redis replay protection (gated on a real Redis).
"""

from __future__ import annotations

import asyncio
import os

import pytest

from examples._demo_server import DemoServer
import pilot_api.app as pilot_app
from pilot_api import recorded_operations, reset_state

from mcc_agent import (
    DeterministicPlanner,
    EmbeddedGovernanceClient,
    GovernedAgent,
    PILOT_RELEASE_NAME,
    PILOT_VERSION,
)

run = asyncio.run
PORT = None

_EVIDENCE_FIELDS = {
    "proposal_id", "actor", "resource", "action_hash", "payload_hash",
    "policy_hash", "authority_state", "verdict", "constraints",
    "execution_result", "audit_ref",
}


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


def _agent(**kw):
    base = f"http://127.0.0.1:{PORT}"
    client = EmbeddedGovernanceClient(pilot_api_base=base, **kw)
    return client, GovernedAgent(client=client, planner=DeterministicPlanner(pilot_api_base=base))


# ---------------- release metadata ----------------

def test_release_metadata():
    assert PILOT_VERSION == "0.1.0-pilot"
    assert PILOT_RELEASE_NAME == "MCC-Core Pilot v0.1"


# ---------------- clean vs fail-closed startup ----------------

def test_clean_startup_runs_a_goal():
    _, agent = _agent()
    r = agent.run("Create a CRM lead for Alice with a campaign budget of 500 EUR")
    assert r.execution_status == "EXECUTED"


def test_fail_closed_startup_when_required_config_missing():
    # A Redis backend is selected but MCC_REDIS_URL is absent -> refuse to start
    # (no silent in-memory fallback).
    with pytest.raises(Exception) as exc:
        EmbeddedGovernanceClient(pilot_api_base=f"http://127.0.0.1:{PORT}",
                                 env={"MCC_NONCE_BACKEND": "redis"})
    assert "MCC_REDIS_URL" in str(exc.value)


# ---------------- four verdicts with re-evaluation ----------------

@pytest.mark.parametrize("goal,verdict,executes", [
    ("Create a CRM lead for Alice with a campaign budget of 500 EUR", "ALLOW", True),
    ("Send customer data to a prohibited destination", "DENY", False),
    ("Increase campaign budget to 5000 EUR", "ESCALATE", True),   # auto-approved
    ("Set campaign budget to 10000 EUR", "CONSTRAIN", True),
])
def test_four_verdicts(goal, verdict, executes):
    _, agent = _agent()
    r = agent.run(goal)
    assert r.decision == verdict
    assert (r.execution_status == "EXECUTED") == executes
    assert (len(recorded_operations()) == 1) == executes


# ---------------- audit evidence completeness ----------------

@pytest.mark.parametrize("goal", [
    "Create a CRM lead for Alice with a campaign budget of 500 EUR",
    "Send customer data to a prohibited destination",
    "Set campaign budget to 10000 EUR",
])
def test_audit_evidence_is_complete(goal):
    _, agent = _agent()
    r = agent.run(goal)
    ev = r.audit_evidence
    assert _EVIDENCE_FIELDS <= set(ev), f"missing: {_EVIDENCE_FIELDS - set(ev)}"
    assert ev["policy_hash"] and ev["action_hash"] and ev["payload_hash"]
    assert ev["verdict"] == r.decision


def test_constrain_evidence_binds_to_clamped_payload():
    from mcc_core import hash_payload
    from egress_proxy.canonical_action import build_canonical_action
    _, agent = _agent()
    r = agent.run("Set campaign budget to 10000 EUR")
    # The evidence payload hash is the CLAMPED body, not the original 10000.
    clamped = build_canonical_action(method="POST", url=r.proposal["url"], headers={},
                                     body={"amount": 5000, "currency": "EUR"})
    assert r.audit_evidence["payload_hash"] == hash_payload(clamped)
    assert r.audit_evidence["constraints"]


# ---------------- audit-before-execution + chain verification ----------------

def test_audit_ref_present_before_external_effect():
    _, agent = _agent()
    r = agent.run("Create a CRM lead for Alice with a campaign budget of 500 EUR")
    # An audit reference exists for the executed action (audit-before-actuation).
    assert r.audit_id and r.audit_evidence["audit_ref"]
    assert len(recorded_operations()) == 1


def test_audit_failure_blocks_execution_no_external_effect():
    client, agent = _agent()

    def boom(*a, **k):
        raise OSError("audit down")

    client._mcc.audit.append = boom
    r = agent.run("Create a CRM lead for Z with a campaign budget of 1 EUR")
    assert r.execution_status == "BLOCKED" and recorded_operations() == []


def test_audit_chain_verifies_after_demo():
    client, agent = _agent()
    agent.run("Create a CRM lead for Alice with a campaign budget of 500 EUR")
    agent.run("Increase campaign budget to 5000 EUR")
    agent.run("Set campaign budget to 10000 EUR")
    assert client.verify_audit_chain() is True


# ---------------- no external execution before authorization ----------------

def test_no_external_execution_before_authorization():
    _, agent = _agent()
    # DENY and ESCALATE-pending must not touch the external API.
    agent.run("Send customer data to a prohibited destination")
    agent.run("Increase campaign budget to 5000 EUR", auto_approve=False)
    assert recorded_operations() == []


# ---------------- Redis replay protection (gated on a real Redis) ----------------

@pytest.mark.skipif(not os.environ.get("MCC_REDIS_URL"),
                    reason="requires a real Redis (MCC_REDIS_URL)")
def test_redis_replay_protection_active():
    base = f"http://127.0.0.1:{PORT}"
    url = os.environ["MCC_REDIS_URL"]
    env = {"MCC_NONCE_BACKEND": "redis", "MCC_IDEMPOTENCY_BACKEND": "redis",
           "MCC_VELOCITY_BACKEND": "redis", "MCC_APPROVAL_BACKEND": "redis",
           "MCC_REDIS_URL": url}
    import uuid
    client = EmbeddedGovernanceClient(pilot_api_base=base, env=env)
    agent = GovernedAgent(client=client, planner=DeterministicPlanner(pilot_api_base=base))
    key = f"rel-{uuid.uuid4().hex}"  # unique per run (Redis state persists across runs)
    first = agent.run("Create a CRM lead for Redis with a campaign budget of 1 EUR",
                      idempotency_key=key)
    second = agent.run("Create a CRM lead for Redis with a campaign budget of 1 EUR",
                       idempotency_key=key)
    assert first.execution_status == "EXECUTED"
    assert second.execution_status == "BLOCKED"
    assert len(recorded_operations()) == 1
