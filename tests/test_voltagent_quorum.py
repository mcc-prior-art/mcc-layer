"""Integration tests for the VoltAgent MCC-side evaluator quorum + contract.

These prove, against the REAL gateway + receipt-verifying governed executor, the
exact HTTP contract the VoltAgent TypeScript client speaks:

* the independent evaluator quorum only signs votes for an EXECUTABLE decision,
  over the gateway's OWN authoritative payload, bound to the challenge nonce;
* a valid consensus execution yields a genuine EXECUTED with a verified receipt;
* DENY/ESCALATE get no votes (the quorum refuses);
* CONSTRAIN executes only the clamped payload;
* a forged/mismatched receipt never yields EXECUTED (fail-closed executor);
* replaying the same authorization does not execute twice.

The quorum holds the evaluator private keys; nothing here re-implements governance.
"""

from __future__ import annotations

import sys
from pathlib import Path

import itertools

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

from examples._demo_server import DemoServer  # noqa: E402
from pilot.client import MCCGatewayClient  # noqa: E402
from pilot_notify import recorded_receipts, reset_receipts  # noqa: E402

from integrations.voltagent.mcc_side.evaluator_quorum import (  # noqa: E402
    QuorumSettings,
    build_quorum_app,
)
from tests._notify_harness import (  # noqa: E402
    API_KEY,
    OPERATOR_KEY,
    TENANT_ID,
    NotifyPilotHarness,
    _free_port,
    agent_key,
)

_idem_counter = itertools.count(1)


class QuorumStack:
    """A real gateway + governed executor + independent evaluator quorum."""

    def __init__(self, *, upstream=None):
        self.harness = NotifyPilotHarness(upstream=upstream)
        # F1: the quorum authenticates the requesting agent (same hash-only
        # registry as the gateway) and votes only for that agent.
        settings = QuorumSettings(
            {"MCC_QUORUM_GATEWAY_URL": self.harness.base_url, "MCC_GATEWAY_API_KEY": API_KEY,
             "MCC_GATEWAY_TENANT_ID": TENANT_ID,
             "MCC_AGENT_CREDENTIALS_CONFIG": self.harness.agent_registry_path}
        )
        self.q_app = build_quorum_app(self.harness.evaluators, settings)
        self.q_port = _free_port()
        self.q_server = DemoServer(self.q_app, self.q_port)
        self.q_server.start()
        self.quorum_url = f"http://127.0.0.1:{self.q_port}"
        # Read-only routes (/verify) only; every governed call uses the actor's key.
        self.client = MCCGatewayClient(self.harness.base_url, api_key=API_KEY, operator_key=OPERATOR_KEY)

    def agent(self, actor):
        """F1: the client of ``actor`` -- presenting its OWN credential."""
        return MCCGatewayClient(self.harness.base_url, api_key=agent_key(actor),
                                operator_key=OPERATOR_KEY)

    def vote(self, *, actor, action, resource, context, nonce):
        r = httpx.post(f"{self.quorum_url}/vote", headers={"x-api-key": agent_key(actor)},
                       json={"actor": actor, "action": action, "resource": resource,
                             "context": context, "nonce": nonce}, timeout=10)
        r.raise_for_status()
        return r.json()

    def govern(self, *, actor, action, resource, context, idempotency_key=None):
        """propose -> challenge -> quorum votes -> governed consensus execute."""
        # Round 25: mandatory logical-operation identity -- auto-generated
        # here in the TEST HARNESS (never inside the gateway/coordinator)
        # for scenarios that aren't specifically about idempotency.
        if idempotency_key is None:
            idempotency_key = f"auto-idem-{next(_idem_counter)}"
        client = self.agent(actor)
        d = client.propose(identity=actor, action=action, resource_id=resource,
                           actor_id=actor, context=context)
        ch = client.issue_challenge(actor=actor, action=action, resource=resource,
                                    context=d.forward_context)
        qv = self.vote(actor=actor, action=action, resource=resource, context=context,
                       nonce=ch["nonce"])
        out = client.execute_with_consensus(
            votes=qv["votes"], actor=actor, action=action, resource=resource,
            context=qv["authorized_context"], nonce=ch["nonce"], challenge_id=ch["challenge_id"],
            idempotency_key=idempotency_key)
        return d, qv, out

    def close(self):
        self.q_server.stop()
        self.harness.close()


@pytest.fixture()
def stack():
    reset_receipts()
    s = QuorumStack()
    try:
        yield s
    finally:
        s.close()


def _ctx(corr, *, priority=2, channel="email", recipient="customer-123", message="hi"):
    return {"recipient": recipient, "message": message, "priority": priority,
            "channel": channel, "correlation_id": corr}


# A — ALLOW -> genuine EXECUTED with a verified receipt.
def test_allow_consensus_executed(stack):
    d, qv, out = stack.govern(actor="agent/notify-bot", action="send_notification",
                              resource="crm", context=_ctx("corr-allow"))
    assert d.decision.value == "ALLOW"
    assert len(qv["votes"]) == 3
    assert out.executed and out.status == "EXECUTED"
    receipts = recorded_receipts()
    assert len(receipts) == 1
    assert receipts[0]["receipt"]["correlation_id"] == "corr-allow"
    assert stack.client.verify_chain()["valid"] is True


# B — DENY -> the quorum refuses to vote; nothing executes.
def test_deny_quorum_refuses(stack):
    d = stack.agent("agent/notify-bot").propose(identity="agent/notify-bot", action="send_notification",
                             resource_id="crm", actor_id="agent/notify-bot",
                             context=_ctx("corr-deny", channel="pager"))
    assert d.decision.value == "DENY"
    qv = stack.vote(actor="agent/notify-bot", action="send_notification", resource="crm",
                    context=_ctx("corr-deny", channel="pager"), nonce="nonce-x")
    assert qv["votes"] == []
    assert qv["verdict"] == "DENY"
    assert recorded_receipts() == []


# C — ESCALATE -> the quorum refuses to vote (not executable without approval).
def test_escalate_quorum_refuses(stack):
    qv = stack.vote(actor="agent/unknown", action="send_notification", resource="crm",
                    context=_ctx("corr-esc"), nonce="nonce-y")
    assert qv["votes"] == []
    assert qv["verdict"] == "ESCALATE"


# D — CONSTRAIN -> only the clamped payload is executed.
def test_constrain_executes_clamped_only(stack):
    d, qv, out = stack.govern(actor="agent/notify-bot", action="send_notification",
                              resource="crm", context=_ctx("corr-con", priority=9))
    assert d.decision.value == "CONSTRAIN"
    assert qv["authorized_context"]["priority"] == 3
    assert out.executed
    receipts = recorded_receipts()
    assert len(receipts) == 1
    assert receipts[0]["payload"]["priority"] == 3
    assert all(r["payload"]["priority"] != 9 for r in recorded_receipts())


# E — a forged/mismatched external receipt never yields EXECUTED (fail-closed).
def test_forged_receipt_not_executed():
    reset_receipts()

    async def lying_upstream(action, payload):
        # Never confirm a matching receipt -> the executor must record non-EXECUTED.
        from pilot_notify import UpstreamReceiptError
        raise UpstreamReceiptError("forged/absent receipt")

    s = QuorumStack(upstream=lying_upstream)
    try:
        _d, qv, out = s.govern(actor="agent/notify-bot", action="send_notification",
                               resource="crm", context=_ctx("corr-forged"))
        assert len(qv["votes"]) == 3          # governance authorized
        assert not out.executed               # but no verified receipt -> not EXECUTED
        assert recorded_receipts() == []
    finally:
        s.close()


# F — replay: reusing the same authorization does not execute twice.
def test_replay_not_executed_twice(stack):
    actor, action, resource = "agent/notify-bot", "send_notification", "crm"
    ctx = _ctx("corr-replay")
    d = stack.agent(actor).propose(identity=actor, action=action, resource_id=resource,
                             actor_id=actor, context=ctx)
    ch = stack.agent(actor).issue_challenge(actor=actor, action=action, resource=resource,
                                      context=d.forward_context)
    qv = stack.vote(actor=actor, action=action, resource=resource, context=ctx, nonce=ch["nonce"])
    first = stack.agent(actor).execute_with_consensus(
        votes=qv["votes"], actor=actor, action=action, resource=resource,
        context=qv["authorized_context"], nonce=ch["nonce"], challenge_id=ch["challenge_id"],
        idempotency_key="op-replay-test")
    second = stack.agent(actor).execute_with_consensus(
        votes=qv["votes"], actor=actor, action=action, resource=resource,
        context=qv["authorized_context"], nonce=ch["nonce"], challenge_id=ch["challenge_id"],
        idempotency_key="op-replay-test")
    assert first.executed and not second.executed
    assert len(recorded_receipts()) == 1


# G — a tampered execute payload (different from the votes) is rejected.
def test_tampered_execute_payload_rejected(stack):
    actor, action, resource = "agent/notify-bot", "send_notification", "crm"
    ctx = _ctx("corr-tamper")
    d = stack.agent(actor).propose(identity=actor, action=action, resource_id=resource,
                             actor_id=actor, context=ctx)
    ch = stack.agent(actor).issue_challenge(actor=actor, action=action, resource=resource,
                                      context=d.forward_context)
    qv = stack.vote(actor=actor, action=action, resource=resource, context=ctx, nonce=ch["nonce"])
    tampered = dict(qv["authorized_context"], message="ALTERED-AFTER-VOTES")
    out = stack.agent(actor).execute_with_consensus(
        votes=qv["votes"], actor=actor, action=action, resource=resource,
        context=tampered, nonce=ch["nonce"], challenge_id=ch["challenge_id"],
        idempotency_key="op-tamper-test")
    assert not out.executed
    assert recorded_receipts() == []
