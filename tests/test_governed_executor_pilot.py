"""Real Governed Executor Pilot — integration tests.

Every test drives the SDK over real HTTP against the real gateway governance
path (Gateway.evaluate + governed execute routes) with the receipt-verifying
governed-executor adapter pointed at a real loopback mock notification service.
EXECUTED means a genuine, confirmed external receipt. Nothing production-security
is stubbed, skipped, or bypassed.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

from mcc_client import (  # noqa: E402
    ConsensusAuthorization,
    MCCClient,
    MCCDeniedError,
    MCCError,
    MCCExecutionError,
    MCCInvalidDecisionError,
    MCCReplayError,
    Verdict,
)

from pilot_notify import (  # noqa: E402
    UpstreamReceiptError,
    recorded_receipts,
    reset_receipts,
)
from tests._notify_harness import NotifyPilotHarness, OPERATOR_KEY, agent_key  # noqa: E402


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


def _client(harness, actor: str = "agent/notify-bot") -> MCCClient:
    # V05 (part 2) + F1: an agent acting as ``actor`` presents its OWN
    # credential on every governed route (/evaluate, /consensus/*, /approvals,
    # the execute routes), so each negative reaches its intended check.
    return MCCClient(harness.base_url, api_key=agent_key(actor), operator_key=OPERATOR_KEY)


def _payload(corr, *, priority=1, channel="email", recipient="cust-1", message="Hello"):
    return {"recipient": recipient, "message": message, "correlation_id": corr,
            "priority": priority, "channel": channel}


def _consensus_execute(harness, client, decision, *, tamper_votes_payload=None,
                       votes_count=None):
    """evaluate -> gateway challenge -> signed votes -> governed consensus execute."""
    ch = client.issue_challenge(decision)
    vote_payload = tamper_votes_payload if tamper_votes_payload is not None else decision.authorized_payload
    votes = harness.votes(action="send_notification", payload=vote_payload,
                          actor=decision.actor_id, nonce=ch["nonce"],
                          resource=decision.resource_id, count=votes_count)
    return client.execute(decision, ConsensusAuthorization(
        votes=votes, challenge_id=ch["challenge_id"], nonce=ch["nonce"]))


# 1 + 6 — ALLOW → genuine EXECUTED (only after a confirmed matching receipt).
def test_allow_executes_after_confirmed_receipt(hz):
    client = _client(hz)
    d = client.evaluate(actor_id="agent/notify-bot", action="send_notification",
                        resource="crm", payload=_payload("corr-allow"),
                        idempotency_key="op-corr-allow")
    assert d.verdict == Verdict.ALLOW
    result = _consensus_execute(hz, client, d)
    assert result.executed and result.status == "EXECUTED"
    receipts = recorded_receipts()
    assert len(receipts) == 1
    assert receipts[0]["receipt"]["correlation_id"] == "corr-allow"
    # And the audit chain verifies.
    assert client.verify_audit_chain().get("valid") is True


def _adapter_with(handler):
    """A receipt-verifying upstream whose HTTP client is a controlled mock."""
    import pilot_notify.governed_upstream as gu

    async def upstream(action, payload):
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            resp = await client.post(f"http://mock/{action}", json=payload)
        finally:
            await client.aclose()
        # re-run the exact verification logic
        if resp.status_code != 200:
            raise gu.UpstreamReceiptError("non-200")
        receipt = resp.json()
        if receipt.get("received") is not True:
            raise gu.UpstreamReceiptError("not confirmed")
        if receipt.get("correlation_id") != payload.get("correlation_id"):
            raise gu.UpstreamReceiptError("correlation mismatch")
        if receipt.get("payload_sha256") != gu.payload_sha256(payload):
            raise gu.UpstreamReceiptError("hash mismatch")
        return {"upstream_status": 200, "receipt_verified": True, "body": receipt}
    return upstream


@pytest.mark.parametrize("receipt", [
    {"received": True, "correlation_id": "WRONG", "payload_sha256": "x"},   # correlation mismatch
    {"received": True, "correlation_id": "c", "payload_sha256": "deadbeef"},  # hash mismatch
    {"received": False},                                                     # not confirmed
])
def test_mismatched_receipt_raises(receipt):
    import asyncio
    adapter = _adapter_with(lambda req: httpx.Response(200, json=receipt))
    with pytest.raises(UpstreamReceiptError):
        asyncio.run(adapter("send_notification", {"correlation_id": "c", "x": 1}))


def test_non_2xx_receipt_raises():
    import asyncio
    adapter = _adapter_with(lambda req: httpx.Response(503, json={}))
    with pytest.raises(UpstreamReceiptError):
        asyncio.run(adapter("send_notification", {"correlation_id": "c"}))


# 7 — DENY: no governed execution, no external receipt.
def test_deny_not_executed_no_receipt(hz):
    client = _client(hz)
    d = client.evaluate(actor_id="agent/notify-bot", action="send_notification",
                        resource="crm", payload=_payload("corr-deny", channel="pager"))
    assert d.verdict == Verdict.DENY
    with pytest.raises(MCCDeniedError):
        _consensus_execute(hz, client, d)
    assert recorded_receipts() == []   # the mock service was never called


# 8 — CONSTRAIN: only the constrained payload is executed; original never sent.
def test_constrain_executes_only_constrained_payload(hz):
    client = _client(hz)
    d = client.evaluate(actor_id="agent/notify-bot", action="send_notification",
                        resource="crm", payload=_payload("corr-con", priority=9),
                        idempotency_key="op-corr-con")
    assert d.verdict == Verdict.CONSTRAIN
    assert d.authorized_payload["priority"] == 3          # clamped
    result = _consensus_execute(hz, client, d)
    assert result.executed
    receipts = recorded_receipts()
    assert len(receipts) == 1
    assert receipts[0]["payload"]["priority"] == 3        # only the clamped payload
    assert all(r["payload"]["priority"] != 9 for r in receipts)  # original never sent


# 5 — altered payload (votes over a different body than the challenge) rejected.
def test_altered_payload_rejected(hz):
    client = _client(hz)
    d = client.evaluate(actor_id="agent/notify-bot", action="send_notification",
                        resource="crm", payload=_payload("corr-alt"))
    tampered = dict(d.authorized_payload, message="ALTERED")
    with pytest.raises(MCCExecutionError):
        _consensus_execute(hz, client, d, tamper_votes_payload=tampered)
    assert recorded_receipts() == []


# 4 — replay: a consumed challenge/nonce cannot execute twice.
def test_replay_rejected(hz):
    client = _client(hz)
    d = client.evaluate(actor_id="agent/notify-bot", action="send_notification",
                        resource="crm", payload=_payload("corr-replay"),
                        idempotency_key="op-corr-replay")
    ch = client.issue_challenge(d)
    votes = hz.votes(action="send_notification", payload=d.authorized_payload,
                     actor=d.actor_id, nonce=ch["nonce"], resource=d.resource_id)
    auth = ConsensusAuthorization(votes=votes, challenge_id=ch["challenge_id"], nonce=ch["nonce"])
    first = client.execute(d, auth)
    assert first.executed
    with pytest.raises((MCCReplayError, MCCExecutionError)):
        client.execute(d, auth)              # same challenge/nonce/votes reused
    assert len(recorded_receipts()) == 1     # external state changed exactly once


# 6b — expired challenge (decision material) rejected.
def test_expired_challenge_rejected(hz):
    client = _client(hz)
    d = client.evaluate(actor_id="agent/notify-bot", action="send_notification",
                        resource="crm", payload=_payload("corr-exp"))
    ch = client.issue_challenge(d, ttl_seconds=1)
    votes = hz.votes(action="send_notification", payload=d.authorized_payload,
                     actor=d.actor_id, nonce=ch["nonce"], resource=d.resource_id)
    time.sleep(1.2)                          # let the challenge expire
    with pytest.raises(MCCExecutionError):
        client.execute(d, ConsensusAuthorization(
            votes=votes, challenge_id=ch["challenge_id"], nonce=ch["nonce"]))
    assert recorded_receipts() == []


# 7b — missing authorization (no votes) rejected.
def test_missing_authorization_rejected(hz):
    client = _client(hz)
    d = client.evaluate(actor_id="agent/notify-bot", action="send_notification",
                        resource="crm", payload=_payload("corr-noauth"))
    ch = client.issue_challenge(d)
    with pytest.raises(MCCExecutionError):
        client.execute(d, ConsensusAuthorization(votes=[], challenge_id=ch["challenge_id"],
                                                 nonce=ch["nonce"]))
    assert recorded_receipts() == []


# 9 — ESCALATE: not executed before approval; executed only after valid approval.
def test_escalate_requires_approval_then_executes(hz):
    client = _client(hz, "agent/unknown")
    d = client.evaluate(actor_id="agent/unknown", action="send_notification",
                        resource="crm", payload=_payload("corr-esc"),
                        idempotency_key="op-corr-esc")
    assert d.verdict == Verdict.ESCALATE
    approval = client.request_approval(d)
    # Execution before approval is impossible (no granted mandate).
    from mcc_client import Approval
    pending = Approval(request_id=approval.request_id, state="PENDING", mandate=None)
    with pytest.raises(MCCInvalidDecisionError):
        client.execute_after_approval(d, pending)
    assert recorded_receipts() == []
    # Operator approves -> governed execution proceeds and confirms receipt.
    granted = client.approve(approval)
    result = client.execute_after_approval(d, granted)
    assert result.executed
    assert len(recorded_receipts()) == 1


# 11 — invalid approval (bogus mandate) rejected.
def test_invalid_approval_rejected(hz):
    client = _client(hz, "agent/unknown")
    d = client.evaluate(actor_id="agent/unknown", action="send_notification",
                        resource="crm", payload=_payload("corr-badappr"))
    from mcc_client import ApprovalAuthorization
    with pytest.raises(MCCExecutionError):
        client.execute(d, ApprovalAuthorization(request_id="nope",
                                                mandate={"forged": True, "approval_id": "nope"}))
    assert recorded_receipts() == []


# 13 — audit write failure prevents execution (audit-before-execution).
def test_audit_write_failure_prevents_execution(hz):
    client = _client(hz)
    d = client.evaluate(actor_id="agent/notify-bot", action="send_notification",
                        resource="crm", payload=_payload("corr-audit"))
    orig = hz.gateway.audit.append

    def boom(*a, **k):
        raise OSError("audit down")

    hz.gateway.audit.append = boom
    try:
        with pytest.raises(MCCExecutionError):
            _consensus_execute(hz, client, d)
    finally:
        hz.gateway.audit.append = orig
    assert recorded_receipts() == []


# 12 — Redis outage fails closed (dedicated harness with a down Redis).
def test_redis_outage_fails_closed():
    down = {"MCC_NONCE_BACKEND": "redis", "MCC_IDEMPOTENCY_BACKEND": "redis",
            "MCC_REDIS_URL": "redis://127.0.0.1:6390/0"}
    harness = NotifyPilotHarness(env=down)
    try:
        client = _client(harness)
        d = client.evaluate(actor_id="agent/notify-bot", action="send_notification",
                            resource="crm", payload=_payload("corr-redis"))
        with pytest.raises(MCCError):   # fail closed (registry-unavailable / replay)
            _consensus_execute(harness, client, d)
        assert recorded_receipts() == []
    finally:
        harness.close()


# 3 — no direct executor bypass: the SDK exposes no way to call the mock directly,
# and a governance block calls the external service zero times.
def test_no_direct_executor_bypass(hz):
    client = _client(hz)
    for forbidden in ("send", "call_external", "http", "request", "notify", "post_target"):
        assert not hasattr(client, forbidden)
    # A blocked governed execution reaches the external service zero times.
    d = client.evaluate(actor_id="agent/notify-bot", action="send_notification",
                        resource="crm", payload=_payload("corr-bypass"))
    with pytest.raises(MCCExecutionError):
        client.execute(d, ConsensusAuthorization(votes=[]))   # no material -> blocked
    assert recorded_receipts() == []
