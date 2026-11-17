"""Tests for the MCC-Core Python client SDK (mcc_client).

Two layers, both against the REAL contract:

* integration — drives the SDK over real HTTP against the real gateway app
  (``gateway.app``) on loopback, for the four verdicts + audit verification;
* controlled-transport units — inject an ``httpx.MockTransport`` that returns the
  gateway's real response schemas (and real transport failures) to exercise the
  SDK's fail-closed and binding invariants deterministically.

No fake governance protocol is invented: the mock returns the exact schema
shapes discovered in gateway/app.py + gateway/governance_api.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

from mcc_client import (  # noqa: E402
    ApprovalAuthorization,
    ConsensusAuthorization,
    Decision,
    MCCAmbiguousExecutionError,
    MCCApprovalRequiredError,
    MCCClient,
    MCCDeniedError,
    MCCExecutionError,
    MCCProtocolError,
    MCCReplayError,
    MCCTimeoutError,
    MCCTransportError,
    MandateAuthorization,
    Transport,
    Verdict,
)
from mcc_client.transport import CORRELATION_HEADER  # noqa: E402

from examples._demo_server import DemoServer  # noqa: E402
from tests._agent_credentials import module_key  # noqa: E402


# --------------------------------------------------------------------------
# Controlled-transport helpers
# --------------------------------------------------------------------------

def _mock_client(handler, **kw) -> MCCClient:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return MCCClient("http://gw", api_key="agent-key", operator_key="op-key",
                     transport=Transport("http://gw", api_key="agent-key",
                                         operator_key="op-key", client=client, **kw))


def _decision_body(verdict, *, actor="agent-01", action="send_message",
                   forward=None, applied=None, constraints=None):
    return {
        "decision": verdict, "reason": f"{verdict} reason", "audit_id": "aud-1",
        "actor_id": actor, "action": action, "resource_id": "crm",
        "forward_context": forward if forward is not None else {"customer_id": "123"},
        "applied_constraints": applied or [], "constraints": constraints or {},
        "decision_token": {"sig": "x"} if verdict in ("ALLOW", "CONSTRAIN") else None,
        "trace_id": "trace-xyz", "policy_ref": "pilot/v1",
        "transaction_id": "txn-1", "idempotency_key": "req-001",
    }


def _evaluate(client, **over):
    kw = dict(actor_id="agent-01", action="send_message", resource="crm",
              payload={"customer_id": "123", "message": "Hello"}, idempotency_key="req-001")
    kw.update(over)
    return client.evaluate(**kw)


# --------------------------------------------------------------------------
# Integration — real gateway over loopback HTTP
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def gateway_url():
    import gateway.app as gw
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    server = DemoServer(gw.app, port)
    server.start()
    try:
        yield f"http://127.0.0.1:{port}", gw.settings.api_key
    finally:
        server.stop()


@pytest.mark.parametrize("identity,action,payload,expected", [
    ("agent/payments-bot", "send_payment", {"amount": 1000}, Verdict.ALLOW),
    ("agent/payments-bot", "send_payment", {"amount": 99000}, Verdict.CONSTRAIN),
    ("agent/nobody", "send_payment", {"amount": 100}, Verdict.ESCALATE),
    ("agent/ops-bot", "delete_database", {}, Verdict.DENY),
])
def test_integration_four_verdicts(gateway_url, identity, action, payload, expected):
    url, _shared_key = gateway_url
    # F1b: the shared tenant key obtains no decision in strict mode; each
    # identity evaluates with its own registered credential.
    with MCCClient(url, api_key=module_key(identity)) as client:
        d = client.evaluate(actor_id=identity, action=action, payload=payload)
        assert d.verdict == expected
        assert d.audit_id  # a real audit id from the running gateway
        if expected == Verdict.CONSTRAIN:
            assert d.applied_constraints  # the server clamped it
            assert d.authorized_payload   # the authoritative (clamped) body


def test_integration_audit_chain_verifies(gateway_url):
    url, _shared_key = gateway_url
    with MCCClient(url, api_key=module_key("agent/payments-bot")) as client:
        client.evaluate(actor_id="agent/payments-bot", action="send_payment", payload={"amount": 10})
        chain = client.verify_audit_chain()
        assert chain.get("valid") is True


# --------------------------------------------------------------------------
# Evaluate — verdict parsing (units)
# --------------------------------------------------------------------------

@pytest.mark.parametrize("verdict", ["ALLOW", "DENY", "ESCALATE", "CONSTRAIN"])
def test_evaluate_returns_typed_verdict(verdict):
    client = _mock_client(lambda req: httpx.Response(200, json=_decision_body(verdict)))
    d = _evaluate(client)
    assert d.verdict == Verdict(verdict)
    assert d.reason and d.audit_id == "aud-1"


def test_constrained_payload_is_preserved():
    body = _decision_body("CONSTRAIN", forward={"amount": 5000}, applied=["amount 10000->5000"])
    client = _mock_client(lambda req: httpx.Response(200, json=body))
    d = _evaluate(client, payload={"amount": 10000})
    assert d.authorized_payload == {"amount": 5000}
    assert d.applied_constraints == ["amount 10000->5000"]


# --------------------------------------------------------------------------
# Fail-closed evaluate
# --------------------------------------------------------------------------

def test_malformed_response_fails_closed():
    client = _mock_client(lambda req: httpx.Response(200, content=b"not json"))
    with pytest.raises(MCCProtocolError):
        _evaluate(client)


def test_unknown_verdict_fails_closed():
    client = _mock_client(lambda req: httpx.Response(200, json=_decision_body("MAYBE")))
    with pytest.raises(MCCProtocolError):
        _evaluate(client)


def test_missing_decision_material_fails_closed():
    client = _mock_client(lambda req: httpx.Response(200, json={"reason": "x"}))
    with pytest.raises(MCCProtocolError):
        _evaluate(client)


def test_timeout_fails_closed():
    def boom(req):
        raise httpx.TimeoutException("timed out")
    client = _mock_client(boom, max_safe_retries=0)
    with pytest.raises(MCCTimeoutError):
        _evaluate(client)


def test_transport_error_fails_closed():
    def boom(req):
        raise httpx.ConnectError("refused")
    client = _mock_client(boom, max_safe_retries=0)
    with pytest.raises(MCCTransportError):
        _evaluate(client)


def test_actor_mismatch_fails_closed():
    body = _decision_body("ALLOW", actor="someone-else")
    client = _mock_client(lambda req: httpx.Response(200, json=body))
    with pytest.raises(MCCProtocolError):
        _evaluate(client)  # requested actor-01, server echoed a different actor


def test_action_mismatch_fails_closed():
    body = _decision_body("ALLOW", action="other_action")
    client = _mock_client(lambda req: httpx.Response(200, json=body))
    with pytest.raises(MCCProtocolError):
        _evaluate(client)


# --------------------------------------------------------------------------
# Execution guards — DENY / ESCALATE never execute
# --------------------------------------------------------------------------

def test_deny_never_reaches_execution():
    calls = []
    def handler(req):
        calls.append(req.url.path)
        return httpx.Response(200, json=_decision_body("DENY"))
    client = _mock_client(handler)
    d = _evaluate(client)
    with pytest.raises(MCCDeniedError):
        client.execute(d, MandateAuthorization(mandate={"m": 1}))
    assert calls == ["/evaluate"]  # execution endpoint was never called


def test_escalate_never_executes_without_approval():
    calls = []
    def handler(req):
        calls.append(req.url.path)
        return httpx.Response(200, json=_decision_body("ESCALATE"))
    client = _mock_client(handler)
    d = _evaluate(client)
    with pytest.raises(MCCApprovalRequiredError):
        client.execute(d, MandateAuthorization(mandate={"m": 1}))
    assert calls == ["/evaluate"]


def test_no_direct_execute_surface():
    # There is no method that performs an external call without a decision.
    for forbidden in ("send", "call", "call_external", "http", "request", "post_target"):
        assert not hasattr(MCCClient, forbidden)
    import inspect
    params = list(inspect.signature(MCCClient.execute).parameters)
    assert params[:3] == ["self", "decision", "authorization"]  # a Decision is required


# --------------------------------------------------------------------------
# Execution — governed routing, authoritative payload, binding
# --------------------------------------------------------------------------

def _exec_client(exec_status="EXECUTED", exec_reason="ok", capture=None):
    def handler(req):
        path = req.url.path
        if path == "/evaluate":
            v = json.loads(req.content)["action"]  # not used; verdict set by caller below
        if capture is not None and path != "/evaluate":
            capture.append({"path": path, "body": json.loads(req.content),
                            "corr": req.headers.get(CORRELATION_HEADER)})
        if path.endswith("/execute"):
            return httpx.Response(200, json={"status": exec_status, "reason": exec_reason,
                                             "decision": "ALLOW", "audit_ref": "aud-2"})
        return httpx.Response(200, json=_decision_body("ALLOW"))
    return handler


def test_constrain_executes_only_constrained_payload():
    captured = []
    body = _decision_body("CONSTRAIN", forward={"amount": 5000}, applied=["amount 10000->5000"])
    def handler(req):
        if req.url.path == "/evaluate":
            return httpx.Response(200, json=body)
        captured.append(json.loads(req.content))
        return httpx.Response(200, json={"status": "EXECUTED", "reason": "ok", "audit_ref": "a"})
    client = _mock_client(handler)
    d = _evaluate(client, payload={"amount": 10000})
    res = client.execute(d, MandateAuthorization(mandate={"m": 1}))
    assert res.executed
    # Only the server-authorized clamped body is sent — never the original 10000.
    assert captured[0]["context"] == {"amount": 5000}
    assert captured[0]["actor"] == "agent-01" and captured[0]["action"] == "send_message"
    assert captured[0]["resource"] == "crm"


def test_idempotency_and_correlation_propagated():
    captured = []
    def handler(req):
        if req.url.path == "/evaluate":
            b = json.loads(req.content)
            captured.append(("evaluate", b, req.headers.get(CORRELATION_HEADER)))
            return httpx.Response(200, json=_decision_body("ALLOW"))
        captured.append(("execute", json.loads(req.content), req.headers.get(CORRELATION_HEADER)))
        return httpx.Response(200, json={"status": "EXECUTED", "reason": "ok"})
    client = _mock_client(handler)
    d = _evaluate(client, idempotency_key="req-001", correlation_id="corr-fixed")
    client.execute(d, MandateAuthorization(mandate={"m": 1}))
    ev = [c for c in captured if c[0] == "evaluate"][0]
    ex = [c for c in captured if c[0] == "execute"][0]
    assert ev[1]["idempotency_key"] == "req-001"   # idempotency propagated to evaluate
    assert ev[2] == "corr-fixed"                    # correlation header propagated
    assert ex[1]["idempotency_key"] == "req-001"   # and to execution (echoed from the decision)


def test_execution_not_retried_on_timeout_and_is_ambiguous():
    attempts = {"n": 0}
    def handler(req):
        if req.url.path == "/evaluate":
            return httpx.Response(200, json=_decision_body("ALLOW"))
        attempts["n"] += 1
        raise httpx.TimeoutException("exec timed out")
    client = _mock_client(handler, max_safe_retries=3)
    d = _evaluate(client)
    with pytest.raises(MCCAmbiguousExecutionError):
        client.execute(d, MandateAuthorization(mandate={"m": 1}))
    assert attempts["n"] == 1  # execution POST attempted exactly once (no unsafe retry)


def test_ambiguous_when_execution_status_missing():
    def handler(req):
        if req.url.path == "/evaluate":
            return httpx.Response(200, json=_decision_body("ALLOW"))
        return httpx.Response(200, json={"reason": "who knows"})  # no status
    client = _mock_client(handler)
    d = _evaluate(client)
    with pytest.raises(MCCAmbiguousExecutionError):
        client.execute(d, MandateAuthorization(mandate={"m": 1}))


def test_blocked_execution_raises_execution_error():
    def handler(req):
        if req.url.path == "/evaluate":
            return httpx.Response(200, json=_decision_body("ALLOW"))
        return httpx.Response(200, json={"status": "BLOCKED", "reason": "velocity exceeded"})
    client = _mock_client(handler)
    d = _evaluate(client)
    with pytest.raises(MCCExecutionError):
        client.execute(d, MandateAuthorization(mandate={"m": 1}))


def test_replayed_decision_rejected():
    def handler(req):
        if req.url.path == "/evaluate":
            return httpx.Response(200, json=_decision_body("ALLOW"))
        return httpx.Response(200, json={"status": "BLOCKED", "reason": "nonce already consumed (replay)"})
    client = _mock_client(handler)
    d = _evaluate(client)
    with pytest.raises(MCCReplayError):
        client.execute(d, MandateAuthorization(mandate={"m": 1}))


def test_full_escalate_approve_execute_routing():
    seen = []
    def handler(req):
        p = req.url.path
        seen.append(p)
        if p == "/evaluate":
            return httpx.Response(200, json=_decision_body("ESCALATE"))
        if p == "/approvals":
            return httpx.Response(200, json={"request_id": "rq-1", "state": "PENDING"})
        if p == "/approvals/rq-1/approve":
            return httpx.Response(200, json={"request_id": "rq-1", "state": "APPROVED",
                                             "mandate": {"mandate_id": "m-1"}})
        if p == "/approvals/rq-1/execute":
            body = json.loads(req.content)
            assert body["mandate"] == {"mandate_id": "m-1"}
            return httpx.Response(200, json={"status": "EXECUTED", "reason": "ok", "audit_ref": "a"})
        return httpx.Response(404, json={})
    client = _mock_client(handler)
    d = _evaluate(client)
    assert d.needs_approval
    approval = client.request_approval(d)
    granted = client.approve(approval)
    assert granted.granted
    res = client.execute_after_approval(d, granted)
    assert res.executed
    assert "/approvals/rq-1/execute" in seen


def test_consensus_authorization_routes_to_consensus_execute():
    seen = []
    def handler(req):
        seen.append(req.url.path)
        if req.url.path == "/evaluate":
            return httpx.Response(200, json=_decision_body("ALLOW"))
        body = json.loads(req.content)
        assert body["votes"] == [{"v": 1}] and body["challenge_id"] == "ch-1"
        return httpx.Response(200, json={"status": "EXECUTED", "reason": "ok"})
    client = _mock_client(handler)
    d = _evaluate(client)
    res = client.execute(d, ConsensusAuthorization(votes=[{"v": 1}], challenge_id="ch-1", nonce="n"))
    assert res.executed and "/consensus/execute" in seen
