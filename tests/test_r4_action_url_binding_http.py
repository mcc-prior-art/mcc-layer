"""R4 remediation regression suite: action names cannot alter upstream URLs.

R4 (internal red-team assessment, redteam/ at cb5bd33, V02 x4): the shipped
governed upstreams build the outbound URL as ``{base}/{action}``, and nothing
constrained the action string. A wildcard mandate scope (``pay_*``) matched
it, the token signed it, and the HTTP client then rewrote it on the wire.
Measured on main @ cdab4ed with a raw-socket receiver (the exact request line):

    pay_x/../../admin/wipe -> POST /admin/wipe        (EXECUTED: endpoint escape)
    pay_x?admin=1          -> POST /pay_x?admin=1     (EXECUTED: query injection)
    pay_x#frag             -> POST /pay_x             (EXECUTED: a different action than signed)
    pay_\\nX                -> nothing sent; httpx InvalidURL AFTER dispatch ownership
                              -> EXECUTION_FAILED (outcome unknown, key held)

Percent-encoding is no defense: a real Starlette receiver decodes ``%2F``
back into ``/`` before routing. So the fix REJECTS rather than encodes.

The contract (``mcc_core.action_name``): one or more dot-separated segments
of ASCII ``[A-Za-z0-9_-]``, starting with a letter or digit, at most 128
characters. A non-conforming name is refused, never sanitized, at:

* every ``GovernanceService`` execute route, before authority, token,
  idempotency/velocity reservation, audit or actuator;
* ``POST /approvals``, with HTTP 422 and no record;
* each URL-building sink (``_httpx_upstream``,
  ``receipt_verifying_upstream``, ``OutboundHTTPExecutor``), before any
  connection.

Every rejection asserts a controlled outcome (no HTTP 500), ZERO actuator
calls and ZERO requests on the wire. Valid controls assert exactly one call
and that the wire request line is exactly ``POST /<action>``.
"""
from __future__ import annotations

import asyncio
import gc
import json
import socket
import threading
import time

import pytest
from fastapi.testclient import TestClient

from mcc_core.action_name import (
    ACTION_NAME_MAX_LENGTH,
    ActionNameError,
    action_endpoint_url,
    action_name_error,
    validate_action_name,
)

from tests.test_r2_numeric_constraint_http import (
    ACTOR,
    AGENT,
    OP,
    POLICY,
    RESOURCE,
    DelegationStack,
    GovGateway,
    _audit_kinds,
    payment,
)


@pytest.fixture(autouse=True, scope="module")
def _release_this_modules_garbage():
    """Same test hygiene as the R3 modules: collect this module's cyclic
    garbage at its own teardown, not in whichever module runs next."""
    yield
    gc.collect()


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

ORIGINAL_R4 = [("dotdot", "pay_x/../../admin/wipe"), ("query", "pay_x?admin=1"),
               ("fragment", "pay_x#frag"), ("newline", "pay_\nX")]

MORE_UNSAFE = [
    # encoded / double-encoded traversal and separators
    ("enc-slash-traversal", "pay_x%2F..%2F..%2Fadmin"),
    ("enc-dots", "pay_x%2e%2e/admin"),
    ("enc-dots-and-slash", "pay_x%2e%2e%2fadmin"),
    ("double-enc-traversal", "pay_x%252e%252e%252fadmin"),
    ("enc-query", "pay_x%3Fadmin=1"),
    ("enc-fragment", "pay_x%23frag"),
    ("enc-crlf", "pay_x%0d%0aHost:evil"),
    ("enc-backslash", "pay_x%5c..%5cadmin"),
    ("enc-null", "pay_x%00"),
    # slash / backslash
    ("slash", "pay_x/admin"),
    ("leading-slash", "/pay_x"),
    ("trailing-slash", "pay_x/"),
    ("backslash-traversal", "pay_x\\..\\..\\admin"),
    ("backslash", "pay_x\\admin"),
    # query / fragment / params
    ("bare-query", "pay_x?"),
    ("bare-fragment", "pay_x#"),
    ("matrix-param", "pay_x;p=1"),
    ("ampersand", "pay_x&admin=1"),
    # CR / LF / other controls / whitespace
    ("crlf-header", "pay_x\r\nHost: evil"),
    ("cr", "pay_x\r"),
    ("lf-trailing", "pay_x\n"),
    ("tab", "pay_x\t"),
    ("nul", "pay_x\x00"),
    ("del", "pay_x\x7f"),
    ("esc", "pay_x\x1b[0m"),
    ("leading-space", " pay_x"),
    ("trailing-space", "pay_x "),
    ("inner-space", "pay x"),
    ("unicode-line-sep", "pay_ x"),
    ("unicode-nbsp", "pay_ x"),
    # non-ASCII look-alikes of separators / letters
    ("division-slash", "pay_∕admin"),
    ("fullwidth-slash", "pay_／admin"),
    ("fullwidth-dots", "pay_．．"),
    ("latin-e-acute", "pay_é"),
    ("cyrillic-a", "pаy_x"),
    # absolute and scheme-relative URLs, authority/port injection
    ("absolute-http", "http://evil.example/x"),
    ("absolute-https", "https://evil.example/x"),
    ("scheme-only", "https:evil.example"),
    ("scheme-relative", "//evil.example/x"),
    ("userinfo", "pay_x@evil.example"),
    ("at-prefix", "@evil.example"),
    ("port", "pay_x:8080"),
    # dot segments and malformed dots
    ("dot", "."),
    ("dotdot-only", ".."),
    ("leading-dot", ".pay_x"),
    ("trailing-dot", "pay_x."),
    ("double-dot-inside", "pay..x"),
    # empty / overlong
    ("empty", ""),
    ("too-long", "pay_" + "x" * (ACTION_NAME_MAX_LENGTH - 3)),
]
ALL_UNSAFE = ORIGINAL_R4 + MORE_UNSAFE
UNSAFE_IDS = [i for i, _ in ALL_UNSAFE]
UNSAFE = [a for _, a in ALL_UNSAFE]

# Every concrete action shape used by this repository's pilots, integrations,
# docs and tests: underscores, dots, digits and hyphens.
VALID = ["send_payment", "pay_now", "pay_x", "appointment_book", "medical_advice_request",
         "send_notification", "http.egress", "http.request", "github.create_issue",
         "payment.send", "deploy-release", "a", "x1", "A9", "pay_" + "x" * (ACTION_NAME_MAX_LENGTH - 4)]


# ---------------------------------------------------------------------------
# Real local HTTP receiver: records the exact request line each client sends
# ---------------------------------------------------------------------------

class RawReceiver:
    """A raw-socket HTTP/1.1 server, so the test sees exactly the request
    target the client put on the wire: no framework routing, decoding or
    normalization in between."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.requests: list = []
        self._closed = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _serve(self):
        while not self._closed:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(2)
                data = b""
                try:
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                except OSError:
                    pass
                self.requests.append(data.split(b"\r\n", 1)[0].decode("latin-1"))
                body = b'{"ok": true}'
                try:
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                 b"Content-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body))
                except OSError:
                    pass

    def close(self):
        self._closed = True
        self.sock.close()


@pytest.fixture
def rx():
    r = RawReceiver()
    yield r
    r.close()


def _raw_client(gw):
    """Surface unhandled exceptions as HTTP 500 instead of raising in-test."""
    return TestClient(gw.client.app, raise_server_exceptions=False)


def _post(client, url, headers, body):
    return client.post(url, headers={**headers, "content-type": "application/json"},
                       content=json.dumps(body))


def _wire_gateway(base):
    """GovGateway whose upstream is the SHIPPED gateway upstream
    (governance_api._httpx_upstream) pointed at a real local receiver. Every
    actuator call is still counted."""
    from gateway.governance_api import _httpx_upstream
    gw = GovGateway()
    real = _httpx_upstream(base)

    async def counted(action, payload):
        gw.calls.append((action, dict(payload)))
        return await real(action, payload)

    gw.service.upstream = counted
    gw.client = _raw_client(gw)
    return gw


def _assert_controlled_rejection(r, action):
    """BLOCKED/DENY with INVALID_ACTION_NAME, or -- for the empty name only --
    the request schema's own pre-existing 422 (min_length=1). Never a 500."""
    if action == "" and r.status_code == 422:
        return
    assert r.status_code == 200, (r.status_code, r.text)
    out = r.json()
    assert out["status"] == "BLOCKED" and out["decision"] == "DENY", out
    assert out["reason"].startswith("INVALID_ACTION_NAME"), out


def _mandate_execute(gw, action, *, scope=("*",), key="k-1", context=None):
    m = gw.mandate(action=scope[0]) if len(scope) == 1 else None
    r = _post(gw.client, "/mandates/execute", AGENT, {
        "mandate": m, "actor": ACTOR, "action": action, "resource": RESOURCE,
        "context": context or payment(100.0), "idempotency_key": key})
    return r


# ===========================================================================
# 1. The contract itself
# ===========================================================================

@pytest.mark.parametrize("action", VALID)
def test_contract_accepts_every_legitimate_action_shape_unchanged(action):
    assert action_name_error(action) is None
    assert validate_action_name(action) is action                        # never rewritten
    assert action_endpoint_url("http://h:1/base/", action) == f"http://h:1/base/{action}"


@pytest.mark.parametrize("action", UNSAFE, ids=UNSAFE_IDS)
def test_contract_rejects_unsafe_action_names(action):
    assert action_name_error(action)
    with pytest.raises(ActionNameError):
        validate_action_name(action)
    with pytest.raises(ActionNameError):
        action_endpoint_url("http://h:1", action)


@pytest.mark.parametrize("value", [None, 1, 1.5, True, b"pay_x", ["pay_x"], {"a": 1}],
                         ids=["none", "int", "float", "bool", "bytes", "list", "dict"])
def test_contract_is_total_for_non_strings(value):
    assert action_name_error(value)                                    # never raises
    with pytest.raises(ActionNameError):
        validate_action_name(value)


def test_contract_error_message_is_bounded():
    assert len(action_name_error("/" * 10_000)) < 300


# ===========================================================================
# 2. The URL-building sinks: refuse before any connection
# ===========================================================================

def _sinks(base):
    from gateway.governance_api import _httpx_upstream
    from pilot.outbound_executor import OutboundHTTPExecutor
    from pilot_notify.governed_upstream import receipt_verifying_upstream
    ex = OutboundHTTPExecutor(base)
    return {
        "governance_api._httpx_upstream": _httpx_upstream(base),
        "pilot_notify.receipt_verifying_upstream": receipt_verifying_upstream(base),
        "pilot.OutboundHTTPExecutor": lambda a, p: ex.execute(
            a, p, authorization={"decision": "ALLOW", "action": a, "subject": "s"}),
    }


@pytest.mark.parametrize("sink", ["governance_api._httpx_upstream",
                                  "pilot_notify.receipt_verifying_upstream",
                                  "pilot.OutboundHTTPExecutor"])
@pytest.mark.parametrize("action", UNSAFE, ids=UNSAFE_IDS)
def test_sink_refuses_unsafe_action_with_zero_requests_on_the_wire(rx, sink, action):
    with pytest.raises(ActionNameError):
        asyncio.run(_sinks(rx.base)[sink](action, {"correlation_id": "c"}))
    time.sleep(0.01)
    assert rx.requests == []


@pytest.mark.parametrize("sink", ["governance_api._httpx_upstream", "pilot.OutboundHTTPExecutor"])
@pytest.mark.parametrize("action", ["pay_now", "http.egress", "github.create_issue", "deploy-release"])
def test_sink_sends_exactly_the_action_as_one_literal_path_segment(rx, sink, action):
    asyncio.run(_sinks(rx.base)[sink](action, {"a": 1}))
    assert rx.requests == [f"POST /{action} HTTP/1.1"]


def test_outbound_executor_no_longer_strips_a_leading_slash(rx):
    """Pre-R4, '/pay_now' was silently rewritten to 'pay_now' (sanitizing the
    signed action into a different string). It is now refused."""
    from pilot.outbound_executor import OutboundHTTPExecutor
    ex = OutboundHTTPExecutor(rx.base)
    with pytest.raises(ActionNameError):
        asyncio.run(ex.execute("/pay_now", {}, authorization={"decision": "ALLOW", "action": "/pay_now"}))
    assert rx.requests == [] and ex.count() == 0


# ===========================================================================
# 3. POST /mandates/execute (wildcard scope "*": the authority would match ANY string)
# ===========================================================================

@pytest.mark.parametrize("action", UNSAFE, ids=UNSAFE_IDS)
def test_mandates_execute_unsafe_action_blocked_zero_calls_zero_wire(rx, action):
    gw = _wire_gateway(rx.base)
    _assert_controlled_rejection(_mandate_execute(gw, action), action)
    assert gw.calls == [] and rx.requests == []


@pytest.mark.parametrize("label,action", ORIGINAL_R4, ids=[i for i, _ in ORIGINAL_R4])
def test_mandates_execute_original_r4_cases_under_the_original_pay_wildcard(rx, label, action):
    """The assessment's exact setup: mandate action_scope=['pay_*']."""
    gw = _wire_gateway(rx.base)
    out = _mandate_execute(gw, action, scope=("pay_*",)).json()
    assert out["status"] == "BLOCKED" and "INVALID_ACTION_NAME" in out["reason"], out
    assert gw.calls == [] and rx.requests == []


def test_rejected_action_reserves_nothing_and_writes_no_pre_actuation(rx):
    """Rejected before the coordinator: the SAME idempotency key is still
    free for a legitimate operation, and the audit chain holds no
    pre_actuation / actuation record for the rejected attempt."""
    gw = _wire_gateway(rx.base)
    bad = _mandate_execute(gw, "pay_x/../../admin/wipe", key="shared-key").json()
    assert bad["status"] == "BLOCKED"
    kinds = _audit_kinds(gw.coordinator.audit.path)
    assert not [k for k in kinds if k == "pre_actuation" or str(k).startswith("actuation_")], kinds
    ok = _mandate_execute(gw, "pay_x", key="shared-key").json()
    assert ok["status"] == "EXECUTED", ok
    assert [a for a, _ in gw.calls] == ["pay_x"]
    assert rx.requests == ["POST /pay_x HTTP/1.1"]


@pytest.mark.parametrize("action", ["pay_x", "pay_now", "send_payment", "github.create_issue"])
def test_mandates_execute_legitimate_action_executes_exactly_once_at_its_own_path(rx, action):
    gw = _wire_gateway(rx.base)
    out = _mandate_execute(gw, action, scope=("*",)).json()
    assert out["status"] == "EXECUTED", out
    assert [a for a, _ in gw.calls] == [action]
    assert rx.requests == [f"POST /{action} HTTP/1.1"]       # signed action == executed path


# ===========================================================================
# 4. POST /approvals (422, no record) and /approvals/{id}/execute
# ===========================================================================

@pytest.mark.parametrize("action", UNSAFE, ids=UNSAFE_IDS)
def test_approval_request_with_unsafe_action_is_422_and_creates_no_record(action):
    gw = GovGateway()
    client = _raw_client(gw)
    r = _post(client, "/approvals", AGENT, {
        "actor": ACTOR, "action": action, "resource": RESOURCE, "transaction_id": "tx-1",
        "policy_hash": POLICY, "payload": payment(100.0)})
    assert r.status_code == 422, (r.status_code, r.text)
    if action != "":   # empty may already be refused by the request schema
        assert "INVALID_ACTION_NAME" in r.text
    assert gw.approvals.registry._records == {}
    assert gw.calls == []


@pytest.mark.parametrize("action", UNSAFE, ids=UNSAFE_IDS)
def test_approval_service_itself_refuses_unsafe_action(action):
    gw = GovGateway()
    with pytest.raises(ValueError):
        asyncio.run(gw.approvals.request(actor=ACTOR, action=action, resource=RESOURCE,
                                         transaction_id="tx-1", policy_hash=POLICY,
                                         payload=payment(100.0)))
    assert gw.approvals.registry._records == {}


@pytest.mark.parametrize("label,action", ORIGINAL_R4 + [("scheme-relative", "//evil.example/x"),
                                                        ("enc-slash-traversal", "pay_x%2F..%2Fadmin")],
                         ids=[i for i, _ in ORIGINAL_R4] + ["scheme-relative", "enc-slash-traversal"])
def test_approval_execute_with_legacy_unsafe_action_is_blocked(rx, label, action):
    """A record stored BEFORE R4 (bypassing request()) can still be approved:
    the approval mandate names the unsafe action. Executing it on either route
    is refused before the coordinator, and the approval is not consumed."""
    from mcc_core import ApprovalRecord, ApprovalState
    from mcc_core.signing import hash_action, hash_payload
    gw = _wire_gateway(rx.base)
    now = int(time.time())
    rec = ApprovalRecord(
        request_id="req-legacy-r4", actor=ACTOR, action=action, action_hash=hash_action(action),
        resource=RESOURCE, transaction_id="tx-1", policy_hash=POLICY,
        payload_hash=hash_payload(payment(100.0)), constraints={},
        state=ApprovalState.PENDING.value, created_at=now, expires_at=now + 300,
        tenant_id="tenant-1", payload=payment(100.0))
    asyncio.run(gw.approvals.registry.create(rec))
    a = gw.client.post("/approvals/req-legacy-r4/approve", headers=OP)
    assert a.status_code == 200, a.text
    for route in ("approval", "mandate"):
        url = "/approvals/req-legacy-r4/execute" if route == "approval" else "/mandates/execute"
        r = _post(gw.client, url, AGENT, {
            "mandate": a.json()["mandate"], "actor": ACTOR, "action": action, "resource": RESOURCE,
            "context": payment(100.0), "transaction_id": "tx-1", "idempotency_key": f"k-{route}"})
        assert r.status_code == 200, (route, r.status_code, r.text)
        out = r.json()
        assert out["status"] == "BLOCKED" and "INVALID_ACTION_NAME" in out["reason"], (route, out)
    assert gw.calls == [] and rx.requests == []
    assert gw.client.get("/approvals/req-legacy-r4", headers=AGENT).json()["state"] == "APPROVED"


def test_approval_legitimate_action_executes_exactly_once(rx):
    gw = _wire_gateway(rx.base)
    rid = _post(gw.client, "/approvals", AGENT, {
        "actor": ACTOR, "action": "send_payment", "resource": RESOURCE, "transaction_id": "tx-1",
        "policy_hash": POLICY, "payload": payment(100.0)}).json()["request_id"]
    m = gw.client.post(f"/approvals/{rid}/approve", headers=OP).json()["mandate"]
    out = _post(gw.client, f"/approvals/{rid}/execute", AGENT, {
        "mandate": m, "actor": ACTOR, "action": "send_payment", "resource": RESOURCE,
        "context": payment(100.0), "transaction_id": "tx-1", "idempotency_key": "ok"}).json()
    assert out["status"] == "EXECUTED", out
    assert [a for a, _ in gw.calls] == ["send_payment"]
    assert rx.requests == ["POST /send_payment HTTP/1.1"]


# ===========================================================================
# 5. POST /consensus/execute: a full 3-of-3 quorum signed over the unsafe action
# ===========================================================================

@pytest.mark.parametrize("action", UNSAFE, ids=UNSAFE_IDS)
def test_consensus_execute_unsafe_action_blocked_even_with_full_quorum(rx, action):
    from mcc_core import issue_vote
    from tests.test_r2_numeric_constraint_http import FUTURE
    gw = _wire_gateway(rx.base)
    votes = [issue_vote(k, evaluator_id=k.kid, verdict="ALLOW", action=action, payload=payment(100.0),
                        actor=ACTOR, resource=RESOURCE, policy_hash=POLICY, nonce="n-1",
                        not_before=0, not_after=FUTURE) for k in gw.evals]
    r = _post(gw.client, "/consensus/execute", AGENT, {
        "votes": votes, "actor": ACTOR, "action": action, "resource": RESOURCE,
        "context": payment(100.0), "nonce": "n-1", "idempotency_key": "k-1"})
    _assert_controlled_rejection(r, action)
    assert gw.calls == [] and rx.requests == []


def test_consensus_legitimate_action_executes_exactly_once(rx):
    gw = _wire_gateway(rx.base)
    out = gw.consensus_execute(payment(100.0), action="send_payment")
    assert out["status"] == "EXECUTED", out
    assert rx.requests == ["POST /send_payment HTTP/1.1"] and len(gw.calls) == 1


# ===========================================================================
# 6. Delegation (no HTTP route; service boundary execute_with_delegation)
# ===========================================================================

def _delegated(s, action, key):
    return asyncio.run(s.service.execute_with_delegation(
        delegation=s.delegation(), actor=ACTOR, action=action, resource=RESOURCE,
        purpose="vendor_payment", context=payment(100.0), tenant_id="tenant-1",
        idempotency_key=key))


@pytest.mark.parametrize("label,action", ORIGINAL_R4 + [("absolute-http", "http://evil.example/x"),
                                                        ("double-enc", "pay_x%252e%252e")],
                         ids=[i for i, _ in ORIGINAL_R4] + ["absolute-http", "double-enc"])
def test_delegation_unsafe_action_blocked(label, action):
    s = DelegationStack()
    out = _delegated(s, action, "d-1")
    assert out.status == "BLOCKED" and "INVALID_ACTION_NAME" in out.reason, out
    assert s.calls == []


def test_delegation_legitimate_action_executes_exactly_once():
    s = DelegationStack()
    out = _delegated(s, "send_payment", "d-ok")
    assert out.status == "EXECUTED", out
    assert len(s.calls) == 1


# ===========================================================================
# 7. End-to-end against a REAL HTTP service: the receipt-verifying upstream
#    (pilot_notify) in front of the real uvicorn mock notification service
# ===========================================================================

@pytest.fixture
def notify_gw():
    from examples._demo_server import DemoServer, free_port
    from pilot_notify import service as notify
    from pilot_notify.governed_upstream import receipt_verifying_upstream
    notify.reset_receipts()
    port = free_port()
    server = DemoServer(notify.build_notification_service(), port).start()
    gw = GovGateway()
    real = receipt_verifying_upstream(f"http://127.0.0.1:{port}")

    async def counted(action, payload):
        gw.calls.append((action, dict(payload)))
        return await real(action, payload)

    gw.service.upstream = counted
    gw.client = _raw_client(gw)
    try:
        yield gw, notify
    finally:
        server.stop()


def _notification(corr):
    return {"recipient": "ops@example.com", "message": "hello", "correlation_id": corr}


@pytest.mark.parametrize("action", ["send_notification/../send_notification", "send_notification?x=1",
                                    "send_notification#x", "send_notification\n",
                                    "send_notification%2F..%2Fsend_notification", "//127.0.0.1/send_notification"],
                         ids=["dotdot", "query", "fragment", "newline", "enc-traversal", "scheme-relative"])
def test_real_notification_service_receives_nothing_for_unsafe_action(notify_gw, action):
    gw, notify = notify_gw
    r = _post(gw.client, "/mandates/execute", AGENT, {
        "mandate": gw.mandate(action="send_notification*", resource_scope=(), constraints={}), "actor": ACTOR,
        "action": action, "resource": None, "context": _notification("c-bad"), "idempotency_key": "k"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "BLOCKED" and "INVALID_ACTION_NAME" in r.json()["reason"]
    assert gw.calls == [] and notify.recorded_receipts() == []


def test_real_notification_service_legitimate_action_executes_exactly_once(notify_gw):
    gw, notify = notify_gw
    out = _post(gw.client, "/mandates/execute", AGENT, {
        "mandate": gw.mandate(action="send_notification", resource_scope=(), constraints={}), "actor": ACTOR,
        "action": "send_notification", "resource": None, "context": _notification("c-ok"),
        "idempotency_key": "k"}).json()
    assert out["status"] == "EXECUTED", out
    assert len(gw.calls) == 1
    receipts = notify.recorded_receipts()
    assert len(receipts) == 1 and receipts[0]["receipt"]["correlation_id"] == "c-ok"
