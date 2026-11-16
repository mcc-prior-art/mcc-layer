"""F1b: per-principal identity on the separately deployed runtimes.

Reproduced on PR #136 head 0315574 over real HTTP (uvicorn on loopback):

* gateway/app.py ``/evaluate``: the shared tenant key obtained ALLOW + a
  decision token signed for ``agent/payments-bot`` (an unregistered policy
  identity) -- a caller-selected service identity;
* MVP interceptor: a caller with NO credential set ``X-MCC-Identity:
  agent/payments-bot`` and was forwarded upstream (the interceptor evaluated
  with its own service key);
* egress proxy: one service key; ``actor=agent/egress`` (the mandate holder)
  in the body -> EXECUTED, upstream +1;
* main.py: the token subject ``agent/<session_id>`` was caller-chosen, and B
  reusing A's ``idempotency_key`` received A's cached signed token;
* Pilot Execution API: B (its own tenant key) executed A's stored operation
  by id (EXECUTED, ledger +1) and read its status; B could submit a
  proposal naming ``actor=agent/a``.

Contract (strict, the default): tenant AND principal are resolved
server-side from the presented credential (hash-only registry,
MCC_AGENT_CREDENTIALS_CONFIG); actor/identity headers and body fields are
never proof and must EQUAL the principal; shared tenant/service keys are
refused on every authority-issuing route; stored operations are bound to the
submitting principal; every refusal happens before authority issuance,
approval/challenge use, reservation, audit record or actuator call.

Each negative is paired with a positive control on the same surface, and a
rejected attempt is followed by a legitimate retry with the SAME idempotency
key / operation id.
"""
from __future__ import annotations

import json
import os
import tempfile
import uuid
from typing import Any, Dict, List

import httpx
import pytest
from fastapi import FastAPI, Request

from examples._demo_server import DemoServer, free_port
from mcc_core.agent_identity import (
    AGENT_IDENTITY_LEGACY,
    AGENT_IDENTITY_STRICT,
    AgentCredentialRegistry,
    AuthenticatedAgent,
    evaluate_identity_error,
    hash_agent_key,
    principal_binding_error,
)
from tests._agent_credentials import derived_agent_key, module_headers, module_key

SHARED = "demo-key"          # the module apps' shared tenant/service key (never registered)


def _sink():
    seen: List[Dict[str, Any]] = []
    app = FastAPI()

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def sink(request: Request, path: str):
        if request.method != "GET":
            seen.append({"path": path, "headers": {k.lower() for k in request.headers}})
        return {"ok": True}
    return app, seen


def _lines(path: str) -> int:
    try:
        with open(path, encoding="utf-8") as f:
            return sum(1 for ln in f if ln.strip())
    except FileNotFoundError:
        return 0


def _registry_file(entries) -> str:
    path = os.path.join(tempfile.mkdtemp(prefix="f1b-agents-"), "agents.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"agents": [
            {"credential_id": f"c-{i}", "tenant_id": t, "principal_id": p,
             "key_sha256": hash_agent_key(k), "status": st}
            for i, (t, p, k, st) in enumerate(entries)]}, f)
    return path


PAYMENT = {"amount": 1000, "currency": "usd", "source": "acct-1", "beneficiary_id": "ben-1"}


# ======================================================================
# 1 + 3. gateway/app.py /evaluate and the MVP interceptor in front of it
# ======================================================================

@pytest.fixture(scope="module")
def gw():
    import gateway.app as gwmod
    # Enforcement (inline) mode: in observe mode the interceptor is
    # deliberately transparent and blocks nothing, identity or not.
    saved = gwmod.settings.mode
    gwmod.settings.mode = "inline"
    port = free_port()
    srv = DemoServer(gwmod.app, port)
    srv.start()
    yield gwmod, f"http://127.0.0.1:{port}"
    srv.stop()
    gwmod.settings.mode = saved


def _evaluate(base, headers, identity, actor_id=None, idem=None):
    body = {"identity": identity, "action": "send_payment", "context": dict(PAYMENT)}
    if actor_id:
        body["actor_id"] = actor_id
    if idem:
        body["idempotency_key"] = idem
        body["transaction_id"] = idem
    return httpx.post(f"{base}/evaluate", headers=headers, json=body, timeout=15)


def test_gateway_evaluate_refuses_the_shared_key_for_every_identity(gw):
    gwmod, base = gw
    audit = gwmod.gateway.audit.path
    before = _lines(audit)
    for identity in ("agent/payments-bot", "svc/billing", "agent/never-registered", "agent/b"):
        r = _evaluate(base, {"x-api-key": SHARED}, identity)
        assert r.status_code == 403 and "AGENT_IDENTITY_REQUIRED" in r.json()["detail"], identity
    assert _lines(audit) == before                       # no evaluate record, no token
    ok = _evaluate(base, module_headers("agent/payments-bot"), "agent/payments-bot")
    assert ok.status_code == 200 and ok.json()["decision"] == "ALLOW"
    assert ok.json()["decision_token"]["sub"] == "agent/payments-bot"
    # read-only audit verification still accepts the shared key
    assert httpx.get(f"{base}/verify", headers={"x-api-key": SHARED}, timeout=15).status_code == 200


def test_gateway_evaluate_binds_registered_and_refuses_bad_credentials(gw):
    _, base = gw
    r = _evaluate(base, module_headers("agent/b"), "agent/payments-bot")
    assert r.status_code == 403 and "AGENT_PRINCIPAL_MISMATCH" in r.json()["detail"]
    r = _evaluate(base, module_headers("agent/b"), "agent/b", actor_id="agent/payments-bot")
    assert r.status_code == 403
    assert _evaluate(base, module_headers("agent/revoked"), "agent/revoked").status_code == 403
    assert _evaluate(base, {"x-api-key": "not-registered"}, "agent/b").status_code == 401
    r = _evaluate(base, {**module_headers("agent/b"), "x-mcc-identity": "agent/payments-bot",
                         "x-principal-id": "agent/payments-bot"}, "agent/payments-bot")
    assert r.status_code == 403                          # headers grant nothing


def test_gateway_evaluate_rejection_leaves_the_idempotency_key_usable(gw):
    gwmod, base = gw
    audit = gwmod.gateway.audit.path
    k = f"f1b-gw-{uuid.uuid4().hex[:8]}"
    before = _lines(audit)
    for headers, ident in (({"x-api-key": SHARED}, "agent/payments-bot"),
                           (module_headers("agent/b"), "agent/payments-bot")):
        assert _evaluate(base, headers, ident, idem=k).status_code == 403
    assert _lines(audit) == before                       # nothing recorded, nothing reserved
    ok = _evaluate(base, module_headers("agent/payments-bot"), "agent/payments-bot", idem=k)
    assert ok.status_code == 200 and ok.json()["decision"] == "ALLOW"
    assert ok.json()["decision_token"]["sub"] == "agent/payments-bot"


@pytest.fixture(scope="module")
def interceptor(gw):
    from interceptors.egress_proxy import (
        ActionMapper, EgressGovernor, Route, build_decide_via_http, build_gate_from_health,
        build_proxy_app)
    from mcc_core.agent_identity import agent_registry_from_env
    _, base = gw
    up, seen = _sink()
    up_port, px_port = free_port(), free_port()
    gov = EgressGovernor(
        mapper=ActionMapper([Route(action="send_payment", method="POST", host="*", path="*charge*")]),
        decide=build_decide_via_http(base, SHARED), gate=build_gate_from_health(base),
        agent_credentials=agent_registry_from_env(os.environ), tenant_id="pilot",
        identity_mode=AGENT_IDENTITY_STRICT)
    servers = [DemoServer(up, up_port),
               DemoServer(build_proxy_app(gov, upstream_base=f"http://127.0.0.1:{up_port}"), px_port)]
    for s in servers:
        s.start()
    yield f"http://127.0.0.1:{px_port}", seen, base
    for s in reversed(servers):
        s.stop()


def _charge(px, headers):
    return httpx.post(f"{px}/charge", json=dict(PAYMENT), headers=headers, timeout=15)


def test_interceptor_refuses_callers_without_their_own_credential(gw, interceptor):
    gwmod, _ = gw
    px, seen, _ = interceptor
    audit = gwmod.gateway.audit.path
    before_up, before_audit = len(seen), _lines(audit)
    for headers in ({}, {"x-mcc-identity": "agent/payments-bot"},
                    {"x-mcc-agent-key": SHARED, "x-mcc-identity": "agent/payments-bot"},
                    {"x-mcc-agent-key": "not-registered"}):
        r = _charge(px, headers)
        assert r.status_code == 401 and r.headers["x-mcc-decision"] == "DENY", headers
    r = _charge(px, {"x-mcc-agent-key": module_key("agent/revoked")})
    assert r.status_code == 403
    assert len(seen) == before_up and _lines(audit) == before_audit   # gateway never asked


def test_interceptor_binds_identity_to_the_authenticated_principal(gw, interceptor):
    px, seen, _ = interceptor
    before = len(seen)
    r = _charge(px, {"x-mcc-agent-key": module_key("agent/b"), "x-mcc-identity": "agent/payments-bot"})
    assert r.status_code == 403 and "AGENT_PRINCIPAL_MISMATCH" in r.headers["x-mcc-reason"]
    r = _charge(px, {"x-mcc-agent-key": module_key("agent/b")})          # b holds no mandate
    assert r.status_code == 403 and r.headers["x-mcc-decision"] == "ESCALATE"
    assert len(seen) == before
    # positive control: payments-bot with ITS OWN key is forwarded, and the
    # credential header never reaches the upstream.
    r = _charge(px, {"x-mcc-agent-key": module_key("agent/payments-bot"),
                     "x-mcc-identity": "agent/payments-bot"})
    assert r.status_code == 200 and r.headers["x-mcc-decision"] == "ALLOW"
    assert len(seen) == before + 1 and "x-mcc-agent-key" not in seen[-1]["headers"]


def test_interceptor_service_key_cannot_mint_authority_even_in_legacy_header_mode(gw, interceptor):
    from interceptors.egress_proxy import (
        ActionMapper, EgressGovernor, OutboundRequest, Route, build_decide_via_http,
        build_gate_from_health)
    import asyncio
    _, base = gw
    gov = EgressGovernor(
        mapper=ActionMapper([Route(action="send_payment", method="POST", host="*", path="*charge*")]),
        decide=build_decide_via_http(base, SHARED), gate=build_gate_from_health(base),
        identity_mode=AGENT_IDENTITY_LEGACY)
    out = asyncio.run(gov.govern(OutboundRequest(
        method="POST", url="http://up/charge", headers={"x-mcc-identity": "agent/payments-bot"},
        body=dict(PAYMENT))))
    # the strict gateway refuses the interceptor's service key for every identity
    assert not out.forward


def test_interceptor_refuses_another_tenants_credential_before_any_decision():
    from interceptors.egress_proxy import ActionMapper, EgressGovernor, OutboundRequest, Route
    import asyncio
    called = []

    async def decide(payload, **kw):
        called.append((payload, kw))
        return {"decision": "ALLOW", "enforce": True}
    reg = AgentCredentialRegistry.from_config({"agents": [
        {"credential_id": "1", "tenant_id": "pilot", "principal_id": "agent/a",
         "key_sha256": hash_agent_key("k-a"), "status": "active"},
        {"credential_id": "2", "tenant_id": "tenant-other", "principal_id": "agent/a",
         "key_sha256": hash_agent_key("k-a-other"), "status": "active"}]})
    gov = EgressGovernor(mapper=ActionMapper([Route(action="send_payment", method="POST", host="*",
                                                    path="*charge*")]),
                         decide=decide, gate=None, agent_credentials=reg, tenant_id="pilot",
                         identity_mode=AGENT_IDENTITY_STRICT)

    def go(headers):
        return asyncio.run(gov.govern(OutboundRequest(method="POST", url="http://up/charge",
                                                      headers=headers, body=dict(PAYMENT))))
    out = go({"x-mcc-agent-key": "k-a-other", "x-mcc-identity": "agent/a"})
    assert not out.forward and called == []              # same principal name, other tenant
    out = go({"x-mcc-agent-key": "k-a"})
    assert called and called[-1][1].get("credential") == "k-a"   # forwarded as ITSELF


def test_interceptor_without_a_registry_fails_closed(gw):
    from interceptors.egress_proxy import ActionMapper, EgressGovernor, OutboundRequest, Route
    import asyncio
    called = []

    async def decide(payload, **kw):
        called.append(payload)
        return {"decision": "ALLOW", "enforce": True}
    gov = EgressGovernor(mapper=ActionMapper([Route(action="send_payment", method="POST", host="*",
                                                    path="*charge*")]),
                         decide=decide, gate=None, identity_mode=AGENT_IDENTITY_STRICT)
    out = asyncio.run(gov.govern(OutboundRequest(
        method="POST", url="http://up/charge",
        headers={"x-mcc-agent-key": module_key("agent/payments-bot")}, body=dict(PAYMENT))))
    assert not out.forward and "AGENT_IDENTITY_UNAVAILABLE" in out.reason and called == []


# ======================================================================
# 2. egress proxy POST /v1/http/execute
# ======================================================================

@pytest.fixture(scope="module")
def egress():
    from tests._egress_harness import EGRESS_TEST_PRINCIPALS, EgressHarness
    tenant = "governed-agent-demo"
    entries = [(tenant, p, derived_agent_key("agent-key", p), "active") for p in EGRESS_TEST_PRINCIPALS]
    entries += [(tenant, "agent/revoked", "f1b-egress-revoked", "revoked"),
                ("tenant-other", "agent/egress", "f1b-egress-other-tenant", "active")]
    hz = EgressHarness(require_consensus=False,
                       env={"MCC_AGENT_CREDENTIALS_CONFIG": _registry_file(entries)})
    port = free_port()
    srv = DemoServer(hz.app, port)
    srv.start()
    hz.base = f"http://127.0.0.1:{port}"
    yield hz
    srv.stop()


def _egress(hz, key, *, actor, idem, extra=None, amount=10, headers=None):
    body = {"method": "POST", "url": hz.url("/charge"), "body": {"amount": amount}, "actor": actor,
            "resource": "acct-1", "transaction_id": f"tx-{idem}", "idempotency_key": idem}
    body.update(extra or {})
    h = {"x-api-key": key}
    h.update(headers or {})
    return httpx.post(f"{hz.base}/v1/http/execute", headers=h, json=body, timeout=15)


def test_egress_refuses_service_key_and_bad_credentials(egress):
    hz = egress
    audit_before = _lines(hz.settings.audit_log_path)
    before = (len(hz.seen), hz.executor.count())
    idem = f"f1b-e-{uuid.uuid4().hex[:8]}"
    for key, code in ((hz.H["x-api-key"], 403), ("f1b-egress-revoked", 403),
                      ("f1b-egress-other-tenant", 403), ("unknown", 401)):
        r = _egress(hz, key, actor="agent/egress", idem=idem)
        assert r.status_code == code, (key, r.text)
    assert (len(hz.seen), hz.executor.count()) == before
    assert _lines(hz.settings.audit_log_path) == audit_before   # no proposal/audit record
    ok = _egress(hz, hz.key_for("agent/egress"), actor="agent/egress", idem=idem)   # same idem key
    assert ok.status_code == 200 and ok.json()["executed"] is True
    assert hz.executor.count() == before[1] + 1


def test_egress_actor_must_be_the_authenticated_principal(egress):
    hz = egress
    before = (len(hz.seen), hz.executor.count())
    idem = f"f1b-e-{uuid.uuid4().hex[:8]}"
    r = _egress(hz, hz.key_for("agent/intern"), actor="agent/egress", idem=idem,
                headers={"x-mcc-identity": "agent/egress", "x-principal-id": "agent/egress"})
    assert r.status_code == 403 and "AGENT_PRINCIPAL_MISMATCH" in r.json()["detail"]
    r = _egress(hz, hz.key_for("agent/intern"), actor="agent/intern", idem=idem,
                extra={"principal_id": "agent/egress"})
    assert r.status_code == 422                                  # identity body field rejected
    assert (len(hz.seen), hz.executor.count()) == before
    # another tenant's agent/egress credential (same principal name)
    r = _egress(hz, "f1b-egress-other-tenant", actor="agent/egress", idem=idem)
    assert r.status_code == 403 and hz.executor.count() == before[1]
    own = _egress(hz, hz.key_for("agent/intern"), actor="agent/intern", idem=idem)
    assert own.json()["outcome"] == "ESCALATE" and not own.json()["executed"]   # intern has no mandate
    ok = _egress(hz, hz.key_for("agent/egress"), actor="agent/egress", idem=f"{idem}-holder")
    assert ok.json()["executed"] is True


def test_egress_copied_approval_is_unusable_by_another_principal(egress):
    hz = egress
    idem = f"f1b-e-{uuid.uuid4().hex[:8]}"
    r = _egress(hz, hz.key_for("agent/intern"), actor="agent/intern", idem=idem)
    rid = r.json()["approval_request_id"]
    assert hz.approve(rid).json()["approved"]
    before = hz.executor.count()
    # agent/x holds no mandate of its own, so only the copied approval could
    # authorize it.
    stolen = _egress(hz, hz.key_for("agent/x"), actor="agent/intern", idem=idem,
                     extra={"approval_id": rid})
    assert stolen.status_code == 403 and "AGENT_PRINCIPAL_MISMATCH" in stolen.json()["detail"]
    as_self = _egress(hz, hz.key_for("agent/x"), actor="agent/x", idem=idem,
                      extra={"approval_id": rid})
    assert not as_self.json().get("executed")                    # approval is bound to intern
    assert hz.executor.count() == before
    mine = _egress(hz, hz.key_for("agent/intern"), actor="agent/intern", idem=idem,
                   extra={"approval_id": rid})
    assert mine.json()["executed"] is True and hz.executor.count() == before + 1


# ======================================================================
# 4. main.py /evaluate and /evaluate/challenge
# ======================================================================

@pytest.fixture(scope="module")
def main_app():
    import main
    port = free_port()
    srv = DemoServer(main.app, port)
    srv.start()
    yield main, f"http://127.0.0.1:{port}"
    srv.stop()


def _main_eval(base, headers, session, idem=None):
    body = {"session_id": session, "intent": "send_payment", "args": {"amount": 100}}
    if idem:
        body["idempotency_key"] = idem
    return httpx.post(f"{base}/evaluate", headers=headers, json=body, timeout=15)


def test_main_refuses_shared_key_and_foreign_sessions(main_app):
    main, base = main_app
    audit = main.mcc.audit.path
    before = _lines(audit)
    assert _main_eval(base, {"x-api-key": SHARED}, "alice").status_code == 403
    r = _main_eval(base, module_headers("agent/bob"), "alice")
    assert r.status_code == 403 and "AGENT_PRINCIPAL_MISMATCH" in r.json()["detail"]
    assert _main_eval(base, module_headers("agent/revoked"), "revoked").status_code == 403
    assert _main_eval(base, {"x-api-key": "unknown"}, "alice").status_code == 401
    for path in ("/evaluate/challenge",):
        body = {"session_id": "alice", "intent": "send_payment", "args": {"amount": 100}}
        assert httpx.post(f"{base}{path}", headers={"x-api-key": SHARED}, json=body,
                          timeout=15).status_code == 403
        r = httpx.post(f"{base}{path}", headers=module_headers("agent/bob"), json=body, timeout=15)
        assert r.status_code == 403 and "AGENT_PRINCIPAL_MISMATCH" in r.json()["detail"]
    assert _lines(audit) == before
    ok = _main_eval(base, module_headers("agent/bob"), "bob")
    assert ok.status_code == 200 and ok.json()["decision_token"]["sub"] == "agent/bob"


def test_main_idempotency_cache_is_per_principal(main_app):
    _, base = main_app
    k = f"f1b-main-{uuid.uuid4().hex[:8]}"
    a = _main_eval(base, module_headers("agent/alice"), "alice", idem=k).json()
    rejected = _main_eval(base, module_headers("agent/bob"), "alice", idem=k)
    assert rejected.status_code == 403
    b = _main_eval(base, module_headers("agent/bob"), "bob", idem=k).json()   # same key, own session
    assert a["decision_token"]["sub"] == "agent/alice" and b["decision_token"]["sub"] == "agent/bob"
    assert a["decision_token"]["jti"] != b["decision_token"]["jti"]
    again = _main_eval(base, module_headers("agent/alice"), "alice", idem=k).json()
    assert again["decision_token"]["jti"] == a["decision_token"]["jti"]       # cache still works


def test_main_refuses_a_registry_with_a_principal_in_two_tenants():
    reg = AgentCredentialRegistry.from_config({"agents": [
        {"credential_id": "1", "tenant_id": "t1", "principal_id": "agent/x",
         "key_sha256": hash_agent_key("k1"), "status": "active"},
        {"credential_id": "2", "tenant_id": "t2", "principal_id": "agent/x",
         "key_sha256": hash_agent_key("k2"), "status": "active"}]})
    assert reg.principals_in_multiple_tenants() == ["agent/x"]


# ======================================================================
# 5. Pilot Execution API (/v1/proposals + /v1/operations/{id}/execute)
# ======================================================================

KEY_A, KEY_B, KEY_C, KEY_R, KEY_SHARED = ("f1b-pa", "f1b-pb", "f1b-pc", "f1b-pr", "f1b-tenant-a-shared")


@pytest.fixture()
def pilot_api():
    from pathlib import Path

    from examples.external_pilot.actuator.demo_actuator import build_demo_actuator
    from examples.external_pilot.scenarios import ACTION, TENANTS_AUTHORITY
    from gateway.proposal_api import mount_proposal_routes
    from gateway.proposal_execution_api import mount_proposal_execution_routes
    from gateway.proposal_execution_stack import build_proposal_execution_stack
    from mcc_core import InMemoryIdempotencyRegistry, InMemoryNonceRegistry
    from mcc_proposal import InMemoryProposalRegistry, MCCProposalService
    upstream, ledger = build_demo_actuator()
    proposals, idem = InMemoryProposalRegistry(), InMemoryIdempotencyRegistry()
    stack = build_proposal_execution_stack(
        proposals=proposals, idempotency=idem, nonces=InMemoryNonceRegistry(),
        tenants=TENANTS_AUTHORITY, action=ACTION, upstream=upstream,
        audit_log_path=str(Path(tempfile.mkdtemp()) / "audit.jsonl"))
    reg = AgentCredentialRegistry.from_file(_registry_file([
        ("tenant-a", "agent/a", KEY_A, "active"), ("tenant-a", "agent/b", KEY_B, "active"),
        ("tenant-b", "agent/a", KEY_C, "active"), ("tenant-a", "agent/r", KEY_R, "revoked")]))
    tenants = {KEY_SHARED: "tenant-a"}
    app = FastAPI()
    mount_proposal_routes(app, MCCProposalService(proposals=proposals, durable_execution_state=idem),
                          tenants=tenants, agent_credentials=reg, identity_mode=AGENT_IDENTITY_STRICT)
    mount_proposal_execution_routes(app, stack.service, tenants=tenants, agent_credentials=reg,
                                    identity_mode=AGENT_IDENTITY_STRICT)
    port = free_port()
    srv = DemoServer(app, port)
    srv.start()
    yield f"http://127.0.0.1:{port}", ledger, ACTION, upstream.resource
    srv.stop()


def _propose(base, key, *, op, actor, action, resource, extra=None):
    body = {"logical_operation_id": op, "actor": actor, "action": action, "resource": resource,
            "payload": {"title": "f1b", "amount": 1}}
    body.update(extra or {})
    return httpx.post(f"{base}/v1/proposals", headers={"x-api-key": key}, json=body, timeout=15)


def _execute(base, key, op):
    return httpx.post(f"{base}/v1/operations/{op}/execute", headers={"x-api-key": key}, timeout=15)


def test_pilot_api_proposal_actor_is_the_principal(pilot_api):
    base, ledger, action, resource = pilot_api
    r = _propose(base, KEY_B, op="op-1", actor="agent/a", action=action, resource=resource)
    assert r.status_code == 403 and "AGENT_PRINCIPAL_MISMATCH" in r.json()["detail"]
    r = _propose(base, KEY_B, op="op-1", actor="agent/b", action=action, resource=resource,
                 extra={"principal_id": "agent/a"})
    assert r.status_code == 422
    # nothing was recorded for op-1: A can now own it
    assert _propose(base, KEY_A, op="op-1", actor="agent/a", action=action,
                    resource=resource).json()["status"] == "PROPOSED"


def test_pilot_api_operation_is_bound_to_its_principal(pilot_api):
    base, ledger, action, resource = pilot_api
    assert _propose(base, KEY_A, op="op-2", actor="agent/a", action=action,
                    resource=resource).json()["status"] == "PROPOSED"
    r = _execute(base, KEY_B, "op-2")                         # B, same tenant, copied op id
    assert r.status_code == 404 and ledger.entries == []
    assert httpx.get(f"{base}/v1/operations/op-2", headers={"x-api-key": KEY_B},
                     timeout=15).json()["status"] == "NOT_FOUND"
    assert _execute(base, KEY_C, "op-2").status_code == 404   # agent/a of ANOTHER tenant
    assert _propose(base, KEY_B, op="op-2", actor="agent/b", action=action,
                    resource=resource).json()["status"] == "BINDING_CONFLICT"
    for key, code in ((KEY_SHARED, 403), (KEY_R, 403), ("unknown", 401)):
        assert _execute(base, key, "op-2").status_code == code
    assert ledger.entries == []
    ok = _execute(base, KEY_A, "op-2")                        # same operation id: nothing reserved
    assert ok.status_code == 200 and ok.json()["status"] == "EXECUTED" and len(ledger.entries) == 1
    again = _execute(base, KEY_A, "op-2")                     # replay never dispatches twice
    assert again.json()["status"] != "EXECUTED" and len(ledger.entries) == 1
    assert httpx.get(f"{base}/v1/operations/op-2", headers={"x-api-key": KEY_A},
                     timeout=15).json()["status"] == "EXECUTED"


def test_pilot_api_spoofed_identity_headers_grant_nothing(pilot_api):
    base, ledger, action, resource = pilot_api
    assert _propose(base, KEY_A, op="op-4", actor="agent/a", action=action,
                    resource=resource).json()["status"] == "PROPOSED"
    spoof = {"x-api-key": KEY_B, "x-mcc-identity": "agent/a", "x-principal-id": "agent/a",
             "x-tenant-id": "tenant-a", "x-actor": "agent/a"}
    r = httpx.post(f"{base}/v1/operations/op-4/execute", headers=spoof, timeout=15)
    assert r.status_code == 404 and ledger.entries == []
    r = httpx.get(f"{base}/v1/operations/op-4", headers={**spoof, "x-api-key": KEY_C}, timeout=15)
    assert r.json()["status"] == "NOT_FOUND"              # agent/a of tenant-b reads nothing
    ok = _execute(base, KEY_A, "op-4")
    assert ok.json()["status"] == "EXECUTED" and len(ledger.entries) == 1


def test_pilot_api_shared_tenant_key_refused_on_proposals(pilot_api):
    base, _, action, resource = pilot_api
    r = _propose(base, KEY_SHARED, op="op-3", actor="agent/a", action=action, resource=resource)
    assert r.status_code == 403 and "AGENT_IDENTITY_REQUIRED" in r.json()["detail"]


# ======================================================================
# units: total, fail-closed checks
# ======================================================================

def test_evaluate_identity_error_strict_refuses_shared_key_for_all_identities():
    me = AuthenticatedAgent("pilot", "agent/a", "c")
    for ident in ("agent/a", "svc/x", "anything"):
        assert "IDENTITY_REQUIRED" in evaluate_identity_error(None, tenant_id="pilot", identities=(ident,),
                                                              mode=AGENT_IDENTITY_STRICT)
        assert evaluate_identity_error(None, tenant_id="pilot", identities=(ident,),
                                       mode=AGENT_IDENTITY_LEGACY) is None
    assert evaluate_identity_error(me, tenant_id="pilot", identities=("agent/a",),
                                   mode=AGENT_IDENTITY_STRICT) is None
    assert "PRINCIPAL" in evaluate_identity_error(me, tenant_id="pilot", identities=(),
                                                  mode=AGENT_IDENTITY_STRICT)


def test_principal_binding_error_is_total():
    me = AuthenticatedAgent("t", "agent/a", "c")
    S, L = AGENT_IDENTITY_STRICT, AGENT_IDENTITY_LEGACY
    assert principal_binding_error(me, claimed="agent/a", mode=S) is None
    assert principal_binding_error(me, claimed=None, mode=S) is None
    assert "MISMATCH" in principal_binding_error(me, claimed="agent/b", mode=S)
    assert "MISMATCH" in principal_binding_error(me, claimed="agent/b", mode=L)   # registered: every mode
    assert "REQUIRED" in principal_binding_error(None, claimed="agent/a", mode=S)
    assert principal_binding_error(None, claimed="agent/a", mode=L) is None
    assert "INVALID" in principal_binding_error("forged", claimed="agent/a", mode=S)
    assert "MODE" in principal_binding_error(me, claimed="agent/a", mode="off")


def test_registry_authenticate_is_multi_tenant_and_fail_closed():
    reg = AgentCredentialRegistry.from_config({"agents": [
        {"credential_id": "1", "tenant_id": "t1", "principal_id": "agent/x",
         "key_sha256": hash_agent_key("k1"), "status": "active"},
        {"credential_id": "2", "tenant_id": "t2", "principal_id": "agent/y",
         "key_sha256": hash_agent_key("k2"), "status": "revoked"}]})
    assert reg.authenticate("k1").agent == AuthenticatedAgent("t1", "agent/x", "1")
    assert reg.authenticate("k2").error == "AGENT_CREDENTIAL_REVOKED"
    assert reg.authenticate("nope").error == "AGENT_CREDENTIAL_UNKNOWN"
    for junk in (None, "", 5):
        assert reg.authenticate(junk).agent is None


def test_in_process_proposal_backend_binds_the_principal():
    import asyncio

    from mcc_proposal import InMemoryProposalRegistry, MCCProposalService
    from mcc_proposal.transport import InProcessProposalBackend, ProposalBackendError
    reg = AgentCredentialRegistry.from_config({"agents": [
        {"credential_id": "1", "tenant_id": "t", "principal_id": "agent/a",
         "key_sha256": hash_agent_key("ka"), "status": "active"}]})
    svc = MCCProposalService(proposals=InMemoryProposalRegistry())
    be = InProcessProposalBackend(service=svc, tenants={"shared": "t"}, agent_credentials=reg,
                                  identity_mode=AGENT_IDENTITY_STRICT)
    req = {"logical_operation_id": "op", "actor": "agent/a", "action": "generic_op", "payload": {"x": 1}}
    with pytest.raises(ProposalBackendError, match="AGENT_IDENTITY_REQUIRED"):
        asyncio.run(be.submit_proposal(credential="shared", request=req))
    with pytest.raises(ProposalBackendError, match="AGENT_PRINCIPAL_MISMATCH"):
        asyncio.run(be.submit_proposal(credential="ka", request={**req, "actor": "agent/b"}))
    assert asyncio.run(be.submit_proposal(credential="ka", request=req))["status"] == "PROPOSED"
    legacy = InProcessProposalBackend(service=svc, tenants={"shared": "t"},
                                      identity_mode=AGENT_IDENTITY_LEGACY)
    out = asyncio.run(legacy.get_operation_status(credential="shared", logical_operation_id="op"))
    assert out["status"] == "PROPOSED"           # explicit legacy: tenant-level, unprotected


@pytest.mark.parametrize("backend", ["memory", "redis"])
def test_proposal_registry_principal_ownership(backend):
    import asyncio

    from mcc_proposal import InMemoryProposalRegistry
    from mcc_proposal.registry import ProposalRegisterStatus
    if backend == "memory":
        reg = InMemoryProposalRegistry()
    else:
        from mcc_proposal import RedisProposalRegistry
        try:
            import redis as _r
            _r.Redis().ping()
        except Exception:
            pytest.skip("no local Redis")
        reg = RedisProposalRegistry.from_url("redis://127.0.0.1:6379/0",
                                             namespace=f"f1b-test:{uuid.uuid4().hex}:")

    async def go():
        kw = dict(tenant_id="t", logical_operation_id="op", binding="b1", action="a",
                  resource=None, payload={})
        r1 = await reg.register(**kw, principal_id="agent/a")
        r2 = await reg.register(**kw, principal_id="agent/b")
        r3 = await reg.register(**kw, principal_id="agent/a")
        r4 = await reg.register(**kw, principal_id=None)
        rec = await reg.get(tenant_id="t", logical_operation_id="op")
        return r1.status, r2.status, r3.status, r4.status, rec.principal_id
    s1, s2, s3, s4, owner = asyncio.run(go())
    assert s1 == ProposalRegisterStatus.REGISTERED
    assert s2 == ProposalRegisterStatus.BINDING_CONFLICT
    assert s3 == ProposalRegisterStatus.IDEMPOTENT_DUPLICATE
    assert s4 == ProposalRegisterStatus.BINDING_CONFLICT       # an unbound caller never shares it
    assert owner == "agent/a"
