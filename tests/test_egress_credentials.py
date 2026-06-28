"""Governed credential references: scope binding, resolution, header injection,
redirect behavior, and redaction. Deterministic (local HTTP echo; no internet)."""

import asyncio
import json
import threading
import time

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request

from egress_proxy.canonical_action import CanonicalActionError, build_canonical_action
from egress_proxy.credentials import (
    CA_BUNDLE, CLIENT_IDENTITY, SECRET_HEADER, CredentialBinding, CredentialEntry,
    CredentialError, CredentialScope, InMemoryCredentialProvider, SecretHeaderCredential,
    build_provider_from_config,
)
from egress_proxy.executor import HTTPEgressExecutor
from egress_proxy.ssrf import DestinationPolicy
from tests._tls_harness import host_resolver

HOST = "egress.test"
SECRET = "Bearer super-secret-token-123"
AUTH = {"decision": "ALLOW", "action": "http.request", "actor_id": "agent/egress"}
run = asyncio.run


def _free_port():
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def _echo_server():
    app = FastAPI()

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def echo(request: Request, path: str):
        return {"headers": {k.lower(): v for k, v in request.headers.items()}}
    port = _free_port()
    threading.Thread(target=lambda: uvicorn.run(app, host="127.0.0.1", port=port,
                                                log_level="error"), daemon=True).start()
    for _ in range(100):
        try:
            httpx.get(f"http://127.0.0.1:{port}/", timeout=0.3); break
        except Exception:
            time.sleep(0.05)
    return port


def _entry(value, *, header="authorization", hosts=(HOST,), methods=("GET",),
           actions=("http.request",), envs=("dev",), **extra):
    binding = CredentialBinding(allowed_hosts=hosts, allowed_methods=methods,
                                allowed_actions=actions, allowed_envs=envs, **extra)
    return CredentialEntry(binding=binding, type=SECRET_HEADER, header_name=header,
                           loader=lambda: value)


def _executor(provider, *, env="dev", max_redirects=0):
    return HTTPEgressExecutor(
        policy=DestinationPolicy(allow_loopback=True, allowed_hosts=frozenset({HOST})),
        resolver=host_resolver({HOST: "127.0.0.1"}), require_https=False, allow_http=True,
        credential_provider=provider, env_name=env, max_redirects=max_redirects)


def _act(port, *, method="GET", credential_ref=None, **refs):
    return build_canonical_action(method=method, url=f"http://{HOST}:{port}/x", headers={},
                                  body=None, credential_ref=credential_ref, **refs)


# ---------------- scope binding (pure) ----------------

def test_binding_permits_and_denies():
    b = CredentialBinding(allowed_hosts=("*.stripe.com",), allowed_ports=(443,),
                          allowed_methods=("POST",), allowed_actions=("http.request",),
                          allowed_envs=("prod",), path_prefix="/v1/")
    ok = CredentialScope(host="api.stripe.com", port=443, method="POST", action="http.request",
                         env="prod", path="/v1/charges")
    assert b.permits(ok) is None
    assert b.permits(CredentialScope("evil.com", 443, "POST", "http.request", "prod", "/v1/"))
    assert b.permits(CredentialScope("api.stripe.com", 80, "POST", "http.request", "prod", "/v1/"))
    assert b.permits(CredentialScope("api.stripe.com", 443, "GET", "http.request", "prod", "/v1/"))
    assert b.permits(CredentialScope("api.stripe.com", 443, "POST", "other", "prod", "/v1/"))
    assert b.permits(CredentialScope("api.stripe.com", 443, "POST", "http.request", "dev", "/v1/"))
    assert b.permits(CredentialScope("api.stripe.com", 443, "POST", "http.request", "prod", "/x"))


def test_empty_allowlists_deny_by_default():
    assert CredentialBinding().permits(
        CredentialScope("a", 1, "GET", "http.request", "dev")) is not None


# ---------------- provider resolution + redaction ----------------

def test_unknown_reference_fails_closed():
    p = InMemoryCredentialProvider({})
    with pytest.raises(CredentialError):
        run(p.resolve("nope", scope=CredentialScope(HOST, 80, "GET", "http.request", "dev"),
                      expected_type=SECRET_HEADER))


def test_type_mismatch_fails_closed():
    p = InMemoryCredentialProvider({"r": _entry(SECRET)})
    with pytest.raises(CredentialError):
        run(p.resolve("r", scope=CredentialScope(HOST, 80, "GET", "http.request", "dev"),
                      expected_type=CLIENT_IDENTITY))


def test_secret_value_not_in_repr_or_str():
    c = SecretHeaderCredential(header_name="authorization", value=SECRET, ref="r")
    assert SECRET not in repr(c) and SECRET not in str(c) and "REDACTED" in repr(c)


def test_config_provider_reads_from_env_not_config():
    cfg = {"credentials": {"api": {"type": "secret_header", "header": "authorization",
                                   "env_var": "MY_SECRET",
                                   "binding": {"allowed_hosts": [HOST], "allowed_methods": ["GET"],
                                               "allowed_actions": ["http.request"],
                                               "allowed_envs": ["dev"]}}}}
    assert "super" not in json.dumps(cfg)  # config carries no secret
    p = build_provider_from_config("env", cfg, env={"MY_SECRET": SECRET})
    c = run(p.resolve("api", scope=CredentialScope(HOST, 80, "GET", "http.request", "dev"),
                      expected_type=SECRET_HEADER))
    assert c.value == SECRET
    # Missing env var -> fail closed.
    p2 = build_provider_from_config("env", cfg, env={})
    with pytest.raises(CredentialError):
        run(p2.resolve("api", scope=CredentialScope(HOST, 80, "GET", "http.request", "dev"),
                       expected_type=SECRET_HEADER))


# ---------------- executor integration: injection + scope ----------------

def test_valid_credential_resolved_and_injected_after_authorization():
    port = _echo_server()
    ex = _executor(InMemoryCredentialProvider({"api": _entry(SECRET)}))
    r = run(ex.execute("http.request", _act(port, credential_ref="api"), authorization=AUTH))
    assert r["executed"] and r["credential_resolved"] is True
    received = json.loads(r["upstream_body"])["headers"]
    assert received["authorization"] == SECRET  # injected, reached upstream


def test_unknown_reference_denies_execution():
    port = _echo_server()
    ex = _executor(InMemoryCredentialProvider({}))
    with pytest.raises(CredentialError):
        run(ex.execute("http.request", _act(port, credential_ref="missing"), authorization=AUTH))
    assert ex.count() == 0


@pytest.mark.parametrize("entry_kw,act_kw", [
    (dict(hosts=("other.test",)), dict()),                 # host out of scope
    (dict(methods=("POST",)), dict(method="GET")),         # method out of scope
    (dict(actions=("other",)), dict()),                    # action out of scope
    (dict(envs=("prod",)), dict()),                        # env out of scope (executor env=dev)
])
def test_out_of_scope_reference_denies(entry_kw, act_kw):
    port = _echo_server()
    ex = _executor(InMemoryCredentialProvider({"api": _entry(SECRET, **entry_kw)}))
    with pytest.raises(CredentialError):
        run(ex.execute("http.request", _act(port, credential_ref="api", **act_kw),
                       authorization=AUTH))
    assert ex.count() == 0


def test_agent_cannot_supply_secret_header():
    with pytest.raises(CanonicalActionError):
        build_canonical_action(method="GET", url=f"http://{HOST}/x",
                               headers={"Authorization": "Bearer agent-supplied"})


def test_no_provider_but_reference_fails_closed():
    port = _echo_server()
    ex = _executor(None)
    with pytest.raises(CredentialError):
        run(ex.execute("http.request", _act(port, credential_ref="api"), authorization=AUTH))
    assert ex.count() == 0


# ---------------- redaction: secret not in proposal/audit/exception ----------------

def test_secret_absent_from_proposal_and_audit_and_exception():
    # Proposal carries only the reference, never the secret.
    action = _act(1234, credential_ref="api")
    assert SECRET not in json.dumps(action) and action["cred_ref"] == "api"

    # Audit metadata records the ref + safe flags, never the value.
    import tempfile, os
    from mcc_core import AuditLog
    port = _echo_server()
    audit = AuditLog(os.path.join(tempfile.mkdtemp(), "a.jsonl"))
    ex = _executor(InMemoryCredentialProvider({"api": _entry(SECRET)}))
    ex.audit = audit
    run(ex.execute("http.request", _act(port, credential_ref="api"), authorization=AUTH))
    blob = open(audit.path).read()
    assert "credential_ref" in blob and "api" in blob and SECRET not in blob

    # Exceptions never carry the secret.
    ex2 = _executor(InMemoryCredentialProvider({"api": _entry(SECRET, hosts=("other.test",))}))
    try:
        run(ex2.execute("http.request", _act(port, credential_ref="api"), authorization=AUTH))
        assert False
    except CredentialError as exc:
        assert SECRET not in str(exc)


# ---------------- redirect credential behavior ----------------

def test_cross_origin_redirect_does_not_forward_credential():
    # Two echo servers (different ports => different origins). First 302s to second.
    second = _echo_server()
    first = FastAPI()

    @first.get("/r")
    async def r():
        from fastapi import Response
        return Response(status_code=302, headers={"location": f"http://{HOST}:{second}/x"})
    fport = _free_port()
    threading.Thread(target=lambda: uvicorn.run(first, host="127.0.0.1", port=fport,
                                                log_level="error"), daemon=True).start()
    for _ in range(100):
        try:
            httpx.get(f"http://127.0.0.1:{fport}/r", timeout=0.3); break
        except Exception:
            time.sleep(0.05)
    # Credential is scoped to BOTH ports so scope isn't the blocker — only the
    # cross-origin rule must strip it.
    ex = _executor(InMemoryCredentialProvider({"api": _entry(
        SECRET, methods=("GET",))}), max_redirects=2)
    # Allow both ports in the binding (host same, ports differ -> different origin).
    ex.credential_provider = InMemoryCredentialProvider({"api": _entry(SECRET)})
    action = build_canonical_action(method="GET", url=f"http://{HOST}:{fport}/r", headers={},
                                    credential_ref="api")
    r = run(ex.execute("http.request", action, authorization=AUTH))
    # The final (cross-origin) destination must NOT have received the credential.
    received = json.loads(r["upstream_body"])["headers"]
    assert "authorization" not in received
