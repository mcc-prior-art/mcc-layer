"""HTTPS hardening of the governed egress executor: TLS verification, HTTPS-only,
IP pinning + peer verification. Deterministic, offline (local CA + HTTPS servers).
"""

import asyncio
import datetime
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, Request

from egress_proxy.canonical_action import build_canonical_action
from egress_proxy.executor import HTTPEgressExecutor, SchemeError
from egress_proxy.secure_transport import PinnedBackend
from egress_proxy.ssrf import DestinationPolicy, SSRFError
from tests._tls_harness import (
    DAY, _now, host_resolver, make_ca, make_leaf, serve_https, write_ca_bundle,
    write_cert_and_key,
)

HOST = "egress.test"
AUTH = {"decision": "ALLOW", "action": "http.request", "transaction_id": "t",
        "audit_ref": "a", "payload_hash": "h"}
run = asyncio.run


def _app():
    app = FastAPI()

    @app.api_route("/{p:path}", methods=["GET", "POST"])
    async def ok(request: Request, p: str):
        return {"ok": True, "path": p}

    return app


def _executor(ca_file, *, allowed_hosts=(HOST,), max_redirects=0, allow_http=False,
              resolver_map=None):
    return HTTPEgressExecutor(
        policy=DestinationPolicy(allow_loopback=True, allowed_hosts=frozenset(allowed_hosts)),
        resolver=host_resolver(resolver_map or {HOST: "127.0.0.1"}),
        tls_ca_file=ca_file, require_https=True, allow_http=allow_http,
        max_redirects=max_redirects)


def _act(url, *, method="GET", body=None):
    return build_canonical_action(method=method, url=url, headers={}, body=body)


def _serve_valid(tmp_path: Path, hostname=HOST, **leaf_kw):
    ca_key, ca_cert = make_ca()
    key, cert = make_leaf(ca_key, ca_cert, hostname, **leaf_kw)
    certfile, keyfile = write_cert_and_key(tmp_path, cert, key, prefix="leaf")
    ca_file = write_ca_bundle(tmp_path, ca_cert)
    port = serve_https(_app(), certfile, keyfile)
    return ca_file, port


# ---------------- valid HTTPS ----------------

def test_valid_trusted_https_executes(tmp_path):
    ca_file, port = _serve_valid(tmp_path)
    ex = _executor(ca_file)
    r = run(ex.execute("http.request", _act(f"https://{HOST}:{port}/charge"), authorization=AUTH))
    assert r["executed"] and r["upstream_status"] == 200
    assert r["tls_validated"] is True and r["peer_ip"] == "127.0.0.1"
    assert (r.get("tls_version") or "").startswith("TLS")
    assert ex.count() == 1


# ---------------- HTTPS-only ----------------

def test_http_rejected_in_production(tmp_path):
    ca_file, port = _serve_valid(tmp_path)
    ex = _executor(ca_file)  # allow_http=False
    with pytest.raises(SchemeError):
        run(ex.execute("http.request", _act(f"http://{HOST}:{port}/x"), authorization=AUTH))
    assert ex.count() == 0


def test_http_allowed_only_with_explicit_override(tmp_path):
    # An ordinary HTTP echo (no TLS) reached only because allow_http=True.
    from tests._egress_harness import _free_port
    import threading, time, uvicorn
    app = FastAPI()

    @app.get("/{p:path}")
    async def ok(p: str):
        return {"ok": True}
    port = _free_port()
    threading.Thread(target=lambda: uvicorn.run(app, host="127.0.0.1", port=port,
                                                log_level="error"), daemon=True).start()
    for _ in range(100):
        try:
            httpx.get(f"http://127.0.0.1:{port}/", timeout=0.3); break
        except Exception:
            time.sleep(0.05)
    ex = _executor(None, allow_http=True)
    r = run(ex.execute("http.request", _act(f"http://{HOST}:{port}/x"), authorization=AUTH))
    assert r["executed"] and r["upstream_status"] == 200


# ---------------- bad certificates ----------------

def test_expired_certificate_rejected(tmp_path):
    ca_file, port = _serve_valid(tmp_path, not_before=_now() - 2 * DAY, not_after=_now() - DAY)
    ex = _executor(ca_file)
    with pytest.raises(httpx.HTTPError):
        run(ex.execute("http.request", _act(f"https://{HOST}:{port}/x"), authorization=AUTH))
    assert ex.count() == 0


def test_self_signed_certificate_rejected(tmp_path):
    ca_key, ca_cert = make_ca()
    key, cert = make_leaf(ca_key, ca_cert, HOST, self_signed=True)
    certfile, keyfile = write_cert_and_key(tmp_path, cert, key, prefix="ss")
    ca_file = write_ca_bundle(tmp_path, ca_cert)  # trusts the CA, not the self-signed leaf
    port = serve_https(_app(), certfile, keyfile)
    ex = _executor(ca_file)
    with pytest.raises(httpx.HTTPError):
        run(ex.execute("http.request", _act(f"https://{HOST}:{port}/x"), authorization=AUTH))
    assert ex.count() == 0


def test_untrusted_ca_rejected(tmp_path):
    # Server cert signed by CA-A; executor trusts CA-B only.
    ca_a_key, ca_a_cert = make_ca()
    key, cert = make_leaf(ca_a_key, ca_a_cert, HOST)
    certfile, keyfile = write_cert_and_key(tmp_path, cert, key, prefix="a")
    _, ca_b_cert = make_ca()
    ca_b_file = write_ca_bundle(tmp_path, ca_b_cert)
    port = serve_https(_app(), certfile, keyfile)
    ex = _executor(ca_b_file)
    with pytest.raises(httpx.HTTPError):
        run(ex.execute("http.request", _act(f"https://{HOST}:{port}/x"), authorization=AUTH))
    assert ex.count() == 0


def test_wrong_host_certificate_rejected(tmp_path):
    # Cert is valid + trusted but issued for a different hostname -> SNI/hostname mismatch.
    ca_key, ca_cert = make_ca()
    key, cert = make_leaf(ca_key, ca_cert, "wrong.test")
    certfile, keyfile = write_cert_and_key(tmp_path, cert, key, prefix="wh")
    ca_file = write_ca_bundle(tmp_path, ca_cert)
    port = serve_https(_app(), certfile, keyfile)
    ex = _executor(ca_file)
    with pytest.raises(httpx.HTTPError):
        run(ex.execute("http.request", _act(f"https://{HOST}:{port}/x"), authorization=AUTH))
    assert ex.count() == 0


# ---------------- IP pinning / peer verification ----------------

def test_peer_ip_mismatch_fails_closed():
    # The backend connects to a pinned IP but approves a different set -> reject.
    backend = PinnedBackend("127.0.0.1", {"203.0.113.7"}, {})
    import socket as _s
    import threading
    # A plain TCP listener on a free loopback port.
    srv = _s.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    threading.Thread(target=lambda: srv.accept(), daemon=True).start()
    import httpcore
    with pytest.raises(httpcore.ConnectError):
        run(backend.connect_tcp("example.test", port, timeout=2.0))
    srv.close()


def test_mixed_public_and_loopback_dns_rejected():
    ex = HTTPEgressExecutor(
        policy=DestinationPolicy(allowed_hosts=frozenset({HOST})),  # loopback NOT allowed
        resolver=lambda h, p: [(2, "93.184.216.34"), (2, "127.0.0.1")],
        tls_ca_file=None, require_https=True)
    with pytest.raises(SSRFError):
        run(ex.execute("http.request", _act(f"https://{HOST}/x"), authorization=AUTH))
    assert ex.count() == 0
