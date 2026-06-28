"""Safe redirect handling: per-hop re-validation, downgrade/private rejection,
loop + max-redirect bounds, and cross-origin sensitive-header stripping.
"""

import asyncio
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, Request, Response

from egress_proxy.canonical_action import build_canonical_action
from egress_proxy.executor import HTTPEgressExecutor
from egress_proxy.secure_transport import (
    RedirectError, same_origin, strip_cross_origin_headers, validate_redirect,
)
from egress_proxy.ssrf import DestinationPolicy, SSRFError
from tests._tls_harness import (
    host_resolver, make_ca, make_leaf, serve_https, write_ca_bundle, write_cert_and_key,
)

HOST = "egress.test"
AUTH = {"decision": "ALLOW", "action": "http.request"}
run = asyncio.run
POL = DestinationPolicy(allow_loopback=True, allowed_hosts=frozenset({HOST}))
RES = host_resolver({HOST: "127.0.0.1"})


# ---------------- validate_redirect (pure) ----------------

def test_redirect_https_to_http_downgrade_rejected():
    with pytest.raises(RedirectError, match="downgrade"):
        validate_redirect(f"https://{HOST}/a", f"http://{HOST}/b", policy=POL,
                          require_https=True, resolver=RES)


def test_redirect_requires_https_when_required():
    with pytest.raises(RedirectError):
        validate_redirect(f"https://{HOST}/a", "http://other.test/b", policy=POL,
                          require_https=True, resolver=RES)


def test_redirect_to_private_literal_rejected():
    with pytest.raises(SSRFError):
        validate_redirect(f"https://{HOST}/a", "https://10.0.0.1/b", policy=POL,
                          require_https=True, resolver=RES)


def test_redirect_to_loopback_rejected_by_default():
    pol = DestinationPolicy(allowed_hosts=None)  # default: loopback denied
    with pytest.raises(SSRFError):
        validate_redirect("https://pub.test/a", "https://127.0.0.1/b", policy=pol,
                          require_https=True)


def test_redirect_embedded_credentials_rejected():
    with pytest.raises(RedirectError):
        validate_redirect(f"https://{HOST}/a", f"https://user:pw@{HOST}/b", policy=POL,
                          require_https=True, resolver=RES)


def test_redirect_relative_resolved_and_allowed():
    target = validate_redirect(f"https://{HOST}:8443/a/b", "/c", policy=POL,
                               require_https=True, resolver=RES)
    assert target == f"https://{HOST}:8443/c"


# ---------------- header stripping ----------------

def test_same_origin_keeps_headers():
    h = {"authorization": "secret", "cookie": "c", "content-type": "json"}
    out = strip_cross_origin_headers(h, "https://a.test/x", "https://a.test/y")
    assert out == h


def test_cross_origin_strips_sensitive_headers():
    h = {"authorization": "secret", "proxy-authorization": "p", "cookie": "c",
         "x-api-key": "k", "x-operator-key": "o", "content-type": "json"}
    out = strip_cross_origin_headers(h, "https://a.test/x", "https://b.test/y")
    assert out == {"content-type": "json"}


def test_same_origin_helper():
    assert same_origin("https://a.test/x", "https://a.test:443/y")
    assert not same_origin("https://a.test/x", "https://a.test:8443/y")
    assert not same_origin("https://a.test/x", "https://b.test/y")


# ---------------- integration (live HTTPS redirect server) ----------------

def _redirect_app():
    app = FastAPI()

    @app.get("/loop")
    async def loop():
        return Response(status_code=302, headers={"location": "/loop"})

    @app.get("/downgrade")
    async def downgrade(request: Request):
        # Redirect to plain HTTP on the same authority -> must be rejected.
        base = str(request.base_url).replace("https://", "http://").rstrip("/")
        return Response(status_code=302, headers={"location": f"{base}/final"})

    @app.get("/final")
    async def final():
        return {"ok": True}

    return app


def _serve(tmp_path: Path):
    ca_key, ca_cert = make_ca()
    key, cert = make_leaf(ca_key, ca_cert, HOST)
    certfile, keyfile = write_cert_and_key(tmp_path, cert, key, prefix="leaf")
    ca_file = write_ca_bundle(tmp_path, ca_cert)
    return ca_file, serve_https(_redirect_app(), certfile, keyfile)


def _executor(ca_file, *, max_redirects):
    return HTTPEgressExecutor(policy=POL, resolver=RES, tls_ca_file=ca_file,
                              require_https=True, max_redirects=max_redirects)


def _act(url):
    return build_canonical_action(method="GET", url=url, headers={}, body=None)


def test_redirect_disabled_by_default_returns_3xx(tmp_path):
    ca_file, port = _serve(tmp_path)
    ex = _executor(ca_file, max_redirects=0)
    r = run(ex.execute("http.request", _act(f"https://{HOST}:{port}/loop"), authorization=AUTH))
    assert r["upstream_status"] == 302 and r["redirect_chain"] == []  # not followed


def test_redirect_loop_detected(tmp_path):
    ca_file, port = _serve(tmp_path)
    ex = _executor(ca_file, max_redirects=3)
    with pytest.raises(SSRFError, match="loop"):
        run(ex.execute("http.request", _act(f"https://{HOST}:{port}/loop"), authorization=AUTH))
    assert ex.count() == 0


def test_redirect_https_to_http_downgrade_blocked_live(tmp_path):
    ca_file, port = _serve(tmp_path)
    ex = _executor(ca_file, max_redirects=2)
    with pytest.raises(SSRFError):
        run(ex.execute("http.request", _act(f"https://{HOST}:{port}/downgrade"), authorization=AUTH))
    assert ex.count() == 0
