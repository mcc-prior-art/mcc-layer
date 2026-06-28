"""Secure HTTPS transport for the governed egress executor.

The hard part of safe egress is connecting to a *pre-validated* IP while still
performing TLS against the *original hostname*. This module provides:

* :func:`build_ssl_context` — a strict client context (verify chain + hostname,
  TLS 1.2+); never ``verify=False``;
* :class:`PinnedBackend` — an httpcore network backend that connects only to the
  approved pinned IP (ignoring any second DNS lookup), preserves the hostname for
  SNI/certificate verification (httpcore calls ``start_tls`` with the origin
  host), captures the connected peer IP, and fails closed on a peer-IP mismatch;
* :func:`build_pinned_transport` — wires the backend + context into an httpx
  transport;
* :func:`validate_redirect` / :func:`strip_cross_origin_headers` — hop-by-hop
  redirect safety.
"""

from __future__ import annotations

import ipaddress
import ssl
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx

from .ssrf import DestinationPolicy, Resolver, SSRFError, validate_destination

try:  # the async backend lives in a private path but is stable across httpcore 1.x
    from httpcore._backends.anyio import AnyIOBackend
except Exception:  # pragma: no cover - fallback
    from httpcore import AnyIOBackend  # type: ignore

DEFAULT_GOVERNED_API_KEY_HEADERS = ("x-api-key", "x-operator-key", "api-key")
SENSITIVE_REDIRECT_HEADERS = ("authorization", "proxy-authorization", "cookie")


def _norm_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return ip


def build_ssl_context(*, ca_file: Optional[str] = None, capath: Optional[str] = None,
                      minimum_tls: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2) -> ssl.SSLContext:
    """A strict TLS client context. With ``ca_file`` it trusts exactly that CA
    (deterministic test roots); otherwise the system trust store. Hostname and
    chain verification are mandatory; TLS floor is 1.2."""
    ctx = ssl.create_default_context(cafile=ca_file, capath=capath)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        ctx.minimum_version = minimum_tls
    except (ValueError, OSError):  # pragma: no cover - platform dependent
        pass
    return ctx


class PinnedBackend(httpcore.AsyncNetworkBackend):
    """Connect ONLY to the approved pinned IP; preserve hostname for TLS."""

    def __init__(self, pinned_ip: str, approved_ips: Iterable[str], capture: Dict[str, Any]) -> None:
        self._inner = AnyIOBackend()
        self._pinned_ip = pinned_ip
        self._approved = {_norm_ip(ip) for ip in approved_ips}
        self._capture = capture

    async def connect_tcp(self, host: str, port: int, timeout: Optional[float] = None,
                          local_address: Optional[str] = None, socket_options=None):
        # Ignore the requested host (and any second DNS lookup the client would do)
        # — connect to the pre-validated pinned IP only.
        stream = await self._inner.connect_tcp(
            self._pinned_ip, port, timeout=timeout, local_address=local_address,
            socket_options=socket_options)
        peer_ip = self._peer_ip(stream) or self._pinned_ip
        if _norm_ip(peer_ip) not in self._approved:
            await stream.aclose()
            raise httpcore.ConnectError(f"peer IP {peer_ip} not in approved set; fail-closed")
        self._capture["peer_ip"] = _norm_ip(peer_ip)
        self._capture["stream"] = stream
        return stream

    async def connect_unix_socket(self, *args, **kwargs):  # pragma: no cover
        raise httpcore.ConnectError("unix socket egress not permitted")

    async def sleep(self, seconds: float) -> None:  # pragma: no cover
        await self._inner.sleep(seconds)

    @staticmethod
    def _peer_ip(stream) -> Optional[str]:
        for key in ("server_addr",):
            try:
                info = stream.get_extra_info(key)
                if info:
                    return info[0]
            except Exception:  # noqa: BLE001
                pass
        for key in ("raw_socket", "socket"):
            try:
                sock = stream.get_extra_info(key)
                if sock is not None:
                    return sock.getpeername()[0]
            except Exception:  # noqa: BLE001
                pass
        return None


def build_pinned_transport(*, pinned_ip: str, approved_ips: Iterable[str],
                           ssl_context: ssl.SSLContext, capture: Dict[str, Any]
                           ) -> httpx.AsyncHTTPTransport:
    """An httpx transport whose connection pool dials only the pinned IP and
    performs TLS against the original hostname (no auto-retries, no HTTP/2)."""
    pool = httpcore.AsyncConnectionPool(
        ssl_context=ssl_context,
        network_backend=PinnedBackend(pinned_ip, approved_ips, capture),
        retries=0, http1=True, http2=False)
    transport = httpx.AsyncHTTPTransport()
    transport._pool = pool  # inject the pinned pool (stable in httpx 1.x/0.28)
    return transport


def tls_info(response: httpx.Response) -> Dict[str, Any]:
    """Negotiated TLS facts for the audit trail (no secrets)."""
    try:
        stream = response.extensions.get("network_stream")
        ssl_obj = stream.get_extra_info("ssl_object") if stream is not None else None
        if ssl_obj is None:
            return {"tls": False}
        return {"tls": True, "tls_version": ssl_obj.version(),
                "cipher": (ssl_obj.cipher() or (None,))[0]}
    except Exception:  # noqa: BLE001
        return {"tls": None}


class RedirectError(SSRFError):
    """A redirect target failed validation (subclass of SSRFError -> fail-closed)."""


def validate_redirect(current_url: str, location: str, *, policy: DestinationPolicy,
                      require_https: bool, resolver: Optional[Resolver] = None) -> str:
    """Validate a redirect hop and return the absolute target URL.

    Re-applies scheme/SSRF/DNS validation to the new destination and rejects an
    HTTPS->HTTP downgrade. Fail-closed (raises) on any violation."""
    target = urljoin(current_url, location)
    cur = urlsplit(current_url)
    new = urlsplit(target)
    scheme = (new.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise RedirectError(f"redirect to unsupported scheme {scheme!r}")
    if cur.scheme.lower() == "https" and scheme == "http":
        raise RedirectError("HTTPS->HTTP downgrade redirect rejected")
    if require_https and scheme != "https":
        raise RedirectError("redirect to non-HTTPS rejected")
    if new.username or new.password or "@" in (new.netloc or ""):
        raise RedirectError("redirect URL contains embedded credentials")
    host = (new.hostname or "").lower()
    if not host:
        raise RedirectError("redirect URL has no host")
    port = new.port or (443 if scheme == "https" else 80)
    # Re-resolve + re-validate the new destination (SSRF, DNS rebinding defence).
    validate_destination(host, int(port), policy=policy, resolver=resolver)
    return target


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    pa_port = pa.port or (443 if pa.scheme == "https" else 80)
    pb_port = pb.port or (443 if pb.scheme == "https" else 80)
    return (pa.scheme.lower(), (pa.hostname or "").lower(), pa_port) == \
           (pb.scheme.lower(), (pb.hostname or "").lower(), pb_port)


def strip_cross_origin_headers(headers: Dict[str, str], from_url: str, to_url: str, *,
                               api_key_headers: Tuple[str, ...] = DEFAULT_GOVERNED_API_KEY_HEADERS
                               ) -> Dict[str, str]:
    """On a cross-origin redirect, drop sensitive headers (Authorization,
    Proxy-Authorization, Cookie, configured API-key headers)."""
    if same_origin(from_url, to_url):
        return dict(headers)
    drop = {h.lower() for h in SENSITIVE_REDIRECT_HEADERS} | {h.lower() for h in api_key_headers}
    return {k: v for k, v in headers.items() if k.lower() not in drop}
