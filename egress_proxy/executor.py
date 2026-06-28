"""HTTPEgressExecutor — the governed outbound HTTP(S) call (the executor callback).

This is the thing being governed, not a gate. It is reached only from inside
``EnforcementCoordinator.enforce`` (the embedded runtime's one governed path),
after the ``ExecutionGate`` verifies the signed token, consensus/challenge/approval
predicates hold, idempotency/velocity are reserved, and the pre-actuation audit
record is written. It:

* refuses any call lacking the verified decision token for this exact action
  (``UnauthorizedExecution``) — no agent→network shortcut;
* enforces HTTPS-only in production (HTTP only when explicitly enabled for tests);
* reconstructs the *exact* authorized request from the canonical action;
* re-validates the destination (SSRF), resolves + pins to a validated IP,
  preserves the hostname for TLS SNI/verification, and refuses a peer-IP mismatch
  (DNS-rebinding defence);
* enforces strict TLS (verify chain + hostname, TLS 1.2+); never ``verify=False``;
* disables automatic redirects; any followed hop (when explicitly enabled) is
  re-validated and cross-origin sensitive headers are stripped;
* enforces timeouts and a response-size cap;
* extends the audit chain with safe execution metadata (no secrets).
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import httpx

from .canonical_action import HOP_BY_HOP, reconstruct_request
from .secure_transport import (
    DEFAULT_GOVERNED_API_KEY_HEADERS,
    build_pinned_transport,
    build_ssl_context,
    strip_cross_origin_headers,
    tls_info,
    validate_redirect,
)
from .ssrf import DestinationPolicy, Resolver, SSRFError, validate_destination

EXECUTABLE = ("ALLOW", "CONSTRAIN")
_REDIRECT_CODES = (301, 302, 303, 307, 308)

# Response headers we will not relay back to the caller.
_SENSITIVE_RESPONSE_HEADERS = frozenset({"set-cookie", "set-cookie2"} | HOP_BY_HOP)


class UnauthorizedExecution(Exception):
    """Raised when the executor is invoked without a verified MCC authorization."""


class SchemeError(SSRFError):
    """A disallowed URL scheme (e.g. HTTP in HTTPS-only production)."""


@dataclass
class EgressCall:
    method: str
    url: str
    host: str
    port: int
    pinned_ip: str
    peer_ip: Optional[str]
    status_code: int
    tls_validated: Optional[bool]
    redirect_chain: List[Dict[str, Any]]
    final_url: str
    audit_ref: Optional[str]
    correlation_id: Optional[str]
    transaction_id: Optional[str]
    authorized_action_hash: Optional[str]


@dataclass
class HTTPEgressExecutor:
    policy: DestinationPolicy = field(default_factory=DestinationPolicy)
    connect_timeout: float = 2.0
    read_timeout: float = 5.0
    total_timeout: float = 8.0
    max_response_bytes: int = 1 * 1024 * 1024
    resolver: Optional[Resolver] = None
    # TLS / scheme posture.
    require_https: bool = True
    allow_http: bool = False                 # test/dev override; never in production
    tls_ca_file: Optional[str] = None        # trust exactly this CA (tests); else system roots
    tls_min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2
    # Redirects: disabled by default (the governed action is one request). When a
    # positive cap is set, each hop is re-validated and cross-origin creds stripped.
    max_redirects: int = 0
    api_key_headers: Tuple[str, ...] = DEFAULT_GOVERNED_API_KEY_HEADERS
    audit: Optional[Any] = None              # AuditLog instance (shared with the runtime)

    _records: List[EgressCall] = field(default_factory=list, init=False)
    _responses: Dict[str, Dict[str, Any]] = field(default_factory=dict, init=False)
    _errors: Dict[str, str] = field(default_factory=dict, init=False)

    # ---- accessors used by the proxy/tests ----

    def pop_response(self, correlation_id: Optional[str]) -> Optional[Dict[str, Any]]:
        return None if correlation_id is None else self._responses.pop(correlation_id, None)

    def pop_error(self, correlation_id: Optional[str]) -> Optional[str]:
        return None if correlation_id is None else self._errors.pop(correlation_id, None)

    @property
    def calls(self) -> List[EgressCall]:
        return list(self._records)

    @property
    def executed(self) -> bool:
        return bool(self._records)

    def count(self) -> int:
        return len(self._records)

    def last(self) -> Optional[EgressCall]:
        return self._records[-1] if self._records else None

    # ---- the governed call ----

    async def execute(
        self, action: str, authorized_payload: Dict[str, Any], *,
        authorization: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self._is_authorized(authorization, action):
            raise UnauthorizedExecution(
                "egress executor invoked without a verified MCC decision token; refused")

        method, url, headers, body = reconstruct_request(authorized_payload)
        send_headers = {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}

        try:
            result = await self._run_with_redirects(method, url, send_headers, body)
        except (SSRFError, SchemeError):
            if correlation_id is not None:
                self._errors[correlation_id] = "DENY"
            self._audit_metadata(authorization, method, url, status=0, outcome="DENY_SSRF")
            raise
        except httpx.TimeoutException:
            if correlation_id is not None:
                self._errors[correlation_id] = "UPSTREAM_TIMEOUT"
            self._audit_metadata(authorization, method, url, status=0, outcome="UPSTREAM_TIMEOUT")
            raise
        except httpx.HTTPError:
            if correlation_id is not None:
                self._errors[correlation_id] = "UPSTREAM_ERROR"
            self._audit_metadata(authorization, method, url, status=0, outcome="UPSTREAM_ERROR")
            raise

        self._records.append(EgressCall(
            method=method, url=url, host=result["host"], port=result["port"],
            pinned_ip=result["pinned_ip"], peer_ip=result["peer_ip"],
            status_code=result["status"], tls_validated=result["tls_validated"],
            redirect_chain=result["redirect_chain"], final_url=result["final_url"],
            audit_ref=_g(authorization, "audit_ref"), correlation_id=correlation_id,
            transaction_id=_g(authorization, "transaction_id"),
            authorized_action_hash=_g(authorization, "payload_hash")))

        self._audit_metadata(authorization, method, url, status=result["status"],
                             outcome="EXECUTED", result=result)

        response = {
            "executed": True,
            "upstream_status": result["status"],
            "upstream_headers": result["headers"],
            "upstream_body": result["body"],
            "truncated": result["truncated"],
            "pinned_ip": result["pinned_ip"],
            "peer_ip": result["peer_ip"],
            "tls_validated": result["tls_validated"],
            "tls_version": result.get("tls_version"),
            "redirect_chain": result["redirect_chain"],
            "final_url": result["final_url"],
        }
        if correlation_id is not None:
            self._responses[correlation_id] = response
        return response

    async def _run_with_redirects(self, method: str, url: str, headers: Dict[str, str],
                                  body: Any) -> Dict[str, Any]:
        current_url = url
        current_method = method
        current_headers = dict(headers)
        current_body: Any = body
        visited = {url}
        chain: List[Dict[str, Any]] = []
        resolved_ips: List[str] = []
        pinned_ip = peer_ip = ""
        tls_validated: Optional[bool] = None
        tls_version: Optional[str] = None

        for _hop in range(self.max_redirects + 1):
            parts = urlsplit(current_url)
            scheme = (parts.scheme or "").lower()
            if scheme not in ("http", "https"):
                raise SchemeError(f"unsupported scheme {scheme!r}")
            if scheme != "https" and not self.allow_http:
                raise SchemeError("HTTPS required; HTTP rejected (production)")
            host = (parts.hostname or "").lower()
            port = parts.port or (443 if scheme == "https" else 80)

            dest = validate_destination(host, int(port), policy=self.policy,
                                        resolver=self.resolver)
            resolved_ips, pinned_ip = dest.ips, dest.pinned_ip

            status, hdrs, content, truncated, peer_ip, tls_validated, tls_version, location = \
                await self._send_once(current_method, current_url, current_headers, current_body,
                                      scheme, dest)

            if (status in _REDIRECT_CODES and location and _hop < self.max_redirects):
                target = validate_redirect(current_url, location, policy=self.policy,
                                           require_https=(self.require_https and not self.allow_http),
                                           resolver=self.resolver)
                if target in visited:
                    raise SSRFError("redirect loop detected; fail-closed")
                current_headers = strip_cross_origin_headers(
                    current_headers, current_url, target, api_key_headers=self.api_key_headers)
                # 303 (and conventionally 301/302) -> GET without body; 307/308 preserve.
                if status in (301, 302, 303):
                    current_method, current_body = "GET", None
                chain.append({"from": current_url, "to": target, "status": status})
                visited.add(target)
                current_url = target
                continue

            return {
                "host": host, "port": int(port), "pinned_ip": pinned_ip, "peer_ip": peer_ip,
                "resolved_ips": resolved_ips, "status": status, "headers": hdrs,
                "body": content, "truncated": truncated, "tls_validated": tls_validated,
                "tls_version": tls_version, "redirect_chain": chain, "final_url": current_url}

        raise SSRFError(f"too many redirects (> {self.max_redirects}); fail-closed")

    async def _send_once(self, method: str, url: str, headers: Dict[str, str], body: Any,
                         scheme: str, dest) -> Tuple:
        capture: Dict[str, Any] = {}
        ssl_context = build_ssl_context(ca_file=self.tls_ca_file, minimum_tls=self.tls_min_version)
        transport = build_pinned_transport(pinned_ip=dest.pinned_ip, approved_ips=dest.ips,
                                           ssl_context=ssl_context, capture=capture)
        timeout = httpx.Timeout(self.total_timeout, connect=self.connect_timeout,
                                read=self.read_timeout)
        content = b""
        truncated = False
        tls_validated: Optional[bool] = None
        tls_version: Optional[str] = None
        async with httpx.AsyncClient(transport=transport, timeout=timeout,
                                     follow_redirects=False) as client:
            kwargs: Dict[str, Any] = {"headers": headers}
            if isinstance(body, dict):
                kwargs["json"] = body
            elif isinstance(body, (bytes, bytearray)):
                kwargs["content"] = bytes(body)
            request = client.build_request(method, url, **kwargs)
            resp = await client.send(request, stream=True)
            try:
                status_code = resp.status_code
                sanitized = {k: v for k, v in resp.headers.items()
                             if k.lower() not in _SENSITIVE_RESPONSE_HEADERS}
                location = resp.headers.get("location")
                if scheme == "https":
                    info = tls_info(resp)
                    tls_validated = info.get("tls") is True
                    tls_version = info.get("tls_version")
                async for chunk in resp.aiter_bytes():
                    content += chunk
                    if len(content) > self.max_response_bytes:
                        truncated = True
                        content = content[: self.max_response_bytes]
                        break
            finally:
                await resp.aclose()
        peer_ip = capture.get("peer_ip", dest.pinned_ip)
        try:
            decoded: Any = content.decode("utf-8")
        except Exception:  # noqa: BLE001
            import base64
            decoded = {"_b64": base64.b64encode(content).decode("ascii")}
        return (status_code, sanitized, decoded, truncated, peer_ip, tls_validated,
                tls_version, location)

    def _audit_metadata(self, authorization, method: str, url: str, *, status: int,
                        outcome: str, result: Optional[Dict[str, Any]] = None) -> None:
        """Append safe egress execution metadata to the existing audit chain.

        Post-actuation only (the durable pre-actuation record is the coordinator's
        responsibility and already happened). Never logs secrets/headers/bodies."""
        if self.audit is None:
            return
        parts = urlsplit(url)
        entry = {
            "kind": "egress_execution",
            "method": method,
            "url": f"{parts.scheme}://{parts.hostname}{parts.path}",
            "host": (parts.hostname or "").lower(),
            "port": parts.port or (443 if parts.scheme == "https" else 80),
            "outcome": outcome,
            "status": status,
            "audit_ref": _g(authorization, "audit_ref"),
            "transaction_id": _g(authorization, "transaction_id"),
            "authorized_action_hash": _g(authorization, "payload_hash"),
        }
        if result is not None:
            entry.update({
                "resolved_ips": result.get("resolved_ips"),
                "selected_ip": result.get("pinned_ip"),
                "peer_ip": result.get("peer_ip"),
                "tls_validated": result.get("tls_validated"),
                "tls_version": result.get("tls_version"),
                "redirect_chain": [h.get("status") for h in result.get("redirect_chain", [])],
                "final_destination": result.get("final_url"),
            })
        try:
            self.audit.append(entry)
        except Exception:  # noqa: BLE001 — best-effort post-actuation metadata
            pass

    @staticmethod
    def _is_authorized(token: Any, action: str) -> bool:
        if not isinstance(token, dict):
            return False
        if token.get("decision") not in EXECUTABLE:
            return False
        if token.get("action") != action:
            return False
        return True


def _g(token: Any, key: str) -> Optional[Any]:
    return token.get(key) if isinstance(token, dict) else None
