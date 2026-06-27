"""HTTPEgressExecutor — the governed outbound HTTP call (the executor callback).

This is the thing being governed, not a gate. It is reached only from inside
``EnforcementCoordinator.enforce`` (the embedded runtime's one governed path),
after the ``ExecutionGate`` verifies the signed token, consensus/challenge/approval
predicates hold, idempotency/velocity are reserved, and the pre-actuation audit
record is written. It:

* refuses any call lacking the verified decision token for this exact action
  (``UnauthorizedExecution``) — no agent→network shortcut;
* reconstructs the *exact* authorized request from the canonical action;
* re-validates the destination (SSRF) and pins the connection to the validated
  IP (closing the DNS-rebinding window);
* enforces timeouts, no redirects by default, and a response-size cap;
* returns a sanitized response and records what it actually sent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from .canonical_action import HOP_BY_HOP, reconstruct_request
from .ssrf import DestinationPolicy, Resolver, SSRFError, validate_destination

EXECUTABLE = ("ALLOW", "CONSTRAIN")

# Response headers we will not relay back to the caller.
_SENSITIVE_RESPONSE_HEADERS = frozenset({"set-cookie", "set-cookie2"} | HOP_BY_HOP)


class UnauthorizedExecution(Exception):
    """Raised when the executor is invoked without a verified MCC authorization."""


@dataclass
class EgressCall:
    method: str
    url: str
    host: str
    port: int
    pinned_ip: str
    status_code: int
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
    _records: List[EgressCall] = field(default_factory=list, init=False)
    # Sanitized responses keyed by correlation_id, so the proxy can return the
    # upstream result (which the GovernedResult does not carry) without a shared
    # mutable race across concurrent requests.
    _responses: Dict[str, Dict[str, Any]] = field(default_factory=dict, init=False)

    _errors: Dict[str, str] = field(default_factory=dict, init=False)

    def pop_response(self, correlation_id: Optional[str]) -> Optional[Dict[str, Any]]:
        if correlation_id is None:
            return None
        return self._responses.pop(correlation_id, None)

    def pop_error(self, correlation_id: Optional[str]) -> Optional[str]:
        """The upstream failure class for a correlation_id, if the call raised:
        ``UPSTREAM_TIMEOUT`` / ``UPSTREAM_ERROR`` / ``RESPONSE_TOO_LARGE`` / ``DENY``."""
        if correlation_id is None:
            return None
        return self._errors.pop(correlation_id, None)

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

    async def execute(
        self, action: str, authorized_payload: Dict[str, Any], *,
        authorization: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self._is_authorized(authorization, action):
            raise UnauthorizedExecution(
                "egress executor invoked without a verified MCC decision token; refused")

        method, url, headers, body = reconstruct_request(authorized_payload)
        host = authorized_payload["host"]
        port = int(authorized_payload["port"])
        scheme = authorized_payload["scheme"]

        # Re-validate the destination at connect time and pin to the resolved IP.
        try:
            dest = validate_destination(host, port, policy=self.policy, resolver=self.resolver)
        except SSRFError:
            if correlation_id is not None:
                self._errors[correlation_id] = "DENY"
            raise

        # Connect to the pinned IP, preserving the Host header so vhosts/routing
        # still work but DNS cannot be rebound between validation and connect.
        netloc = host if port in (80, 443) else f"{host}:{port}"
        connect_host = dest.pinned_ip
        connect_netloc = connect_host if port in (80, 443) else f"{connect_host}:{port}"
        path_and_query = url.split(f"{scheme}://{netloc}", 1)[-1] or "/"
        pinned_url = f"{scheme}://{connect_netloc}{path_and_query}"
        send_headers = {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}
        send_headers["host"] = netloc

        timeout = httpx.Timeout(self.total_timeout, connect=self.connect_timeout,
                                read=self.read_timeout)
        status_code = 0
        sanitized_headers: Dict[str, str] = {}
        content = b""
        truncated = False
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                kwargs: Dict[str, Any] = {"headers": send_headers}
                if isinstance(body, dict):
                    kwargs["json"] = body
                elif isinstance(body, (bytes, bytearray)):
                    kwargs["content"] = bytes(body)
                request = client.build_request(method, pinned_url, **kwargs)
                resp = await client.send(request, stream=True)
                try:
                    status_code = resp.status_code
                    sanitized_headers = {
                        k: v for k, v in resp.headers.items()
                        if k.lower() not in _SENSITIVE_RESPONSE_HEADERS
                    }
                    async for chunk in resp.aiter_bytes():
                        content += chunk
                        if len(content) > self.max_response_bytes:
                            truncated = True
                            content = content[: self.max_response_bytes]
                            break
                finally:
                    await resp.aclose()
        except httpx.TimeoutException:
            if correlation_id is not None:
                self._errors[correlation_id] = "UPSTREAM_TIMEOUT"
            raise
        except httpx.HTTPError:
            if correlation_id is not None:
                self._errors[correlation_id] = "UPSTREAM_ERROR"
            raise

        self._records.append(EgressCall(
            method=method, url=url, host=host, port=port, pinned_ip=dest.pinned_ip,
            status_code=status_code,
            audit_ref=authorization.get("audit_ref") if isinstance(authorization, dict) else None,
            correlation_id=correlation_id,
            transaction_id=authorization.get("transaction_id") if isinstance(authorization, dict) else None,
            authorized_action_hash=authorization.get("payload_hash") if isinstance(authorization, dict) else None,
        ))
        try:
            decoded: Any = content.decode("utf-8")
        except Exception:  # noqa: BLE001
            import base64
            decoded = {"_b64": base64.b64encode(content).decode("ascii")}
        response = {
            "executed": True,
            "upstream_status": status_code,
            "upstream_headers": sanitized_headers,
            "upstream_body": decoded,
            "truncated": truncated,
            "pinned_ip": dest.pinned_ip,
        }
        if correlation_id is not None:
            self._responses[correlation_id] = response
        return response

    @staticmethod
    def _is_authorized(token: Any, action: str) -> bool:
        if not isinstance(token, dict):
            return False
        if token.get("decision") not in EXECUTABLE:
            return False
        if token.get("action") != action:
            return False
        return True
