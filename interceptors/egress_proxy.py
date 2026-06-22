#!/usr/bin/env python3
"""MCC-Core egress proxy — the one interceptor.

The honest truth, stated up front (read ``docs/MVP_GATEWAY.md`` for the full
version): a decorator or a webhook step is *opt-in on every action*. An agent
can simply not call you on the dangerous step, and then you are a
recommendation, not enforcement. DENY means DENY only when you own the
execution path. This interceptor owns the path: the agent's outbound calls
physically pass through it, so a DENY is a connection that never opens.

    agent --HTTP--> [ MCC egress proxy ] --HTTP--> upstream
                          |
                          +-- POST /evaluate {identity, action, context}
                          +-- ALLOW / CONSTRAIN  -> forward (carry token)
                          +-- DENY  / ESCALATE   -> 403, upstream never reached

The governing logic is kept free of sockets so it can be tested directly:

* ``ActionMapper``   turns an outbound request into ``(action, context)``.
* ``EgressGovernor`` asks the gateway and returns an enforcement outcome.
* ``build_proxy_app`` wraps both in a forwarding ASGI app.
"""

from __future__ import annotations

import fnmatch
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcc_core import (  # noqa: E402
    ExecutionGate,
    InMemoryNonceRegistry,
    public_key_from_b64,
)


@dataclass(frozen=True)
class OutboundRequest:
    """The part of an intercepted call MCC needs to reason about."""

    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Dict[str, Any] = field(default_factory=dict)

    @property
    def host(self) -> str:
        return urlparse(self.url).netloc

    @property
    def path(self) -> str:
        return urlparse(self.url).path or "/"


@dataclass(frozen=True)
class Route:
    """Maps a destination to a named action understood by the authority policy."""

    action: str
    method: str = "*"
    host: str = "*"
    path: str = "*"

    def matches(self, req: OutboundRequest) -> bool:
        return (
            fnmatch.fnmatchcase(req.method.upper(), self.method.upper())
            and fnmatch.fnmatchcase(req.host, self.host)
            and fnmatch.fnmatchcase(req.path, self.path)
        )


class ActionMapper:
    """Turns an outbound request into the ``(action, context)`` MCC evaluates.

    Routes are tried in order; the first match wins. If nothing matches, the
    action is derived as ``"<method>_<host>"`` — which, having no policy, the
    gateway resolves to DENY (fail-closed: an unmapped destination is not an
    authorized one).
    """

    def __init__(self, routes: Optional[List[Route]] = None) -> None:
        self.routes = routes or []

    def map(self, req: OutboundRequest) -> Tuple[str, Dict[str, Any]]:
        action = None
        for route in self.routes:
            if route.matches(req):
                action = route.action
                break
        if action is None:
            action = f"{req.method.lower()}_{req.host}"
        context = {**req.body}
        return action, context


@dataclass(frozen=True)
class EnforcementOutcome:
    forward: bool
    status_code: int
    decision: str
    reason: str
    audit_id: str
    enforce: bool
    decision_token: Optional[Dict[str, Any]]
    # The body to forward upstream: original context for ALLOW, the rewritten
    # (clamped) context for CONSTRAIN. Empty when the request is blocked.
    forward_body: Dict[str, Any] = field(default_factory=dict)
    applied_constraints: List[str] = field(default_factory=list)


# A decide callable performs the /evaluate round trip. Injected so the
# governor can be unit-tested without a live gateway.
DecideFn = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]


class EgressGovernor:
    """Decides whether an intercepted request may leave.

    Enforcement (inline) path, in order:

    1. Ask the gateway. If it cannot be reached or errors -> block (fail-closed).
    2. Non-executable verdict (DENY/ESCALATE) -> block 403.
    3. Executable verdict -> the signed decision token MUST verify through the
       ExecutionGate: Ed25519 signature, audience, expiry, action/payload-hash
       binding, and a single-use nonce (replay protection). Any failure, or no
       gate configured at all -> block 403 (fail-closed). Only a verified token
       forwards, and it forwards exactly the body the token authorizes (the
       rewritten, clamped body for CONSTRAIN).

    Observe path: the gateway returns ``enforce=false``; the proxy is fully
    transparent — it forwards the *original* request unchanged and never
    blocks (the decision is already recorded gateway-side). Shadow mode does
    not touch traffic, so the fail-closed rule above is an enforcement-mode
    guarantee.
    """

    EXECUTABLE = ("ALLOW", "CONSTRAIN")

    def __init__(
        self,
        *,
        mapper: ActionMapper,
        decide: DecideFn,
        gate: Optional[ExecutionGate] = None,
        identity_header: str = "x-mcc-identity",
    ) -> None:
        self.mapper = mapper
        self.decide = decide
        self.gate = gate
        self.identity_header = identity_header.lower()

    def _identity(self, req: OutboundRequest) -> str:
        lower = {k.lower(): v for k, v in req.headers.items()}
        return lower.get(self.identity_header, "unknown")

    @staticmethod
    def _block(status_code: int, reason: str, audit_id: str = "") -> EnforcementOutcome:
        return EnforcementOutcome(
            forward=False,
            status_code=status_code,
            decision="DENY",
            reason=reason,
            audit_id=audit_id,
            enforce=True,
            decision_token=None,
        )

    async def govern(self, req: OutboundRequest) -> EnforcementOutcome:
        identity = self._identity(req)
        action, context = self.mapper.map(req)

        try:
            result = await self.decide(
                {"identity": identity, "action": action, "context": context}
            )
        except Exception:
            # Gateway unreachable / timeout / error -> fail-closed.
            return self._block(502, "gateway unreachable; fail-closed")

        decision = str(result.get("decision", "DENY"))
        enforce = bool(result.get("enforce", True))
        reason = str(result.get("reason", ""))
        audit_id = str(result.get("audit_id", ""))
        executable = decision in self.EXECUTABLE
        forward_context = result.get("forward_context") or dict(context)
        applied = list(result.get("applied_constraints", []) or [])
        token = result.get("decision_token")

        # Observe mode: transparent. Forward the original request, never block.
        if not enforce:
            return EnforcementOutcome(
                forward=True,
                status_code=200,
                decision=decision,
                reason=reason,
                audit_id=audit_id,
                enforce=False,
                decision_token=token,
                forward_body=dict(context),
                applied_constraints=[],
            )

        # Inline enforcement. A non-executable verdict blocks, but the proxy
        # reports the gateway's real verdict (DENY/ESCALATE), not a flattened one.
        if not executable:
            return EnforcementOutcome(
                forward=False,
                status_code=403,
                decision=decision,
                reason=reason or f"{decision}: blocked",
                audit_id=audit_id,
                enforce=True,
                decision_token=None,
            )

        # An executable verdict is only trusted once its token verifies.
        if self.gate is None:
            return self._block(403, "no execution gate configured; fail-closed", audit_id)
        try:
            gate_result = await self.gate.verify(
                token, action=action, payload=forward_context
            )
        except Exception:
            return self._block(403, "gate verification error; fail-closed", audit_id)
        if not gate_result.allowed:
            return self._block(403, f"gate rejected token: {gate_result.reason}", audit_id)

        return EnforcementOutcome(
            forward=True,
            status_code=200,
            decision=decision,
            reason=reason,
            audit_id=audit_id,
            enforce=True,
            decision_token=token,
            forward_body=forward_context,
            applied_constraints=applied,
        )


# --------------------------------------------------------------------------
# ASGI forwarding layer (thin; the interesting logic is above)
# --------------------------------------------------------------------------

def build_decide_via_http(
    gateway_url: str, api_key: str, timeout: float = 2.0
) -> DecideFn:
    """A ``decide`` that calls a real MCC gateway's POST /evaluate."""
    base = gateway_url.rstrip("/")

    async def decide(payload: Dict[str, Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{base}/evaluate", json=payload, headers={"x-api-key": api_key}
            )
            resp.raise_for_status()
            return resp.json()

    return decide


def build_proxy_app(governor: "EgressGovernor", *, upstream_base: Optional[str] = None):
    """A forwarding proxy: governs every request, forwards only what's allowed.

    Target resolution, in order: an absolute-form URL (as a true HTTP proxy
    receives), an ``X-MCC-Target`` header, or a configured ``upstream_base``.
    On a blocked decision the upstream is never contacted.
    """
    app = FastAPI(title="MCC-Core Egress Proxy", version="1.0.0-mvp")

    def _resolve_target(request: Request, path: str) -> Optional[str]:
        raw = request.url.path
        if raw.startswith("http://") or raw.startswith("https://"):
            return str(request.url)
        target = request.headers.get("x-mcc-target")
        if target:
            return target.rstrip("/") + "/" + path.lstrip("/")
        if upstream_base:
            return upstream_base.rstrip("/") + "/" + path.lstrip("/")
        return None

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    )
    async def proxy(request: Request, path: str) -> Response:
        target = _resolve_target(request, path)
        if target is None:
            return JSONResponse(
                {"error": "NO_TARGET", "detail": "no upstream resolved"},
                status_code=400,
            )

        try:
            body = await request.json()
        except Exception:
            body = {}

        outbound = OutboundRequest(
            method=request.method,
            url=target,
            headers=dict(request.headers),
            body=body if isinstance(body, dict) else {},
        )
        outcome = await governor.govern(outbound)

        headers = {
            "X-MCC-Decision": outcome.decision,
            "X-MCC-Audit-Id": outcome.audit_id,
            "X-MCC-Reason": outcome.reason,
        }
        if outcome.applied_constraints:
            headers["X-MCC-Constraints-Applied"] = "; ".join(outcome.applied_constraints)

        if not outcome.forward:
            return JSONResponse(
                {
                    "error": "BLOCKED_BY_MCC",
                    "decision": outcome.decision,
                    "reason": outcome.reason,
                    "audit_id": outcome.audit_id,
                },
                status_code=outcome.status_code,
                headers=headers,
            )

        # Forward exactly the body MCC authorized: rewritten (clamped) for
        # CONSTRAIN, original for ALLOW/observe.
        forward_body = outcome.forward_body or None
        async with httpx.AsyncClient(timeout=10.0) as client:
            upstream = await client.request(
                outbound.method,
                target,
                json=forward_body,
                headers={
                    k: v
                    for k, v in outbound.headers.items()
                    if k.lower() not in ("host", "content-length")
                },
            )
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers={**headers, "Content-Type": upstream.headers.get("content-type", "application/json")},
        )

    return app


def build_gate_from_health(
    gateway_url: str, *, nonce_ttl_seconds: int = 300, timeout: float = 5.0
) -> ExecutionGate:
    """Build an ExecutionGate that trusts the running gateway's signing key.

    Fetches the gateway's public key, kid, token audience and policy hash from
    ``/health`` so the gate binds to exactly that gateway. Replay protection is
    a single-process in-memory nonce registry (use the Redis-backed registry
    for multi-instance deployments).
    """
    info = httpx.get(f"{gateway_url.rstrip('/')}/health", timeout=timeout).json()
    signing = info["signing"]
    return ExecutionGate(
        trusted_keys={signing["kid"]: public_key_from_b64(signing["public_key_b64"])},
        audience=info["token_audience"],
        nonce_registry=InMemoryNonceRegistry(),
        policy_hash=info["policy_hash"],
        nonce_ttl_seconds=nonce_ttl_seconds,
    )


# Module-level app for ``uvicorn interceptors.egress_proxy:app``.
def _default_app():
    gateway_url = os.environ.get("MCC_GATEWAY_URL", "http://127.0.0.1:8001")
    api_key = os.environ.get("MCC_GATEWAY_API_KEY", "demo-key")
    # Default pilot routes: map destinations onto the pilot authority policy.
    routes = [
        Route(action="send_payment", method="POST", host="*", path="*charge*"),
        Route(action="send_payment", method="POST", host="*", path="*payment*"),
        Route(action="read_account", method="GET", host="*", path="*"),
        Route(action="delete_resource", method="DELETE", host="*", path="*"),
    ]
    governor = EgressGovernor(
        mapper=ActionMapper(routes),
        decide=build_decide_via_http(gateway_url, api_key),
        gate=build_gate_from_health(gateway_url),
    )
    upstream = os.environ.get("MCC_PROXY_UPSTREAM")
    return build_proxy_app(governor, upstream_base=upstream)


# Built lazily: ``uvicorn interceptors.egress_proxy:app`` requires a running
# gateway (the gate is keyed from its /health). Import stays cheap for tests.
app = None
if os.environ.get("MCC_PROXY_AUTOSTART") == "1":
    app = _default_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app or _default_app(), host="0.0.0.0", port=8080)
