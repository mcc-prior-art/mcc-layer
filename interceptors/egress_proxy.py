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
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response


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


# A decide callable performs the /evaluate round trip. Injected so the
# governor can be unit-tested without a live gateway.
DecideFn = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]


class EgressGovernor:
    """Decides whether an intercepted request may leave.

    ``forward`` is True only for an executable verdict (ALLOW/CONSTRAIN) when
    enforcing. In observe mode the gateway returns ``enforce=false`` and the
    governor forwards regardless — but the decision is already recorded, so a
    drop-in can be run in shadow before it is trusted to block real traffic.

    Fail-closed: if the gateway cannot be reached or returns nothing usable,
    an *enforcing* governor blocks (502). An *observing* governor forwards,
    because by definition it is not on the hook for blocking yet.
    """

    EXECUTABLE = ("ALLOW", "CONSTRAIN")

    def __init__(self, *, mapper: ActionMapper, decide: DecideFn, identity_header: str = "x-mcc-identity") -> None:
        self.mapper = mapper
        self.decide = decide
        self.identity_header = identity_header.lower()

    def _identity(self, req: OutboundRequest) -> str:
        lower = {k.lower(): v for k, v in req.headers.items()}
        return lower.get(self.identity_header, "unknown")

    async def govern(self, req: OutboundRequest) -> EnforcementOutcome:
        identity = self._identity(req)
        action, context = self.mapper.map(req)

        try:
            result = await self.decide(
                {"identity": identity, "action": action, "context": context}
            )
        except Exception:
            # Gateway unreachable. Enforcing -> block (fail-closed).
            return EnforcementOutcome(
                forward=False,
                status_code=502,
                decision="DENY",
                reason="gateway unreachable; fail-closed",
                audit_id="",
                enforce=True,
                decision_token=None,
            )

        decision = str(result.get("decision", "DENY"))
        enforce = bool(result.get("enforce", True))
        executable = decision in self.EXECUTABLE

        # Observe mode: never block, only record what would have happened.
        forward = executable if enforce else True
        status_code = 200 if forward else 403

        return EnforcementOutcome(
            forward=forward,
            status_code=status_code,
            decision=decision,
            reason=str(result.get("reason", "")),
            audit_id=str(result.get("audit_id", "")),
            enforce=enforce,
            decision_token=result.get("decision_token"),
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

        async with httpx.AsyncClient(timeout=10.0) as client:
            upstream = await client.request(
                outbound.method,
                target,
                json=outbound.body or None,
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
    )
    upstream = os.environ.get("MCC_PROXY_UPSTREAM")
    return build_proxy_app(governor, upstream_base=upstream)


app = _default_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
