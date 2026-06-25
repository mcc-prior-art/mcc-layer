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
    RUNTIME_VERSION,
    AuditLog,
    EnforcementCoordinator,
    ExecutionGate,
    ProfileRegistry,
    VelocityLimit,
    idempotency_registry_from_env,
    nonce_registry_from_env,
    public_key_from_b64,
    velocity_registry_from_env,
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

    def _binding(self, req: OutboundRequest) -> Dict[str, Any]:
        """Extract the operation binding the executor will present to the gate.

        Actor is the identity; transaction/idempotency/resource come from
        ``X-MCC-*`` headers. The gate compares these to the token's signed
        claims, so a substituted actor/resource/transaction is denied.
        """
        lower = {k.lower(): v for k, v in req.headers.items()}
        return {
            "actor_id": lower.get(self.identity_header),
            "transaction_id": lower.get("x-mcc-transaction-id"),
            "idempotency_key": lower.get("x-mcc-idempotency-key"),
            "resource_id": lower.get("x-mcc-resource-id"),
        }

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
        binding = self._binding(req)

        try:
            result = await self.decide(
                {
                    "identity": identity,
                    "action": action,
                    "context": context,
                    **{k: v for k, v in binding.items() if v is not None},
                }
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
                token, action=action, payload=forward_context, binding=binding
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

    async def decide_operation(self, req: OutboundRequest) -> "OperationDecision":
        """Run only the decision round trip (no gate/nonce). Used by the
        coordinator path, where the EnforcementCoordinator owns the gate (a),
        the nonce (b), and steps c-h around the actual forward."""
        identity = self._identity(req)
        action, context = self.mapper.map(req)
        binding = self._binding(req)
        try:
            result = await self.decide(
                {
                    "identity": identity,
                    "action": action,
                    "context": context,
                    **{k: v for k, v in binding.items() if v is not None},
                }
            )
        except Exception:
            return OperationDecision(
                action=action, context=context, decision="DENY", enforce=True,
                reason="gateway unreachable; fail-closed", forward_context=context,
                token=None, binding=binding, reachable=False,
            )
        return OperationDecision(
            action=action,
            context=context,
            decision=str(result.get("decision", "DENY")),
            enforce=bool(result.get("enforce", True)),
            reason=str(result.get("reason", "")),
            audit_id=str(result.get("audit_id", "")),
            forward_context=result.get("forward_context") or dict(context),
            token=result.get("decision_token"),
            binding=binding,
            reachable=True,
        )


@dataclass(frozen=True)
class OperationDecision:
    action: str
    context: Dict[str, Any]
    decision: str
    enforce: bool
    reason: str
    forward_context: Dict[str, Any]
    token: Optional[Dict[str, Any]]
    binding: Dict[str, Any]
    reachable: bool
    audit_id: str = ""

    @property
    def executable(self) -> bool:
        return self.decision in ("ALLOW", "CONSTRAIN")


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


async def _forward_upstream(outbound: "OutboundRequest", target: str, body: Optional[Dict[str, Any]]):
    async with httpx.AsyncClient(timeout=10.0) as client:
        return await client.request(
            outbound.method,
            target,
            json=body or None,
            headers={
                k: v
                for k, v in outbound.headers.items()
                if k.lower() not in ("host", "content-length")
            },
        )


def build_proxy_app(
    governor: "EgressGovernor",
    *,
    upstream_base: Optional[str] = None,
    coordinator: "Optional[Any]" = None,
):
    """A forwarding proxy: governs every request, forwards only what's allowed.

    Target resolution, in order: an absolute-form URL (as a true HTTP proxy
    receives), an ``X-MCC-Target`` header, or a configured ``upstream_base``.
    On a blocked decision the upstream is never contacted.

    When an ``EnforcementCoordinator`` is supplied, the inline path runs the
    full a-h ordering — gate (token + binding + nonce), idempotency reservation,
    velocity reservation, audit-before-actuation, the forward, the outcome
    record, and idempotency finalize — wrapping the upstream call as the
    executor. Without one, the proxy uses the gate-only path (token + nonce).
    """
    app = FastAPI(title="MCC-Core Egress Proxy", version=RUNTIME_VERSION)

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

    async def _read(request: Request, target: str) -> "OutboundRequest":
        try:
            body = await request.json()
        except Exception:
            body = {}
        return OutboundRequest(
            method=request.method,
            url=target,
            headers=dict(request.headers),
            body=body if isinstance(body, dict) else {},
        )

    async def _via_governor(outbound: "OutboundRequest", target: str) -> Response:
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
                {"error": "BLOCKED_BY_MCC", "decision": outcome.decision,
                 "reason": outcome.reason, "audit_id": outcome.audit_id},
                status_code=outcome.status_code, headers=headers,
            )
        upstream = await _forward_upstream(outbound, target, outcome.forward_body)
        return Response(
            content=upstream.content, status_code=upstream.status_code,
            headers={**headers, "Content-Type": upstream.headers.get("content-type", "application/json")},
        )

    async def _via_coordinator(outbound: "OutboundRequest", target: str) -> Response:
        from mcc_core import ActuationStatus  # local import to keep base path light

        op = await governor.decide_operation(outbound)
        headers = {"X-MCC-Decision": op.decision, "X-MCC-Reason": op.reason}

        if not op.enforce:  # observe: transparent
            upstream = await _forward_upstream(outbound, target, op.context)
            return Response(content=upstream.content, status_code=upstream.status_code,
                            headers={**headers, "Content-Type": upstream.headers.get("content-type", "application/json")})

        if not op.executable:
            status = 502 if not op.reachable else 403
            return JSONResponse(
                {"error": "BLOCKED_BY_MCC", "decision": op.decision, "reason": op.reason},
                status_code=status, headers=headers,
            )

        captured: Dict[str, Any] = {}

        async def executor():
            resp = await _forward_upstream(outbound, target, op.forward_context)
            captured["resp"] = resp
            return resp

        result = await coordinator.enforce(
            token=op.token, action=op.action, payload=op.forward_context,
            executor=executor, request_binding=op.binding,
        )
        headers["X-MCC-Audit-Ref"] = result.audit_ref or ""
        if result.status == ActuationStatus.EXECUTED:
            resp = captured["resp"]
            return Response(content=resp.content, status_code=resp.status_code,
                            headers={**headers, "Content-Type": resp.headers.get("content-type", "application/json")})
        status = 502 if result.status == ActuationStatus.EXECUTION_FAILED else 403
        return JSONResponse(
            {"error": "BLOCKED_BY_MCC", "status": result.status.value, "reason": result.reason},
            status_code=status, headers=headers,
        )

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
    )
    async def proxy(request: Request, path: str) -> Response:
        target = _resolve_target(request, path)
        if target is None:
            return JSONResponse(
                {"error": "NO_TARGET", "detail": "no upstream resolved"}, status_code=400,
            )
        outbound = await _read(request, target)
        if coordinator is not None:
            return await _via_coordinator(outbound, target)
        return await _via_governor(outbound, target)

    return app


def build_gate_from_health(
    gateway_url: str,
    *,
    nonce_registry=None,
    nonce_ttl_seconds: int = 300,
    timeout: float = 5.0,
) -> ExecutionGate:
    """Build an ExecutionGate that trusts the running gateway's signing key.

    Fetches the gateway's public key, kid, token audience and policy hash from
    ``/health`` so the gate binds to exactly that gateway.

    Replay protection comes from ``nonce_registry``; when not supplied it is
    selected from the environment (``nonce_registry_from_env``): in-memory by
    default, Redis when ``MCC_NONCE_BACKEND=redis`` + ``MCC_REDIS_URL`` are set.
    Multi-instance enforcement deployments must select Redis so replays are
    rejected across every proxy/gate instance, not just within one process.
    """
    info = httpx.get(f"{gateway_url.rstrip('/')}/health", timeout=timeout).json()
    signing = info["signing"]
    registry = nonce_registry if nonce_registry is not None else nonce_registry_from_env()
    return ExecutionGate(
        trusted_keys={signing["kid"]: public_key_from_b64(signing["public_key_b64"])},
        audience=info["token_audience"],
        nonce_registry=registry,
        policy_hash=info["policy_hash"],
        nonce_ttl_seconds=nonce_ttl_seconds,
    )


def build_velocity_resolver(velocity_config: Dict[str, Any]):
    """action -> [VelocityLimit] resolver from a ``{action_pattern: [limit,...]}``
    config, first matching pattern wins."""
    compiled = [
        (pattern, [VelocityLimit.from_config(item) for item in items])
        for pattern, items in velocity_config.items()
    ]

    def resolve(action: str) -> List[VelocityLimit]:
        for pattern, limits in compiled:
            if fnmatch.fnmatchcase(action, pattern):
                return limits
        return []

    return resolve


def build_coordinator(
    gate: ExecutionGate,
    *,
    velocity_config: Optional[Dict[str, Any]] = None,
    audit_path: Optional[str] = None,
    profiles: Optional[ProfileRegistry] = None,
) -> EnforcementCoordinator:
    """Assemble the EnforcementCoordinator for the proxy.

    Idempotency and velocity backends are selected from the environment
    (in-memory by default, Redis under ``MCC_*_BACKEND=redis`` + ``MCC_REDIS_URL``
    with no silent fallback). The audit log is the enforcement-side
    audit-before-actuation chain.
    """
    return EnforcementCoordinator(
        gate=gate,
        idempotency=idempotency_registry_from_env(),
        velocity=velocity_registry_from_env(),
        audit=AuditLog(audit_path or os.environ.get("MCC_PROXY_AUDIT_LOG_PATH", "proxy-audit.jsonl")),
        profiles=profiles or ProfileRegistry.default_pilot(),
        velocity_limits_for=build_velocity_resolver(velocity_config or {}),
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
    gate = build_gate_from_health(gateway_url)
    governor = EgressGovernor(
        mapper=ActionMapper(routes),
        decide=build_decide_via_http(gateway_url, api_key),
        gate=gate,
    )
    upstream = os.environ.get("MCC_PROXY_UPSTREAM")
    coordinator = None
    if os.environ.get("MCC_PROXY_COORDINATOR", "1") == "1":
        from gateway.pilot_policy import PILOT_VELOCITY

        coordinator = build_coordinator(gate, velocity_config=PILOT_VELOCITY)
    return build_proxy_app(governor, upstream_base=upstream, coordinator=coordinator)


# Built lazily: ``uvicorn interceptors.egress_proxy:app`` requires a running
# gateway (the gate is keyed from its /health). Import stays cheap for tests.
app = None
if os.environ.get("MCC_PROXY_AUTOSTART") == "1":
    app = _default_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app or _default_app(), host="0.0.0.0", port=8080)
