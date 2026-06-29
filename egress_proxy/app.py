"""MCC-Core Enforced Outbound HTTP Egress Proxy — HTTP service.

``POST /v1/http/execute`` accepts a proposed outbound HTTP action, binds it to a
canonical MCC action, and submits it through the embedded unified runtime. The
proxy never decides a verdict; it surfaces the runtime's ALLOW/DENY/ESCALATE/
CONSTRAIN and only the governed executor performs the outbound call.

Continuations (consensus votes, approval) are carried by the caller and resolved
by the existing runtime — the proxy keeps no governance state of its own.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional, Tuple

from fastapi import Depends, FastAPI, Header, HTTPException, Response

from mcc_core import RUNTIME_VERSION

from examples.governed_agent.agent import Agent, ProposedAction

from .canonical_action import CanonicalActionError, action_hash, build_canonical_action
from .config import EgressSettings
from .models import HTTPExecuteRequest, HTTPExecuteResponse, Outcome
from .observability import (
    EXECUTOR_CATEGORY_TO_CODE,
    CorrelationError,
    ErrorCode,
    Metrics,
    classify_reason,
    emit_event,
    resolve_correlation_id,
    safe_message,
    span,
)
from .runtime import EgressRuntime
from .ssrf import SSRFError, validate_destination

settings = EgressSettings()

# Outcome -> the verdict it represents (for bounded decision metrics), if any.
_OUTCOME_VERDICT = {
    Outcome.ALLOW: "ALLOW", Outcome.DENY: "DENY", Outcome.ESCALATE: "ESCALATE",
    Outcome.CONSTRAIN: "CONSTRAIN",
}

# Stable error code -> (external outcome, HTTP status). Governance/credential/SSRF
# denials are 403; dependency/audit failures are 503; upstream failures are 5xx.
_CODE_OUTCOME = {
    ErrorCode.UPSTREAM_TIMEOUT: (Outcome.UPSTREAM_TIMEOUT, 504),
    ErrorCode.UPSTREAM_ERROR: (Outcome.UPSTREAM_ERROR, 502),
    ErrorCode.TLS_FAILED: (Outcome.UPSTREAM_ERROR, 502),
    ErrorCode.MTLS_FAILED: (Outcome.DENY, 403),
    ErrorCode.SSRF_DENIED: (Outcome.DENY, 403),
    ErrorCode.REDIRECT_DENIED: (Outcome.DENY, 403),
    ErrorCode.CREDENTIAL_DENIED: (Outcome.DENY, 403),
    ErrorCode.CREDENTIAL_UNAVAILABLE: (Outcome.DEPENDENCY_UNAVAILABLE, 503),
    ErrorCode.DEPENDENCY_UNAVAILABLE: (Outcome.DEPENDENCY_UNAVAILABLE, 503),
    ErrorCode.AUDIT_WRITE_FAILED: (Outcome.DEPENDENCY_UNAVAILABLE, 503),
    ErrorCode.NONCE_REPLAY: (Outcome.DENY, 403),
    ErrorCode.IDEMPOTENCY_CONFLICT: (Outcome.DENY, 403),
    ErrorCode.VELOCITY_EXCEEDED: (Outcome.DENY, 403),
    ErrorCode.CONSENSUS_FAILED: (Outcome.DENY, 403),
    ErrorCode.APPROVAL_INVALID: (Outcome.DENY, 403),
    ErrorCode.MANDATE_INVALID: (Outcome.DENY, 403),
    ErrorCode.GOVERNANCE_DENY: (Outcome.DENY, 403),
    ErrorCode.INTERNAL_ERROR: (Outcome.GOVERNANCE_UNAVAILABLE, 503),
}


def _host_of(url: str) -> Optional[str]:
    from urllib.parse import urlsplit
    try:
        return (urlsplit(url).hostname or "").lower() or None
    except Exception:  # noqa: BLE001
        return None


# ---------------- service ----------------

class EgressService:
    def __init__(self, rt: EgressRuntime, *, metrics: Optional[Metrics] = None) -> None:
        self.rt = rt
        self.settings = rt.settings
        self.metrics = metrics or Metrics()

    # -- build the canonical action + a proposal bound to it --

    def _canonical(self, req: HTTPExecuteRequest) -> Dict[str, Any]:
        action = build_canonical_action(
            method=req.method, url=req.url, headers=req.headers, body=req.body,
            credential_ref=req.credential_ref, client_identity_ref=req.client_identity_ref,
            ca_bundle_ref=req.ca_bundle_ref)
        # Submission-time SSRF gate (re-checked again at connect time in the executor).
        validate_destination(action["host"], int(action["port"]),
                             policy=self.rt.executor.policy)
        return action

    def _propose(self, req: HTTPExecuteRequest, action: Dict[str, Any],
                 correlation_id: str) -> ProposedAction:
        return Agent(req.actor).propose(
            "http.request", resource=req.resource, payload=action,
            transaction_id=req.transaction_id, idempotency_key=req.idempotency_key,
            correlation_id=correlation_id)

    async def handle(self, req: HTTPExecuteRequest) -> Tuple[HTTPExecuteResponse, int]:
        """Correlate, dispatch through the governed path, then record bounded
        metrics + a redacted structured event. Observability never alters the
        decision: recording happens after the verdict, and any telemetry failure
        is swallowed."""
        started = time.monotonic()
        try:
            correlation_id = resolve_correlation_id(req.correlation_id)
        except CorrelationError:
            self.metrics.correlation_rejected.inc()
            self.metrics.record(outcome=Outcome.INVALID_REQUEST.value, verdict=None,
                                code=ErrorCode.INVALID_CORRELATION_ID, latency_s=0.0,
                                executed=False)
            return self._resp(Outcome.INVALID_REQUEST,
                              reason=safe_message(ErrorCode.INVALID_CORRELATION_ID),
                              error_code=ErrorCode.INVALID_CORRELATION_ID), 400

        with span("egress.request", {"mcc.correlation_id": correlation_id,
                                     "http.method": req.method}, metrics=self.metrics):
            resp, status = await self._dispatch(req, correlation_id)

        latency = time.monotonic() - started
        code = self._error_code_for(resp)
        verdict = _OUTCOME_VERDICT.get(resp.outcome)
        try:
            self.metrics.record(outcome=resp.outcome.value, verdict=verdict, code=code,
                                latency_s=latency, executed=resp.executed)
            emit_event(self.rt.logger, "egress.request", correlation_id=correlation_id,
                       outcome=resp.outcome.value, verdict=verdict, error_code=code.value,
                       executed=resp.executed, status=status, action_hash=resp.action_hash,
                       host=_host_of(req.url), method=req.method,
                       duration_ms=round(latency * 1000, 2),
                       mtls_requested=resp.mtls_requested,
                       credential_resolved=resp.credential_resolved)
        except Exception:  # noqa: BLE001 — telemetry must never break the path
            pass
        return resp, status

    @staticmethod
    def _error_code_for(resp: HTTPExecuteResponse) -> ErrorCode:
        if resp.error_code:
            try:
                return ErrorCode(resp.error_code)
            except ValueError:
                return ErrorCode.INTERNAL_ERROR
        return ErrorCode.OK if resp.executed else ErrorCode.GOVERNANCE_DENY

    async def _dispatch(self, req: HTTPExecuteRequest,
                        correlation_id: str) -> Tuple[HTTPExecuteResponse, int]:
        try:
            action = self._canonical(req)
        except (CanonicalActionError, SSRFError) as exc:
            code = ErrorCode.SSRF_DENIED if isinstance(exc, SSRFError) else ErrorCode.INVALID_REQUEST
            return self._resp(Outcome.INVALID_REQUEST, reason=safe_message(code),
                              error_code=code, correlation_id=correlation_id), 400

        p = self._propose(req, action, correlation_id)
        ah = action_hash(action)
        client = self.rt.client

        try:
            # --- continuation: approval (ESCALATE execute) ---
            if req.approval_id:
                challenge = await self._reload_challenge(req.challenge_id)
                r = await client.execute_with_approval(
                    p, req.approval_id, challenge=challenge, votes=req.votes)
                return self._finalize(r, correlation_id, ah)

            # --- continuation: constrained re-consensus execute ---
            if req.constrained:
                challenge = await self._reload_challenge(req.challenge_id)
                r = await client.execute_constrained(
                    p, action, challenge=challenge, votes=req.votes)
                return self._finalize(r, correlation_id, ah)

            # --- consensus mode ---
            if self.settings.require_consensus:
                if not (req.challenge_id and req.votes):
                    # Round 1: gateway-issued challenge bound to this exact action.
                    ch = await client.issue_challenge(p)
                    return self._resp(
                        Outcome.CONSENSUS_REQUIRED,
                        reason="supply N-of-M evaluator votes for this challenge",
                        error_code=ErrorCode.CONSENSUS_REQUIRED,
                        action_hash=ah, challenge_id=ch.challenge_id, nonce=ch.nonce,
                        correlation_id=correlation_id), 202
                challenge = await self._reload_challenge(req.challenge_id)
                r = await client.submit(p, challenge=challenge, votes=req.votes)
                return await self._after_submit(r, p, action, correlation_id, ah)

            # --- non-consensus mode: one-shot authority decision ---
            r = await client.submit(p)
            return await self._after_submit(r, p, action, correlation_id, ah)
        except HTTPException:
            raise
        except Exception:  # noqa: BLE001 — any runtime failure is fail-closed
            # No raw exception text / stack trace leaves the process.
            return self._resp(Outcome.GOVERNANCE_UNAVAILABLE,
                              reason=safe_message(ErrorCode.INTERNAL_ERROR),
                              error_code=ErrorCode.INTERNAL_ERROR,
                              correlation_id=correlation_id, action_hash=ah), 503

    async def _reload_challenge(self, challenge_id: Optional[str]):
        if not challenge_id or self.rt.client.challenges is None:
            return None
        return await self.rt.client.challenges.get(challenge_id)

    async def _after_submit(self, r, p: ProposedAction, action: Dict[str, Any],
                            correlation_id: str, ah: str) -> Tuple[HTTPExecuteResponse, int]:
        if r.verdict == "DENY":
            code = classify_reason(r.reason)
            return self._resp(Outcome.DENY, reason=safe_message(code), error_code=code,
                              action_hash=ah, audit_ref=r.audit_ref,
                              correlation_id=correlation_id), 403

        if r.verdict == "ESCALATE" and not r.executed:
            # Open an approval bound to this exact operation; the caller has the
            # operator approve it and resubmits with approval_id (+ votes in
            # consensus mode). Approval state lives in the runtime, not the proxy.
            rid = await self.rt.client.request_approval(p)
            return self._resp(
                Outcome.ESCALATE, reason=safe_message(ErrorCode.ESCALATION_REQUIRED),
                error_code=ErrorCode.ESCALATION_REQUIRED,
                action_hash=ah, correlation_id=correlation_id,
                approval_request_id=rid), 202

        if r.verdict == "CONSTRAIN" and r.status == "RECONSENSUS_REQUIRED":
            # Fresh consensus over the clamped action: issue a NEW challenge bound
            # to the new payload hash. The original action is never executed.
            constrained = r.authorized_payload
            ch = await self.rt.client.issue_challenge(p, payload=constrained)
            return self._resp(
                Outcome.CONSTRAIN,
                reason=safe_message(ErrorCode.CONSTRAINT_RECONSENSUS),
                error_code=ErrorCode.CONSTRAINT_RECONSENSUS,
                action_hash=action_hash(constrained), correlation_id=correlation_id,
                challenge_id=ch.challenge_id, nonce=ch.nonce,
                constrained_action=constrained, applied_constraints=r.applied_changes), 202

        return self._finalize(r, correlation_id, ah)

    def _finalize(self, r, correlation_id: str, ah: str) -> Tuple[HTTPExecuteResponse, int]:
        if r.executed:
            resp = self.rt.executor.pop_response(correlation_id) or {}
            outcome = Outcome.CONSTRAIN if r.verdict == "CONSTRAIN" else Outcome.ALLOW
            return self._resp(
                outcome, executed=True, reason="executed", error_code=ErrorCode.OK,
                action_hash=action_hash(r.authorized_payload) if r.authorized_payload else ah,
                audit_ref=r.audit_ref, correlation_id=correlation_id,
                upstream_status=resp.get("upstream_status"),
                upstream_headers=resp.get("upstream_headers"),
                upstream_body=resp.get("upstream_body"),
                truncated=resp.get("truncated"),
                credential_ref=resp.get("credential_ref"),
                credential_resolved=resp.get("credential_resolved"),
                mtls_requested=resp.get("mtls_requested"),
                client_identity_loaded=resp.get("client_identity_loaded"),
                applied_constraints=getattr(r, "applied_changes", []) or []), 200

        # Not executed -> a stable error code from the executor's failure category
        # (precise) or, failing that, the runtime's safe reason (keyword-classified).
        err = self.rt.executor.pop_error(correlation_id)
        code = EXECUTOR_CATEGORY_TO_CODE.get(err) if err else None
        if code is None:
            code = ErrorCode.INTERNAL_ERROR if r.verdict == "ERROR" else classify_reason(r.reason)
        outcome, status = _CODE_OUTCOME.get(code, (Outcome.DENY, 403))
        return self._resp(outcome, reason=safe_message(code), error_code=code,
                          correlation_id=correlation_id, action_hash=ah), status

    @staticmethod
    def _resp(outcome: Outcome, *, executed: bool = False, reason: str = "",
              error_code: Optional[ErrorCode] = None,
              action_hash: Optional[str] = None, audit_ref: Optional[str] = None,
              correlation_id: Optional[str] = None, challenge_id: Optional[str] = None,
              nonce: Optional[str] = None, approval_request_id: Optional[str] = None,
              constrained_action: Optional[Dict[str, Any]] = None,
              applied_constraints=None, upstream_status: Optional[int] = None,
              upstream_headers=None, upstream_body: Any = None,
              truncated: Optional[bool] = None, credential_ref: Optional[str] = None,
              credential_resolved: Optional[bool] = None, mtls_requested: Optional[bool] = None,
              client_identity_loaded: Optional[bool] = None) -> HTTPExecuteResponse:
        return HTTPExecuteResponse(
            outcome=outcome, executed=executed, reason=reason,
            error_code=(error_code.value if isinstance(error_code, ErrorCode) else error_code),
            action_hash=action_hash,
            audit_ref=audit_ref, correlation_id=correlation_id, challenge_id=challenge_id,
            nonce=nonce, approval_request_id=approval_request_id,
            constrained_action=constrained_action, applied_constraints=applied_constraints or [],
            upstream_status=upstream_status, upstream_headers=upstream_headers,
            upstream_body=upstream_body, truncated=truncated, credential_ref=credential_ref,
            credential_resolved=credential_resolved, mtls_requested=mtls_requested,
            client_identity_loaded=client_identity_loaded)


# ---------------- app factory ----------------

_REDIS_BACKEND_VARS = (
    "MCC_NONCE_BACKEND", "MCC_IDEMPOTENCY_BACKEND", "MCC_VELOCITY_BACKEND",
    "MCC_APPROVAL_BACKEND", "MCC_CHALLENGE_BACKEND", "MCC_REVOCATION_BACKEND",
)


def _redis_required(env) -> bool:
    return any(env.get(v, "").strip().lower() == "redis" for v in _REDIS_BACKEND_VARS)


def _audit_durable(runtime) -> bool:
    """The audit chain must be durably writable for actuation to be allowed."""
    try:
        path = getattr(runtime.client.audit, "path", None)
        if not path:
            return False
        d = os.path.dirname(os.path.abspath(path)) or "."
        return os.path.isdir(d) and os.access(d, os.W_OK)
    except Exception:  # noqa: BLE001
        return False


async def _redis_ok(env) -> bool:
    from mcc_core.redis_client import RedisConfigError, redis_client_from_env

    try:
        client = redis_client_from_env(env)
    except RedisConfigError:
        return False
    try:
        return bool(await client.ping())
    except Exception:  # noqa: BLE001
        return False
    finally:
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001
            pass


def build_app(cfg: EgressSettings, *, env=None, resolver=None) -> FastAPI:
    """Build the egress proxy app. Fail-closed startup is surfaced via /ready
    (and, in pilot, by refusing to start at all)."""
    env = os.environ if env is None else env
    metrics = Metrics()
    service: Optional[EgressService] = None
    runtime: Optional[EgressRuntime] = None
    startup_error: Optional[str] = None
    try:
        runtime = EgressRuntime(cfg, env=env, resolver=resolver)
        service = EgressService(runtime, metrics=metrics)
    except Exception as exc:  # noqa: BLE001
        startup_error = f"{type(exc).__name__}: {exc}"
        if cfg.mcc_env == "pilot":
            raise

    application = FastAPI(title="MCC-Core Enforced Egress Proxy", version=RUNTIME_VERSION)

    def require_api_key(x_api_key: str = Header(...)) -> str:
        if x_api_key != cfg.api_key:
            raise HTTPException(status_code=401, detail="INVALID_API_KEY")
        return "agent"

    def require_operator(x_operator_key: Optional[str] = Header(default=None)) -> str:
        # No operator key configured, or a wrong one -> no operator actions (403).
        if not cfg.operator_api_key or x_operator_key != cfg.operator_api_key:
            raise HTTPException(status_code=403, detail="INVALID_OPERATOR_KEY")
        return "operator"

    @application.post("/v1/http/execute", response_model=HTTPExecuteResponse,
                      response_model_exclude_none=True)
    async def http_execute(req: HTTPExecuteRequest, response: Response,
                           _=Depends(require_api_key)) -> HTTPExecuteResponse:
        if service is None:
            metrics.failclosed_dependency.inc()
            response.status_code = 503
            return HTTPExecuteResponse(outcome=Outcome.GOVERNANCE_UNAVAILABLE,
                                       error_code=ErrorCode.DEPENDENCY_UNAVAILABLE.value,
                                       reason=safe_message(ErrorCode.DEPENDENCY_UNAVAILABLE))
        body, status = await service.handle(req)
        response.status_code = status
        if body.correlation_id:
            response.headers["X-MCC-Correlation-Id"] = body.correlation_id
        return body

    @application.post("/v1/approvals/{request_id}/approve")
    async def approve(request_id: str, response: Response,
                      _=Depends(require_operator)) -> Dict[str, Any]:
        """Operator grants a pending ESCALATE approval. Delegates to the embedded
        runtime's ApprovalService (mints a single-use mandate); it executes
        nothing. The agent then resubmits with the approval_id."""
        if service is None:
            response.status_code = 503
            return {"approved": False, "reason": "runtime not initialized"}
        ok = await service.rt.client.approve(request_id)
        if not ok:
            response.status_code = 409
        return {"approved": bool(ok), "request_id": request_id}

    @application.post("/v1/approvals/{request_id}/deny")
    async def deny(request_id: str, response: Response,
                   _=Depends(require_operator)) -> Dict[str, Any]:
        if service is None:
            response.status_code = 503
            return {"denied": False, "reason": "runtime not initialized"}
        ok = await service.rt.client.deny_approval(request_id)
        if not ok:
            response.status_code = 409
        return {"denied": bool(ok), "request_id": request_id}

    @application.get("/livez")
    def livez() -> Dict[str, Any]:
        """Liveness only: the process is running. No dependency checks, no secrets,
        no internal topology — distinct from readiness."""
        return {"alive": True, "version": RUNTIME_VERSION}

    @application.get("/health")
    def health() -> Dict[str, Any]:
        # Liveness (kept for compatibility). Distinct from /ready below.
        body = {"status": "ok", "fail_closed": True, "version": RUNTIME_VERSION,
                "consensus_required": cfg.require_consensus,
                "action_type": "http.request"}
        if service is not None:
            # The policy hash binds votes/tokens; it is public (not a secret).
            body["policy_hash"] = runtime.policy_hash
        return body

    @application.get("/metrics")
    def metrics_endpoint() -> Response:
        body, content_type = metrics.render()
        return Response(content=body, media_type=content_type)

    @application.get("/ready")
    async def ready(response: Response) -> Dict[str, Any]:
        # Readiness validates required production dependencies/config. It never
        # exposes secrets or internal topology — only boolean check results.
        checks: Dict[str, Any] = {"runtime_initialized": service is not None}
        if service is not None:
            checks["ephemeral_signing_key"] = runtime.ephemeral_signing_key
            checks["audit_durable"] = _audit_durable(runtime)
            checks["credential_provider"] = (
                "configured" if runtime.executor.credential_provider is not None else "none")
            if cfg.require_consensus:
                checks["consensus_verifier"] = (
                    runtime.client.consensus_required and runtime.client.challenges is not None)
        redis_required = _redis_required(env)
        checks["redis_required"] = redis_required
        if redis_required:
            checks["redis"] = await _redis_ok(env)
            metrics.redis_up.set(1 if checks["redis"] else 0)

        required = [checks.get("runtime_initialized", False)]
        if service is not None:
            required.append(checks.get("audit_durable", False))
        if cfg.require_consensus and service is not None:
            required.append(checks.get("consensus_verifier", False))
        if redis_required:
            required.append(checks.get("redis", False))
        ready_now = all(required)
        metrics.readiness.set(1 if ready_now else 0)
        if not ready_now:
            response.status_code = 503
        # Only safe boolean/string check results are returned (no startup detail).
        return {"ready": ready_now, "checks": checks}

    # Test/operator hook (not an HTTP surface): the in-process service + runtime.
    application.state.egress_service = service
    application.state.startup_error = startup_error
    return application


# Module-level app for ``uvicorn egress_proxy.app:app`` (config from environment).
app = build_app(settings)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8090)
