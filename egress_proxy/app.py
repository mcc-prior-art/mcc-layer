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
import uuid
from typing import Any, Dict, Optional, Tuple

from fastapi import Depends, FastAPI, Header, HTTPException, Response

from mcc_core import RUNTIME_VERSION

from examples.governed_agent.agent import Agent, ProposedAction

from .canonical_action import CanonicalActionError, action_hash, build_canonical_action
from .config import EgressSettings
from .models import HTTPExecuteRequest, HTTPExecuteResponse, Outcome
from .runtime import EgressRuntime
from .ssrf import SSRFError, validate_destination

settings = EgressSettings()


# ---------------- service ----------------

class EgressService:
    def __init__(self, rt: EgressRuntime) -> None:
        self.rt = rt
        self.settings = rt.settings

    # -- build the canonical action + a proposal bound to it --

    def _canonical(self, req: HTTPExecuteRequest) -> Dict[str, Any]:
        action = build_canonical_action(
            method=req.method, url=req.url, headers=req.headers, body=req.body)
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
        correlation_id = req.correlation_id or f"corr-{uuid.uuid4().hex}"
        try:
            action = self._canonical(req)
        except (CanonicalActionError, SSRFError) as exc:
            return self._resp(Outcome.INVALID_REQUEST, reason=str(exc),
                              correlation_id=correlation_id), 400

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
        except Exception as exc:  # noqa: BLE001 — any runtime failure is fail-closed
            return self._resp(Outcome.GOVERNANCE_UNAVAILABLE,
                              reason=f"runtime error; fail-closed: {type(exc).__name__}",
                              correlation_id=correlation_id, action_hash=ah), 503

    async def _reload_challenge(self, challenge_id: Optional[str]):
        if not challenge_id or self.rt.client.challenges is None:
            return None
        return await self.rt.client.challenges.get(challenge_id)

    async def _after_submit(self, r, p: ProposedAction, action: Dict[str, Any],
                            correlation_id: str, ah: str) -> Tuple[HTTPExecuteResponse, int]:
        if r.verdict == "DENY":
            return self._resp(Outcome.DENY, reason=r.reason, action_hash=ah,
                              audit_ref=r.audit_ref, correlation_id=correlation_id), 403

        if r.verdict == "ESCALATE" and not r.executed:
            # Open an approval bound to this exact operation; the caller has the
            # operator approve it and resubmits with approval_id (+ votes in
            # consensus mode). Approval state lives in the runtime, not the proxy.
            rid = await self.rt.client.request_approval(p)
            return self._resp(
                Outcome.ESCALATE, reason=r.reason or "human approval required",
                action_hash=ah, correlation_id=correlation_id,
                approval_request_id=rid), 202

        if r.verdict == "CONSTRAIN" and r.status == "RECONSENSUS_REQUIRED":
            # Fresh consensus over the clamped action: issue a NEW challenge bound
            # to the new payload hash. The original action is never executed.
            constrained = r.authorized_payload
            ch = await self.rt.client.issue_challenge(p, payload=constrained)
            return self._resp(
                Outcome.CONSTRAIN,
                reason="action constrained; obtain fresh consensus for the new action hash",
                action_hash=action_hash(constrained), correlation_id=correlation_id,
                challenge_id=ch.challenge_id, nonce=ch.nonce,
                constrained_action=constrained, applied_constraints=r.applied_changes), 202

        return self._finalize(r, correlation_id, ah)

    def _finalize(self, r, correlation_id: str, ah: str) -> Tuple[HTTPExecuteResponse, int]:
        if r.executed:
            resp = self.rt.executor.pop_response(correlation_id) or {}
            outcome = Outcome.CONSTRAIN if r.verdict == "CONSTRAIN" else Outcome.ALLOW
            return self._resp(
                outcome, executed=True, reason=r.reason,
                action_hash=action_hash(r.authorized_payload) if r.authorized_payload else ah,
                audit_ref=r.audit_ref, correlation_id=correlation_id,
                upstream_status=resp.get("upstream_status"),
                upstream_headers=resp.get("upstream_headers"),
                upstream_body=resp.get("upstream_body"),
                truncated=resp.get("truncated"),
                applied_constraints=getattr(r, "applied_changes", []) or []), 200

        # Not executed and not a clean DENY/ESCALATE/CONSTRAIN above -> classify.
        err = self.rt.executor.pop_error(correlation_id)
        if err == "UPSTREAM_TIMEOUT":
            return self._resp(Outcome.UPSTREAM_TIMEOUT, reason=r.reason,
                              correlation_id=correlation_id, action_hash=ah), 504
        if err == "UPSTREAM_ERROR":
            return self._resp(Outcome.UPSTREAM_ERROR, reason=r.reason,
                              correlation_id=correlation_id, action_hash=ah), 502
        if err == "DENY":  # connect-time SSRF rebinding rejection
            return self._resp(Outcome.DENY, reason="destination rejected at connect time",
                              correlation_id=correlation_id, action_hash=ah), 403

        reason = (r.reason or "").lower()
        # A single-use violation (one-time nonce / challenge / approval replay) is a
        # governance denial. The gate deliberately does not distinguish replay from
        # nonce-store unavailability (to avoid leaking state); both are fail-closed
        # with zero upstream calls, and we surface the security interpretation.
        if "replay" in reason or "nonce" in reason or "already consumed" in reason:
            return self._resp(Outcome.DENY, reason=r.reason,
                              correlation_id=correlation_id, action_hash=ah), 403
        # Explicit backend/durability failure -> dependency unavailable.
        if any(k in reason for k in ("redis", "could not reserve", "registry unavailable",
                                     "audit-before-actuation", "backend")):
            return self._resp(Outcome.DEPENDENCY_UNAVAILABLE, reason=r.reason,
                              correlation_id=correlation_id, action_hash=ah), 503
        if r.verdict == "ERROR":
            return self._resp(Outcome.GOVERNANCE_UNAVAILABLE, reason=r.reason,
                              correlation_id=correlation_id, action_hash=ah), 503
        # Governance refusal (consensus below threshold, idempotency, velocity, etc.).
        return self._resp(Outcome.DENY, reason=r.reason or "governance refused",
                          correlation_id=correlation_id, action_hash=ah), 403

    @staticmethod
    def _resp(outcome: Outcome, *, executed: bool = False, reason: str = "",
              action_hash: Optional[str] = None, audit_ref: Optional[str] = None,
              correlation_id: Optional[str] = None, challenge_id: Optional[str] = None,
              nonce: Optional[str] = None, approval_request_id: Optional[str] = None,
              constrained_action: Optional[Dict[str, Any]] = None,
              applied_constraints=None, upstream_status: Optional[int] = None,
              upstream_headers=None, upstream_body: Any = None,
              truncated: Optional[bool] = None) -> HTTPExecuteResponse:
        return HTTPExecuteResponse(
            outcome=outcome, executed=executed, reason=reason, action_hash=action_hash,
            audit_ref=audit_ref, correlation_id=correlation_id, challenge_id=challenge_id,
            nonce=nonce, approval_request_id=approval_request_id,
            constrained_action=constrained_action, applied_constraints=applied_constraints or [],
            upstream_status=upstream_status, upstream_headers=upstream_headers,
            upstream_body=upstream_body, truncated=truncated)


# ---------------- app factory ----------------

_REDIS_BACKEND_VARS = (
    "MCC_NONCE_BACKEND", "MCC_IDEMPOTENCY_BACKEND", "MCC_VELOCITY_BACKEND",
    "MCC_APPROVAL_BACKEND", "MCC_CHALLENGE_BACKEND", "MCC_REVOCATION_BACKEND",
)


def _redis_required(env) -> bool:
    return any(env.get(v, "").strip().lower() == "redis" for v in _REDIS_BACKEND_VARS)


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
    service: Optional[EgressService] = None
    runtime: Optional[EgressRuntime] = None
    startup_error: Optional[str] = None
    try:
        runtime = EgressRuntime(cfg, env=env, resolver=resolver)
        service = EgressService(runtime)
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
            response.status_code = 503
            return HTTPExecuteResponse(outcome=Outcome.GOVERNANCE_UNAVAILABLE,
                                       reason=f"runtime not initialized: {startup_error}")
        body, status = await service.handle(req)
        response.status_code = status
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

    @application.get("/health")
    def health() -> Dict[str, Any]:
        body = {"status": "ok", "fail_closed": True, "version": RUNTIME_VERSION,
                "consensus_required": cfg.require_consensus,
                "action_type": "http.request"}
        if service is not None:
            # The policy hash binds votes/tokens; it is public (not a secret).
            body["policy_hash"] = runtime.policy_hash
        return body

    @application.get("/ready")
    async def ready(response: Response) -> Dict[str, Any]:
        checks: Dict[str, Any] = {"runtime_initialized": service is not None}
        if startup_error:
            checks["startup_error"] = startup_error
        if service is not None:
            checks["ephemeral_signing_key"] = runtime.ephemeral_signing_key
            if cfg.require_consensus:
                checks["consensus_verifier"] = (
                    runtime.client.consensus_required and runtime.client.challenges is not None)
        redis_required = _redis_required(env)
        checks["redis_required"] = redis_required
        if redis_required:
            checks["redis"] = await _redis_ok(env)

        required = [checks.get("runtime_initialized", False)]
        if cfg.require_consensus and service is not None:
            required.append(checks.get("consensus_verifier", False))
        if redis_required:
            required.append(checks.get("redis", False))
        ready_now = all(required)
        if not ready_now:
            response.status_code = 503
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
