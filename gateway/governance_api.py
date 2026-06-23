"""Governance HTTP API — thin transport over GovernanceService.

Route handlers do exactly three things: validate the request schema, call the
service, and shape the response. No governance decision logic lives here, and
there is no endpoint that reaches the upstream without going through the
coordinator + gate. Two authentication boundaries:

* **agent** (``X-API-Key``)      — propose/verify/execute.
* **operator** (``X-Operator-Key``) — approve/deny/invalidate/revoke/trust admin.

Mandate routes are mounted here; approval routes are added by
``mount_approval_routes`` (separate module surface).
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .governance_service import GovernanceService


# ---------- schemas (strict: unknown fields rejected) ----------

class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MandateVerifyRequest(_Strict):
    mandate: Dict[str, Any]
    subject: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: Optional[str] = None
    policy_hash: Optional[str] = None


class MandateVerifyResponse(_Strict):
    verified: bool
    reason: str
    mandate_id: Optional[str] = None
    issuer_id: Optional[str] = None
    constraints: Optional[Dict[str, Any]] = None


class MandateExecuteRequest(_Strict):
    mandate: Dict[str, Any]
    actor: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    transaction_id: Optional[str] = None
    idempotency_key: Optional[str] = None


class ExecuteResponse(_Strict):
    status: str
    reason: str
    decision: Optional[str] = None
    audit_ref: Optional[str] = None
    execution: Any = None


class RevocationStatusResponse(_Strict):
    mandate_id: str
    status: str


class OkResponse(_Strict):
    ok: bool
    detail: Optional[str] = None


# ---------- auth boundaries ----------

def _auth_deps(api_key: str, operator_key: Optional[str]):
    def require_agent(x_api_key: str = Header(...)) -> str:
        if x_api_key != api_key:
            raise HTTPException(status_code=401, detail="INVALID_API_KEY")
        return "agent"

    def require_operator(x_operator_key: Optional[str] = Header(default=None)) -> str:
        # No operator key configured, or a missing/incorrect one -> no operator
        # actions (fail closed with 403, not a 422 validation error).
        if not operator_key or x_operator_key != operator_key:
            raise HTTPException(status_code=403, detail="INVALID_OPERATOR_KEY")
        return "operator"

    return require_agent, require_operator


def mount_mandate_routes(app: FastAPI, service: GovernanceService, *, api_key: str,
                         operator_key: Optional[str]) -> None:
    require_agent, require_operator = _auth_deps(api_key, operator_key)

    @app.post("/mandates/verify", response_model=MandateVerifyResponse)
    async def verify_mandate(req: MandateVerifyRequest, _=Depends(require_agent)):
        out = await service.verify_mandate(
            mandate=req.mandate, subject=req.subject, action=req.action,
            resource=req.resource, policy_hash=req.policy_hash,
        )
        return MandateVerifyResponse(verified=out.verified, reason=out.reason,
                                     mandate_id=out.mandate_id, issuer_id=out.issuer_id,
                                     constraints=out.constraints)

    @app.post("/mandates/execute", response_model=ExecuteResponse)
    async def execute_with_mandate(req: MandateExecuteRequest, _=Depends(require_agent)):
        out = await service.execute_with_mandate(
            mandate=req.mandate, actor=req.actor, action=req.action, resource=req.resource,
            context=req.context, transaction_id=req.transaction_id,
            idempotency_key=req.idempotency_key,
        )
        return ExecuteResponse(status=out.status, reason=out.reason, decision=out.decision,
                               audit_ref=out.audit_ref, execution=out.execution)

    @app.get("/mandates/{mandate_id}/revocation", response_model=RevocationStatusResponse)
    async def revocation_status(mandate_id: str, _=Depends(require_agent)):
        return RevocationStatusResponse(mandate_id=mandate_id,
                                        status=await service.revocation_status(mandate_id))

    @app.post("/mandates/{mandate_id}/revoke", response_model=OkResponse)
    async def revoke_mandate(mandate_id: str, _=Depends(require_operator)):
        return OkResponse(ok=await service.revoke_mandate(mandate_id))

    # ---- trust administration (operator) ----

    @app.get("/trust")
    async def trust_summary(_=Depends(require_operator)) -> List[dict]:
        return service.trust_set.summary()

    @app.post("/trust/issuers/{issuer_id}/disable", response_model=OkResponse)
    async def disable_issuer(issuer_id: str, _=Depends(require_operator)):
        return OkResponse(ok=service.trust_set.disable_issuer(issuer_id))

    @app.post("/trust/keys/{kid}/revoke", response_model=OkResponse)
    async def revoke_key(kid: str, _=Depends(require_operator)):
        return OkResponse(ok=service.trust_set.revoke_key(kid))


# ---------- service builder ----------

def _httpx_upstream(base: str, timeout: float = 10.0):
    import httpx

    async def upstream(action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(f"{base.rstrip('/')}/{action}", json=payload)
            try:
                body = resp.json()
            except Exception:
                body = resp.text
            return {"upstream_status": resp.status_code, "body": body}

    return upstream


def build_governance_service(
    *, engine, signing_key, audit, policy_hash: str, token_audience: str,
    env: Optional[Dict[str, str]] = None, upstream=None,
) -> GovernanceService:
    """Assemble a GovernanceService from env-selected backends, reusing the
    gateway's decision engine, signing key, and audit chain. Refuses startup in
    pilot if the trust configuration is invalid (TrustConfigError)."""
    from mcc_core import (
        ApprovalService,
        EnforcementCoordinator,
        ExecutionGate,
        ProfileRegistry,
        SigningKey,
        VelocityLimit,
        approval_registry_from_env,
        idempotency_registry_from_env,
        nonce_registry_from_env,
        revocation_registry_from_env,
        velocity_registry_from_env,
    )

    from .pilot_policy import PILOT_VELOCITY
    from .trust import trust_set_from_env

    env = os.environ if env is None else env
    trust_set = trust_set_from_env(env)

    approver_path = env.get("MCC_APPROVER_SIGNING_KEY_PATH", "").strip()
    approver_kid = env.get("MCC_APPROVER_KEY_ID", "mcc-approver-1")
    if approver_path:
        approver_key = SigningKey.from_pem_file(approver_path, approver_kid)
    else:
        approver_key = SigningKey.generate(approver_kid)
    # The gateway is itself the approval issuer: trust its approver public key
    # by construction (not via external config).
    trust_set.add_runtime_issuer("mcc/approvals", approver_key.kid, approver_key.public_key())

    gate = ExecutionGate(
        trusted_keys={signing_key.kid: signing_key.public_key()},
        audience=token_audience, nonce_registry=nonce_registry_from_env(env),
        policy_hash=policy_hash,
    )
    revocation = revocation_registry_from_env(env)
    approvals = ApprovalService(approval_registry_from_env(env), approver_key)

    limits = {pat: [VelocityLimit.from_config(i) for i in items]
              for pat, items in PILOT_VELOCITY.items()}

    def limits_for(action: str):
        import fnmatch
        for pat, lst in limits.items():
            if fnmatch.fnmatchcase(action, pat):
                return lst
        return []

    coordinator = EnforcementCoordinator(
        gate=gate, idempotency=idempotency_registry_from_env(env),
        velocity=velocity_registry_from_env(env), audit=audit,
        profiles=ProfileRegistry.default_pilot(), velocity_limits_for=limits_for,
        revocation_registry=revocation, approvals=approvals,
    )

    if upstream is None:
        base = env.get("MCC_UPSTREAM_BASE", "").strip()
        upstream = _httpx_upstream(base) if base else None

    return GovernanceService(
        engine=engine, coordinator=coordinator, trust_set=trust_set,
        revocation_registry=revocation, approvals=approvals,
        profiles=ProfileRegistry.default_pilot(), upstream=upstream, policy_hash=policy_hash,
    )
