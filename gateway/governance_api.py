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


class ApprovalCreateRequest(_Strict):
    actor: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: Optional[str] = None
    transaction_id: Optional[str] = None
    policy_hash: Optional[str] = None
    payload_hash: Optional[str] = None
    constraints: Optional[Dict[str, Any]] = None
    ttl_seconds: Optional[int] = Field(default=None, ge=1)


class ApprovalCreateResponse(_Strict):
    request_id: str
    state: str


class ApprovalStatusResponse(_Strict):
    request_id: str
    state: str
    actor: str
    action: str
    resource: Optional[str] = None
    transaction_id: Optional[str] = None
    created_at: int
    expires_at: int


class ApprovalDecisionResponse(_Strict):
    request_id: str
    state: str
    mandate: Optional[Dict[str, Any]] = None


class ApprovalExecuteRequest(_Strict):
    mandate: Dict[str, Any]
    actor: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    transaction_id: Optional[str] = None
    idempotency_key: Optional[str] = None


class ConsensusVerifyRequest(_Strict):
    votes: List[Dict[str, Any]]
    actor: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    nonce: Optional[str] = None


class ConsensusVerifyResponse(_Strict):
    verdict: str
    reason: str
    agreement: int
    threshold: int
    evaluators: List[str]
    rejected_votes: int


class ConsensusExecuteRequest(_Strict):
    votes: List[Dict[str, Any]]
    actor: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    transaction_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    nonce: Optional[str] = None
    challenge_id: Optional[str] = None


class ChallengeCreateRequest(_Strict):
    actor: str = Field(min_length=1)
    action: str = Field(min_length=1)
    resource: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: Optional[int] = Field(default=None, ge=1)


class ChallengeCreateResponse(_Strict):
    challenge_id: str
    nonce: str
    action: str
    actor: str
    resource: Optional[str] = None
    payload_hash: str
    policy_hash: Optional[str] = None
    issued_at: int
    expires_at: int


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


def mount_approval_routes(app: FastAPI, service: GovernanceService, *, api_key: str,
                          operator_key: Optional[str]) -> None:
    """ESCALATE approval endpoints. Operators approve/deny/invalidate; agents
    create requests and execute the approved single-use mandate. Human approval
    never executes — it only mints bounded authority."""
    require_agent, require_operator = _auth_deps(api_key, operator_key)

    @app.post("/approvals", response_model=ApprovalCreateResponse)
    async def create_approval(req: ApprovalCreateRequest, _=Depends(require_agent)):
        out = await service.create_approval(
            actor=req.actor, action=req.action, resource=req.resource,
            transaction_id=req.transaction_id, policy_hash=req.policy_hash,
            payload_hash=req.payload_hash, constraints=req.constraints,
            ttl_seconds=req.ttl_seconds,
        )
        return ApprovalCreateResponse(**out)

    @app.get("/approvals/{request_id}", response_model=ApprovalStatusResponse)
    async def get_approval(request_id: str, _=Depends(require_agent)):
        rec = await service.get_approval(request_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="approval not found")
        return ApprovalStatusResponse(**rec)

    @app.post("/approvals/{request_id}/approve", response_model=ApprovalDecisionResponse)
    async def approve(request_id: str, _=Depends(require_operator)):
        mandate = await service.approve(request_id)
        if mandate is None:
            rec = await service.get_approval(request_id)
            state = rec["state"] if rec else "NOT_FOUND"
            raise HTTPException(status_code=409, detail=f"not approvable in state {state}")
        return ApprovalDecisionResponse(request_id=request_id, state="APPROVED", mandate=mandate)

    @app.post("/approvals/{request_id}/deny", response_model=ApprovalDecisionResponse)
    async def deny(request_id: str, _=Depends(require_operator)):
        if not await service.deny(request_id):
            raise HTTPException(status_code=409, detail="not deniable in current state")
        return ApprovalDecisionResponse(request_id=request_id, state="DENIED")

    @app.post("/approvals/{request_id}/invalidate", response_model=ApprovalDecisionResponse)
    async def invalidate(request_id: str, _=Depends(require_operator)):
        if not await service.invalidate(request_id):
            raise HTTPException(status_code=409, detail="not invalidatable in current state")
        return ApprovalDecisionResponse(request_id=request_id, state="INVALIDATED")

    @app.post("/approvals/{request_id}/execute", response_model=ExecuteResponse)
    async def execute_with_approval(request_id: str, req: ApprovalExecuteRequest,
                                    _=Depends(require_agent)):
        out = await service.execute_with_approval(
            mandate=req.mandate, actor=req.actor, action=req.action, resource=req.resource,
            context=req.context, transaction_id=req.transaction_id,
            idempotency_key=req.idempotency_key,
        )
        return ExecuteResponse(status=out.status, reason=out.reason, decision=out.decision,
                               audit_ref=out.audit_ref, execution=out.execution)


def mount_consensus_routes(app: FastAPI, service: GovernanceService, *, api_key: str,
                           operator_key: Optional[str]) -> None:
    """Multi-Context Consensus endpoints: N-of-M independent signed evaluators
    must agree before a token is issued. /verify is a pure check; /execute runs
    the one coordinator path only on consensus."""
    require_agent, _ = _auth_deps(api_key, operator_key)

    @app.post("/consensus/challenge", response_model=ChallengeCreateResponse)
    async def create_challenge(req: ChallengeCreateRequest, _=Depends(require_agent)):
        out = await service.issue_challenge(
            action=req.action, actor=req.actor, resource=req.resource,
            context=req.context, ttl_seconds=req.ttl_seconds)
        if "error" in out:
            raise HTTPException(status_code=409, detail=out["error"])
        return ChallengeCreateResponse(**out)

    @app.post("/consensus/verify", response_model=ConsensusVerifyResponse)
    async def verify_consensus(req: ConsensusVerifyRequest, _=Depends(require_agent)):
        out = await service.verify_consensus(votes=req.votes, action=req.action,
                                             context=req.context, actor=req.actor,
                                             resource=req.resource, nonce=req.nonce)
        return ConsensusVerifyResponse(**out)

    @app.post("/consensus/execute", response_model=ExecuteResponse)
    async def execute_with_consensus(req: ConsensusExecuteRequest, _=Depends(require_agent)):
        out = await service.execute_with_consensus(
            votes=req.votes, actor=req.actor, action=req.action, resource=req.resource,
            context=req.context, transaction_id=req.transaction_id,
            idempotency_key=req.idempotency_key, nonce=req.nonce,
            challenge_id=req.challenge_id)
        return ExecuteResponse(status=out.status, reason=out.reason, decision=out.decision,
                               audit_ref=out.audit_ref, execution=out.execution)


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
        ChallengeService,
        EnforcementCoordinator,
        ExecutionGate,
        ProfileRegistry,
        SigningKey,
        VelocityLimit,
        approval_registry_from_env,
        challenge_registry_from_env,
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

    # Optional Multi-Context Consensus: a separate trust set of evaluator keys
    # plus an N-of-M threshold. Disabled (None) unless a config is provided.
    consensus_verifier = _build_consensus_verifier(env)

    # Mandatory consensus: when MCC_REQUIRE_CONSENSUS is set, the coordinator
    # refuses to actuate any governed action without a valid N-of-M consensus
    # bound to the token. Refuse fail-open startup: require a verifier to exist.
    require_consensus = _env_flag(env, "MCC_REQUIRE_CONSENSUS")
    if require_consensus and consensus_verifier is None:
        raise RuntimeError(
            "MCC_REQUIRE_CONSENSUS is set but no consensus trust config "
            "(MCC_CONSENSUS_TRUST_CONFIG) was provided; refusing fail-open startup"
        )

    # Consensus challenge: the gateway issues the one-time nonce. The challenge
    # store is single-use and TTL-bounded; the coordinator consumes it before
    # actuation. Always available; MCC_REQUIRE_CHALLENGE makes a gateway-issued
    # challenge mandatory for actuation (clients can no longer supply a nonce).
    challenge_service = ChallengeService(challenge_registry_from_env(env))
    require_challenge = _env_flag(env, "MCC_REQUIRE_CHALLENGE")

    coordinator = EnforcementCoordinator(
        gate=gate, idempotency=idempotency_registry_from_env(env),
        velocity=velocity_registry_from_env(env), audit=audit,
        profiles=ProfileRegistry.default_pilot(), velocity_limits_for=limits_for,
        revocation_registry=revocation, approvals=approvals,
        consensus_verifier=consensus_verifier, require_consensus=require_consensus,
        challenges=challenge_service, require_challenge=require_challenge,
    )

    if upstream is None:
        base = env.get("MCC_UPSTREAM_BASE", "").strip()
        upstream = _httpx_upstream(base) if base else None

    return GovernanceService(
        engine=engine, coordinator=coordinator, trust_set=trust_set,
        revocation_registry=revocation, approvals=approvals,
        profiles=ProfileRegistry.default_pilot(), upstream=upstream, policy_hash=policy_hash,
        consensus_verifier=consensus_verifier, challenge_service=challenge_service,
    )


def _env_flag(env, name: str) -> bool:
    return env.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _build_consensus_verifier(env):
    import json
    from pathlib import Path

    from mcc_core import ConsensusPolicy, ConsensusVerifier
    from .trust import load_trust_config

    path = env.get("MCC_CONSENSUS_TRUST_CONFIG", "").strip()
    if not path:
        return None
    trust = load_trust_config(json.loads(Path(path).read_text(encoding="utf-8")))
    import time
    threshold = int(env.get("MCC_CONSENSUS_THRESHOLD", "3"))
    return ConsensusVerifier(
        trusted_keys=trust.active_trusted_keys(now=int(time.time())),
        policy=ConsensusPolicy(threshold=threshold),
    )
