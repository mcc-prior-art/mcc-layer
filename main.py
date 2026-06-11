#!/usr/bin/env python3
"""
MCC-Core — Execution Governance Runtime with OPA/Rego Policy Adapter

Reference implementation:
- Real OPA/Rego policy evaluation via /v1/data/mcc/decision
- Fail-closed behavior when OPA is unavailable or returns invalid output
- Explicit outcomes: ALLOW / DENY / ESCALATE / CONSTRAIN
- Ed25519-signed decision tokens for ALLOW and CONSTRAIN only
- Append-only hash-chain audit log (fsync on every write)
- Idempotency cache
- Prometheus metrics
- Optional Redis connection placeholder

Intent is not authority.
Execution requires a verified decision.
No verified decision — no execution.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import sys
import time
import uuid
from pathlib import Path
from enum import Enum
from typing import Any, Dict, Optional

import httpx
import redis.asyncio as redis
from fastapi import Depends, FastAPI, Header, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, Histogram, generate_latest
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from mcc_core import (
    AuditLog,
    DecisionEngine,
    PolicyBundle,
    SigningKey,
    hash_payload,
)


# ---------- Settings ----------

class Settings(BaseSettings):
    redis_url: str = "redis://redis:6379"

    signing_key_path: str = ""
    signing_key_id: str = "mcc-core-dev-key-1"
    token_issuer: str = "mcc/core"
    token_audience: str = "execution-gate-1"
    token_ttl_seconds: int = 60

    audit_log_path: str = "audit.jsonl"
    policy_bundle_path: str = "policies/mcc.rego"
    policy_id: str = "mcc.rego/v1"

    api_key: str = "demo-key"

    use_opa: bool = True
    opa_url: str = "http://opa:8181"
    opa_data_path: str = "mcc/decision"
    opa_timeout_seconds: float = 1.5

    class Config:
        env_prefix = "MCC_"


settings = Settings()


# ---------- Logging ----------

logging.basicConfig(level="INFO")
logger = logging.getLogger("mcc")


# ---------- Metrics ----------

DECISIONS = Counter("mcc_decisions_total", "MCC decisions", ["decision"])
OPA_ERRORS = Counter("mcc_opa_errors_total", "OPA evaluation errors", ["reason"])
LATENCY = Histogram("mcc_latency_seconds", "MCC evaluation latency")


# ---------- Redis ----------

redis_client: Optional[redis.Redis] = None


async def get_redis() -> redis.Redis:
    global redis_client
    if redis_client is None:
        redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    return redis_client


# ---------- Models ----------

class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"
    CONSTRAIN = "CONSTRAIN"


class EvaluateRequest(BaseModel):
    session_id: str = Field(..., min_length=1)
    intent: str = Field(..., min_length=1)
    args: Dict[str, Any] = Field(default_factory=dict)
    idempotency_key: Optional[str] = None


class EvaluateResponse(BaseModel):
    decision: Decision
    trace_id: str
    reason: str
    constraints: Dict[str, Any] = Field(default_factory=dict)
    policy_engine: str = "opa"
    policy_ref: Optional[str] = None
    decision_token: Optional[Dict[str, Any]] = None


class PolicyDecision(BaseModel):
    decision: Decision
    reason: str
    constraints: Dict[str, Any] = Field(default_factory=dict)
    policy_ref: Optional[str] = None


# ---------- Auth ----------

def get_tenant(x_api_key: str = Header(...)) -> Dict[str, str]:
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="INVALID_API_KEY")
    return {"tenant": "demo"}


# ---------- OPA Adapter ----------

class OPAAdapter:
    """
    Real OPA/Rego adapter.

    Calls:
        POST {OPA_URL}/v1/data/{OPA_DATA_PATH}

    Expected OPA response:
        {
          "result": {
            "decision": "ALLOW|DENY|ESCALATE|CONSTRAIN",
            "reason": "...",
            "constraints": {...},
            "policy_ref": "optional"
          }
        }

    Fail-closed rule:
        Any timeout, connection error, invalid JSON, missing result,
        or invalid decision resolves to DENY.
    """

    def __init__(self, base_url: str, data_path: str, timeout_seconds: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.data_path = data_path.strip("/")
        self.timeout_seconds = timeout_seconds

    async def evaluate(
        self,
        *,
        tenant: str,
        trace_id: str,
        req: EvaluateRequest,
    ) -> PolicyDecision:
        url = f"{self.base_url}/v1/data/{self.data_path}"
        payload = {
            "input": {
                "tenant": tenant,
                "trace_id": trace_id,
                "session_id": req.session_id,
                "intent": req.intent,
                "args": req.args,
                "ts_unix": int(time.time()),
            }
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
        except httpx.TimeoutException:
            OPA_ERRORS.labels(reason="timeout").inc()
            logger.warning("OPA timeout; fail closed | trace=%s", trace_id)
            return self._deny("OPA timeout; fail closed")
        except httpx.HTTPError as exc:
            OPA_ERRORS.labels(reason="http_error").inc()
            logger.warning("OPA HTTP error; fail closed | trace=%s | error=%s", trace_id, exc)
            return self._deny("OPA HTTP error; fail closed")
        except json.JSONDecodeError:
            OPA_ERRORS.labels(reason="invalid_json").inc()
            logger.warning("OPA invalid JSON; fail closed | trace=%s", trace_id)
            return self._deny("OPA invalid JSON; fail closed")

        result = data.get("result")
        if not isinstance(result, dict):
            OPA_ERRORS.labels(reason="missing_result").inc()
            logger.warning("OPA missing result; fail closed | trace=%s", trace_id)
            return self._deny("OPA missing result; fail closed")

        try:
            return PolicyDecision(
                decision=Decision(result.get("decision")),
                reason=str(result.get("reason") or "OPA decision"),
                constraints=result.get("constraints") if isinstance(result.get("constraints"), dict) else {},
                policy_ref=result.get("policy_ref"),
            )
        except Exception:
            OPA_ERRORS.labels(reason="invalid_decision").inc()
            logger.warning("OPA invalid decision object; fail closed | trace=%s | result=%s", trace_id, result)
            return self._deny("OPA invalid decision; fail closed")

    @staticmethod
    def _deny(reason: str) -> PolicyDecision:
        return PolicyDecision(
            decision=Decision.DENY,
            reason=reason,
            constraints={},
            policy_ref="fail-closed",
        )


# ---------- Local Fallback Policy ----------

class LocalFallbackPolicy:
    """
    Explicit non-production fallback.

    Used only when MCC_USE_OPA=false.
    Default operational posture should use OPA.
    """

    async def evaluate(self, *, req: EvaluateRequest) -> PolicyDecision:
        decision = Decision.DENY
        reason = "deny-by-default"
        constraints: Dict[str, Any] = {}

        if req.intent == "send_payment":
            amount = float(req.args.get("amount", 0))
            if amount <= 5000:
                decision = Decision.ALLOW
                reason = "local fallback: within safe limit"
            elif amount <= 10000:
                decision = Decision.ESCALATE
                reason = "local fallback: requires human approval"
            else:
                decision = Decision.DENY
                reason = "local fallback: amount exceeds policy limit"

        elif req.intent == "delete_user":
            decision = Decision.ESCALATE
            reason = "local fallback: high-risk action requires approval"

        elif req.intent == "delete_database":
            decision = Decision.DENY
            reason = "local fallback: destructive infrastructure action denied"

        return PolicyDecision(
            decision=decision,
            reason=reason,
            constraints=constraints,
            policy_ref="local-fallback",
        )


# ---------- MCC Core ----------

class MCC:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._idem_cache: Dict[str, EvaluateResponse] = {}
        self.opa = OPAAdapter(
            base_url=settings.opa_url,
            data_path=settings.opa_data_path,
            timeout_seconds=settings.opa_timeout_seconds,
        )
        self.local_fallback = LocalFallbackPolicy()

        if settings.signing_key_path:
            self.signing_key = SigningKey.from_pem_file(
                settings.signing_key_path, settings.signing_key_id
            )
        else:
            self.signing_key = SigningKey.generate(settings.signing_key_id)
            logger.warning(
                "MCC_SIGNING_KEY_PATH not set; using ephemeral Ed25519 dev key "
                "(not a production posture)"
            )

        self.audit = AuditLog(settings.audit_log_path)

        # No trusted policy bundle -> no decision engine -> no tokens (fail-closed).
        self.engine: Optional[DecisionEngine] = None
        try:
            self.policy_bundle: Optional[PolicyBundle] = PolicyBundle.from_file(
                settings.policy_bundle_path, settings.policy_id
            )
            self.engine = DecisionEngine(
                signing_key=self.signing_key,
                issuer=settings.token_issuer,
                audience=settings.token_audience,
                policy_id=self.policy_bundle.policy_id,
                policy_hash=self.policy_bundle.policy_hash,
                token_ttl_seconds=settings.token_ttl_seconds,
            )
        except Exception:
            self.policy_bundle = None
            logger.warning(
                "policy bundle unavailable at %s; decision tokens will not be "
                "issued (fail-closed)",
                settings.policy_bundle_path,
            )

    def _trace(self, session_id: str) -> str:
        return hashlib.sha256((session_id + str(uuid.uuid4())).encode()).hexdigest()[:12]

    async def evaluate(self, tenant: str, req: EvaluateRequest) -> EvaluateResponse:
        trace_id = self._trace(req.session_id)

        if req.idempotency_key:
            key = f"{tenant}:{req.idempotency_key}"
            if key in self._idem_cache:
                return self._idem_cache[key]

        if settings.use_opa:
            policy_decision = await self.opa.evaluate(
                tenant=tenant,
                trace_id=trace_id,
                req=req,
            )
            policy_engine = "opa"
        else:
            policy_decision = await self.local_fallback.evaluate(req=req)
            policy_engine = "local-fallback"

        # Audit before any authority is released: no audit record, no token.
        try:
            async with self._lock:
                audit_entry = self.audit.append(
                    {
                        "tenant": tenant,
                        "session_id": req.session_id,
                        "intent": req.intent,
                        "args_hash": hash_payload(req.args),
                        "decision": policy_decision.decision.value,
                        "reason": policy_decision.reason,
                        "trace_id": trace_id,
                        "policy_engine": policy_engine,
                        "policy_ref": policy_decision.policy_ref,
                    }
                )
        except Exception:
            logger.error("audit write failed; fail closed | trace=%s", trace_id)
            policy_decision = PolicyDecision(
                decision=Decision.DENY,
                reason="audit unavailable; fail closed",
                constraints={},
                policy_ref="fail-closed",
            )
            audit_entry = None

        decision_token: Optional[Dict[str, Any]] = None
        if policy_decision.decision in (Decision.ALLOW, Decision.CONSTRAIN):
            try:
                if self.engine is None:
                    raise RuntimeError("decision engine unavailable")
                decision_token = self.engine.issue_token(
                    verdict=policy_decision.decision.value,
                    subject=f"agent/{req.session_id}",
                    action=req.intent,
                    payload=req.args,
                    constraints=policy_decision.constraints,
                    audit_ref=audit_entry["hash"] if audit_entry else None,
                )
            except Exception:
                logger.error(
                    "decision token issuance failed; fail closed | trace=%s", trace_id
                )
                decision_token = None
                policy_decision = PolicyDecision(
                    decision=Decision.DENY,
                    reason="decision token unavailable; fail closed",
                    constraints={},
                    policy_ref="fail-closed",
                )
                try:
                    async with self._lock:
                        self.audit.append(
                            {
                                "tenant": tenant,
                                "intent": req.intent,
                                "decision": Decision.DENY.value,
                                "reason": "token issuance failed; downgraded to DENY",
                                "trace_id": trace_id,
                            }
                        )
                except Exception:
                    logger.error("audit write failed on downgrade | trace=%s", trace_id)

        result = EvaluateResponse(
            decision=policy_decision.decision,
            trace_id=trace_id,
            reason=policy_decision.reason,
            constraints=policy_decision.constraints,
            policy_engine=policy_engine,
            policy_ref=policy_decision.policy_ref,
            decision_token=decision_token,
        )

        if req.idempotency_key:
            key = f"{tenant}:{req.idempotency_key}"
            self._idem_cache[key] = result

        DECISIONS.labels(decision=result.decision.value).inc()

        logger.info(
            "%s | intent=%s | trace=%s | engine=%s | reason=%s",
            result.decision.value,
            req.intent,
            trace_id,
            policy_engine,
            result.reason,
        )

        return result


mcc = MCC()


# ---------- FastAPI ----------

app = FastAPI(
    title="MCC-Core Execution Governance Runtime",
    version="1.2.0-ed25519",
    description=(
        "MCC-Core runtime with real OPA/Rego policy adapter, fail-closed "
        "evaluation, and Ed25519-signed decision tokens."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- API ----------
#
# Authority is carried by the Ed25519-signed decision token inside the
# response body (ALLOW / CONSTRAIN only). There is no transport-level
# symmetric signature: verification happens at the execution gate.

@app.post("/evaluate", response_model=EvaluateResponse)
async def evaluate(req: EvaluateRequest, tenant_ctx: Dict[str, str] = Depends(get_tenant)):
    with LATENCY.time():
        return await mcc.evaluate(tenant_ctx["tenant"], req)


@app.get("/health")
async def health():
    opa_status = "disabled"
    if settings.use_opa:
        try:
            async with httpx.AsyncClient(timeout=0.75) as client:
                r = await client.get(f"{settings.opa_url.rstrip('/')}/health")
                opa_status = "ok" if r.status_code == 200 else f"error:{r.status_code}"
        except Exception:
            opa_status = "unreachable"

    return {
        "status": "ok",
        "policy_engine": "opa" if settings.use_opa else "local-fallback",
        "opa_status": opa_status,
        "fail_closed": True,
        "signing": {
            "algorithm": "Ed25519",
            "kid": mcc.signing_key.kid,
            "public_key_b64": mcc.signing_key.public_key_b64(),
            "ephemeral_key": not bool(settings.signing_key_path),
        },
        "policy_bundle": (
            {
                "policy_id": mcc.policy_bundle.policy_id,
                "policy_hash": mcc.policy_bundle.policy_hash,
            }
            if mcc.policy_bundle
            else "unavailable (tokens not issued; fail-closed)"
        ),
    }


@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type="text/plain")


# ---------- Run ----------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
