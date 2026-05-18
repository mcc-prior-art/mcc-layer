#!/usr/bin/env python3
"""
MCC-Core — Execution Governance Runtime with OPA/Rego Policy Adapter

Reference implementation:
- Real OPA/Rego policy evaluation via /v1/data/mcc/decision
- Fail-closed behavior when OPA is unavailable or returns invalid output
- Explicit outcomes: ALLOW / DENY / ESCALATE / CONSTRAIN
- HMAC response signature
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
import hmac
import json
import logging
import time
import uuid
from enum import Enum
from typing import Any, Dict, Optional

import httpx
import redis.asyncio as redis
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, Histogram, generate_latest
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from starlette.middleware.base import BaseHTTPMiddleware


# ---------- Settings ----------

class Settings(BaseSettings):
    hmac_secret: str = "change-me"
    redis_url: str = "redis://redis:6379"

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
        self.prev_hash = "GENESIS"
        self._lock = asyncio.Lock()
        self._idem_cache: Dict[str, EvaluateResponse] = {}
        self.opa = OPAAdapter(
            base_url=settings.opa_url,
            data_path=settings.opa_data_path,
            timeout_seconds=settings.opa_timeout_seconds,
        )
        self.local_fallback = LocalFallbackPolicy()

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

        result = EvaluateResponse(
            decision=policy_decision.decision,
            trace_id=trace_id,
            reason=policy_decision.reason,
            constraints=policy_decision.constraints,
            policy_engine=policy_engine,
            policy_ref=policy_decision.policy_ref,
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
    version="1.1.0-opa",
    description="MCC-Core runtime with real OPA/Rego policy adapter and fail-closed evaluation.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Signature Middleware ----------

class SignMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if request.url.path == "/evaluate":
            body = b""
            async for chunk in response.body_iterator:
                body += chunk

            sig = hmac.new(
                settings.hmac_secret.encode(),
                body,
                hashlib.sha256,
            ).hexdigest()

            return Response(
                content=body,
                headers={"X-MCC-Signature": sig},
                media_type="application/json",
                status_code=response.status_code,
            )

        return response


app.add_middleware(SignMiddleware)


# ---------- API ----------

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
    }


@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type="text/plain")


# ---------- Run ----------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
