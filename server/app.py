#!/usr/bin/env python3
"""
MCC Policy Engine — production-grade single-file reference

DEPRECATED (2026-06-11): legacy standalone runtime kept for historical
reference only. It predates Ed25519 decision tokens and does not issue
them, which conflicts with the MCC-Core invariant
"no verified decision token — no execution".

The supported runtime is main.py + src/mcc_core/.
Do not deploy this module. Removal requires explicit AX approval.
"""

import warnings

warnings.warn(
    "server/app.py is a deprecated legacy runtime without Ed25519 decision "
    "tokens; use main.py + src/mcc_core/ instead",
    DeprecationWarning,
    stacklevel=2,
)

import os
import time
import json
import uuid
import hashlib
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel, Field, model_validator

# =========================
# CONFIG
# =========================

MAX_INTENT_LENGTH = 64
MAX_ARGS_BYTES = 2048
POLICY_TIMEOUT_SEC = 0.2
RATE_LIMIT_PER_MIN = 60
BLOCK_WINDOW_SEC = 30

API_KEYS = {
    os.getenv("MCC_API_KEY", "demo-key"): {
        "tenant": "tenant_demo",
        "scopes": ["payments:write"]
    }
}

# =========================
# LOGGING
# =========================

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcc")

# =========================
# MODELS
# =========================

class EvaluateRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    intent: str = Field(..., min_length=1, max_length=MAX_INTENT_LENGTH)
    args: Dict[str, Any] = Field(default_factory=dict)
    idempotency_key: Optional[str] = None

    @model_validator(mode="after")
    def validate_args_size(self):
        if len(json.dumps(self.args)) > MAX_ARGS_BYTES:
            raise ValueError("ARGS_TOO_LARGE")
        return self


class Reason(BaseModel):
    code: str
    message: str


class EvaluateResponse(BaseModel):
    decision: str
    reason: Reason
    trace_id: str
    request_id: str


# =========================
# RATE LIMIT
# =========================

rate_lock = asyncio.Lock()
rate_counters = defaultdict(list)
blocked_until = defaultdict(float)


async def check_rate_limit(tenant: str):
    async with rate_lock:
        now = time.time()

        if blocked_until[tenant] > now:
            raise HTTPException(status_code=429, detail="RATE_LIMIT_BLOCKED")

        rate_counters[tenant] = [t for t in rate_counters[tenant] if t > now - 60]

        if len(rate_counters[tenant]) >= RATE_LIMIT_PER_MIN:
            blocked_until[tenant] = now + BLOCK_WINDOW_SEC
            raise HTTPException(status_code=429, detail="RATE_LIMIT_EXCEEDED")

        rate_counters[tenant].append(now)


# =========================
# AUTH
# =========================

def get_tenant(x_api_key: str = Header(...)):
    if x_api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="INVALID_API_KEY")
    return API_KEYS[x_api_key]


# =========================
# IDEMPOTENCY
# =========================

idempotency_cache: Dict[str, EvaluateResponse] = {}

# =========================
# POLICY
# =========================

POLICY = {
    "send_payment": {
        "max_amount": 10000,
        "scope": "payments:write"
    },
    "delete_user": {
        "forbidden": True
    }
}

# =========================
# MCC CORE
# =========================

class MCC:
    def __init__(self):
        self.prev_hash = "GENESIS"
        self.audit_log = []
        self.lock = asyncio.Lock()

    def _hash(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    async def _audit(self, tenant, req, decision, reason, trace_id, request_id):
        async with self.lock:
            record = {
                "timestamp": self._now(),
                "tenant": tenant,
                "request": req.model_dump(),
                "decision": decision,
                "reason": reason.model_dump(),
                "trace_id": trace_id,
                "request_id": request_id,
                "prev_hash": self.prev_hash
            }

            serialized = json.dumps(record, sort_keys=True)
            current_hash = hashlib.sha256((self.prev_hash + serialized).encode()).hexdigest()

            self.prev_hash = current_hash
            self.audit_log.append({**record, "hash": current_hash})

    async def evaluate(self, tenant_ctx, req: EvaluateRequest) -> EvaluateResponse:
        tenant = tenant_ctx["tenant"]
        scopes = tenant_ctx["scopes"]

        request_id = str(uuid.uuid4())
        trace_id = hashlib.sha256((request_id + req.session_id).encode()).hexdigest()[:12]

        if req.idempotency_key and req.idempotency_key in idempotency_cache:
            return idempotency_cache[req.idempotency_key]

        try:
            result = await asyncio.wait_for(
                self._evaluate_internal(scopes, req, trace_id, request_id),
                timeout=POLICY_TIMEOUT_SEC
            )
        except asyncio.TimeoutError:
            result = EvaluateResponse(
                decision="DENY",
                reason=Reason(code="TIMEOUT", message="policy timeout"),
                trace_id=trace_id,
                request_id=request_id
            )
        except Exception:
            result = EvaluateResponse(
                decision="DENY",
                reason=Reason(code="ERROR", message="fail-closed"),
                trace_id=trace_id,
                request_id=request_id
            )

        await self._audit(tenant, req, result.decision, result.reason, trace_id, request_id)

        if req.idempotency_key:
            idempotency_cache[req.idempotency_key] = result

        logger.info(f"{tenant} {req.intent} -> {result.decision}")
        return result

    async def _evaluate_internal(self, scopes, req, trace_id, request_id):
        policy = POLICY.get(req.intent)

        if not policy:
            return EvaluateResponse(
                decision="DENY",
                reason=Reason(code="UNKNOWN_INTENT", message="not allowed"),
                trace_id=trace_id,
                request_id=request_id
            )

        if policy.get("forbidden"):
            return EvaluateResponse(
                decision="DENY",
                reason=Reason(code="FORBIDDEN", message="blocked by policy"),
                trace_id=trace_id,
                request_id=request_id
            )

        if policy.get("scope") and policy["scope"] not in scopes:
            return EvaluateResponse(
                decision="DENY",
                reason=Reason(code="FORBIDDEN_SCOPE", message="missing scope"),
                trace_id=trace_id,
                request_id=request_id
            )

        if req.intent == "send_payment":
            amount = req.args.get("amount", 0)

            if amount <= policy["max_amount"]:
                return EvaluateResponse(
                    decision="ALLOW",
                    reason=Reason(code="OK", message="within limit"),
                    trace_id=trace_id,
                    request_id=request_id
                )

            return EvaluateResponse(
                decision="DENY",
                reason=Reason(code="LIMIT", message="amount too large"),
                trace_id=trace_id,
                request_id=request_id
            )

        return EvaluateResponse(
            decision="DENY",
            reason=Reason(code="DEFAULT", message="blocked"),
            trace_id=trace_id,
            request_id=request_id
        )

# =========================
# APP
# =========================

app = FastAPI(title="MCC Policy Engine", version="1.0")
mcc = MCC()

@app.post("/evaluate", response_model=EvaluateResponse)
async def evaluate(req: EvaluateRequest, tenant_ctx: Dict = Depends(get_tenant)):
    await check_rate_limit(tenant_ctx["tenant"])
    return await mcc.evaluate(tenant_ctx, req)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/ready")
def ready():
    return {"ready": True}
