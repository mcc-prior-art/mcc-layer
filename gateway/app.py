#!/usr/bin/env python3
"""MCC-Core Gateway — the gate as an HTTP service.

    The model proposes.
    MCC-Core decides.
    The gate enforces.
    The audit chain records.

This is the thin service an interceptor calls on the execution path:

    POST /evaluate  {identity, action, context}
                 -> {decision, reason, signature, audit_id, ...}

It wraps the existing runtime primitives — the authority model resolves a
verdict from mandates, the decision engine signs ALLOW/CONSTRAIN as Ed25519
tokens, and every evaluation is written to the append-only hash-chain audit
log *before* any authority is released.

Two modes:

* ``inline``  — the interceptor enforces the verdict (DENY blocks).
* ``observe`` — verdicts are computed and recorded but not enforced; the
                response carries ``enforce=false`` so a drop-in can be run in
                shadow before it is allowed to block real traffic.

Companion endpoints:

* ``GET /verify`` — recompute the audit hash chain and report integrity.
* ``GET /export`` — hand the signed log to an external auditor.

Fail-closed everywhere: no matched policy, no audit write, or no signed token
means DENY. No verified decision token — no execution.
"""

from __future__ import annotations

import hashlib
import sys
import time
import uuid
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcc_core import (  # noqa: E402
    AuditLog,
    AuthorityModel,
    DecisionEngine,
    SigningKey,
    Verdict,
    canonical_bytes,
    hash_payload,
    sha256_hex,
)

from .pilot_policy import PILOT_POLICY  # noqa: E402


# ---------- Settings ----------

class GatewaySettings(BaseSettings):
    signing_key_path: str = ""
    signing_key_id: str = "mcc-gateway-dev-key-1"
    token_issuer: str = "mcc/core"
    token_audience: str = "egress-gate-1"
    token_ttl_seconds: int = 60

    audit_log_path: str = "audit.jsonl"
    policy_id: str = "pilot-authority/v1"

    # "inline" enforces verdicts; "observe" records but does not enforce.
    mode: str = "observe"

    api_key: str = "demo-key"

    class Config:
        env_prefix = "MCC_GATEWAY_"


settings = GatewaySettings()


# ---------- Models ----------

class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"
    CONSTRAIN = "CONSTRAIN"


class EvaluateRequest(BaseModel):
    identity: str = Field(..., min_length=1, description="Who is asking to act")
    action: str = Field(..., min_length=1, description="What they want to do")
    context: Dict[str, Any] = Field(
        default_factory=dict, description="Parameters of the action"
    )
    # Per-request override of the gateway mode; falls back to the deployment default.
    mode: Optional[str] = None


class EvaluateResponse(BaseModel):
    decision: Decision
    reason: str
    audit_id: str
    # Detached Ed25519 signature of the decision token (ALLOW/CONSTRAIN only).
    signature: Optional[str] = None
    # Full signed decision token; the artifact the execution gate verifies.
    decision_token: Optional[Dict[str, Any]] = None
    constraints: Dict[str, Any] = Field(default_factory=dict)
    # The body the verdict authorizes: original context for ALLOW, rewritten
    # (clamped) context for CONSTRAIN. The decision token is signed over this.
    forward_context: Dict[str, Any] = Field(default_factory=dict)
    # Human-readable list of rewrites applied for CONSTRAIN (empty otherwise).
    applied_constraints: List[str] = Field(default_factory=list)
    # False in observe mode: decision recorded, interceptor must not block on it.
    enforce: bool = True
    mode: str = "observe"
    authority_required: Optional[str] = None
    policy_ref: str = ""
    trace_id: str = ""


# ---------- Auth ----------

def get_caller(x_api_key: str = Header(...)) -> str:
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="INVALID_API_KEY")
    return "pilot"


# ---------- Gateway ----------

class Gateway:
    def __init__(self) -> None:
        # The authority policy in force, and a hash that binds every decision
        # token to the exact configuration that produced it.
        self.authority = AuthorityModel.from_config(PILOT_POLICY)
        self.policy_hash = sha256_hex(canonical_bytes(PILOT_POLICY))

        if settings.signing_key_path:
            self.signing_key = SigningKey.from_pem_file(
                settings.signing_key_path, settings.signing_key_id
            )
            self.ephemeral_key = False
        else:
            self.signing_key = SigningKey.generate(settings.signing_key_id)
            self.ephemeral_key = True

        self.audit = AuditLog(settings.audit_log_path)
        self.engine = DecisionEngine(
            signing_key=self.signing_key,
            issuer=settings.token_issuer,
            audience=settings.token_audience,
            policy_id=settings.policy_id,
            policy_hash=self.policy_hash,
            token_ttl_seconds=settings.token_ttl_seconds,
        )

    @staticmethod
    def _trace(identity: str) -> str:
        return hashlib.sha256((identity + uuid.uuid4().hex).encode()).hexdigest()[:12]

    def evaluate(self, req: EvaluateRequest) -> EvaluateResponse:
        trace_id = self._trace(req.identity)
        mode = (req.mode or settings.mode).lower()
        enforce = mode == "inline"

        # 1. The verdict follows from authority, not from a bare condition.
        authority = self.authority.evaluate(
            identity=req.identity, action=req.action, context=req.context
        )
        decision = Decision(authority.verdict.value)
        reason = authority.reason
        constraints = authority.constraints
        # The body the verdict authorizes (rewritten for CONSTRAIN). The token
        # is signed over this, so the gate binds to what is actually forwarded.
        forward_context = dict(authority.forward_context)
        applied = list(authority.applied_changes)

        # 2. Record before releasing any authority: no audit entry, no token.
        try:
            entry = self.audit.append(
                {
                    "kind": "evaluate",
                    "identity": req.identity,
                    "action": req.action,
                    "context_hash": hash_payload(req.context),
                    "forward_context_hash": hash_payload(forward_context)
                    if forward_context
                    else None,
                    "applied_constraints": applied,
                    "decision": decision.value,
                    "reason": reason,
                    "authority_required": authority.authority_required,
                    "mandate_holder": authority.mandate_holder,
                    "mode": mode,
                    "enforced": enforce,
                    "policy_id": settings.policy_id,
                    "policy_hash": self.policy_hash,
                    "trace_id": trace_id,
                }
            )
            audit_id = entry["hash"]
        except Exception:
            return EvaluateResponse(
                decision=Decision.DENY,
                reason="audit log unavailable; fail-closed",
                audit_id="",
                enforce=enforce,
                mode=mode,
                policy_ref=f"{settings.policy_id}@{self.policy_hash}",
                trace_id=trace_id,
            )

        # 3. Sign ALLOW/CONSTRAIN into a decision token; downgrade to DENY on
        #    any signing failure (fail-closed).
        decision_token: Optional[Dict[str, Any]] = None
        signature: Optional[str] = None
        if authority.verdict in (Verdict.ALLOW, Verdict.CONSTRAIN):
            try:
                decision_token = self.engine.issue_token(
                    verdict=authority.verdict.value,
                    subject=req.identity,
                    action=req.action,
                    payload=forward_context,
                    constraints=constraints,
                    audit_ref=audit_id,
                )
                signature = decision_token["sig"]
            except Exception:
                decision = Decision.DENY
                reason = "decision token unavailable; fail-closed"
                decision_token = None
                signature = None
                constraints = {}
                forward_context = {}
                applied = []
                try:
                    self.audit.append(
                        {
                            "kind": "downgrade",
                            "identity": req.identity,
                            "action": req.action,
                            "decision": Decision.DENY.value,
                            "reason": "token issuance failed; downgraded to DENY",
                            "trace_id": trace_id,
                        }
                    )
                except Exception:
                    pass

        return EvaluateResponse(
            decision=decision,
            reason=reason,
            audit_id=audit_id,
            signature=signature,
            decision_token=decision_token,
            constraints=constraints,
            forward_context=forward_context,
            applied_constraints=applied,
            enforce=enforce,
            mode=mode,
            authority_required=authority.authority_required,
            policy_ref=f"{settings.policy_id}@{self.policy_hash}",
            trace_id=trace_id,
        )

    def verify_chain(self) -> Dict[str, Any]:
        valid = AuditLog.verify_chain(settings.audit_log_path)
        entries = self._read_entries()
        head = entries[-1]["hash"] if entries else None
        return {
            "valid": valid,
            "entries": len(entries),
            "head_hash": head,
            "signing_kid": self.signing_key.kid,
            "public_key_b64": self.signing_key.public_key_b64(),
        }

    def _read_entries(self) -> List[Dict[str, Any]]:
        import json

        path = Path(settings.audit_log_path)
        if not path.exists():
            return []
        out: List[Dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out


gateway = Gateway()


# ---------- FastAPI ----------

app = FastAPI(
    title="MCC-Core Gateway",
    version="1.0.0-mvp",
    description=(
        "Gate-as-a-service: authority-driven verdicts, Ed25519 decision "
        "tokens, append-only signed audit. The interceptor calls /evaluate "
        "on the execution path."
    ),
)


@app.post("/evaluate", response_model=EvaluateResponse, response_model_exclude_none=False)
def evaluate(req: EvaluateRequest, _caller: str = Depends(get_caller)) -> EvaluateResponse:
    return gateway.evaluate(req)


@app.get("/verify")
def verify(_caller: str = Depends(get_caller)) -> Dict[str, Any]:
    """Recompute the audit hash chain and report integrity."""
    return gateway.verify_chain()


@app.get("/export")
def export(
    _caller: str = Depends(get_caller),
    fmt: str = Query("jsonl", pattern="^(jsonl|json)$"),
) -> Response:
    """Hand the append-only signed audit log to an external auditor.

    The export is self-verifying: it carries the chain-validity flag and the
    Ed25519 public key needed to check every issued decision token.
    """
    import json

    entries = gateway._read_entries()
    valid = AuditLog.verify_chain(settings.audit_log_path)
    if fmt == "jsonl":
        body = "\n".join(json.dumps(e, sort_keys=True) for e in entries)
        return PlainTextResponse(
            body,
            media_type="application/x-ndjson",
            headers={"Content-Disposition": "attachment; filename=mcc-audit.jsonl"},
        )
    payload = {
        "chain_valid": valid,
        "entries": entries,
        "signing": {
            "algorithm": "Ed25519",
            "kid": gateway.signing_key.kid,
            "public_key_b64": gateway.signing_key.public_key_b64(),
        },
        "policy_ref": f"{settings.policy_id}@{gateway.policy_hash}",
    }
    return Response(
        json.dumps(payload, sort_keys=True),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=mcc-audit.json"},
    )


@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "mode": settings.mode,
        "fail_closed": True,
        "token_audience": settings.token_audience,
        "policy_hash": gateway.policy_hash,
        "signing": {
            "algorithm": "Ed25519",
            "kid": gateway.signing_key.kid,
            "public_key_b64": gateway.signing_key.public_key_b64(),
            "ephemeral_key": gateway.ephemeral_key,
        },
        "policy_ref": f"{settings.policy_id}@{gateway.policy_hash}",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
