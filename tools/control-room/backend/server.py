"""The Control Room's backend-for-frontend (BFF).

This is the ONLY code the browser ever talks to. It contains **no**
governance decision logic of its own: every route is a thin translation
between an HTTP request from the browser and a call through
``pilot.client.MCCGatewayClient`` against the real, separately-running
``gateway.app`` process (see :mod:`runtime`). Nothing here computes a
verdict, mints or verifies a token, or writes an audit entry -- it only
displays what the real gateway already returned.

Trust boundary: the browser never receives the demo's evaluator private
keys, the operator API key, or the gateway signing key. Consensus votes are
signed inside this process (never in the browser); operator actions
(``/approvals/{id}/approve``) are issued from this process using a key held
only here.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

_HERE = Path(__file__).resolve()
ROOT = _HERE.parents[3]
for _p in (str(ROOT),):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from pilot.client import MCCGatewayError  # noqa: E402

from .runtime import DemoRuntime  # noqa: E402
from .scenarios import (  # noqa: E402
    SCENARIO_METADATA,
    SCENARIOS,
    audit_entries_by_trace,
    client_for,
    run_execution,
    token_view,
)

FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"

DISCLAIMER_LABEL = "Local Self-Administered Demonstration — Not a Production Administrative Console"
DISCLAIMER_TEXT = (
    "This is a local, self-administered demonstration of the MCC-Core "
    "protocol implementation. It is not a third-party audit, production "
    "administrative console, or production deployment."
)


class ProposeRequest(BaseModel):
    identity: str
    action: str
    context: Dict[str, Any] = {}
    resource_id: Optional[str] = None


class ExecuteRequest(BaseModel):
    actor: str
    action: str
    context: Dict[str, Any] = {}
    resource_id: Optional[str] = None
    idempotency_key: Optional[str] = None


def create_app(rt: DemoRuntime) -> FastAPI:
    app = FastAPI(
        title="MCC-Core Control Room",
        description=f"{DISCLAIMER_LABEL}. {DISCLAIMER_TEXT}",
    )
    # Local-only demo; the browser and this backend are the same machine.
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"], allow_headers=["*"],
    )

    @app.get("/api/health")
    def health() -> Dict[str, Any]:
        client = client_for(rt)
        try:
            gw_health = client.health()
            gw_ready = client.is_ready()
        except MCCGatewayError as exc:
            raise HTTPException(status_code=502, detail=f"real gateway unreachable: {exc}") from exc
        return {
            "status": "ok",
            "disclaimer_label": DISCLAIMER_LABEL,
            "disclaimer": DISCLAIMER_TEXT,
            "gateway_url": rt.gateway_url,
            "gateway": gw_health,
            "gateway_ready": gw_ready,
        }

    @app.get("/api/scenarios")
    def list_scenarios() -> Dict[str, Any]:
        return {"scenarios": SCENARIO_METADATA}

    @app.post("/api/scenarios/{scenario_id}/run")
    def run_scenario(scenario_id: str) -> Dict[str, Any]:
        fn = SCENARIOS.get(scenario_id)
        if fn is None:
            raise HTTPException(status_code=404, detail=f"unknown scenario: {scenario_id}")
        try:
            result = fn(rt)
        except MCCGatewayError as exc:
            raise HTTPException(status_code=502, detail=f"real gateway unreachable: {exc}") from exc
        return result.to_dict()

    @app.post("/api/propose")
    def propose(req: ProposeRequest) -> Dict[str, Any]:
        # F1: a registered demo agent is evaluated with ITS OWN credential.
        client = client_for(rt, req.identity)
        try:
            result = client.propose(identity=req.identity, action=req.action,
                                    context=req.context, resource_id=req.resource_id)
        except MCCGatewayError as exc:
            raise HTTPException(status_code=502, detail=f"real gateway unreachable: {exc}") from exc
        entries = audit_entries_by_trace(client, result.raw.get("trace_id", ""))
        return {
            "proposed_action": {"identity": req.identity, "action": req.action, "context": req.context},
            "decision": {
                "decision": result.decision.value, "reason": result.reason,
                "constraints": result.constraints, "forward_context": result.forward_context,
                "applied_constraints": result.applied_constraints,
                "authority_required": result.authority_required, "policy_ref": result.policy_ref,
            },
            "token": token_view(result.decision_token),
            "audit": {"matched_entries": entries},
        }

    @app.post("/api/execute")
    def execute(req: ExecuteRequest) -> Dict[str, Any]:
        idem = req.idempotency_key or f"control-room-custom-{int(time.time() * 1000)}"
        try:
            gate_stage, actuation_stage = run_execution(
                rt, actor=req.actor, action=req.action, context=req.context,
                idem=idem, resource=req.resource_id)
        except MCCGatewayError as exc:
            raise HTTPException(status_code=502, detail=f"real gateway unreachable: {exc}") from exc
        return {"gate_and_actuation": gate_stage.to_dict(), "actuation_result": actuation_stage.to_dict()}

    @app.get("/api/audit/verify")
    def audit_verify() -> Dict[str, Any]:
        client = client_for(rt)
        try:
            return client.verify_chain()
        except MCCGatewayError as exc:
            raise HTTPException(status_code=502, detail=f"real gateway unreachable: {exc}") from exc

    if FRONTEND_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")

    return app
