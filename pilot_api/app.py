"""The external pilot API (CRM + outbound actions) — a real network service.

It receives real HTTP requests from the governed HTTPS executor, maintains
deterministic in-memory state, records every executed operation, exposes the
recorded operations for inspection, and rejects malformed requests (strict
schemas). It contains **no** governance logic: governance happens entirely in
MCC-Core, upstream of this service. This service only proves whether an
authorized action actually reached an external system.

Endpoints:
    POST /leads                    create a CRM lead
    POST /campaigns/{id}/budget    set a campaign budget
    POST /notifications            send a customer notification
    POST /tasks                    create a customer task
    POST /webhooks                 trigger a webhook
    GET  /operations               list every recorded operation (evidence)
    GET  /health                   liveness
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------
# Deterministic in-memory state (process-local; reset between test runs).
# --------------------------------------------------------------------------

class _State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.operations: List[Dict[str, Any]] = []
        self.seq = 0

    def record(self, kind: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self.lock:
            self.seq += 1
            digest = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            op = {"op_id": self.seq, "kind": kind, "payload": payload,
                  "payload_sha256": digest}
            self.operations.append(op)
            return op


_STATE = _State()


def reset_state() -> None:
    """Reset recorded operations (test determinism)."""
    global _STATE
    _STATE = _State()


def recorded_operations() -> List[Dict[str, Any]]:
    """The operations the service has actually performed (in-process inspection)."""
    return list(_STATE.operations)


# --------------------------------------------------------------------------
# Strict request schemas — malformed requests are rejected (422).
# --------------------------------------------------------------------------

class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LeadIn(_Strict):
    name: str = Field(min_length=1)
    email: Optional[str] = None
    campaign_budget_eur: float = Field(ge=0)


class BudgetIn(_Strict):
    amount: float = Field(ge=0)
    currency: str = Field(min_length=3, max_length=3)


class NotificationIn(_Strict):
    customer_id: str = Field(min_length=1)
    message: str = Field(min_length=1)


class TaskIn(_Strict):
    title: str = Field(min_length=1)
    assignee: Optional[str] = None


class WebhookIn(_Strict):
    event: str = Field(min_length=1)
    target: str = Field(min_length=1)


def build_pilot_api() -> FastAPI:
    """Build the external pilot API app (fresh app; shared process state)."""
    app = FastAPI(title="MCC-Core Pilot External API")

    @app.get("/health")
    def health() -> Dict[str, Any]:
        return {"status": "ok", "service": "pilot-api", "operations": len(_STATE.operations)}

    @app.get("/operations")
    def operations() -> Dict[str, Any]:
        # Full evidence surface: every operation the service actually performed.
        return {"count": len(_STATE.operations), "operations": list(_STATE.operations)}

    @app.post("/leads")
    def create_lead(body: LeadIn) -> Dict[str, Any]:
        op = _STATE.record("create_lead", body.model_dump())
        return {"created": True, "op_id": op["op_id"], "lead": body.model_dump()}

    @app.post("/campaigns/{campaign_id}/budget")
    def set_budget(campaign_id: str, body: BudgetIn) -> Dict[str, Any]:
        payload = {"campaign_id": campaign_id, **body.model_dump()}
        op = _STATE.record("set_campaign_budget", payload)
        return {"updated": True, "op_id": op["op_id"], "budget": payload}

    @app.post("/notifications")
    def notify(body: NotificationIn) -> Dict[str, Any]:
        op = _STATE.record("send_notification", body.model_dump())
        return {"sent": True, "op_id": op["op_id"]}

    @app.post("/tasks")
    def create_task(body: TaskIn) -> Dict[str, Any]:
        op = _STATE.record("create_task", body.model_dump())
        return {"created": True, "op_id": op["op_id"]}

    @app.post("/webhooks")
    def trigger_webhook(body: WebhookIn) -> Dict[str, Any]:
        op = _STATE.record("trigger_webhook", body.model_dump())
        return {"triggered": True, "op_id": op["op_id"]}

    return app


# Module-level app for `uvicorn pilot_api.app:app` (Docker service entrypoint).
app = build_pilot_api()


if __name__ == "__main__":
    import uvicorn

    # Blocking main-thread server (clean SIGTERM/SIGINT shutdown) for the
    # Docker pilot-api service.
    uvicorn.run(app, host="0.0.0.0", port=9100, log_level="info")
