#!/usr/bin/env python3
"""Operator sidecar for gateway/governance_api.py-backed pilot demos.

Shared by TWO compose demos that use the identical gateway approval HTTP
shape (``/approvals/{id}/approve`` then ``/approvals/{id}/execute``):
``docker-compose.notify-pilot.yml`` (``pilot-operator``, paired with
``notify_pilot_agent.py``) and ``docker-compose.reference-agent.yml``
(``reference-agent-operator``, paired with ``reference_agent_runner.py``'s
ESCALATE scenario). Runs inside its OWN container, SEPARATE from the agent.
Holds ``MCC_GATEWAY_OPERATOR_API_KEY`` (plus the shared, non-privileged
``MCC_GATEWAY_API_KEY`` every governed participant needs just to call the
gateway at all); the agent container holds neither form of the operator key.

Coordination is via a shared, non-secret state file the agent writes BEFORE
any operator action -- the pending escalation's ``request_id``, actor,
resource, action, context (the proposed payload), and the ORIGINAL
``correlation_id`` (never a credential, never derived or substituted after
the fact). This mirrors the established pattern in
integrations/voltagent/mcc_side/operator_cli.py, adapted to run as an
unattended sidecar (this compose file has no second terminal / `make
pilot-approve` step): rather than a human running it once via `docker compose
exec`, it polls for the agent's recorded escalation and processes it as soon
as it appears.

Round 27 invariant preserved exactly as in operator_cli.py: the execute call
uses ``idempotency_key=correlation_id`` -- the ORIGINAL logical-operation
identity the agent minted before any operator action -- never the
approval's own ``request_id`` (a distinct object, from a distinct subsystem,
minted at a distinct time, never proven equivalent to the original
operation). A state file missing ``correlationId`` fails closed here, before
anything is approved or executed.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict

import httpx

GATEWAY = os.environ.get("MCC_GATEWAY_URL", "http://mcc-gateway:8001")
API_KEY = os.environ.get("MCC_GATEWAY_API_KEY", "")
OP_KEY = os.environ.get("MCC_GATEWAY_OPERATOR_API_KEY", "")
STATE_DIR = Path(os.environ.get("MCC_PILOT_STATE_DIR", "/pilot-state"))
STATE_PATH = STATE_DIR / "escalation.json"
RESULT_PATH = STATE_DIR / "escalation_result.json"
POLL_INTERVAL_S = float(os.environ.get("MCC_OPERATOR_POLL_INTERVAL_S", "1.0"))


def _process_one(client: httpx.Client, state: Dict[str, Any]) -> Dict[str, Any]:
    request_id = state["requestId"]
    actor, resource, context = state["actor"], state["resource"], state["context"]
    action = state.get("action", "send_notification")
    agent_h = {"x-api-key": API_KEY}
    op_h = {"x-api-key": API_KEY, "x-operator-key": OP_KEY}

    # See module docstring: the request_id is never substituted for the
    # original logical-operation identity.
    correlation_id = state.get("correlationId")
    if not isinstance(correlation_id, str) or not correlation_id.strip():
        print(f"[operator] FAILED: escalation state for {request_id} is missing its "
              "original correlationId; refusing to continue (fail-closed).")
        return {"approval_state": None, "status": None, "execution": None, "executed": False}

    r = client.post(f"{GATEWAY}/approvals/{request_id}/approve", json={}, headers=op_h)
    if r.status_code != 200:
        print(f"[operator] FAILED: approve returned HTTP {r.status_code}: {r.text[:200]}")
        return {"approval_state": None, "status": None, "execution": None, "executed": False}
    granted = r.json()
    mandate = granted.get("mandate")

    body = {"mandate": mandate, "actor": actor, "action": action, "resource": resource,
            "context": context, "idempotency_key": correlation_id}
    r = client.post(f"{GATEWAY}/approvals/{request_id}/execute", json=body, headers=agent_h)
    if r.status_code != 200:
        print(f"[operator] FAILED: execute returned HTTP {r.status_code}: {r.text[:200]}")
        return {"approval_state": granted.get("state"), "status": None, "execution": None,
                "executed": False}
    out = r.json()
    status = out.get("status")
    print(f"[operator] escalation {request_id}: approval={granted.get('state')} "
          f"execution={status}")
    return {"approval_state": granted.get("state"), "status": status,
            "execution": out.get("execution"), "executed": status == "EXECUTED"}


def main() -> int:
    if not OP_KEY:
        print("FAILED: no operator key configured (MCC_GATEWAY_OPERATOR_API_KEY); "
              "operator actions are disabled (fail-closed).")
        return 1

    print("=" * 64)
    print("MCC-Core governed pilot: operator sidecar")
    print(f"  watching {STATE_PATH} for pending escalations")
    print("  holds the operator key only -- pilot-agent never holds it")
    print("=" * 64)

    with httpx.Client(timeout=15.0) as client:
        while True:
            if STATE_PATH.exists():
                try:
                    state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
                except (OSError, ValueError) as exc:
                    print(f"[operator] malformed state file, ignoring: {exc!r}")
                    time.sleep(POLL_INTERVAL_S)
                    continue

                result = _process_one(client, state)
                RESULT_PATH.write_text(json.dumps(result), encoding="utf-8")
                try:
                    STATE_PATH.unlink()
                except OSError:
                    pass

            time.sleep(POLL_INTERVAL_S)


if __name__ == "__main__":
    sys.exit(main())
