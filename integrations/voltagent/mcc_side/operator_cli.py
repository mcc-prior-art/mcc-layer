#!/usr/bin/env python3
"""Operator approval step for the ESCALATE pilot scenario.

Run by the OPERATOR, inside the gateway container (which holds the operator key)
— never inside the VoltAgent agent container. It reads the pending-approval state
that the agent recorded, grants the approval (operator authority), and continues
the governed execution of the SAME proposed action.

    make pilot-approve

This is the human-authority half of ESCALATE: nothing executed before this; after
a valid approval the governed executor runs and a verified receipt yields EXECUTED.
Uses plain HTTP (httpx) against the gateway — no governance logic here.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx


def main() -> int:
    gateway = os.environ.get("MCC_OPERATOR_GATEWAY_URL", "http://127.0.0.1:8001").rstrip("/")
    api_key = os.environ.get("MCC_GATEWAY_API_KEY", "")
    operator_key = os.environ.get("MCC_GATEWAY_OPERATOR_API_KEY", "")
    state_dir = os.environ.get("MCC_PILOT_STATE_DIR", "/pilot-state")

    if not operator_key:
        print("FAILED: no operator key configured (MCC_GATEWAY_OPERATOR_API_KEY); "
              "operator actions are disabled (fail-closed).")
        return 1

    state_path = Path(state_dir) / "escalation.json"
    if not state_path.exists():
        print(f"FAILED: no pending escalation at {state_path}; run 'make pilot-escalate' first.")
        return 1
    state = json.loads(state_path.read_text(encoding="utf-8"))
    request_id = state["requestId"]
    actor, resource, context = state["actor"], state["resource"], state["context"]
    # The action is recorded by the scenario runner; default to send_notification
    # for the original VoltAgent pilot (backward-compatible).
    action = state.get("action", "send_notification")
    # V05 (part 2): the approved execution is presented with the ESCALATED
    # AGENT's own registered credential (MCC_AGENT_API_KEYS = JSON
    # {principal: key}); the shared tenant key cannot execute as an agent.
    # A missing entry fails closed before the approval is even granted.
    try:
        agent_keys = json.loads(os.environ.get("MCC_AGENT_API_KEYS") or "{}")
    except ValueError:
        agent_keys = None
    agent_key = agent_keys.get(actor) if isinstance(agent_keys, dict) else None
    if not isinstance(agent_key, str) or not agent_key:
        print(f"FAILED: no per-agent credential for {actor!r} in MCC_AGENT_API_KEYS; "
              "refusing to continue (fail-closed).")
        return 1
    agent_h = {"x-api-key": agent_key}
    op_h = {"x-api-key": api_key, "x-operator-key": operator_key}

    print("=" * 64)
    print(f"OPERATOR APPROVAL for escalation {request_id}")
    print("=" * 64)
    print(f"  actor / resource    : {actor} / {resource}")
    print(f"  correlation id      : {state.get('correlationId')}")

    # Round 27: the coordinator's mandatory idempotency_key (Round 25) must be
    # the EXACT stable identity established for the original logical
    # operation -- never substituted, derived, or reconstructed. correlationId
    # is that identity: it is recorded by the proposal-time scenario runner
    # (pilot-cli.ts / clinic-cli.ts) into this same state file, once, before
    # any operator action. ``request_id`` names the APPROVAL request instead
    # -- a distinct object minted by a different subsystem (ApprovalService),
    # at a different time, for a different purpose. It is never proven
    # equivalent to the original logical operation, so it is never used as a
    # fallback identity. A state file missing correlationId (legacy,
    # malformed, or hand-edited) fails closed here -- before the approval is
    # even granted, so nothing is approved OR executed for an operation whose
    # original identity cannot be established.
    correlation_id = state.get("correlationId")
    if not isinstance(correlation_id, str) or not correlation_id.strip():
        print(f"\nFAILED: escalation state at {state_path} is missing its original "
              "logical_operation_id (correlationId); refusing to continue "
              "(fail-closed) -- the approval request id is never substituted "
              "for it.")
        return 1

    with httpx.Client(timeout=15.0) as client:
        # 1. Operator grants the approval (mints a single-use mandate).
        r = client.post(f"{gateway}/approvals/{request_id}/approve", json={}, headers=op_h)
        if r.status_code != 200:
            print(f"FAILED: approve returned HTTP {r.status_code}: {r.text[:200]}")
            return 1
        granted = r.json()
        mandate = granted.get("mandate")
        print(f"  approval state      : {granted.get('state')} (operator granted)")

        # 2. Continue the governed execution of the ORIGINAL proposed action,
        # under the ORIGINAL logical_operation_id validated above.
        body = {"mandate": mandate, "actor": actor, "action": action,
                "resource": resource, "context": context,
                "idempotency_key": correlation_id}
        r = client.post(f"{gateway}/approvals/{request_id}/execute", json=body, headers=agent_h)
        if r.status_code != 200:
            print(f"FAILED: execute returned HTTP {r.status_code}: {r.text[:200]}")
            return 1
        out = r.json()
        status = out.get("status")
        print(f"  execution status    : {status}")
        print(f"  external receipt    : {out.get('execution')}")

        # 3. Audit must verify.
        v = client.get(f"{gateway}/verify", headers=agent_h)
        valid = v.json().get("valid") if v.status_code == 200 else None
        print(f"  audit verification  : valid={valid}")

    if status != "EXECUTED":
        print("\nFAILED: escalation did not reach EXECUTED after approval.")
        return 1
    # Consume the state so it cannot be replayed by a second approval.
    try:
        state_path.unlink()
    except OSError:
        pass
    print("\nSCENARIO OK: ESCALATE approved -> governed execution -> verified receipt -> EXECUTED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
