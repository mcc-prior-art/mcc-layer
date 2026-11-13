#!/usr/bin/env python3
"""Operator approval step for the ESCALATE pilot scenario (approve ONLY).

Run by the OPERATOR -- inside the gateway container, which holds the operator
key -- never inside an agent container. It reads the pending-approval state the
escalating agent recorded, grants the approval (operator authority), and hands
the granted single-use mandate back through the shared state directory
(``approval.json``).

V05 (part 2): the operator NEVER executes. It holds no agent credential and
never presents one. Execution is performed afterwards by the escalating agent
itself, from its own container, with its own provisioned credential
(``pilot-cli.ts execute-approved`` / ``clinic-cli.ts execute-approved``), so the
gateway's per-agent identity check (authenticated principal == actor == signed
subject) applies to the approved execution exactly as to any other.

    make pilot-approve          # approve (here) + the agent executes (agent container)
    python -m integrations.voltagent.mcc_side.operator_cli --watch
                                # long-running sidecar for the CI E2E harness

Uses plain HTTP (httpx) against the gateway -- no governance logic here. The
gateway's own independent authority policy (MCC_AUTHORITY_POLICY_CONFIG) still
decides whether an operator approval is permitted at all.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import httpx

ESCALATION_FILE = "escalation.json"
APPROVAL_FILE = "approval.json"


def _write_atomic(path: Path, doc: dict) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def approve_pending(client: httpx.Client, gateway: str, operator_key: str, state_dir: Path) -> int:
    """Approve the ONE pending escalation in ``state_dir``. 0 on a granted
    approval handed back to the agent; 1 on anything else (fail-closed)."""
    state_path = state_dir / ESCALATION_FILE
    if not state_path.exists():
        print(f"FAILED: no pending escalation at {state_path}; run 'make pilot-escalate' first.")
        return 1
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        request_id = state["requestId"]
    except (ValueError, KeyError, TypeError):
        print(f"FAILED: escalation state at {state_path} is malformed; refusing to continue (fail-closed).")
        return 1
    if not isinstance(request_id, str) or not request_id.strip():
        print("FAILED: escalation state has no usable requestId; refusing to continue (fail-closed).")
        return 1

    print("=" * 64)
    print(f"OPERATOR APPROVAL for escalation {request_id}")
    print("=" * 64)
    print(f"  actor / resource    : {state.get('actor')} / {state.get('resource')}")
    print(f"  correlation id      : {state.get('correlationId')}")

    # Round 27: the protected execution's mandatory idempotency_key (Round 25)
    # must be the EXACT stable identity established for the original logical
    # operation -- its correlationId, recorded by the proposal-time scenario
    # runner. ``requestId`` names the APPROVAL (a different subsystem, time and
    # purpose) and is never a fallback. A state file without a valid
    # correlationId fails closed HERE -- before the approval is even granted --
    # so nothing is approved OR executed for an operation whose original
    # identity cannot be established. (The agent re-checks the same rule
    # before it executes.)
    correlation_id = state.get("correlationId")
    if not isinstance(correlation_id, str) or not correlation_id.strip():
        print(f"\nFAILED: escalation state at {state_path} is missing its original "
              "logical_operation_id (correlationId); refusing to continue "
              "(fail-closed) -- the approval request id is never substituted "
              "for it.")
        return 1

    # The approve route needs ONLY the operator credential (no agent key).
    r = client.post(f"{gateway}/approvals/{request_id}/approve", json={},
                    headers={"x-operator-key": operator_key})
    if r.status_code != 200:
        print(f"FAILED: approve returned HTTP {r.status_code}: {r.text[:200]}")
        return 1
    granted = r.json()
    mandate = granted.get("mandate")
    print(f"  approval state      : {granted.get('state')} (operator granted)")
    if granted.get("state") != "APPROVED" or not isinstance(mandate, dict):
        print("\nFAILED: the gateway did not grant an approval mandate (fail-closed).")
        return 1

    # Hand the single-use mandate back to the escalating agent. The mandate is
    # bound (signed) to that agent, the exact operation and the tenant; it is
    # useless to any other principal, so the shared state directory carries no
    # credential.
    _write_atomic(state_dir / APPROVAL_FILE, {
        "requestId": request_id, "correlationId": correlation_id,
        "state": granted.get("state"), "mandate": mandate})
    print(f"  handed to agent     : {state.get('actor')} executes with its OWN credential")
    print("\nSCENARIO OK: operator approved; the escalated agent performs the governed execution.")
    return 0


def _settings():
    gateway = os.environ.get("MCC_OPERATOR_GATEWAY_URL", "http://127.0.0.1:8001").rstrip("/")
    operator_key = os.environ.get("MCC_GATEWAY_OPERATOR_API_KEY", "")
    state_dir = Path(os.environ.get("MCC_PILOT_STATE_DIR", "/pilot-state"))
    return gateway, operator_key, state_dir


def watch(poll_interval: float) -> int:
    """Long-running operator sidecar (CI E2E harness): approve each NEW
    pending escalation once. Never executes anything."""
    gateway, operator_key, state_dir = _settings()
    if not operator_key:
        print("FAILED: no operator key configured (MCC_GATEWAY_OPERATOR_API_KEY); "
              "operator actions are disabled (fail-closed).")
        return 1
    print(f"operator sidecar (approve-only) watching {state_dir / ESCALATION_FILE}", flush=True)
    handled = set()
    with httpx.Client(timeout=15.0) as client:
        while True:
            try:
                state = json.loads((state_dir / ESCALATION_FILE).read_text(encoding="utf-8"))
                rid = state.get("requestId")
            except (OSError, ValueError, AttributeError):
                rid = None
            if isinstance(rid, str) and rid and rid not in handled:
                handled.add(rid)
                approve_pending(client, gateway, operator_key, state_dir)
                sys.stdout.flush()
            time.sleep(poll_interval)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--watch", action="store_true", help="run as an approve-only sidecar")
    ap.add_argument("--poll-interval", type=float, default=1.0)
    args = ap.parse_args(argv if argv is not None else [])
    if args.watch:
        return watch(args.poll_interval)
    gateway, operator_key, state_dir = _settings()
    if not operator_key:
        print("FAILED: no operator key configured (MCC_GATEWAY_OPERATOR_API_KEY); "
              "operator actions are disabled (fail-closed).")
        return 1
    with httpx.Client(timeout=15.0) as client:
        return approve_pending(client, gateway, operator_key, state_dir)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
