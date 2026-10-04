#!/usr/bin/env python3
"""Operator sidecar for gateway/governance_api.py-backed pilot demos.

Shared by TWO compose demos that use the identical gateway approval HTTP
shape (``/approvals/{id}/approve``): ``docker-compose.notify-pilot.yml``
(``pilot-operator``, paired with ``notify_pilot_agent.py``) and
``docker-compose.reference-agent.yml`` (``reference-agent-operator``, paired
with ``reference_agent_runner.py``'s ESCALATE scenario). Runs inside its OWN
container, SEPARATE from the agent. Holds ONLY
``MCC_GATEWAY_OPERATOR_API_KEY`` -- not ``MCC_GATEWAY_API_KEY``.

Credential separation (AUTHORITY_CREDENTIALS ∩ EXECUTION_CREDENTIALS = ∅):
this process GRANTS an approval mandate; it never calls
``/approvals/{id}/execute``. Actuation is performed by the agent that
proposed the operation, under its own api key, with the exact payload it
already has -- the authority plane never needs the ability to actuate
anything itself. (An earlier version of this script also called ``execute``
using the agent's own api key, which it additionally held -- collapsing
proposer-execution and authority into one credential holder. That is the
combined-privilege shape this split removes.)

Approving does NOT by itself grant permission: ``/approvals/{id}/approve``
is, server-side, gated by an independently configured ``AuthorityPolicy``
(see ``gateway/governance_api.py``'s ``build_governance_service`` and
``MCC_AUTHORITY_POLICY_CONFIG``) that this process cannot read, write, or
influence -- it only calls the endpoint and reports whatever the server
decides. An approve() call for an operation the policy does not allow
returns a non-200/absent-mandate response; this operator reports that
faithfully (no mandate) rather than fabricating one.

Coordination is via a shared, non-secret state file the agent writes BEFORE
any operator action -- the pending escalation's ``request_id`` only. (Any
OTHER field in that file -- actor/resource/context/correlationId -- is
agent-controlled and is NOT trusted for the approval decision; this operator
reads none of them. The request_id is a pointer, not evidence: the record
``/approve`` acts on is the server's own authoritative stored record, keyed
by request_id, never anything this file claims about it.)
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
OP_KEY = os.environ.get("MCC_GATEWAY_OPERATOR_API_KEY", "")
STATE_DIR = Path(os.environ.get("MCC_PILOT_STATE_DIR", "/pilot-state"))
STATE_PATH = STATE_DIR / "escalation.json"
RESULT_PATH = STATE_DIR / "escalation_result.json"
POLL_INTERVAL_S = float(os.environ.get("MCC_OPERATOR_POLL_INTERVAL_S", "1.0"))


def _process_one(client: httpx.Client, state: Dict[str, Any]) -> Dict[str, Any]:
    # The ONLY field trusted from the agent-written state file: a pointer to
    # the server's own authoritative pending-approval record.
    request_id = state["requestId"]
    op_h = {"x-operator-key": OP_KEY}

    r = client.post(f"{GATEWAY}/approvals/{request_id}/approve", json={}, headers=op_h)
    if r.status_code != 200:
        print(f"[operator] approve({request_id}) -> HTTP {r.status_code}: {r.text[:200]} "
              "(not approvable, or the independent authority policy did not allow this "
              "exact operation)")
        return {"approval_state": None, "mandate": None}
    granted = r.json()
    print(f"[operator] escalation {request_id}: approval={granted.get('state')} "
          "(grant only -- this process never executes)")
    return {"approval_state": granted.get("state"), "mandate": granted.get("mandate")}


def main() -> int:
    if not OP_KEY:
        print("FAILED: no operator key configured (MCC_GATEWAY_OPERATOR_API_KEY); "
              "operator actions are disabled (fail-closed).")
        return 1

    print("=" * 64)
    print("MCC-Core governed pilot: operator sidecar (approve-only)")
    print(f"  watching {STATE_PATH} for pending escalations")
    print("  holds the operator key only -- no MCC_GATEWAY_API_KEY, no execute route")
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
