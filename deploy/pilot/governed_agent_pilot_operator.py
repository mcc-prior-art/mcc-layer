"""Operator sidecar for the governed-agent compose pilot (mcc-operator service).

Runs inside its OWN container -- ``mcc-operator`` -- which holds the egress
proxy's operator key. It is a SEPARATE process and a SEPARATE credential
holder from ``mcc-agent`` (``governed_agent_compose_demo.py``): the agent
container does not have MCC_EGRESS_OPERATOR_API_KEY in its environment at
all, and this script does not have MCC_EGRESS_API_KEY.

Coordination is via a shared, non-secret state file written by the agent
BEFORE any operator action (the agent's own proposed-action identity --
``request_id`` -- never a credential). This mirrors the established pattern
in integrations/voltagent/mcc_side/operator_cli.py, adapted to run as an
unattended sidecar (this compose file has no second terminal / `make
pilot-approve` step) and to the egress-proxy's two-call approval shape:
``POST /v1/approvals/{id}/approve`` only GRANTS the approval here -- it does
not execute anything. The agent (not this process) resubmits the ORIGINAL
proposed action to ``/v1/http/execute`` with ``approval_id`` set, under its
own ``MCC_EGRESS_API_KEY`` -- so a granted approval is still only consumed
by the proposer that owns the original logical operation, never actuated by
the operator on the agent's behalf.

Security property this preserves: this process holding the operator key,
alone, grants no execution -- it can only flip one escalation from
PENDING_APPROVAL to approved. The agent, holding its own api key, still has
to separately resubmit the exact original payload/actor/resource for the
gate to execute it. Compromising this process lets an attacker approve
escalations; it does not let them execute an arbitrary action, because it
never holds the ability to call /v1/http/execute itself (no MCC_EGRESS_API_KEY).
Compromising the agent cannot approve anything, because it never holds the
operator key.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import httpx

GATEWAY = os.environ.get("MCC_GATEWAY_URL", "http://mcc-gateway:8090")
OP_KEY = os.environ.get("MCC_EGRESS_OPERATOR_API_KEY", "")
STATE_DIR = Path(os.environ.get("MCC_PILOT_STATE_DIR", "/pilot-state"))
STATE_PATH = STATE_DIR / "escalation.json"
POLL_INTERVAL_S = float(os.environ.get("MCC_OPERATOR_POLL_INTERVAL_S", "1.0"))


def _approve_once(client: httpx.Client, request_id: str) -> bool:
    op_h = {"x-operator-key": OP_KEY}
    r = client.post(f"{GATEWAY}/v1/approvals/{request_id}/approve", headers=op_h, timeout=10.0)
    print(f"[operator] approve({request_id}) -> HTTP {r.status_code}: {r.text[:200]}")
    return r.status_code == 200


def main() -> int:
    if not OP_KEY:
        print("FAILED: no operator key configured (MCC_EGRESS_OPERATOR_API_KEY); "
              "operator actions are disabled (fail-closed).")
        return 1

    print("=" * 64)
    print("MCC-Core governed-agent pilot: operator sidecar")
    print(f"  watching {STATE_PATH} for pending escalations")
    print("  holds the operator key only -- no MCC_EGRESS_API_KEY, no execute route")
    print("=" * 64)

    with httpx.Client() as client:
        # Unattended sidecar: poll indefinitely for the single demo escalation
        # (or any future one, if this compose file is reused for more than
        # one run) and process it as soon as the agent records it.
        while True:
            if STATE_PATH.exists():
                try:
                    state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
                    request_id = state["requestId"]
                except (OSError, ValueError, KeyError) as exc:
                    print(f"[operator] malformed state file, ignoring: {exc!r}")
                    time.sleep(POLL_INTERVAL_S)
                    continue

                _approve_once(client, request_id)
                # Consume the state file immediately: this operator's job for
                # this escalation is done (approve only, never execute), and
                # removing it prevents a stale file being mistaken for a new
                # request on a later run.
                try:
                    STATE_PATH.unlink()
                except OSError:
                    pass

            time.sleep(POLL_INTERVAL_S)


if __name__ == "__main__":
    sys.exit(main())
