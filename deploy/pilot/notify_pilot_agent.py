#!/usr/bin/env python3
"""Real Governed Executor Pilot — agent runner (Docker Compose).

Uses the supported MCC Python SDK (``mcc_client``) to drive the canonical path
against the running gateway. It never calls the mock notification service
directly — only the governed executor (inside the gateway) does, and only after a
verified decision + authorization + audit-before-execution + a confirmed receipt.

Demonstrates the four verdicts (evaluate) and a genuine EXECUTED result via the
ESCALATE -> approve -> execute path (which reaches the mock service and requires a
confirmed matching receipt before EXECUTED).

Authority principal separation: this process holds ONLY
``MCC_GATEWAY_API_KEY``. It never holds, reads, or derives
``MCC_GATEWAY_OPERATOR_API_KEY`` -- the ``pilot-operator`` service
(``gateway_approval_operator.py``) is a separate process, in a separate
container, that holds it. For ESCALATE, this agent records a non-secret
pending-approval request (request_id + the original proposal, never a
credential) to a shared state file and polls for the operator's result; it
cannot grant its own approval even if its own code were compromised.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, "/app/sdk/python/src")
sys.path.insert(0, "/app/src")
sys.path.insert(0, "/app")

from mcc_client import (  # noqa: E402
    Approval, MCCClient, Verdict, MCCDeniedError, MCCError,
)

GATEWAY = os.environ.get("MCC_GATEWAY_URL", "http://mcc-gateway:8001")
API_KEY = os.environ.get("MCC_GATEWAY_API_KEY", "demo-key")
STATE_DIR = Path(os.environ.get("MCC_PILOT_STATE_DIR", "/pilot-state"))
APPROVAL_WAIT_TIMEOUT_S = float(os.environ.get("MCC_APPROVAL_WAIT_TIMEOUT_S", "60.0"))
APPROVAL_POLL_INTERVAL_S = float(os.environ.get("MCC_APPROVAL_POLL_INTERVAL_S", "1.0"))


def _wait_ready(client: MCCClient) -> None:
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if client._t.get("/ready").get("ready") in (True, False):  # reachable
                return
        except Exception:
            time.sleep(1.0)
    raise SystemExit("gateway did not become reachable")


def _corr(name: str) -> str:
    return f"corr-{name}-{int(time.time())}"


def main() -> int:
    client = MCCClient(GATEWAY, api_key=API_KEY, timeout=15.0)
    _wait_ready(client)
    failures = []

    scenarios = [
        ("ALLOW", "agent/notify-bot", {"recipient": "cust-1", "message": "Hi", "priority": 1, "channel": "email"}),
        ("DENY", "agent/notify-bot", {"recipient": "cust-1", "message": "Hi", "priority": 1, "channel": "pager"}),
        ("CONSTRAIN", "agent/notify-bot", {"recipient": "cust-1", "message": "Hi", "priority": 9, "channel": "email"}),
        ("ESCALATE", "agent/unknown", {"recipient": "cust-1", "message": "Hi", "priority": 1, "channel": "email"}),
    ]

    print("\n" + "=" * 60)
    print("MCC-Core Real Governed Executor Pilot")
    print("=" * 60)

    for expected, actor, payload in scenarios:
        payload = dict(payload, correlation_id=_corr(expected.lower()))
        d = client.evaluate(actor_id=actor, action="send_notification",
                            resource="crm", payload=payload,
                            idempotency_key=payload["correlation_id"])
        print(f"\n--- Scenario: {expected} ---")
        print(f"  proposed action    : send_notification  by {actor}")
        print(f"  proposed payload   : {payload}")
        print(f"  MCC verdict        : {d.verdict.value}")
        print(f"  authorization state: {'authorized-body-present' if d.executable else d.verdict.value}")
        if d.verdict.value != expected:
            failures.append(f"{expected}: got {d.verdict.value}")

        if d.verdict == Verdict.DENY:
            try:
                from mcc_client import MandateAuthorization
                client.execute(d, MandateAuthorization(mandate={"unused": True}))
                failures.append("DENY executed")
            except MCCDeniedError:
                print("  execution result   : BLOCKED (governed executor never called)")

        if d.verdict == Verdict.ESCALATE:
            approval = client.request_approval(d)
            print(f"  approval state     : requested ({approval.request_id}) — not executed")

            # This agent has no operator key and cannot grant its own
            # approval. It records the (non-secret) pending request for the
            # separate pilot-operator process, then polls for its result.
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            result_path = STATE_DIR / "escalation_result.json"
            try:
                result_path.unlink()
            except OSError:
                pass
            (STATE_DIR / "escalation.json").write_text(json.dumps({
                "requestId": approval.request_id,
                "actor": actor,
                "resource": "crm",
                "context": payload,
                "action": "send_notification",
                "correlationId": payload["correlation_id"],
            }), encoding="utf-8")

            result = None
            deadline = time.time() + APPROVAL_WAIT_TIMEOUT_S
            while time.time() < deadline:
                if result_path.exists():
                    try:
                        result = json.loads(result_path.read_text(encoding="utf-8"))
                    except (OSError, ValueError):
                        result = None
                    if result is not None:
                        break
                time.sleep(APPROVAL_POLL_INTERVAL_S)

            if result is None:
                failures.append("ESCALATE: operator never processed the pending approval (timeout)")
            elif not result.get("mandate"):
                # Not approved -- either still pending, or the independent
                # authority policy did not allow this exact operation. Either
                # way: zero actuation. Never treated as a bypass/retry path.
                print(f"  approval state     : {result.get('approval_state')} (no mandate granted)")
                failures.append("ESCALATE: approval not granted (operator denied/not approvable)")
            else:
                # The operator GRANTED a mandate; it never executes. This
                # agent -- the proposer that already holds the exact payload
                # -- resubmits it with its OWN api key via the supported
                # public SDK call, under the SAME approval_id. Execution is
                # still re-evaluated and bound to action/transaction/payload
                # server-side; a mismatched or replayed mandate fails closed
                # there regardless of what this agent sends.
                granted = Approval(request_id=approval.request_id,
                                   state=result.get("approval_state") or "APPROVED",
                                   mandate=result["mandate"])
                exec_result = client.execute_after_approval(d, granted)
                print(f"  approval state     : {result.get('approval_state')} (operator granted)")
                print(f"  final payload      : {payload}")
                print(f"  execution result   : {exec_result.status}")
                print(f"  external receipt   : {exec_result.execution}")
                if not exec_result.executed:
                    failures.append("ESCALATE approved but not executed")

    print("\n--- Audit chain ---")
    try:
        chain = client.verify_audit_chain()
        print(f"  audit verification : valid={chain.get('valid')}")
        if chain.get("valid") is not True:
            failures.append("audit chain did not verify")
    except MCCError as exc:
        failures.append(f"audit verify: {exc}")

    print("\n" + "=" * 60)
    if failures:
        print("PILOT FAILED:", "; ".join(failures))
        return 1
    print("PILOT PASSED: four verdicts + genuine EXECUTED (confirmed receipt) + audit verified.")
    print("The model proposes. MCC decides. The gate enforces. The audit chain records.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
