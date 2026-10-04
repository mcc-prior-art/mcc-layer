#!/usr/bin/env python3
"""Reference Governed Agent — Docker Compose runner.

Drives the framework-neutral reference agent (``examples.reference_governed_agent``)
against the running MCC gateway through the supported SDK. It never calls the mock
notification service directly — only the governed executor inside the gateway does,
and only after a verified decision + operator approval + audit-before-execution +
a confirmed receipt.

It proves, end-to-end in real containers:

* DENY     -> no execution, the external service is never called;
* ESCALATE -> operator approval enforced -> governed execution -> verified external
              receipt -> EXECUTED -> the audit chain verifies.

(ALLOW/CONSTRAIN genuine execution needs consensus authorization material, which a
remote agent does not hold; those flows are proven in the deterministic tests. The
agent here reports them BLOCKED for lack of authorization — never a bypass.)

Authority principal separation: this process holds ONLY
``MCC_GATEWAY_API_KEY``. It never holds, reads, or derives
``MCC_GATEWAY_OPERATOR_API_KEY`` -- the ``reference-agent-operator`` service
(``gateway_approval_operator.py``) is a separate process, in a separate
container, that holds it. The DENY scenario never involves an operator at
all, so it is driven through ``ReferenceGovernedAgent`` unchanged. The
ESCALATE scenario is driven here directly with the SDK (the same primitives
``ReferenceGovernedAgent._escalate`` uses internally -- see
examples/reference_governed_agent/agent.py) rather than through
``ReferenceGovernedAgent``'s built-in ``Operator`` hook: that hook is called
by, and performs its approve() call through, the SAME client object passed
to the agent -- there is no way for a caller to inject a SEPARATE,
differently-credentialed client for just the approval step without
widening that shared reference implementation's constructor (used by 20+
other tests and proofs elsewhere in this repository), which is out of
scope here. Driving ESCALATE directly keeps that shared reference
implementation, and everything built on it, completely unchanged, while
still proving the real security property for this deployment: this agent
process cannot grant its own approval, because it never holds the key to.

Prints the markers the E2E workflow asserts; a clean exit alone is NOT success.
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

from mcc_client import Approval, MCCClient, MCCError, Verdict  # noqa: E402

from examples.reference_governed_agent import (  # noqa: E402
    DeterministicProvider,
    ReferenceGovernedAgent,
)
from examples.reference_governed_agent.models import AgentRunResult  # noqa: E402

GATEWAY = os.environ.get("MCC_GATEWAY_URL", "http://mcc-gateway:8001")
API_KEY = os.environ.get("MCC_GATEWAY_API_KEY", "demo-key")
STATE_DIR = Path(os.environ.get("MCC_PILOT_STATE_DIR", "/pilot-state"))
APPROVAL_WAIT_TIMEOUT_S = float(os.environ.get("MCC_APPROVAL_WAIT_TIMEOUT_S", "60.0"))
APPROVAL_POLL_INTERVAL_S = float(os.environ.get("MCC_APPROVAL_POLL_INTERVAL_S", "1.0"))

REQUEST = "Notify customer-123 that the appointment is confirmed"


def _wait_ready(client: MCCClient) -> None:
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if client._t.get("/ready").get("ready") in (True, False):
                return
        except Exception:  # noqa: BLE001
            time.sleep(1.0)
    raise SystemExit("gateway did not become reachable")


def _print(result) -> None:
    print(f"  user request       : {result.request}")
    print(f"  proposal created   : {result.proposal.get('action')} "
          f"by {result.proposal.get('actor_id')}")
    print(f"  MCC verdict        : {result.verdict}")
    print(f"  verdict reason     : {result.reason}")
    if result.approval_status is not None:
        print(f"  operator approval  : {result.approval_status}")
    if result.final_payload is not None:
        print(f"  executed payload   : {result.final_payload}")
    print(f"  execution result   : {result.execution_status}")
    if result.receipt is not None:
        print(f"  external receipt   : {result.receipt}")
    if result.audit_valid is not None:
        print(f"  audit verification : valid={result.audit_valid}")
    if result.error:
        print(f"  detail             : {result.error}")


def _escalate_with_separated_operator(client: MCCClient, request: str) -> AgentRunResult:
    """Drive the ESCALATE path with the same SDK primitives
    ``ReferenceGovernedAgent._escalate`` uses internally, but WITHOUT ever
    constructing a client that holds the operator key: the approval is
    recorded to a shared, non-secret state file and granted by the
    separate reference-agent-operator process (see module docstring)."""
    provider = DeterministicProvider(actor_id="agent/unknown", priority="normal",
                                     channel="email")
    proposal = provider.propose(request)
    proposal_dict = proposal.to_dict()

    try:
        decision = client.evaluate(
            actor_id=proposal.actor_id, action=proposal.action,
            resource=proposal.resource, payload=proposal.payload,
            idempotency_key=proposal.idempotency_key)
    except MCCError as exc:
        return AgentRunResult(
            request=request, proposal=proposal_dict, verdict="ERROR",
            reason="governance evaluation failed", execution_status="BLOCKED",
            error=f"{type(exc).__name__}: {exc}")

    if decision.verdict != Verdict.ESCALATE:
        return AgentRunResult(
            request=request, proposal=proposal_dict, verdict=decision.verdict.value,
            reason=decision.reason, execution_status="BLOCKED",
            error="expected ESCALATE for this scenario")

    try:
        approval = client.request_approval(decision)
    except MCCError as exc:
        return AgentRunResult(
            request=request, proposal=proposal_dict, verdict="ESCALATE",
            reason="could not open approval request", approval_status="ERROR",
            execution_status="BLOCKED", error=f"{type(exc).__name__}: {exc}")

    # This agent has no operator key and cannot grant its own approval. It
    # records the (non-secret) pending request for the separate
    # reference-agent-operator process, then polls for its result.
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    result_path = STATE_DIR / "escalation_result.json"
    try:
        result_path.unlink()
    except OSError:
        pass
    (STATE_DIR / "escalation.json").write_text(json.dumps({
        "requestId": approval.request_id,
        "actor": decision.actor_id,
        "resource": decision.resource_id,
        "context": dict(decision.requested_payload),
        "action": decision.action,
        "correlationId": proposal.idempotency_key,
    }), encoding="utf-8")

    outcome = None
    deadline = time.time() + APPROVAL_WAIT_TIMEOUT_S
    while time.time() < deadline:
        if result_path.exists():
            try:
                outcome = json.loads(result_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                outcome = None
            if outcome is not None:
                break
        time.sleep(APPROVAL_POLL_INTERVAL_S)

    if outcome is None:
        return AgentRunResult(
            request=request, proposal=proposal_dict, verdict="ESCALATE",
            reason="operator never processed the pending approval (timeout)",
            approval_status="PENDING", execution_status="BLOCKED")

    if not outcome.get("mandate"):
        # The operator holds ONLY the ability to grant; it never executes.
        # No mandate means either still-pending or the independently
        # configured authority policy did not allow this exact operation --
        # either way, zero actuation from this agent.
        return AgentRunResult(
            request=request, proposal=proposal_dict, verdict="ESCALATE",
            reason="approval not granted (operator denied/not approvable)",
            approval_status=outcome.get("approval_state"), execution_status="BLOCKED")

    # The operator GRANTED a mandate; this agent -- the proposer that
    # already holds the exact payload -- resubmits it with its OWN api key
    # via the supported public SDK call, under the SAME approval_id.
    # Execution is still re-evaluated and bound to action/transaction/
    # payload server-side.
    granted = Approval(request_id=approval.request_id,
                       state=outcome.get("approval_state") or "APPROVED",
                       mandate=outcome["mandate"])
    exec_result = client.execute_after_approval(decision, granted)
    outcome = {
        "approval_state": outcome.get("approval_state"),
        "status": exec_result.status,
        "executed": exec_result.executed,
        "execution": exec_result.execution,
    }

    if not outcome.get("executed"):
        return AgentRunResult(
            request=request, proposal=proposal_dict, verdict="ESCALATE",
            reason="governed execution after approval did not complete",
            approval_status=outcome.get("approval_state"),
            execution_status=outcome.get("status") or "BLOCKED")

    audit_valid = None
    try:
        audit_valid = client.verify_audit_chain().get("valid")
    except MCCError:
        audit_valid = None

    execution = outcome.get("execution") or {}
    body = execution.get("body") if isinstance(execution, dict) else None
    receipt = body if isinstance(body, dict) else (execution if isinstance(execution, dict) else {})
    receipt_summary = {
        "receipt_verified": execution.get("receipt_verified") if isinstance(execution, dict) else None,
        "upstream_status": execution.get("upstream_status") if isinstance(execution, dict) else None,
        "received": receipt.get("received"),
        "correlation_id": receipt.get("correlation_id"),
        "payload_sha256": receipt.get("payload_sha256"),
    }

    return AgentRunResult(
        request=request, proposal=proposal_dict, verdict="ESCALATE",
        reason=decision.reason or "authorized",
        execution_status=outcome.get("status") or "EXECUTED",
        approval_status="APPROVED",
        final_payload=dict(decision.requested_payload),
        receipt=receipt_summary,
        audit_valid=audit_valid)


def main() -> int:
    client = MCCClient(GATEWAY, api_key=API_KEY, timeout=15.0)
    _wait_ready(client)
    failures: list[str] = []

    print("\n" + "=" * 66)
    print("MCC-Core Framework-Neutral Reference Governed Agent (Docker E2E)")
    print("=" * 66)

    # --- DENY: a disallowed channel is blocked; the service is never called. ---
    print("\n--- Scenario: DENY (disallowed channel) ---")
    deny_agent = ReferenceGovernedAgent(
        client, provider=DeterministicProvider(actor_id="agent/notify-bot",
                                               priority="normal", channel="pager"),
        authorizer=None)
    deny = deny_agent.handle(REQUEST)
    _print(deny)
    if deny.verdict != "DENY" or deny.executed:
        failures.append(f"DENY: verdict={deny.verdict} executed={deny.executed}")

    # --- ESCALATE: operator approval -> governed execution -> confirmed receipt. ---
    print("\n--- Scenario: ESCALATE (operator authorization) ---")
    esc = _escalate_with_separated_operator(client, REQUEST)
    _print(esc)
    if esc.verdict != "ESCALATE":
        failures.append(f"ESCALATE: got verdict {esc.verdict}")
    if esc.approval_status != "APPROVED":
        failures.append("ESCALATE: operator approval was not enforced/granted")
    if esc.execution_status != "EXECUTED":
        failures.append("ESCALATE: genuine EXECUTED result absent (no confirmed receipt)")
    if not (esc.receipt and esc.receipt.get("receipt_verified")):
        failures.append("ESCALATE: external receipt was not verified")
    if esc.audit_valid is not True:
        failures.append("ESCALATE: audit chain did not verify")

    print("\n" + "=" * 66)
    if failures:
        print("REFERENCE AGENT PILOT FAILED:", "; ".join(failures))
        return 1
    print("REFERENCE AGENT PILOT PASSED: DENY blocked + ESCALATE approved -> "
          "governed execution -> verified receipt -> EXECUTED + audit verified.")
    print("The model proposes. MCC-Core decides. The gate enforces. "
          "The audit chain records.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
