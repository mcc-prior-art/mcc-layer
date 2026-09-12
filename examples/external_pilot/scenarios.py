"""Required pilot scenarios A-H (PR #113), exercised over the REAL public
HTTP boundary (``examples.external_pilot.client.mcc_pilot_client.
MCCPilotClient``) -- never a direct call into
``gateway.proposal_execution_service.ProposalExecutionService``.

Each scenario is a plain async function taking a ``make_client`` factory
(``api_key -> MCCPilotClient``, already pointed at a shared transport) and
returns a :class:`ScenarioResult`. This lets the SAME scenario logic run
both in-process (``tests/test_external_pilot_scenarios.py``, via
``httpx.ASGITransport``) and against a real TCP socket
(``run_external_pilot_self_check.py``, via ``examples._demo_server.
DemoServer`` + a real ``httpx.AsyncClient(base_url=...)``) with zero
duplication.

Tenant/credential layout used by every scenario in this module (built by
``build_scenario_stack`` below, reusing ``examples.external_pilot.server.
build_external_pilot_app`` -- itself reusing the EXISTING
``gateway.proposal_execution_stack.build_proposal_execution_stack``):

    api_key            tenant_id         execution authority for ACTION
    -----------------  ----------------  -------------------------------
    scenario-key-a      tenant-a          GRANTED
    scenario-key-b      tenant-b          GRANTED  (isolation counterpart)
    scenario-key-denied denied-tenant     NOT GRANTED (policy denial)
    (none / wrong key)  --                unauthenticated
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional

from fastapi import FastAPI

from mcc_core import AuthorityModel, InMemoryIdempotencyRegistry, InMemoryNonceRegistry
from mcc_proposal import InMemoryProposalRegistry

from gateway.proposal_api import mount_proposal_routes
from gateway.proposal_execution_api import mount_proposal_execution_routes
from gateway.proposal_execution_service import reconcile_proposal_operation
from gateway.proposal_execution_stack import build_proposal_execution_stack

from examples.external_pilot.actuator.demo_actuator import DemoLedgerActuator, build_demo_actuator
from examples.external_pilot.client.example_producer import build_proposal_from_agent_output
from examples.external_pilot.client.mcc_pilot_client import MCCPilotClient, ProposalSubmission
from examples.external_pilot.server import ACTION

TENANT_A_KEY = "scenario-key-a"
TENANT_B_KEY = "scenario-key-b"
DENIED_KEY = "scenario-key-denied"
WRONG_KEY = "scenario-key-does-not-exist"

TENANTS_CREDENTIALS = {TENANT_A_KEY: "tenant-a", TENANT_B_KEY: "tenant-b", DENIED_KEY: "denied-tenant"}
# denied-tenant deliberately has NO entry below -> zero authority grants,
# DENY by default (the SAME fail-closed default every other governed HTTP
# surface in this repository uses).
TENANTS_AUTHORITY = {"tenant-a": {}, "tenant-b": {}}


@dataclass(frozen=True)
class ScenarioStack:
    app: FastAPI
    ledger: DemoLedgerActuator
    resource: str
    proposals: Any
    idempotency: Any
    authority: AuthorityModel


def build_scenario_stack() -> ScenarioStack:
    """In-memory, fully isolated stack for the pilot scenarios -- reuses
    ``gateway.proposal_execution_stack.build_proposal_execution_stack``
    (the SAME builder ``examples.external_pilot.server.
    build_external_pilot_app`` uses) directly rather than through that
    module's opaque ``FastAPI`` return value, so scenario G can reach the
    SAME ``AuthorityModel`` instance the execute path uses for its
    operator-side reconciliation demonstration -- no second, independently
    constructed authority model. No new authority/Gate/coordinator/
    actuator-dispatch architecture; identical wiring to
    ``build_external_pilot_app``."""
    import tempfile
    from pathlib import Path

    from mcc_proposal import MCCProposalService

    upstream, ledger = build_demo_actuator()
    proposals = InMemoryProposalRegistry()
    idempotency = InMemoryIdempotencyRegistry()
    nonces = InMemoryNonceRegistry()
    audit_log_path = str(Path(tempfile.mkdtemp(prefix="mcc-external-pilot-scenarios-")) / "audit.jsonl")

    exec_stack = build_proposal_execution_stack(
        proposals=proposals, idempotency=idempotency, nonces=nonces,
        tenants=TENANTS_AUTHORITY, action=ACTION, upstream=upstream, audit_log_path=audit_log_path,
    )
    proposal_service = MCCProposalService(proposals=proposals, durable_execution_state=idempotency)
    app = FastAPI(title="MCC External Pilot Integration Pack (scenarios)")
    mount_proposal_routes(app, proposal_service, tenants=TENANTS_CREDENTIALS)
    mount_proposal_execution_routes(app, exec_stack.service, tenants=TENANTS_CREDENTIALS)

    return ScenarioStack(
        app=app, ledger=ledger, resource=upstream.resource, proposals=proposals,
        idempotency=idempotency, authority=exec_stack.authority,
    )


MakeClient = Callable[[str], MCCPilotClient]


@dataclass
class ScenarioResult:
    name: str
    passed: bool
    detail: Dict[str, Any] = field(default_factory=dict)
    failures: List[str] = field(default_factory=list)


def _new_op_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _status(response: Dict[str, Any]) -> Optional[str]:
    """``gateway.proposal_execution_api``'s router returns the governed
    outcome dict directly for a 2xx response, but FastAPI's own
    ``HTTPException(status_code=code, detail=body)`` wraps it under a
    ``"detail"`` key for any 4xx/5xx response (401/404/422/503) -- this
    normalizes both shapes to the SAME ``status`` field regardless of
    HTTP status code, based on the response's actual status_code, never
    by guessing from the body's shape."""
    body = response["body"]
    if not isinstance(body, dict):
        return None
    if response["status_code"] >= 400:
        body = body.get("detail", body)
    return body.get("status") if isinstance(body, dict) else None


async def scenario_a_happy_path(make_client: MakeClient, stack: ScenarioStack) -> ScenarioResult:
    """generic external producer -> proposal accepted -> trusted MCC
    authority evaluation -> signed authority -> execution admitted ->
    audit-before-actuation -> actuator invoked exactly once -> EXECUTED
    evidence returned."""
    failures: List[str] = []
    op_id = _new_op_id("happy")
    client = make_client(TENANT_A_KEY)
    proposal = build_proposal_from_agent_output(
        {"title": "example external-agent output", "note": "happy path"},
        logical_operation_id=op_id, actor="external-agent-example/v1", action=ACTION, resource=stack.resource,
    )
    r_submit = await client.submit_proposal(ProposalSubmission(**proposal))
    if r_submit["status_code"] != 200 or _status(r_submit) != "PROPOSED":
        failures.append(f"submit did not report PROPOSED: {r_submit}")
    entries_before = len(stack.ledger.entries)
    r_exec = await client.execute(op_id)
    if r_exec["status_code"] != 200 or _status(r_exec) != "EXECUTED":
        failures.append(f"execute did not report EXECUTED: {r_exec}")
    if len(stack.ledger.entries) != entries_before + 1:
        failures.append(f"expected exactly one new actuator dispatch, saw {len(stack.ledger.entries) - entries_before}")
    return ScenarioResult(
        "A_happy_path", not failures, detail={
            "logical_operation_id": op_id, "submit": r_submit, "execute": r_exec,
            "audit_ref": r_exec["body"].get("audit_ref"),
        }, failures=failures,
    )


async def scenario_b_policy_denial(make_client: MakeClient, stack: ScenarioStack) -> ScenarioResult:
    """A proposal that is not authorized must produce no actuator side
    effect."""
    failures: List[str] = []
    op_id = _new_op_id("denied")
    client = make_client(DENIED_KEY)
    proposal = build_proposal_from_agent_output(
        {"title": "should never execute"}, logical_operation_id=op_id,
        actor="external-agent-example/v1", action=ACTION, resource=stack.resource,
    )
    await client.submit_proposal(ProposalSubmission(**proposal))
    entries_before = len(stack.ledger.entries)
    r_exec = await client.execute(op_id)
    if _status(r_exec) != "DENIED":
        failures.append(f"expected DENIED, got {r_exec}")
    if len(stack.ledger.entries) != entries_before:
        failures.append("actuator was invoked despite policy denial")
    return ScenarioResult("B_policy_denial", not failures, detail={"execute": r_exec}, failures=failures)


async def scenario_c_replay(make_client: MakeClient, stack: ScenarioStack) -> ScenarioResult:
    """Repeated execution of the same tenant + logical operation must not
    cause a second side effect."""
    failures: List[str] = []
    op_id = _new_op_id("replay")
    client = make_client(TENANT_A_KEY)
    proposal = build_proposal_from_agent_output(
        {"title": "replay test"}, logical_operation_id=op_id,
        actor="external-agent-example/v1", action=ACTION, resource=stack.resource,
    )
    await client.submit_proposal(ProposalSubmission(**proposal))
    r1 = await client.execute(op_id)
    entries_after_first = len(stack.ledger.entries)
    r2 = await client.execute(op_id)
    if _status(r1) != "EXECUTED":
        failures.append(f"first execute did not report EXECUTED: {r1}")
    if _status(r2) == "EXECUTED":
        failures.append("replay wrongly reported EXECUTED a second time")
    if len(stack.ledger.entries) != entries_after_first:
        failures.append("replay caused a second actuator dispatch")
    return ScenarioResult(
        "C_replay", not failures, detail={"first": r1, "replay": r2, "dispatch_count": len(stack.ledger.entries)},
        failures=failures,
    )


async def scenario_d_tenant_isolation(make_client: MakeClient, stack: ScenarioStack) -> ScenarioResult:
    """One tenant must not execute/read another tenant's stored proposal
    or durable execution identity."""
    failures: List[str] = []
    op_id = _new_op_id("isolation")
    owner = make_client(TENANT_A_KEY)
    other = make_client(TENANT_B_KEY)
    proposal = build_proposal_from_agent_output(
        {"title": "owned by tenant-a"}, logical_operation_id=op_id,
        actor="external-agent-example/v1", action=ACTION, resource=stack.resource,
    )
    await owner.submit_proposal(ProposalSubmission(**proposal))

    r_cross_status = await other.get_status(op_id)
    r_cross_exec = await other.execute(op_id)
    if _status(r_cross_status) != "NOT_FOUND":
        failures.append(f"cross-tenant status read did not report NOT_FOUND: {r_cross_status}")
    if _status(r_cross_exec) != "NOT_FOUND":
        failures.append(f"cross-tenant execute did not report NOT_FOUND: {r_cross_exec}")

    r_owner_exec = await owner.execute(op_id)
    if _status(r_owner_exec) != "EXECUTED":
        failures.append(f"legitimate owner execute did not succeed: {r_owner_exec}")
    return ScenarioResult(
        "D_tenant_isolation", not failures,
        detail={"cross_tenant_status": r_cross_status, "cross_tenant_execute": r_cross_exec, "owner_execute": r_owner_exec},
        failures=failures,
    )


async def scenario_e_resource_binding(make_client: MakeClient, stack: ScenarioStack) -> ScenarioResult:
    """An actuator bound to resource A must not execute authority/
    proposal intended for resource B."""
    failures: List[str] = []
    op_id = _new_op_id("resource-mismatch")
    client = make_client(TENANT_A_KEY)
    wrong_resource = f"{stack.resource}-DIFFERENT"
    proposal = build_proposal_from_agent_output(
        {"title": "targets the wrong resource"}, logical_operation_id=op_id,
        actor="external-agent-example/v1", action=ACTION, resource=wrong_resource,
    )
    await client.submit_proposal(ProposalSubmission(**proposal))
    entries_before = len(stack.ledger.entries)
    r_exec = await client.execute(op_id)
    if _status(r_exec) != "RESOURCE_MISMATCH":
        failures.append(f"expected RESOURCE_MISMATCH, got {r_exec}")
    if len(stack.ledger.entries) != entries_before:
        failures.append("actuator was invoked despite a resource mismatch")
    return ScenarioResult("E_resource_binding", not failures, detail={"execute": r_exec}, failures=failures)


async def scenario_f_payload_action_binding(make_client: MakeClient, stack: ScenarioStack) -> ScenarioResult:
    """Execution cannot silently mutate the authority-bound action or
    payload before actuation -- the execute route takes no body at all
    (structural, not merely policy); a caller attempting to smuggle a
    different action/resource/payload/authority field into the execute
    request is silently ignored, and the actually-dispatched content
    matches only what was originally proposed."""
    failures: List[str] = []
    op_id = _new_op_id("binding")
    client = make_client(TENANT_A_KEY)
    original_payload = {"title": "original authorized content", "amount": 1}
    proposal = build_proposal_from_agent_output(
        original_payload, logical_operation_id=op_id,
        actor="external-agent-example/v1", action=ACTION, resource=stack.resource,
    )
    await client.submit_proposal(ProposalSubmission(**proposal))
    entries_before = len(stack.ledger.entries)

    # A well-behaved caller cannot even express this smuggling attempt
    # through MCCPilotClient.execute (it takes no body parameter at all)
    # -- ``adversarial_execute_with_body`` is a deliberate adversarial
    # probe (see its own docstring) proving the SERVER, not merely this
    # reference client, ignores it.
    smuggled_body = {
        "action": "some_other_action", "resource": "some_other_resource",
        "payload": {"title": "TAMPERED", "amount": 999999},
        "tenant_id": "some-other-tenant", "authority": "ALLOW", "decision": "ALLOW",
        "signed_authority": "forged", "actuator": "direct", "actuator_destination": "bypass",
    }
    r_exec = await client.adversarial_execute_with_body(op_id, smuggled_body)
    status = _status(r_exec)
    if status != "EXECUTED":
        failures.append(f"execute with a smuggled body did not report EXECUTED: {r_exec}")
    new_entries = stack.ledger.entries[entries_before:]
    dispatched = new_entries[-1] if new_entries else None
    if len(new_entries) != 1:
        failures.append(f"expected exactly one new dispatch, saw {len(new_entries)}")
    elif dispatched[2] != original_payload:
        failures.append(f"dispatched payload was mutated by the smuggled body: {dispatched}")
    elif dispatched[1] != ACTION:
        failures.append(f"dispatched action was mutated by the smuggled body: {dispatched}")
    return ScenarioResult(
        "F_payload_action_binding", not failures,
        detail={"execute_status": status, "dispatched": dispatched},
        failures=failures,
    )


async def scenario_g_unknown_reconciliation(make_client: MakeClient, stack: ScenarioStack) -> ScenarioResult:
    """An ambiguous execution outcome must not be blindly retried as a
    fresh operation; the same logical operation remains governed by the
    EXISTING durable identity/reconciliation semantics
    (``gateway.proposal_execution_service.reconcile_proposal_operation``,
    called here as the operator-side capability it is -- never exposed
    over HTTP, per PR #111/#112's deliberate no-reconciliation-route
    decision)."""
    failures: List[str] = []
    op_id = _new_op_id("unknown")
    client = make_client(TENANT_A_KEY)
    ambiguous_payload = {"title": "will fail ambiguously", "__simulate_ambiguous_failure__": True}
    proposal = build_proposal_from_agent_output(
        ambiguous_payload, logical_operation_id=op_id,
        actor="external-agent-example/v1", action=ACTION, resource=stack.resource,
    )
    await client.submit_proposal(ProposalSubmission(**proposal))
    entries_before = len(stack.ledger.entries)
    r1 = await client.execute(op_id)
    if _status(r1) != "EXECUTION_FAILED":
        failures.append(f"expected EXECUTION_FAILED (ambiguous), got {r1}")

    # No automatic retry: a second explicit call must not silently
    # re-dispatch or report EXECUTED.
    r2 = await client.execute(op_id)
    if _status(r2) == "EXECUTED":
        failures.append("ambiguous operation was silently retried to EXECUTED")
    if len(stack.ledger.entries) != entries_before:
        failures.append("actuator ledger recorded a dispatch despite the simulated ambiguous failure")

    # The existing reconciliation contract: an operator-side call with NO
    # independent evidence leaves the operation unresolved.
    async def _no_evidence(**_kwargs: Any) -> Optional[Dict[str, Any]]:
        return None

    reconcile_none = await reconcile_proposal_operation(
        proposals=stack.proposals, idempotency=stack.idempotency,
        authority=stack.authority, tenant_id="tenant-a", logical_operation_id=op_id,
        verify_external_evidence=_no_evidence,
    )
    if reconcile_none.outcome.value != "NO_EVIDENCE":
        failures.append(f"expected NO_EVIDENCE with no evidence supplied, got {reconcile_none.outcome.value}")

    # With independently-verified evidence that correctly binds to this
    # exact operation, the SAME existing reconciliation function resolves
    # it -- proving the contract works, without adding any HTTP surface.
    # The evidence payload must match the AUTHORIZED payload byte-for-byte
    # (here, the raw submitted payload, simulate-flag included -- that
    # flag is exactly what authority evaluated and what the durable
    # record's own binding was computed from); a real integration's
    # payload would obviously carry no such flag.
    async def _matching_evidence(*, tenant_id: str, logical_operation_id: str, action: str,
                                  resource: Optional[str], payload_hash: str) -> Dict[str, Any]:
        return {
            "tenant_id": tenant_id, "logical_operation_id": logical_operation_id,
            "action": action, "resource": resource, "payload": dict(ambiguous_payload),
        }

    reconcile_resolved = await reconcile_proposal_operation(
        proposals=stack.proposals, idempotency=stack.idempotency,
        authority=stack.authority, tenant_id="tenant-a", logical_operation_id=op_id,
        verify_external_evidence=_matching_evidence,
    )
    if reconcile_resolved.outcome.value != "RESOLVED":
        failures.append(f"expected RESOLVED with matching evidence, got {reconcile_resolved.outcome.value}: {reconcile_resolved.reason}")

    return ScenarioResult(
        "G_unknown_reconciliation", not failures,
        detail={
            "first_execute": r1["body"], "replay_execute": r2["body"],
            "reconcile_no_evidence": reconcile_none.outcome.value,
            "reconcile_with_evidence": reconcile_resolved.outcome.value,
        }, failures=failures,
    )


async def scenario_h_unauthenticated(make_client: MakeClient, stack: ScenarioStack) -> ScenarioResult:
    """Requests lacking required authentication/trusted tenant context
    must fail closed with zero actuator side effects."""
    failures: List[str] = []
    op_id = _new_op_id("unauth")
    wrong_client = make_client(WRONG_KEY)
    proposal = build_proposal_from_agent_output(
        {"title": "should never be accepted"}, logical_operation_id=op_id,
        actor="external-agent-example/v1", action=ACTION, resource=stack.resource,
    )
    entries_before = len(stack.ledger.entries)
    r_submit = await wrong_client.submit_proposal(ProposalSubmission(**proposal))
    r_exec = await wrong_client.execute(op_id)
    if r_submit["status_code"] != 401:
        failures.append(f"expected 401 on submit with an invalid API key, got {r_submit['status_code']}")
    if r_exec["status_code"] != 401:
        failures.append(f"expected 401 on execute with an invalid API key, got {r_exec['status_code']}")
    if len(stack.ledger.entries) != entries_before:
        failures.append("actuator was invoked for an unauthenticated caller")
    return ScenarioResult(
        "H_unauthenticated", not failures, detail={"submit_status": r_submit["status_code"], "execute_status": r_exec["status_code"]},
        failures=failures,
    )


ALL_SCENARIOS: List[Callable[[MakeClient, ScenarioStack], Awaitable[ScenarioResult]]] = [
    scenario_a_happy_path,
    scenario_b_policy_denial,
    scenario_c_replay,
    scenario_d_tenant_isolation,
    scenario_e_resource_binding,
    scenario_f_payload_action_binding,
    scenario_g_unknown_reconciliation,
    scenario_h_unauthenticated,
]


__all__ = [
    "ScenarioStack", "ScenarioResult", "build_scenario_stack",
    "TENANTS_CREDENTIALS", "TENANTS_AUTHORITY",
    "TENANT_A_KEY", "TENANT_B_KEY", "DENIED_KEY", "WRONG_KEY",
    "scenario_a_happy_path", "scenario_b_policy_denial", "scenario_c_replay",
    "scenario_d_tenant_isolation", "scenario_e_resource_binding",
    "scenario_f_payload_action_binding", "scenario_g_unknown_reconciliation",
    "scenario_h_unauthenticated", "ALL_SCENARIOS",
]
