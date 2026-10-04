"""The supported MCC-Core Python client.

Canonical integration path::

    External AI Agent
      -> MCCClient (this SDK)
      -> MCC Gateway            (POST /evaluate)
      -> Governance Decision    (ALLOW / DENY / ESCALATE / CONSTRAIN)
      -> Execution Gate         (governed /…/execute)
      -> Governed Executor
      -> External System

The model proposes. MCC decides. The gate enforces. The audit chain records.
Proposal is not permission.

The SDK is a *client*, not a policy engine: it creates no decisions locally,
signs nothing, bypasses neither the gateway nor the execution gate, calls no
external target directly, and never treats a network success as approval.
Execution is always an explicit, separate call and only ever goes to a governed
endpoint with the authoritative (server-decided) payload.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Union

from .exceptions import (
    MCCAmbiguousExecutionError,
    MCCApprovalRequiredError,
    MCCDeniedError,
    MCCExecutionError,
    MCCInvalidDecisionError,
    MCCProtocolError,
    MCCReplayError,
    MCCTransportError,
)
from .models import (
    Approval,
    ApprovalAuthorization,
    ConsensusAuthorization,
    Decision,
    ExecutionResult,
    MandateAuthorization,
    Payload,
    Verdict,
)
from .transport import Transport

Authorization = Union[ApprovalAuthorization, MandateAuthorization, ConsensusAuthorization]

_REPLAY_MARKERS = ("replay", "already consumed", "already used", "nonce", "consumed")


class MCCClient:
    """A synchronous client for a running MCC-Core gateway."""

    def __init__(
        self,
        base_url: str,
        *,
        api_key: Optional[str] = None,
        operator_key: Optional[str] = None,
        timeout: float = 10.0,
        max_safe_retries: int = 2,
        transport: Optional[Transport] = None,
    ) -> None:
        self._t = transport or Transport(
            base_url, api_key=api_key, operator_key=operator_key,
            timeout=timeout, max_safe_retries=max_safe_retries)

    def close(self) -> None:
        self._t.close()

    def __enter__(self) -> "MCCClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------ #
    # 1. Evaluate — propose an action, get a verdict (no execution).      #
    # ------------------------------------------------------------------ #

    def evaluate(
        self,
        *,
        actor_id: str,
        action: str,
        resource: Optional[str] = None,
        payload: Optional[Payload] = None,
        idempotency_key: Optional[str] = None,
        transaction_id: Optional[str] = None,
        identity: Optional[str] = None,
        mode: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> Decision:
        """Submit a proposed action to the gateway and return the typed decision.

        This is side-effect-free: it never executes. A timeout/transport failure
        is safe to retry here (done automatically for the configured budget)."""
        if not actor_id or not action:
            raise MCCInvalidDecisionError("actor_id and action are required to evaluate")
        body: Dict[str, Any] = {
            "identity": identity or actor_id,
            "action": action,
            "context": dict(payload or {}),
            "actor_id": actor_id,
        }
        if resource is not None:
            body["resource_id"] = resource
        if idempotency_key is not None:
            body["idempotency_key"] = idempotency_key
        if transaction_id is not None:
            body["transaction_id"] = transaction_id
        if mode is not None:
            body["mode"] = mode

        data = self._t.post("/evaluate", body, correlation_id=correlation_id, retry_safe=True)
        decision = Decision.from_response(
            data, requested_actor=actor_id, requested_action=action, requested_resource=resource,
            requested_payload=dict(payload or {}))
        # Preserve the correlation id used for the round trip if the server did
        # not echo a trace id.
        if not decision.correlation_id:
            object.__setattr__(decision, "correlation_id", data.get("_correlation_id", ""))
        return decision

    # ------------------------------------------------------------------ #
    # 2. ESCALATE — approvals.                                            #
    # ------------------------------------------------------------------ #

    def request_approval(self, decision: Decision, *, ttl_seconds: Optional[int] = None,
                         correlation_id: Optional[str] = None) -> Approval:
        """Open an approval request bound to an ESCALATE decision's operation."""
        if decision.verdict != Verdict.ESCALATE:
            raise MCCInvalidDecisionError(
                f"request_approval is only valid for ESCALATE (got {decision.verdict.value})")
        body: Dict[str, Any] = {
            "actor": decision.actor_id, "action": decision.action,
            # The exact proposed operation payload, stored verbatim server-side
            # so an independently configured authority policy (never supplied
            # by this caller) can evaluate it at approve()-time. Without this,
            # every escalation record would carry an empty payload and any
            # policy bound on a payload field would always fail closed.
            "payload": dict(decision.requested_payload or {}),
        }
        if decision.resource_id is not None:
            body["resource"] = decision.resource_id
        if decision.transaction_id is not None:
            body["transaction_id"] = decision.transaction_id
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        data = self._t.post("/approvals", body, correlation_id=correlation_id)
        return Approval(request_id=str(data.get("request_id", "")),
                        state=str(data.get("state", "")), mandate=data.get("mandate"))

    def approve(self, approval: Union[Approval, str], *,
                correlation_id: Optional[str] = None) -> Approval:
        """Operator action: grant a pending approval (mints a single-use mandate).

        Requires the operator key. This is a distinct, human-authority action —
        the SDK never approves automatically."""
        request_id = approval.request_id if isinstance(approval, Approval) else approval
        data = self._t.post(f"/approvals/{request_id}/approve", {}, operator=True,
                            correlation_id=correlation_id)
        return Approval(request_id=str(data.get("request_id", request_id)),
                        state=str(data.get("state", "")), mandate=data.get("mandate"))

    def deny_approval(self, approval: Union[Approval, str], *,
                      correlation_id: Optional[str] = None) -> Approval:
        request_id = approval.request_id if isinstance(approval, Approval) else approval
        data = self._t.post(f"/approvals/{request_id}/deny", {}, operator=True,
                            correlation_id=correlation_id)
        return Approval(request_id=str(data.get("request_id", request_id)),
                        state=str(data.get("state", "")), mandate=data.get("mandate"))

    # ------------------------------------------------------------------ #
    # 3. Consensus material.                                              #
    # ------------------------------------------------------------------ #

    def issue_challenge(self, decision: Decision, *,
                        ttl_seconds: Optional[int] = None,
                        correlation_id: Optional[str] = None) -> Dict[str, Any]:
        """Request a gateway-issued, one-time challenge for a decision's operation
        (the agent never mints the nonce itself)."""
        body: Dict[str, Any] = {"actor": decision.actor_id, "action": decision.action,
                                "context": dict(decision.authorized_payload)}
        if decision.resource_id is not None:
            body["resource"] = decision.resource_id
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        return self._t.post("/consensus/challenge", body, correlation_id=correlation_id)

    # ------------------------------------------------------------------ #
    # 4. Execute — explicit, governed, authoritative-payload only.        #
    # ------------------------------------------------------------------ #

    def execute(self, decision: Decision, authorization: Authorization, *,
                correlation_id: Optional[str] = None) -> ExecutionResult:
        """Explicitly execute an authorized decision through the governed path.

        Never executes DENY or an unapproved ESCALATE. Sends ONLY the decision's
        authoritative payload (the server-clamped body for CONSTRAIN) — the caller
        cannot substitute or mutate actor/action/resource/payload-bound fields.
        A transport failure during execution is surfaced as an ambiguous-execution
        error and is never retried."""
        self._guard_executable(decision, authorization)

        # The authoritative body the verdict authorizes (clamped for CONSTRAIN).
        # For an approved ESCALATE the verdict carried no authorized body, so the
        # originally-proposed payload is submitted and the gateway RE-EVALUATES it
        # under the granted mandate (clamping server-side if needed) — the caller
        # still cannot substitute an arbitrary body: it is exactly what was proposed.
        context = dict(decision.authorized_payload or decision.requested_payload)
        base: Dict[str, Any] = {
            "actor": decision.actor_id,
            "action": decision.action,
            "context": context,
        }
        if decision.resource_id is not None:
            base["resource"] = decision.resource_id
        if decision.transaction_id is not None:
            base["transaction_id"] = decision.transaction_id
        if decision.idempotency_key is not None:
            base["idempotency_key"] = decision.idempotency_key

        if isinstance(authorization, ApprovalAuthorization):
            path = f"/approvals/{authorization.request_id}/execute"
            base["mandate"] = authorization.mandate
        elif isinstance(authorization, MandateAuthorization):
            path = "/mandates/execute"
            base["mandate"] = authorization.mandate
        elif isinstance(authorization, ConsensusAuthorization):
            path = "/consensus/execute"
            base["votes"] = authorization.votes
            if authorization.challenge_id is not None:
                base["challenge_id"] = authorization.challenge_id
            if authorization.nonce is not None:
                base["nonce"] = authorization.nonce
        else:  # pragma: no cover - guarded above
            raise MCCInvalidDecisionError("unsupported authorization type")

        cid = correlation_id or decision.correlation_id or None
        try:
            data = self._t.post(path, base, correlation_id=cid)
        except MCCProtocolError:
            # Malformed execution response -> we cannot tell if it executed.
            raise MCCAmbiguousExecutionError(
                "governed execution response was malformed; execution outcome is unknown",
                correlation_id=cid)
        except MCCTransportError as exc:
            # Timeout / transport failure on a POST that may already have executed.
            raise MCCAmbiguousExecutionError(
                f"governed execution outcome is unknown ({exc}); do not assume success",
                correlation_id=cid)
        return self._result(data)

    def execute_after_approval(self, decision: Decision, approval: Approval, *,
                               correlation_id: Optional[str] = None) -> ExecutionResult:
        """Convenience: execute an ESCALATE decision against a granted approval."""
        if approval.mandate is None:
            raise MCCInvalidDecisionError("approval carries no mandate; cannot execute")
        return self.execute(
            decision, ApprovalAuthorization(request_id=approval.request_id, mandate=approval.mandate),
            correlation_id=correlation_id)

    # ------------------------------------------------------------------ #
    # 5. Audit.                                                           #
    # ------------------------------------------------------------------ #

    def verify_audit_chain(self, *, correlation_id: Optional[str] = None) -> Dict[str, Any]:
        return self._t.get("/verify", correlation_id=correlation_id)

    # ------------------------------------------------------------------ #
    # 6. Universal Proposal Service (Phase 1) — additive, non-actuating.  #
    # ------------------------------------------------------------------ #
    #
    # Pure translation onto POST /v1/proposals and GET /v1/operations/{id}
    # (gateway/proposal_api.py). Neither method computes a binding, evaluates
    # policy, infers status, or executes anything -- that is all
    # mcc_proposal.MCCProposalService, reached identically by every other
    # adapter. Submitting a proposal is never permission: it never touches
    # /evaluate, /consensus/execute, or /approvals/*.

    def submit_proposal(
        self,
        *,
        logical_operation_id: str,
        actor: str,
        action: str,
        resource: Optional[str] = None,
        payload: Optional[Payload] = None,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Register a proposal (status ``PROPOSED``). Returns the exact
        ``ProposalReceiptV1`` dict; this method never re-interprets it."""
        if not logical_operation_id or not isinstance(logical_operation_id, str):
            raise MCCInvalidDecisionError("logical_operation_id is required to submit a proposal")
        body: Dict[str, Any] = {
            "logical_operation_id": logical_operation_id,
            "actor": actor,
            "action": action,
            "resource": resource,
            "payload": dict(payload or {}),
        }
        return self._t.post("/v1/proposals", body, correlation_id=correlation_id)

    def get_operation_status(
        self, logical_operation_id: str, *, correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Read-only. Returns the exact ``OperationStatusV1`` dict."""
        from urllib.parse import quote

        path = f"/v1/operations/{quote(logical_operation_id, safe='')}"
        return self._t.get(path, correlation_id=correlation_id)

    # -- internals --

    @staticmethod
    def _guard_executable(decision: Decision, authorization: Authorization) -> None:
        if decision.denied:
            raise MCCDeniedError(decision.reason or "governance denied the action",
                                 audit_id=decision.audit_id)
        if decision.needs_approval and not isinstance(
                authorization, (ApprovalAuthorization, ConsensusAuthorization)):
            raise MCCApprovalRequiredError(
                decision.reason or "human approval required before execution",
                authority_required=decision.authority_required, audit_id=decision.audit_id)
        if not decision.executable and not decision.needs_approval:
            raise MCCInvalidDecisionError(
                f"decision {decision.verdict.value} carries no authorized body to execute")
        if authorization is None:  # pragma: no cover - typing prevents this
            raise MCCInvalidDecisionError("execution requires authorization material")

    @staticmethod
    def _result(data: Dict[str, Any]) -> ExecutionResult:
        status = data.get("status")
        if not isinstance(status, str) or not status:
            # No determinable status -> we cannot say whether it executed.
            raise MCCAmbiguousExecutionError(
                "governed execution response has no status; outcome is unknown",
                correlation_id=data.get("_correlation_id"))
        result = ExecutionResult(
            status=status, reason=str(data.get("reason", "")),
            decision=data.get("decision"), audit_ref=data.get("audit_ref"),
            execution=data.get("execution"), raw=data)
        if result.executed:
            return result
        reason_l = (result.reason or "").lower()
        if any(m in reason_l for m in _REPLAY_MARKERS):
            raise MCCReplayError(result.reason or "decision replayed / already consumed")
        # BLOCKED / EXECUTION_FAILED / anything non-executed -> typed execution error
        # (never downgraded to success).
        raise MCCExecutionError(result.reason or f"execution not completed ({status})",
                                status=status, audit_ref=result.audit_ref, raw=data)


__all__ = ["MCCClient", "Authorization"]
