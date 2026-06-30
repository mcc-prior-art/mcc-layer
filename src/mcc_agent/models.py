"""Typed, documented models for the supported MCC-Core agent client.

The models make the four governance stages explicit and keep a hard separation
between *proposing* an action and *being authorized* to execute it:

* :class:`ActionProposal`  — what the agent wants to do (never a permission).
* :class:`GovernanceOutcome` — what MCC-Core decided + (for ALLOW/CONSTRAIN) the
  result of the single governed execution; for ESCALATE, the approval handle.
* :class:`ApprovalRequirement` / approval submission flows through the existing
  MCC approval path — the agent never mints authorization itself.
* :class:`AgentResult` — the structured, audit-anchored summary returned to the
  caller.

No private signing key, internal token, or raw authorization object is exposed
through these models. The agent submits a proposal (and, for ESCALATE, an
approval id) and receives a decision — it never reconstructs MCC internals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"
    CONSTRAIN = "CONSTRAIN"
    # Non-verdict terminal states surfaced by the governed runtime.
    INVALID_REQUEST = "INVALID_REQUEST"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    BLOCKED = "BLOCKED"


class ExecutionStatus(str, Enum):
    EXECUTED = "EXECUTED"
    BLOCKED = "BLOCKED"
    PENDING_APPROVAL = "PENDING_APPROVAL"


@dataclass(frozen=True)
class ActionProposal:
    """A structured action proposal — the agent's *intent*, never authority.

    ``method``/``url``/``body`` describe the outbound HTTP action that the
    governed HTTPS executor would perform *if and only if* MCC-Core authorizes
    it. ``actor``/``resource``/``transaction_id``/``idempotency_key`` bind the
    operation for replay, idempotency, and audit."""

    goal: str
    actor: str
    action_type: str
    method: str
    url: str
    body: Dict[str, Any]
    resource: str
    transaction_id: str
    idempotency_key: str
    amount: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal": self.goal,
            "actor": self.actor,
            "action_type": self.action_type,
            "method": self.method,
            "url": self.url,
            "body": dict(self.body),
            "resource": self.resource,
            "transaction_id": self.transaction_id,
            "idempotency_key": self.idempotency_key,
            "amount": self.amount,
        }


@dataclass(frozen=True)
class GovernanceOutcome:
    """The result of one governed step through MCC-Core."""

    decision: Decision
    executed: bool
    reason: str
    error_code: Optional[str] = None
    action_hash: Optional[str] = None
    audit_ref: Optional[str] = None
    correlation_id: Optional[str] = None
    # ESCALATE: the approval request the operator must approve.
    approval_request_id: Optional[str] = None
    # CONSTRAIN: the clamped action that was (or must be) authorized; the original
    # is never executed.
    constrained_action: Optional[Dict[str, Any]] = None
    applied_constraints: List[str] = field(default_factory=list)
    # ALLOW / CONSTRAIN executed: the external API's response.
    upstream_status: Optional[int] = None
    upstream_body: Any = None
    # The payload actually authorized + sent (clamped for CONSTRAIN).
    final_payload: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class AgentResult:
    """The structured result returned by :meth:`GovernedAgent.run`."""

    goal: str
    proposal: Dict[str, Any]
    decision: str
    execution_status: str
    final_payload: Optional[Dict[str, Any]]
    audit_id: Optional[str]
    reason: str = ""
    error_code: Optional[str] = None
    original_payload: Optional[Dict[str, Any]] = None
    applied_constraints: List[str] = field(default_factory=list)
    upstream_status: Optional[int] = None
    correlation_id: Optional[str] = None
    approval_request_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal": self.goal,
            "proposal": self.proposal,
            "decision": self.decision,
            "execution_status": self.execution_status,
            "final_payload": self.final_payload,
            "audit_id": self.audit_id,
            "reason": self.reason,
            "error_code": self.error_code,
            "original_payload": self.original_payload,
            "applied_constraints": list(self.applied_constraints),
            "upstream_status": self.upstream_status,
            "correlation_id": self.correlation_id,
            "approval_request_id": self.approval_request_id,
        }
