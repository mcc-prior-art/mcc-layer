"""GovernedAgent — receives a goal, proposes, and acts only on MCC's decision.

The agent is a thin orchestrator:

    goal -> planner.plan(goal) -> proposal
         -> client.submit(proposal)            # MCC decides (and the gate executes)
         -> [ESCALATE] client.approve + execute_after_approval
         -> AgentResult

It holds no executor, no signing key, and no governance logic. A proposal is
never treated as permission: the agent executes an external action only via the
governed client, after MCC-Core authorizes it. The four-line formula holds —
the model proposes, MCC decides, the gate enforces, the audit chain records.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from .client import GovernanceClient
from .models import AgentResult, Decision, ExecutionStatus
from .planner import DeterministicPlanner


class GovernedAgent:
    def __init__(self, *, client: GovernanceClient, planner: DeterministicPlanner,
                 auto_approve: bool = True) -> None:
        self.client = client
        self.planner = planner
        # auto_approve=True lets the pilot demonstrate the full ESCALATE -> approve
        # -> execute loop end to end; set False to stop at PENDING_APPROVAL.
        self.auto_approve = auto_approve

    async def arun(
        self,
        goal: str,
        *,
        actor: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        transaction_id: Optional[str] = None,
        destination_url: Optional[str] = None,
        auto_approve: Optional[bool] = None,
    ) -> AgentResult:
        proposal = self.planner.plan(
            goal, actor=actor, idempotency_key=idempotency_key,
            transaction_id=transaction_id, destination_url=destination_url)

        outcome = await self.client.submit(proposal)
        decision = outcome.decision
        approval_id = outcome.approval_request_id

        approve = self.auto_approve if auto_approve is None else auto_approve
        if decision == Decision.ESCALATE and not outcome.executed and approve and approval_id:
            await self.client.approve(approval_id)
            outcome = await self.client.execute_after_approval(proposal, approval_id)
            # The governance journey was an ESCALATE that an operator approved;
            # keep the verdict as ESCALATE and reflect the post-approval execution.
            decision = Decision.ESCALATE

        return _result(goal, proposal, decision, outcome, approval_id)

    def run(self, goal: str, **kwargs) -> AgentResult:
        """Synchronous convenience wrapper (drives the async governed path)."""
        return asyncio.run(self.arun(goal, **kwargs))


def _result(goal, proposal, decision, outcome, approval_id) -> AgentResult:
    if outcome.executed:
        status = ExecutionStatus.EXECUTED
    elif decision == Decision.ESCALATE:
        status = ExecutionStatus.PENDING_APPROVAL
    else:
        status = ExecutionStatus.BLOCKED
    return AgentResult(
        goal=goal,
        proposal=proposal.to_dict(),
        decision=decision.value,
        execution_status=status.value,
        final_payload=outcome.final_payload,
        audit_id=outcome.audit_ref,
        reason=outcome.reason,
        error_code=outcome.error_code,
        original_payload=dict(proposal.body),
        applied_constraints=list(outcome.applied_constraints),
        upstream_status=outcome.upstream_status,
        correlation_id=outcome.correlation_id,
        approval_request_id=approval_id,
    )
