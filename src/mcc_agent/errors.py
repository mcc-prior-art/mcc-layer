"""Structured errors for the governed agent.

These are agent-side errors only. They never represent an authorization: a
governance DENY/ESCALATE is a *value* in the result, not an exception. Exceptions
here mean the agent could not even form or submit a proposal, or the caller
misused the API.
"""

from __future__ import annotations


class AgentError(Exception):
    """Base class for governed-agent errors."""


class UnsupportedGoalError(AgentError):
    """The deterministic planner has no plan for this goal."""


class PlannerError(AgentError):
    """The planner produced an invalid or incomplete proposal."""


class GovernanceClientError(AgentError):
    """The governance client could not complete a propose/approve/execute step."""


class ApprovalError(AgentError):
    """An approval continuation could not be performed (not that it was denied)."""
