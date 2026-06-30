"""MCC-Core governed agent.

A real, runnable agent whose external actions are governed end to end by
MCC-Core. The agent proposes; MCC-Core decides; the execution gate enforces; the
governed HTTPS executor performs the request; the audit chain records.

The agent package itself performs no outbound networking and holds no executor or
signing key — it only submits proposals and approval material to MCC-Core through
the supported governance client.
"""

from __future__ import annotations

from .agent import GovernedAgent
from .client import (
    DEFAULT_MAX_BUDGET,
    EmbeddedGovernanceClient,
    GovernanceClient,
    TRUSTED_ACTOR,
    build_pilot_authority,
)
from .errors import (
    AgentError,
    ApprovalError,
    GovernanceClientError,
    PlannerError,
    UnsupportedGoalError,
)
from .models import (
    ActionProposal,
    AgentResult,
    Decision,
    ExecutionStatus,
    GovernanceOutcome,
)
from .planner import DeterministicPlanner
from .version import PILOT_RELEASE_NAME, PILOT_VERSION

__all__ = [
    "PILOT_RELEASE_NAME",
    "PILOT_VERSION",
    "GovernedAgent",
    "DeterministicPlanner",
    "EmbeddedGovernanceClient",
    "GovernanceClient",
    "build_pilot_authority",
    "TRUSTED_ACTOR",
    "DEFAULT_MAX_BUDGET",
    "ActionProposal",
    "AgentResult",
    "Decision",
    "ExecutionStatus",
    "GovernanceOutcome",
    "AgentError",
    "ApprovalError",
    "GovernanceClientError",
    "PlannerError",
    "UnsupportedGoalError",
]
