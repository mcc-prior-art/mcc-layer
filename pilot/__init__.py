"""MCC-Core Pilot Runtime Package.

Deploy and integrate the *existing* unified governance runtime as a real
execution-control layer. This package adds no governance logic of its own — it
is a thin, supported surface over the runtime that already lives in
``mcc_core`` / ``gateway`` / ``interceptors``:

* :class:`pilot.client.MCCGatewayClient` — a typed Python client for the
  deployed HTTP gateway. It submits proposals, reads the four verdicts
  (ALLOW / DENY / ESCALATE / CONSTRAIN), submits approvals or consensus
  material, and executes **only** through the gateway's governed endpoints
  (which run the one ``EnforcementCoordinator`` path). It has no local executor.

* :class:`pilot.outbound_executor.OutboundHTTPExecutor` — the governed *side
  effect* used by the reference integration: a real outbound HTTP call that
  refuses to run without the verified decision token MCC issued for that exact
  operation. It is the thing being governed, never a second gate.

See ``docs/unified-governance-runtime.md`` and ``deploy/pilot/RUNBOOK.md``.
"""

from .client import (
    Decision,
    ExecutionOutcome,
    MCCGatewayClient,
    ProposalResult,
)
from .outbound_executor import OutboundHTTPExecutor, UnauthorizedExecution

__all__ = [
    "Decision",
    "ProposalResult",
    "ExecutionOutcome",
    "MCCGatewayClient",
    "OutboundHTTPExecutor",
    "UnauthorizedExecution",
]
