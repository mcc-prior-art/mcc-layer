"""Bring-your-own-actuator template (PR #113).

THE AGENT NEVER GETS THE ACTUATOR DIRECTLY. This module shows the
smallest safe implementation plugging into the EXISTING
``gateway.proposal_execution_service.ResourceBoundUpstream`` contract --
the ONLY actuator boundary :class:`gateway.proposal_execution_service.
ProposalExecutionService` accepts (see that module's own docstring). No
parallel actuator framework is introduced here; this is a NEW INSTANCE of
the existing contract, not a new shape.

``ResourceBoundUpstream`` requires exactly two things from an integrator:

* a fixed, trusted ``.resource`` -- set once, at construction, by the
  deployment operator; NEVER derived from proposal content, request
  payload, or any other untrusted input;
* an async ``dispatch(*, resource, action, payload) -> Any`` callable --
  the ONE place a real integration replaces with its own system call
  (an internal API, a queue publish, a database write, a robot command,
  anything). ``ResourceBoundUpstream.execute`` independently re-verifies
  ``resource`` against the fixed configuration immediately before calling
  ``dispatch`` (defense in depth beyond ``ProposalExecutionService``'s own
  pre-token-issuance check) -- an integrator's ``dispatch`` never needs to
  re-implement that check itself.

:class:`DemoLedgerActuator` below is DELIBERATELY the smallest possible
implementation: an in-memory list, obviously non-production, with two
literal payload keys reserved ONLY for the pilot pack's own self-check
scenarios (never meaningful to a real integration):

* ``payload["__simulate_ambiguous_failure__"]`` -- raises after being
  called, to exercise the EXISTING UNKNOWN/durable-uncertainty contract
  (``mcc_core.coordinator.EnforcementCoordinator`` marks the durable state
  UNKNOWN, never a false EXECUTED, and never silently retryable) -- see
  ``tests/test_proposal_execution_api.py::test_m_ambiguous_post_dispatch_failure_no_automatic_retry``,
  which this template's own self-check scenario G reproduces.
* ``payload["__simulate_deterministic_failure__"]`` -- raises a distinct,
  clearly-non-ambiguous error, for exercising deterministic actuator
  failure without touching the ambiguous/UNKNOWN path.

A real integration deletes both branches (or ignores those keys entirely
-- they are not part of the generic proposal contract) and writes its own
dispatch logic in their place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from gateway.proposal_execution_service import ResourceBoundUpstream

DEFAULT_RESOURCE = "external-pilot-demo-resource"


class SimulatedAmbiguousFailure(Exception):
    """Raised by :class:`DemoLedgerActuator` when asked to simulate a
    post-dispatch-uncertain failure (self-check scenario G only)."""


class SimulatedDeterministicFailure(Exception):
    """Raised by :class:`DemoLedgerActuator` when asked to simulate a
    plain, non-ambiguous actuator failure (self-check scenario only)."""


@dataclass
class DemoLedgerActuator:
    """Minimal, obviously non-production actuator: records each dispatched
    (resource, action, payload) triple in-memory. Replace ``dispatch`` (or
    subclass/compose) with your real system call for an actual
    integration -- this class exists only so the pack's quick-start and
    self-check can run with zero external dependencies."""

    resource: Optional[str] = DEFAULT_RESOURCE
    entries: List[Tuple[str, str, Dict[str, Any]]] = field(default_factory=list)

    async def dispatch(self, *, resource: Optional[str], action: str, payload: Dict[str, Any]) -> Any:
        if payload.get("__simulate_ambiguous_failure__"):
            raise SimulatedAmbiguousFailure(
                "demo actuator: simulated post-dispatch-ambiguous failure (self-check scenario G)"
            )
        if payload.get("__simulate_deterministic_failure__"):
            raise SimulatedDeterministicFailure("demo actuator: simulated deterministic failure")
        entry_id = len(self.entries)
        clean_payload = {k: v for k, v in payload.items() if not k.startswith("__simulate_")}
        self.entries.append((resource, action, dict(clean_payload)))
        return {"ledger_entry_id": entry_id, "resource": resource, "action": action}


def build_demo_actuator(resource: Optional[str] = DEFAULT_RESOURCE) -> Tuple[ResourceBoundUpstream, DemoLedgerActuator]:
    """Returns ``(upstream, ledger)`` -- ``upstream`` is what
    ``gateway.proposal_execution_stack.build_proposal_execution_stack``
    accepts as its ``upstream`` argument; ``ledger`` is the same object,
    kept so scenario code can independently assert ``len(ledger.entries)``
    (exactly-once dispatch) without touching MCC-Core internals."""
    ledger = DemoLedgerActuator(resource=resource)
    upstream = ResourceBoundUpstream(resource=resource, dispatch=ledger.dispatch)
    return upstream, ledger


__all__ = [
    "DemoLedgerActuator", "build_demo_actuator", "DEFAULT_RESOURCE",
    "SimulatedAmbiguousFailure", "SimulatedDeterministicFailure",
]
