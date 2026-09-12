"""A MINIMAL, TEST-ONLY, non-GitHub actuator implementing the exact same
generic controlled-execution contract (``ResourceBoundUpstream``) GitHub's
actuator implements -- proof that GitHub is not structurally privileged
inside MCC-Core (actuator-neutrality non-vacuity, PR #112).

This is deliberately NOT a second production actuator architecture: it is
one in-process Python dict standing in for "some other execution domain"
(think: a toy ledger, not AWS/SAP/payments/robotics/anything real). It
exists ONLY to be run through the IDENTICAL generic path
(``ProposalExecutionService.authorize_and_execute`` via the real HTTP
routes) that the GitHub actuator runs through, with zero changes to
MCC-Core, the authority model, token semantics, the Gate, or
``ProposalExecutionService`` -- see
``tests/test_universal_execution_proof.py``'s actuator-replaceability
non-vacuity test.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from gateway.proposal_execution_service import ResourceMismatchError


class GenericLedgerUpstream:
    """Records ``(resource, action, payload)`` into an in-memory list --
    nothing external, nothing domain-specific. Implements the SAME
    ``resource`` attribute + ``execute(*, resource, action, payload)``
    shape ``ResourceBoundUpstream`` defines, so
    ``ProposalExecutionService`` cannot tell it apart from any other
    controlled actuator (including the GitHub one) at the type level."""

    def __init__(self, resource: Optional[str]) -> None:
        self.resource = resource
        self.entries: List[Tuple[Optional[str], str, Dict[str, Any]]] = []

    async def execute(self, *, resource: Optional[str], action: str, payload: Dict[str, Any]) -> Any:
        if resource != self.resource:
            raise ResourceMismatchError(
                f"generic ledger actuator configured for resource {self.resource!r} refuses "
                f"to dispatch to {resource!r}; refusing before any recorded side effect"
            )
        entry_id = len(self.entries)
        self.entries.append((resource, action, dict(payload)))
        return {"ledger_entry_id": entry_id, "resource": resource, "action": action}


def build_generic_ledger_upstream(resource: Optional[str] = "generic-resource-1") -> GenericLedgerUpstream:
    """Returns a plain object satisfying the SAME duck-typed contract
    ``ProposalExecutionService`` requires of ``ResourceBoundUpstream``
    (a ``.resource`` attribute + async ``.execute(resource=, action=,
    payload=)``) -- interchangeable, from
    ``ProposalExecutionService``'s point of view, with
    the GitHub-backed reference actuator used elsewhere in this proof."""
    return GenericLedgerUpstream(resource=resource)


__all__ = ["GenericLedgerUpstream", "build_generic_ledger_upstream"]
