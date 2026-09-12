"""GPT-6 Astra as the concrete upstream producer for the Universal
Execution Authority proof (PR #112, correction addendum).

Reuses, unchanged, ``examples.gpt6_astra_reference``'s existing
intelligence-layer abstraction (``AstraProvider.propose(task) ->
AstraResponse``, ``DeterministicAstraProvider``, ``AstraProposal``) — no
new provider integration, no new Astra-specific architecture. Astra
itself has, and can reach, nothing MCC would treat as trusted evidence or
authority: no signing key, no attestation material, no reference to
``mcc_core``/the Gate/the coordinator at all (see
``examples/gpt6_astra_reference/astra_provider.py``'s own module
docstring and ``tests/test_gpt6_astra_reference_architecture_guards.py``,
both unmodified and reused as the structural proof that Astra cannot mint
or bypass execution authority).

This module's ONLY job is translating one ``AstraProposal`` (whatever
Astra "decided" to propose) into the plain JSON shape PR #111's real HTTP
boundary (``POST /v1/proposals``) already accepts -- there is no
Astra-specific field, no Astra-specific verdict, and no Astra-specific
execution path. Any other proposal producer (a different provider, a
different framework, a human) uses the exact same
``astra_proposal_to_http_request`` shape trivially, because it is nothing
more than ``{action, resource, payload}``.
"""

from __future__ import annotations

from typing import Any, Dict

from examples.gpt6_astra_reference.astra_provider import DeterministicAstraProvider
from examples.gpt6_astra_reference.models import AstraError, AstraProposal, AstraSelfRefusal


class AstraUpstreamError(Exception):
    """Raised when Astra declined (self-refusal) or its output could not
    be used (parse/format error) -- in both cases, exactly as
    ``examples.gpt6_astra_reference`` already documents, MCC-Core is never
    invoked at all; there is nothing to authorize."""


def build_astra_provider(task: str, *, action: str, resource: str, payload: Dict[str, Any]) -> DeterministicAstraProvider:
    """The reference/offline Astra provider this repository's own demos
    and tests already default to (no live OpenAI-compatible call, no
    credential) -- one canned task -> proposal table entry, run through
    the SAME strict parser (``parse_proposals``) a live model's output
    would be."""
    return DeterministicAstraProvider({task: {"action": action, "resource": resource, "payload": payload}})


async def propose_via_astra(provider: DeterministicAstraProvider, task: str) -> AstraProposal:
    """Calls Astra (``propose``) and returns exactly one
    :class:`AstraProposal` -- raising :class:`AstraUpstreamError` for a
    self-refusal or a malformed/forbidden-field response, precisely
    mirroring how a real live-model failure would be handled: MCC-Core is
    never reached in either case."""
    response = await provider.propose(task)
    outcome = response.outcome
    if isinstance(outcome, AstraSelfRefusal):
        raise AstraUpstreamError(f"Astra declined to propose: {outcome.reason}")
    if isinstance(outcome, AstraError):
        raise AstraUpstreamError(f"Astra output could not be used: {outcome.detail}")
    if not outcome:
        raise AstraUpstreamError("Astra produced no proposals")
    return outcome[0]


def astra_proposal_to_http_request(proposal: AstraProposal) -> Dict[str, Any]:
    """The ENTIRE upstream-adaptation surface: an ``AstraProposal`` has no
    field this dict does not already carry, and no field of this dict is
    Astra-specific -- ``actor`` is the only addition, a plain label
    (unused by authority; see
    ``docs/UNIVERSAL_EXECUTION_PROOF.md`` §2), never a trust signal."""
    return {
        "actor": "gpt-6-astra-reference/v1",
        "action": proposal.action,
        "resource": proposal.resource,
        "payload": dict(proposal.payload),
    }


__all__ = [
    "AstraUpstreamError", "build_astra_provider", "propose_via_astra", "astra_proposal_to_http_request",
]
