"""Workstream K -- Five-Adapter Semantic Equivalence (PR #71).

Proves the assurance baseline's central claims do not depend on WHICH
framework originated the governed action. Reuses the five REAL adapters
built for PR #48's interoperability proof
(``tests/interoperability/adapters/*.py`` -- generic-http, LangGraph,
AutoGen, CrewAI, VoltAgent) unmodified: each one's ``proposal_for("ALLOW")``
runs the actual native framework offline and normalizes its output to a
``CanonicalProposal`` (``actor_id``, ``action``, ``resource``, ``payload``).
This module takes that REAL proposal and drives it through the Gateway's
``/consensus/*`` HTTP API exactly as Workstream C does, then re-runs a
subset of Workstream A/C's adversarial attacks (forged evaluator, replay)
against it -- proving the SAME containment properties hold for every
adapter's proposal shape, not just the one this SUT's own harness happens
to use elsewhere.

Same pattern PR #69 established for ecosystem certification: `generic-http`
has no extra dependency and runs FULLY, locally, always. The other four
require their native framework installed (`langgraph`, `autogen-core`,
`crewai`, or Node + `@voltagent/core` + `tsx`) -- each raises a clean
``ImportError`` when its dependency is absent (the SAME lazy-import
convention ``mcc_certify.ecosystems`` already uses), in which case this
module SKIPS with an explicit reason rather than silently passing. In THIS
environment none of the four framework dependencies are installed, so only
`generic-http` actually runs here; the other four are exercised by
dedicated, isolated CI jobs (one per ecosystem, matching PR #69's job
layout) that install exactly one framework each -- see
``.github/workflows/mcc-runtime-ci.yml``.
"""

from __future__ import annotations

import importlib
import uuid
from typing import Any, Dict

import httpx
import pytest

ADAPTER_MODULES = {
    "generic-http": ("tests.interoperability.adapters.generic_http", "GenericHttpAdapter"),
    "langgraph": ("tests.interoperability.adapters.langgraph_adapter", "LangGraphAdapter"),
    "autogen": ("tests.interoperability.adapters.autogen_adapter", "AutoGenAdapter"),
    "crewai": ("tests.interoperability.adapters.crewai_adapter", "CrewAIAdapter"),
    "voltagent": ("tests.interoperability.adapters.voltagent_adapter", "VoltAgentAdapter"),
}
ADAPTER_NAMES = tuple(ADAPTER_MODULES)


def _load_adapter(name: str):
    module_path, class_name = ADAPTER_MODULES[name]
    try:
        module = importlib.import_module(module_path)
    except ImportError as exc:
        pytest.skip(f"{name} adapter's native framework dependency is not installed here: {exc}")
    return getattr(module, class_name)()


def _challenge(sut, proposal) -> Dict[str, Any]:
    r = httpx.post(
        f"{sut.gateway_url}/consensus/challenge", headers={"x-api-key": sut.agent_key(proposal.actor_id)},
        json={"actor": proposal.actor_id, "action": proposal.action, "resource": proposal.resource,
              "context": proposal.payload}, timeout=10.0,
    )
    r.raise_for_status()
    return r.json()


def _execute(sut, proposal, challenge: Dict[str, Any], votes) -> Dict[str, Any]:
    r = httpx.post(
        f"{sut.gateway_url}/consensus/execute", headers={"x-api-key": sut.agent_key(proposal.actor_id)},
        json={"votes": votes, "actor": proposal.actor_id, "action": proposal.action,
              "resource": proposal.resource, "context": proposal.payload,
              "challenge_id": challenge["challenge_id"], "nonce": challenge["nonce"],
              "idempotency_key": f"k-auto-{uuid.uuid4()}"}, timeout=10.0,
    )
    return r.json()


@pytest.mark.parametrize("adapter_name", ADAPTER_NAMES)
def test_k1_authorized_proposal_from_each_adapter_executes_identically(sut, adapter_name):
    """Each adapter's REAL proposal, given genuine consensus, reaches the
    same governed outcome: EXECUTED, an incremented external-effect count."""
    adapter = _load_adapter(adapter_name)
    proposal = adapter.proposal_for("ALLOW")
    assert proposal.actor_id == "agent/notify-bot"
    assert proposal.action == "send_notification"

    before = sut.gateway_notification_receipt_count()
    challenge = _challenge(sut, proposal)
    votes = sut.gateway_consensus_votes(
        action=proposal.action, payload=proposal.payload, actor=proposal.actor_id,
        resource=proposal.resource, nonce=challenge["nonce"], policy_hash=challenge.get("policy_hash"),
    )
    result = _execute(sut, proposal, challenge, votes)

    assert result["status"] == "EXECUTED"
    assert result["decision"] == "ALLOW"
    assert sut.gateway_notification_receipt_count() == before + 1


@pytest.mark.parametrize("adapter_name", ADAPTER_NAMES)
def test_k2_forged_evaluator_rejected_identically_regardless_of_origin(sut, adapter_name):
    """Workstream A/C's forged-evaluator attack, replayed against EACH
    adapter's real proposal shape -- containment must not depend on which
    framework proposed the action."""
    adapter = _load_adapter(adapter_name)
    proposal = adapter.proposal_for("ALLOW")

    before = sut.gateway_notification_receipt_count()
    challenge = _challenge(sut, proposal)
    forged = sut.forge_vote(
        action=proposal.action, payload=proposal.payload, actor=proposal.actor_id,
        resource=proposal.resource, nonce=challenge["nonce"], policy_hash=challenge.get("policy_hash"),
    )
    result = _execute(sut, proposal, challenge, [forged] * 3)

    assert result["status"] != "EXECUTED"
    assert sut.gateway_notification_receipt_count() == before


@pytest.mark.parametrize("adapter_name", ADAPTER_NAMES)
def test_k3_replay_rejected_identically_regardless_of_origin(sut, adapter_name):
    adapter = _load_adapter(adapter_name)
    proposal = adapter.proposal_for("ALLOW")

    before = sut.gateway_notification_receipt_count()
    challenge = _challenge(sut, proposal)
    votes = sut.gateway_consensus_votes(
        action=proposal.action, payload=proposal.payload, actor=proposal.actor_id,
        resource=proposal.resource, nonce=challenge["nonce"], policy_hash=challenge.get("policy_hash"),
    )
    first = _execute(sut, proposal, challenge, votes)
    assert first["status"] == "EXECUTED"
    assert sut.gateway_notification_receipt_count() == before + 1

    replay = _execute(sut, proposal, challenge, votes)
    assert replay["status"] != "EXECUTED"
    assert sut.gateway_notification_receipt_count() == before + 1
