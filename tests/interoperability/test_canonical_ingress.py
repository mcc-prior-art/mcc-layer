"""PR #49 evidence: every PR #48 adapter traverses the ONE Canonical Ingress
Pipeline into the ONE shared MCC Gateway and yields a GovernanceDecision.

This is the reproducible proof that the five independent adapters (Generic HTTP +
the four real frameworks that register in a given job) do not merely reach the same
gateway (PR #48) but do so through the *same normative protocol and the same
in-process ingress pipeline* (PR #49):

    adapter -> CanonicalProposal -> Canonical Ingress Pipeline -> MCC Gateway
            -> GovernanceDecision

The pipeline routes into the REAL out-of-process gateway over real HTTP via
``mcc_client`` — it never authorizes, evaluates policy, signs, or executes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import mcc_protocol as mp
from tests.interoperability.conftest import ADAPTERS
from tests.interoperability.harness import _client

# The pipeline's action is "the gateway decides"; for evidence we exercise the
# ALLOW path (evaluate returns a real Decision from the shared gateway).
SCENARIO = "ALLOW"


def _promote(adapter, harness_proposal) -> mp.CanonicalProposal:
    """Promote an adapter's (lightweight) interop proposal into the normative
    CanonicalProposal, tagging it with the adapter/framework identity."""
    prov = adapter.framework_provenance()
    return mp.CanonicalProposal.create(
        adapter_id=adapter.adapter_name,
        adapter_version=getattr(adapter, "adapter_version", "1.0.0"),
        framework=prov.get("framework_name", adapter.adapter_name),
        framework_version=str(prov.get("framework_version", "")) or None,
        actor=harness_proposal.actor_id,
        action=harness_proposal.action,
        resource=harness_proposal.resource,
        payload=dict(harness_proposal.payload),
        metadata={"classification": adapter.adapter_classification},
    )


def _registry_for(adapters) -> mp.AdapterRegistry:
    reg = mp.AdapterRegistry()
    for a in adapters:
        prov = a.framework_provenance()
        reg.register(mp.AdapterDescriptor(
            adapter_id=a.adapter_name,
            framework=prov.get("framework_name", a.adapter_name),
            adapter_version=getattr(a, "adapter_version", "1.0.0"),
            supported_protocol_versions=(mp.PROTOCOL_VERSION,),
            conformance={"classification": a.adapter_classification}))
    return reg


def _router_into(gateway):
    """A router that submits a CanonicalProposal to the REAL shared gateway via the
    public mcc_client boundary and returns the canonical Decision. No governance is
    performed here — the gateway decides."""
    def router(proposal: mp.CanonicalProposal):
        client = _client(gateway.base_url, proposal.actor)   # F1: the actor's own key
        return client.evaluate(actor_id=proposal.actor, action=proposal.action,
                               resource=proposal.resource, payload=proposal.payload)
    return router


def test_every_adapter_traverses_the_same_ingress_pipeline(shared_gateway):
    registry = _registry_for(ADAPTERS)
    pipeline = mp.CanonicalIngressPipeline(registry, _router_into(shared_gateway))

    traversals = []
    for adapter in ADAPTERS:
        proposal = _promote(adapter, adapter.proposal_for(SCENARIO))
        result = pipeline.process(proposal)
        assert result.ok, f"{adapter.adapter_name} ingress failed: {result.error}"
        assert result.decision.verdict is mp.Verdict.ALLOW
        # The GovernanceDecision wraps the authoritative gateway Decision + token.
        assert result.decision.has_decision_token
        assert result.decision.audit_reference
        traversals.append({
            "adapter": adapter.adapter_name,
            "framework": proposal.framework,
            "stages": [s.value for s in result.stages_completed],
            "verdict": result.decision.verdict.value,
            "protocol_version": proposal.contract_version,
        })

    # Every adapter traversed the identical ordered pipeline (one shared pipeline).
    stage_sets = {tuple(t["stages"]) for t in traversals}
    assert len(stage_sets) == 1, "adapters did not share one identical pipeline"
    assert stage_sets.pop() == tuple(s.value for s in mp.PIPELINE_STAGES)
    # One protocol version across all adapters.
    assert {t["protocol_version"] for t in traversals} == {mp.PROTOCOL_VERSION}


def test_write_canonical_ingress_evidence(shared_gateway, tmp_path_factory):
    registry = _registry_for(ADAPTERS)
    pipeline = mp.CanonicalIngressPipeline(registry, _router_into(shared_gateway))

    adapters_evidence = []
    for adapter in ADAPTERS:
        proposal = _promote(adapter, adapter.proposal_for(SCENARIO))
        result = pipeline.process(proposal)
        assert result.ok
        adapters_evidence.append({
            "adapter": adapter.adapter_name,
            "classification": adapter.adapter_classification,
            "framework": proposal.framework,
            "proposal_id": proposal.proposal_id,
            "action_hash": proposal.action_hash,
            "stages_completed": [s.value for s in result.stages_completed],
            "governance_decision": result.decision.to_dict(),
        })

    bundle = {
        "proof": "canonical-ingress/1",
        "protocol_version": mp.PROTOCOL_VERSION,
        "contract_version": mp.CONTRACT_VERSION,
        "shared_gateway": shared_gateway.identity(),
        "pipeline_stages": [s.value for s in mp.PIPELINE_STAGES],
        "adapters": adapters_evidence,
        "reconciliation": {
            "single_version_axis": mp.PROTOCOL_VERSION == mp.CONTRACT_VERSION,
            "decision_model": "mcc_client.Decision (wrapped, not replaced)",
            "verdict_model": "mcc_client.Verdict",
        },
    }
    out_dir = Path("artifacts/protocol")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "canonical_ingress_evidence.json").write_text(
        json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")

    # Evidence hygiene: no secrets/keys leaked into the bundle.
    text = json.dumps(bundle).lower()
    for forbidden in ("api_key", "operator_key", "private", "secret", "-----begin"):
        assert forbidden not in text
