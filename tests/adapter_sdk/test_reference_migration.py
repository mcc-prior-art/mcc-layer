"""Reference migration: the framework-neutral HTTP adapter on the SDK (PR #50).

Proves the migrated adapter (a) uses the public Adapter SDK, (b) preserves the
behaviour of the PR #48 interop ``GenericHttpAdapter`` (identical stable proposal
content + identical verdicts), and (c) still traverses the mandatory
CanonicalIngressPipeline into the REAL shared Gateway over HTTP. The existing
interoperability matrix/evidence is untouched — this only adds the SDK expression.
"""

from __future__ import annotations

import pytest

import mcc_protocol as mp
from examples.adapter_sdk.reference_http_adapter import ReferenceHttpAdapter
from mcc_adapter_sdk import AdapterContext, AdapterRunner, validate_adapter
from tests.interoperability.adapters.generic_http import GenericHttpAdapter
from tests.interoperability.harness import _client


@pytest.fixture(scope="module")
def gateway():
    from tests.interoperability.harness import SharedGovernedGateway
    gw = SharedGovernedGateway()
    try:
        yield gw
    finally:
        gw.close()


def _router_into(gw):
    def router(proposal: mp.CanonicalProposal) -> mp.Decision:
        client = _client(gw.base_url, proposal.actor)   # F1: the actor's own key
        return client.evaluate(actor_id=proposal.actor, action=proposal.action,
                               resource=proposal.resource, payload=proposal.payload)
    return router


def test_migrated_adapter_is_structurally_valid():
    assert validate_adapter(ReferenceHttpAdapter()).structurally_valid


def test_migrated_adapter_preserves_proposal_content():
    # The SDK adapter's stable proposal content matches the original interop adapter.
    sdk_adapter = ReferenceHttpAdapter()
    ctx = AdapterContext.create(actor_reference="agent/notify-bot")
    for scenario in ("ALLOW", "DENY"):
        sdk_prop = sdk_adapter.to_proposal(ctx, scenario)
        orig_prop = GenericHttpAdapter().proposal_for(scenario)
        assert sdk_prop.actor == orig_prop.actor_id
        assert sdk_prop.action == orig_prop.action
        assert sdk_prop.resource == orig_prop.resource
        # Stable payload fields identical (correlation_id is intentionally per-call).
        for k in ("recipient", "message", "priority", "channel"):
            assert sdk_prop.payload[k] == orig_prop.payload[k]


def test_migrated_adapter_traverses_pipeline_to_real_gateway(gateway):
    runner = AdapterRunner(ReferenceHttpAdapter(), _router_into(gateway))
    ctx = AdapterContext.create(actor_reference="agent/notify-bot")

    allow = runner.run(ctx, "ALLOW")
    assert allow.ok and allow.governance_decision.verdict is mp.Verdict.ALLOW
    assert allow.pipeline_summary["stages_completed"] == [s.value for s in mp.PIPELINE_STAGES]
    assert allow.governance_decision.has_decision_token

    deny = runner.run(ctx, "DENY")
    assert deny.ok and deny.governance_decision.verdict is mp.Verdict.DENY
    assert deny.native_response["executable"] is False
