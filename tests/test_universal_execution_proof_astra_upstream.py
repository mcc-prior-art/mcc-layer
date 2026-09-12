"""GPT-6 Astra as the concrete upstream producer (PR #112 correction
addendum) — offline, deterministic.

Proves: an Astra-produced proposal reaches EXECUTED through the exact
same generic HTTP boundary (``POST /v1/proposals`` ->
``POST /v1/operations/{id}/execute``) any other upstream producer uses in
``tests/test_universal_execution_proof.py``, and that Astra itself never
touches signing/authority material (reusing, unmodified, the EXISTING
guard in ``tests/test_gpt6_astra_reference_architecture_guards.py`` — no
duplicate Astra-specific Core architecture is introduced here).
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from mcc_core import InMemoryIdempotencyRegistry, InMemoryNonceRegistry
from mcc_proposal import InMemoryProposalRegistry

from examples._demo_server import DemoServer, free_port
from examples.gpt6_astra_reference.github_actuator import GitHubActuatorConfig, GitHubIssueActuator
from examples.gpt6_astra_reference.issue_contract import GITHUB_ISSUE_ACTION
from examples.gpt6_astra_reference.mock_github_service import (
    build_mock_github_service,
    recorded_issues,
    reset_issues,
)
from examples.phase2_live_sandbox.actuator import GitHubSandboxUpstream
from examples.universal_execution_proof import build_universal_proof_stack
from examples.universal_execution_proof.astra_upstream import (
    AstraUpstreamError,
    astra_proposal_to_http_request,
    build_astra_provider,
    propose_via_astra,
)

run = asyncio.run
CREDS = {"key-a": "tenant-a"}


@pytest.fixture(scope="module")
def mock_github():
    reset_issues()
    port = free_port()
    server = DemoServer(build_mock_github_service(), port).start()
    yield f"http://127.0.0.1:{port}"
    server.stop()


def _github_stack(mock_github: str, repo: str = "sandbox-owner/sandbox-repo"):
    reset_issues()
    proposals = InMemoryProposalRegistry()
    idem = InMemoryIdempotencyRegistry()
    nonces = InMemoryNonceRegistry()
    actuator_config = GitHubActuatorConfig(mode="live", repo=repo, base_url=mock_github, token=None)
    upstream = GitHubSandboxUpstream(GitHubIssueActuator(actuator_config))
    audit_path = str(Path(tempfile.mkdtemp(prefix="mcc-astra-upstream-test-")) / "audit.jsonl")
    proof = build_universal_proof_stack(
        proposals=proposals, idempotency=idem, nonces=nonces,
        tenants_credentials=CREDS, tenants_authority={"tenant-a": {}},
        upstream=upstream, action=GITHUB_ISSUE_ACTION, audit_log_path=audit_path,
    )
    return SimpleNamespace(proof=proof, client=TestClient(proof.app), repo=repo)


# --------------------------------------------------------------------------- #
# A/B. Astra proposal reaches EXECUTED through the real HTTP boundary.
# --------------------------------------------------------------------------- #

def test_astra_proposal_reaches_real_actuator_through_http_boundary(mock_github):
    ctx = _github_stack(mock_github)
    provider = build_astra_provider(
        "file-a-sandbox-issue",
        action=GITHUB_ISSUE_ACTION, resource=ctx.repo,
        payload={"title": "Astra-originated proof issue", "body": "produced by GPT-6 Astra reference provider"},
    )
    astra_proposal = run(propose_via_astra(provider, "file-a-sandbox-issue"))
    http_request = astra_proposal_to_http_request(astra_proposal)

    r = ctx.client.post("/v1/proposals", headers={"x-api-key": "key-a"}, json={
        "logical_operation_id": "op-astra-1", **http_request,
    })
    assert r.status_code == 200
    assert r.json()["status"] == "PROPOSED"

    r2 = ctx.client.post("/v1/operations/op-astra-1/execute", headers={"x-api-key": "key-a"})
    assert r2.status_code == 200
    assert r2.json()["status"] == "EXECUTED"
    assert len(recorded_issues()) == 1
    assert recorded_issues()[0]["title"] == "Astra-originated proof issue"


# --------------------------------------------------------------------------- #
# C. Astra cannot directly cause consequential execution -- it only ever
# produces a proposal dict; nothing in this adapter calls an actuator.
# --------------------------------------------------------------------------- #

def test_astra_upstream_module_never_touches_actuator_or_authority():
    import examples.universal_execution_proof.astra_upstream as mod

    source = Path(mod.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "ResourceBoundUpstream(", ".execute(resource=", "EnforcementCoordinator", "ExecutionGate",
        "AuthorityModel", "DecisionEngine", "SigningKey", "issue_token",
    ):
        assert forbidden not in source, f"astra_upstream.py references {forbidden!r}"


# --------------------------------------------------------------------------- #
# Astra self-refusal / malformed output: MCC-Core is never reached.
# --------------------------------------------------------------------------- #

def test_astra_self_refusal_never_reaches_mcc(mock_github):
    from examples.gpt6_astra_reference.astra_provider import DeterministicAstraProvider
    from examples.gpt6_astra_reference.models import AstraSelfRefusal

    provider = DeterministicAstraProvider({"declined-task": AstraSelfRefusal(reason="not appropriate")})
    with pytest.raises(AstraUpstreamError):
        run(propose_via_astra(provider, "declined-task"))
    # No proposal was ever submitted -- nothing to assert against the
    # governed path except that it was never touched, which is exactly
    # what NOT calling ctx.client here already demonstrates.


def test_astra_malformed_output_never_reaches_mcc():
    from examples.gpt6_astra_reference.astra_provider import DeterministicAstraProvider

    provider = DeterministicAstraProvider({"bad-task": {"resource": "missing-action-field"}})
    with pytest.raises(AstraUpstreamError):
        run(propose_via_astra(provider, "bad-task"))


# --------------------------------------------------------------------------- #
# F/G (restated for Astra specifically): replay and resource-mismatch hold
# identically for an Astra-sourced proposal.
# --------------------------------------------------------------------------- #

def test_astra_sourced_proposal_replay_zero_second_dispatch(mock_github):
    ctx = _github_stack(mock_github)
    provider = build_astra_provider(
        "file-b-sandbox-issue", action=GITHUB_ISSUE_ACTION, resource=ctx.repo,
        payload={"title": "Astra replay test", "body": "b"},
    )
    proposal = run(propose_via_astra(provider, "file-b-sandbox-issue"))
    http_request = astra_proposal_to_http_request(proposal)
    ctx.client.post("/v1/proposals", headers={"x-api-key": "key-a"}, json={
        "logical_operation_id": "op-astra-2", **http_request,
    })
    r1 = ctx.client.post("/v1/operations/op-astra-2/execute", headers={"x-api-key": "key-a"})
    r2 = ctx.client.post("/v1/operations/op-astra-2/execute", headers={"x-api-key": "key-a"})
    assert r1.json()["status"] == "EXECUTED"
    assert r2.json()["status"] != "EXECUTED"
    assert len(recorded_issues()) == 1


def test_astra_sourced_proposal_resource_mismatch_zero_external_call(mock_github):
    ctx = _github_stack(mock_github, repo="sandbox-owner/FIXED-repo")
    provider = build_astra_provider(
        "file-c-sandbox-issue", action=GITHUB_ISSUE_ACTION, resource="sandbox-owner/DIFFERENT-repo",
        payload={"title": "Astra mismatch test", "body": "c"},
    )
    proposal = run(propose_via_astra(provider, "file-c-sandbox-issue"))
    http_request = astra_proposal_to_http_request(proposal)
    ctx.client.post("/v1/proposals", headers={"x-api-key": "key-a"}, json={
        "logical_operation_id": "op-astra-3", **http_request,
    })
    r = ctx.client.post("/v1/operations/op-astra-3/execute", headers={"x-api-key": "key-a"})
    assert r.json()["status"] == "RESOURCE_MISMATCH"
    assert recorded_issues() == []
