"""Universal Execution Authority Proof (PR #112) — offline, deterministic
adversarial/negative matrix (A-H), replay/concurrency (F/G), actuator-
replaceability non-vacuity, and upstream-replaceability non-vacuity.

Exercises the REAL HTTP surface PR #111 shipped
(``gateway.proposal_api.mount_proposal_routes`` +
``gateway.proposal_execution_api.mount_proposal_execution_routes``, via
``examples.universal_execution_proof.build_universal_proof_app``) —
never a direct ``ProposalExecutionService`` call. The GitHub-backed
scenarios use a REAL local HTTP mock server
(``examples/gpt6_astra_reference/mock_github_service.py``, reused
unchanged) through the existing, unmodified
``GitHubSandboxUpstream``/``GitHubIssueActuator`` — no live GitHub network
access is used or required by this module.
"""

from __future__ import annotations

import asyncio
import copy
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcc_core import InMemoryIdempotencyRegistry, InMemoryNonceRegistry, Verdict
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
from examples.universal_execution_proof.generic_ledger_actuator import build_generic_ledger_upstream
from gateway.proposal_execution_service import ProposalExecutionService, ResourceBoundUpstream

run = asyncio.run
# The GitHub-backed stack must authorize exactly the action the real
# GitHubIssueActuator accepts (GITHUB_ISSUE_ACTION) -- MCC-Core itself is
# domain-neutral about the action string, but the actuator behind it is
# not, exactly like any other real domain-specific actuator would be.
ACTION = GITHUB_ISSUE_ACTION
CREDS = {"key-a": "tenant-a", "key-b": "tenant-b"}


@pytest.fixture(scope="module")
def mock_github():
    reset_issues()
    port = free_port()
    server = DemoServer(build_mock_github_service(), port).start()
    yield f"http://127.0.0.1:{port}"
    server.stop()


def _github_stack(mock_github: str, *, repo: str = "sandbox-owner/sandbox-repo", allowed=("tenant-a", "tenant-b"),
                   without_mandate: Verdict = Verdict.DENY, max_amount=None):
    reset_issues()
    proposals = InMemoryProposalRegistry()
    idem = InMemoryIdempotencyRegistry()
    nonces = InMemoryNonceRegistry()
    actuator_config = GitHubActuatorConfig(mode="live", repo=repo, base_url=mock_github, token=None)
    upstream = GitHubSandboxUpstream(GitHubIssueActuator(actuator_config))
    audit_path = str(Path(tempfile.mkdtemp(prefix="mcc-universal-proof-test-")) / "audit.jsonl")
    tenants_authority = {t: ({"max_amount": max_amount} if max_amount is not None else {}) for t in allowed}
    proof = build_universal_proof_stack(
        proposals=proposals, idempotency=idem, nonces=nonces,
        tenants_credentials=CREDS, tenants_authority=tenants_authority,
        upstream=upstream, action=ACTION, audit_log_path=audit_path, without_mandate=without_mandate,
    )
    return SimpleNamespace(proof=proof, client=TestClient(proof.app), upstream=upstream, repo=repo)


def _ledger_stack(*, allowed=("tenant-a", "tenant-b"), resource="generic-resource-1"):
    proposals = InMemoryProposalRegistry()
    idem = InMemoryIdempotencyRegistry()
    nonces = InMemoryNonceRegistry()
    upstream = build_generic_ledger_upstream(resource=resource)
    audit_path = str(Path(tempfile.mkdtemp(prefix="mcc-universal-proof-ledger-test-")) / "audit.jsonl")
    tenants_authority = {t: {} for t in allowed}
    proof = build_universal_proof_stack(
        proposals=proposals, idempotency=idem, nonces=nonces,
        tenants_credentials=CREDS, tenants_authority=tenants_authority,
        upstream=upstream, action=ACTION, audit_log_path=audit_path,
    )
    return SimpleNamespace(proof=proof, client=TestClient(proof.app), upstream=upstream, resource=resource)


def _submit(client: TestClient, *, key: str, op_id: str, resource: str, payload: Optional[Dict[str, Any]] = None,
            actor: str = "test-actor"):
    # {"title": ..., "body": ...} is a valid shape for BOTH the real
    # GitHubIssueActuator (which validates it) and the generic ledger
    # actuator (which accepts anything) -- one payload shape usable
    # against either domain, demonstrating MCC-Core's own indifference to
    # payload business meaning (it only binds/hashes it).
    return client.post("/v1/proposals", headers={"x-api-key": key}, json={
        "logical_operation_id": op_id, "actor": actor, "action": ACTION,
        "resource": resource, "payload": payload or {"title": "Universal proof test", "body": "n=1"},
    })


def _execute(client: TestClient, *, key: Optional[str], op_id: str):
    headers = {"x-api-key": key} if key else {}
    return client.post(f"/v1/operations/{op_id}/execute", headers=headers)


# --------------------------------------------------------------------------- #
# A. Missing API key -> 401, zero actuation
# --------------------------------------------------------------------------- #

def test_a_missing_api_key_401_zero_actuation(mock_github):
    ctx = _github_stack(mock_github)
    _submit(ctx.client, key="key-a", op_id="op-a", resource=ctx.repo)
    r = _execute(ctx.client, key=None, op_id="op-a")
    assert r.status_code == 401
    assert recorded_issues() == []


# --------------------------------------------------------------------------- #
# B. Invalid API key -> 401, zero actuation
# --------------------------------------------------------------------------- #

def test_b_invalid_api_key_401_zero_actuation(mock_github):
    ctx = _github_stack(mock_github)
    _submit(ctx.client, key="key-a", op_id="op-b", resource=ctx.repo)
    r = ctx.client.post("/v1/operations/op-b/execute", headers={"x-api-key": "wrong"})
    assert r.status_code == 401
    assert recorded_issues() == []


# --------------------------------------------------------------------------- #
# C. Cross-tenant execution -> tenant-safe 404, zero actuation
# --------------------------------------------------------------------------- #

def test_c_cross_tenant_execution_404_zero_actuation(mock_github):
    ctx = _github_stack(mock_github)
    _submit(ctx.client, key="key-b", op_id="op-c", resource=ctx.repo)
    r = _execute(ctx.client, key="key-a", op_id="op-c")
    assert r.status_code == 404
    assert recorded_issues() == []
    own = _execute(ctx.client, key="key-b", op_id="op-c")
    assert own.status_code == 200
    assert own.json()["status"] == "EXECUTED"


# --------------------------------------------------------------------------- #
# D. Authenticated identity, no execution authority -> DENIED, zero actuation
# --------------------------------------------------------------------------- #

def test_d_no_authority_denied_zero_actuation(mock_github):
    # tenant-c has a real credential (authenticates) but is not in the
    # authority grant map (without_mandate defaults to DENY). Build a
    # fresh stack with the wider credential map but the SAME authority map.
    repo = "sandbox-owner/sandbox-repo"
    creds = {**CREDS, "key-c": "tenant-c"}
    proposals = InMemoryProposalRegistry()
    idem = InMemoryIdempotencyRegistry()
    nonces = InMemoryNonceRegistry()
    actuator_config = GitHubActuatorConfig(mode="live", repo=repo, base_url=mock_github, token=None)
    upstream = GitHubSandboxUpstream(GitHubIssueActuator(actuator_config))
    audit_path = str(Path(tempfile.mkdtemp(prefix="mcc-universal-proof-test-")) / "audit.jsonl")
    proof = build_universal_proof_stack(
        proposals=proposals, idempotency=idem, nonces=nonces,
        tenants_credentials=creds, tenants_authority={"tenant-a": {}, "tenant-b": {}},
        upstream=upstream, action=ACTION, audit_log_path=audit_path,
    )
    client = TestClient(proof.app)
    reset_issues()
    _submit(client, key="key-c", op_id="op-d", resource=repo)
    r = _execute(client, key="key-c", op_id="op-d")
    assert r.status_code == 200
    assert r.json()["status"] == "DENIED"
    assert recorded_issues() == []


# --------------------------------------------------------------------------- #
# E. Resource differs from fixed actuator destination -> RESOURCE_MISMATCH
# --------------------------------------------------------------------------- #

def test_e_resource_mismatch_zero_external_call(mock_github):
    ctx = _github_stack(mock_github, repo="sandbox-owner/fixed-repo")
    _submit(ctx.client, key="key-a", op_id="op-e", resource="sandbox-owner/DIFFERENT-repo")
    r = _execute(ctx.client, key="key-a", op_id="op-e")
    assert r.status_code == 200
    assert r.json()["status"] == "RESOURCE_MISMATCH"
    assert recorded_issues() == []


# --------------------------------------------------------------------------- #
# F. Replay -> zero second dispatch
# --------------------------------------------------------------------------- #

def test_f_replay_zero_second_dispatch(mock_github):
    ctx = _github_stack(mock_github)
    _submit(ctx.client, key="key-a", op_id="op-f", resource=ctx.repo)
    r1 = _execute(ctx.client, key="key-a", op_id="op-f")
    r2 = _execute(ctx.client, key="key-a", op_id="op-f")
    assert r1.json()["status"] == "EXECUTED"
    assert r2.json()["status"] != "EXECUTED"
    assert len(recorded_issues()) == 1


# --------------------------------------------------------------------------- #
# G. Concurrent duplicate execution -> at most one dispatch
# --------------------------------------------------------------------------- #

async def _concurrent_execute(app: FastAPI, *, key: str, op_id: str, n: int) -> List[Any]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await asyncio.gather(*[
            client.post(f"/v1/operations/{op_id}/execute", headers={"x-api-key": key}) for _ in range(n)
        ])


def test_g_concurrent_duplicate_at_most_one_dispatch(mock_github):
    ctx = _github_stack(mock_github)
    _submit(ctx.client, key="key-a", op_id="op-g", resource=ctx.repo)
    results = run(_concurrent_execute(ctx.proof.app, key="key-a", op_id="op-g", n=8))
    statuses = [r.json()["status"] for r in results]
    assert statuses.count("EXECUTED") == 1
    assert len(recorded_issues()) == 1


# --------------------------------------------------------------------------- #
# H. Caller attempts to smuggle trusted fields -> cannot modify authority/destination
# --------------------------------------------------------------------------- #

def test_h_caller_cannot_smuggle_trusted_fields(mock_github):
    ctx = _github_stack(mock_github)
    _submit(ctx.client, key="key-a", op_id="op-h", resource=ctx.repo)
    r = ctx.client.post(
        f"/v1/operations/op-h/execute",
        headers={"x-api-key": "key-a"},
        json={
            "tenant_id": "tenant-b", "resource": "some-other-repo", "payload": {"n": 999},
            "authority": "ALLOW", "decision": "ALLOW", "signed_authority": "forged",
            "actuator": "evil", "actuator_destination": "evil-repo", "provider_permission": "granted",
        },
    )
    assert r.status_code == 200
    assert r.json()["status"] == "EXECUTED"
    assert len(recorded_issues()) == 1
    issue = recorded_issues()[0]
    # The dispatched payload/resource are provably the ORIGINAL stored
    # ones -- the smuggled JSON body was never even parsed into anything
    # the execute handler reads (no body model on that route): the real
    # issue landed in the ORIGINALLY authorized repo, not "some-other-repo"
    # or "evil-repo".
    assert issue["repo"] == ctx.repo


# --------------------------------------------------------------------------- #
# Reconciliation must remain absent (Section "NO RECONCILIATION EXPANSION")
# --------------------------------------------------------------------------- #

def test_no_reconcile_route_on_universal_proof_app(mock_github):
    ctx = _github_stack(mock_github)
    paths = [r.path for r in ctx.proof.app.routes]
    assert not any("reconcile" in p for p in paths), paths
    schema = ctx.proof.app.openapi()
    assert not any("reconcile" in p for p in schema.get("paths", {})), schema["paths"]


# --------------------------------------------------------------------------- #
# Actuator-replaceability non-vacuity: the SAME generic path, through a
# non-GitHub actuator, with zero MCC-Core/authority/token/Gate/service changes.
# --------------------------------------------------------------------------- #

def test_actuator_replaceability_non_vacuity_generic_ledger():
    ledger_ctx = _ledger_stack()
    _submit(ledger_ctx.client, key="key-a", op_id="op-ledger-1", resource=ledger_ctx.resource)
    r = _execute(ledger_ctx.client, key="key-a", op_id="op-ledger-1")
    assert r.status_code == 200
    assert r.json()["status"] == "EXECUTED"
    assert len(ledger_ctx.upstream.entries) == 1

    # Structural proof: the SAME ProposalExecutionService class drives
    # both the GitHub-backed and the ledger-backed stack -- not a second
    # execution-engine implementation.
    assert type(ledger_ctx.proof.exec_stack.service) is ProposalExecutionService

    # Replay/DENY/RESOURCE_MISMATCH all hold identically through the
    # non-GitHub actuator too (spot-check replay, since that is the
    # invariant most likely to be actuator-specific if something were
    # wrong).
    r2 = _execute(ledger_ctx.client, key="key-a", op_id="op-ledger-1")
    assert r2.json()["status"] != "EXECUTED"
    assert len(ledger_ctx.upstream.entries) == 1


def test_actuator_replaceability_resource_mismatch_holds_for_ledger_too():
    ledger_ctx = _ledger_stack(resource="generic-resource-FIXED")
    _submit(ledger_ctx.client, key="key-a", op_id="op-ledger-2", resource="generic-resource-DIFFERENT")
    r = _execute(ledger_ctx.client, key="key-a", op_id="op-ledger-2")
    assert r.json()["status"] == "RESOURCE_MISMATCH"
    assert ledger_ctx.upstream.entries == []


# --------------------------------------------------------------------------- #
# Upstream-replaceability non-vacuity: two differently-labelled proposal
# producers use the IDENTICAL generic path with IDENTICAL Core behavior.
# No Core behavior may depend on which producer generated the proposal.
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("producer_label", [
    "openai-style-agent/v1",
    "anthropic-style-agent/v1",
    "meta-style-autonomous-agent/v1",
    "human-operated-client/v1",
    "enterprise-deterministic-app/v1",
])
def test_upstream_replaceability_non_vacuity_identical_behavior(mock_github, producer_label):
    ctx = _github_stack(mock_github)
    op_id = f"op-producer-{uuid.uuid4().hex[:8]}"
    _submit(ctx.client, key="key-a", op_id=op_id, resource=ctx.repo, actor=producer_label)
    r = _execute(ctx.client, key="key-a", op_id=op_id)
    assert r.status_code == 200
    assert r.json()["status"] == "EXECUTED"
    assert r.json()["decision"] == "ALLOW"


def test_upstream_replaceability_structural_proof_actor_never_drives_authority():
    """Structural, not just behavioral: the authority evaluation call
    site inside the existing, UNMODIFIED ProposalExecutionService never
    reads record.actor -- identity is exclusively the authenticated
    tenant_id (Section "NO PROVIDER PRIVILEGE": the proposal is evaluated
    because of its bound authority context, never because of who
    produced it)."""
    import inspect

    source = inspect.getsource(ProposalExecutionService.authorize_and_execute)
    assert "record.actor" not in source
    assert ".actor" not in source
    assert "identity=tenant_id" in source


# --------------------------------------------------------------------------- #
# Framework/provider-neutrality spot check: the assembled app never
# imports or references a specific model/provider/framework name.
# --------------------------------------------------------------------------- #

def test_no_provider_or_framework_names_in_universal_proof_package():
    import examples.universal_execution_proof.stack as mod

    source = Path(mod.__file__).read_text(encoding="utf-8")
    forbidden = (
        "openai", "OpenAI", "anthropic.Client", "langgraph", "crewai", "autogen",
        "voltagent", "boto3", "azure.", "google.generativeai", "Sora",
    )
    for token in forbidden:
        assert token not in source, f"{token!r} found in stack.py"
