"""HTTP transport tests for the Universal Proposal Service Phase 1
(Section 11): tenant auth, strict schema, remote-ingress bounds, and the
REAL ``gateway/app.py`` wiring end-to-end (proving the actual mounted routes
behave, not just a standalone router)."""

from __future__ import annotations

import json
import os
import tempfile

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.proposal_api import (
    ProposalTenantConfigError,
    mount_proposal_routes,
    tenants_from_env,
)
from mcc_proposal import InMemoryProposalRegistry, MCCProposalService


# -- tenants_from_env --------------------------------------------------------- #

def test_tenants_from_env_unset_is_empty_fail_closed_default():
    assert tenants_from_env({}) == {}


def test_tenants_from_env_parses_valid_json():
    t = tenants_from_env({"MCC_PROPOSAL_TENANTS": json.dumps({"k1": "tenant-a"})})
    assert t == {"k1": "tenant-a"}


def test_tenants_from_env_malformed_json_raises():
    with pytest.raises(ProposalTenantConfigError):
        tenants_from_env({"MCC_PROPOSAL_TENANTS": "not json"})


def test_tenants_from_env_non_string_values_rejected():
    with pytest.raises(ProposalTenantConfigError):
        tenants_from_env({"MCC_PROPOSAL_TENANTS": json.dumps({"k1": 123})})


# -- standalone router (fast, isolated) --------------------------------------- #

def _build_app(tenants):
    app = FastAPI()
    service = MCCProposalService(proposals=InMemoryProposalRegistry())
    mount_proposal_routes(app, service, tenants=tenants)
    return app, service


def test_no_api_key_is_401():
    # Missing credential is an authentication failure -- exactly 401, never
    # 422 (get_tenant_dependency declares x_api_key Optional/default=None
    # precisely so an absent header is handled by the auth check itself,
    # not by FastAPI's own request-validation layer).
    app, _ = _build_app({"k": "t"})
    client = TestClient(app)
    r = client.post("/v1/proposals", json={"logical_operation_id": "x", "actor": "a", "action": "b"})
    assert r.status_code == 401


def test_blank_api_key_is_401():
    app, _ = _build_app({"k": "t"})
    client = TestClient(app)
    r = client.post("/v1/proposals", headers={"x-api-key": ""},
                    json={"logical_operation_id": "x", "actor": "a", "action": "b"})
    assert r.status_code == 401


def test_wrong_api_key_is_401():
    app, _ = _build_app({"k": "t"})
    client = TestClient(app)
    r = client.post("/v1/proposals", headers={"x-api-key": "wrong"},
                    json={"logical_operation_id": "x", "actor": "a", "action": "b"})
    assert r.status_code == 401


def test_unknown_field_is_422():
    app, _ = _build_app({"k": "t"})
    client = TestClient(app)
    r = client.post("/v1/proposals", headers={"x-api-key": "k"},
                    json={"logical_operation_id": "x", "actor": "a", "action": "b", "mandate": {}})
    assert r.status_code == 422


def test_missing_logical_operation_id_is_422():
    app, _ = _build_app({"k": "t"})
    client = TestClient(app)
    r = client.post("/v1/proposals", headers={"x-api-key": "k"}, json={"actor": "a", "action": "b"})
    assert r.status_code == 422


def test_happy_path_submit_and_status():
    app, _ = _build_app({"k": "t"})
    client = TestClient(app)
    body = {"logical_operation_id": "op-http-happy", "actor": "a", "action": "send_notification",
           "resource": "crm", "payload": {"recipient": "c"}}
    r = client.post("/v1/proposals", headers={"x-api-key": "k"}, json=body)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "PROPOSED"
    assert data["accepted"] is True

    r2 = client.get("/v1/operations/op-http-happy", headers={"x-api-key": "k"})
    assert r2.status_code == 200
    assert r2.json()["status"] == "PROPOSED"
    assert r2.json()["proposal_binding"] == data["proposal_binding"]


def test_status_for_unknown_operation_is_200_not_found_body():
    app, _ = _build_app({"k": "t"})
    client = TestClient(app)
    r = client.get("/v1/operations/never-submitted", headers={"x-api-key": "k"})
    assert r.status_code == 200
    assert r.json()["status"] == "NOT_FOUND"


def test_oversized_request_body_is_413():
    app, _ = _build_app({"k": "t"})
    client = TestClient(app)
    from mcc_proposal.models import MAX_PAYLOAD_BYTES

    huge_payload = {"blob": "x" * (MAX_PAYLOAD_BYTES + 100_000)}
    body = {"logical_operation_id": "op-huge", "actor": "a", "action": "b", "payload": huge_payload}
    body_bytes = json.dumps(body).encode()
    r = client.post(
        "/v1/proposals",
        headers={"x-api-key": "k", "content-length": str(len(body_bytes)), "content-type": "application/json"},
        content=body_bytes,
    )
    assert r.status_code == 413


# -- the REAL gateway/app.py wiring, end-to-end -------------------------------- #

@pytest.fixture()
def real_gateway_app(monkeypatch):
    """Import the real gateway.app module (the literal production app) with
    an isolated audit log and a configured tenant map, proving the actual
    mounted /v1/proposals + /v1/operations/{id} routes work end-to-end --
    not just a standalone router built for this test file."""
    monkeypatch.setenv("MCC_USE_OPA", "false")
    monkeypatch.setenv(
        "MCC_GATEWAY_AUDIT_LOG_PATH",
        os.path.join(tempfile.mkdtemp(prefix="mcc-proposal-http-test-"), "audit.jsonl"),
    )
    monkeypatch.setenv("MCC_PROPOSAL_TENANTS", json.dumps({"tenant-a-key": "tenant-a", "tenant-b-key": "tenant-b"}))
    import importlib
    import sys

    sys.modules.pop("gateway.app", None)
    module = importlib.import_module("gateway.app")
    return module


def test_real_gateway_app_proposal_endpoints_end_to_end(real_gateway_app):
    client = TestClient(real_gateway_app.app)
    body = {"logical_operation_id": "op-real-gw-1", "actor": "agent/notify-bot",
           "action": "send_notification", "resource": "crm", "payload": {"recipient": "c-1"}}
    r = client.post("/v1/proposals", headers={"x-api-key": "tenant-a-key"}, json=body)
    assert r.status_code == 200
    assert r.json()["status"] == "PROPOSED"

    r2 = client.get("/v1/operations/op-real-gw-1", headers={"x-api-key": "tenant-b-key"})
    assert r2.json()["status"] == "NOT_FOUND"  # cross-tenant isolation on the REAL app

    # /evaluate semantics are completely untouched by this addition.
    r3 = client.get("/health")
    assert r3.status_code == 200


def test_real_gateway_app_proposal_endpoints_never_call_the_upstream_executor(real_gateway_app, monkeypatch):
    """Zero-actuator proof (Section 9/AA/AB) against the REAL wired app: the
    coordinator's own upstream executor is poisoned; proposal submission and
    status lookup must never trigger it."""

    async def _boom(action, payload):
        raise AssertionError("proposal endpoints must never call the upstream executor")

    monkeypatch.setattr(real_gateway_app.governance, "upstream", _boom)
    client = TestClient(real_gateway_app.app)
    body = {"logical_operation_id": "op-real-gw-noexec", "actor": "agent/notify-bot",
           "action": "send_notification", "resource": "crm", "payload": {"recipient": "c-1"}}
    r = client.post("/v1/proposals", headers={"x-api-key": "tenant-a-key"}, json=body)
    assert r.status_code == 200
    assert r.json()["status"] == "PROPOSED"
    r2 = client.get("/v1/operations/op-real-gw-noexec", headers={"x-api-key": "tenant-a-key"})
    assert r2.json()["status"] == "PROPOSED"


def test_real_gateway_app_status_reflects_the_real_coordinators_durable_state(real_gateway_app):
    """The proposal service was wired with ``governance.coordinator.idempotency``
    -- the SAME object the real EnforcementCoordinator uses -- so a state
    change made directly against it (simulating real execution admission)
    must be visible through GET /v1/operations/{id}. The reservation is made
    under the SAME binding the posted proposal computed (tenant-isolation
    remediation: the durable record's binding must match the tenant's own
    registered binding before it is disclosed -- see
    tests/test_proposal_service_tenant_status_isolation.py)."""
    import asyncio

    from mcc_proposal.binding import compute_proposal_binding

    client = TestClient(real_gateway_app.app)
    body = {"logical_operation_id": "op-real-gw-durable", "actor": "agent/notify-bot",
           "action": "send_notification", "resource": "crm", "payload": {"recipient": "c-1"}}
    client.post("/v1/proposals", headers={"x-api-key": "tenant-a-key"}, json=body)

    idem = real_gateway_app.governance.coordinator.idempotency
    binding = compute_proposal_binding(
        action=body["action"], resource=body["resource"], payload=body["payload"],
        profiles=real_gateway_app.gateway.profiles,
    )
    asyncio.run(idem.reserve("op-real-gw-durable", binding=binding, tenant_id="tenant-a"))

    r = client.get("/v1/operations/op-real-gw-durable", headers={"x-api-key": "tenant-a-key"})
    assert r.json()["status"] == "RESERVED"
