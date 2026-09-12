"""External Pilot Integration Pack -- server composition tests (PR #113).

``examples.external_pilot.server`` mirrors
``examples.pilot_execution_api.app``'s (PR #111) fail-closed deployable/
demo split exactly: required configuration missing (``None``) refuses
construction; an explicit ``{}`` is honored as-is, never silently
replaced by a more permissive default.
"""

from __future__ import annotations

import pytest

from examples.external_pilot.actuator.demo_actuator import build_demo_actuator
from examples.external_pilot.server import (
    ExternalPilotConfigError,
    authority_from_env,
    build_app_from_env,
    build_demo_app,
    build_external_pilot_app,
)
from mcc_core import InMemoryIdempotencyRegistry, InMemoryNonceRegistry
from mcc_proposal import InMemoryProposalRegistry


def _memory_kwargs(**overrides):
    upstream, _ledger = build_demo_actuator()
    kwargs = dict(
        proposals=InMemoryProposalRegistry(), idempotency=InMemoryIdempotencyRegistry(),
        nonces=InMemoryNonceRegistry(), tenants_credentials={"k": "t"}, tenants_authority={"t": {}},
        upstream=upstream, audit_log_path="/tmp/mcc-external-pilot-server-test-audit.jsonl",
    )
    kwargs.update(overrides)
    return kwargs


def test_build_demo_app_succeeds_with_zero_configuration():
    app = build_demo_app()
    assert app.title == "MCC External Pilot Integration Pack"
    route_paths = {getattr(r, "path", None) for r in app.router.routes}
    assert "/v1/proposals" in route_paths
    assert "/v1/operations/{logical_operation_id}/execute" in route_paths
    assert "/v1/operations/{logical_operation_id}" in route_paths


@pytest.mark.parametrize("missing", ["tenants_credentials", "tenants_authority", "upstream"])
def test_build_external_pilot_app_fails_closed_on_missing_required_config(missing):
    kwargs = _memory_kwargs()
    kwargs[missing] = None
    with pytest.raises(ExternalPilotConfigError):
        build_external_pilot_app(**kwargs)


def test_build_external_pilot_app_honors_explicit_empty_dicts():
    """An explicit {} (zero clients / zero authority) is NOT the same as
    None -- it must be accepted and used exactly as given, never silently
    replaced by a demo default (PR #111 remediation Blocker 1, reused
    contract)."""
    app = build_external_pilot_app(**_memory_kwargs(tenants_credentials={}, tenants_authority={}))
    assert app is not None


def test_authority_from_env_empty_is_zero_authority():
    assert authority_from_env({}) == {}


def test_authority_from_env_malformed_json_fails_closed():
    with pytest.raises(ExternalPilotConfigError):
        authority_from_env({"MCC_EXTERNAL_PILOT_AUTHORITY": "not json"})


def test_authority_from_env_wrong_shape_fails_closed():
    with pytest.raises(ExternalPilotConfigError):
        authority_from_env({"MCC_EXTERNAL_PILOT_AUTHORITY": '{"tenant-a": "not-a-dict"}'})


def test_authority_from_env_valid():
    result = authority_from_env({"MCC_EXTERNAL_PILOT_AUTHORITY": '{"tenant-a": {"max_amount": 100}}'})
    assert result == {"tenant-a": {"max_amount": 100}}


def test_build_app_from_env_fails_closed_without_upstream():
    with pytest.raises(ExternalPilotConfigError):
        build_app_from_env(upstream=None)


def test_build_app_from_env_memory_backend_succeeds():
    upstream, _ledger = build_demo_actuator()
    env = {"MCC_PROPOSAL_TENANTS": '{"k":"t"}', "MCC_EXTERNAL_PILOT_AUTHORITY": '{"t":{}}'}
    app = build_app_from_env(upstream=upstream, env=env)
    assert app is not None


def test_build_app_from_env_redis_backend_requires_redis_url():
    upstream, _ledger = build_demo_actuator()
    env = {"MCC_PROPOSAL_TENANTS": '{"k":"t"}', "MCC_EXTERNAL_PILOT_AUTHORITY": '{"t":{}}',
           "MCC_EXTERNAL_PILOT_BACKEND": "redis"}
    with pytest.raises(ExternalPilotConfigError):
        build_app_from_env(upstream=upstream, env=env)


def test_build_app_from_env_rejects_unknown_backend():
    upstream, _ledger = build_demo_actuator()
    env = {"MCC_EXTERNAL_PILOT_BACKEND": "not-a-real-backend"}
    with pytest.raises(ExternalPilotConfigError):
        build_app_from_env(upstream=upstream, env=env)
