"""Tests for the runnable Pilot Execution API reference composition
(``examples/pilot_execution_api/app.py``).

Two things are proven:

1. The documented shared-instance wiring (docs/PILOT_EXECUTION_API.md
   §11) actually works end-to-end: a proposal submitted via the Phase 1
   routes is visible to, and executable through, the Phase 2 execute
   route on the SAME app.
2. (PR #111 remediation, Blocker 1) ``build_app`` (the DEPLOYABLE
   composition) never substitutes a demo credential/authority default for
   missing OR explicitly-empty configuration, fails closed on genuinely
   missing (``None``) configuration, and cannot be made to combine a real
   actuator with demo security defaults -- while ``build_demo_app`` (the
   DEMO-ONLY composition) still works standalone.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import pytest
from fastapi.testclient import TestClient

from examples.pilot_execution_api.app import (
    PilotExecutionAPIConfigError,
    build_app,
    build_demo_app,
    echo_upstream,
)
from gateway.proposal_execution_service import ResourceBoundUpstream


def _upstream(resource: Optional[str] = None) -> ResourceBoundUpstream:
    return ResourceBoundUpstream(resource=resource, dispatch=echo_upstream)


# --------------------------------------------------------------------------- #
# Shared-instance wiring, end to end (unchanged from before remediation,
# updated for the now-required ``upstream`` argument).
# --------------------------------------------------------------------------- #

def test_example_app_shared_instance_wiring_end_to_end():
    app = build_app(
        tenants_credentials={"k": "demo-tenant"}, tenants_authority={"demo-tenant": {}},
        upstream=_upstream(),
    )
    client = TestClient(app)

    r = client.post("/v1/proposals", headers={"x-api-key": "k"}, json={
        "logical_operation_id": "example-op", "actor": "agent/demo", "action": "send_notification",
        "resource": None, "payload": {"msg": "hi"},
    })
    assert r.status_code == 200
    assert r.json()["status"] == "PROPOSED"

    r2 = client.post("/v1/operations/example-op/execute", headers={"x-api-key": "k"})
    assert r2.status_code == 200
    assert r2.json()["status"] == "EXECUTED"

    r3 = client.get("/v1/operations/example-op", headers={"x-api-key": "k"})
    assert r3.json()["status"] == "EXECUTED"

    assert client.get("/health").status_code == 200


# --------------------------------------------------------------------------- #
# Blocker 1 mandatory tests A-G
# --------------------------------------------------------------------------- #

def test_a_explicit_empty_credentials_does_not_create_demo_key():
    app = build_app(tenants_credentials={}, tenants_authority={}, upstream=_upstream())
    client = TestClient(app)
    # The demo credential must not exist: neither an unrelated key nor the
    # literal "demo-key" authenticates against an explicitly empty map.
    for key in ("demo-key", "anything", ""):
        r = client.post("/v1/proposals", headers={"x-api-key": key} if key else {}, json={
            "logical_operation_id": "op", "actor": "a", "action": "send_notification",
            "resource": None, "payload": {},
        })
        assert r.status_code == 401, f"key {key!r} unexpectedly authenticated against an empty credential map"


def test_b_explicit_empty_authority_does_not_auto_grant():
    # A tenant WITH a real credential, but the authority map is explicitly
    # empty -- must be denied, never auto-granted.
    app = build_app(
        tenants_credentials={"k": "tenant-x"}, tenants_authority={}, upstream=_upstream(),
    )
    client = TestClient(app)
    r = client.post("/v1/proposals", headers={"x-api-key": "k"}, json={
        "logical_operation_id": "op-b", "actor": "a", "action": "send_notification",
        "resource": None, "payload": {},
    })
    assert r.status_code == 200
    r2 = client.post("/v1/operations/op-b/execute", headers={"x-api-key": "k"})
    assert r2.status_code == 200
    assert r2.json()["status"] == "DENIED", "an explicitly empty authority map must not auto-grant execution authority"


def test_c_missing_credentials_fails_closed():
    with pytest.raises(PilotExecutionAPIConfigError):
        build_app(tenants_credentials=None, tenants_authority={}, upstream=_upstream())


def test_d_missing_authority_fails_closed():
    with pytest.raises(PilotExecutionAPIConfigError):
        build_app(tenants_credentials={}, tenants_authority=None, upstream=_upstream())


def test_missing_upstream_fails_closed():
    with pytest.raises(PilotExecutionAPIConfigError):
        build_app(tenants_credentials={}, tenants_authority={}, upstream=None)


def test_e_real_custom_upstream_cannot_silently_receive_demo_defaults():
    """Supplying a real/custom upstream while omitting credentials/authority
    must fail closed -- it must NEVER silently receive the demo
    credential/authority instead. ``build_app`` has no demo literals to
    fall back to in the first place, so this is structurally guaranteed,
    not merely behaviorally observed."""
    real_calls = []

    async def real_dispatch(*, resource, action, payload):
        real_calls.append((resource, action, payload))
        return {"real": True}

    real_upstream = ResourceBoundUpstream(resource="prod-resource", dispatch=real_dispatch)

    with pytest.raises(PilotExecutionAPIConfigError):
        build_app(tenants_credentials=None, tenants_authority=None, upstream=real_upstream)

    # Even when ONE of the two config maps is real but the other is
    # missing, construction must still fail closed rather than filling
    # the gap with a demo default.
    with pytest.raises(PilotExecutionAPIConfigError):
        build_app(tenants_credentials={"k": "tenant-x"}, tenants_authority=None, upstream=real_upstream)

    assert real_calls == [], "the real upstream must never be reachable through a demo-default fallback path"


def test_f_build_demo_app_still_works_with_echo_actuator():
    app = build_demo_app()
    client = TestClient(app)
    r = client.post("/v1/proposals", headers={"x-api-key": "demo-key"}, json={
        "logical_operation_id": "example-op-2", "actor": "agent/demo", "action": "send_notification",
        "resource": None, "payload": {},
    })
    assert r.status_code == 200
    r2 = client.post("/v1/operations/example-op-2/execute", headers={"x-api-key": "demo-key"})
    assert r2.status_code == 200
    assert r2.json()["status"] == "EXECUTED"


def test_build_demo_app_has_no_upstream_parameter():
    """Structural proof for E/F together: build_demo_app cannot be handed
    a real upstream at all -- there is no parameter for one."""
    import inspect

    sig = inspect.signature(build_demo_app)
    assert "upstream" not in sig.parameters


def test_g_non_vacuity_planted_truthiness_fallback_is_caught():
    """Reproduce the ORIGINAL defect with a throwaway local function
    (never modifying the shipped code): a truthiness-based fallback that
    treats an explicit {} exactly like None and substitutes a demo
    default. Show it wrongly grants demo-key access to an intentionally
    locked-down deployment, then show the real, remediated build_app
    refuses the identical scenario (test A already proves this; this
    probe demonstrates WHY that proof matters by first showing the
    vulnerable shape actually misbehaves)."""

    def vulnerable_resolve_credentials(tenants_credentials: Optional[Dict[str, str]]) -> Dict[str, str]:
        # The exact defect: `or` cannot distinguish {} from None.
        return tenants_credentials or {"demo-key": "demo-tenant"}

    # An operator explicitly configures ZERO clients...
    resolved = vulnerable_resolve_credentials({})
    # ...but the vulnerable logic wrongly hands back a working demo credential.
    assert resolved == {"demo-key": "demo-tenant"}, "sanity check: the planted defect is genuinely vulnerable"

    # The real, remediated build_app does not do this (test A proves the
    # end-to-end behavior); here we additionally prove the fixed function
    # contains no such fallback expression at the source level.
    import inspect

    source = inspect.getsource(build_app)
    assert "tenants_credentials or" not in source
    assert "tenants_authority or" not in source
    assert "upstream or" not in source
    assert "demo-key" not in source
    assert "demo-tenant" not in source
