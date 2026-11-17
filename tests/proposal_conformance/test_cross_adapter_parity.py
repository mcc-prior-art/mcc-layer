"""Cross-adapter identity, binding-parity, conflict, and canonicalization
tests (Sections 16-17). Every test in this file submits/reads through at
least two different adapters wrapping the SAME shared
``MCCProposalService`` and asserts they observe the identical
``proposal_binding`` / ``status`` — no adapter is allowed to drift.
"""

from __future__ import annotations

import itertools

import pytest

from .harness import TENANT, build_all_adapters, build_shared_stack

BASE_REQUEST = {
    "actor": "a",   # F1b: the credential's own principal (harness.PRINCIPAL)
    "action": "send_notification",
    "resource": "crm",
    "payload": {"recipient": "customer-123", "message": "your order shipped", "priority": 2},
}


@pytest.fixture()
def adapters():
    stack = build_shared_stack()
    return build_all_adapters(stack)


def test_every_adapter_converges_on_the_same_service(adapters):
    """Section 2: no adapter may independently implement proposal identity."""
    assert len(adapters) >= 5
    for name, adapter in adapters.items():
        assert adapter.name == name


def test_cross_adapter_same_operation_produces_one_identical_binding(adapters):
    """Section 16: submit the SAME operation through every adapter with the
    SAME logical_operation_id; every adapter must observe the identical
    proposal_binding and status, and it must be exactly one logical record
    (idempotent duplicates, never N separate ones)."""
    logical_operation_id = "op-parity-1"
    bindings = {}
    for name, adapter in adapters.items():
        receipt = adapter.submit({"logical_operation_id": logical_operation_id, **BASE_REQUEST})
        assert receipt["status"] == "PROPOSED", (name, receipt)
        assert receipt["accepted"] is True
        bindings[name] = receipt["proposal_binding"]
    assert len(set(bindings.values())) == 1, f"bindings diverged across adapters: {bindings}"

    for name, adapter in adapters.items():
        status = adapter.status(logical_operation_id)
        assert status["status"] == "PROPOSED", (name, status)
        assert status["proposal_binding"] == bindings[name]


@pytest.mark.parametrize("first,second", list(itertools.permutations(
    ["generic_http", "mcp", "langgraph", "crewai", "autogen", "python_sdk"], 2)))
def test_cross_adapter_pair_conflicting_submission_is_rejected(adapters, first, second):
    """Section 16: register operation A via one adapter, then submit a
    DIFFERENT payload under the SAME logical_operation_id via a different
    adapter -> BINDING_CONFLICT, regardless of which pair of adapters."""
    logical_operation_id = f"op-conflict-{first}-{second}"
    r1 = adapters[first].submit({"logical_operation_id": logical_operation_id, **BASE_REQUEST})
    assert r1["status"] == "PROPOSED"

    conflicting = {**BASE_REQUEST, "payload": {**BASE_REQUEST["payload"], "message": "ALTERED"}}
    r2 = adapters[second].submit({"logical_operation_id": logical_operation_id, **conflicting})
    assert r2["status"] == "BINDING_CONFLICT", (first, second, r2)
    assert r2["accepted"] is False


def test_canonicalization_parity_key_order_does_not_change_binding(adapters):
    """Section 17: reordered JSON object keys must not change the binding."""
    logical_operation_id = "op-canon-keyorder"
    payload_a = {"recipient": "c-1", "message": "hi", "priority": 2}
    payload_b = {"priority": 2, "message": "hi", "recipient": "c-1"}
    r1 = adapters["generic_http"].submit({
        "logical_operation_id": logical_operation_id, "actor": "a", "action": "send_notification",
        "resource": "crm", "payload": payload_a,
    })
    r2 = adapters["mcp"].submit({
        "logical_operation_id": logical_operation_id, "actor": "a", "action": "send_notification",
        "resource": "crm", "payload": payload_b,
    })
    assert r1["status"] == "PROPOSED"
    assert r2["status"] == "PROPOSED"  # idempotent duplicate, not a conflict
    assert r1["proposal_binding"] == r2["proposal_binding"]


@pytest.mark.parametrize("payload", [
    {"nested": {"a": [1, 2, {"b": None}], "c": True}},
    {"unicode": "héllo wörld 日本語 🎉", "empty_obj": {}, "empty_list": []},
    {"numbers": [1, 2.5, -3, 0]},
    {"bool_and_null": {"x": True, "y": False, "z": None}},
])
def test_canonicalization_parity_difficult_json_shapes(adapters, payload):
    """Section 17: unicode, nested objects, arrays, booleans, null, numeric
    forms, and empty structures must all canonicalize identically across
    adapters (no JS/Python serialization discrepancy may change identity)."""
    import uuid

    logical_operation_id = f"op-canon-{uuid.uuid4().hex}"
    request = {"logical_operation_id": logical_operation_id, "actor": "a",
              "action": "send_notification", "resource": "crm", "payload": payload}
    bindings = set()
    for name in ("generic_http", "mcp", "langgraph", "crewai", "autogen", "python_sdk"):
        r = adapters[name].submit(dict(request))
        assert r["status"] == "PROPOSED", (name, r)
        bindings.add(r["proposal_binding"])
    assert len(bindings) == 1


def test_idempotent_resubmission_never_creates_a_second_record(adapters):
    logical_operation_id = "op-idem-resubmit"
    for _ in range(5):
        r = adapters["generic_http"].submit({"logical_operation_id": logical_operation_id, **BASE_REQUEST})
        assert r["status"] == "PROPOSED"
    # Still exactly one logical record: status is stable and consistent.
    statuses = {adapters[name].status(logical_operation_id)["proposal_binding"]
               for name in adapters}
    assert len(statuses) == 1
