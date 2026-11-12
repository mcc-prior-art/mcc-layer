"""R3 follow-up: oversized integers must be a controlled rejection, never an
unhandled exception.

Reproduced on PR #132 @ b4b913b: ``math.isfinite()`` converts an ``int`` to a
double and raises ``OverflowError`` for one beyond the double range. JSON
parsing yields exactly such an int from a big integer literal (``1e400`` is
a float -> inf, but ``1000...0`` with 401 digits is an ``int``), so
``constraint_errors({"max_amount": 10**400})`` and
``constraint_errors({"allowed_amount": [10**400]})`` raised instead of
reporting a problem. Baseline consequences (all with ZERO actuator calls --
the defect was never an authorization, but it was not a controlled outcome):

* ``POST /approvals`` with such a constraint -> HTTP 500 (no record created);
* ``/mandates/execute`` and ``/mandates/verify`` with a signed mandate
  carrying one -> generic ``MANDATE_ERROR: fail-closed`` (an exception caught
  by the verifier's catch-all), not ``MALFORMED_MANDATE_CONSTRAINTS``;
* ``MandateRegistry`` load and ``AuthorityModel.evaluate`` -> OverflowError;
* an oversized payment ``amount`` (under a VALID mandate) -> HTTP 500 from
  ``float()`` in ``PaymentProfile`` on /mandates/execute; likewise robotics
  ``force`` / infrastructure ``replicas``; the delegation service raised
  OverflowError for a signed oversized ``max_amount``.

Contract after the fix: an int that cannot be represented as a double is an
UNSUPPORTED number -- reported as not finite by the shared predicate
(``mcc_core.authority._finite_number`` / ``_json_scalar``). It is never
authorized, never clamped into compliance and never silently dropped; every
route answers with its normal controlled rejection. Representable values --
including huge-but-representable ints such as ``10**300`` and
``int(sys.float_info.max)`` -- keep their existing semantics.
"""
from __future__ import annotations

import json
import gc
import sys

import pytest
from fastapi.testclient import TestClient

from mcc_core.authority import (
    ActionPolicy,
    AuthorityModel,
    ConstraintError,
    Mandate,
    MandateRegistry,
    Verdict,
    _constraint_violations,
    apply_constraints,
    constraint_errors,
    validate_constraints,
)

from tests.test_r2_numeric_constraint_http import (  # noqa: F401  (fixtures)
    ACTOR,
    AGENT,
    OP,
    POLICY,
    RESOURCE,
    DelegationStack,
    GovGateway,
    _egress_run,
    _gov_decide,
    egress,
    gateway_app,
    gov_main,
    main_app,
    opa_main,
    payment,
)

BIG = 10 ** 400                      # beyond the double range (~1.8e308)
EDGE_OVER = 2 ** 1024                # the smallest power of two that overflows a double
EDGE_MAX = int(sys.float_info.max)   # the largest representable value: still valid

OVERSIZED = [
    ("max-pos", {"max_amount": BIG}),
    ("max-neg", {"max_amount": -BIG}),
    ("min-pos", {"min_amount": BIG}),
    ("min-neg", {"min_amount": -BIG}),
    ("allowed-pos", {"allowed_amount": [BIG]}),
    ("allowed-neg", {"allowed_amount": [-BIG]}),
    ("max-edge-2**1024", {"max_amount": EDGE_OVER}),
    ("allowed-mixed", {"allowed_amount": [100, BIG]}),
    ("valid-max-plus-oversized-min", {"max_amount": 5000, "min_amount": -BIG}),
]
OVERSIZED_IDS = [i for i, _ in OVERSIZED]
OVERSIZED_SETS = [c for _, c in OVERSIZED]
SIGNED = [BIG, -BIG]
SIGNED_IDS = ["pos", "neg"]


@pytest.fixture(autouse=True, scope="module")
def _release_this_modules_garbage():
    """Same test hygiene as tests/test_r3_constraint_validation_http.py: this
    module builds many full governance stacks; collect their cyclic garbage at
    this module's own teardown instead of in whichever module runs next."""
    yield
    gc.collect()


def _raw(client):
    """Same app, but an unhandled exception surfaces as HTTP 500 (what a real
    server returns) instead of being re-raised inside the test."""
    return TestClient(client.app, raise_server_exceptions=False)


def _post(client, url, headers, body):
    # json.dumps writes a Python int as a JSON integer literal of any length;
    # the server's json.loads turns it back into exactly that int.
    return client.post(url, headers={**headers, "content-type": "application/json"},
                       content=json.dumps(body))


@pytest.fixture
def gw():
    g = GovGateway()
    g.client = _raw(g.client)
    return g


# ===========================================================================
# The validator itself: total, never raises
# ===========================================================================

@pytest.mark.parametrize("constraints", OVERSIZED_SETS, ids=OVERSIZED_IDS)
def test_constraint_errors_reports_oversized_numbers_without_raising(constraints):
    errors = constraint_errors(constraints)
    assert errors, constraints
    assert any("supported numeric range" in e for e in errors), errors
    with pytest.raises(ConstraintError):
        validate_constraints(constraints)


def test_validator_messages_stay_bounded_beyond_the_int_to_str_digit_limit():
    """An int with more digits than Python's int->str limit (default 4300)
    cannot even be repr()'d -- the message must not try."""
    huge = 10 ** 5000
    for c in ({"max_amount": huge}, {"min_amount": -huge}, {"allowed_amount": [huge]}):
        errors = constraint_errors(c)
        assert errors and all(len(e) < 400 for e in errors), errors
    v = _constraint_violations({"max_amount": 5000}, {"amount": huge})
    assert v and all(len(x) < 400 for x in v), v


@pytest.mark.parametrize("value", SIGNED, ids=SIGNED_IDS)
def test_oversized_context_value_is_a_violation_never_clamped(value):
    for constraints in ({"max_amount": 5000}, {"min_amount": 1}, {"max_amount": 5000, "min_amount": -5000}):
        assert _constraint_violations(constraints, {"amount": value}), constraints
        new_context, changes = apply_constraints(constraints, {"amount": value})
        assert new_context == {"amount": value} and changes == []      # not clamped into compliance
    assert _constraint_violations({"allowed_amount": [100]}, {"amount": value})


@pytest.mark.parametrize("constraints", OVERSIZED_SETS, ids=OVERSIZED_IDS)
def test_mandate_registry_refuses_oversized_bounds(constraints):
    with pytest.raises(ConstraintError):
        MandateRegistry([Mandate(holder="agent/x", authority="pay", constraints=constraints)])


@pytest.mark.parametrize("constraints", OVERSIZED_SETS, ids=OVERSIZED_IDS)
def test_authority_model_denies_oversized_bounds_even_when_policy_escalates(constraints):
    m = Mandate(holder="agent/x", authority="pay", constraints={"max_amount": 5000})
    model = AuthorityModel(registry=MandateRegistry([m]), policies=[
        ActionPolicy(action="pay", requires="pay", on_violation=Verdict.ESCALATE)])
    m.constraints.clear()
    m.constraints.update(constraints)                # became invalid after load
    d = model.evaluate(identity="agent/x", action="pay", context={"amount": 1})
    assert d.verdict == Verdict.DENY and "INVALID_CONSTRAINTS" in d.reason, d


# ===========================================================================
# POST /approvals -- controlled 422, no record created
# ===========================================================================

@pytest.mark.parametrize("constraints", OVERSIZED_SETS, ids=OVERSIZED_IDS)
def test_approval_request_with_oversized_constraint_is_422_and_creates_no_record(gw, constraints):
    r = _post(gw.client, "/approvals", AGENT, {
        "actor": ACTOR, "action": "send_payment", "resource": RESOURCE, "transaction_id": "tx-1",
        "policy_hash": POLICY, "payload": payment(999_999.0), "constraints": constraints})
    assert r.status_code == 422, (r.status_code, r.text)
    assert "INVALID_CONSTRAINTS" in r.text and "supported numeric range" in r.text
    assert gw.approvals.registry._records == {}
    assert gw.calls == []


@pytest.mark.parametrize("constraints", [{"max_amount": 10 ** 300}, {"max_amount": EDGE_MAX},
                                         {"min_amount": -(10 ** 300), "max_amount": 5000},
                                         {"allowed_amount": [10 ** 300, 100.0]}],
                         ids=["max-1e300", "max-edge", "min-neg-1e300", "allowed-1e300"])
def test_approval_with_huge_but_representable_bound_executes_exactly_once(gw, constraints):
    """Valid control: a representable bound is still a valid constraint."""
    r = _post(gw.client, "/approvals", AGENT, {
        "actor": ACTOR, "action": "send_payment", "resource": RESOURCE, "transaction_id": "tx-1",
        "policy_hash": POLICY, "payload": payment(100.0), "constraints": constraints})
    assert r.status_code == 200, r.text
    rid = r.json()["request_id"]
    a = gw.client.post(f"/approvals/{rid}/approve", headers=OP)
    assert a.status_code == 200, a.text
    out = _post(gw.client, f"/approvals/{rid}/execute", AGENT, {
        "mandate": a.json()["mandate"], "actor": ACTOR, "action": "send_payment", "resource": RESOURCE,
        "context": payment(100.0), "transaction_id": "tx-1", "idempotency_key": "ok-1"}).json()
    assert out["status"] == "EXECUTED", out
    assert gw.calls == [("send_payment", payment(100.0))]


@pytest.mark.parametrize("constraints", OVERSIZED_SETS, ids=OVERSIZED_IDS)
def test_approval_minted_mandate_with_oversized_constraint_blocked_on_both_routes(gw, constraints):
    """An approval mandate carrying such a constraint (signed by the trusted
    approver key outside request(), e.g. minted before the fix) never executes."""
    rid = _post(gw.client, "/approvals", AGENT, {
        "actor": ACTOR, "action": "send_payment", "resource": RESOURCE, "transaction_id": "tx-1",
        "policy_hash": POLICY, "payload": payment(100.0)}).json()["request_id"]
    real = gw.client.post(f"/approvals/{rid}/approve", headers=OP).json()["mandate"]
    claims = {k: v for k, v in real.items() if k not in ("kid", "sig")}
    claims["constraints"] = dict(constraints)
    forged = gw.approver.sign_token(claims)
    for route in ("mandate", "approval"):
        url = "/mandates/execute" if route == "mandate" else f"/approvals/{rid}/execute"
        r = _post(gw.client, url, AGENT, {
            "mandate": forged, "actor": ACTOR, "action": "send_payment", "resource": RESOURCE,
            "context": payment(100.0), "transaction_id": "tx-1", "idempotency_key": f"k-{route}"})
        assert r.status_code == 200, (route, r.status_code, r.text)
        out = r.json()
        assert out["status"] == "BLOCKED" and "MALFORMED_MANDATE_CONSTRAINTS" in out["reason"], (route, out)
    assert gw.calls == []


# ===========================================================================
# Signed mandate: /mandates/execute + /mandates/verify
# ===========================================================================

@pytest.mark.parametrize("constraints", OVERSIZED_SETS, ids=OVERSIZED_IDS)
def test_signed_mandate_with_oversized_constraint_is_rejected_with_zero_actuator_calls(gw, constraints):
    m = gw.mandate(constraints=constraints)
    r = _post(gw.client, "/mandates/execute", AGENT, {
        "mandate": m, "actor": ACTOR, "action": "send_payment", "resource": RESOURCE,
        "context": payment(100.0), "idempotency_key": "k-1"})
    assert r.status_code == 200, (r.status_code, r.text)
    out = r.json()
    assert out["status"] == "BLOCKED" and "MALFORMED_MANDATE_CONSTRAINTS" in out["reason"], out
    assert gw.calls == []
    v = _post(gw.client, "/mandates/verify", AGENT, {
        "mandate": m, "subject": ACTOR, "action": "send_payment", "resource": RESOURCE})
    assert v.status_code == 200, v.text
    assert v.json()["verified"] is False and "MALFORMED_MANDATE_CONSTRAINTS" in v.json()["reason"]


@pytest.mark.parametrize("constraints,amount,executed", [
    ({"max_amount": 10 ** 300}, 100.0, 100.0),
    ({"max_amount": EDGE_MAX}, 100.0, 100.0),
    ({"allowed_amount": [10 ** 300, 100.0]}, 100.0, 100.0),
    ({"min_amount": -(10 ** 300), "max_amount": 5000}, 7500.0, 5000.0),     # still CONSTRAINs to the cap
], ids=["max-1e300", "max-edge", "allowed-1e300", "min-neg-1e300-constrain"])
def test_signed_mandate_with_huge_but_representable_bound_executes_exactly_once(gw, constraints, amount, executed):
    out = _post(gw.client, "/mandates/execute", AGENT, {
        "mandate": gw.mandate(constraints=constraints), "actor": ACTOR, "action": "send_payment",
        "resource": RESOURCE, "context": payment(amount), "idempotency_key": "ok-1"}).json()
    assert out["status"] == "EXECUTED", out
    assert gw.calls == [("send_payment", payment(executed))]


# ===========================================================================
# Oversized VALUES (valid constraints) on every actuating / deciding route
# ===========================================================================

@pytest.mark.parametrize("amount", SIGNED, ids=SIGNED_IDS)
def test_mandates_execute_oversized_payment_amount_is_profile_error_not_500(gw, amount):
    r = _post(gw.client, "/mandates/execute", AGENT, {
        "mandate": gw.mandate(), "actor": ACTOR, "action": "send_payment", "resource": RESOURCE,
        "context": payment(amount), "idempotency_key": "k-1"})
    assert r.status_code == 200, (r.status_code, r.text)
    assert r.json()["status"] == "BLOCKED" and "PROFILE_ERROR" in r.json()["reason"], r.json()
    assert gw.calls == []


@pytest.mark.parametrize("value", SIGNED, ids=SIGNED_IDS)
def test_mandates_execute_oversized_generic_value_is_blocked(gw, value):
    m = gw.mandate(action="discount_offer", resource_scope=(),
                   constraints={"max_requested_discount_percent": 20})
    r = _post(gw.client, "/mandates/execute", AGENT, {
        "mandate": m, "actor": ACTOR, "action": "discount_offer", "resource": None,
        "context": {"requested_discount_percent": value}, "idempotency_key": "k-1"})
    assert r.status_code == 200, (r.status_code, r.text)
    assert r.json()["status"] == "BLOCKED", r.json()
    assert gw.calls == []


@pytest.mark.parametrize("value", SIGNED, ids=SIGNED_IDS)
@pytest.mark.parametrize("action,resource,field,base,constraints", [
    ("move_to_zone", "robot-1", "force", {"robot": "robot-1", "zone": "a"}, {"max_force": 50}),
    ("move_to_zone", "robot-1", "force", {"robot": "robot-1", "zone": "a"}, {"allowed_zone": ["a"]}),
    ("scale_cluster", "cluster-1", "replicas", {"target": "cluster-1", "environment": "prod"},
     {"allowed_environment": ["prod"]}),
], ids=["robotics-max_force", "robotics-allowed_zone", "infra-allowed_environment"])
def test_mandates_execute_oversized_profile_field_is_profile_error_not_500(gw, value, action, resource,
                                                                           field, base, constraints):
    m = gw.mandate(action=action, resource_scope=(resource,), constraints=constraints)
    r = _post(gw.client, "/mandates/execute", AGENT, {
        "mandate": m, "actor": ACTOR, "action": action, "resource": resource,
        "context": {**base, field: value}, "idempotency_key": "k-1"})
    assert r.status_code == 200, (r.status_code, r.text)
    assert r.json()["status"] == "BLOCKED" and "PROFILE_ERROR" in r.json()["reason"], r.json()
    assert gw.calls == []


@pytest.mark.parametrize("action,resource,context,constraints,executed", [
    ("move_to_zone", "robot-1", {"robot": "robot-1", "zone": "a", "force": 10}, {"max_force": 50},
     {"robot": "robot-1", "zone": "a", "force": 10.0}),
    ("scale_cluster", "cluster-1", {"target": "cluster-1", "environment": "prod", "replicas": 3},
     {"allowed_environment": ["prod"]}, {"target": "cluster-1", "environment": "prod", "replicas": 3}),
], ids=["robotics", "infra"])
def test_profile_fields_valid_control_executes_exactly_once(gw, action, resource, context, constraints, executed):
    m = gw.mandate(action=action, resource_scope=(resource,), constraints=constraints)
    out = _post(gw.client, "/mandates/execute", AGENT, {
        "mandate": m, "actor": ACTOR, "action": action, "resource": resource,
        "context": context, "idempotency_key": "ok-1"}).json()
    assert out["status"] == "EXECUTED", out
    assert gw.calls == [(action, executed)]


@pytest.mark.parametrize("amount", SIGNED, ids=SIGNED_IDS)
def test_approval_of_oversized_payload_creates_a_record_but_never_executes(gw, amount):
    """Consistent with R2: an approval REQUEST carries no numeric validation of
    its payload (a human may be asked about anything); EXECUTION of an
    unsupported amount is refused by the payment profile."""
    r = _post(gw.client, "/approvals", AGENT, {
        "actor": ACTOR, "action": "send_payment", "resource": RESOURCE, "transaction_id": "tx-1",
        "policy_hash": POLICY, "payload": payment(amount)})
    assert r.status_code == 200, r.text
    rid = r.json()["request_id"]
    a = gw.client.post(f"/approvals/{rid}/approve", headers=OP)
    assert a.status_code == 200, a.text
    r = _post(gw.client, f"/approvals/{rid}/execute", AGENT, {
        "mandate": a.json()["mandate"], "actor": ACTOR, "action": "send_payment", "resource": RESOURCE,
        "context": payment(amount), "transaction_id": "tx-1", "idempotency_key": "k-1"})
    assert r.status_code == 200, (r.status_code, r.text)
    assert r.json()["status"] == "BLOCKED", r.json()
    assert gw.calls == []


@pytest.mark.parametrize("amount", SIGNED, ids=SIGNED_IDS)
def test_consensus_execute_oversized_amount_is_blocked(gw, amount):
    out = gw.consensus_execute(payment(amount))
    assert out["status"] == "BLOCKED" and "PROFILE_ERROR" in out["reason"], out
    assert gw.calls == []


@pytest.mark.parametrize("amount", SIGNED, ids=SIGNED_IDS)
def test_egress_oversized_body_amount_never_executes(egress, amount):
    egress.client = _raw(egress.client)
    out = _egress_run(egress, amount, "e-big")
    assert out.get("executed") is not True and out.get("outcome") not in ("ALLOW", "CONSTRAIN"), out
    assert egress.seen == [] and egress.executor.count() == 0


@pytest.mark.parametrize("amount", SIGNED, ids=SIGNED_IDS)
def test_gateway_evaluate_oversized_value_issues_no_token(gateway_app, amount):
    gwapp, client = gateway_app
    for identity, action, context in ((ACTOR, "send_payment", {"amount": amount}),
                                      ("agent/axflow-clinic", "discount_offer",
                                       {"requested_discount_percent": amount})):
        r = _post(_raw(client), "/evaluate", {"x-api-key": gwapp.settings.api_key},
                  {"identity": identity, "action": action, "context": context})
        assert r.status_code == 200, (action, r.status_code, r.text)
        assert r.json()["decision"] not in ("ALLOW", "CONSTRAIN") and r.json()["decision_token"] is None


@pytest.mark.parametrize("amount", SIGNED, ids=SIGNED_IDS)
def test_main_fallback_oversized_amount_denied(main_app, amount):
    main, client = main_app
    r = _post(_raw(client), "/evaluate", {"x-api-key": main.settings.api_key},
              {"session_id": "s-big", "intent": "send_payment", "args": {"amount": amount}})
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "DENY" and r.json().get("decision_token") is None
    assert "supported numeric range" in r.json()["reason"]


@pytest.mark.parametrize("amount", SIGNED, ids=SIGNED_IDS)
def test_main_opa_path_oversized_amount_never_reaches_opa(opa_main, amount):
    main, client, seen = opa_main
    r = _post(client, "/evaluate", {"x-api-key": main.settings.api_key},
              {"session_id": "o-big", "intent": "send_payment", "args": {"amount": amount}})
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "DENY" and r.json().get("decision_token") is None
    assert seen == []


@pytest.mark.parametrize("amount", SIGNED, ids=SIGNED_IDS)
def test_main_governance_mode_oversized_amount_full_quorum_no_token(gov_main, amount):
    out = _gov_decide(gov_main, amount, f"g-big-{amount > 0}")
    assert out["decision"] == "DENY" and out.get("decision_token") is None, out
    assert gov_main[3] == []


# ===========================================================================
# Delegation (service boundary; no HTTP route)
# ===========================================================================

@pytest.mark.parametrize("amount", SIGNED, ids=SIGNED_IDS)
def test_delegation_oversized_amount_blocked(amount):
    s = DelegationStack()
    out = s.execute(amount)
    assert out.status == "BLOCKED", out
    assert s.calls == []


@pytest.mark.parametrize("ceiling", SIGNED, ids=SIGNED_IDS)
def test_delegation_signed_oversized_ceiling_is_a_denial_not_an_exception(ceiling):
    s = DelegationStack()
    claims = {k: v for k, v in s.delegation().items() if k not in ("kid", "sig")}
    claims["max_amount"] = ceiling
    out = s.execute(100.0, delegation=s.owner.sign_token(claims))
    assert out.status == "BLOCKED" and "INVALID_DELEGATION_CEILING" in out.reason, out
    assert s.calls == []


@pytest.mark.parametrize("ceiling", SIGNED, ids=SIGNED_IDS)
def test_issue_delegation_rejects_oversized_ceiling_with_value_error(ceiling):
    with pytest.raises(ValueError):
        DelegationStack().delegation(max_amount=ceiling)


def test_delegation_valid_control_executes_exactly_once():
    s = DelegationStack()
    out = s.execute(100.0)
    assert out.status == "EXECUTED", out
    assert len(s.calls) == 1
