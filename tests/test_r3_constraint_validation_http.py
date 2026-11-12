"""R3 remediation regression suite -- fail-closed policy constraint validation.

R3 (internal red-team assessment, redteam/ at cb5bd33, V08 x6): a mandate
constraint key that is not exactly ``max_<field>`` / ``min_<field>`` /
``allowed_<field>`` was silently SKIPPED by the shared evaluator
(``mcc_core.authority._constraint_violations`` / ``apply_constraints``). A
mandate meant to cap a payment at 5000 -- but spelled ``max-amount``,
``amount_max``, ``MAX_amount``, ``maxAmount``, or expressed as an unsupported
``denied_beneficiary`` / bare ``currency`` -- carried NO restriction at all:
999,999 EUR executed under it (ALLOW, actuator called once).

Supported contract (the only one -- see ``mcc_core.authority``):

    max_<field>      bound: finite number          (CONSTRAIN clamps to it)
    min_<field>      bound: finite number          (CONSTRAIN raises to it)
    allowed_<field>  bound: list of JSON scalars   (no rewrite; violation = DENY)

Operators are exact and lowercase; ``<field>`` is a dotted path of
``[A-Za-z0-9_-]`` segments matched literally against the (flat, canonical)
context key -- e.g. the egress proxy's ``body.amount``. Any other key, a
malformed path, a wrong-typed bound or an unsatisfiable min > max is an
INVALID constraint set: never evaluated, clamped, corrected or discarded.

Every actuating route asserts on the actuator itself: ZERO calls for an
invalid constraint set and EXACTLY ONE for the valid control. Decision-only
routes assert no executable token. Delegation (no HTTP route) is tested at its
service boundary; consensus has no constraint input surface (strict schema),
which is asserted rather than assumed.
"""
from __future__ import annotations

import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from mcc_core import SigningKey, issue_delegation
from mcc_core.authority import ActionPolicy, AuthorityModel, Mandate, MandateRegistry, Verdict

try:
    from mcc_core.authority import ConstraintError, constraint_errors
except ImportError:  # pre-R3 baseline (used only to prove these tests fail there)
    class ConstraintError(Exception):
        """Stand-in: pre-R3 code raises nothing, so pytest.raises() fails."""

    def constraint_errors(constraints):
        """Stand-in: pre-R3 code has no validator, i.e. accepts everything."""
        return []
from mcc_core.mandate import issue_mandate

from tests.test_r2_numeric_constraint_http import (
    ACTOR,
    AGENT,
    OP,
    POLICY,
    RESOURCE,
    DelegationStack,
    GovGateway,
    _audit_kinds,
    _egress_run,
    payment,
    post_json,
)

@pytest.fixture(autouse=True, scope="module")
def _release_this_modules_garbage():
    """This module builds ~180 full governance stacks (FastAPI apps, egress
    harnesses, audit logs), leaving a large amount of cyclic garbage. Left
    alone, the resulting generation-2 collection lands in whichever module
    runs next. In the full suite that is
    tests/test_redis_approval_consume_atomicity.py, whose approve-vs-deny race
    uses a 0.5 s per-Redis-operation timeout. A measured 566.6 ms gen-2 pause
    (126,511 objects collected) inside that race made both sides time out and
    lose. Collecting here, at this module's own teardown, keeps that cost in
    the module that created it. Test hygiene only; no assertion is affected."""
    yield
    import gc
    gc.collect()


# The six original R3 cases, verbatim from the assessment.
ORIGINAL_R3 = [{"max-amount": 5000}, {"amount_max": 5000}, {"MAX_amount": 5000},
               {"denied_beneficiary": ["vendor-42"]}, {"currency": "USD"}, {"maxAmount": 5000}]
ORIGINAL_IDS = [next(iter(c)) for c in ORIGINAL_R3]

# Further invalid sets: mixed valid+invalid, wrong case, malformed operators,
# malformed nested paths, wrong-typed bounds, unsatisfiable ranges.
MORE_INVALID = [
    ("mixed-valid-and-unknown", {"max_amount": 5000, "maxAmount": 1}),
    ("mixed-valid-and-denylist", {"max_amount": 5000, "denied_beneficiary": ["vendor-42"]}),
    ("case-Max_", {"Max_amount": 5000}),
    ("case-MAX_AMOUNT", {"MAX_AMOUNT": 5000}),
    ("case-Allowed_", {"Allowed_currency": ["EUR"]}),
    ("op-bare-max", {"max": 5000}),
    ("op-empty-field", {"max_": 5000}),
    ("op-no-separator", {"maxamount": 5000}),
    ("op-hyphen-min", {"min-amount": 1}),
    ("op-hyphen-allowed", {"allowed-currency": ["EUR"]}),
    ("op-leading-space", {" max_amount": 5000}),
    ("op-trailing-space", {"max_amount ": 5000}),
    ("op-unknown-eq", {"eq_currency": "EUR"}),
    ("op-unknown-not", {"not_beneficiary_id": ["x"]}),
    ("path-double-dot", {"max_body..amount": 5000}),
    ("path-leading-dot", {"max_.amount": 5000}),
    ("path-trailing-dot", {"max_amount.": 5000}),
    ("path-slash", {"max_body/amount": 5000}),
    ("path-space", {"max_body amount": 5000}),
    ("bound-allowed-string", {"allowed_currency": "EUR,USD"}),
    ("bound-allowed-object", {"allowed_currency": {"EUR": True}}),
    ("bound-allowed-nested-list", {"allowed_currency": [["EUR"]]}),
    ("bound-max-string", {"max_amount": "5000"}),
    ("bound-max-null", {"max_amount": None}),
    ("bound-max-list", {"max_amount": [5000]}),
    ("bound-max-bool", {"max_amount": True}),
    ("bound-min-object", {"min_amount": {"v": 1}}),
    ("unsatisfiable-min-gt-max", {"min_amount": 10, "max_amount": 5}),
]
ALL_INVALID = [(i, c) for i, c in zip(ORIGINAL_IDS, ORIGINAL_R3)] + MORE_INVALID


# ===========================================================================
# The shared contract (unit level) -- what is valid is decided in ONE place
# ===========================================================================

@pytest.mark.parametrize("constraints", [c for _, c in ALL_INVALID], ids=[i for i, _ in ALL_INVALID])
def test_contract_rejects_invalid_constraint_sets(constraints):
    assert constraint_errors(constraints), constraints


@pytest.mark.parametrize("constraints", [
    {}, {"max_amount": 5000}, {"min_amount": 0, "max_amount": 5000},
    {"allowed_currency": ["EUR", "USD"]}, {"allowed_host": []},          # empty = deny every value
    {"max_body.amount": 5000, "allowed_method": ["post"]},              # egress canonical keys
    {"max_limits.cpu": 4}, {"max_rate-limit": 10}, {"allowed_zone": ["zone-a"]},
    {"max_force": 50, "allowed_environment": ["prod"], "max_replicas": 10},
    {"min_delta": -10, "max_delta": 10}, {"allowed_flag": [True, None, 1, "x"]},
], ids=["empty", "max", "min-max", "allowed", "allowed-empty", "egress", "dotted", "hyphen",
        "robotics", "infra-robotics-mix", "negative-range", "scalars"])
def test_contract_accepts_every_documented_form(constraints):
    assert constraint_errors(constraints) == []


def test_contract_rejects_non_object_constraint_sets():
    for bad in (["max_amount"], "max_amount", 5000):
        assert constraint_errors(bad)


# ===========================================================================
# POST /mandates/execute  (+ /mandates/verify)
# ===========================================================================

@pytest.fixture
def gw():
    return GovGateway()


@pytest.mark.parametrize("constraints", [c for _, c in ALL_INVALID], ids=[i for i, _ in ALL_INVALID])
def test_mandates_execute_invalid_constraints_never_execute(gw, constraints):
    out = gw.mandate_execute(payment(999_999.0), mandate=gw.mandate(constraints=constraints))
    assert out["status"] == "BLOCKED" and out["decision"] == "DENY", out
    assert "MALFORMED_MANDATE_CONSTRAINTS" in out["reason"], out
    assert gw.calls == []


@pytest.mark.parametrize("constraints", ORIGINAL_R3, ids=ORIGINAL_IDS)
def test_mandates_verify_reports_invalid_constraints(gw, constraints):
    r = gw.client.post("/mandates/verify", headers=AGENT, json={
        "mandate": gw.mandate(constraints=constraints), "subject": ACTOR,
        "action": "send_payment", "resource": RESOURCE})
    assert r.status_code == 200
    assert r.json()["verified"] is False and "MALFORMED_MANDATE_CONSTRAINTS" in r.json()["reason"]


@pytest.mark.parametrize("raw", [None, "max_amount=5000", ["max_amount"], 5000],
                         ids=["null", "string", "list", "number"])
def test_mandate_with_non_object_constraints_claim_is_rejected(gw, raw):
    """A mandate signed (e.g. before R3, or by a non-conforming issuer) whose
    constraints claim is not an object -- never treated as 'no constraints'."""
    now = int(time.time())
    claims = {k: v for k, v in gw.mandate().items() if k not in ("kid", "sig")}
    claims.update(constraints=raw, iat=now - 10, nbf=now - 10, exp=now + 3600)
    out = gw.mandate_execute(payment(100.0), mandate=gw.issuer.sign_token(claims))
    assert out["status"] == "BLOCKED" and "MALFORMED_MANDATE_CONSTRAINTS" in out["reason"], out
    assert gw.calls == []


@pytest.mark.parametrize("constraints,context,decision,executed_amount", [
    ({"max_amount": 5000}, payment(100.0), "ALLOW", 100.0),
    ({"max_amount": 5000}, payment(7500.0), "CONSTRAIN", 5000),
    ({"min_amount": 10, "max_amount": 5000}, payment(5000.0), "ALLOW", 5000.0),
    ({"allowed_currency": ["EUR"], "max_amount": 5000}, payment(100.0), "ALLOW", 100.0),
    ({"allowed_beneficiary_id": ["vendor-42"]}, payment(100.0), "ALLOW", 100.0),
    ({}, payment(100.0), "ALLOW", 100.0),
], ids=["max-allow", "max-constrain", "min-max", "allowed+max", "allowed-recipient", "no-constraints"])
def test_mandates_execute_valid_constraints_execute_exactly_once(gw, constraints, context, decision,
                                                                 executed_amount):
    out = gw.mandate_execute(context, mandate=gw.mandate(constraints=constraints))
    assert out["status"] == "EXECUTED" and out["decision"] == decision, out
    assert [p["amount"] for _, p in gw.calls] == [executed_amount]


@pytest.mark.parametrize("constraints,context", [
    ({"allowed_currency": ["USD"]}, payment(100.0)),
    ({"allowed_beneficiary_id": ["someone-else"]}, payment(100.0)),
    ({"allowed_currency": []}, payment(100.0)),
], ids=["currency-not-allowed", "recipient-not-allowed", "empty-allowlist"])
def test_valid_allowlist_still_denies_values_outside_it(gw, constraints, context):
    out = gw.mandate_execute(context, mandate=gw.mandate(constraints=constraints))
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


@pytest.mark.parametrize("constraints,context,executed", [
    ({"max_limits.cpu": 4}, {"limits.cpu": 2}, {"limits.cpu": 2}),
    ({"max_limits.cpu": 4}, {"limits.cpu": 9}, {"limits.cpu": 4}),
    ({"allowed_tier-name": ["gold"]}, {"tier-name": "gold"}, {"tier-name": "gold"}),
], ids=["dotted-allow", "dotted-constrain", "hyphen-allowed"])
def test_generic_and_nested_field_constraints_still_work(gw, constraints, context, executed):
    m = gw.mandate(action="adjust_setting", resource_scope=(), constraints=constraints)
    out = gw.mandate_execute(context, action="adjust_setting", resource=None, mandate=m)
    assert out["status"] == "EXECUTED", out
    assert gw.calls == [("adjust_setting", executed)]


def test_nested_path_with_missing_field_fails_closed(gw):
    """A well-formed path the context does not carry is a violation (the
    bound cannot be shown to hold), never 'no constraint'."""
    m = gw.mandate(action="adjust_setting", resource_scope=(), constraints={"max_limits.cpu": 4})
    out = gw.mandate_execute({"limits": {"cpu": 99}}, action="adjust_setting", resource=None, mandate=m)
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


@pytest.mark.parametrize("constraints", [{"max_amount": float("nan")}, {"max_amount": 5000}],
                         ids=["r2-nan-bound", "r2-value-checks"])
def test_r2_numeric_protections_still_hold(gw, constraints):
    if "nan" in str(constraints):
        out = gw.mandate_execute(payment(100.0), mandate=gw.mandate(constraints=constraints))
    else:
        out = gw.mandate_execute(payment(float("nan")), mandate=gw.mandate(constraints=constraints))
    assert out["status"] == "BLOCKED", out
    assert gw.calls == []


# ===========================================================================
# POST /approvals  ->  /approvals/{id}/approve  ->  /approvals/{id}/execute
# ===========================================================================

@pytest.mark.parametrize("constraints", [c for _, c in ALL_INVALID], ids=[i for i, _ in ALL_INVALID])
def test_approval_request_with_invalid_constraints_is_a_controlled_422(gw, constraints):
    r = post_json(gw.client, "/approvals", AGENT, {
        "actor": ACTOR, "action": "send_payment", "resource": RESOURCE, "transaction_id": "tx-1",
        "policy_hash": POLICY, "payload": payment(999_999.0), "constraints": constraints})
    assert r.status_code == 422, r.text
    assert "INVALID_CONSTRAINTS" in r.text
    assert gw.calls == []


def test_approval_valid_constraints_execute_exactly_once(gw):
    out = gw.approval_execute(payment(100.0), constraints={"max_amount": 5000, "allowed_currency": ["EUR"]})
    assert out["status"] == "EXECUTED", out
    assert gw.calls == [("send_payment", payment(100.0))]


@pytest.mark.parametrize("constraints", ORIGINAL_R3, ids=ORIGINAL_IDS)
def test_legacy_approval_record_with_invalid_constraints_cannot_be_approved(gw, constraints):
    """A record stored BEFORE R3 (bypassing request()'s check) is never
    minted into an approval mandate, and nothing executes."""
    from mcc_core import ApprovalRecord, ApprovalState
    from mcc_core.signing import hash_action, hash_payload
    now = int(time.time())
    rec = ApprovalRecord(
        request_id="req-legacy-r3", actor=ACTOR, action="send_payment",
        action_hash=hash_action("send_payment"), resource=RESOURCE, transaction_id="tx-1",
        policy_hash=POLICY, payload_hash=hash_payload(payment(999_999.0)), constraints=dict(constraints),
        state=ApprovalState.PENDING.value, created_at=now, expires_at=now + 300,
        tenant_id="tenant-1", payload=payment(999_999.0))
    asyncio.run(gw.approvals.registry.create(rec))
    r = gw.client.post("/approvals/req-legacy-r3/approve", headers=OP)
    assert r.status_code == 409, r.text
    assert gw.client.get("/approvals/req-legacy-r3", headers=AGENT).json()["state"] == "PENDING"
    assert gw.calls == []


@pytest.mark.parametrize("constraints", ORIGINAL_R3, ids=ORIGINAL_IDS)
def test_legacy_approval_minted_mandate_with_invalid_constraints_is_blocked(gw, constraints):
    """An approval mandate minted BEFORE R3 (signed by the trusted approver key
    with the unsupported constraint) is blocked on both execute routes."""
    rid = post_json(gw.client, "/approvals", AGENT, {
        "actor": ACTOR, "action": "send_payment", "resource": RESOURCE, "transaction_id": "tx-1",
        "policy_hash": POLICY, "payload": payment(999_999.0)}).json()["request_id"]
    real = gw.client.post(f"/approvals/{rid}/approve", headers=OP).json()["mandate"]
    claims = {k: v for k, v in real.items() if k not in ("kid", "sig")}
    claims["constraints"] = dict(constraints)
    legacy = gw.approver.sign_token(claims)
    for route in ("mandate", "approval"):
        body = {"mandate": legacy, "actor": ACTOR, "action": "send_payment", "resource": RESOURCE,
                "context": payment(999_999.0), "transaction_id": "tx-1", "idempotency_key": f"k-{route}"}
        url = "/mandates/execute" if route == "mandate" else f"/approvals/{rid}/execute"
        out = post_json(gw.client, url, AGENT, body).json()
        assert out["status"] == "BLOCKED" and "MALFORMED_MANDATE_CONSTRAINTS" in out["reason"], (route, out)
    assert gw.calls == []
    assert gw.client.get(f"/approvals/{rid}", headers=AGENT).json()["state"] == "APPROVED"  # not consumed


def test_r1_approval_binding_still_enforced(gw):
    out = gw.approval_execute(payment(100.0))
    assert out["status"] == "EXECUTED"
    # second use of the same approval on either route stays blocked (R1)
    rid = post_json(gw.client, "/approvals", AGENT, {
        "actor": ACTOR, "action": "send_payment", "resource": RESOURCE, "transaction_id": "tx-2",
        "policy_hash": POLICY, "payload": payment(100.0)}).json()["request_id"]
    m = gw.client.post(f"/approvals/{rid}/approve", headers=OP).json()["mandate"]
    evil = post_json(gw.client, "/mandates/execute", AGENT, {
        "mandate": m, "actor": ACTOR, "action": "send_payment", "resource": RESOURCE,
        "context": payment(999_999.0), "transaction_id": "tx-2", "idempotency_key": "evil"}).json()
    assert evil["status"] == "BLOCKED" and "APPROVAL_PAYLOAD_MISMATCH" in evil["reason"]
    assert len(gw.calls) == 1


# ===========================================================================
# POST /consensus/execute -- no constraint input surface
# ===========================================================================

def test_consensus_request_cannot_carry_constraints(gw):
    """Consensus authority has no constraint map at all; the strict request
    schema refuses a smuggled one (controlled 422, not silently ignored)."""
    r = post_json(gw.client, "/consensus/execute", AGENT, {
        "votes": [], "actor": ACTOR, "action": "send_payment", "resource": RESOURCE,
        "context": payment(100.0), "nonce": "n", "idempotency_key": "k",
        "constraints": {"maxAmount": 5000}})
    assert r.status_code == 422
    assert gw.calls == []


def test_consensus_valid_execution_unchanged(gw):
    out = gw.consensus_execute(payment(100.0))
    assert out["status"] == "EXECUTED", out
    assert gw.calls == [("send_payment", payment(100.0))]


# ===========================================================================
# Enforced egress proxy: POST /v1/http/execute  (config AuthorityModel)
# ===========================================================================

@pytest.fixture
def egress():
    from tests._egress_harness import EgressHarness
    return EgressHarness(max_amount=5000)


def _egress_mandate(hz):
    authority = hz.app.state.egress_service.rt.client.authority
    m = authority.registry.find(hz.settings.egress_actor_mandate, "http.egress", now=int(time.time()))
    assert m is not None
    return m


@pytest.mark.parametrize("extra", ORIGINAL_R3 + [{"max_body..amount": 1}, {"allowed_host": "127.0.0.1"}],
                         ids=ORIGINAL_IDS + ["path-double-dot", "allowed-string"])
def test_egress_policy_with_invalid_constraint_denies_and_never_calls_upstream(egress, extra):
    """A policy whose constraint set became invalid after load (or was loaded
    by pre-R3 code) DENIES -- the CONSTRAIN/ESCALATE paths are not taken."""
    _egress_mandate(egress).constraints.update(extra)
    out = _egress_run(egress, 1000, "e-r3")
    assert out.get("executed") is not True and out.get("outcome") == "DENY", out
    assert egress.seen == []
    assert "pre_actuation" not in _audit_kinds(egress.settings.audit_log_path)


def test_egress_valid_policy_executes_exactly_once(egress):
    out = _egress_run(egress, 1000, "e-ok")
    assert out["executed"] is True, out
    assert [s["body"] for s in egress.seen] == [{"amount": 1000}]


def test_egress_authority_refuses_to_load_invalid_constraints():
    with pytest.raises(ConstraintError):
        MandateRegistry([Mandate(holder="agent/egress", authority="http.egress",
                                 constraints={"allowed_host": "*", "maxAmount": 1})])


# ===========================================================================
# Decision-only: gateway/app.py POST /evaluate (config AuthorityModel)
# ===========================================================================

@pytest.fixture
def gateway_app(monkeypatch, tmp_path):
    import gateway.app as gwapp
    monkeypatch.setattr(gwapp.settings, "audit_log_path", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(gwapp, "gateway", gwapp.Gateway())
    return gwapp, TestClient(gwapp.app, raise_server_exceptions=False)


def _evaluate(gateway_app, context, identity=ACTOR, action="send_payment"):
    gwapp, client = gateway_app
    r = post_json(client, "/evaluate", {"x-api-key": gwapp.settings.api_key},
                  {"identity": identity, "action": action, "context": context})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.parametrize("extra", ORIGINAL_R3, ids=ORIGINAL_IDS)
def test_gateway_evaluate_invalid_policy_constraint_issues_no_token(gateway_app, extra):
    gwapp, _ = gateway_app
    m = gwapp.gateway.authority.registry.find(ACTOR, "payments.send", now=int(time.time()))
    m.constraints.update(extra)
    out = _evaluate(gateway_app, {"amount": 999_999})
    assert out["decision"] == "DENY" and out["decision_token"] is None, out
    assert "INVALID_CONSTRAINTS" in out["reason"]


def test_gateway_evaluate_valid_policy_still_issues_token(gateway_app):
    out = _evaluate(gateway_app, {"amount": 100})
    assert out["decision"] == "ALLOW" and out["decision_token"] is not None


def test_gateway_policy_with_invalid_constraints_refuses_to_load(monkeypatch):
    import copy
    import gateway.app as gwapp
    bad = copy.deepcopy(gwapp.PILOT_POLICY)
    bad["mandates"]["agent/payments-bot"][0]["constraints"] = {"max-amount": 5000}
    monkeypatch.setattr(gwapp, "PILOT_POLICY", bad)
    with pytest.raises(ConstraintError):
        gwapp.Gateway()


def test_authority_model_invalid_constraints_deny_even_when_policy_escalates_on_violation():
    """Without R3's explicit DENY, an invalid set reported as a violation
    would follow on_violation=ESCALATE to a human approval."""
    m = Mandate(holder="agent/x", authority="pay", constraints={"max_amount": 5000})
    model = AuthorityModel(registry=MandateRegistry([m]), policies=[
        ActionPolicy(action="pay", requires="pay", on_violation=Verdict.ESCALATE)])
    m.constraints["maxAmount"] = 1                   # became invalid after load
    d = model.evaluate(identity="agent/x", action="pay", context={"amount": 1})
    assert d.verdict == Verdict.DENY and "INVALID_CONSTRAINTS" in d.reason


# ===========================================================================
# Delegation (NO HTTP route -- service boundary execute_with_delegation)
# ===========================================================================

def test_issue_delegation_refuses_a_generic_constraints_claim():
    s = DelegationStack()
    now = int(time.time())
    with pytest.raises(ValueError):
        issue_delegation(s.owner, owner_id="owner/alex", subject=ACTOR, tenant_id="tenant-1",
                         purpose="vendor_payment", action_scope=["send_payment"], resource_scope=[RESOURCE],
                         recipient_scope=["vendor-*"], currency="EUR", max_amount=500.0,
                         not_before=now - 10, not_after=now + 3600, consent_ref="sha256:c",
                         extra={"constraints": {"max_amount": 100}})


@pytest.mark.parametrize("constraints", [{"max_amount": 100}, {"maxAmount": 100}], ids=["valid-shape", "r3-key"])
def test_delegation_signed_with_constraints_claim_is_blocked_not_ignored(constraints):
    """A delegation signed with a constraints claim (outside issue_delegation)
    would carry a restriction the verifier does not enforce: blocked."""
    s = DelegationStack()
    d = s.delegation()
    claims = {k: v for k, v in d.items() if k not in ("kid", "sig")}
    claims["constraints"] = constraints
    out = s.execute(300.0, delegation=s.owner.sign_token(claims))   # 300 > the intended 100
    assert out.status == "BLOCKED" and "UNSUPPORTED_DELEGATION_CLAIM" in out.reason, out
    assert s.calls == []


def test_delegation_valid_executes_exactly_once():
    s = DelegationStack()
    out = s.execute(100.0)
    assert out.status == "EXECUTED", out
    assert len(s.calls) == 1
