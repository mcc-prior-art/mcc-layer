"""V02 - Parameter smuggling: allowed action type, forbidden payload."""
import math

import pytest
from _harness import *

BAD = [("nan", float("nan")), ("nan-string", "nan"), ("neg-inf", float("-inf")),
       ("negative", -1_000_000), ("negative-string", "-1e9")]


def _in_bounds(amount, limit=5000):
    return isinstance(amount, (int, float)) and math.isfinite(amount) and 0 <= amount <= limit


@attack(vector=2, severity="high",
        title="Non-finite / negative amount passes mandate max_amount (no velocity limit on action)")
@pytest.mark.parametrize("label,amount", BAD, ids=[b[0] for b in BAD])
def test_bad_amount_vs_max_amount(label, amount):
    s = Stack()
    out = run(s.execute(s.mandate(), idempotency_key="k", context=payment(amount=amount)))
    sent = [p["amount"] for _, p in s.executed]
    assert all(_in_bounds(a) for a in sent), \
        f"actuator received amount={sent} under max_amount=5000 (status={out.status}, decision={out.decision})"


@attack(vector=2, severity="high",
        title="Non-finite / negative amount with pilot velocity limits configured")
@pytest.mark.parametrize("label,amount", BAD, ids=[b[0] for b in BAD])
def test_bad_amount_with_pilot_velocity(label, amount):
    s = Stack(velocity_limits_for=pilot_limits_for())
    run(s.execute(s.mandate(), idempotency_key="k", context=payment(amount=amount)))
    assert all(_in_bounds(p["amount"]) for _, p in s.executed), f"executed {s.executed}"


@attack(vector=2, severity="high",
        title="NaN / negative value passes max_ constraint on a non-payment action (pilot notify/clinic style)")
@pytest.mark.parametrize("value", [float("nan"), -50, float("-inf")], ids=["nan", "negative", "neg-inf"])
def test_bad_value_vs_generic_max_constraint(value):
    s = Stack()
    m = s.mandate(action_scope=["discount_offer"], resource_scope=[],
                  constraints={"max_requested_discount_percent": 20})
    out = run(s.execute(m, idempotency_key="k", action="discount_offer", resource=None,
                        context={"requested_discount_percent": value}))
    sent = [p["requested_discount_percent"] for _, p in s.executed]
    assert all(_in_bounds(v, 20) for v in sent), \
        f"actuator received requested_discount_percent={sent} under max 20 ({out.status})"


@attack(vector=2, severity="critical", title="Over-limit amount is clamped, original never executes")
def test_over_limit_amount_is_clamped():
    s = Stack()
    run(s.execute(s.mandate(), idempotency_key="k", context=payment(amount=999_999)))
    assert [p["amount"] for _, p in s.executed] == [5000], f"executed {s.executed}"


@attack(vector=2, severity="high", title="Numeric-string amount on a generic action")
def test_string_amount_on_generic_action_fails_closed():
    s = Stack()
    m = s.mandate(action_scope=["wire_out"], constraints={"max_amount": 5000})
    run(s.execute(m, idempotency_key="k", action="wire_out", context={"amount": "999999"}))
    assert s.executed == [], f"executed {s.executed}"


@attack(vector=2, severity="medium",
        title="Path/query injection through the action name under a wildcard action scope")
@pytest.mark.parametrize("action", ["pay_x/../../admin/wipe", "pay_x?admin=1", "pay_x#frag", "pay_\nX"],
                         ids=["dotdot", "query", "fragment", "newline"])
def test_action_name_is_not_a_url_injection_vector(action):
    # gateway/governance_api._httpx_upstream builds f"{base}/{action}" from this string.
    s = Stack()
    m = s.mandate(action_scope=["pay_*"])
    out = run(s.execute(m, idempotency_key="k", action=action))
    assert s.executed == [], \
        f"actuator dispatched action {s.executed[0][0]!r}; upstream URL is built as base + '/' + action ({out.status})"


@attack(vector=2, severity="high", title="Extra payload keys cannot override verdict or constraints")
def test_payload_cannot_carry_its_own_authority():
    s = Stack()
    ctx = payment(amount=999_999, decision="ALLOW", verdict="ALLOW", constraints={},
                  max_amount=10**9, approval_id="req-x", mandate_id="mdt-x", policy_hash="x")
    run(s.execute(s.mandate(), idempotency_key="k", context=ctx))
    assert [p["amount"] for _, p in s.executed] == [5000], f"executed {s.executed}"
