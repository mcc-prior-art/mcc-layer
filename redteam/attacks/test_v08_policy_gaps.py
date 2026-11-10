"""V08 - Policy gaps: actions no rule covers (default-allow?)."""
import pytest
from _harness import *
from gateway.pilot_policy import PILOT_POLICY
from mcc_core import AuthorityModel, Verdict


@attack(vector=8, severity="critical", title="Action that no policy rule covers")
@pytest.mark.parametrize("action", ["wire_swift", "SEND_PAYMENT", "send_payment ", "", "delete_database",
                                    "medical_advice_request", "refund_request"])
def test_unknown_action_is_not_allowed_by_authority_model(action):
    model = AuthorityModel.from_config(PILOT_POLICY)
    d = model.evaluate(identity="agent/payments-bot", action=action, context={"amount": 1})
    assert d.verdict in (Verdict.DENY, Verdict.ESCALATE), f"{action!r} -> {d.verdict}"


@attack(vector=8, severity="critical", title="Action outside the mandate's action scope")
@pytest.mark.parametrize("action", ["wire_swift", "send_payment2", "SEND_PAYMENT", "send_paymen"])
def test_action_outside_mandate_scope(action):
    s = Stack()
    run(s.execute(s.mandate(), idempotency_key="k", action=action))
    assert s.executed == [], f"executed {s.executed}"


UNKNOWN = [{"max-amount": 5000}, {"amount_max": 5000}, {"MAX_amount": 5000},
           {"denied_beneficiary": ["vendor-42"]}, {"currency": "USD"}, {"maxAmount": 5000}]


@attack(vector=8, severity="high",
        title="Unrecognized / misspelled mandate constraint key is silently ignored (fail-open)")
@pytest.mark.parametrize("constraints", UNKNOWN, ids=[next(iter(c)) for c in UNKNOWN])
def test_unknown_constraint_key_fails_closed(constraints):
    s = Stack()
    out = run(s.execute(s.mandate(constraints=constraints), idempotency_key="k",
                        context=payment(amount=999_999)))
    assert s.executed == [], \
        f"constraint {constraints} ignored; executed amount={s.executed[0][1]['amount']} ({out.decision})"


@attack(vector=8, severity="low", kind="hardening",
        title="allowed_<field> with a string bound degrades to substring matching")
def test_allowed_constraint_with_string_bound():
    s = Stack()
    m = s.mandate(constraints={"allowed_currency": "EUR,USD"})
    run(s.execute(m, idempotency_key="k", action=ACTION, context=payment(currency="R,U")))
    assert s.executed == [], f"currency {s.executed[0][1]['currency']!r} accepted by substring match"


@attack(vector=8, severity="low", kind="design-gap",
        title="Mandate with empty resource_scope authorizes every resource")
def test_empty_resource_scope_means_any_resource():
    s = Stack()
    run(s.execute(s.mandate(resource_scope=[]), idempotency_key="k", resource="acct-of-someone-else"))
    assert s.executed == [], "empty resource_scope acted as wildcard"
