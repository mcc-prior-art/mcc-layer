"""Authority model tests: the verdict must follow from a verified mandate.

Covers all four verdicts arising from authority (ALLOW/CONSTRAIN/ESCALATE/
DENY), constraint binding, mandate expiry, and deny-by-default for unmapped
actions.
"""

from mcc_core import (
    ActionPolicy,
    AuthorityModel,
    Mandate,
    MandateRegistry,
    Verdict,
    apply_constraints,
)

NOW = 1_780_000_000


def build_model():
    registry = MandateRegistry(
        [
            Mandate(
                holder="agent/payments-bot",
                authority="payments.send",
                constraints={"max_amount": 5000},
            ),
            Mandate(holder="agent/ops-bot", authority="infra.read"),
            Mandate(
                holder="agent/temp-bot",
                authority="payments.send",
                expires_at=NOW - 1,  # already expired
            ),
        ]
    )
    policies = [
        ActionPolicy(
            action="send_payment",
            requires="payments.send",
            on_mandate=Verdict.ALLOW,
            on_violation=Verdict.CONSTRAIN,
            without_mandate=Verdict.ESCALATE,
        ),
        ActionPolicy(
            action="read_*",
            requires="infra.read",
            on_mandate=Verdict.ALLOW,
            without_mandate=Verdict.ESCALATE,
        ),
        ActionPolicy(action="delete_*", requires=None, without_mandate=Verdict.DENY),
    ]
    return AuthorityModel(registry=registry, policies=policies)


def test_held_mandate_within_bounds_allows():
    model = build_model()
    d = model.evaluate(
        identity="agent/payments-bot",
        action="send_payment",
        context={"amount": 100},
        now=NOW,
    )
    assert d.verdict == Verdict.ALLOW
    assert d.authority_required == "payments.send"
    assert d.mandate_holder == "agent/payments-bot"


def test_held_mandate_over_cap_constrains_and_rewrites():
    model = build_model()
    d = model.evaluate(
        identity="agent/payments-bot",
        action="send_payment",
        context={"amount": 9000},
        now=NOW,
    )
    assert d.verdict == Verdict.CONSTRAIN
    assert d.constraints == {"max_amount": 5000}
    # The body is actually rewritten to fit the mandate, not merely flagged.
    assert d.forward_context == {"amount": 5000}
    assert d.applied_changes  # records what was clamped


def test_no_mandate_escalates():
    model = build_model()
    d = model.evaluate(
        identity="agent/unknown",
        action="send_payment",
        context={"amount": 100},
        now=NOW,
    )
    assert d.verdict == Verdict.ESCALATE
    assert d.mandate_holder is None


def test_expired_mandate_is_no_mandate():
    model = build_model()
    d = model.evaluate(
        identity="agent/temp-bot",
        action="send_payment",
        context={"amount": 100},
        now=NOW,
    )
    assert d.verdict == Verdict.ESCALATE


def test_requires_none_action_denies():
    model = build_model()
    d = model.evaluate(
        identity="agent/ops-bot", action="delete_database", context={}, now=NOW
    )
    assert d.verdict == Verdict.DENY


def test_unmapped_action_denies_by_default():
    model = build_model()
    d = model.evaluate(
        identity="agent/payments-bot", action="launch_rocket", context={}, now=NOW
    )
    assert d.verdict == Verdict.DENY
    assert d.matched_action is None


def test_read_with_infra_read_allows():
    model = build_model()
    d = model.evaluate(
        identity="agent/ops-bot", action="read_account", context={}, now=NOW
    )
    assert d.verdict == Verdict.ALLOW


def test_within_cap_allows_unchanged():
    model = build_model()
    d = model.evaluate(
        identity="agent/payments-bot",
        action="send_payment",
        context={"amount": 4999},
        now=NOW,
    )
    assert d.verdict == Verdict.ALLOW
    assert d.forward_context == {"amount": 4999}
    assert d.applied_changes == []


def test_missing_constrained_field_cannot_be_constrained_so_denies():
    # A mandate caps amount; a payment with no amount cannot be clamped into
    # compliance (there is no safe value to invent), so it fails closed to DENY
    # rather than forwarding a non-conforming request.
    model = build_model()
    d = model.evaluate(
        identity="agent/payments-bot", action="send_payment", context={}, now=NOW
    )
    assert d.verdict == Verdict.DENY


def test_apply_constraints_clamps_max_and_min():
    new, changes = apply_constraints(
        {"max_amount": 5000, "min_qty": 2}, {"amount": 9000, "qty": 1, "memo": "x"}
    )
    assert new == {"amount": 5000, "qty": 2, "memo": "x"}
    assert len(changes) == 2


def test_apply_constraints_leaves_compliant_values():
    new, changes = apply_constraints({"max_amount": 5000}, {"amount": 100})
    assert new == {"amount": 100}
    assert changes == []


def test_from_config_roundtrip():
    model = AuthorityModel.from_config(
        {
            "mandates": {
                "agent/x": [{"authority": "pay", "constraints": {"max_amount": 10}}]
            },
            "policies": [
                {"action": "pay_*", "requires": "pay", "without_mandate": "DENY"}
            ],
            "default": "DENY",
        }
    )
    ok = model.evaluate(identity="agent/x", action="pay_now", context={"amount": 5}, now=NOW)
    assert ok.verdict == Verdict.ALLOW
    nope = model.evaluate(identity="agent/y", action="pay_now", context={}, now=NOW)
    assert nope.verdict == Verdict.DENY
