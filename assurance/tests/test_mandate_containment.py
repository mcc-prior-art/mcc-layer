"""Workstream C (extended) -- Genuine Signed-Mandate Containment (PR #71).

C8 (``test_decision_authority_containment.py``) documented, rather than
tested around, a real scope limitation: the original SUT configured only
the consensus authority path, so ``/mandates/execute`` failed closed for
EVERY mandate -- forged or genuine alike -- proving fail-closed-with-no-
authority but not genuine-vs-forged SIGNED MANDATE containment.

This file closes that gap: ``build_system_under_test`` now provisions a
real mandate issuer trust config (``MCC_TRUST_CONFIG``) on the Gateway
subprocess, and ``SystemUnderTest.issue_mandate``/``forge_mandate``/
``tamper_mandate``/``revoke_mandate`` (``assurance/sut/harness.py``) reach
it only through the Gateway's real, public ``/mandates/*`` HTTP API --
never by importing ``mcc_core.mandate`` from this file (forbidden by
``test_boundary_guards.py``). Every test below observes the SAME
independent oracle every other Workstream-C test uses: the Gateway's own
external-effect sink (``gateway_notification_receipt_count``), never the
response body's self-reported status alone.

This also exercises constraint types beyond the actuator's ``max_body.
amount`` (Workstream F's only clampable field): mandates share the exact
same ``max_/min_/allowed_`` convention (``mcc_core.authority.
_constraint_violations``/``apply_constraints``), so C20-C22 below prove
``min_`` and ``allowed_`` containment for the first time in this baseline.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict

import httpx
import pytest

from assurance.sut.harness import build_system_under_test

ACTOR = "agent/mandate-bot"
ACTION = "send_notification"
RESOURCE = "notifications"


def _payload(**overrides: Any) -> Dict[str, Any]:
    base = {"recipient": "customer-mandate-1", "message": "assurance-mandate-probe",
            "priority": 2, "channel": "email", "correlation_id": str(uuid.uuid4())}
    base.update(overrides)
    return base


def _execute(sut, mandate: Dict[str, Any], *, actor: str = ACTOR, action: str = ACTION,
             resource: str = RESOURCE, context: Dict[str, Any],
             idempotency_key: str = None) -> Dict[str, Any]:
    r = httpx.post(
        f"{sut.gateway_url}/mandates/execute", headers={"x-api-key": sut.agent_key(actor)},  # V05 pt2: own key
        json={"mandate": mandate, "actor": actor, "action": action, "resource": resource,
              "context": context,
              "idempotency_key": idempotency_key or f"mandate-auto-{uuid.uuid4()}"},
        timeout=10.0,
    )
    return r.json()


@pytest.fixture(scope="module")
def sut():
    # A mandate-authority-only deployment topology: see
    # build_system_under_test's require_consensus docstring for why this
    # is necessary (the coordinator's mandatory-consensus gate is
    # unconditional and orthogonal to which authority source is used, and
    # execute_with_mandate never supplies consensus evidence) and why it is
    # a legitimate, precedented configuration rather than a workaround.
    with build_system_under_test(require_consensus=False) as s:
        yield s


def test_c9_genuine_mandate_executes(sut):
    """Positive baseline: a mandate signed by the Gateway's own trusted
    issuer key, within its declared scope and bounds, actually executes --
    the C8-documented gap (no genuine path to compare a forgery against) is
    closed. Without this test, every C10+ negative below would be a
    tautology (a SUT that fails closed on everything trivially "resists"
    forgery too)."""
    before = sut.gateway_notification_receipt_count()
    mandate = sut.issue_mandate(subject=ACTOR, action_scope=[ACTION], resource_scope=[RESOURCE])

    result = _execute(sut, mandate, context=_payload())

    assert result["status"] == "EXECUTED", result
    assert result["decision"] == "ALLOW"
    assert sut.gateway_notification_receipt_count() == before + 1


def test_c10_forged_mandate_untrusted_issuer_is_denied(sut):
    """A syntactically valid, correctly bound mandate signed by a key never
    registered in the Gateway's trust config must never execute."""
    before = sut.gateway_notification_receipt_count()
    forged = sut.forge_mandate(subject=ACTOR, action_scope=[ACTION], resource_scope=[RESOURCE])

    result = _execute(sut, forged, context=_payload())

    assert result["status"] != "EXECUTED"
    assert "UNTRUSTED" in result["reason"] or "UNKNOWN" in result["reason"]
    assert sut.gateway_notification_receipt_count() == before


def test_c11_tampered_action_scope_is_denied(sut):
    """A GENUINELY signed mandate, scoped narrowly, then rewritten (without
    re-signing) to claim a wider action scope: the signature no longer
    covers the mutated claim, so verification must fail -- proving the
    Gateway checks the signature over the claims actually used."""
    before = sut.gateway_notification_receipt_count()
    genuine = sut.issue_mandate(subject=ACTOR, action_scope=["some_other_action"],
                                 resource_scope=[RESOURCE])
    tampered = sut.tamper_mandate(genuine, action_scope=[ACTION])

    result = _execute(sut, tampered, context=_payload())

    assert result["status"] != "EXECUTED"
    assert "SIGNATURE" in result["reason"]
    assert sut.gateway_notification_receipt_count() == before


def test_c12_tampered_subject_is_denied(sut):
    """Same tamper-after-signing attack, this time on ``subject`` -- proves
    the binding covers WHO the mandate was issued to, not just what it
    permits."""
    before = sut.gateway_notification_receipt_count()
    genuine = sut.issue_mandate(subject="someone/else", action_scope=[ACTION],
                                 resource_scope=[RESOURCE])
    tampered = sut.tamper_mandate(genuine, subject=ACTOR)

    result = _execute(sut, tampered, context=_payload())

    assert result["status"] != "EXECUTED"
    assert "SIGNATURE" in result["reason"]
    assert sut.gateway_notification_receipt_count() == before


def test_c13_expired_mandate_is_denied(sut):
    """A genuinely signed, correctly scoped mandate whose validity window
    has already closed."""
    before = sut.gateway_notification_receipt_count()
    mandate = sut.issue_mandate(subject=ACTOR, action_scope=[ACTION], resource_scope=[RESOURCE],
                                 not_before=1, not_after=2)  # expired in 1970

    result = _execute(sut, mandate, context=_payload())

    assert result["status"] != "EXECUTED"
    assert "EXPIRED" in result["reason"]
    assert sut.gateway_notification_receipt_count() == before


def test_c14_not_yet_valid_mandate_is_denied(sut):
    """A genuinely signed mandate whose validity window has not started."""
    before = sut.gateway_notification_receipt_count()
    far_future_start = 4_100_000_000
    mandate = sut.issue_mandate(subject=ACTOR, action_scope=[ACTION], resource_scope=[RESOURCE],
                                 not_before=far_future_start, not_after=far_future_start + 1000)

    result = _execute(sut, mandate, context=_payload())

    assert result["status"] != "EXECUTED"
    assert "NOT_YET_VALID" in result["reason"]
    assert sut.gateway_notification_receipt_count() == before


def test_c15_wrong_subject_at_call_time_is_denied(sut):
    """A genuine mandate issued to one actor, presented on behalf of a
    DIFFERENT actor at call time -- the mandate itself is untampered and
    validly signed; the mismatch is the caller substituting who it is."""
    before = sut.gateway_notification_receipt_count()
    mandate = sut.issue_mandate(subject="agent/the-real-holder", action_scope=[ACTION],
                                 resource_scope=[RESOURCE])

    result = _execute(sut, mandate, actor="agent/an-impostor", context=_payload())

    assert result["status"] != "EXECUTED"
    assert "SUBJECT_MISMATCH" in result["reason"]
    assert sut.gateway_notification_receipt_count() == before


def test_c16_action_outside_scope_is_denied(sut):
    """A genuine mandate scoped to a different action than the one actually
    requested."""
    before = sut.gateway_notification_receipt_count()
    mandate = sut.issue_mandate(subject=ACTOR, action_scope=["some_other_action"],
                                 resource_scope=[RESOURCE])

    result = _execute(sut, mandate, context=_payload())

    assert result["status"] != "EXECUTED"
    assert "ACTION_SCOPE_MISMATCH" in result["reason"]
    assert sut.gateway_notification_receipt_count() == before


def test_c17_resource_outside_scope_is_denied(sut):
    """A genuine mandate scoped to a different resource than the one
    actually requested."""
    before = sut.gateway_notification_receipt_count()
    mandate = sut.issue_mandate(subject=ACTOR, action_scope=[ACTION],
                                 resource_scope=["some-other-resource"])

    result = _execute(sut, mandate, context=_payload())

    assert result["status"] != "EXECUTED"
    assert "RESOURCE_SCOPE_MISMATCH" in result["reason"]
    assert sut.gateway_notification_receipt_count() == before


def test_c18_revoked_mandate_is_denied(sut):
    """A GENUINE, otherwise-valid mandate that has since been revoked
    through the Gateway's real operator-authenticated revoke endpoint.
    First proves the mandate executes while active (so the revocation
    itself, not some other property, is what blocks the second call), then
    revokes and proves the identical mandate is denied afterward."""
    before = sut.gateway_notification_receipt_count()
    mandate = sut.issue_mandate(subject=ACTOR, action_scope=[ACTION], resource_scope=[RESOURCE],
                                 revocation_required=True)

    first = _execute(sut, mandate, context=_payload())
    assert first["status"] == "EXECUTED", first
    assert sut.gateway_notification_receipt_count() == before + 1

    assert sut.revoke_mandate(mandate["mandate_id"]) is True

    second = _execute(sut, mandate, context=_payload())
    assert second["status"] != "EXECUTED"
    assert "REVOKED" in second["reason"]
    assert sut.gateway_notification_receipt_count() == before + 1


def test_c19_replayed_mandate_still_only_executes_what_it_authorizes(sut):
    """A genuine, reusable (non-single-use) mandate is not itself a replay
    vulnerability in the nonce/token sense -- re-presenting it re-runs
    THROUGH the SAME verification and profile pipeline each time (unlike a
    consensus vote/decision token, a standing mandate is designed to be
    reusable within its window). This test documents that distinction
    rather than asserting single-use, which would be a false claim about a
    mandate's actual semantics -- see ``docs/SIGNED_MANDATES.md``."""
    mandate = sut.issue_mandate(subject=ACTOR, action_scope=[ACTION], resource_scope=[RESOURCE])
    before = sut.gateway_notification_receipt_count()

    first = _execute(sut, mandate, context=_payload())
    second = _execute(sut, mandate, context=_payload())

    assert first["status"] == "EXECUTED"
    assert second["status"] == "EXECUTED"
    assert sut.gateway_notification_receipt_count() == before + 2


def test_c20_max_constraint_clamps_a_mandate_bounded_field(sut):
    """A constraint type beyond the actuator's ``max_body.amount`` (which
    this mandate path never touches): ``max_priority`` on the generic
    ``send_notification`` profile's own ``priority`` field. An excessive
    value is never executed as proposed -- it CONSTRAINs, and only the
    clamped value reaches the observable effect."""
    mandate = sut.issue_mandate(subject=ACTOR, action_scope=[ACTION], resource_scope=[RESOURCE],
                                 constraints={"max_priority": 3})
    before = sut.gateway_notification_receipt_count()

    result = _execute(sut, mandate, context=_payload(priority=9))

    assert result["status"] == "EXECUTED", result
    assert result["decision"] == "CONSTRAIN"
    assert sut.gateway_notification_receipt_count() == before + 1


def test_c21_min_constraint_clamps_a_below_floor_value_upward(sut):
    """``min_priority``: a value BELOW the floor. Symmetric to C20's
    ``max_`` case -- ``apply_constraints`` raises the value to the floor
    rather than denying outright, proving the SAME generic clamp mechanism
    (not a special case) covers ``min_`` bounds too, not just ``max_``."""
    mandate = sut.issue_mandate(subject=ACTOR, action_scope=[ACTION], resource_scope=[RESOURCE],
                                 constraints={"min_priority": 5})
    before = sut.gateway_notification_receipt_count()

    result = _execute(sut, mandate, context=_payload(priority=1))

    assert result["status"] == "EXECUTED", result
    assert result["decision"] == "CONSTRAIN"
    assert sut.gateway_notification_receipt_count() == before + 1


def test_c22_allowed_constraint_denies_a_disallowed_categorical_value(sut):
    """``allowed_channel``: a categorical constraint type, distinct from
    numeric ``max_``/``min_``. There is no safe value to invent for a
    disallowed category (unlike a numeric bound), so a violation here is
    NEVER clampable -- it must DENY, and the original request must never
    execute."""
    mandate = sut.issue_mandate(subject=ACTOR, action_scope=[ACTION], resource_scope=[RESOURCE],
                                 constraints={"allowed_channel": ["email", "sms"]})
    before = sut.gateway_notification_receipt_count()

    result = _execute(sut, mandate, context=_payload(channel="carrier-pigeon"))

    assert result["status"] != "EXECUTED"
    assert result["decision"] == "DENY"
    assert "cannot be constrained" in result["reason"]
    assert sut.gateway_notification_receipt_count() == before


def test_c23_allowed_constraint_permits_an_allowed_categorical_value(sut):
    """The positive counterpart to C22: a value genuinely within the
    allowed set executes unconstrained -- proves C22 denies because of the
    value, not because ``allowed_`` constraints always fail closed."""
    mandate = sut.issue_mandate(subject=ACTOR, action_scope=[ACTION], resource_scope=[RESOURCE],
                                 constraints={"allowed_channel": ["email", "sms"]})
    before = sut.gateway_notification_receipt_count()

    result = _execute(sut, mandate, context=_payload(channel="sms"))

    assert result["status"] == "EXECUTED", result
    assert result["decision"] == "ALLOW"
    assert sut.gateway_notification_receipt_count() == before + 1
