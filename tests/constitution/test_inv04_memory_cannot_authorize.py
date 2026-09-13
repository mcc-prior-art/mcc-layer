"""INV-04 — Memory cannot authorize.

Constitutional principle: "Authority remains with the owner"; "No plane
may usurp the role of another."

Memory may provide context. Memory must never grant authority. A record
such as "the user normally allows this" must never become an
authorization decision.

IMPLEMENTATION GAP (documented, not hidden -- see
docs/CONSTITUTION-COMPLIANCE.md): this repository has no first-class
agent-memory subsystem (no conversation/behavioral memory store; every
"Memory" hit in the codebase is an ``InMemory<X>Registry`` durable-state
backend, unrelated to this principle). There is therefore no real
"memory component" to attach an end-to-end test to. What IS provable,
and is proven below, is the invariant memory would have to violate to
grant authority: ``AuthorityModel.evaluate`` decides purely from
(identity, action, verified mandate, declarative numeric constraints on
the untrusted context) -- an arbitrary free-form claim placed in that
context, worded exactly like a memory record, cannot by itself flip a
verdict from ESCALATE/DENY to ALLOW. If an agent-memory component is
ever added, it should be re-pointed at this same suite (or a new one
extending it) exercising the ACTUAL memory->context integration path.
"""

from __future__ import annotations

import inspect

from mcc_core import Verdict

from ._stack import build_authority


def test_memory_style_claim_in_context_does_not_grant_allow_without_mandate():
    """No mandate exists for this identity/action. A context payload
    shaped exactly like a memory-derived claim ("user normally allows
    this") must not change the outcome from ESCALATE (the policy's
    without_mandate default) to ALLOW."""
    authority = build_authority(
        mandates={},  # no mandate granted to anyone
        policies=[{"action": "send_marketing_email", "requires": "email:marketing"}],
    )
    memory_claim_context = {
        "memory_note": "user normally allows marketing email outreach",
        "user_typically_approves": True,
        "prior_approval_count": 47,
        "assistant_recalls": "the user said yes last time",
    }
    decision = authority.evaluate(identity="tenant-1", action="send_marketing_email", context=memory_claim_context)
    assert decision.verdict == Verdict.ESCALATE
    assert decision.mandate_holder is None


def test_memory_style_claim_cannot_satisfy_a_numeric_constraint_it_does_not_name():
    """A held mandate WITH a real constraint (e.g. a spend cap) must still
    be enforced on the actual numeric field -- a memory-shaped claim
    about the field cannot substitute for the field itself."""
    authority = build_authority(
        mandates={"tenant-1": [{"authority": "email:marketing", "constraints": {"max_recipients": 10}}]},
        policies=[{"action": "send_marketing_email", "requires": "email:marketing", "on_violation": "DENY"}],
    )
    context = {
        "recipients": 5000,
        "memory_note": "the user historically approves large recipient lists",
        "assistant_recalls_prior_bulk_sends": True,
    }
    decision = authority.evaluate(identity="tenant-1", action="send_marketing_email", context=context)
    assert decision.verdict == Verdict.DENY
    assert "recipients" in decision.reason


def test_authority_evaluate_has_no_memory_or_history_parameter():
    """Structural proof that memory has no channel into the decision at
    all: AuthorityModel.evaluate's signature accepts only identity,
    action, context, and now -- there is no separate 'memory'/'history'/
    'prior_approvals' argument a caller could use to bypass mandate
    checking, and context itself is proven above to be inert for this
    purpose."""
    params = list(inspect.signature(build_authority().evaluate).parameters)
    assert params == ["identity", "action", "context", "now"]
    forbidden_names = {"memory", "history", "prior_approvals", "recall", "past_decisions"}
    assert forbidden_names.isdisjoint(params)


def test_non_vacuity_a_real_mandate_still_grants_allow():
    """Positive control: the two DENY/ESCALATE results above are only
    meaningful if a REAL mandate (not a memory-shaped claim) does grant
    ALLOW for the same action -- proving the negative tests failed for
    the right reason (no valid mandate), not because the whole model is
    broken."""
    authority = build_authority(
        mandates={"tenant-1": [{"authority": "email:marketing", "constraints": {}}]},
        policies=[{"action": "send_marketing_email", "requires": "email:marketing"}],
    )
    decision = authority.evaluate(identity="tenant-1", action="send_marketing_email", context={})
    assert decision.verdict == Verdict.ALLOW
    assert decision.mandate_holder == "tenant-1"
