"""INV-05 — Intelligence cannot increase authority.

Constitutional principle: "Growth of intelligence does not imply growth
of authority."

Changing or upgrading the underlying model must not automatically
increase permissions. The same action, evaluated through different
model identities/runtimes, must remain policy-controlled -- identical
authority outcome regardless of which model produced the proposal.
"""

from __future__ import annotations

import asyncio
import inspect

from mcc_core import Verdict

from ._stack import NOW, Stack, build_authority

run = asyncio.run


def test_authority_evaluate_signature_carries_no_model_or_runtime_parameter():
    """Structural guard: AuthorityModel.evaluate has no 'model'/'runtime'/
    'capability_tier' parameter at all -- there is no channel through
    which a smarter or newer model identity could carry more authority
    than an older one. Authority is a function of (identity, action,
    context, time) only."""
    params = list(inspect.signature(build_authority().evaluate).parameters)
    assert params == ["identity", "action", "context", "now"]
    forbidden = {"model", "runtime", "capability", "capability_tier", "model_version", "intelligence_level"}
    assert forbidden.isdisjoint(params)


def test_same_identity_same_action_same_verdict_regardless_of_declared_model():
    """A proposal's context may legitimately carry a 'model' label as
    informational metadata (for logging/audit), but it must not change
    the authority outcome -- an older/weaker model and a newer/stronger
    one produce the SAME verdict for the SAME (identity, action,
    context)."""
    authority = build_authority(
        mandates={"tenant-1": [{"authority": "email:send", "constraints": {"max_recipients": 10}}]},
        policies=[{"action": "send_email", "requires": "email:send", "on_violation": "DENY"}],
    )
    base_context = {"recipients": 5}
    decision_old_model = authority.evaluate(
        identity="tenant-1", action="send_email", context={**base_context, "model": "gpt-3.5-legacy"},
    )
    decision_new_model = authority.evaluate(
        identity="tenant-1", action="send_email", context={**base_context, "model": "some-hypothetical-future-model"},
    )
    assert decision_old_model.verdict == decision_new_model.verdict == Verdict.ALLOW
    assert decision_old_model.mandate_holder == decision_new_model.mandate_holder


def test_declaring_a_more_capable_model_does_not_bypass_a_violated_constraint():
    """The adversarial version of the above: a proposal that claims to
    come from a more capable/trusted-sounding model must still be denied
    when it violates the held mandate's bounds -- capability claims are
    not a constraint-bypass channel."""
    authority = build_authority(
        mandates={"tenant-1": [{"authority": "email:send", "constraints": {"max_recipients": 10}}]},
        policies=[{"action": "send_email", "requires": "email:send", "on_violation": "DENY"}],
    )
    decision = authority.evaluate(
        identity="tenant-1", action="send_email",
        context={"recipients": 5000, "model": "gpt-6-astra", "model_trust_tier": "maximum"},
    )
    assert decision.verdict == Verdict.DENY


def test_decision_token_actor_field_is_informational_not_authoritative(tmp_path):
    """At the token/gate layer: two tokens differing ONLY in actor_id
    metadata (standing in for "which model/agent produced this") but
    identical in every security-relevant field enforce identically --
    the gate's decision does not vary by which actor/model string issued
    the underlying proposal, only by the verified mandate that produced
    the token in the first place. Mirrors PR #113's own documented
    invariant: 'actor is untrusted, informational only; never read by
    authority evaluation.'"""
    stack = Stack(tmp_path)
    token_actor_a = stack.issue_allow(
        action="send_email", payload={"body": "hello"}, actor_id="agent-running-model-v1", idempotency_key="op-a",
    )
    token_actor_b = stack.issue_allow(
        action="send_email", payload={"body": "hello"}, actor_id="agent-running-hypothetical-smarter-model-v2",
        idempotency_key="op-b",
    )
    result_a = run(stack.gate.verify(token_actor_a, action="send_email", payload={"body": "hello"}, now=NOW))
    result_b = run(stack.gate.verify(token_actor_b, action="send_email", payload={"body": "hello"}, now=NOW))
    assert result_a.allowed == result_b.allowed is True


def test_no_policy_escalation_path_keyed_on_model_identity():
    """Confirms there is no ActionPolicy field or MandateRegistry lookup
    keyed on anything resembling a model identity -- mandates are looked
    up strictly by (holder identity, authority string), never by a model
    or capability label, so no policy configuration could even express
    'give this model more authority than that one' without expressing it
    as an ordinary mandate grant to an ordinary holder identity."""
    from mcc_core import ActionPolicy, Mandate

    mandate_fields = set(Mandate.__dataclass_fields__)
    policy_fields = set(ActionPolicy.__dataclass_fields__)
    assert mandate_fields.isdisjoint({"model", "runtime", "capability_tier", "intelligence_level"})
    assert policy_fields.isdisjoint({"model", "runtime", "capability_tier", "intelligence_level"})
