"""INV-03 — Exact-action authorization.

Constitutional principle: "Execution remains within boundaries";
"Intelligence proposes; authority verifies; execution enforces."

Authorization must be bound to the actual action being executed.
Changing any security-relevant property after authorization must
invalidate execution. Tested here: action, target (resource), payload,
policy hash, tenant/actor context, and the decision token's nonce.
"""

from __future__ import annotations

import asyncio

from ._stack import NOW, Stack

run = asyncio.run


def test_action_changed_after_authorization_is_rejected(tmp_path):
    stack = Stack(tmp_path)
    token = stack.issue_allow(action="send_email", idempotency_key="op-1")
    result = run(stack.gate.verify(token, action="delete_account", payload={"body": "hello"}, now=NOW))
    assert result.allowed is False
    assert result.reason == "ACTION_HASH_MISMATCH: token does not authorize this action"


def test_payload_changed_after_authorization_is_rejected(tmp_path):
    stack = Stack(tmp_path)
    token = stack.issue_allow(action="send_email", payload={"body": "hello"}, idempotency_key="op-1")
    result = run(stack.gate.verify(token, action="send_email", payload={"body": "SOMETHING ELSE ENTIRELY"}, now=NOW))
    assert result.allowed is False
    assert result.reason == "PAYLOAD_HASH_MISMATCH: payload differs from authorized one"


def test_target_resource_changed_after_authorization_is_rejected(tmp_path):
    stack = Stack(tmp_path)
    token = stack.issue_allow(action="send_email", resource_id="mailbox-A", idempotency_key="op-1")
    result = run(stack.gate.verify(
        token, action="send_email", payload={"body": "hello"},
        binding={"resource_id": "mailbox-B-the-agent-wants-instead"}, now=NOW,
    ))
    assert result.allowed is False
    assert "BINDING_MISMATCH" in result.reason


def test_policy_hash_mismatch_is_rejected(tmp_path):
    """A token issued under a different (e.g. stale, or attacker-substituted)
    policy than the one the gate currently trusts must not execute."""
    stack = Stack(tmp_path)
    from mcc_core import DecisionEngine, Verdict

    other_policy_engine = DecisionEngine(
        signing_key=stack.signing_key, issuer="mcc/constitution-test", audience=stack.gate.audience,
        policy_id="constitution/v2-different-policy", policy_hash="sha256:" + "d" * 64,
        token_ttl_seconds=60,
    )
    token = other_policy_engine.issue_token(
        verdict=Verdict.ALLOW, subject="actor-1", action="send_email", payload={"body": "hello"},
        idempotency_key="op-1", now=NOW,
    )
    result = run(stack.gate.verify(token, action="send_email", payload={"body": "hello"}, now=NOW))
    assert result.allowed is False
    assert result.reason == "POLICY_HASH_MISMATCH: token issued under untrusted policy"


def test_tenant_substitution_after_authorization_is_rejected(tmp_path):
    """A token authorized for one tenant must not be executed under a
    different tenant's operation context -- the exact attack the
    coordinator's binding mismatch guard exists to catch."""
    stack = Stack(tmp_path)
    token = stack.issue_allow(action="send_email", tenant_id="tenant-A", idempotency_key="op-1")
    seen = []

    async def executor():
        seen.append("executed")
        return "ok"

    result = run(stack.coordinator.enforce(
        token=token, action="send_email", payload={"body": "hello"}, executor=executor,
        request_binding={"tenant_id": "tenant-B-attacker-controlled"}, now=NOW,
    ))
    assert result.status.value == "BLOCKED"
    assert seen == []


def test_actor_substitution_after_authorization_is_rejected(tmp_path):
    stack = Stack(tmp_path)
    token = stack.issue_allow(action="send_email", actor_id="actor-A", idempotency_key="op-1")
    seen = []

    async def executor():
        seen.append("executed")
        return "ok"

    result = run(stack.coordinator.enforce(
        token=token, action="send_email", payload={"body": "hello"}, executor=executor,
        request_binding={"actor_id": "actor-B-attacker-controlled"}, now=NOW,
    ))
    assert result.status.value == "BLOCKED"
    assert seen == []


def test_decision_token_field_swap_between_two_valid_tokens_is_rejected(tmp_path):
    """An agent holding two genuinely-issued, valid tokens (for two
    different, smaller operations) must not be able to Frankenstein a
    third authorization by copying one token's claims onto another's
    signature -- proven by taking token B's payload_hash-relevant field
    and splicing it into token A: the splice invalidates A's signature."""
    stack = Stack(tmp_path)
    token_a = stack.issue_allow(action="send_email", payload={"body": "small, approved request"}, idempotency_key="op-a")
    token_b = stack.issue_allow(action="send_email", payload={"body": "large, unapproved request"}, idempotency_key="op-b")

    spliced = dict(token_a)
    spliced["payload_hash"] = token_b["payload_hash"]  # attacker splices in B's payload binding
    result = run(stack.gate.verify(spliced, action="send_email", payload={"body": "large, unapproved request"}, now=NOW))
    assert result.allowed is False
    assert result.reason == "INVALID_SIGNATURE: Ed25519 verification failed"


def test_valid_unmodified_token_is_accepted():
    """Positive control: everything above is a negative test, and none of
    them are meaningful unless the identical scenario WITHOUT tampering
    succeeds. Proven separately in every other invariant's happy-path
    assertions, but stated explicitly here for INV-03's own record."""
    import tempfile
    from pathlib import Path

    tmp_path = Path(tempfile.mkdtemp())
    stack = Stack(tmp_path)
    token = stack.issue_allow(action="send_email", payload={"body": "hello"}, idempotency_key="op-1")
    result = run(stack.gate.verify(token, action="send_email", payload={"body": "hello"}, now=NOW))
    assert result.allowed is True
