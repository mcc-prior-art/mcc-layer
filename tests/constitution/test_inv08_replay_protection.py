"""INV-08 — Replay protection.

Constitutional principle: "Execution remains within boundaries";
"Authority is verifiable, not merely trusted."

A valid authorization decision must not be reusable outside its intended
execution context. Nonce/replay protection is verified directly.
"""

from __future__ import annotations

import asyncio

from ._stack import NOW, Stack

run = asyncio.run


def test_same_token_cannot_be_verified_twice(tmp_path):
    stack = Stack(tmp_path)
    token = stack.issue_allow(idempotency_key="op-1")
    first = run(stack.gate.verify(token, action="send_email", payload={"body": "hello"}, now=NOW))
    second = run(stack.gate.verify(token, action="send_email", payload={"body": "hello"}, now=NOW))
    assert first.allowed is True
    assert second.allowed is False
    assert "NONCE_REJECTED" in second.reason


def test_same_token_cannot_execute_twice_through_the_coordinator(tmp_path):
    """The end-to-end replay attack: an agent (or a compromised
    transport) resubmits the exact same decision token a second time,
    attempting a second real side effect."""
    stack = Stack(tmp_path)
    token = stack.issue_allow(idempotency_key="op-1")
    calls = []

    async def executor():
        calls.append("side-effect")
        return "ok"

    first = run(stack.coordinator.enforce(token=token, action="send_email", payload={"body": "hello"}, executor=executor, now=NOW))
    second = run(stack.coordinator.enforce(token=token, action="send_email", payload={"body": "hello"}, executor=executor, now=NOW))
    assert first.status.value == "EXECUTED"
    assert second.status.value != "EXECUTED"
    assert calls == ["side-effect"], "the side effect must happen exactly once, never twice"


def test_explicit_nonce_reuse_across_two_otherwise_different_tokens_is_rejected(tmp_path):
    """Even when an agent crafts two DIFFERENT, otherwise-legitimately-signed
    tokens (different actions/payloads) but the SAME explicit nonce value,
    the second consumption of that nonce is rejected -- the nonce is
    scoped to a single use, not to a particular action/payload
    combination, so it cannot be recycled into a second execution
    context by changing the surrounding claims."""
    stack = Stack(tmp_path)
    shared_nonce = "explicit-shared-nonce-value"
    token_one = stack.issue_allow(action="send_email", payload={"body": "first"}, idempotency_key="op-1", nonce=shared_nonce)
    token_two = stack.issue_allow(action="send_email", payload={"body": "second"}, idempotency_key="op-2", nonce=shared_nonce)

    first = run(stack.gate.verify(token_one, action="send_email", payload={"body": "first"}, now=NOW))
    second = run(stack.gate.verify(token_two, action="send_email", payload={"body": "second"}, now=NOW))
    assert first.allowed is True
    assert second.allowed is False
    assert "NONCE_REJECTED" in second.reason


def test_expired_token_is_rejected_even_with_a_fresh_nonce(tmp_path):
    """A token past its validity window must not execute, regardless of
    nonce freshness -- expiry and replay are independent checks, both
    enforced."""
    stack = Stack(tmp_path)
    token = stack.issue_allow(idempotency_key="op-1", now=NOW - 1000)  # exp = (NOW-1000)+60, already expired at NOW
    result = run(stack.gate.verify(token, action="send_email", payload={"body": "hello"}, now=NOW))
    assert result.allowed is False
    assert result.reason == "TOKEN_EXPIRED"


def test_non_vacuity_a_fresh_distinct_nonce_still_succeeds(tmp_path):
    """Positive control: the replay rejections above are meaningful only
    because a genuinely fresh, distinct nonce DOES succeed."""
    stack = Stack(tmp_path)
    token_a = stack.issue_allow(action="send_email", payload={"body": "a"}, idempotency_key="op-a", nonce="nonce-a")
    token_b = stack.issue_allow(action="send_email", payload={"body": "b"}, idempotency_key="op-b", nonce="nonce-b")
    result_a = run(stack.gate.verify(token_a, action="send_email", payload={"body": "a"}, now=NOW))
    result_b = run(stack.gate.verify(token_b, action="send_email", payload={"body": "b"}, now=NOW))
    assert result_a.allowed is True
    assert result_b.allowed is True
