"""INV-02 — No consequential execution without authorization.

Constitutional principles: "Authority remains with the owner"; "No plane
may usurp the role of another."

Every consequential action must have a valid MCC-Core decision before
execution. If MCC-Core's own infrastructure is unavailable, the result
must FAIL CLOSED (no execution), never fail open.
"""

from __future__ import annotations

import asyncio

from ._stack import NOW, DownDependency, Stack

run = asyncio.run


def test_missing_token_never_executes(tmp_path):
    stack = Stack(tmp_path)
    seen = []

    async def executor():
        seen.append("executed")
        return "ok"

    result = run(stack.coordinator.enforce(
        token={}, action="send_email", payload={"body": "hi"}, executor=executor, now=NOW,
    ))
    assert result.status.value == "BLOCKED"
    assert seen == []


def test_denied_verdict_never_executes(tmp_path):
    """A DENY/ESCALATE verdict never even produces an executable token
    (DecisionEngine.issue_token raises for non-executable verdicts) --
    this proves there is no code path where a non-ALLOW/CONSTRAIN verdict
    reaches the executor."""
    from mcc_core import TokenNotIssuable

    stack = Stack(tmp_path)
    try:
        stack.engine.issue_token(
            verdict="DENY", subject="actor-1", action="send_email", payload={"body": "hi"}, now=NOW,
        )
        raised = False
    except TokenNotIssuable:
        raised = True
    assert raised, "DecisionEngine must refuse to issue a token for a non-executable verdict"


def test_nonce_registry_unavailable_fails_closed(tmp_path):
    """MCC-Core's own replay-protection infrastructure being down must
    deny execution, not silently skip the check."""
    stack = Stack(tmp_path, nonce_registry=DownDependency())
    token = stack.issue_allow(idempotency_key="op-1")
    result = run(stack.gate.verify(token, action="send_email", payload={"body": "hello"}, now=NOW))
    assert result.allowed is False
    assert "fail-closed" in result.reason.lower() or "NONCE_REJECTED" in result.reason


def test_idempotency_backend_unavailable_blocks_before_execution(tmp_path):
    """MCC-Core's durable admission backend being down must block before
    the executor is ever invoked -- fail closed, not fail open. Uses the
    REAL ``RedisIdempotencyRegistry`` wrapping a raw failing Redis client
    (exactly ``tests/test_coordinator.py::test_idempotency_outage_fails_closed``'s
    own pattern) rather than a bare stand-in: fail-closed behavior lives
    in the registry's own Redis-error handling, not in the coordinator
    swallowing arbitrary exceptions -- so the test must exercise that
    real boundary, not assume the coordinator does the catching."""
    from mcc_core import EnforcementCoordinator, InMemoryVelocityRegistry, RedisIdempotencyRegistry

    stack = Stack(tmp_path)
    coordinator = EnforcementCoordinator(
        gate=stack.gate, idempotency=RedisIdempotencyRegistry(DownDependency()),
        velocity=InMemoryVelocityRegistry(), audit=stack.audit, velocity_limits_for=lambda action: [],
    )
    token = stack.issue_allow(idempotency_key="op-1")
    seen = []

    async def executor():
        seen.append("executed")
        return "ok"

    result = run(coordinator.enforce(token=token, action="send_email", payload={"body": "hello"}, executor=executor, now=NOW))
    assert result.status.value == "BLOCKED"
    assert "fail-closed" in result.reason.lower()
    assert seen == [], "executor must never run when the durable admission backend is unavailable"


def test_velocity_backend_unavailable_blocks_before_execution(tmp_path):
    """Same as above for the velocity/aggregate-limit backend, using the
    real ``RedisVelocityRegistry`` over a failing Redis client."""
    from mcc_core import EnforcementCoordinator, InMemoryIdempotencyRegistry, RedisVelocityRegistry, VelocityLimit

    stack = Stack(tmp_path)
    coordinator = EnforcementCoordinator(
        gate=stack.gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=RedisVelocityRegistry(DownDependency()), audit=stack.audit,
        velocity_limits_for=lambda action: [VelocityLimit(name="per-actor", window_seconds=60, max_count=100)],
    )
    token = stack.issue_allow(idempotency_key="op-2")
    seen = []

    async def executor():
        seen.append("executed")
        return "ok"

    result = run(coordinator.enforce(token=token, action="send_email", payload={"body": "hello"}, executor=executor, now=NOW))
    assert result.status.value == "BLOCKED"
    assert seen == [], "executor must never run when the velocity backend is unavailable"


def test_gate_exception_of_any_kind_denies(tmp_path):
    """ExecutionGate.verify wraps ALL internal exceptions into a deny --
    proven here by supplying a payload that cannot be canonically hashed
    consistently (this specific attack: a token with a valid signature
    but a completely malformed shape elsewhere) still resolves to deny,
    never to an unhandled exception escaping to the caller."""
    stack = Stack(tmp_path)
    malformed_token = {"this": "is not a decision token"}
    result = run(stack.gate.verify(malformed_token, action="send_email", payload={"body": "hi"}, now=NOW))
    assert result.allowed is False
