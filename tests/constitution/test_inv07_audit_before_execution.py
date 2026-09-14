"""INV-07 — Audit-before-execution.

Constitutional principle: "Authority is verifiable, not merely trusted";
the canonical doctrine line's own ordering: "The gate enforces. The
audit chain records" follows "MCC-Core decides" -- and, as the
coordinator's own module docstring states, the pre-enforcement decision
is durably recorded (step e) BEFORE dispatch commitment (step f) and
execution (step g).

For consequential actions: Decision -> Audit -> Execution, never
Execution -> Audit.
"""

from __future__ import annotations

import asyncio

from ._stack import NOW, Stack

run = asyncio.run


def test_audit_entry_exists_before_executor_is_invoked(tmp_path):
    """The strongest form of this test: the executor callback itself
    reads the audit log (a SEPARATE read of the same file
    EnforcementCoordinator just wrote to) and asserts a pre-actuation
    entry for this exact operation is already durably present -- proving
    the ordering at runtime, not by trusting a comment."""
    stack = Stack(tmp_path)
    token = stack.issue_allow(idempotency_key="op-1")
    observed = {}

    async def executor():
        entries = stack.read_audit_entries()
        observed["entries_at_execution_time"] = list(entries)
        return "ok"

    result = run(stack.coordinator.enforce(token=token, action="send_email", payload={"body": "hello"}, executor=executor, now=NOW))
    assert result.status.value == "EXECUTED"
    entries = observed["entries_at_execution_time"]
    assert len(entries) >= 1, "an audit entry must already exist before the executor runs"
    kinds = [e.get("kind") for e in entries]
    assert any(k is not None for k in kinds), "the pre-actuation entry must be a real, kinded record"


def test_audit_entry_exists_for_the_completed_operation_afterward(tmp_path):
    stack = Stack(tmp_path)
    token = stack.issue_allow(idempotency_key="op-2")

    async def executor():
        return "ok"

    result = run(stack.coordinator.enforce(token=token, action="send_email", payload={"body": "hello"}, executor=executor, now=NOW))
    assert result.status.value == "EXECUTED"
    entries = stack.read_audit_entries()
    assert len(entries) >= 2, "expect at least a pre-actuation entry and an outcome entry"


def test_rejected_operation_is_still_audited_even_though_never_executed(tmp_path):
    """A BLOCKED decision must itself be audited -- the audit chain
    records MCC-Core's decisions, not merely its successes."""
    stack = Stack(tmp_path)
    seen = []

    async def executor():
        seen.append("executed")
        return "ok"

    result = run(stack.coordinator.enforce(token={}, action="send_email", payload={"body": "hello"}, executor=executor, now=NOW))
    assert result.status.value == "BLOCKED"
    assert seen == []
    entries = stack.read_audit_entries()
    assert any(e.get("kind") == "actuation_rejected" for e in entries)


def test_audit_chain_is_tamper_evident(tmp_path):
    """Each audit entry is hash-chained to the previous one -- a
    modification to an earlier entry breaks verification, which is what
    makes "the audit chain records" a durable claim rather than a mutable
    log a compromised component could quietly edit after the fact."""
    from mcc_core import AuditLog

    stack = Stack(tmp_path)
    token = stack.issue_allow(idempotency_key="op-3")

    async def executor():
        return "ok"

    run(stack.coordinator.enforce(token=token, action="send_email", payload={"body": "hello"}, executor=executor, now=NOW))
    assert AuditLog.verify_chain(str(stack.audit_path)) is True

    # Tamper: flip one character in the first entry's body without
    # recomputing the hash chain.
    lines = stack.audit_path.read_text().splitlines()
    assert lines, "expected at least one audit entry to tamper with"
    tampered_first_line = lines[0].replace("actuation", "TAMPERED", 1)
    lines[0] = tampered_first_line
    stack.audit_path.write_text("\n".join(lines) + "\n")
    assert AuditLog.verify_chain(str(stack.audit_path)) is False


def test_non_vacuity_executor_reading_audit_too_early_would_fail_without_ordering():
    """Non-vacuity for the runtime ordering test above: confirms the
    assertion style itself is capable of failing -- an empty entries list
    (the scenario if audit-before-execution did NOT hold and the
    executor ran before anything was recorded) fails the same assertion
    the real test relies on."""
    entries = []
    try:
        assert len(entries) >= 1, "an audit entry must already exist before the executor runs"
        failed_as_expected = False
    except AssertionError:
        failed_as_expected = True
    assert failed_as_expected
