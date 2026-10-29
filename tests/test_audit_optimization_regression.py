"""Adversarial regression suite for the AuditLog tail-read optimization
(P2-A2). Proves the optimization did not weaken: cross-process write
serialization, crash durability, hash-chain integrity, fail-closed
behavior on storage errors, lock-contention semantics, or the
never-trust-the-cached-prev_hash invariant. Every "must never corrupt /
must never duplicate" assertion is checked against the actual file
content and/or ``AuditLog.verify_chain()``, not a status string alone.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mcc_core.audit import AuditCorruptionError, AuditLockError, AuditLog

WORKER = str(Path(__file__).resolve().parent / "_audit_fault_worker.py")


def _run_worker(*args: str, timeout: float = 15.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, WORKER, *args],
        capture_output=True, text=True, timeout=timeout,
    )


def _popen_worker(*args: str) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, WORKER, *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )


# ---------------------------------------------------------------------------
# Concurrent append races -- real separate OS processes
# ---------------------------------------------------------------------------


def test_concurrent_real_process_appends_never_corrupt_the_chain(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    AuditLog(path)  # create the file up front

    n_workers = 12
    procs = [_popen_worker("--path", path, "--mode", "append", "--worker-id", str(i))
             for i in range(n_workers)]
    for p in procs:
        rc = p.wait(timeout=30)
        assert rc == 0, p.stderr.read()

    with open(path, encoding="utf-8") as fh:
        entries = [json.loads(line) for line in fh if line.strip()]
    assert len(entries) == n_workers
    assert {e["worker"] for e in entries} == {str(i) for i in range(n_workers)}
    assert AuditLog.verify_chain(path) is True


def test_concurrent_appends_plus_concurrent_reads_stay_consistent(tmp_path):
    """While several real processes append, repeatedly construct fresh
    AuditLog instances (which perform the optimized tail-read at
    construction time) and confirm every one either sees a valid chain
    head or (very early on) GENESIS -- never a torn/partial record."""
    path = str(tmp_path / "audit.jsonl")
    AuditLog(path)
    n_workers = 8
    procs = [_popen_worker("--path", path, "--mode", "append", "--worker-id", str(i))
             for i in range(n_workers)]

    observed_hashes = set()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and any(p.poll() is None for p in procs):
        probe = AuditLog(path)
        observed_hashes.add(probe.prev_hash)
        time.sleep(0.01)

    for p in procs:
        rc = p.wait(timeout=30)
        assert rc == 0, p.stderr.read()

    assert AuditLog.verify_chain(path) is True
    # Every hash this test ever observed via a fresh construction must be
    # a hash that genuinely appears in the final, valid chain (or GENESIS)
    # -- never a value that doesn't correspond to any real committed state.
    with open(path, encoding="utf-8") as fh:
        real_hashes = {json.loads(line)["hash"] for line in fh if line.strip()}
    assert observed_hashes <= (real_hashes | {"GENESIS"})


# ---------------------------------------------------------------------------
# Crash / restart recovery
# ---------------------------------------------------------------------------


def test_crash_before_fsync_leaves_a_recoverable_consistent_file(tmp_path):
    """A process SIGKILLed exactly at the fsync() call (write+flush
    already ran) can leave bytes visible on disk (the OS page cache
    survives process death, unlike a real power loss, which this sandbox
    cannot safely simulate -- see module docstring). What must hold
    regardless: a subsequent fresh AuditLog instance reads a consistent
    last entry (whatever actually ended up on disk) and can append a new,
    correctly-chained entry; verify_chain() passes on the result."""
    path = str(tmp_path / "audit.jsonl")
    AuditLog(path).append({"seed": True})

    proc = _popen_worker("--path", path, "--mode", "crash-before-fsync", "--worker-id", "victim")
    rc = proc.wait(timeout=15)
    assert rc == -signal.SIGKILL, (proc.stdout.read(), proc.stderr.read())

    # Whatever is on disk now, it must be made of whole, parseable lines --
    # the crash must never leave a half-written JSON line that breaks
    # every future read.
    with open(path, encoding="utf-8") as fh:
        lines = [l for l in fh if l.strip()]
    for line in lines:
        json.loads(line)  # raises if torn/partial

    # Recovery: a fresh instance can read the real head and append cleanly.
    recovered = AuditLog(path)
    recovered.append({"after_crash": True})
    assert AuditLog.verify_chain(path) is True


def test_crash_while_holding_lock_auto_releases_for_the_next_writer(tmp_path):
    """A process that dies (SIGKILL) while holding the inter-process lock
    must not deadlock every future writer -- flock is tied to the file
    descriptor/process, so the OS releases it on process death. Proves
    this with a real process, not an in-process assumption."""
    path = str(tmp_path / "audit.jsonl")
    AuditLog(path)

    holder = _popen_worker("--path", path, "--mode", "hold-lock")
    try:
        line = holder.stdout.readline()
        assert line.strip() == "LOCK_HELD"

        # While the holder is alive and holding the lock, a short-timeout
        # append from THIS process must fail closed (AuditLockError), not
        # hang or silently proceed.
        contending = AuditLog(path, lock_timeout_seconds=0.3)
        with pytest.raises(AuditLockError):
            contending.append({"should_not_get_the_lock_yet": True})
    finally:
        holder.kill()
        holder.wait(timeout=10)

    # Now that the holder is dead, the lock must be available again.
    recovered = AuditLog(path, lock_timeout_seconds=5.0)
    recovered.append({"after_holder_died": True})
    assert AuditLog.verify_chain(path) is True


# ---------------------------------------------------------------------------
# Hash-chain corruption
# ---------------------------------------------------------------------------


def test_corrupted_last_line_fails_closed_on_append_not_a_silent_chain_restart(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    log.append({"i": 0})
    log.append({"i": 1})
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("not-valid-json{{{\n")

    fresh = AuditLog(path)  # construction tolerates it (best-effort cache)
    assert fresh.prev_hash == "GENESIS"  # degraded, but did not crash startup
    with pytest.raises(AuditCorruptionError):
        fresh.append({"i": 2})  # the AUTHORITATIVE path must fail closed

    # The corruption must still be sitting there untouched -- no silent
    # "recovery" that discards or overwrites it.
    with open(path, encoding="utf-8") as fh:
        content = fh.read()
    assert "not-valid-json{{{" in content


def test_verify_chain_detects_a_broken_link_anywhere_in_the_file(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    for i in range(5):
        log.append({"i": i})
    assert AuditLog.verify_chain(path) is True

    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    entry = json.loads(lines[2])
    entry["prev_hash"] = "tampered"
    lines[2] = json.dumps(entry) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)

    assert AuditLog.verify_chain(path) is False


# ---------------------------------------------------------------------------
# Storage errors
# ---------------------------------------------------------------------------


def test_write_failure_rolls_back_and_reraises_file_unchanged(tmp_path, monkeypatch):
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    log.append({"i": 0})
    size_before = os.path.getsize(path)

    real_fsync = os.fsync

    def failing_fsync(fd):
        raise OSError(28, "No space left on device")  # ENOSPC

    monkeypatch.setattr(os, "fsync", failing_fsync)
    with pytest.raises(OSError):
        log.append({"i": 1})
    monkeypatch.setattr(os, "fsync", real_fsync)

    # Rollback must have truncated back to exactly the pre-attempt size --
    # no phantom partial record left visible.
    assert os.path.getsize(path) == size_before
    assert AuditLog.verify_chain(path) is True
    # The in-memory cache must not have advanced on a failed append.
    with open(path, encoding="utf-8") as fh:
        last = json.loads([l for l in fh if l.strip()][-1])
    assert log.prev_hash == last["hash"]

    # A subsequent, real append must still succeed cleanly.
    log.append({"i": 1, "retry": True})
    assert AuditLog.verify_chain(path) is True


# ---------------------------------------------------------------------------
# Lock contention
# ---------------------------------------------------------------------------


def test_lock_timeout_behavior_unchanged(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    AuditLog(path)
    holder = _popen_worker("--path", path, "--mode", "hold-lock")
    try:
        assert holder.stdout.readline().strip() == "LOCK_HELD"
        log = AuditLog(path, lock_timeout_seconds=0.25)
        t0 = time.monotonic()
        with pytest.raises(AuditLockError):
            log.append({"x": 1})
        elapsed = time.monotonic() - t0
        assert 0.2 <= elapsed < 5.0, f"timeout took {elapsed}s, expected ~0.25s"
    finally:
        holder.kill()
        holder.wait(timeout=10)


# ---------------------------------------------------------------------------
# Stale state -- self.prev_hash must never be trusted for a real write
# ---------------------------------------------------------------------------


def test_stale_in_memory_prev_hash_is_never_used_for_a_real_append(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    first_instance = AuditLog(path)
    first_instance.append({"i": 0})
    stale_cached_hash = first_instance.prev_hash

    # A completely separate instance (models a separate process/gateway
    # replica) appends several more entries to the SAME file.
    second_instance = AuditLog(path)
    for i in range(1, 5):
        second_instance.append({"i": i})
    true_head_hash = second_instance.prev_hash
    assert true_head_hash != stale_cached_hash

    # The FIRST instance's in-memory cache is now stale. Its next append
    # must bind to the TRUE on-disk head, not its own stale cache.
    result = first_instance.append({"i": "from_stale_instance"})
    assert result["prev_hash"] == true_head_hash
    assert result["prev_hash"] != stale_cached_hash
    assert AuditLog.verify_chain(path) is True


# ---------------------------------------------------------------------------
# Zero unauthorized actuator calls -- the optimization must not change any
# authorization-relevant behavior, only read performance. Exercised via the
# real governed stack, not AuditLog in isolation.
# ---------------------------------------------------------------------------


def test_governed_stack_actuator_call_counts_unaffected_by_the_optimization(tmp_path):
    """A minimal real-stack smoke check (the full existing coordinator /
    delegation / clinic suites already re-run unmodified as part of this
    PR's full regression -- see the PR description for exact counts).
    This test exists in THIS file so the property is pinned locally too:
    a DENY must still result in zero actuator calls, and a legitimate
    ALLOW must still result in exactly one, with the optimized AuditLog
    backing the coordinator's audit trail."""
    import asyncio

    from mcc_core import (
        AuditLog as _AuditLog,
        DecisionEngine,
        EnforcementCoordinator,
        ExecutionGate,
        InMemoryIdempotencyRegistry,
        InMemoryNonceRegistry,
        InMemoryVelocityRegistry,
        PaymentProfile,
        ProfileRegistry,
        SigningKey,
    )

    key = SigningKey.generate("k1")
    engine = DecisionEngine(signing_key=key, issuer="mcc/test", audience="gate",
                            policy_id="p/v1", policy_hash="sha256:p", token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={key.kid: key.public_key()}, audience="gate",
                        nonce_registry=InMemoryNonceRegistry(), policy_hash="sha256:p")
    audit = _AuditLog(str(tmp_path / "audit.jsonl"))
    coordinator = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(), velocity=InMemoryVelocityRegistry(),
        audit=audit, profiles=ProfileRegistry.default_pilot(),
        velocity_limits_for=lambda action: [],
    )
    profile = PaymentProfile()
    seen = []

    async def runner():
        seen.append("executed")
        return "ok"

    async def go():
        ctx = {"source": "acct-1", "beneficiary_id": "ben-1", "amount": 10.0, "currency": "usd"}
        payload = profile.canonical_payload(ctx)
        # DENY: a token issued under a non-executable verdict should
        # never even reach the point of calling the executor. Simulate by
        # presenting an unsigned/garbage token.
        deny_result = await coordinator.enforce(
            token={}, action="send_payment", payload=payload, executor=runner, now=1_790_000_000,
        )
        assert deny_result.status.value == "BLOCKED"
        assert seen == []

        token = engine.issue_token(
            verdict="ALLOW", subject="actor-1", action="send_payment", payload=payload,
            transaction_id="t1", idempotency_key="op-1", actor_id="actor-1", resource_id="acct-1",
            auth_claims=profile.auth_claims(ctx), now=1_790_000_000, tenant_id="tenant-1",
        )
        allow_result = await coordinator.enforce(
            token=token, action="send_payment", payload=payload, executor=runner, now=1_790_000_000,
        )
        assert allow_result.status.value == "EXECUTED"
        assert seen == ["executed"]

    asyncio.run(go())
    assert AuditLog.verify_chain(audit.path) is True
