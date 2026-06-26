#!/usr/bin/env python3
"""Deterministic governed-agent scenarios.

    The model proposes. MCC decides. The gate enforces. The audit chain records.
    The executor acts only after a verified MCC decision.

Run:  python examples/governed_agent/scenarios.py

Prints a concise human-readable trace for each scenario. No secrets, signing
keys, or sensitive config are printed. Scenarios 1-7, 10, and the direct-bypass
check run in-process (memory mode). Scenario 8 (multi-instance shared state) and
scenario 9 (Redis-required fail-closed) are demonstrated here with an in-process
shared registry / a down backend respectively, and are proven against a REAL
Redis in tests/examples/test_governed_agent.py + scripts/redis_runtime_smoke.py.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from mcc_core import (  # noqa: E402
    InMemoryNonceRegistry,
    RedisNonceRegistry,
    SigningKey,
    VelocityLimit,
)

from examples.governed_agent.agent import Agent  # noqa: E402
from examples.governed_agent.consensus_support import EvaluatorPool  # noqa: E402
from examples.governed_agent.mcc_client import GovernedMCCClient  # noqa: E402
from examples.governed_agent.mock_executor import MockExecutor, UnauthorizedExecution  # noqa: E402


class _DownRedis:
    def __getattr__(self, _n):
        async def boom(*a, **k):
            raise ConnectionError("redis down")
        return boom


def _client(executor, **kw):
    return GovernedMCCClient(executor=executor, **kw)


def line(label, result, *, executor=None):
    print(f"  Agent proposed action: {result.action}")
    print(f"  MCC verdict: {result.verdict}")
    print(f"  Execution: {'COMPLETED' if result.executed else 'BLOCKED'}")
    print(f"  Reason: {result.reason}")
    if result.applied_changes:
        print(f"  Proposed payload : {result.proposed_payload}")
        print(f"  Authorized payload: {result.authorized_payload}")
    if result.executed:
        print(f"  Audit correlation: {result.correlation_id}  audit_ref={result.audit_ref}")
    print()


async def scenario_allow():
    print("== 1. ALLOW ==")
    ex = MockExecutor(); c = _client(ex)
    a = Agent("agent/ops")
    r = await c.submit(a.propose("transfer_resource", resource="acct-1", payload={"amount": 1000}))
    line("ALLOW", r)
    print(f"  executor calls: {ex.count()} (want 1)\n")


async def scenario_deny():
    print("== 2. DENY ==")
    ex = MockExecutor(); c = _client(ex)
    a = Agent("agent/ops")
    r = await c.submit(a.propose("delete_resource", resource="acct-1", payload={}))
    line("DENY", r)
    print(f"  executor calls: {ex.count()} (want 0)\n")


async def scenario_escalate():
    print("== 3. ESCALATE (approval loop) ==")
    ex = MockExecutor(); c = _client(ex)
    a = Agent("agent/intern")  # no standing mandate
    p = a.propose("transfer_resource", resource="acct-1", payload={"amount": 1000})
    r = await c.submit(p)
    line("ESCALATE", r)
    aid = await c.request_approval(p)
    await c.approve(aid)
    print("  Approval verified")
    r2 = await c.execute_with_approval(p, aid)
    line("APPROVED", r2)
    # forged / replayed approval rejected
    bad = await c.execute_with_approval(p, "req-forged")
    replay = await c.execute_with_approval(p, aid)
    print(f"  forged approval -> {bad.verdict}/{'COMPLETED' if bad.executed else 'BLOCKED'}")
    print(f"  replayed approval -> {replay.verdict}/{'COMPLETED' if replay.executed else 'BLOCKED'}")
    print(f"  executor calls: {ex.count()} (want 1)\n")


async def scenario_constrain():
    print("== 4. CONSTRAIN ==")
    ex = MockExecutor(); c = _client(ex)
    a = Agent("agent/ops")
    r = await c.submit(a.propose("transfer_resource", resource="acct-1", payload={"amount": 9000}))
    line("CONSTRAIN", r)
    rec = ex.last()
    print(f"  executor received authorized payload: {rec.authorized_payload} (clamped; original 9000 never executed)\n")


async def scenario_replay():
    print("== 5. Replay (one-time nonce) ==")
    ex = MockExecutor(); c = _client(ex)
    a = Agent("agent/ops")
    p = a.propose("transfer_resource", resource="acct-1", payload={"amount": 1000}, nonce="nonce-fixed-1")
    first = await c.submit(p)
    second = await c.submit(p)  # same nonce
    print(f"  first:  {first.verdict}/{'COMPLETED' if first.executed else 'BLOCKED'}")
    print(f"  replay: {second.verdict}/{'COMPLETED' if second.executed else 'BLOCKED'} - {second.reason}")
    print(f"  executor calls: {ex.count()} (want 1)\n")


async def scenario_idempotency():
    print("== 6. Idempotency ==")
    ex = MockExecutor(); c = _client(ex)
    a = Agent("agent/ops")
    first = await c.submit(a.propose("transfer_resource", resource="acct-1",
                                     payload={"amount": 1000}, idempotency_key="op-1"))
    # duplicate key, fresh nonce -> idempotency (not nonce) blocks
    dup = await c.submit(a.propose("transfer_resource", resource="acct-1",
                                   payload={"amount": 1000}, idempotency_key="op-1"))
    # conflicting binding: same key, different payload
    conflict = await c.submit(a.propose("transfer_resource", resource="acct-1",
                                        payload={"amount": 2000}, idempotency_key="op-1"))
    print(f"  first:    {'COMPLETED' if first.executed else 'BLOCKED'}")
    print(f"  duplicate:{'COMPLETED' if dup.executed else 'BLOCKED'} - {dup.reason}")
    print(f"  conflict: {'COMPLETED' if conflict.executed else 'BLOCKED'} - {conflict.reason}")
    print(f"  executor calls: {ex.count()} (want 1)\n")


async def scenario_velocity():
    print("== 7. Velocity ==")
    ex = MockExecutor()
    limit = VelocityLimit(name="count2", window_seconds=3600, max_count=2, aggregate_by=("actor",))
    c = _client(ex, velocity_limits=[limit])
    a = Agent("agent/ops")
    verdicts = []
    for i in range(3):
        r = await c.submit(a.propose("transfer_resource", resource="acct-1", payload={"amount": 100}))
        verdicts.append("COMPLETED" if r.executed else f"BLOCKED({r.verdict})")
    print(f"  three transfers (max_count=2): {verdicts}")
    print(f"  executor calls: {ex.count()} (want 2)\n")


async def scenario_multi_instance():
    print("== 8. Multi-instance shared state ==")
    # Two client instances sharing ONE nonce registry model two MCC runtimes on
    # one Redis. (Proven against REAL Redis in the test suite / smoke.)
    shared_nonce = InMemoryNonceRegistry()
    key = SigningKey.generate("shared-signer")
    ex_a, ex_b = MockExecutor(), MockExecutor()
    a = _client(ex_a, signing_key=key, nonce_registry=shared_nonce)
    b = _client(ex_b, signing_key=key, nonce_registry=shared_nonce)
    agent = Agent("agent/ops")
    p = agent.propose("transfer_resource", resource="acct-1", payload={"amount": 1000}, nonce="shared-nonce-9")
    ra = await a.submit(p)
    rb = await b.submit(p)  # same nonce, different instance
    print(f"  instance A: {'COMPLETED' if ra.executed else 'BLOCKED'}")
    print(f"  instance B (same nonce): {'COMPLETED' if rb.executed else 'BLOCKED'} - {rb.reason}")
    print(f"  A calls={ex_a.count()} B calls={ex_b.count()} (want 1 / 0)\n")


async def scenario_redis_failure():
    print("== 9. Redis required but unavailable -> fail closed ==")
    ex = MockExecutor()
    c = _client(ex, nonce_registry=RedisNonceRegistry(_DownRedis(), namespace="x:"))
    a = Agent("agent/ops")
    r = await c.submit(a.propose("transfer_resource", resource="acct-1", payload={"amount": 1000}))
    print(f"  verdict={r.verdict} execution={'COMPLETED' if r.executed else 'BLOCKED'} - {r.reason}")
    print(f"  executor calls: {ex.count()} (want 0)\n")


async def scenario_malformed():
    print("== 10. Malformed / unknown decision -> fail closed ==")

    class _BogusAuthority:
        def evaluate(self, **_):
            class _V:
                value = "MAYBE"
            class _D:
                verdict = _V()
                reason = "bogus"
                forward_context = {}
                constraints = {}
                applied_changes = []
            return _D()

    ex = MockExecutor(); c = _client(ex, authority=_BogusAuthority())
    a = Agent("agent/ops")
    r = await c.submit(a.propose("transfer_resource", resource="acct-1", payload={"amount": 1000}))
    print(f"  verdict={r.verdict} execution={'COMPLETED' if r.executed else 'BLOCKED'} - {r.reason}")
    print(f"  executor calls: {ex.count()} (want 0)\n")


async def scenario_direct_bypass():
    print("== Direct executor invocation is refused ==")
    ex = MockExecutor()
    try:
        await ex.execute("transfer_resource", {"amount": 1000})  # no authorization
        print("  ERROR: direct call succeeded")
    except UnauthorizedExecution as exc:
        print(f"  direct call rejected: {exc}")
    print(f"  executor calls: {ex.count()} (want 0)\n")


async def scenario_consensus():
    print("== 11. Consensus-required path (Challenge -> N-of-M -> MCC -> Gate -> Executor) ==")
    pool = EvaluatorPool(n=3)
    ex = MockExecutor()
    c = _client(ex, consensus_required=True, consensus_threshold=3,
                trusted_evaluators=pool.trusted_keys())
    a = Agent("agent/ops")

    def votes(p, ch, **kw):
        return pool.unanimous(ch, action=p.action, payload=p.payload, actor=p.actor,
                              resource=p.resource, policy_hash=c.policy_hash, **kw)

    # positive: gateway issues the challenge; 3 independent evaluators sign; MCC executes
    p = a.propose("transfer_resource", resource="acct-1", payload={"amount": 1000})
    ch = await c.issue_challenge(p)
    print(f"  Gateway issued challenge: {ch.challenge_id} (nonce withheld from log)")
    print("  3 independent evaluators signed votes bound to the challenge")
    r = await c.submit(p, challenge=ch, votes=votes(p, ch))
    print(f"  MCC verdict: {r.verdict}  Consensus: 3-of-3  Execution: {'COMPLETED' if r.executed else 'BLOCKED'}")

    # below threshold
    p2 = a.propose("transfer_resource", resource="acct-1", payload={"amount": 1000})
    ch2 = await c.issue_challenge(p2)
    r2 = await c.submit(p2, challenge=ch2, votes=votes(p2, ch2, count=2))
    print(f"  2-of-3 -> Execution: {'COMPLETED' if r2.executed else 'BLOCKED'} ({r2.reason})")

    # veto
    p3 = a.propose("transfer_resource", resource="acct-1", payload={"amount": 1000})
    ch3 = await c.issue_challenge(p3)
    v = votes(p3, ch3)
    v[2] = pool.sign(pool.evaluators[2], ch3, action=p3.action, payload=p3.payload, actor=p3.actor,
                     resource=p3.resource, policy_hash=c.policy_hash, verdict="DENY")
    r3 = await c.submit(p3, challenge=ch3, votes=v)
    print(f"  veto -> Execution: {'COMPLETED' if r3.executed else 'BLOCKED'}")

    # consensus does not bypass authority
    pd = a.propose("delete_resource", resource="acct-1", payload={})
    chd = await c.issue_challenge(pd)
    rd = await c.submit(pd, challenge=chd, votes=pool.unanimous(
        chd, action=pd.action, payload=pd.payload, actor=pd.actor, resource=pd.resource,
        policy_hash=c.policy_hash))
    print(f"  valid 3-of-3 on a DENY action -> {rd.verdict}/{'COMPLETED' if rd.executed else 'BLOCKED'} "
          f"(consensus does not bypass authority)")
    print(f"  executor calls: {ex.count()} (want 1)\n")


async def run_all():
    print("\n" + "=" * 64)
    print("GOVERNED AGENT DEMO — MCC-Core sits between agent and executor")
    print("The model proposes. MCC decides. The gate enforces. The audit chain records.")
    print("=" * 64 + "\n")
    await scenario_allow()
    await scenario_deny()
    await scenario_escalate()
    await scenario_constrain()
    await scenario_replay()
    await scenario_idempotency()
    await scenario_velocity()
    await scenario_multi_instance()
    await scenario_redis_failure()
    await scenario_malformed()
    await scenario_direct_bypass()
    await scenario_consensus()
    print("Done. No verified decision — no execution.")


if __name__ == "__main__":
    asyncio.run(run_all())
