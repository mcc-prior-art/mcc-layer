#!/usr/bin/env python3
"""Reference integration: an agent's outbound HTTP action, governed by MCC-Core.

An agent wants to perform an outbound HTTP request (a transfer). It cannot reach
the upstream directly — the request only leaves the process through the **real**
MCC-Core runtime:

    Agent -> GovernedMCCClient (consensus-required)
          -> ConsensusVerifier + ChallengeService   (N-of-M, gateway-issued nonce)
          -> AuthorityModel                          (ALLOW/DENY/ESCALATE/CONSTRAIN)
          -> DecisionEngine                          (Ed25519 token over authorized body)
          -> EnforcementCoordinator -> ExecutionGate (the one governed path)
          -> OutboundHTTPExecutor                    (the real POST; refuses unsigned)
          -> upstream

This is one runtime — no parallel engine, no demo-only verifier, no second
coordinator. The executor is the *only* side effect, and it runs only when handed
the verified decision token for that exact operation.

Demonstrated, with the upstream recording exactly what it actually received:

* ALLOW                       -> upstream receives the request once
* DENY                        -> upstream is never contacted
* ESCALATE -> approval        -> upstream receives only after approval + consensus
* CONSTRAIN -> re-consensus   -> a NEW payload hash forces NEW consensus; the
                                 upstream receives the clamped {amount: 5000},
                                 and the original {amount: 10000} is never sent
* direct-bypass attempt       -> refused (UnauthorizedExecution)

Run:  python examples/pilot_reference_integration.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import httpx
from fastapi import FastAPI, Request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from examples._demo_server import DemoServers  # noqa: E402

from examples.governed_agent.agent import Agent  # noqa: E402
from examples.governed_agent.consensus_support import EvaluatorPool  # noqa: E402
from examples.governed_agent.mcc_client import GovernedMCCClient  # noqa: E402
from pilot.outbound_executor import OutboundHTTPExecutor, UnauthorizedExecution  # noqa: E402

UPSTREAM_PORT = 9019

# The external service the agent is trying to reach. It records every call it
# actually sees (with the body) so we can prove what really left the process.
upstream = FastAPI()
SEEN: list[dict] = []


@upstream.api_route("/{path:path}", methods=["GET", "POST", "DELETE"])
async def sink(request: Request, path: str):
    try:
        body = await request.json()
    except Exception:
        body = {}
    # GET is only used by the readiness probe; record real (executed) calls.
    if request.method != "GET":
        SEEN.append({"action": path, "body": body})
    return {"upstream_reached": True, "action": path, "received": body}


def _votes(pool, client, p, ch, *, payload=None):
    return pool.unanimous(
        ch, action=p.action, payload=payload if payload is not None else p.payload,
        actor=p.actor, resource=p.resource, policy_hash=client.policy_hash)


async def run_scenarios(base_url: str) -> list[str]:
    pool = EvaluatorPool(3)
    ex = OutboundHTTPExecutor(base_url)
    client = GovernedMCCClient(
        executor=ex, consensus_required=True, consensus_threshold=3,
        trusted_evaluators=pool.trusted_keys())
    failures: list[str] = []

    def check(cond: bool, msg: str):
        if not cond:
            failures.append(msg)

    # --- 1. ALLOW: within mandate + cap -> executes, upstream receives once ---
    p = Agent("agent/ops").propose("transfer_resource", resource="acct-1", payload={"amount": 1000})
    ch = await client.issue_challenge(p)
    r = await client.submit(p, challenge=ch, votes=_votes(pool, client, p, ch))
    print(f"[ALLOW]     verdict={r.verdict} executed={r.executed} upstream_calls={ex.count()}")
    check(r.executed and ex.count() == 1, "ALLOW did not execute exactly once")
    check(ex.last() is not None and ex.last().authorized_payload == {"amount": 1000},
          "ALLOW upstream body wrong")

    # --- 2. DENY: destructive action -> blocked, upstream never contacted ---
    pd = Agent("agent/ops").propose("delete_resource", resource="acct-1", payload={})
    chd = await client.issue_challenge(pd)
    rd = await client.submit(pd, challenge=chd, votes=_votes(pool, client, pd, chd))
    print(f"[DENY]      verdict={rd.verdict} executed={rd.executed} upstream_calls={ex.count()}")
    check(rd.verdict == "DENY" and not rd.executed and ex.count() == 1,
          "DENY reached upstream or did not block")

    # --- 3. ESCALATE -> approval -> consensus -> executes ---
    pe = Agent("agent/intern").propose("transfer_resource", resource="acct-1", payload={"amount": 1000})
    che = await client.issue_challenge(pe)
    ve = _votes(pool, client, pe, che)
    re_ = await client.submit(pe, challenge=che, votes=ve)
    print(f"[ESCALATE]  round1 verdict={re_.verdict} executed={re_.executed} (consensus alone cannot execute)")
    check(re_.verdict == "ESCALATE" and not re_.executed, "ESCALATE did not block at round 1")
    aid = await client.request_approval(pe)
    await client.approve(aid)
    rea = await client.execute_with_approval(pe, aid, challenge=che, votes=ve)
    print(f"[ESCALATE]  after approval+consensus executed={rea.executed} upstream_calls={ex.count()}")
    check(rea.executed and ex.count() == 2, "approved ESCALATE did not execute")

    # --- 4. CONSTRAIN -> NEW payload hash -> re-consensus -> executes clamped ---
    pc = Agent("agent/ops").propose("transfer_resource", resource="acct-1", payload={"amount": 10000})
    ch1 = await client.issue_challenge(pc)
    r1 = await client.submit(pc, challenge=ch1, votes=_votes(pool, client, pc, ch1))
    print(f"[CONSTRAIN] round1 verdict={r1.verdict} status={r1.status} "
          f"authorized={r1.authorized_payload} executed={r1.executed}")
    check(r1.verdict == "CONSTRAIN" and r1.status == "RECONSENSUS_REQUIRED" and not r1.executed,
          "CONSTRAIN round 1 should require re-consensus and not execute")
    constrained = r1.authorized_payload
    check(constrained == {"amount": 5000}, "CONSTRAIN did not clamp to the mandate cap")
    ch2 = await client.issue_challenge(pc, payload=constrained)  # NEW challenge, NEW payload hash
    v2 = _votes(pool, client, pc, ch2, payload=constrained)      # NEW votes over the clamped body
    r2 = await client.execute_constrained(pc, constrained, challenge=ch2, votes=v2)
    print(f"[CONSTRAIN] round2 (re-consensus on {constrained}) executed={r2.executed} "
          f"upstream_calls={ex.count()}")
    check(r2.executed and ex.count() == 3, "re-consensus CONSTRAIN did not execute")
    check(ex.last().authorized_payload == {"amount": 5000}, "upstream did not receive the clamped body")
    # The original over-cap amount must never have left the process.
    check(all(c["body"].get("amount") != 10000 for c in SEEN if "amount" in c["body"]),
          "original 10000 reached upstream")

    # --- 5. no direct bypass: the executor refuses an unsigned call ---
    try:
        await ex.execute("transfer_resource", {"amount": 1})  # no authorization token
        failures.append("direct executor call succeeded (bypass!)")
    except UnauthorizedExecution:
        print("[BYPASS]    direct executor call refused (UnauthorizedExecution)")
    # An ungoverned token shape is also refused.
    try:
        await ex.execute("transfer_resource", {"amount": 1}, authorization={"decision": "DENY"})
        failures.append("ungoverned token executed (bypass!)")
    except UnauthorizedExecution:
        pass

    check(ex.count() == 3, f"unexpected executor call count {ex.count()} (want 3)")
    print(f"\nUpstream actually received: {SEEN}")
    return failures


def main() -> int:
    servers = DemoServers()
    try:
        # DemoServers.start() blocks until the upstream is ready (server.started).
        servers.start(upstream, UPSTREAM_PORT)
        base_url = f"http://127.0.0.1:{UPSTREAM_PORT}"

        print("\n=== Reference integration: outbound HTTP governed by MCC-Core (consensus-required) ===\n")
        failures = asyncio.run(run_scenarios(base_url))

        if failures:
            print("\nREFERENCE INTEGRATION FAILED:")
            for f in failures:
                print(f"  - {f}")
            return 1
        print("\nPASSED: only ALLOW / approved-ESCALATE / re-consensused-CONSTRAIN reached upstream; "
              "DENY and direct bypass never did.\n")
        return 0
    finally:
        # Deterministic teardown: stop + join the embedded server before the
        # interpreter exits, on success and on exception alike.
        servers.stop_all()


if __name__ == "__main__":
    sys.exit(main())
