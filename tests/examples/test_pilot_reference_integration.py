"""End-to-end reference integration: an agent's outbound HTTP action, governed.

Proves, against a live loopback upstream and the REAL runtime:
* execution happens only after a verified decision (ALLOW / approved-ESCALATE /
  re-consensused-CONSTRAIN reach upstream; DENY never does);
* the modified (CONSTRAIN) payload requires a new payload hash + new consensus,
  and the original over-cap amount is never sent;
* the outbound executor refuses any unsigned/ungoverned call (no bypass);
* a required Redis being unavailable fails closed (the upstream is never reached).
"""

import asyncio

import pytest

from examples.governed_agent.agent import Agent
from examples.governed_agent.consensus_support import EvaluatorPool
from examples.governed_agent.mcc_client import GovernedMCCClient
from mcc_core import RedisNonceRegistry
from pilot.outbound_executor import OutboundHTTPExecutor, UnauthorizedExecution
from tests._fakeredis import DownRedis

from examples._demo_server import DemoServer
import examples.pilot_reference_integration as ref

run = asyncio.run


@pytest.fixture(scope="module")
def upstream_base():
    """Start the demo's loopback upstream with deterministic shutdown: the server
    thread is joined at teardown (no reliance on daemon-thread termination)."""
    server = DemoServer(ref.upstream, ref.UPSTREAM_PORT)
    server.start()
    try:
        yield f"http://127.0.0.1:{ref.UPSTREAM_PORT}"
    finally:
        server.stop()


def test_reference_integration_all_paths_no_bypass(upstream_base):
    failures = run(ref.run_scenarios(upstream_base))
    assert failures == [], f"reference integration reported: {failures}"
    # The original over-cap body must never have reached upstream.
    assert all(c["body"].get("amount") != 10000 for c in ref.SEEN if "amount" in c["body"])


# ---- unit-level no-bypass (the executor's own defence) ----

def test_outbound_executor_refuses_unsigned_call():
    ex = OutboundHTTPExecutor("http://127.0.0.1:1")  # never contacted
    with pytest.raises(UnauthorizedExecution):
        run(ex.execute("transfer_resource", {"amount": 1}))
    with pytest.raises(UnauthorizedExecution):
        run(ex.execute("transfer_resource", {"amount": 1}, authorization={"decision": "DENY"}))
    # Right verdict but wrong action also refused.
    with pytest.raises(UnauthorizedExecution):
        run(ex.execute("transfer_resource", {"amount": 1},
                       authorization={"decision": "ALLOW", "action": "other"}))
    assert ex.count() == 0


# ---- Redis required but unavailable -> fail closed, upstream untouched ----

def test_redis_unavailable_fails_closed_no_outbound():
    pool = EvaluatorPool(3)
    ex = OutboundHTTPExecutor("http://127.0.0.1:1")  # would refuse a connection anyway
    c = GovernedMCCClient(
        executor=ex, consensus_required=True, consensus_threshold=3,
        trusted_evaluators=pool.trusted_keys(),
        nonce_registry=RedisNonceRegistry(DownRedis(), namespace="x:"))
    p = Agent("agent/ops").propose("transfer_resource", resource="a", payload={"amount": 100})
    ch = run(c.issue_challenge(p))
    v = pool.unanimous(ch, action=p.action, payload=p.payload, actor=p.actor,
                       resource=p.resource, policy_hash=c.policy_hash)
    r = run(c.submit(p, challenge=ch, votes=v))
    assert not r.executed and ex.count() == 0
