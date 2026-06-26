"""Combined consensus governance flows: consensus + ESCALATE, consensus + CONSTRAIN.

Both paths extend the *real* runtime (AuthorityModel -> DecisionEngine ->
ExecutionGate -> EnforcementCoordinator -> ApprovalService / ConsensusVerifier /
ChallengeService). No predicate replaces another:

Path A (consensus + ESCALATE): an ESCALATEd action executes only when the final
call carries BOTH a valid single-use approval AND a valid N-of-M consensus bound
to a gateway-issued challenge. Consensus never turns ESCALATE into ALLOW; the
approval never bypasses consensus.

Path B (consensus + CONSTRAIN): consensus over the original (over-cap) body does
NOT authorize the clamped body. The gateway issues a FRESH challenge bound to the
constrained body, evaluators sign FRESH votes, and only that re-consensus can
execute the constrained amount. The original amount is never executed.
"""

import asyncio
import json
import os
from pathlib import Path

import pytest

from mcc_core import (
    AuditLog,
    RedisChallengeRegistry,
    RedisNonceRegistry,
    SigningKey,
    VelocityLimit,
    build_redis_client,
    issue_vote,
    redis_keys,
)

from examples.governed_agent.agent import Agent
from examples.governed_agent.consensus_support import FAR_FUTURE, EvaluatorPool
from examples.governed_agent.mcc_client import GovernedMCCClient
from examples.governed_agent.mock_executor import MockExecutor
from tests._fakeredis import FakeRedis

run = asyncio.run


def _client(executor, pool, *, threshold=3, **kw):
    return GovernedMCCClient(
        executor=executor, consensus_required=True, consensus_threshold=threshold,
        trusted_evaluators=pool.trusted_keys(), **kw)


def _votes(pool, client, p, ch, *, payload=None, **kw):
    return pool.unanimous(ch, action=p.action, payload=payload if payload is not None else p.payload,
                          actor=p.actor, resource=p.resource, policy_hash=client.policy_hash, **kw)


# ============================================================================
# Path A — consensus + ESCALATE
# ============================================================================

def _escalating_proposal(**kw):
    # agent/intern holds no transfer mandate -> transfer_resource ESCALATEs.
    return Agent("agent/intern").propose("transfer_resource", resource="acct-1",
                                         payload={"amount": 1000}, **kw)


async def _approved(client, proposed):
    rid = await client.request_approval(proposed)
    assert await client.approve(rid)
    return rid


# ---- positive ----

def test_consensus_escalate_executes_with_both_predicates():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _escalating_proposal()
    ch = run(c.issue_challenge(p)); v = _votes(pool, c, p, ch)
    # Round 1: valid consensus does NOT execute an ESCALATE.
    r1 = run(c.submit(p, challenge=ch, votes=v))
    assert r1.verdict == "ESCALATE" and not r1.executed and ex.count() == 0
    # Operator approves; final execution carries approval + the same consensus.
    rid = run(_approved(c, p))
    r2 = run(c.execute_with_approval(p, rid, challenge=ch, votes=v))
    assert r2.executed and ex.count() == 1
    assert ex.last().authorized_payload == {"amount": 1000}


def test_consensus_escalate_audit_binds_both():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _escalating_proposal()
    ch = run(c.issue_challenge(p)); v = _votes(pool, c, p, ch)
    rid = run(_approved(c, p))
    assert run(c.execute_with_approval(p, rid, challenge=ch, votes=v)).executed
    assert AuditLog.verify_chain(c.audit.path)
    kinds = [json.loads(l)["kind"] for l in Path(c.audit.path).read_text().splitlines() if l.strip()]
    assert "consensus_verified" in kinds and "challenge_consumed" in kinds and "pre_actuation" in kinds


# ---- negative: approval without consensus stays blocked ----

def test_approval_without_consensus_fails_closed():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _escalating_proposal()
    rid = run(_approved(c, p))
    r = run(c.execute_with_approval(p, rid))  # no challenge/votes
    assert not r.executed and ex.count() == 0


def test_approval_with_below_threshold_consensus_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _escalating_proposal()
    ch = run(c.issue_challenge(p)); v = _votes(pool, c, p, ch, count=2)
    rid = run(_approved(c, p))
    assert not run(c.execute_with_approval(p, rid, challenge=ch, votes=v)).executed
    assert ex.count() == 0


def test_approval_with_untrusted_votes_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _escalating_proposal()
    ch = run(c.issue_challenge(p))
    rogue = SigningKey.generate("rogue")
    v = _votes(pool, c, p, ch, count=2) + [issue_vote(
        rogue, evaluator_id="eval-2", verdict="ALLOW", action=p.action, payload=p.payload,
        actor=p.actor, not_before=0, not_after=FAR_FUTURE, resource=p.resource,
        policy_hash=c.policy_hash, nonce=ch.nonce)]
    rid = run(_approved(c, p))
    assert not run(c.execute_with_approval(p, rid, challenge=ch, votes=v)).executed
    assert ex.count() == 0


# ---- negative: consensus without a valid approval stays ESCALATE ----

def test_consensus_without_approval_stays_escalate():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _escalating_proposal()
    ch = run(c.issue_challenge(p)); v = _votes(pool, c, p, ch)
    # submit with full consensus but no approval -> still ESCALATE, never executes.
    assert run(c.submit(p, challenge=ch, votes=v)).verdict == "ESCALATE"
    # execute_with_approval with an unknown approval id -> approval consume fails.
    r = run(c.execute_with_approval(p, "approval-does-not-exist", challenge=ch, votes=v))
    assert not r.executed and ex.count() == 0


def test_denied_approval_cannot_execute():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _escalating_proposal()
    ch = run(c.issue_challenge(p)); v = _votes(pool, c, p, ch)
    rid = run(c.request_approval(p))
    assert run(c.deny_approval(rid))
    assert not run(c.execute_with_approval(p, rid, challenge=ch, votes=v)).executed
    assert ex.count() == 0


# ---- negative: substitution / tamper after approval+consensus ----

def test_changed_payload_after_approval_and_consensus_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _escalating_proposal()
    ch = run(c.issue_challenge(p)); v = _votes(pool, c, p, ch)
    rid = run(_approved(c, p))
    # Tamper the payload after approval+consensus were bound to the original.
    tampered = Agent("agent/intern").propose(
        "transfer_resource", resource="acct-1", payload={"amount": 999999},
        transaction_id=p.transaction_id, idempotency_key=p.idempotency_key,
        nonce=p.nonce, correlation_id=p.correlation_id)
    assert not run(c.execute_with_approval(tampered, rid, challenge=ch, votes=v)).executed
    assert ex.count() == 0


def test_approval_for_other_action_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _escalating_proposal()
    ch = run(c.issue_challenge(p)); v = _votes(pool, c, p, ch)
    # Approve a *different* operation, then try to spend it on p.
    other = Agent("agent/intern").propose("transfer_resource", resource="acct-2",
                                           payload={"amount": 1000})
    rid_other = run(_approved(c, other))
    assert not run(c.execute_with_approval(p, rid_other, challenge=ch, votes=v)).executed
    assert ex.count() == 0


# ---- negative: reuse / replay ----

def test_reused_approval_denies_second_execution():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _escalating_proposal()
    ch = run(c.issue_challenge(p)); v = _votes(pool, c, p, ch)
    rid = run(_approved(c, p))
    assert run(c.execute_with_approval(p, rid, challenge=ch, votes=v)).executed
    # Reuse the same approval with a *fresh* challenge/votes -> approval is single-use.
    ch2 = run(c.issue_challenge(p)); v2 = _votes(pool, c, p, ch2)
    assert not run(c.execute_with_approval(p, rid, challenge=ch2, votes=v2)).executed
    assert ex.count() == 1


def test_replayed_challenge_denies_in_escalate_path():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _escalating_proposal()
    ch = run(c.issue_challenge(p)); v = _votes(pool, c, p, ch)
    rid = run(_approved(c, p))
    assert run(c.execute_with_approval(p, rid, challenge=ch, votes=v)).executed
    # New approval, but reuse the consumed challenge -> challenge single-use blocks.
    rid2 = run(_approved(c, p))
    assert not run(c.execute_with_approval(p, rid2, challenge=ch, votes=v)).executed
    assert ex.count() == 1


# ============================================================================
# Path B — consensus + CONSTRAIN (re-consensus over the clamped body)
# ============================================================================

def _overcap_proposal(amount=10000, **kw):
    # agent/ops holds transfer max_amount=5000 -> amount above cap -> CONSTRAIN.
    return Agent("agent/ops").propose("transfer_resource", resource="acct-1",
                                      payload={"amount": amount}, **kw)


async def _round_one(c, pool, p):
    """Original consensus over the over-cap body -> RECONSENSUS_REQUIRED."""
    ch1 = await c.issue_challenge(p)
    v1 = pool.unanimous(ch1, action=p.action, payload=p.payload, actor=p.actor,
                        resource=p.resource, policy_hash=c.policy_hash)
    r1 = await c.submit(p, challenge=ch1, votes=v1)
    return ch1, v1, r1


# ---- positive ----

def test_constrain_reconsensus_executes_clamped_body_once():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _overcap_proposal(10000)
    ch1, v1, r1 = run(_round_one(c, pool, p))
    assert r1.verdict == "CONSTRAIN" and r1.status == "RECONSENSUS_REQUIRED"
    assert not r1.executed and ex.count() == 0
    constrained = r1.authorized_payload
    assert constrained == {"amount": 5000}            # clamped to the mandate cap
    # Fresh challenge + fresh votes bound to the constrained body.
    ch2 = run(c.issue_challenge(p, payload=constrained))
    v2 = _votes(pool, c, p, ch2, payload=constrained)
    r2 = run(c.execute_constrained(p, constrained, challenge=ch2, votes=v2))
    assert r2.executed and ex.count() == 1
    assert ex.last().authorized_payload == {"amount": 5000}  # never 10000


def test_constrain_reconsensus_audit_binds_constrained_body():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _overcap_proposal(10000)
    _, _, r1 = run(_round_one(c, pool, p))
    constrained = r1.authorized_payload
    ch2 = run(c.issue_challenge(p, payload=constrained))
    v2 = _votes(pool, c, p, ch2, payload=constrained)
    assert run(c.execute_constrained(p, constrained, challenge=ch2, votes=v2)).executed
    assert AuditLog.verify_chain(c.audit.path)
    entries = [json.loads(l) for l in Path(c.audit.path).read_text().splitlines() if l.strip()]
    kinds = [e.get("kind") for e in entries]
    assert "consensus_verified" in kinds and "challenge_consumed" in kinds and "pre_actuation" in kinds
    # The actuated payload-hash is the constrained body's, not the original's.
    from mcc_core import hash_payload
    pre = [e for e in entries if e.get("kind") == "pre_actuation"][-1]
    assert pre["payload_hash"] == hash_payload({"amount": 5000})
    assert pre["payload_hash"] != hash_payload({"amount": 10000})


# ---- negative: the original consensus cannot execute the constrained body ----

def test_original_votes_cannot_execute_constrained_body():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _overcap_proposal(10000)
    ch1, v1, r1 = run(_round_one(c, pool, p))
    constrained = r1.authorized_payload
    # Fresh challenge for the constrained body, but the ORIGINAL (over-cap) votes.
    ch2 = run(c.issue_challenge(p, payload=constrained))
    assert not run(c.execute_constrained(p, constrained, challenge=ch2, votes=v1)).executed
    assert ex.count() == 0


def test_reused_original_challenge_denies_constrained_execution():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _overcap_proposal(10000)
    ch1, v1, r1 = run(_round_one(c, pool, p))
    constrained = r1.authorized_payload
    v2 = _votes(pool, c, p, ch1, payload=constrained)  # votes over constrained but old challenge nonce
    # Reuse the ORIGINAL challenge (bound to the 10000 payload-hash).
    assert not run(c.execute_constrained(p, constrained, challenge=ch1, votes=v2)).executed
    assert ex.count() == 0


# ---- negative: the original body can never be executed after CONSTRAIN ----

def test_resubmitting_original_body_as_constrained_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _overcap_proposal(10000)
    ch1, v1, _ = run(_round_one(c, pool, p))
    # Try to push the original 10000 through execute_constrained with its own
    # challenge/votes -> authority re-constrains (verdict != ALLOW) -> refused.
    assert not run(c.execute_constrained(p, {"amount": 10000}, challenge=ch1, votes=v1)).executed
    assert ex.count() == 0


# ---- negative: second challenge / payload mismatches ----

def test_second_challenge_bound_to_wrong_payload_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _overcap_proposal(10000)
    _, _, r1 = run(_round_one(c, pool, p))
    constrained = r1.authorized_payload
    ch_wrong = run(c.issue_challenge(p, payload={"amount": 3000}))  # bound to 3000, not 5000
    v2 = _votes(pool, c, p, ch_wrong, payload=constrained)
    assert not run(c.execute_constrained(p, constrained, challenge=ch_wrong, votes=v2)).executed
    assert ex.count() == 0


def test_tampered_constrained_body_after_reconsensus_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _overcap_proposal(10000)
    _, _, r1 = run(_round_one(c, pool, p))
    constrained = r1.authorized_payload                  # {"amount": 5000}
    ch2 = run(c.issue_challenge(p, payload=constrained))
    v2 = _votes(pool, c, p, ch2, payload=constrained)    # consensus over 5000
    # Execute a different body (4000) than the one the consensus/challenge bind to.
    assert not run(c.execute_constrained(p, {"amount": 4000}, challenge=ch2, votes=v2)).executed
    assert ex.count() == 0


# ---- negative: re-consensus quality (threshold / forged / duplicate / expired) ----

def _reconsensus_setup(c, pool, p):
    _, _, r1 = run(_round_one(c, pool, p))
    constrained = r1.authorized_payload
    ch2 = run(c.issue_challenge(p, payload=constrained))
    return constrained, ch2


def test_below_threshold_reconsensus_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _overcap_proposal(10000)
    constrained, ch2 = _reconsensus_setup(c, pool, p)
    v2 = _votes(pool, c, p, ch2, payload=constrained, count=2)
    assert not run(c.execute_constrained(p, constrained, challenge=ch2, votes=v2)).executed
    assert ex.count() == 0


def test_duplicate_evaluator_reconsensus_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _overcap_proposal(10000)
    constrained, ch2 = _reconsensus_setup(c, pool, p)
    one = pool.sign(pool.evaluators[0], ch2, action=p.action, payload=constrained, actor=p.actor,
                    resource=p.resource, policy_hash=c.policy_hash)
    assert not run(c.execute_constrained(p, constrained, challenge=ch2, votes=[one, one, one])).executed
    assert ex.count() == 0


def test_forged_evaluator_reconsensus_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _overcap_proposal(10000)
    constrained, ch2 = _reconsensus_setup(c, pool, p)
    rogue = SigningKey.generate("rogue")
    v2 = _votes(pool, c, p, ch2, payload=constrained, count=2) + [issue_vote(
        rogue, evaluator_id="eval-2", verdict="ALLOW", action=p.action, payload=constrained,
        actor=p.actor, not_before=0, not_after=FAR_FUTURE, resource=p.resource,
        policy_hash=c.policy_hash, nonce=ch2.nonce)]
    assert not run(c.execute_constrained(p, constrained, challenge=ch2, votes=v2)).executed
    assert ex.count() == 0


def test_veto_reconsensus_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _overcap_proposal(10000)
    constrained, ch2 = _reconsensus_setup(c, pool, p)
    v2 = _votes(pool, c, p, ch2, payload=constrained)
    v2[2] = pool.sign(pool.evaluators[2], ch2, action=p.action, payload=constrained, actor=p.actor,
                      resource=p.resource, policy_hash=c.policy_hash, verdict="DENY")
    assert not run(c.execute_constrained(p, constrained, challenge=ch2, votes=v2)).executed
    assert ex.count() == 0


def test_expired_reconsensus_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _overcap_proposal(10000)
    constrained, ch2 = _reconsensus_setup(c, pool, p)
    v2 = [pool.sign(e, ch2, action=p.action, payload=constrained, actor=p.actor, resource=p.resource,
                    policy_hash=c.policy_hash, not_before=0, not_after=1, issued_at=0)
          for e in pool.evaluators]
    assert not run(c.execute_constrained(p, constrained, challenge=ch2, votes=v2)).executed
    assert ex.count() == 0


# ---- negative: replay of a successful re-consensus ----

def test_replayed_reconsensus_denies_second_execution():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _overcap_proposal(10000)
    constrained, ch2 = _reconsensus_setup(c, pool, p)
    v2 = _votes(pool, c, p, ch2, payload=constrained)
    assert run(c.execute_constrained(p, constrained, challenge=ch2, votes=v2)).executed
    # Replay the exact constrained evidence -> single-use challenge + one-time nonce.
    assert not run(c.execute_constrained(p, constrained, challenge=ch2, votes=v2)).executed
    assert ex.count() == 1


# ---- re-consensus does not bypass idempotency / velocity ----

def test_constrained_path_does_not_bypass_idempotency():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p1 = _overcap_proposal(10000, idempotency_key="dup")
    constrained, ch2 = _reconsensus_setup(c, pool, p1)
    v2 = _votes(pool, c, p1, ch2, payload=constrained)
    assert run(c.execute_constrained(p1, constrained, challenge=ch2, votes=v2)).executed
    # Second op, same idempotency key, fresh constrained evidence -> idempotency blocks.
    p2 = _overcap_proposal(10000, idempotency_key="dup")
    constrained2, ch2b = _reconsensus_setup(c, pool, p2)
    v2b = _votes(pool, c, p2, ch2b, payload=constrained2)
    assert not run(c.execute_constrained(p2, constrained2, challenge=ch2b, votes=v2b)).executed
    assert ex.count() == 1


def test_constrained_path_does_not_bypass_velocity():
    pool = EvaluatorPool(3); ex = MockExecutor()
    limit = VelocityLimit(name="cc", window_seconds=3600, max_count=1, aggregate_by=("actor",))
    c = _client(ex, pool, velocity_limits=[limit])
    for _ in range(2):
        p = _overcap_proposal(10000)
        constrained, ch2 = _reconsensus_setup(c, pool, p)
        v2 = _votes(pool, c, p, ch2, payload=constrained)
        run(c.execute_constrained(p, constrained, challenge=ch2, votes=v2))
    assert ex.count() == 1  # second blocked by velocity despite valid re-consensus


# ---- configuration: execute_constrained is consensus-only ----

def test_execute_constrained_requires_consensus_mode():
    ex = MockExecutor(); c = GovernedMCCClient(executor=ex)  # no consensus
    p = _overcap_proposal(10000)
    r = run(c.execute_constrained(p, {"amount": 5000}, challenge=None, votes=None))
    assert not r.executed and ex.count() == 0


# ============================================================================
# Redis-backed challenge consumption is single-use ACROSS instances
# ----------------------------------------------------------------------------
# The challenge registry (not just nonce/idempotency) is Redis-backed, so the
# single-use consume of a gateway-issued challenge holds across MCC instances.
# Each instance keeps its own in-memory nonce registry here, so the replay is
# blocked *specifically by the shared challenge* — proving the challenge state,
# not only the nonce, is durable and multi-instance.
# ============================================================================

def _consensus_instance(executor, pool, key, challenge_registry):
    return GovernedMCCClient(
        executor=executor, consensus_required=True, consensus_threshold=3,
        trusted_evaluators=pool.trusted_keys(), signing_key=key,
        challenge_registry=challenge_registry)


def _shared_challenge_pair(shared, pool, key, ns):
    exA, exB = MockExecutor(), MockExecutor()
    a = _consensus_instance(exA, pool, key, RedisChallengeRegistry(
        shared, namespace=redis_keys.prefix("chal", ns)))
    b = _consensus_instance(exB, pool, key, RedisChallengeRegistry(
        shared, namespace=redis_keys.prefix("chal", ns)))
    return a, b, exA, exB


def _consume_once_then_replay(a, b, pool):
    p = Agent("agent/ops").propose("transfer_resource", resource="acct-1", payload={"amount": 1000})
    ch = run(a.issue_challenge(p))
    v = pool.unanimous(ch, action=p.action, payload=p.payload, actor=p.actor,
                       resource=p.resource, policy_hash=a.policy_hash)
    assert run(a.submit(p, challenge=ch, votes=v)).executed     # instance A consumes the challenge
    r = run(b.submit(p, challenge=ch, votes=v))                 # instance B sees it consumed in Redis
    return r


def test_redis_backed_challenge_single_use_across_instances_fakeredis():
    shared = FakeRedis()
    pool = EvaluatorPool(3)
    key = SigningKey.generate("shared")
    a, b, exA, exB = _shared_challenge_pair(shared, pool, key, {"MCC_ENV": "test"})
    r = _consume_once_then_replay(a, b, pool)
    assert not r.executed and "challenge" in r.reason.lower()
    assert exA.count() == 1 and exB.count() == 0


@pytest.mark.skipif(not os.environ.get("MCC_REDIS_URL"), reason="requires a real Redis (MCC_REDIS_URL)")
def test_real_redis_challenge_single_use_across_instances():
    import uuid

    url = os.environ["MCC_REDIS_URL"]
    pool = EvaluatorPool(3)
    key = SigningKey.generate("shared")
    ns = {"MCC_ENV": "gacombined-" + uuid.uuid4().hex[:8]}
    exA, exB = MockExecutor(), MockExecutor()
    # Two MCC instances, SEPARATE connections to the same real Redis.
    a = _consensus_instance(exA, pool, key, RedisChallengeRegistry(
        build_redis_client(url), namespace=redis_keys.prefix("chal", ns)))
    b = _consensus_instance(exB, pool, key, RedisChallengeRegistry(
        build_redis_client(url), namespace=redis_keys.prefix("chal", ns)))

    async def _flow():
        # Keep every Redis op inside one event loop: redis.asyncio binds a
        # connection to the loop it was first used on.
        p = Agent("agent/ops").propose("transfer_resource", resource="acct-1", payload={"amount": 1000})
        ch = await a.issue_challenge(p)
        v = pool.unanimous(ch, action=p.action, payload=p.payload, actor=p.actor,
                           resource=p.resource, policy_hash=a.policy_hash)
        ra = await a.submit(p, challenge=ch, votes=v)   # A consumes the challenge in Redis
        rb = await b.submit(p, challenge=ch, votes=v)   # B sees it consumed across instances
        return ra, rb

    ra, rb = asyncio.run(_flow())
    assert ra.executed
    assert not rb.executed and "challenge" in rb.reason.lower()
    assert exA.count() == 1 and exB.count() == 0
