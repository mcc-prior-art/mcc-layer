"""Consensus-required governed-agent path.

Agent proposal -> gateway-issued challenge -> independently signed N-of-M votes
-> ConsensusVerifier -> authority -> gate (nonce) -> idempotency/velocity ->
audit -> executor. Consensus is an ADDITIONAL required predicate: it never
bypasses authority, approval, nonce, idempotency, velocity, the gate, or audit.

Uses the real ChallengeService / ConsensusVerifier / EnforcementCoordinator —
no demo-only verifier.
"""

import asyncio
import json
from pathlib import Path

import pytest

from mcc_core import AuditLog, SigningKey, VelocityLimit, issue_vote

from examples.governed_agent.agent import Agent
from examples.governed_agent.consensus_support import FAR_FUTURE, EvaluatorPool
from examples.governed_agent.mcc_client import GovernedMCCClient
from examples.governed_agent.mock_executor import MockExecutor

run = asyncio.run


def _client(executor, pool, *, threshold=3, **kw):
    return GovernedMCCClient(
        executor=executor, consensus_required=True, consensus_threshold=threshold,
        trusted_evaluators=pool.trusted_keys(), **kw)


def _votes(pool, client, p, ch, **kw):
    return pool.unanimous(ch, action=p.action, payload=p.payload, actor=p.actor,
                          resource=p.resource, policy_hash=client.policy_hash, **kw)


def _propose(actor="agent/ops", amount=1000, **kw):
    return Agent(actor).propose("transfer_resource", resource="acct-1",
                                payload={"amount": amount}, **kw)


async def _challenge_and_votes(client, pool, p, **kw):
    ch = await client.issue_challenge(p)
    return ch, _votes(pool, client, p, ch, **kw)


# ---- positive ----

def test_valid_threshold_consensus_executes_once():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _propose()
    ch, v = run(_challenge_and_votes(c, pool, p))
    r = run(c.submit(p, challenge=ch, votes=v))
    assert r.executed and ex.count() == 1


def test_audit_linkage_under_consensus():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _propose()
    ch, v = run(_challenge_and_votes(c, pool, p))
    r = run(c.submit(p, challenge=ch, votes=v))
    assert r.executed and AuditLog.verify_chain(c.audit.path)
    kinds = [json.loads(l)["kind"] for l in Path(c.audit.path).read_text().splitlines() if l.strip()]
    assert "consensus_verified" in kinds and "challenge_consumed" in kinds and "pre_actuation" in kinds


# ---- negative consensus paths (all fail closed, executor never called) ----

def test_below_threshold_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _propose()
    ch, v = run(_challenge_and_votes(c, pool, p, count=2))
    assert not run(c.submit(p, challenge=ch, votes=v)).executed and ex.count() == 0


def test_untrusted_evaluator_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _propose(); ch = run(c.issue_challenge(p))
    rogue = SigningKey.generate("rogue")
    v = _votes(pool, c, p, ch, count=2) + [issue_vote(
        rogue, evaluator_id="eval-2", verdict="ALLOW", action=p.action, payload=p.payload,
        actor=p.actor, not_before=0, not_after=FAR_FUTURE, resource=p.resource,
        policy_hash=c.policy_hash, nonce=ch.nonce)]
    assert not run(c.submit(p, challenge=ch, votes=v)).executed and ex.count() == 0


def test_duplicate_evaluator_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _propose(); ch = run(c.issue_challenge(p))
    one = pool.sign(pool.evaluators[0], ch, action=p.action, payload=p.payload, actor=p.actor,
                    resource=p.resource, policy_hash=c.policy_hash)
    assert not run(c.submit(p, challenge=ch, votes=[one, one, one])).executed and ex.count() == 0


def test_vote_bound_to_wrong_challenge_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _propose(); ch = run(c.issue_challenge(p))
    # votes carry a different nonce than the issued challenge
    v = [pool.sign(e, ch, action=p.action, payload=p.payload, actor=p.actor, resource=p.resource,
                   policy_hash=c.policy_hash, nonce="some-other-nonce") for e in pool.evaluators]
    assert not run(c.submit(p, challenge=ch, votes=v)).executed and ex.count() == 0


def test_vote_bound_to_wrong_action_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _propose(); ch = run(c.issue_challenge(p))
    v = [pool.sign(e, ch, action="other_action", payload=p.payload, actor=p.actor,
                   resource=p.resource, policy_hash=c.policy_hash) for e in pool.evaluators]
    assert not run(c.submit(p, challenge=ch, votes=v)).executed and ex.count() == 0


def test_vote_bound_to_wrong_payload_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _propose(); ch = run(c.issue_challenge(p))
    v = [pool.sign(e, ch, action=p.action, payload={"amount": 999999}, actor=p.actor,
                   resource=p.resource, policy_hash=c.policy_hash) for e in pool.evaluators]
    assert not run(c.submit(p, challenge=ch, votes=v)).executed and ex.count() == 0


def test_vote_bound_to_wrong_actor_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _propose(); ch = run(c.issue_challenge(p))
    v = [pool.sign(e, ch, action=p.action, payload=p.payload, actor="agent/someone-else",
                   resource=p.resource, policy_hash=c.policy_hash) for e in pool.evaluators]
    assert not run(c.submit(p, challenge=ch, votes=v)).executed and ex.count() == 0


def test_expired_vote_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _propose(); ch = run(c.issue_challenge(p))
    v = [pool.sign(e, ch, action=p.action, payload=p.payload, actor=p.actor, resource=p.resource,
                   policy_hash=c.policy_hash, not_before=0, not_after=1, issued_at=0)
         for e in pool.evaluators]
    assert not run(c.submit(p, challenge=ch, votes=v)).executed and ex.count() == 0


def test_veto_denies():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _propose(); ch = run(c.issue_challenge(p))
    v = _votes(pool, c, p, ch)
    v[2] = pool.sign(pool.evaluators[2], ch, action=p.action, payload=p.payload, actor=p.actor,
                     resource=p.resource, policy_hash=c.policy_hash, verdict="DENY")
    assert not run(c.submit(p, challenge=ch, votes=v)).executed and ex.count() == 0


def test_missing_challenge_or_votes_fails_closed():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _propose()
    assert not run(c.submit(p)).executed                       # no challenge/votes
    ch = run(c.issue_challenge(p))
    assert not run(c.submit(p, challenge=ch, votes=[])).executed  # empty votes
    assert ex.count() == 0


def test_replayed_challenge_denied():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _propose()
    ch, v = run(_challenge_and_votes(c, pool, p))
    assert run(c.submit(p, challenge=ch, votes=v)).executed
    # reuse the same challenge + votes -> single-use challenge + one-time nonce
    assert not run(c.submit(p, challenge=ch, votes=v)).executed
    assert ex.count() == 1


# ---- consensus does NOT bypass the rest of the governance path ----

def test_consensus_does_not_bypass_authority_deny():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = Agent("agent/ops").propose("delete_resource", resource="acct-1", payload={})
    ch = run(c.issue_challenge(p))
    v = pool.unanimous(ch, action=p.action, payload=p.payload, actor=p.actor,
                       resource=p.resource, policy_hash=c.policy_hash)
    r = run(c.submit(p, challenge=ch, votes=v))
    assert r.verdict == "DENY" and not r.executed and ex.count() == 0


def test_consensus_does_not_bypass_escalate():
    # A valid 3-of-3 does not turn a no-mandate action into an ALLOW.
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p = _propose(actor="agent/intern")
    ch = run(c.issue_challenge(p))
    v = _votes(pool, c, p, ch)
    r = run(c.submit(p, challenge=ch, votes=v))
    assert r.verdict == "ESCALATE" and not r.executed and ex.count() == 0


def test_consensus_does_not_bypass_idempotency():
    pool = EvaluatorPool(3); ex = MockExecutor(); c = _client(ex, pool)
    p1 = _propose(idempotency_key="dup")
    ch1, v1 = run(_challenge_and_votes(c, pool, p1))
    assert run(c.submit(p1, challenge=ch1, votes=v1)).executed
    # second op, same idempotency key, fresh challenge/votes -> idempotency blocks
    p2 = _propose(idempotency_key="dup")
    ch2, v2 = run(_challenge_and_votes(c, pool, p2))
    assert not run(c.submit(p2, challenge=ch2, votes=v2)).executed
    assert ex.count() == 1


def test_consensus_does_not_bypass_velocity():
    pool = EvaluatorPool(3); ex = MockExecutor()
    limit = VelocityLimit(name="c2", window_seconds=3600, max_count=2, aggregate_by=("actor",))
    c = _client(ex, pool, velocity_limits=[limit])
    for _ in range(3):
        p = _propose()
        ch, v = run(_challenge_and_votes(c, pool, p))
        run(c.submit(p, challenge=ch, votes=v))
    assert ex.count() == 2  # third blocked by velocity despite valid consensus


# ---- fail-closed configuration ----

def test_consensus_required_without_trust_refuses_startup():
    with pytest.raises(ValueError):
        GovernedMCCClient(executor=MockExecutor(), consensus_required=True, trusted_evaluators={})


def test_unsatisfiable_threshold_refuses_startup():
    pool = EvaluatorPool(2)
    with pytest.raises(ValueError):
        GovernedMCCClient(executor=MockExecutor(), consensus_required=True,
                          consensus_threshold=3, trusted_evaluators=pool.trusted_keys())


def test_non_consensus_mode_still_works():
    ex = MockExecutor(); c = GovernedMCCClient(executor=ex)  # default: no consensus
    r = run(c.submit(_propose()))
    assert r.executed and ex.count() == 1
