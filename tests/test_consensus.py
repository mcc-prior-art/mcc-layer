"""Multi-Context Consensus tests.

N-of-M independent signed evaluations. A forged, mismatched, expired, or
duplicate-evaluator vote is ignored; a trusted DENY vetoes; below threshold
denies. No single evaluator (or key) can manufacture consensus.
"""

from mcc_core import (
    ConsensusPolicy,
    ConsensusVerifier,
    SigningKey,
    Verdict,
    hash_action,
    hash_payload,
    issue_vote,
)

NOW = 1_780_000_000
ACTION = "deploy_release"
PAYLOAD = {"target": "cluster-1", "environment": "prod"}
ACTOR = "agent/ops"


def evaluators(n=3):
    keys = [SigningKey.generate(f"eval-{i}") for i in range(n)]
    trusted = {k.kid: k.public_key() for k in keys}
    return keys, trusted


def vote(key, evaluator_id, verdict=Verdict.ALLOW, *, action=ACTION, payload=PAYLOAD,
         actor=ACTOR, nbf=NOW - 10, exp=NOW + 3600):
    return issue_vote(key, evaluator_id=evaluator_id, verdict=verdict, action=action,
                      payload=payload, actor=actor, not_before=nbf, not_after=exp, issued_at=NOW)


def verifier(trusted, threshold=3, **over):
    return ConsensusVerifier(trusted_keys=trusted, policy=ConsensusPolicy(threshold=threshold, **over))


def decide(trusted, votes, threshold=3, **over):
    return verifier(trusted, threshold, **over).verify(
        votes, action=ACTION, payload=PAYLOAD, actor=ACTOR, now=NOW)


# ---- Agreement ----

def test_unanimous_3_of_3_allows():
    keys, trusted = evaluators(3)
    votes = [vote(keys[i], f"eval-{i}") for i in range(3)]
    r = decide(trusted, votes, threshold=3)
    assert r.verdict == Verdict.ALLOW
    assert r.agreement == 3
    assert sorted(r.allow_evaluators) == ["eval-0", "eval-1", "eval-2"]


def test_exactly_threshold_allows():
    keys, trusted = evaluators(3)
    votes = [vote(keys[0], "eval-0"), vote(keys[1], "eval-1")]
    assert decide(trusted, votes, threshold=2).verdict == Verdict.ALLOW


def test_below_threshold_denies():
    keys, trusted = evaluators(3)
    votes = [vote(keys[0], "eval-0"), vote(keys[1], "eval-1")]  # only 2 of 3
    r = decide(trusted, votes, threshold=3)
    assert r.verdict == Verdict.DENY
    assert r.agreement == 2


# ---- Veto ----

def test_any_deny_vetoes():
    keys, trusted = evaluators(3)
    votes = [vote(keys[0], "eval-0"), vote(keys[1], "eval-1"),
             vote(keys[2], "eval-2", verdict=Verdict.DENY)]
    r = decide(trusted, votes, threshold=3)
    assert r.verdict == Verdict.DENY
    assert "VETO" in r.reason


def test_escalate_vote_counts_as_not_allow():
    keys, trusted = evaluators(3)
    votes = [vote(keys[0], "eval-0"), vote(keys[1], "eval-1"),
             vote(keys[2], "eval-2", verdict=Verdict.ESCALATE)]
    assert decide(trusted, votes, threshold=3).verdict == Verdict.DENY  # only 2 ALLOW


# ---- Forgery / trust ----

def test_untrusted_evaluator_ignored():
    keys, trusted = evaluators(3)
    rogue = SigningKey.generate("rogue")
    votes = [vote(keys[0], "eval-0"), vote(keys[1], "eval-1"),
             vote(rogue, "eval-rogue")]  # untrusted key
    r = decide(trusted, votes, threshold=3)
    assert r.verdict == Verdict.DENY  # only 2 trusted ALLOW
    assert r.rejected_votes == 1


def test_tampered_vote_ignored():
    keys, trusted = evaluators(3)
    v = vote(keys[2], "eval-2")
    v["verdict"] = "DENY"  # tamper after signing -> signature breaks
    votes = [vote(keys[0], "eval-0"), vote(keys[1], "eval-1"), v]
    r = decide(trusted, votes, threshold=3)
    assert r.verdict == Verdict.DENY and r.rejected_votes == 1


def test_single_evaluator_cannot_manufacture_consensus():
    keys, trusted = evaluators(3)
    # The same evaluator submits three ballots — counted once.
    votes = [vote(keys[0], "eval-0"), vote(keys[0], "eval-0"), vote(keys[0], "eval-0")]
    r = decide(trusted, votes, threshold=3)
    assert r.verdict == Verdict.DENY
    assert r.agreement == 1


# ---- Operation binding ----

def test_vote_for_wrong_action_ignored():
    keys, trusted = evaluators(3)
    votes = [vote(keys[0], "eval-0"), vote(keys[1], "eval-1"),
             vote(keys[2], "eval-2", action="delete_everything")]
    assert decide(trusted, votes, threshold=3).verdict == Verdict.DENY


def test_vote_for_wrong_payload_ignored():
    keys, trusted = evaluators(3)
    votes = [vote(keys[0], "eval-0"), vote(keys[1], "eval-1"),
             vote(keys[2], "eval-2", payload={"target": "other", "environment": "prod"})]
    assert decide(trusted, votes, threshold=3).verdict == Verdict.DENY


def test_vote_for_wrong_actor_ignored():
    keys, trusted = evaluators(3)
    votes = [vote(keys[0], "eval-0"), vote(keys[1], "eval-1"),
             vote(keys[2], "eval-2", actor="agent/someone-else")]
    assert decide(trusted, votes, threshold=3).verdict == Verdict.DENY


def test_expired_vote_ignored():
    keys, trusted = evaluators(3)
    votes = [vote(keys[0], "eval-0"), vote(keys[1], "eval-1"),
             vote(keys[2], "eval-2", exp=NOW - 1)]  # expired
    assert decide(trusted, votes, threshold=3).verdict == Verdict.DENY


# ---- Robustness ----

def test_malformed_votes_deny():
    _, trusted = evaluators(3)
    assert decide(trusted, "not-a-list", threshold=3).verdict == Verdict.DENY


def test_summary_carries_evaluators_no_key_material():
    keys, trusted = evaluators(3)
    votes = [vote(keys[i], f"eval-{i}") for i in range(3)]
    r = decide(trusted, votes, threshold=3)
    s = r.summary()
    assert s["agreement"] == 3 and s["threshold"] == 3
    assert set(s["evaluators"]) == {"eval-0", "eval-1", "eval-2"}
    assert s["consensus_hash"] and "public" not in str(s).lower()
