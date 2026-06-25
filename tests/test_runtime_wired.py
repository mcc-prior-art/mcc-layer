"""Phase 1 — the full governance stack wired into main.py:/evaluate.

When an evaluator trust set is configured, /evaluate routes through:
challenge issuance -> policy decision -> N-of-M quorum over cryptographically
verified votes from DISTINCT TRUSTED evaluator identities -> ExecutionGate
(signature + binding + one-time nonce consume) -> challenge single-use consume
-> hash-chain audit. Every missing or invalid condition fails closed -> DENY.

(Verified votes are NOT a guarantee of evaluator independence — that is a
deployment/governance property, asserted in RUNTIME_VALIDATION_RECORD.md.)
"""

import asyncio
import json
import time

import pytest

import main
from mcc_core import SigningKey, issue_vote

run = asyncio.run
FUTURE = 4_000_000_000


def _trust_file(tmp_path, evals):
    cfg = {"issuers": [
        {"issuer_id": f"e{i}", "enabled": True,
         "keys": [{"kid": e.kid, "public_key_b64": e.public_key_b64(), "not_after": None}]}
        for i, e in enumerate(evals)]}
    p = tmp_path / "evaluators.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    return p


def _activate(tmp_path, monkeypatch, *, threshold=3, n_eval=3, token_ttl=60):
    """Build a governance-ACTIVE MCC without disturbing the global one.
    monkeypatch auto-restores settings after the test."""
    evals = [SigningKey.generate(f"eval-{i}") for i in range(n_eval)]
    monkeypatch.setattr(main.settings, "use_opa", False)
    monkeypatch.setattr(main.settings, "consensus_trust_config", str(_trust_file(tmp_path, evals)))
    monkeypatch.setattr(main.settings, "consensus_threshold", threshold)
    monkeypatch.setattr(main.settings, "challenge_ttl_seconds", 120)
    monkeypatch.setattr(main.settings, "token_ttl_seconds", token_ttl)
    monkeypatch.setattr(main.settings, "audit_log_path", str(tmp_path / "audit.jsonl"))
    mcc = main.MCC()
    assert mcc.governance is not None
    return mcc, evals


def _challenge(mcc, *, amount=100, resource="res-1", sid="s1", intent="send_payment"):
    return run(mcc.issue_challenge("t", main.ChallengeRequest(
        session_id=sid, intent=intent, args={"amount": amount}, resource=resource)))


def _votes(evals, ch, *, verdicts=None, payload=None, actor=None, resource=None,
           policy_hash=None, nonce=None, n=None):
    verdicts = verdicts or ["ALLOW"] * len(evals)
    n = n if n is not None else len(verdicts)
    return [issue_vote(
        evals[i], evaluator_id=f"eval-{i}", verdict=verdicts[i], action=ch.action,
        payload=payload if payload is not None else {"amount": 100},
        actor=actor or ch.actor, not_before=0, not_after=FUTURE,
        resource=resource if resource is not None else ch.resource,
        policy_hash=policy_hash if policy_hash is not None else ch.policy_hash,
        nonce=nonce if nonce is not None else ch.nonce) for i in range(n)]


def _decide(mcc, ch, votes, *, amount=100, resource="res-1", sid="s1"):
    return run(mcc.evaluate("t", main.EvaluateRequest(
        session_id=sid, intent="send_payment", args={"amount": amount}, resource=resource,
        challenge_id=ch.challenge_id if ch else None, votes=votes)))


# ---- The one path that authorizes ----

def test_valid_quorum_allows_with_token(tmp_path, monkeypatch):
    mcc, evals = _activate(tmp_path, monkeypatch)
    ch = _challenge(mcc)
    out = _decide(mcc, ch, _votes(evals, ch))
    assert out.decision.value == "ALLOW"
    assert out.decision_token is not None
    assert out.quorum and out.quorum["verified"] is True
    # Honesty: evidence must NOT claim independence.
    assert "not a guarantee of evaluator independence" in out.quorum["claim"].lower()


def test_challenge_endpoint_binds_the_operation(tmp_path, monkeypatch):
    mcc, evals = _activate(tmp_path, monkeypatch)
    ch = _challenge(mcc, resource="res-9")
    assert ch.action == "send_payment" and ch.actor == "agent/s1" and ch.resource == "res-9"
    assert ch.policy_hash and ch.nonce and len(ch.nonce) >= 32


# ---- Fail-closed paths (each must DENY and issue no token) ----

def test_insufficient_quorum_denies(tmp_path, monkeypatch):
    mcc, evals = _activate(tmp_path, monkeypatch)
    ch = _challenge(mcc)
    out = _decide(mcc, ch, _votes(evals, ch, verdicts=["ALLOW", "ALLOW"]))
    assert out.decision.value == "DENY" and out.decision_token is None


def test_veto_denies(tmp_path, monkeypatch):
    mcc, evals = _activate(tmp_path, monkeypatch)
    ch = _challenge(mcc)
    out = _decide(mcc, ch, _votes(evals, ch, verdicts=["ALLOW", "ALLOW", "DENY"]))
    assert out.decision.value == "DENY"


def test_no_challenge_or_votes_denies(tmp_path, monkeypatch):
    mcc, evals = _activate(tmp_path, monkeypatch)
    out = _decide(mcc, None, None)
    assert out.decision.value == "DENY" and "fail-closed" in out.reason.lower()


def test_replayed_nonce_denies(tmp_path, monkeypatch):
    mcc, evals = _activate(tmp_path, monkeypatch)
    ch = _challenge(mcc)
    votes = _votes(evals, ch)
    first = _decide(mcc, ch, votes)
    second = _decide(mcc, ch, votes)
    assert first.decision.value == "ALLOW"
    assert second.decision.value == "DENY"  # challenge consumed / nonce single-use


def test_duplicate_evaluator_identity_denies(tmp_path, monkeypatch):
    mcc, evals = _activate(tmp_path, monkeypatch)
    ch = _challenge(mcc)
    one = _votes([evals[0]], ch)[0]
    out = _decide(mcc, ch, [one, one, one])  # same identity 3x -> counted once
    assert out.decision.value == "DENY"


def test_non_member_evaluator_denies(tmp_path, monkeypatch):
    mcc, evals = _activate(tmp_path, monkeypatch)
    ch = _challenge(mcc)
    rogue = SigningKey.generate("rogue")
    votes = _votes(evals, ch, n=2) + _votes([rogue], ch)  # rogue not in trust set
    out = _decide(mcc, ch, votes)
    assert out.decision.value == "DENY"


def test_forged_signature_denies(tmp_path, monkeypatch):
    mcc, evals = _activate(tmp_path, monkeypatch)
    ch = _challenge(mcc)
    votes = _votes(evals, ch)
    votes[2]["verdict"] = "DENY"  # tamper after signing -> signature breaks
    out = _decide(mcc, ch, votes)
    assert out.decision.value == "DENY"


def test_challenge_payload_mismatch_denies(tmp_path, monkeypatch):
    mcc, evals = _activate(tmp_path, monkeypatch)
    ch = _challenge(mcc)
    out = _decide(mcc, ch, _votes(evals, ch, payload={"amount": 999}))
    assert out.decision.value == "DENY"


def test_unknown_challenge_denies(tmp_path, monkeypatch):
    mcc, evals = _activate(tmp_path, monkeypatch)
    ch = _challenge(mcc)
    votes = _votes(evals, ch)
    ch.challenge_id = "chal-does-not-exist"
    out = _decide(mcc, ch, votes)
    assert out.decision.value == "DENY" and "challenge" in out.reason.lower()


def test_expired_challenge_denies(tmp_path, monkeypatch):
    mcc, evals = _activate(tmp_path, monkeypatch)
    ch = _challenge(mcc)
    votes = _votes(evals, ch)
    # Force the stored challenge past its window (no sleep).
    rec = mcc.governance.challenges.registry._records[ch.challenge_id]
    rec.expires_at = int(time.time()) - 1
    out = _decide(mcc, ch, votes)
    assert out.decision.value == "DENY"


def test_expired_token_denies(tmp_path, monkeypatch):
    # The token is issued and verified within one /evaluate call, so it can only
    # be expired by verifying it past its window. Drive the wired coordinator/gate
    # at a time past the token's expiry: the ExecutionGate rejects it -> no
    # actuation (DENY). Token TTL=1 so iat+100 is well past exp.
    from mcc_core import ActuationStatus

    mcc, evals = _activate(tmp_path, monkeypatch, token_ttl=1)
    ch = _challenge(mcc)
    votes = _votes(evals, ch)
    token = mcc.governance.engine.issue_token(
        verdict="ALLOW", subject=ch.actor, action=ch.action, payload={"amount": 100},
        nonce=ch.nonce, actor_id=ch.actor, resource_id=ch.resource,
        auth_claims={"challenge_id": ch.challenge_id})

    async def grant():
        return "x"

    res = run(mcc.governance.coordinator.enforce(
        token=token, action=ch.action, payload={"amount": 100}, executor=grant,
        request_binding={"actor_id": ch.actor, "resource_id": ch.resource},
        consensus_votes=votes, now=int(token["iat"]) + 100))
    assert res.status != ActuationStatus.EXECUTED
    assert "exp" in res.reason.lower() or "gate" in res.reason.lower() or "fail" in res.reason.lower()


# ---- Base mode (no trust set) must not regress ----

def test_base_mode_unchanged_without_trust_set(tmp_path, monkeypatch):
    monkeypatch.setattr(main.settings, "use_opa", False)
    monkeypatch.setattr(main.settings, "consensus_trust_config", "")
    monkeypatch.setattr(main.settings, "audit_log_path", str(tmp_path / "audit.jsonl"))
    mcc = main.MCC()
    assert mcc.governance is None
    out = run(mcc.evaluate("t", main.EvaluateRequest(
        session_id="s1", intent="send_payment", args={"amount": 100})))
    # Base policy-decision layer still issues an ALLOW + token (no quorum required).
    assert out.decision.value == "ALLOW" and out.decision_token is not None
    assert out.quorum is None


def test_require_governance_without_trust_refuses_startup(tmp_path, monkeypatch):
    monkeypatch.setattr(main.settings, "consensus_trust_config", "")
    monkeypatch.setattr(main.settings, "require_governance", True)
    monkeypatch.setattr(main.settings, "audit_log_path", str(tmp_path / "audit.jsonl"))
    with pytest.raises(RuntimeError, match="refusing fail-open"):
        main.MCC()
