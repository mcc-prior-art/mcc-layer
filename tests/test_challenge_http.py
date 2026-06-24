"""End-to-end HTTP proof of the consensus challenge / nonce handshake.

The gateway issues the one-time nonce inside a challenge (clients never generate
it). A full flow over real HTTP (FastAPI TestClient):

    POST /consensus/challenge  -> {challenge_id, nonce, binding...}
    evaluators sign votes bound to that nonce
    POST /consensus/execute {challenge_id, votes} -> EXECUTED, upstream reached

The coordinator runs with require_consensus=True AND require_challenge=True, so:
* a valid challenge-backed 3-of-3 reaches the downstream exactly once;
* reused / expired / unknown challenges and every binding mismatch are denied
  and never forwarded;
* a client that supplies its own nonce (no challenge) cannot actuate.
"""

import tempfile
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcc_core import (
    ApprovalService,
    AuditLog,
    ChallengeService,
    ConsensusPolicy,
    ConsensusVerifier,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryApprovalRegistry,
    InMemoryChallengeRegistry,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryRevocationRegistry,
    InMemoryVelocityRegistry,
    ProfileRegistry,
    SigningKey,
    issue_vote,
)

from gateway.governance_api import mount_consensus_routes
from gateway.governance_service import GovernanceService
from gateway.trust import TrustSet

AGENT = {"x-api-key": "agent-key"}
ACTION = "generic_op"
CTX = {"value": 1}
POLICY_HASH = "sha256:p"


def build(threshold=3, *, challenge_registry=None):
    evals = [SigningKey.generate(f"eval-{i}") for i in range(3)]
    trusted = {k.kid: k.public_key() for k in evals}
    verifier = ConsensusVerifier(trusted_keys=trusted, policy=ConsensusPolicy(threshold=threshold))
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc", audience="gate",
                            policy_id="p", policy_hash=POLICY_HASH, token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH)
    audit = AuditLog(str(Path(tempfile.mkdtemp(prefix="mcc-chal-http-")) / "a.jsonl"))
    challenges = ChallengeService(challenge_registry or InMemoryChallengeRegistry())
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=audit,
        profiles=ProfileRegistry.default_pilot(),
        revocation_registry=InMemoryRevocationRegistry(),
        approvals=ApprovalService(InMemoryApprovalRegistry(), SigningKey.generate("apr")),
        consensus_verifier=verifier, require_consensus=True,
        challenges=challenges, require_challenge=True)
    calls = []

    async def upstream(action, payload):
        calls.append((action, payload)); return {"ok": True}

    svc = GovernanceService(engine=engine, coordinator=coord, trust_set=TrustSet(),
                            revocation_registry=InMemoryRevocationRegistry(),
                            approvals=coord.approvals, upstream=upstream, policy_hash=POLICY_HASH,
                            consensus_verifier=verifier, challenge_service=challenges)
    app = FastAPI()
    mount_consensus_routes(app, svc, api_key="agent-key", operator_key="op-key")
    return evals, TestClient(app), calls, challenges


def get_challenge(client, *, actor="agent/x", resource="res-1", action=ACTION, context=None,
                  ttl=None):
    body = {"actor": actor, "action": action, "resource": resource,
            "context": CTX if context is None else context}
    if ttl is not None:
        body["ttl_seconds"] = ttl
    return client.post("/consensus/challenge", headers=AGENT, json=body).json()


def votes_for(evals, ch, *, actor="agent/x", verdicts=("ALLOW", "ALLOW", "ALLOW"),
              payload=CTX, action=ACTION, resource=None, policy_hash=None, nonce=None):
    return [issue_vote(evals[i], evaluator_id=f"eval-{i}", verdict=verdicts[i], action=action,
                       payload=payload, actor=actor, not_before=0, not_after=4_000_000_000,
                       resource=resource if resource is not None else ch["resource"],
                       policy_hash=policy_hash if policy_hash is not None else ch["policy_hash"],
                       nonce=nonce if nonce is not None else ch["nonce"])
            for i in range(len(verdicts))]


def execute(client, ch, votes, *, actor="agent/x", resource="res-1", idem="op-1"):
    return client.post("/consensus/execute", headers=AGENT, json={
        "votes": votes, "actor": actor, "action": ACTION, "resource": resource,
        "context": CTX, "idempotency_key": idem, "challenge_id": ch["challenge_id"]})


# ---- Challenge issuance ----

def test_challenge_has_gateway_nonce_and_binding():
    evals, client, _, _ = build()
    ch = get_challenge(client)
    assert ch["challenge_id"].startswith("chal-")
    assert len(ch["nonce"]) >= 32
    assert ch["action"] == ACTION and ch["actor"] == "agent/x" and ch["resource"] == "res-1"
    assert ch["policy_hash"] == POLICY_HASH and ch["payload_hash"].startswith("sha256:")
    assert ch["expires_at"] > ch["issued_at"]


# ---- The one path that actuates ----

def test_valid_challenge_flow_reaches_downstream():
    evals, client, calls, _ = build()
    ch = get_challenge(client)
    r = execute(client, ch, votes_for(evals, ch))
    assert r.json()["status"] == "EXECUTED"
    assert len(calls) == 1 and calls[0][0] == ACTION


# ---- Reuse / expiry / unknown ----

def test_reused_challenge_denied():
    evals, client, calls, _ = build()
    ch = get_challenge(client)
    assert execute(client, ch, votes_for(evals, ch), idem="op-1").json()["status"] == "EXECUTED"
    # Same challenge, fresh votes/idem -> the challenge is spent (CONSUMED).
    r = execute(client, ch, votes_for(evals, ch), idem="op-2")
    assert r.json()["status"] == "BLOCKED"
    assert len(calls) == 1


def test_unknown_challenge_denied():
    evals, client, calls, _ = build()
    ch = get_challenge(client)
    ch_bad = dict(ch, challenge_id="chal-does-not-exist")
    r = execute(client, ch_bad, votes_for(evals, ch))
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_expired_challenge_denied():
    evals, client, calls, challenges = build()
    ch = get_challenge(client, ttl=1)
    # Force expiry by mutating the stored record's window (no sleep).
    rec = challenges.registry._records[ch["challenge_id"]]
    rec.expires_at = int(time.time()) - 1
    r = execute(client, ch, votes_for(evals, ch))
    assert r.json()["status"] == "BLOCKED" and calls == []


# ---- Binding mismatches: votes that don't match the issued challenge ----

def test_votes_wrong_nonce_denied():
    evals, client, calls, _ = build()
    ch = get_challenge(client)
    r = execute(client, ch, votes_for(evals, ch, nonce="client-picked-nonce"))
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_votes_wrong_action_denied():
    evals, client, calls, _ = build()
    ch = get_challenge(client)
    r = execute(client, ch, votes_for(evals, ch, action="other_op"))
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_votes_wrong_actor_denied():
    evals, client, calls, _ = build()
    ch = get_challenge(client)
    r = execute(client, ch, votes_for(evals, ch, actor="agent/evil"))
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_votes_wrong_resource_denied():
    evals, client, calls, _ = build()
    ch = get_challenge(client)
    r = execute(client, ch, votes_for(evals, ch, resource="res-evil"))
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_votes_wrong_payload_denied():
    evals, client, calls, _ = build()
    ch = get_challenge(client)
    r = execute(client, ch, votes_for(evals, ch, payload={"value": 999}))
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_votes_wrong_policy_hash_denied():
    evals, client, calls, _ = build()
    ch = get_challenge(client)
    r = execute(client, ch, votes_for(evals, ch, policy_hash="sha256:other"))
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_below_threshold_denied():
    evals, client, calls, _ = build()
    ch = get_challenge(client)
    r = execute(client, ch, votes_for(evals, ch)[:2])
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_veto_denied():
    evals, client, calls, _ = build()
    ch = get_challenge(client)
    r = execute(client, ch, votes_for(evals, ch, verdicts=("ALLOW", "ALLOW", "DENY")))
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_forged_vote_denied():
    evals, client, calls, _ = build()
    ch = get_challenge(client)
    rogue = SigningKey.generate("rogue")
    votes = votes_for(evals, ch)[:2] + [
        issue_vote(rogue, evaluator_id="eval-2", verdict="ALLOW", action=ACTION, payload=CTX,
                   actor="agent/x", not_before=0, not_after=4_000_000_000,
                   resource=ch["resource"], policy_hash=ch["policy_hash"], nonce=ch["nonce"])]
    r = execute(client, ch, votes)
    assert r.json()["status"] == "BLOCKED" and calls == []


# ---- Client cannot self-issue the nonce ----

def test_client_supplied_nonce_without_challenge_denied():
    """With require_challenge on, an execute that carries a client nonce and no
    challenge_id cannot actuate — the gateway must have issued the nonce."""
    evals, client, calls, _ = build()
    fake = {"resource": "res-1", "policy_hash": POLICY_HASH, "nonce": "client-picked"}
    votes = votes_for(evals, fake)
    r = client.post("/consensus/execute", headers=AGENT, json={
        "votes": votes, "actor": "agent/x", "action": ACTION, "resource": "res-1",
        "context": CTX, "idempotency_key": "op-1", "nonce": "client-picked"})
    assert r.json()["status"] == "BLOCKED" and calls == []
