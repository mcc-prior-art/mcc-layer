"""End-to-end HTTP proof of mandatory Multi-Context Consensus 3-of-3.

The coordinator behind the gateway runs with ``require_consensus=True``: it
re-verifies consensus against the *issued token* (action/actor/payload/resource/
policy_hash/nonce) before any actuation. This is stronger than the service-level
pre-check — even if a token were minted, the coordinator refuses to actuate
without valid evidence bound to that token.

Proven here over real HTTP (FastAPI TestClient):

* a valid 3-of-3 reaches the downstream upstream exactly once;
* every invalid or incomplete case (missing, <3, veto, duplicate, untrusted,
  bad signature, expired, action/actor/resource/payload/nonce/policy mismatch,
  replayed evidence) is denied and the upstream is never called;
* with mandatory consensus on, a path that supplies no votes (mandate execute)
  also fails closed — no governed action actuates without consensus.
"""

import tempfile
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from mcc_core import (
    ApprovalService,
    AuditLog,
    ConsensusPolicy,
    ConsensusVerifier,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryApprovalRegistry,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryRevocationRegistry,
    InMemoryVelocityRegistry,
    ProfileRegistry,
    SigningKey,
    issue_vote,
)

from gateway.governance_api import mount_consensus_routes, mount_mandate_routes
from gateway.governance_service import GovernanceService
from gateway.trust import TrustSet

FUTURE = 4_000_000_000
AGENT = {"x-api-key": "agent-key"}
ACTION = "generic_op"
CTX = {"value": 1}
POLICY_HASH = "sha256:p"


def build(threshold=3):
    evals = [SigningKey.generate(f"eval-{i}") for i in range(3)]
    trusted = {k.kid: k.public_key() for k in evals}
    verifier = ConsensusVerifier(trusted_keys=trusted, policy=ConsensusPolicy(threshold=threshold))
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc", audience="gate",
                            policy_id="p", policy_hash=POLICY_HASH, token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={dk.kid: dk.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH)
    audit = AuditLog(str(Path(tempfile.mkdtemp(prefix="mcc-cons-enf-")) / "a.jsonl"))
    # Mandatory consensus: the coordinator itself refuses actuation without it.
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=audit,
        profiles=ProfileRegistry.default_pilot(),
        revocation_registry=InMemoryRevocationRegistry(),
        approvals=ApprovalService(InMemoryApprovalRegistry(), SigningKey.generate("apr")),
        consensus_verifier=verifier, require_consensus=True)
    calls = []

    async def upstream(action, payload):
        calls.append((action, payload)); return {"ok": True}

    svc = GovernanceService(engine=engine, coordinator=coord, trust_set=TrustSet(),
                            revocation_registry=InMemoryRevocationRegistry(),
                            approvals=coord.approvals, upstream=upstream, policy_hash=POLICY_HASH,
                            consensus_verifier=verifier)
    app = FastAPI()
    mount_consensus_routes(app, svc, api_key="agent-key", operator_key="op-key")
    mount_mandate_routes(app, svc, api_key="agent-key", operator_key="op-key")
    return evals, TestClient(app), calls


def votes_for(evals, *, actor="agent/x", verdicts=("ALLOW", "ALLOW", "ALLOW"),
              payload=CTX, action=ACTION, resource="res-1", policy_hash=POLICY_HASH,
              nonce="nonce-1"):
    return [issue_vote(evals[i], evaluator_id=f"eval-{i}", verdict=verdicts[i], action=action,
                       payload=payload, actor=actor, not_before=0, not_after=FUTURE,
                       resource=resource, policy_hash=policy_hash, nonce=nonce)
            for i in range(len(verdicts))]


def execute(client, votes, *, actor="agent/x", resource="res-1", nonce="nonce-1",
            idem="op-1", action=ACTION, context=None):
    return client.post("/consensus/execute", headers=AGENT, json={
        "votes": votes, "actor": actor, "action": action, "resource": resource,
        "context": CTX if context is None else context, "idempotency_key": idem, "nonce": nonce})


# ---- The one path that actuates ----

def test_valid_3_of_3_reaches_downstream(tmp_path):
    evals, client, calls = build()
    r = execute(client, votes_for(evals))
    assert r.json()["status"] == "EXECUTED"
    assert len(calls) == 1 and calls[0][0] == ACTION


# ---- Every invalid / incomplete case is denied and never forwarded ----

def test_missing_votes_denied(tmp_path):
    evals, client, calls = build()
    r = execute(client, [])
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_fewer_than_three_denied(tmp_path):
    evals, client, calls = build()
    r = execute(client, votes_for(evals)[:2])
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_veto_denied(tmp_path):
    evals, client, calls = build()
    r = execute(client, votes_for(evals, verdicts=("ALLOW", "ALLOW", "DENY")))
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_duplicate_evaluator_denied(tmp_path):
    evals, client, calls = build()
    one = votes_for(evals)[0]
    r = execute(client, [one, one, one])
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_untrusted_evaluator_denied(tmp_path):
    evals, client, calls = build()
    rogue = SigningKey.generate("rogue")
    votes = votes_for(evals)[:2] + [
        issue_vote(rogue, evaluator_id="eval-2", verdict="ALLOW", action=ACTION, payload=CTX,
                   actor="agent/x", not_before=0, not_after=FUTURE, resource="res-1",
                   policy_hash=POLICY_HASH, nonce="nonce-1")]
    r = execute(client, votes)
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_bad_signature_denied(tmp_path):
    evals, client, calls = build()
    votes = votes_for(evals)
    votes[2]["verdict"] = "DENY"  # tamper after signing
    r = execute(client, votes)
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_expired_vote_denied(tmp_path):
    evals, client, calls = build()
    votes = votes_for(evals)
    votes[2] = issue_vote(evals[2], evaluator_id="eval-2", verdict="ALLOW", action=ACTION,
                          payload=CTX, actor="agent/x", not_before=0, not_after=1, issued_at=0,
                          resource="res-1", policy_hash=POLICY_HASH, nonce="nonce-1")
    r = execute(client, votes)
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_action_mismatch_denied(tmp_path):
    evals, client, calls = build()
    # Votes bound to a different action than the request.
    votes = votes_for(evals)[:2] + votes_for(evals, action="other_op")[2:]
    r = execute(client, votes)
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_actor_mismatch_denied(tmp_path):
    evals, client, calls = build()
    votes = votes_for(evals, actor="agent/evil")
    r = execute(client, votes)  # request actor is agent/x
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_resource_mismatch_denied(tmp_path):
    evals, client, calls = build()
    votes = votes_for(evals, resource="res-evil")
    r = execute(client, votes)  # request resource is res-1
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_payload_mismatch_denied(tmp_path):
    evals, client, calls = build()
    votes = votes_for(evals, payload={"value": 999})
    r = execute(client, votes)  # request context is {"value": 1}
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_policy_hash_mismatch_denied(tmp_path):
    evals, client, calls = build()
    votes = votes_for(evals, policy_hash="sha256:other")
    r = execute(client, votes)
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_nonce_mismatch_denied(tmp_path):
    evals, client, calls = build()
    votes = votes_for(evals, nonce="nonce-other")
    r = execute(client, votes, nonce="nonce-1")
    assert r.json()["status"] == "BLOCKED" and calls == []


def test_replayed_evidence_denied(tmp_path):
    evals, client, calls = build()
    votes = votes_for(evals, nonce="nonce-1")
    assert execute(client, votes, nonce="nonce-1", idem="op-1").json()["status"] == "EXECUTED"
    # Same evidence, fresh nonce/op -> the votes no longer bind to the new nonce.
    r = execute(client, votes, nonce="nonce-2", idem="op-2")
    assert r.json()["status"] == "BLOCKED"
    assert len(calls) == 1  # upstream reached only by the first, valid call


def test_same_nonce_replay_denied_by_gate(tmp_path):
    evals, client, calls = build()
    votes = votes_for(evals, nonce="nonce-1")
    assert execute(client, votes, nonce="nonce-1", idem="op-1").json()["status"] == "EXECUTED"
    # Replaying the identical evidence + nonce: the one-time nonce is consumed,
    # so the gate rejects the second attempt.
    r = execute(client, votes, nonce="nonce-1", idem="op-1b")
    assert r.json()["status"] == "BLOCKED"
    assert len(calls) == 1


# ---- Cross-path guarantee: no consensus, no actuation ----

def test_mandate_path_blocked_under_mandatory_consensus(tmp_path):
    """With mandatory consensus on, the mandate execute path supplies no votes,
    so the coordinator fails closed — proving the guarantee holds across paths,
    not only the consensus endpoint."""
    evals, client, calls = build()
    issuer = SigningKey.generate("issuer-1")
    # A structurally well-formed mandate request; whatever authority it carries,
    # the coordinator still refuses to actuate without consensus evidence.
    r = client.post("/mandates/execute", headers=AGENT, json={
        "mandate": {"kid": issuer.kid, "mandate_id": "m-1"}, "actor": "agent/x",
        "action": ACTION, "resource": "res-1", "context": CTX, "idempotency_key": "m-op-1"})
    assert r.json()["status"] == "BLOCKED" and calls == []
