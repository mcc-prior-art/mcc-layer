"""F1: bind every non-mandate authority path to the authenticated agent.

Reproduced on PR #135 head 2761f4f through real HTTP (in-process uvicorn
gateway + real loopback notification service, honest evaluators): agent B,
using its OWN registered credential,

* evaluated as agent A on ``POST /evaluate`` -> ALLOW + a decision token
  signed for A;
* issued a consensus challenge, verified and executed under consensus as A
  (``/consensus/challenge|verify|execute``) -> EXECUTED, receipt +1;
* obtained 3 ALLOW votes for A from the REAL VoltAgent evaluator quorum and
  executed with them -> EXECUTED, receipt +1;
* executed with A's own challenge + votes -> EXECUTED (A's challenge burned).

The shared tenant key was also accepted on every consensus route. Consensus
consumed no mandate, so PR #135's identity binding never applied there.

Contract (strict, the default):

* ``/consensus/challenge``, ``/consensus/verify`` and ``/consensus/execute``
  are identity routes: a registered, active credential of the mount's tenant
  whose principal equals ``actor``. The shared tenant key grants no identity
  (403 AGENT_IDENTITY_REQUIRED); revoked / other-tenant keys 403; unknown 401.
* A challenge records the server-resolved tenant and the authenticated
  principal; it is usable only by that principal in that tenant (checked
  before consumption, and again when the coordinator consumes it).
* Every counted vote must be signed for that tenant (``tenant_id`` claim);
  its signed ``actor`` is the principal binding.
* ``/evaluate``: a registered agent credential evaluates only as itself; the
  shared tenant key may not evaluate as a registered agent.
* The evaluator quorum votes only for the agent that authenticated to it and
  forwards that agent's credential to ``/evaluate``.
* Every refusal happens before any token, challenge consumption, idempotency
  reservation, audit record or actuator call.

Every negative case below is paired with a positive control that reaches the
same check with valid inputs, so no rejection is vacuous.

NOT covered (see docs/AGENT_IDENTITY.md): theft of an agent's OWN credential
(no proof of possession), a compromised quorum / gateway / evaluator, and the
separately deployed runtimes that have no per-agent registry (egress proxy,
MVP interceptor, main.py).
"""
from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any, Dict, Optional

import httpx
import pytest

from mcc_core import SigningKey, issue_vote
from mcc_core.challenge import (
    ChallengeRecord,
    ChallengeService,
    InMemoryChallengeRegistry,
    challenge_identity_error,
)
from mcc_core.consensus import ConsensusPolicy, ConsensusVerifier
from mcc_core.signing import hash_payload

from gateway.agent_identity import (
    AGENT_IDENTITY_LEGACY,
    AGENT_IDENTITY_STRICT,
    AgentCredentialRegistry,
    AuthenticatedAgent,
    evaluate_identity_error,
    hash_agent_key,
)
from pilot_notify import recorded_receipts, reset_receipts
from tests._notify_harness import API_KEY, TENANT_ID, NotifyPilotHarness, agent_key

A = "agent/notify-bot"
B = "agent/unknown"
OTHER_TENANT_KEY = "f1-other-tenant-agent-key"
REVOKED_KEY = "f1-revoked-agent-key"
ACTION = "send_notification"
RESOURCE = "crm"


@pytest.fixture(scope="module")
def hz():
    h = NotifyPilotHarness(
        env={"MCC_REQUIRE_CONSENSUS": "1", "MCC_REQUIRE_CHALLENGE": "1"},
        extra_credentials=[
            ("cred-f1-other-tenant", "tenant-other", A, OTHER_TENANT_KEY, "active"),
            ("cred-f1-revoked", TENANT_ID, "agent/other-unknown-revoked", REVOKED_KEY, "revoked"),
        ])
    yield h
    h.close()


# ---------------------------------------------------------------- helpers

def _post(hz, path: str, key: Optional[str], body: Dict[str, Any], headers=None) -> httpx.Response:
    h = {} if key is None else {"x-api-key": key}
    h.update(headers or {})
    return httpx.post(f"{hz.base_url}{path}", headers=h, json=body, timeout=15)


def _payload(corr: str) -> Dict[str, Any]:
    return {"recipient": "cust-f1", "message": "hello", "priority": 2, "channel": "email",
            "correlation_id": corr}


def _receipts() -> int:
    return len(recorded_receipts())


def _audit_entries(hz) -> int:
    with open(hz._audit_path, encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())


def _challenge_state(hz, challenge_id: str) -> Optional[str]:
    rec = asyncio.run(hz.service.challenge_service.get(challenge_id))
    return None if rec is None else rec.state


def _evaluate(hz, actor: str, corr: str, key: Optional[str] = None) -> httpx.Response:
    return _post(hz, "/evaluate", agent_key(actor) if key is None else key, {
        "identity": actor, "actor_id": actor, "action": ACTION, "resource_id": RESOURCE,
        "context": _payload(corr), "idempotency_key": corr})


def _own_material(hz, actor: str, corr: str, *, evaluate: bool = True):
    """An HONEST agent's own decision + challenge + votes (positive path).
    ``evaluate=False``: an agent with no standing mandate (agent/unknown gets
    ESCALATE from /evaluate); the harness evaluators sign for its OWN
    operation directly, as consensus authority does not depend on /evaluate."""
    if evaluate:
        ev = _evaluate(hz, actor, corr)
        assert ev.status_code == 200 and ev.json()["decision"] == "ALLOW", ev.text
        fc = ev.json()["forward_context"]
    else:
        fc = hz.profiles.for_action(ACTION).canonical_payload(_payload(corr))
    ch = _post(hz, "/consensus/challenge", agent_key(actor),
               {"actor": actor, "action": ACTION, "resource": RESOURCE, "context": fc})
    assert ch.status_code == 200, ch.text
    ch = ch.json()
    votes = hz.votes(action=ACTION, payload=fc, actor=actor, nonce=ch["nonce"],
                     resource=RESOURCE, tenant_id=ch["tenant_id"])
    return fc, ch, votes


def _execute(hz, key: Optional[str], *, actor: str, fc, ch, votes, idem: str) -> httpx.Response:
    return _post(hz, "/consensus/execute", key, {
        "votes": votes, "actor": actor, "action": ACTION, "resource": RESOURCE, "context": fc,
        "idempotency_key": idem, "challenge_id": ch["challenge_id"]})


def _corr() -> str:
    return f"corr-f1-{uuid.uuid4().hex[:12]}"


@pytest.fixture(autouse=True)
def _fresh_receipts():
    reset_receipts()
    yield


# ---------------------------------------------------------- positive controls

def test_baseline_A_executes_its_own_consensus_operation(hz):
    corr = _corr()
    fc, ch, votes = _own_material(hz, A, corr)
    assert ch["tenant_id"] == TENANT_ID and ch["principal_id"] == A
    assert all(v["tenant_id"] == TENANT_ID and v["actor"] == A for v in votes)
    r = _execute(hz, agent_key(A), actor=A, fc=fc, ch=ch, votes=votes, idem=corr)
    assert r.json()["status"] == "EXECUTED", r.text
    assert _receipts() == 1
    assert _challenge_state(hz, ch["challenge_id"]) == "CONSUMED"


def test_baseline_B_executes_its_own_consensus_operation(hz):
    corr = _corr()
    fc, ch, votes = _own_material(hz, B, corr, evaluate=False)
    r = _execute(hz, agent_key(B), actor=B, fc=fc, ch=ch, votes=votes, idem=corr)
    assert r.json()["status"] == "EXECUTED", r.text
    assert _receipts() == 1


# ------------------------------------------------ B acting as A: every route

def test_B_cannot_evaluate_as_A(hz):
    before = _audit_entries(hz)
    r = _evaluate(hz, A, _corr(), key=agent_key(B))
    assert r.status_code == 403 and "AGENT_PRINCIPAL_MISMATCH" in r.json()["detail"]
    # identity only in actor_id (identity = B) is refused too
    r2 = _post(hz, "/evaluate", agent_key(B), {
        "identity": B, "actor_id": A, "action": ACTION, "context": _payload(_corr())})
    assert r2.status_code == 403
    assert _audit_entries(hz) == before          # no evaluate record, no token
    # control: B evaluates as itself
    assert _evaluate(hz, B, _corr()).status_code == 200


def test_B_cannot_issue_a_challenge_as_A(hz):
    records = len(hz.service.challenge_service.registry._records)
    r = _post(hz, "/consensus/challenge", agent_key(B),
              {"actor": A, "action": ACTION, "resource": RESOURCE, "context": _payload(_corr())})
    assert r.status_code == 403 and "AGENT_PRINCIPAL_MISMATCH" in r.json()["detail"]
    assert len(hz.service.challenge_service.registry._records) == records   # nothing created


def test_B_cannot_verify_consensus_as_A(hz):
    corr = _corr()
    fc, ch, votes = _own_material(hz, A, corr)
    body = {"votes": votes, "action": ACTION, "context": fc, "actor": A, "resource": RESOURCE,
            "nonce": ch["nonce"]}
    r = _post(hz, "/consensus/verify", agent_key(B), body)
    assert r.status_code == 403 and "AGENT_PRINCIPAL_MISMATCH" in r.json()["detail"]
    ok = _post(hz, "/consensus/verify", agent_key(A), body)     # control
    assert ok.status_code == 200 and ok.json()["verdict"] == "ALLOW"


def test_B_with_As_challenge_and_votes_as_A_is_blocked_then_A_succeeds(hz):
    corr = _corr()
    fc, ch, votes = _own_material(hz, A, corr)
    audit_before = _audit_entries(hz)
    r = _execute(hz, agent_key(B), actor=A, fc=fc, ch=ch, votes=votes, idem=corr)
    assert r.json()["status"] == "BLOCKED" and "AGENT_PRINCIPAL_MISMATCH" in r.json()["reason"]
    assert _receipts() == 0
    assert _challenge_state(hz, ch["challenge_id"]) == "ISSUED"   # not consumed
    assert _audit_entries(hz) == audit_before                    # no pre_actuation/any record
    # A, same challenge, same votes, SAME idempotency key -> nothing was reserved
    ok = _execute(hz, agent_key(A), actor=A, fc=fc, ch=ch, votes=votes, idem=corr)
    assert ok.json()["status"] == "EXECUTED", ok.text
    assert _receipts() == 1
    # replay of the spent challenge is still rejected; single-use preserved
    again = _execute(hz, agent_key(A), actor=A, fc=fc, ch=ch, votes=votes, idem=corr + "-2")
    assert again.json()["status"] == "BLOCKED"
    assert _receipts() == 1


def test_B_as_itself_with_As_challenge_is_blocked(hz):
    corr = _corr()
    fc, ch, votes_a = _own_material(hz, A, corr)
    votes_b = hz.votes(action=ACTION, payload=fc, actor=B, nonce=ch["nonce"], resource=RESOURCE)
    r = _execute(hz, agent_key(B), actor=B, fc=fc, ch=ch, votes=votes_b, idem=corr)
    assert r.json()["status"] == "BLOCKED"
    assert "CHALLENGE_PRINCIPAL_MISMATCH" in r.json()["reason"]
    assert _receipts() == 0 and _challenge_state(hz, ch["challenge_id"]) == "ISSUED"
    ok = _execute(hz, agent_key(A), actor=A, fc=fc, ch=ch, votes=votes_a, idem=corr)
    assert ok.json()["status"] == "EXECUTED" and _receipts() == 1


def test_B_with_As_votes_on_its_own_challenge_is_blocked(hz):
    corr = _corr()
    fc, ch_b, votes_b = _own_material(hz, B, corr, evaluate=False)
    votes_for_a = hz.votes(action=ACTION, payload=fc, actor=A, nonce=ch_b["nonce"],
                           resource=RESOURCE)
    r = _execute(hz, agent_key(B), actor=B, fc=fc, ch=ch_b, votes=votes_for_a, idem=corr)
    assert r.json()["status"] == "BLOCKED" and _receipts() == 0
    assert _challenge_state(hz, ch_b["challenge_id"]) == "ISSUED"
    ok = _execute(hz, agent_key(B), actor=B, fc=fc, ch=ch_b, votes=votes_b, idem=corr)
    assert ok.json()["status"] == "EXECUTED" and _receipts() == 1


# ------------------------------------------------------------ vote binding

@pytest.mark.parametrize("vote_tenant", ["tenant-other", None, ""])
def test_votes_signed_for_another_or_no_tenant_are_not_counted(hz, vote_tenant):
    corr = _corr()
    fc, ch, good = _own_material(hz, A, corr)
    bad = hz.votes(action=ACTION, payload=fc, actor=A, nonce=ch["nonce"], resource=RESOURCE,
                   tenant_id=vote_tenant)
    r = _execute(hz, agent_key(A), actor=A, fc=fc, ch=ch, votes=bad, idem=corr)
    assert r.json()["status"] == "BLOCKED" and "NO_CONSENSUS" in r.json()["reason"]
    assert _receipts() == 0 and _challenge_state(hz, ch["challenge_id"]) == "ISSUED"
    ok = _execute(hz, agent_key(A), actor=A, fc=fc, ch=ch, votes=good, idem=corr)
    assert ok.json()["status"] == "EXECUTED" and _receipts() == 1


def test_mixed_votes_count_only_tenant_bound_ones(hz):
    corr = _corr()
    fc, ch, good = _own_material(hz, A, corr)
    other = hz.votes(action=ACTION, payload=fc, actor=A, nonce=ch["nonce"], resource=RESOURCE,
                     tenant_id="tenant-other")
    r = _execute(hz, agent_key(A), actor=A, fc=fc, ch=ch, votes=good[:2] + other[2:], idem=corr)
    assert r.json()["status"] == "BLOCKED" and "2/3" in r.json()["reason"]
    assert _receipts() == 0


# ------------------------------------------------ credentials and spoofing

@pytest.mark.parametrize("path", ["/consensus/challenge", "/consensus/verify", "/consensus/execute"])
def test_shared_tenant_key_grants_no_identity_on_consensus_routes(hz, path):
    corr = _corr()
    fc, ch, votes = _own_material(hz, A, corr)
    bodies = {
        "/consensus/challenge": {"actor": A, "action": ACTION, "resource": RESOURCE, "context": fc},
        "/consensus/verify": {"votes": votes, "action": ACTION, "context": fc, "actor": A,
                              "resource": RESOURCE, "nonce": ch["nonce"]},
        "/consensus/execute": {"votes": votes, "actor": A, "action": ACTION, "resource": RESOURCE,
                               "context": fc, "idempotency_key": corr,
                               "challenge_id": ch["challenge_id"]},
    }
    r = _post(hz, path, API_KEY, bodies[path])
    assert r.status_code == 403 and "AGENT_IDENTITY_REQUIRED" in r.json()["detail"]
    assert _receipts() == 0 and _challenge_state(hz, ch["challenge_id"]) == "ISSUED"


@pytest.mark.parametrize("key,status,code", [
    (OTHER_TENANT_KEY, 403, "AGENT_CREDENTIAL_WRONG_TENANT"),
    (REVOKED_KEY, 403, "AGENT_CREDENTIAL_REVOKED"),
    ("not-a-registered-key", 401, "INVALID_API_KEY"),
    ("", 401, "INVALID_API_KEY"),
])
def test_bad_credentials_refused_on_every_route(hz, key, status, code):
    corr = _corr()
    fc, ch, votes = _own_material(hz, A, corr)
    for path, body in (
        ("/evaluate", {"identity": A, "action": ACTION, "context": fc}),
        ("/consensus/challenge", {"actor": A, "action": ACTION, "resource": RESOURCE, "context": fc}),
        ("/consensus/verify", {"votes": votes, "action": ACTION, "context": fc, "actor": A,
                               "nonce": ch["nonce"]}),
        ("/consensus/execute", {"votes": votes, "actor": A, "action": ACTION, "resource": RESOURCE,
                                "context": fc, "idempotency_key": corr,
                                "challenge_id": ch["challenge_id"]}),
    ):
        r = _post(hz, path, key, body)
        assert r.status_code == status and code in r.json()["detail"], (path, r.text)
    assert _receipts() == 0 and _challenge_state(hz, ch["challenge_id"]) == "ISSUED"


def test_spoofed_identity_headers_change_nothing(hz):
    corr = _corr()
    fc, ch, votes = _own_material(hz, A, corr)
    spoof = {"x-mcc-identity": A, "x-mcc-principal": A, "x-agent-id": A, "x-principal-id": A,
             "x-tenant-id": TENANT_ID, "x-forwarded-user": A}
    r = _post(hz, "/consensus/execute", agent_key(B), {
        "votes": votes, "actor": A, "action": ACTION, "resource": RESOURCE, "context": fc,
        "idempotency_key": corr, "challenge_id": ch["challenge_id"]}, headers=spoof)
    assert r.json()["status"] == "BLOCKED" and "AGENT_PRINCIPAL_MISMATCH" in r.json()["reason"]
    e = _post(hz, "/evaluate", agent_key(B), {"identity": A, "action": ACTION, "context": fc},
              headers=spoof)
    assert e.status_code == 403
    assert _receipts() == 0


@pytest.mark.parametrize("field,value", [("principal_id", A), ("tenant_id", TENANT_ID),
                                         ("agent", A), ("credential_id", "cred-agent/notify-bot")])
def test_identity_fields_in_body_are_rejected_by_strict_schema(hz, field, value):
    corr = _corr()
    fc, ch, votes = _own_material(hz, A, corr)
    body = {"votes": votes, "actor": A, "action": ACTION, "resource": RESOURCE, "context": fc,
            "idempotency_key": corr, "challenge_id": ch["challenge_id"], field: value}
    assert _post(hz, "/consensus/execute", agent_key(B), body).status_code == 422
    cbody = {"actor": A, "action": ACTION, "resource": RESOURCE, "context": fc, field: value}
    assert _post(hz, "/consensus/challenge", agent_key(B), cbody).status_code == 422
    assert _receipts() == 0


def test_shared_key_evaluates_only_non_agent_identities(hz):
    # A registered agent identity: refused for the shared key.
    r = _post(hz, "/evaluate", API_KEY, {"identity": A, "action": ACTION, "context": _payload(_corr())})
    assert r.status_code == 403 and "AGENT_IDENTITY_REQUIRED" in r.json()["detail"]
    r = _post(hz, "/evaluate", API_KEY, {"identity": "svc/billing", "actor_id": A,
                                         "action": ACTION, "context": _payload(_corr())})
    assert r.status_code == 403
    # A revoked agent is still an agent identity.
    r = _post(hz, "/evaluate", API_KEY, {"identity": "agent/other-unknown-revoked",
                                         "action": ACTION, "context": _payload(_corr())})
    assert r.status_code == 403
    # Not a registered agent: the tenant service credential still evaluates.
    ok = _post(hz, "/evaluate", API_KEY, {"identity": "svc/billing", "action": ACTION,
                                          "context": _payload(_corr())})
    assert ok.status_code == 200


# --------------------------------------------------- the real evaluator quorum

@pytest.fixture(scope="module")
def quorum(hz, tmp_path_factory):
    from examples._demo_server import DemoServer, free_port
    from integrations.voltagent.mcc_side.evaluator_quorum import QuorumSettings, build_quorum_app
    from tests._notify_harness import AGENT_PRINCIPALS
    path = tmp_path_factory.mktemp("f1q") / "agent_credentials.json"
    path.write_text(json.dumps({"agents": [
        {"credential_id": f"cred-{p}", "tenant_id": TENANT_ID, "principal_id": p,
         "key_sha256": hash_agent_key(agent_key(p)), "status": "active"}
        for p in AGENT_PRINCIPALS]}))

    def start(mode: str):
        settings = QuorumSettings({
            "MCC_QUORUM_GATEWAY_URL": hz.base_url, "MCC_GATEWAY_API_KEY": API_KEY,
            "MCC_QUORUM_API_KEY": "f1-quorum-shared-key", "MCC_GATEWAY_TENANT_ID": TENANT_ID,
            "MCC_AGENT_CREDENTIALS_CONFIG": str(path), "MCC_AGENT_IDENTITY_MODE": mode})
        port = free_port()
        srv = DemoServer(build_quorum_app(hz.evaluators, settings), port)
        srv.start()
        return srv, f"http://127.0.0.1:{port}"

    strict_srv, strict_url = start(AGENT_IDENTITY_STRICT)
    yield {"strict": strict_url}
    strict_srv.stop()


def test_quorum_refuses_to_vote_for_another_agent(hz, quorum):
    corr = _corr()
    _fc, ch, _votes = _own_material(hz, A, corr)
    r = httpx.post(f"{quorum['strict']}/vote", headers={"x-api-key": agent_key(B)}, json={
        "actor": A, "action": ACTION, "resource": RESOURCE, "nonce": ch["nonce"],
        "context": _payload(corr)}, timeout=15)
    assert r.status_code == 403 and "AGENT_PRINCIPAL_MISMATCH" in r.json()["detail"]


def test_quorum_refuses_its_shared_key_in_strict_mode(hz, quorum):
    r = httpx.post(f"{quorum['strict']}/vote", headers={"x-api-key": "f1-quorum-shared-key"}, json={
        "actor": A, "action": ACTION, "resource": RESOURCE, "nonce": "n",
        "context": _payload(_corr())}, timeout=15)
    assert r.status_code == 403 and "AGENT_IDENTITY_REQUIRED" in r.json()["detail"]


def test_quorum_votes_for_the_authenticated_agent_and_they_execute(hz, quorum):
    corr = _corr()
    ev = _evaluate(hz, A, corr)
    fc = ev.json()["forward_context"]
    ch = _post(hz, "/consensus/challenge", agent_key(A),
               {"actor": A, "action": ACTION, "resource": RESOURCE, "context": fc}).json()
    q = httpx.post(f"{quorum['strict']}/vote", headers={"x-api-key": agent_key(A)}, json={
        "actor": A, "action": ACTION, "resource": RESOURCE, "nonce": ch["nonce"],
        "context": _payload(corr)}, timeout=15)
    assert q.status_code == 200, q.text
    votes = q.json()["votes"]
    assert len(votes) == 3 and all(v["tenant_id"] == TENANT_ID and v["actor"] == A for v in votes)
    # B cannot use A's quorum votes (as A or as itself); A can.
    assert _execute(hz, agent_key(B), actor=A, fc=fc, ch=ch, votes=votes,
                    idem=corr).json()["status"] == "BLOCKED"
    assert _receipts() == 0
    ok = _execute(hz, agent_key(A), actor=A, fc=fc, ch=ch, votes=votes, idem=corr)
    assert ok.json()["status"] == "EXECUTED" and _receipts() == 1


# ------------------------------------------------- library / unit contract

def _svc_challenge_record(**kw) -> ChallengeRecord:
    base = dict(challenge_id="chal-x", nonce="n", action=ACTION, action_hash="h", actor=A,
                resource=RESOURCE, payload_hash="p", policy_hash="ph", state="ISSUED",
                issued_at=0, expires_at=10**10, tenant_id=TENANT_ID, principal_id=A)
    base.update(kw)
    return ChallengeRecord(**base)


def test_challenge_identity_error_is_total_and_fail_closed():
    rec = _svc_challenge_record()
    assert challenge_identity_error(rec, tenant_id=TENANT_ID, actor=A, principal_id=A) is None
    assert "TENANT" in challenge_identity_error(rec, tenant_id="other", actor=A)
    assert "TENANT" in challenge_identity_error(rec, tenant_id=None, actor=A)
    assert "TENANT" in challenge_identity_error(rec, actor=A)          # unscoped consumer
    assert "PRINCIPAL" in challenge_identity_error(rec, tenant_id=TENANT_ID, actor=B)
    assert "PRINCIPAL" in challenge_identity_error(rec, tenant_id=TENANT_ID, actor=A, principal_id=B)
    unscoped = _svc_challenge_record(tenant_id=None, principal_id=None)
    assert challenge_identity_error(unscoped, actor=A) is None          # pre-F1 library use
    assert "TENANT" in challenge_identity_error(unscoped, tenant_id=TENANT_ID, actor=A)
    for junk in (None, 1, "x", object()):
        challenge_identity_error(junk, tenant_id=TENANT_ID, actor=A)   # never raises


def test_tenant_scoped_challenge_consume_binding():
    svc = ChallengeService(InMemoryChallengeRegistry())
    rec = asyncio.run(svc.issue(action=ACTION, actor=A, resource=RESOURCE, payload_hash="p",
                                policy_hash="ph", tenant_id=TENANT_ID, principal_id=A))
    kw = dict(action=ACTION, actor=A, resource=RESOURCE, payload_hash="p", policy_hash="ph",
              nonce=rec.nonce)
    assert not asyncio.run(svc.consume(rec.challenge_id, **kw)).ok                     # unscoped
    assert not asyncio.run(svc.consume(rec.challenge_id, **kw, tenant_id="other")).ok
    assert not asyncio.run(svc.consume(rec.challenge_id, **{**kw, "actor": B},
                                       tenant_id=TENANT_ID)).ok
    assert asyncio.run(svc.get(rec.challenge_id)).state == "ISSUED"
    assert asyncio.run(svc.consume(rec.challenge_id, **kw, tenant_id=TENANT_ID)).ok  # control
    assert not asyncio.run(svc.consume(rec.challenge_id, **kw, tenant_id=TENANT_ID)).ok


def test_verifier_tenant_binding_and_unscoped_compatibility():
    evals = [SigningKey.generate(f"e{i}") for i in range(3)]
    v = ConsensusVerifier(trusted_keys={e.kid: e.public_key() for e in evals},
                          policy=ConsensusPolicy(threshold=3))

    def votes(tenant):
        return [issue_vote(e, evaluator_id=e.kid, verdict="ALLOW", action=ACTION, payload={"x": 1},
                           actor=A, not_before=0, not_after=10**10, tenant_id=tenant)
                for e in evals]
    kw = dict(action=ACTION, payload={"x": 1}, actor=A)
    assert v.verify(votes(TENANT_ID), **kw, tenant_id=TENANT_ID).ok
    assert not v.verify(votes("other"), **kw, tenant_id=TENANT_ID).ok
    assert not v.verify(votes(None), **kw, tenant_id=TENANT_ID).ok
    assert not v.verify(votes(TENANT_ID), **kw, tenant_id="").ok          # "" never matches
    assert v.verify(votes(None), **kw).ok                                 # unscoped callers unchanged
    # the tenant is covered by the signature: rewriting it breaks the vote
    tampered = votes(TENANT_ID)
    for t in tampered:
        t["tenant_id"] = "other"
    assert not v.verify(tampered, **kw, tenant_id="other").ok
    assert hash_payload({"x": 1})  # sanity: same canonicalization as the gateway


def test_evaluate_identity_error_is_total():
    reg = AgentCredentialRegistry.from_config({"agents": [
        {"credential_id": "c1", "tenant_id": TENANT_ID, "principal_id": A,
         "key_sha256": hash_agent_key("k1"), "status": "revoked"}]})
    me = AuthenticatedAgent(TENANT_ID, A, "c1")
    S = AGENT_IDENTITY_STRICT
    assert evaluate_identity_error(me, tenant_id=TENANT_ID, identities=(A, None), mode=S) is None
    assert "PRINCIPAL" in evaluate_identity_error(me, tenant_id=TENANT_ID, identities=(A, B), mode=S)
    assert "TENANT" in evaluate_identity_error(me, tenant_id="other", identities=(A,), mode=S)
    assert "PRINCIPAL" in evaluate_identity_error(me, tenant_id=TENANT_ID, identities=(B,),
                                                  mode=AGENT_IDENTITY_LEGACY)   # agent key: every mode
    assert "IDENTITY_REQUIRED" in evaluate_identity_error(None, tenant_id=TENANT_ID,
                                                          identities=(A,), mode=S, registry=reg)
    assert evaluate_identity_error(None, tenant_id=TENANT_ID, identities=(A,),
                                   mode=AGENT_IDENTITY_LEGACY, registry=reg) is None
    assert evaluate_identity_error(None, tenant_id=TENANT_ID, identities=("svc/x",), mode=S,
                                   registry=reg) is None
    assert "INVALID" in evaluate_identity_error("forged", tenant_id=TENANT_ID, identities=(A,), mode=S)
    assert "MODE" in evaluate_identity_error(me, tenant_id=TENANT_ID, identities=(A,), mode="off")
    assert "INVALID" in evaluate_identity_error(None, tenant_id=TENANT_ID, identities=5, mode=S,
                                                registry=reg)

    class Broken:
        def is_registered_principal(self, *a, **k):
            raise RuntimeError("boom")
    assert "INVALID" in evaluate_identity_error(None, tenant_id=TENANT_ID, identities=(A,), mode=S,
                                                registry=Broken())


def test_library_strict_mode_refuses_an_omitted_agent(hz):
    svc = hz.service
    assert svc.agent_identity_mode == AGENT_IDENTITY_STRICT
    out = asyncio.run(svc.issue_challenge(action=ACTION, actor=A, resource=RESOURCE,
                                          context=_payload(_corr()), tenant_id=TENANT_ID))
    assert out.get("identity_error") and "AGENT_IDENTITY_REQUIRED" in out["error"]
    v = asyncio.run(svc.verify_consensus(votes=[], action=ACTION, context=_payload(_corr()),
                                         actor=A, tenant_id=TENANT_ID))
    assert v["verdict"] == "DENY" and "AGENT_IDENTITY_REQUIRED" in v["reason"]
    corr = _corr()
    fc, ch, votes = _own_material(hz, A, corr)
    out = asyncio.run(svc.execute_with_consensus(
        votes=votes, actor=A, action=ACTION, resource=RESOURCE, context=fc,
        idempotency_key=corr, tenant_id=TENANT_ID, challenge_id=ch["challenge_id"]))
    assert out.status == "BLOCKED" and "AGENT_IDENTITY_REQUIRED" in out.reason
    assert _receipts() == 0 and _challenge_state(hz, ch["challenge_id"]) == "ISSUED"
    # trusted agent passed explicitly by the library caller -> executes
    me = AuthenticatedAgent(TENANT_ID, A, "cred-lib")
    ok = asyncio.run(svc.execute_with_consensus(
        votes=votes, actor=A, action=ACTION, resource=RESOURCE, context=fc,
        idempotency_key=corr, tenant_id=TENANT_ID, challenge_id=ch["challenge_id"], agent=me))
    assert ok.status == "EXECUTED" and _receipts() == 1


def test_library_challenge_from_another_tenant_is_refused_before_consumption(hz):
    corr = _corr()
    fc, ch, votes = _own_material(hz, A, corr)
    other = AuthenticatedAgent("tenant-other", A, "cred-other")
    out = asyncio.run(hz.service.execute_with_consensus(
        votes=votes, actor=A, action=ACTION, resource=RESOURCE, context=fc,
        idempotency_key=corr, tenant_id="tenant-other", challenge_id=ch["challenge_id"],
        agent=other))
    assert out.status == "BLOCKED" and "CHALLENGE_TENANT_MISMATCH" in out.reason
    assert _receipts() == 0 and _challenge_state(hz, ch["challenge_id"]) == "ISSUED"


# ------------------------- the quorum's OWN checks, isolated from the gateway

def _quorum_with_permissive_gateway(mode=AGENT_IDENTITY_STRICT):
    """The real quorum app in front of a STUB gateway that would ALLOW
    anything -- so these tests prove the quorum's own checks, not the
    gateway's defense in depth behind it."""
    import tempfile

    from fastapi.testclient import TestClient

    from integrations.voltagent.mcc_side.evaluator_quorum import QuorumSettings, build_quorum_app
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.url.path, request.headers.get("x-api-key")))
        if request.url.path == "/health":
            return httpx.Response(200, json={"policy_hash": "sha256:stub"})
        body = json.loads(request.content)
        return httpx.Response(200, json={"decision": "ALLOW", "forward_context": body["context"]})
    reg = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump({"agents": [
        {"credential_id": f"c-{p}", "tenant_id": TENANT_ID, "principal_id": p,
         "key_sha256": hash_agent_key(agent_key(p)), "status": "active"} for p in (A, B)]}, reg)
    reg.close()
    settings = QuorumSettings({"MCC_QUORUM_GATEWAY_URL": "http://gw.stub", "MCC_GATEWAY_API_KEY": "svc",
                               "MCC_QUORUM_API_KEY": "q-shared", "MCC_GATEWAY_TENANT_ID": TENANT_ID,
                               "MCC_AGENT_CREDENTIALS_CONFIG": reg.name, "MCC_AGENT_IDENTITY_MODE": mode})
    app = build_quorum_app([SigningKey.generate("e0")], settings,
                           client=httpx.Client(transport=httpx.MockTransport(handler)))
    return TestClient(app), calls


def _vote_body(actor):
    return {"actor": actor, "action": ACTION, "resource": RESOURCE, "nonce": "n",
            "context": _payload("c")}


def test_quorum_itself_refuses_another_actor_before_asking_the_gateway():
    tc, calls = _quorum_with_permissive_gateway()
    r = tc.post("/vote", headers={"x-api-key": agent_key(B)}, json=_vote_body(A))
    assert r.status_code == 403 and "AGENT_PRINCIPAL_MISMATCH" in r.json()["detail"]
    assert calls == []                                   # gateway never consulted
    ok = tc.post("/vote", headers={"x-api-key": agent_key(B)}, json=_vote_body(B))   # control
    assert ok.status_code == 200 and len(ok.json()["votes"]) == 1
    assert ok.json()["votes"][0]["tenant_id"] == TENANT_ID and ok.json()["votes"][0]["actor"] == B
    # the caller's OWN credential is what was forwarded to /evaluate
    assert ("/evaluate", agent_key(B)) in calls


def test_quorum_itself_refuses_its_shared_key_in_strict_mode():
    tc, calls = _quorum_with_permissive_gateway()
    r = tc.post("/vote", headers={"x-api-key": "q-shared"}, json=_vote_body(A))
    assert r.status_code == 403 and "AGENT_IDENTITY_REQUIRED" in r.json()["detail"]
    assert calls == []
    legacy, lcalls = _quorum_with_permissive_gateway(AGENT_IDENTITY_LEGACY)   # explicit legacy
    assert legacy.post("/vote", headers={"x-api-key": "q-shared"}, json=_vote_body(A)).status_code == 200
    assert ("/evaluate", "svc") in lcalls


def test_quorum_refuses_unknown_key():
    tc, calls = _quorum_with_permissive_gateway()
    assert tc.post("/vote", headers={"x-api-key": "nope"}, json=_vote_body(A)).status_code == 401
    assert calls == []
