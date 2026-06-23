"""Signed, revocable mandate tests.

Negative coverage: forged, expired, not-yet-valid, untrusted, malformed, wrong
subject, wrong resource, scope widening, revoked, unavailable revocation
backend, stale authority, policy drift. Plus the happy path and token binding.
"""

import asyncio

import pytest

from mcc_core import (
    DecisionEngine,
    InMemoryRevocationRegistry,
    MandateVerifier,
    RedisRevocationRegistry,
    RevocationConfigError,
    RevocationStatus,
    SigningKey,
    issue_mandate,
    revocation_registry_from_env,
)

run = asyncio.run
NOW = 1_780_000_000


def issuer():
    return SigningKey.generate("issuer-key-1")


def trusted(key):
    return {key.kid: key.public_key()}


def make_mandate(key, **over):
    kw = dict(
        issuer="axlogiq/pilot", subject="agent/payments-bot",
        action_scope=["send_payment", "pay_*"], resource_scope=["acct-1", "acct-2"],
        constraints={"max_amount": 5000}, not_before=NOW - 10, not_after=NOW + 3600,
        issued_at=NOW, revocation_required=False, policy_hash=None,
    )
    kw.update(over)
    return issue_mandate(key, **kw)


def verifier(key, revocation=None):
    return MandateVerifier(trusted_keys=trusted(key), revocation_registry=revocation)


# ---- Happy path ----

def test_valid_mandate_verifies():
    key = issuer()
    m = make_mandate(key)
    res = run(verifier(key).verify(m, subject="agent/payments-bot", action="send_payment",
                                   resource="acct-1", now=NOW))
    assert res.ok
    assert res.constraints == {"max_amount": 5000}
    assert res.mandate_id == m["mandate_id"]


# ---- Signature / trust ----

def test_forged_mandate_rejected():
    key = issuer()
    m = make_mandate(key)
    m["constraints"] = {"max_amount": 10 ** 9}  # tamper after signing
    res = run(verifier(key).verify(m, subject="agent/payments-bot", action="send_payment",
                                   resource="acct-1", now=NOW))
    assert not res.ok
    assert "INVALID_MANDATE_SIGNATURE" in res.reason


def test_untrusted_issuer_rejected():
    key = issuer()
    other = SigningKey.generate("rogue-issuer-key")  # a kid the verifier does not trust
    m = make_mandate(other)  # signed by an untrusted issuer
    res = run(verifier(key).verify(m, subject="agent/payments-bot", action="send_payment",
                                   resource="acct-1", now=NOW))
    assert not res.ok
    assert "UNTRUSTED_ISSUER" in res.reason


def test_malformed_mandate_rejected():
    key = issuer()
    m = make_mandate(key)
    del m["sig"]  # not even a signature
    res = run(verifier(key).verify(m, subject="agent/payments-bot", action="send_payment",
                                   resource="acct-1", now=NOW))
    assert not res.ok


# ---- Validity window ----

def test_expired_mandate_rejected():
    key = issuer()
    m = make_mandate(key, not_after=NOW - 1)
    res = run(verifier(key).verify(m, subject="agent/payments-bot", action="send_payment",
                                   resource="acct-1", now=NOW))
    assert not res.ok
    assert "EXPIRED" in res.reason


def test_not_yet_valid_mandate_rejected():
    key = issuer()
    m = make_mandate(key, not_before=NOW + 100)
    res = run(verifier(key).verify(m, subject="agent/payments-bot", action="send_payment",
                                   resource="acct-1", now=NOW))
    assert not res.ok
    assert "NOT_YET_VALID" in res.reason


# ---- Substitution / scope ----

def test_wrong_subject_rejected():
    key = issuer()
    m = make_mandate(key, subject="agent/payments-bot")
    res = run(verifier(key).verify(m, subject="agent/attacker", action="send_payment",
                                   resource="acct-1", now=NOW))
    assert not res.ok
    assert "SUBJECT_MISMATCH" in res.reason


def test_scope_widening_rejected():
    key = issuer()
    m = make_mandate(key, action_scope=["send_payment"])
    res = run(verifier(key).verify(m, subject="agent/payments-bot", action="delete_database",
                                   resource="acct-1", now=NOW))
    assert not res.ok
    assert "ACTION_SCOPE_MISMATCH" in res.reason


def test_wrong_resource_rejected():
    key = issuer()
    m = make_mandate(key, resource_scope=["acct-1"])
    res = run(verifier(key).verify(m, subject="agent/payments-bot", action="send_payment",
                                   resource="acct-EVIL", now=NOW))
    assert not res.ok
    assert "RESOURCE_SCOPE_MISMATCH" in res.reason


def test_policy_binding_mismatch_rejected():
    key = issuer()
    m = make_mandate(key, policy_hash="sha256:policyA")
    res = run(verifier(key).verify(m, subject="agent/payments-bot", action="send_payment",
                                   resource="acct-1", now=NOW, policy_hash="sha256:policyB"))
    assert not res.ok
    assert "POLICY_BINDING_MISMATCH" in res.reason


# ---- Revocation ----

def test_revoked_mandate_rejected():
    key = issuer()
    revocation = InMemoryRevocationRegistry()
    m = make_mandate(key, revocation_required=True)
    run(revocation.revoke(m["mandate_id"]))
    res = run(verifier(key, revocation).verify(m, subject="agent/payments-bot",
                                               action="send_payment", resource="acct-1", now=NOW))
    assert not res.ok
    assert "REVOKED" in res.reason


def test_revocation_required_but_no_service_fails_closed():
    key = issuer()
    m = make_mandate(key, revocation_required=True)
    res = run(verifier(key, None).verify(m, subject="agent/payments-bot",
                                         action="send_payment", resource="acct-1", now=NOW))
    assert not res.ok
    assert "REVOCATION_REQUIRED" in res.reason


def test_revocation_backend_unavailable_fails_closed():
    key = issuer()

    class DownRedis:
        async def sismember(self, *a, **k):
            raise ConnectionError("down")
        async def sadd(self, *a, **k):
            raise ConnectionError("down")

    revocation = RedisRevocationRegistry(DownRedis())
    m = make_mandate(key, revocation_required=True)
    res = run(verifier(key, revocation).verify(m, subject="agent/payments-bot",
                                               action="send_payment", resource="acct-1", now=NOW))
    assert not res.ok
    assert "REVOCATION_UNAVAILABLE" in res.reason


def test_active_mandate_passes_revocation():
    key = issuer()
    revocation = InMemoryRevocationRegistry()
    m = make_mandate(key, revocation_required=True)
    res = run(verifier(key, revocation).verify(m, subject="agent/payments-bot",
                                               action="send_payment", resource="acct-1", now=NOW))
    assert res.ok


# ---- Token binding ----

def test_verified_mandate_binds_into_decision_token():
    key = issuer()
    m = make_mandate(key)
    res = run(verifier(key).verify(m, subject="agent/payments-bot", action="send_payment",
                                   resource="acct-1", now=NOW))
    assert res.ok
    engine = DecisionEngine(signing_key=SigningKey.generate("dk"), issuer="mcc",
                            audience="gate", policy_id="p", policy_hash="sha256:p")
    token = engine.issue_token(verdict="ALLOW", subject="agent/payments-bot",
                               action="send_payment", payload={"amount": 100},
                               mandate_id=res.mandate_id, now=NOW)
    assert token["mandate_id"] == m["mandate_id"]


# ---- Factory ----

def test_revocation_factory_defaults_memory():
    assert isinstance(revocation_registry_from_env({}), InMemoryRevocationRegistry)


def test_revocation_factory_redis_requires_url():
    with pytest.raises(RevocationConfigError):
        revocation_registry_from_env({"MCC_REVOCATION_BACKEND": "redis"})


def test_revocation_status_enum_values():
    assert RevocationStatus.ACTIVE.value == "ACTIVE"
    assert RevocationStatus.REVOKED.value == "REVOKED"


# ---- MandateAuthority (verified mandate -> verdict) ----

from mcc_core import (  # noqa: E402
    ActuationStatus,
    AuditLog,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryVelocityRegistry,
    MandateAuthority,
    Verdict,
)


def test_mandate_authority_allow_within_bounds():
    key = issuer()
    ma = MandateAuthority(verifier(key))
    d = run(ma.authorize(make_mandate(key), subject="agent/payments-bot",
                         action="send_payment", resource="acct-1",
                         context={"amount": 100}, now=NOW))
    assert d.verdict == Verdict.ALLOW
    assert d.mandate_id is not None


def test_mandate_authority_constrains_over_cap():
    key = issuer()
    ma = MandateAuthority(verifier(key))
    d = run(ma.authorize(make_mandate(key), subject="agent/payments-bot",
                         action="send_payment", resource="acct-1",
                         context={"amount": 99999}, now=NOW))
    assert d.verdict == Verdict.CONSTRAIN
    assert d.forward_context == {"amount": 5000}


def test_mandate_authority_denies_on_failed_verification():
    key = issuer()
    ma = MandateAuthority(verifier(key))
    d = run(ma.authorize(make_mandate(key, not_after=NOW - 1), subject="agent/payments-bot",
                         action="send_payment", resource="acct-1",
                         context={"amount": 100}, now=NOW))
    assert d.verdict == Verdict.DENY


# ---- Coordinator actuation-time revocation re-check ----

def _coordinator(tmp_path, revocation):
    key = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=key, issuer="mcc", audience="gate",
                            policy_id="p", policy_hash="sha256:p", token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={key.kid: key.public_key()}, audience="gate",
                         nonce_registry=InMemoryNonceRegistry(), policy_hash="sha256:p")
    coord = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=AuditLog(str(tmp_path / "a.jsonl")),
        revocation_registry=revocation,
    )
    return engine, coord


def test_coordinator_blocks_revoked_mandate_at_actuation(tmp_path):
    revocation = InMemoryRevocationRegistry()
    engine, coord = _coordinator(tmp_path, revocation)
    token = engine.issue_token(verdict="ALLOW", subject="s", action="act",
                               payload={"x": 1}, mandate_id="mdt-xyz", now=NOW)
    run(revocation.revoke("mdt-xyz"))  # revoked after issuance

    async def ex():
        return "ran"

    res = run(coord.enforce(token=token, action="act", payload={"x": 1}, executor=ex, now=NOW))
    assert res.status == ActuationStatus.BLOCKED
    assert "revoked" in res.reason.lower()


def test_coordinator_allows_active_mandate_at_actuation(tmp_path):
    revocation = InMemoryRevocationRegistry()
    engine, coord = _coordinator(tmp_path, revocation)
    token = engine.issue_token(verdict="ALLOW", subject="s", action="act",
                               payload={"x": 1}, mandate_id="mdt-ok", now=NOW)
    ran = []

    async def ex():
        ran.append(1)
        return "ran"

    res = run(coord.enforce(token=token, action="act", payload={"x": 1}, executor=ex, now=NOW))
    assert res.status == ActuationStatus.EXECUTED
    assert ran == [1]
