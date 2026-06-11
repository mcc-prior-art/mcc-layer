"""MCC-Core runtime security tests.

Covers: Ed25519 signing/verification, all four verdict paths,
replay rejection, expiry/nbf rejection, fail-closed behavior when
Redis or OPA are unavailable, scope-binding hash checks, the
no-token-no-execution rule, and audit hash-chain integrity.
"""

import asyncio
import json
from pathlib import Path

import pytest

from mcc_core import (
    AuditLog,
    DecisionEngine,
    ExecutionGate,
    NonceRegistry,
    PolicyBundle,
    PolicyBundleError,
    SigningKey,
    TokenNotIssuable,
    Verdict,
    canonical_bytes,
    verify_token,
)

run = asyncio.run

NOW = 1_780_000_000


# =========================
# Fakes
# =========================

class FakeRedis:
    """Minimal async Redis double supporting SET NX EX."""

    def __init__(self):
        self.store = {}

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True


class DownRedis:
    """Redis double that is unreachable."""

    async def set(self, *args, **kwargs):
        raise ConnectionError("redis unavailable")


# =========================
# Fixtures
# =========================

@pytest.fixture
def signing_key():
    return SigningKey.generate("test-key-1")


@pytest.fixture
def engine(signing_key):
    return DecisionEngine(
        signing_key=signing_key,
        issuer="mcc/test",
        audience="execution-gate-1",
        policy_id="test-policy",
        policy_hash="sha256:policyhash",
        token_ttl_seconds=60,
    )


def make_gate(signing_key, *, nonce_registry=None, policy_hash="sha256:policyhash"):
    return ExecutionGate(
        trusted_keys={signing_key.kid: signing_key.public_key()},
        audience="execution-gate-1",
        nonce_registry=nonce_registry or NonceRegistry(FakeRedis()),
        policy_hash=policy_hash,
    )


def issue(engine, **overrides):
    kwargs = dict(
        verdict=Verdict.ALLOW,
        subject="agent/test",
        action="send_payment",
        payload={"amount": 100},
        constraints={},
        audit_ref="auditref",
        now=NOW,
    )
    kwargs.update(overrides)
    return engine.issue_token(**kwargs)


# =========================
# Signing
# =========================

def test_sign_and_verify_roundtrip(signing_key):
    token = signing_key.sign_token({"a": 1, "b": "x"})
    assert verify_token(token, signing_key.public_key())


def test_tampered_token_rejected(signing_key):
    token = signing_key.sign_token({"amount": 100})
    token["amount"] = 1_000_000
    assert not verify_token(token, signing_key.public_key())


def test_signature_from_other_key_rejected(signing_key):
    other = SigningKey.generate("other-key")
    token = other.sign_token({"a": 1})
    assert not verify_token(token, signing_key.public_key())


def test_garbage_signature_rejected(signing_key):
    token = signing_key.sign_token({"a": 1})
    token["sig"] = "not-base64-!!!"
    assert not verify_token(token, signing_key.public_key())


def test_canonical_serialization_is_deterministic():
    assert canonical_bytes({"b": 2, "a": 1}) == canonical_bytes({"a": 1, "b": 2})


# =========================
# Decision engine / verdict paths
# =========================

def test_token_issued_for_allow(engine):
    token = issue(engine, verdict=Verdict.ALLOW)
    assert token["decision"] == "ALLOW"


def test_token_issued_for_constrain(engine):
    token = issue(engine, verdict=Verdict.CONSTRAIN, constraints={"max_amount": 10})
    assert token["decision"] == "CONSTRAIN"
    assert token["constraints"] == {"max_amount": 10}


def test_no_token_for_deny(engine):
    with pytest.raises(TokenNotIssuable):
        issue(engine, verdict=Verdict.DENY)


def test_no_token_for_escalate(engine):
    with pytest.raises(TokenNotIssuable):
        issue(engine, verdict=Verdict.ESCALATE)


def test_token_contains_required_fields(engine, signing_key):
    token = issue(engine)
    for field in (
        "iss", "sub", "aud", "jti", "iat", "nbf", "exp", "decision",
        "action", "action_hash", "payload_hash", "constraints",
        "policy_id", "policy_hash", "nonce", "audit_ref", "kid", "sig",
    ):
        assert field in token, f"missing field: {field}"
    assert token["kid"] == signing_key.kid
    assert token["exp"] == token["iat"] + 60


# =========================
# Execution gate
# =========================

def test_gate_allows_valid_token(engine, signing_key):
    gate = make_gate(signing_key)
    result = run(gate.verify(issue(engine), action="send_payment",
                             payload={"amount": 100}, now=NOW))
    assert result.allowed


def test_gate_denies_missing_token(signing_key):
    gate = make_gate(signing_key)
    for no_token in (None, {}, "", []):
        result = run(gate.verify(no_token, now=NOW))
        assert not result.allowed


def test_gate_denies_tampered_token(engine, signing_key):
    gate = make_gate(signing_key)
    token = issue(engine)
    token["constraints"] = {"max_amount": 10**9}
    result = run(gate.verify(token, now=NOW))
    assert not result.allowed
    assert "INVALID_SIGNATURE" in result.reason


def test_gate_denies_unknown_kid(engine):
    rogue = SigningKey.generate("rogue-key")
    gate = make_gate(rogue)
    token = issue(engine)  # signed by test-key-1, gate trusts rogue-key only
    result = run(gate.verify(token, now=NOW))
    assert not result.allowed
    assert "UNTRUSTED_KEY" in result.reason


def test_gate_denies_expired_token(engine, signing_key):
    gate = make_gate(signing_key)
    result = run(gate.verify(issue(engine), now=NOW + 3600))
    assert not result.allowed
    assert "EXPIRED" in result.reason


def test_gate_denies_not_yet_valid_token(engine, signing_key):
    gate = make_gate(signing_key)
    result = run(gate.verify(issue(engine, now=NOW + 3600), now=NOW))
    assert not result.allowed
    assert "NOT_YET_VALID" in result.reason


def test_gate_denies_wrong_audience(signing_key):
    other_engine = DecisionEngine(
        signing_key=signing_key,
        issuer="mcc/test",
        audience="some-other-gate",
        policy_id="test-policy",
        policy_hash="sha256:policyhash",
    )
    gate = make_gate(signing_key)
    result = run(gate.verify(issue(other_engine), now=NOW))
    assert not result.allowed
    assert "AUDIENCE_MISMATCH" in result.reason


def test_gate_denies_replayed_nonce(engine, signing_key):
    gate = make_gate(signing_key)
    token = issue(engine)
    first = run(gate.verify(token, now=NOW))
    second = run(gate.verify(token, now=NOW))
    assert first.allowed
    assert not second.allowed
    assert "NONCE_REJECTED" in second.reason


def test_gate_fail_closed_when_redis_down(engine, signing_key):
    gate = make_gate(signing_key, nonce_registry=NonceRegistry(DownRedis()))
    result = run(gate.verify(issue(engine), now=NOW))
    assert not result.allowed
    assert "NONCE_REJECTED" in result.reason


def test_gate_denies_payload_hash_mismatch(engine, signing_key):
    gate = make_gate(signing_key)
    token = issue(engine, payload={"amount": 100})
    result = run(gate.verify(token, payload={"amount": 999_999}, now=NOW))
    assert not result.allowed
    assert "PAYLOAD_HASH_MISMATCH" in result.reason


def test_gate_denies_action_hash_mismatch(engine, signing_key):
    gate = make_gate(signing_key)
    token = issue(engine, action="send_payment")
    result = run(gate.verify(token, action="delete_database", now=NOW))
    assert not result.allowed
    assert "ACTION_HASH_MISMATCH" in result.reason


def test_gate_denies_policy_hash_mismatch(engine, signing_key):
    gate = make_gate(signing_key, policy_hash="sha256:differentpolicy")
    result = run(gate.verify(issue(engine), now=NOW))
    assert not result.allowed
    assert "POLICY_HASH_MISMATCH" in result.reason


def test_gate_denies_signed_deny_verdict(engine, signing_key):
    # Even a correctly signed token never executes a non-ALLOW/CONSTRAIN verdict.
    claims = dict(issue(engine))
    del claims["sig"], claims["kid"]
    claims["decision"] = "DENY"
    forged = signing_key.sign_token(claims)
    gate = make_gate(signing_key)
    result = run(gate.verify(forged, now=NOW))
    assert not result.allowed
    assert "NON_EXECUTABLE_VERDICT" in result.reason


def test_failed_static_check_does_not_burn_nonce(engine, signing_key):
    gate = make_gate(signing_key)
    token = issue(engine)
    expired = run(gate.verify(token, now=NOW + 3600))
    assert not expired.allowed
    valid = run(gate.verify(token, now=NOW))
    assert valid.allowed


# =========================
# Nonce registry
# =========================

def test_nonce_consumed_once():
    registry = NonceRegistry(FakeRedis())
    assert run(registry.consume("n1"))
    assert not run(registry.consume("n1"))


def test_nonce_fail_closed_on_registry_error():
    registry = NonceRegistry(DownRedis())
    assert not run(registry.consume("n1"))


def test_empty_nonce_rejected():
    registry = NonceRegistry(FakeRedis())
    assert not run(registry.consume(""))
    assert not run(registry.consume(None))


# =========================
# Audit hash chain
# =========================

def test_audit_chain_append_and_verify(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    for i in range(5):
        log.append({"decision": "DENY", "seq": i})
    assert AuditLog.verify_chain(path)


def test_audit_chain_detects_tampering(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    for i in range(3):
        log.append({"decision": "ALLOW", "seq": i})

    lines = Path(path).read_text().splitlines()
    entry = json.loads(lines[1])
    entry["decision"] = "DENY"
    lines[1] = json.dumps(entry, sort_keys=True)
    Path(path).write_text("\n".join(lines) + "\n")

    assert not AuditLog.verify_chain(path)


def test_audit_chain_continues_across_restart(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    AuditLog(path).append({"decision": "DENY", "seq": 0})
    reopened = AuditLog(path)
    reopened.append({"decision": "ALLOW", "seq": 1})
    assert AuditLog.verify_chain(path)
    entries = [json.loads(l) for l in Path(path).read_text().splitlines()]
    assert entries[1]["prev_hash"] == entries[0]["hash"]


# =========================
# Policy bundle
# =========================

def test_policy_bundle_hash_verification(tmp_path):
    policy = tmp_path / "policy.rego"
    policy.write_text("package mcc\n")
    bundle = PolicyBundle.from_file(str(policy))
    assert bundle.verify(bundle.policy_hash)
    assert not bundle.verify("sha256:" + "0" * 64)


def test_policy_bundle_rejects_tampered_bundle(tmp_path):
    policy = tmp_path / "policy.rego"
    policy.write_text("package mcc\n")
    good_hash = PolicyBundle.from_file(str(policy)).policy_hash
    policy.write_text("package mcc  # tampered\n")
    with pytest.raises(PolicyBundleError):
        PolicyBundle.from_file(str(policy), expected_hash=good_hash)


# =========================
# OPA fail-closed
# =========================

def test_opa_unreachable_fail_closed():
    import main

    adapter = main.OPAAdapter(
        base_url="http://127.0.0.1:9", data_path="mcc/decision", timeout_seconds=0.2
    )
    req = main.EvaluateRequest(
        session_id="s1", intent="send_payment", args={"amount": 100}
    )
    decision = run(adapter.evaluate(tenant="t", trace_id="tr", req=req))
    assert decision.decision == main.Decision.DENY
    assert decision.policy_ref == "fail-closed"


# =========================
# Runtime integration (main.py, local fallback engine)
# =========================

def _evaluate(intent, args):
    import main

    req = main.EvaluateRequest(session_id="it", intent=intent, args=args)
    return run(main.mcc.evaluate("tenant-test", req))


def test_evaluate_allow_returns_signed_token():
    import main

    resp = _evaluate("send_payment", {"amount": 100})
    assert resp.decision == main.Decision.ALLOW
    assert resp.decision_token is not None
    assert resp.decision_token["decision"] == "ALLOW"
    assert verify_token(resp.decision_token, main.mcc.signing_key.public_key())


def test_evaluate_deny_returns_no_token():
    import main

    resp = _evaluate("send_payment", {"amount": 50_000})
    assert resp.decision == main.Decision.DENY
    assert resp.decision_token is None


def test_evaluate_escalate_returns_no_token():
    import main

    resp = _evaluate("send_payment", {"amount": 7_500})
    assert resp.decision == main.Decision.ESCALATE
    assert resp.decision_token is None


def test_evaluate_unknown_intent_denied_without_token():
    import main

    resp = _evaluate("launch_rocket", {})
    assert resp.decision == main.Decision.DENY
    assert resp.decision_token is None


def test_issued_token_passes_execution_gate():
    import main

    resp = _evaluate("send_payment", {"amount": 200})
    gate = ExecutionGate(
        trusted_keys={main.mcc.signing_key.kid: main.mcc.signing_key.public_key()},
        audience=main.settings.token_audience,
        nonce_registry=NonceRegistry(FakeRedis()),
        policy_hash=main.mcc.policy_bundle.policy_hash,
    )
    result = run(
        gate.verify(resp.decision_token, action="send_payment", payload={"amount": 200})
    )
    assert result.allowed


def test_token_binds_to_audit_chain():
    import main

    resp = _evaluate("send_payment", {"amount": 300})
    entries = [
        json.loads(l)
        for l in Path(main.settings.audit_log_path).read_text().splitlines()
    ]
    assert resp.decision_token["audit_ref"] in {e["hash"] for e in entries}
    assert AuditLog.verify_chain(main.settings.audit_log_path)


def test_no_hmac_in_authority_bearing_runtime():
    repo_root = Path(__file__).resolve().parents[1]
    sources = [repo_root / "main.py"]
    sources += sorted((repo_root / "src").rglob("*.py"))
    for source in sources:
        assert "hmac" not in source.read_text().lower(), f"HMAC found in {source}"
