"""Fail-closed startup and readiness for the pilot deployment.

These pin the deployment guarantees the docker-compose pilot relies on:
* MCC_ENV=pilot refuses to start without a valid mandate trust set;
* MCC_REQUIRE_CONSENSUS refuses to start without a consensus verifier (no fail-open);
* readiness reports not-ready when a required Redis is unreachable.
"""

import asyncio
import tempfile
from pathlib import Path

import pytest

import gateway.app as gw
from gateway.governance_api import build_governance_service
from gateway.trust import TrustConfigError
from mcc_core import AuditLog, DecisionEngine, SigningKey


def _engine_bits():
    key = SigningKey.generate("startup-test")
    engine = DecisionEngine(signing_key=key, issuer="mcc", audience="gate",
                            policy_id="p", policy_hash="sha256:p", token_ttl_seconds=60)
    audit = AuditLog(str(Path(tempfile.mkdtemp(prefix="mcc-startup-")) / "a.jsonl"))
    return engine, key, audit


def _build(env):
    engine, key, audit = _engine_bits()
    return build_governance_service(
        engine=engine, signing_key=key, audit=audit,
        policy_hash="sha256:p", token_audience="gate", env=env)


def test_pilot_without_trust_config_refuses_startup():
    with pytest.raises(TrustConfigError):
        _build({"MCC_ENV": "pilot"})


def test_require_consensus_without_verifier_refuses_startup():
    # dev env (empty trust allowed), but consensus required with no verifier config.
    with pytest.raises(RuntimeError):
        _build({"MCC_REQUIRE_CONSENSUS": "1"})


def test_dev_startup_without_consensus_is_allowed():
    svc = _build({})  # no consensus, empty trust set in dev
    assert svc.consensus_verifier is None
    # The challenge service is always built (challenge optional until required).
    assert svc.challenge_service is not None


# ---- readiness helpers (the /ready logic, deterministic) ----

def test_redis_required_detection():
    assert gw._redis_required({"MCC_NONCE_BACKEND": "redis"}) is True
    assert gw._redis_required({"MCC_CHALLENGE_BACKEND": "redis"}) is True
    assert gw._redis_required({}) is False
    assert gw._redis_required({"MCC_NONCE_BACKEND": "memory"}) is False


def test_redis_ok_false_when_unreachable():
    env = {"MCC_REDIS_URL": "redis://127.0.0.1:6555/0",  # nothing listening
           "MCC_REDIS_CONNECT_TIMEOUT_SECONDS": "0.3", "MCC_REDIS_OP_TIMEOUT_SECONDS": "0.3"}
    assert asyncio.run(gw._redis_ok(env)) is False


def test_redis_ok_false_when_url_missing():
    assert asyncio.run(gw._redis_ok({})) is False
