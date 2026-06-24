"""build_governance_service wiring for mandatory consensus.

The production builder reads ``MCC_REQUIRE_CONSENSUS`` and ``MCC_CONSENSUS_TRUST_CONFIG``
from the environment. Mandatory consensus must never start fail-open: requiring
consensus without a configured evaluator trust set refuses startup.
"""

import json
import tempfile
from pathlib import Path

import pytest

from mcc_core import AuditLog, DecisionEngine, SigningKey

from gateway.governance_api import build_governance_service


def _engine_bits(tmp_path):
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc", audience="gate",
                            policy_id="p", policy_hash="sha256:p", token_ttl_seconds=60)
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    return dk, engine, audit


def _consensus_trust_file(tmp_path):
    evals = [SigningKey.generate(f"eval-{i}") for i in range(3)]
    config = {"issuers": [
        {"issuer_id": f"eval-{i}", "enabled": True,
         "keys": [{"kid": e.kid, "public_key_b64": e.public_key_b64(), "not_after": None}]}
        for i, e in enumerate(evals)]}
    path = tmp_path / "consensus_trust.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def _build(tmp_path, env):
    dk, engine, audit = _engine_bits(tmp_path)
    return build_governance_service(
        engine=engine, signing_key=dk, audit=audit, policy_hash="sha256:p",
        token_audience="gate", env=env, upstream=lambda a, p: None)


def test_require_consensus_without_trust_refuses_startup(tmp_path):
    with pytest.raises(RuntimeError, match="refusing fail-open"):
        _build(tmp_path, {"MCC_REQUIRE_CONSENSUS": "1"})


def test_require_consensus_with_trust_enables_coordinator(tmp_path):
    trust = _consensus_trust_file(tmp_path)
    svc = _build(tmp_path, {"MCC_REQUIRE_CONSENSUS": "true",
                            "MCC_CONSENSUS_TRUST_CONFIG": str(trust)})
    assert svc.coordinator.require_consensus is True
    assert svc.coordinator.consensus_verifier is not None


def test_default_does_not_require_consensus(tmp_path):
    svc = _build(tmp_path, {})
    assert svc.coordinator.require_consensus is False
