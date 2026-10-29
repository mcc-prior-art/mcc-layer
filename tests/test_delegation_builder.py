"""build_governance_service wiring for Verifiable Delegation's owner trust root.

The production builder reads ``MCC_DELEGATION_OWNER_TRUST_CONFIG`` from the
environment and constructs a ``DelegationVerifier`` from a dedicated
``TrustSet`` -- never the gateway's mandate/approval trust_set, and never the
consensus evaluator trust config. Unconfigured means disabled (``None``), not
a silent fallback to any other trust source.
"""

import json

from mcc_core import AuditLog, DecisionEngine, SigningKey

from gateway.governance_api import build_governance_service


def _engine_bits(tmp_path):
    dk = SigningKey.generate("dk")
    engine = DecisionEngine(signing_key=dk, issuer="mcc", audience="gate",
                            policy_id="p", policy_hash="sha256:p", token_ttl_seconds=60)
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    return dk, engine, audit


def _owner_trust_file(tmp_path, *, owner_id="owner-1"):
    owner_key = SigningKey.generate("owner-key-1")
    config = {"issuers": [
        {"issuer_id": owner_id, "enabled": True,
         "keys": [{"kid": owner_key.kid, "public_key_b64": owner_key.public_key_b64(),
                   "not_after": None}]},
    ]}
    path = tmp_path / "delegation_owner_trust.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path, owner_key


def _build(tmp_path, env):
    dk, engine, audit = _engine_bits(tmp_path)
    return build_governance_service(
        engine=engine, signing_key=dk, audit=audit, policy_hash="sha256:p",
        token_audience="gate", env=env, upstream=lambda a, p: None)


def test_unconfigured_delegation_owner_trust_disables_delegation(tmp_path):
    svc = _build(tmp_path, {})
    assert svc.delegation_verifier is None


def test_configured_delegation_owner_trust_builds_verifier(tmp_path):
    trust, owner_key = _owner_trust_file(tmp_path)
    svc = _build(tmp_path, {"MCC_DELEGATION_OWNER_TRUST_CONFIG": str(trust)})
    assert svc.delegation_verifier is not None
    assert owner_key.kid in svc.delegation_verifier.trusted_owner_keys


def test_delegation_owner_trust_is_disjoint_from_mandate_trust_set(tmp_path):
    # The gateway's own mandate/approval trust_set must never gain the owner
    # key just because a delegation owner trust config was supplied -- the
    # two trust roots are architecturally separate (see delegation.py's
    # module docstring, point 2).
    trust, owner_key = _owner_trust_file(tmp_path)
    svc = _build(tmp_path, {"MCC_DELEGATION_OWNER_TRUST_CONFIG": str(trust)})
    import time
    assert owner_key.kid not in svc.trust_set.active_trusted_keys(now=int(time.time()))


def test_delegation_owner_trust_is_disjoint_from_consensus_trust_config(tmp_path):
    # Even when BOTH a consensus trust config and a delegation owner trust
    # config are supplied, each builds its OWN disjoint TrustSet instance --
    # an evaluator key must never satisfy owner verification, and vice versa.
    consensus_key = SigningKey.generate("eval-1")
    consensus_config = {"issuers": [
        {"issuer_id": "eval-1", "enabled": True,
         "keys": [{"kid": consensus_key.kid, "public_key_b64": consensus_key.public_key_b64(),
                   "not_after": None}]},
    ]}
    consensus_path = tmp_path / "consensus_trust.json"
    consensus_path.write_text(json.dumps(consensus_config), encoding="utf-8")

    owner_trust, owner_key = _owner_trust_file(tmp_path)
    svc = _build(tmp_path, {
        "MCC_CONSENSUS_TRUST_CONFIG": str(consensus_path),
        "MCC_DELEGATION_OWNER_TRUST_CONFIG": str(owner_trust),
    })
    assert consensus_key.kid not in svc.delegation_verifier.trusted_owner_keys
    assert owner_key.kid in svc.delegation_verifier.trusted_owner_keys
