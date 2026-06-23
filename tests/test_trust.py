"""Multi-issuer trust-set tests: resolution, rotation, disablement, expiry,
malformed config, and fail-closed pilot startup."""

import json

import pytest

from mcc_core import SigningKey

from gateway.trust import (
    TrustConfigError,
    TrustStatus,
    load_trust_config,
    trust_set_from_env,
)

NOW = 1_780_000_000


def keypair(kid):
    k = SigningKey.generate(kid)
    return k, k.public_key_b64()


def config(*entries):
    return {"issuers": list(entries)}


def issuer(issuer_id, *keys, enabled=True):
    return {"issuer_id": issuer_id, "enabled": enabled, "keys": list(keys)}


def key_entry(kid, b64, not_after=None, revoked=False):
    e = {"kid": kid, "public_key_b64": b64}
    if not_after is not None:
        e["not_after"] = not_after
    if revoked:
        e["revoked"] = True
    return e


# ---- Resolution ----

def test_resolve_trusted_key():
    k, b64 = keypair("k1")
    ts = load_trust_config(config(issuer("iss-a", key_entry("k1", b64))))
    res = ts.resolve("k1", now=NOW)
    assert res.ok and res.issuer_id == "iss-a"
    assert res.public_key is not None


def test_unknown_kid():
    k, b64 = keypair("k1")
    ts = load_trust_config(config(issuer("iss-a", key_entry("k1", b64))))
    assert ts.resolve("nope", now=NOW).status == TrustStatus.UNKNOWN_KID


def test_disabled_issuer():
    k, b64 = keypair("k1")
    ts = load_trust_config(config(issuer("iss-a", key_entry("k1", b64), enabled=False)))
    assert ts.resolve("k1", now=NOW).status == TrustStatus.DISABLED_ISSUER


def test_expired_key():
    k, b64 = keypair("k1")
    ts = load_trust_config(config(issuer("iss-a", key_entry("k1", b64, not_after=NOW - 1))))
    assert ts.resolve("k1", now=NOW).status == TrustStatus.EXPIRED_KEY


def test_revoked_key():
    k, b64 = keypair("k1")
    ts = load_trust_config(config(issuer("iss-a", key_entry("k1", b64, revoked=True))))
    assert ts.resolve("k1", now=NOW).status == TrustStatus.REVOKED_KEY


# ---- Rotation: multiple keys per issuer ----

def test_multiple_keys_per_issuer_for_rotation():
    _, b1 = keypair("k-old")
    _, b2 = keypair("k-new")
    ts = load_trust_config(config(issuer("iss-a", key_entry("k-old", b1), key_entry("k-new", b2))))
    assert ts.resolve("k-old", now=NOW).ok
    assert ts.resolve("k-new", now=NOW).ok
    assert set(ts.active_trusted_keys(now=NOW)) == {"k-old", "k-new"}


def test_active_keys_exclude_disabled_expired_revoked():
    _, b1 = keypair("k1")
    _, b2 = keypair("k2")
    _, b3 = keypair("k3")
    ts = load_trust_config(config(
        issuer("iss-a", key_entry("k1", b1)),
        issuer("iss-b", key_entry("k2", b2), enabled=False),
        issuer("iss-c", key_entry("k3", b3, not_after=NOW - 1)),
    ))
    assert set(ts.active_trusted_keys(now=NOW)) == {"k1"}


# ---- Operator mutations ----

def test_disable_issuer_and_revoke_key():
    _, b1 = keypair("k1")
    _, b2 = keypair("k2")
    ts = load_trust_config(config(issuer("iss-a", key_entry("k1", b1)),
                                  issuer("iss-b", key_entry("k2", b2))))
    assert ts.disable_issuer("iss-a")
    assert ts.resolve("k1", now=NOW).status == TrustStatus.DISABLED_ISSUER
    assert ts.revoke_key("k2")
    assert ts.resolve("k2", now=NOW).status == TrustStatus.REVOKED_KEY


def test_summary_has_no_key_material():
    _, b1 = keypair("k1")
    ts = load_trust_config(config(issuer("iss-a", key_entry("k1", b1))))
    s = ts.summary()
    assert s[0]["issuer_id"] == "iss-a"
    assert "public_key_b64" not in json.dumps(s)
    assert b1 not in json.dumps(s)


# ---- Malformed config ----

def test_duplicate_kid_rejected():
    _, b1 = keypair("k1")
    _, b2 = keypair("k1b")
    with pytest.raises(TrustConfigError):
        load_trust_config(config(issuer("iss-a", key_entry("dup", b1)),
                                 issuer("iss-b", key_entry("dup", b2))))


def test_missing_issuers_rejected():
    with pytest.raises(TrustConfigError):
        load_trust_config({"nope": []})


def test_bad_public_key_rejected():
    with pytest.raises(TrustConfigError):
        load_trust_config(config(issuer("iss-a", key_entry("k1", "not-base64-32-bytes"))))


def test_empty_keys_rejected():
    with pytest.raises(TrustConfigError):
        load_trust_config(config({"issuer_id": "iss-a", "keys": []}))


# ---- Env loading: dev/test/pilot paths ----

def test_pilot_without_config_refuses_startup():
    with pytest.raises(TrustConfigError):
        trust_set_from_env({"MCC_ENV": "pilot"})


def test_dev_without_config_is_empty():
    ts = trust_set_from_env({"MCC_ENV": "dev"})
    assert ts.issuer_count == 0


def test_pilot_with_valid_config_loads(tmp_path):
    _, b1 = keypair("k1")
    cfg = tmp_path / "trust.json"
    cfg.write_text(json.dumps(config(issuer("iss-a", key_entry("k1", b1)))))
    ts = trust_set_from_env({"MCC_ENV": "pilot", "MCC_TRUST_CONFIG": str(cfg)})
    assert ts.resolve("k1", now=NOW).ok


def test_pilot_with_all_expired_keys_refuses_startup(tmp_path):
    _, b1 = keypair("k1")
    cfg = tmp_path / "trust.json"
    cfg.write_text(json.dumps(config(issuer("iss-a", key_entry("k1", b1, not_after=1)))))
    with pytest.raises(TrustConfigError):
        trust_set_from_env({"MCC_ENV": "pilot", "MCC_TRUST_CONFIG": str(cfg)})


def test_malformed_config_file_refuses(tmp_path):
    cfg = tmp_path / "trust.json"
    cfg.write_text("{ not json")
    with pytest.raises(TrustConfigError):
        trust_set_from_env({"MCC_ENV": "pilot", "MCC_TRUST_CONFIG": str(cfg)})
