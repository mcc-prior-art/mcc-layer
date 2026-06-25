"""Canonical Redis key model tests."""

from mcc_core import redis_keys


def test_prefix_format_namespace_schema_env_registry():
    p = redis_keys.prefix("nonce", {"MCC_ENV": "pilot"})
    assert p == "mcc:v1:pilot:nonce:"


def test_env_prefers_redis_namespace_over_env():
    p = redis_keys.prefix("idem", {"MCC_REDIS_NAMESPACE": "tenantA", "MCC_ENV": "pilot"})
    assert p == "mcc:v1:tenantA:idem:"


def test_env_defaults_when_absent():
    assert redis_keys.prefix("vel", {}) == "mcc:v1:default:vel:"


def test_env_is_normalized_and_bounded():
    # Unsafe characters collapse to '-'; never an empty segment.
    p = redis_keys.prefix("chal", {"MCC_ENV": "prod env/2:x"})
    assert p.startswith("mcc:v1:prod-env-2-x:chal:")
    assert redis_keys.prefix("chal", {"MCC_ENV": "///"}) == "mcc:v1:default:chal:"


def test_registry_types_never_collide():
    env = {"MCC_ENV": "p"}
    prefixes = {redis_keys.prefix(r, env) for r in ("nonce", "idem", "vel", "chal", "appr")}
    assert len(prefixes) == 5


def test_singleton_key_has_no_trailing_separator():
    assert redis_keys.singleton_key("revoked", {"MCC_ENV": "p"}) == "mcc:v1:p:revoked"


def test_hash_component_is_stable_and_opaque():
    a = redis_keys.hash_component("agent/ops")
    b = redis_keys.hash_component("agent/ops")
    c = redis_keys.hash_component("agent/other")
    assert a == b and a != c
    assert len(a) == 32 and "agent" not in a  # no raw content leaks into the key


def test_safe_segment_embeds_opaque_ids_but_hashes_risky_ones():
    # An opaque generated id is embedded as-is.
    assert redis_keys.safe_segment("vote-abc123_DEF.4") == "vote-abc123_DEF.4"
    # A value with separators / spaces / length is hashed instead.
    risky = "a:b c/" + "x" * 200
    seg = redis_keys.safe_segment(risky)
    assert ":" not in seg and " " not in seg and len(seg) == 32


def test_different_values_do_not_collide_via_separator_injection():
    # 'a' + ':' + 'b'  must not collide with 'a:b' once hashed.
    assert redis_keys.hash_component("a:b") != redis_keys.hash_component("a") + redis_keys.hash_component("b")
