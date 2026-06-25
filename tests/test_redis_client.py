"""Centralized Redis client builder tests (no real Redis required)."""

import pytest

from mcc_core import RedisConfigError, build_redis_client, redis_client_from_env


def test_from_env_without_url_raises():
    with pytest.raises(RedisConfigError):
        redis_client_from_env({})


def test_from_env_empty_url_raises():
    with pytest.raises(RedisConfigError):
        redis_client_from_env({"MCC_REDIS_URL": "   "})


def test_build_requires_url():
    with pytest.raises(RedisConfigError):
        build_redis_client("")


def test_from_env_builds_lazy_client_no_io():
    # Construction does not connect (lazy); just returns a client object.
    client = redis_client_from_env({"MCC_REDIS_URL": "redis://127.0.0.1:6379/0"})
    assert client is not None


def test_tls_scheme_accepted():
    client = redis_client_from_env({"MCC_REDIS_URL": "rediss://example:6379/0"})
    assert client is not None


def test_timeouts_parsed_with_safe_defaults():
    # Invalid numeric env values fall back to defaults rather than crashing.
    client = redis_client_from_env({
        "MCC_REDIS_URL": "redis://127.0.0.1:6379/0",
        "MCC_REDIS_OP_TIMEOUT_SECONDS": "not-a-number",
    })
    assert client is not None
