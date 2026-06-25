"""Centralized Redis client construction for governance registries.

One place builds the async Redis client so timeouts, TLS, and connection limits
are consistent and credentials are never logged. Registries call
:func:`redis_client_from_env` (or pass an explicit URL) instead of each
re-deriving connection options.

Configuration (all optional except the URL):

* ``MCC_REDIS_URL``                — ``redis://`` or ``rediss://`` (TLS) URL.
* ``MCC_REDIS_OP_TIMEOUT_SECONDS`` — per-operation socket timeout (default 0.5).
* ``MCC_REDIS_CONNECT_TIMEOUT_SECONDS`` — connect timeout (default 1.0).

TLS is selected by the URL scheme (``rediss://``) per standard redis-py
conventions; no credential material is read from or written to logs here.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

DEFAULT_OP_TIMEOUT_SECONDS = 0.5
DEFAULT_CONNECT_TIMEOUT_SECONDS = 1.0


class RedisConfigError(Exception):
    """Raised when a Redis client is required but cannot be configured."""


def _f(src: Mapping[str, str], key: str, default: float) -> float:
    try:
        v = src.get(key)
        return float(v) if v not in (None, "") else default
    except (TypeError, ValueError):
        return default


def build_redis_client(
    url: str,
    *,
    op_timeout_seconds: float = DEFAULT_OP_TIMEOUT_SECONDS,
    connect_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT_SECONDS,
) -> Any:
    """Build an async redis client (lazy connect — no I/O here). The first real
    command is where an outage surfaces, and it surfaces as a fail-closed denial
    in the registries, never a fallback. ``rediss://`` enables TLS."""
    if not url or not isinstance(url, str):
        raise RedisConfigError("a non-empty MCC_REDIS_URL is required")
    import redis.asyncio as redis  # local import: optional dependency in dev

    return redis.from_url(
        url,
        socket_timeout=op_timeout_seconds,
        socket_connect_timeout=connect_timeout_seconds,
        decode_responses=True,
    )


def redis_client_from_env(env: Optional[Mapping[str, str]] = None) -> Any:
    """Build the governance Redis client from the environment. Raises
    ``RedisConfigError`` if ``MCC_REDIS_URL`` is absent — callers that require
    Redis must fail closed at startup rather than run unprotected."""
    import os

    src = os.environ if env is None else env
    url = (src.get("MCC_REDIS_URL") or "").strip()
    if not url:
        raise RedisConfigError("MCC_REDIS_URL is not set")
    return build_redis_client(
        url,
        op_timeout_seconds=_f(src, "MCC_REDIS_OP_TIMEOUT_SECONDS", DEFAULT_OP_TIMEOUT_SECONDS),
        connect_timeout_seconds=_f(
            src, "MCC_REDIS_CONNECT_TIMEOUT_SECONDS", DEFAULT_CONNECT_TIMEOUT_SECONDS
        ),
    )
