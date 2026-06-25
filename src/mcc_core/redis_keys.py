"""Canonical Redis key model for shared governance state.

All Redis-backed governance registries derive their key namespace from one place
so that multiple MCC runtime instances address the *same* logical state and
cannot collide across registry types, environments, or schema versions.

Key format::

    mcc:{schema}:{env}:{registry}:{suffix}

* ``mcc``      — fixed product namespace.
* ``schema``   — key-schema version (``v1``); lets the format evolve without
                 silently reading an incompatible layout.
* ``env``      — deployment / environment / trust-domain separator
                 (``MCC_REDIS_NAMESPACE`` or ``MCC_ENV``; normalized).
* ``registry`` — the registry type (``nonce``, ``idem``, ``vel``, ``chal``,
                 ``appr``, ``revoked`` …), so types never share a key space.
* ``suffix``   — the per-record identifier(s). Long, sensitive, or
                 attacker-controlled components are SHA-256 hashed via
                 :func:`hash_component` rather than embedded raw, so key names
                 never carry secrets/payloads and cannot be made to collide by
                 crafting separators.

This module constructs *prefixes*; the individual registries keep their existing
internal key shapes under the canonical prefix. No secret or raw payload is ever
placed in a key name.
"""

from __future__ import annotations

import hashlib
import re
from typing import Mapping, Optional

PRODUCT = "mcc"
SCHEMA_VERSION = "v1"

# A conservative charset for key segments that we embed raw (already-opaque
# generated ids: uuids, token_urlsafe nonces, hashes). Anything outside this is
# hashed rather than embedded, so an attacker cannot inject ':' separators.
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")
# Environment / namespace label: short, normalized.
_ENV_SAFE = re.compile(r"[^A-Za-z0-9._\-]")


def normalize_env(env: Optional[Mapping[str, str]] = None) -> str:
    """The deployment/trust-domain segment. Prefers ``MCC_REDIS_NAMESPACE``,
    falls back to ``MCC_ENV``, else ``default``. Normalized to the safe charset
    and bounded; empty/invalid -> ``default`` (never an empty segment)."""
    import os

    src = os.environ if env is None else env
    raw = (src.get("MCC_REDIS_NAMESPACE") or src.get("MCC_ENV") or "default").strip()
    norm = _ENV_SAFE.sub("-", raw)[:64].strip("-")
    return norm or "default"


def hash_component(value: object) -> str:
    """Stable, collision-resistant token for a long/sensitive/attacker-controlled
    key component. SHA-256 over the UTF-8 string form, truncated to 32 hex chars
    (128 bits) — enough to make collisions infeasible while keeping keys short.
    Never reversible to the original content."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:32]


def safe_segment(value: object) -> str:
    """Return ``value`` verbatim if it is already a short, opaque, separator-free
    identifier; otherwise return its :func:`hash_component`. This guarantees a
    key segment can never contain a raw secret, a payload, or an injected ``:``."""
    s = str(value)
    return s if _SAFE_SEGMENT.match(s) else hash_component(s)


def prefix(registry: str, env: Optional[Mapping[str, str]] = None) -> str:
    """Canonical key prefix for a registry type, ending in ``:`` so a registry
    can append its own identifier(s):  ``mcc:v1:{env}:{registry}:``."""
    return f"{PRODUCT}:{SCHEMA_VERSION}:{normalize_env(env)}:{registry}:"


def singleton_key(registry: str, env: Optional[Mapping[str, str]] = None) -> str:
    """Canonical key for a single shared structure (e.g. the revocation set):
    ``mcc:v1:{env}:{registry}`` (no trailing separator)."""
    return f"{PRODUCT}:{SCHEMA_VERSION}:{normalize_env(env)}:{registry}"
