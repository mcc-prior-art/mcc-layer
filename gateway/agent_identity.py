"""Per-agent authenticated identity (V05 remediation, part 2).

PR #134 bound every signed mandate to a tenant. Within a tenant, though, the
gateway authenticated only the TENANT: one shared agent API key per mount.
``actor`` was a request field. So any caller holding that shared key could
execute a copied mandate by naming its subject as ``actor`` (reproduced on
main @ 1f0bd3a).

This module provides the server-controlled mapping

    presented credential (X-API-Key)  ->  (tenant_id, principal_id)

and the trusted :class:`AuthenticatedAgent` context the HTTP layer passes
explicitly into ``GovernanceService``.

Credential registry (``MCC_AGENT_CREDENTIALS_CONFIG``, a JSON file)::

    {"agents": [
      {"credential_id": "cred-payments-bot-1",
       "tenant_id": "tenant-1",
       "principal_id": "agent/payments-bot",
       "key_sha256": "<64 lowercase hex: sha256 of the raw key>",
       "status": "active"}            # or "revoked"
    ]}

* The server stores only SHA-256 hashes; the raw key is given to the agent
  only (see ``scripts/generate_agent_credential.py``).
* A credential maps to exactly ONE (tenant, principal). A principal may hold
  several active credentials, so a key can be rotated with no gap: add the
  new one, deploy it, then mark the old one ``revoked``.
* Fail-closed loading: a malformed file, an unknown field, a bad hash, an
  empty id, an unknown status, or a duplicate ``key_sha256`` /
  ``credential_id`` refuses to load -- never a partial registry.

Identity modes (``MCC_AGENT_IDENTITY_MODE``; server-side only):

* ``strict`` (default): identity routes require a registered, active
  credential of the mount's tenant. The authenticated principal must equal
  the requested ``actor`` and the signed mandate ``subject``. The mount's
  shared tenant key grants NO identity on those routes.
* ``legacy-shared-key``: explicit compatibility. The shared tenant key is
  accepted on identity routes and ``actor`` is caller-asserted, which is the
  pre-remediation behaviour. It gives NO protection against within-tenant
  impersonation. A registered credential is still enforced exactly as in
  strict mode.

What this does NOT do: it authenticates whoever presents an agent's key. It
does not prevent use of an agent's OWN credential by someone who stole it;
that would need proof of possession or a hardware-bound key, which is out of
scope. Rotation and revocation are the response to a stolen key.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

AGENT_IDENTITY_STRICT = "strict"
AGENT_IDENTITY_LEGACY = "legacy-shared-key"
AGENT_IDENTITY_MODES = (AGENT_IDENTITY_STRICT, AGENT_IDENTITY_LEGACY)

_HEX64 = re.compile(r"[0-9a-f]{64}")
_FIELDS = {"credential_id", "tenant_id", "principal_id", "key_sha256", "status"}
_STATUSES = ("active", "revoked")


class AgentCredentialConfigError(ValueError):
    """The agent credential registry is malformed or ambiguous (fail closed)."""


class AgentIdentityError(PermissionError):
    """An identity-bound request is not authorized for the asserted actor."""


@dataclass(frozen=True)
class AuthenticatedAgent:
    """The TRUSTED, server-resolved identity of an individually
    authenticated agent. The HTTP layer creates it only from a registered
    credential. A direct library caller that constructs one is asserting it
    authenticated that agent itself -- that is the library trust boundary."""

    tenant_id: str
    principal_id: str
    credential_id: str


def hash_agent_key(raw_key: str) -> str:
    """The registry form of a raw agent key: lowercase hex SHA-256."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def agent_identity_mode_from_env(env: Mapping[str, str]) -> str:
    raw = (env.get("MCC_AGENT_IDENTITY_MODE") or "").strip()
    mode = raw or AGENT_IDENTITY_STRICT
    if mode not in AGENT_IDENTITY_MODES:
        raise ValueError(
            f"MCC_AGENT_IDENTITY_MODE={raw!r} is invalid; expected one of {AGENT_IDENTITY_MODES}")
    return mode


@dataclass(frozen=True)
class _Entry:
    credential_id: str
    tenant_id: str
    principal_id: str
    active: bool


class AgentCredentialRegistry:
    """Server-side credential -> (tenant, principal) resolution."""

    def __init__(self, entries: Optional[list] = None) -> None:
        self._by_hash: Dict[str, _Entry] = {}
        ids = set()
        for i, raw in enumerate(entries or []):
            if not isinstance(raw, dict):
                raise AgentCredentialConfigError(f"agents[{i}] must be an object")
            unknown = set(raw) - _FIELDS
            missing = _FIELDS - set(raw)
            if unknown or missing:
                raise AgentCredentialConfigError(
                    f"agents[{i}]: unknown fields {sorted(unknown)} / missing fields {sorted(missing)}")
            for f in ("credential_id", "tenant_id", "principal_id"):
                v = raw[f]
                if not isinstance(v, str) or not v.strip() or v != v.strip():
                    raise AgentCredentialConfigError(f"agents[{i}].{f} must be a non-empty, unpadded string")
            if not isinstance(raw["key_sha256"], str) or not _HEX64.fullmatch(raw["key_sha256"]):
                raise AgentCredentialConfigError(f"agents[{i}].key_sha256 must be 64 lowercase hex chars")
            if raw["status"] not in _STATUSES:
                raise AgentCredentialConfigError(f"agents[{i}].status must be one of {_STATUSES}")
            if raw["key_sha256"] in self._by_hash:
                raise AgentCredentialConfigError(
                    f"agents[{i}]: duplicate key_sha256 (one key may identify exactly one principal)")
            if raw["credential_id"] in ids:
                raise AgentCredentialConfigError(f"agents[{i}]: duplicate credential_id")
            ids.add(raw["credential_id"])
            self._by_hash[raw["key_sha256"]] = _Entry(
                raw["credential_id"], raw["tenant_id"], raw["principal_id"], raw["status"] == "active")

    @classmethod
    def from_config(cls, config: Any) -> "AgentCredentialRegistry":
        if not isinstance(config, dict) or set(config) != {"agents"} or not isinstance(config["agents"], list):
            raise AgentCredentialConfigError('agent credential config must be {"agents": [...]}')
        return cls(config["agents"])

    @classmethod
    def from_file(cls, path: str) -> "AgentCredentialRegistry":
        try:
            with open(path, "r", encoding="utf-8") as f:
                config = json.load(f)
        except (OSError, ValueError) as exc:
            raise AgentCredentialConfigError(f"cannot load agent credential config {path!r}: {exc}") from exc
        return cls.from_config(config)

    def __len__(self) -> int:
        return len(self._by_hash)

    def resolve(self, presented_key: Any, *, tenant_id: str) -> "Resolution":
        """Resolve a presented key for the mount's trusted ``tenant_id``.
        Never raises; an unknown, revoked or other-tenant key is a refusal."""
        if not isinstance(presented_key, str) or not presented_key:
            return Resolution("AGENT_CREDENTIAL_MISSING", None)
        digest = hash_agent_key(presented_key)
        entry = None
        for known, candidate in self._by_hash.items():   # constant-time compare of each hash
            if secrets.compare_digest(known, digest):
                entry = candidate
        if entry is None:
            return Resolution("AGENT_CREDENTIAL_UNKNOWN", None)
        if not entry.active:
            return Resolution("AGENT_CREDENTIAL_REVOKED", None)
        if entry.tenant_id != tenant_id:
            return Resolution("AGENT_CREDENTIAL_WRONG_TENANT", None)
        return Resolution(None, AuthenticatedAgent(entry.tenant_id, entry.principal_id, entry.credential_id))


@dataclass(frozen=True)
class Resolution:
    error: Optional[str]
    agent: Optional[AuthenticatedAgent]


def agent_identity_error(agent: Any, *, tenant_id: Any, actor: Any, mode: str) -> Optional[str]:
    """Why an identity-bound request may NOT proceed for ``actor`` in
    ``tenant_id``, or ``None``. Pure and total; never raises.

    ``agent`` must be the trusted :class:`AuthenticatedAgent` (never derived
    from ``actor`` or a mandate). In strict mode an absent agent is refused --
    it never falls back to trusting ``actor``."""
    if mode not in AGENT_IDENTITY_MODES:
        return f"AGENT_IDENTITY_MODE_INVALID: {mode!r}; fail-closed"
    if agent is None:
        if mode == AGENT_IDENTITY_LEGACY:
            return None
        return ("AGENT_IDENTITY_REQUIRED: no individually authenticated agent; "
                "a shared tenant credential cannot assert an actor")
    if not isinstance(agent, AuthenticatedAgent):
        return "AGENT_IDENTITY_INVALID: untrusted identity context; fail-closed"
    if agent.tenant_id != tenant_id:
        return "AGENT_TENANT_MISMATCH: authenticated agent belongs to another tenant"
    if agent.principal_id != actor:
        return "AGENT_PRINCIPAL_MISMATCH: authenticated agent is not the requested actor"
    return None
