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


def agent_registry_from_env(env: Mapping[str, str]) -> Optional["AgentCredentialRegistry"]:
    """F1b: the hash-only registry named by ``MCC_AGENT_CREDENTIALS_CONFIG``,
    or ``None`` when unset. A set-but-unusable file raises
    (AgentCredentialConfigError) -- never a silent fallback."""
    path = (env.get("MCC_AGENT_CREDENTIALS_CONFIG") or "").strip()
    return AgentCredentialRegistry.from_file(path) if path else None


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
    def from_key_map(cls, keys: Mapping[str, Any]) -> "AgentCredentialRegistry":
        """F1b convenience for in-process composition (examples, tests):
        ``{raw_key: (tenant_id, principal_id)}`` -> a registry holding only
        the keys' SHA-256 hashes. Same fail-closed validation as a file."""
        return cls([
            {"credential_id": f"cred-{i}", "tenant_id": t, "principal_id": p,
             "key_sha256": hash_agent_key(k), "status": "active"}
            for i, (k, (t, p)) in enumerate(sorted(keys.items()))])

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

    def principals_in_multiple_tenants(self) -> list:
        """F1b: principal ids registered in more than one tenant. Runtimes
        whose consensus evidence is bound to the actor but not the tenant
        (``main.py``) refuse to start with such a registry."""
        seen: Dict[str, set] = {}
        for e in self._by_hash.values():
            seen.setdefault(e.principal_id, set()).add(e.tenant_id)
        return sorted(p for p, t in seen.items() if len(t) > 1)

    def is_registered_principal(self, principal_id: Any, *, tenant_id: str) -> bool:
        """F1: whether ``principal_id`` is an agent identity of ``tenant_id``
        in this registry -- ANY status (a revoked agent is still an agent
        identity the shared tenant key must not assume). Never raises."""
        if not isinstance(principal_id, str):
            return False
        return any(e.principal_id == principal_id and e.tenant_id == tenant_id
                   for e in self._by_hash.values())

    def authenticate(self, presented_key: Any) -> "Resolution":
        """F1b: resolve a presented key to its registered (tenant, principal)
        WITHOUT an expected tenant -- for multi-tenant surfaces (the Pilot
        Execution API, main.py) where the credential itself names the
        tenant. Never raises; unknown/revoked keys are refusals."""
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
        return Resolution(None, AuthenticatedAgent(entry.tenant_id, entry.principal_id, entry.credential_id))

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


def evaluate_identity_error(agent: Any, *, tenant_id: Any, identities: Any, mode: str,
                            registry: Any = None) -> Optional[str]:
    """Why a decision request (``POST /evaluate``) may NOT be made for the
    named ``identities`` (the request's ``identity`` and ``actor_id``), or
    ``None``. Pure and total; never raises.

    ``/evaluate`` returns a SIGNED decision token whose subject/actor is the
    named identity, and its verdict depends on that identity's mandates, so
    naming an identity is an authority claim.

    * A registered credential (``agent``) may evaluate ONLY as itself: every
      named identity must equal its principal, in its tenant -- every mode.
    * F1b: in strict mode the mount's shared tenant/service key
      (``agent is None``) is refused for EVERY identity, registered or not.
      A service that needs decisions authenticates as its own registered
      principal; there is no caller-selected service identity. Only the
      explicit ``legacy-shared-key`` mode accepts it (no protection).
      (``registry`` is accepted for backward compatibility and ignored.)"""
    if mode not in AGENT_IDENTITY_MODES:
        return f"AGENT_IDENTITY_MODE_INVALID: {mode!r}; fail-closed"
    try:
        named = [i for i in identities if i is not None]
    except TypeError:
        return "AGENT_IDENTITY_INVALID: malformed identities; fail-closed"
    if agent is not None:
        if not isinstance(agent, AuthenticatedAgent):
            return "AGENT_IDENTITY_INVALID: untrusted identity context; fail-closed"
        if agent.tenant_id != tenant_id:
            return "AGENT_TENANT_MISMATCH: authenticated agent belongs to another tenant"
        if not named or any(i != agent.principal_id for i in named):
            return ("AGENT_PRINCIPAL_MISMATCH: a credential may obtain decisions only for "
                    "its own principal")
        return None
    if mode == AGENT_IDENTITY_LEGACY:
        return None
    return ("AGENT_IDENTITY_REQUIRED: the shared tenant/service credential cannot obtain "
            "decisions; authenticate as an individually registered principal")


def principal_binding_error(agent: Any, *, claimed: Any, mode: str) -> Optional[str]:
    """F1b: the generic runtime check -- why a request whose caller-supplied
    actor/identity field is ``claimed`` may NOT proceed for the
    authenticated ``agent``, or ``None``. Pure and total.

    ``claimed`` is never proof: it must EQUAL the authenticated principal
    (``None``/omitted claims are filled from the principal by the caller).
    Strict mode refuses an omitted agent; legacy mode accepts it."""
    if mode not in AGENT_IDENTITY_MODES:
        return f"AGENT_IDENTITY_MODE_INVALID: {mode!r}; fail-closed"
    if agent is None:
        if mode == AGENT_IDENTITY_LEGACY:
            return None
        return ("AGENT_IDENTITY_REQUIRED: no individually authenticated principal; "
                "a shared service credential cannot assert an actor")
    if not isinstance(agent, AuthenticatedAgent):
        return "AGENT_IDENTITY_INVALID: untrusted identity context; fail-closed"
    if claimed is not None and claimed != agent.principal_id:
        return "AGENT_PRINCIPAL_MISMATCH: authenticated principal is not the requested actor"
    return None
