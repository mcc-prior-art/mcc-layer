"""Governed credential references for the egress executor.

The agent proposes a *reference* (``credential_ref`` / ``client_identity_ref`` /
``ca_bundle_ref``) — never raw secret material. The reference is part of the
governed canonical action (bound by the payload hash, evaluated by authority /
consensus / approval). Raw secrets are resolved **only inside the trusted
executor, only after governance authorization + durable audit**, and only after
the reference's *scope* is re-authorized against the final action.

This module is the credential boundary:

* :class:`CredentialScope` — the destination/operation a credential is requested
  for (host/port/method/action/env/path/actor);
* :class:`CredentialBinding` — the scope a reference is allowed for (fail-closed);
* typed resolved material — secret-header / client-identity / CA-bundle — whose
  ``repr`` never reveals the secret;
* :class:`CredentialProvider` — the resolver interface, with a safe in-memory
  (tests) and environment-backed (local pilot) implementation. The interface is
  shaped so external adapters (Vault / AWS / GCP / Azure / k8s) can be added
  without changing the executor.

No production secret-manager dependency is introduced.
"""

from __future__ import annotations

import fnmatch
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

SECRET_HEADER = "secret_header"
CLIENT_IDENTITY = "client_identity"
CA_BUNDLE = "ca_bundle"

# Headers a caller may never set directly (they are resolved from references and
# injected inside the executor). A proposal carrying one of these fails closed.
SECRET_BEARING_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie",
    "x-api-key", "x-operator-key", "api-key",
})


class CredentialError(Exception):
    """A credential reference could not be resolved/authorized (fail-closed).

    Messages NEVER contain secret material — only the reference id and a reason.
    """


@dataclass(frozen=True)
class CredentialScope:
    host: str
    port: int
    method: str
    action: str
    env: str
    path: str = "/"
    actor: Optional[str] = None


@dataclass(frozen=True)
class CredentialBinding:
    """The scope a reference is permitted for. Empty tuple = unconstrained on that
    dimension; ``allowed_hosts`` supports fnmatch patterns (e.g. ``*.stripe.com``)."""

    allowed_hosts: Tuple[str, ...] = ()
    allowed_ports: Tuple[int, ...] = ()
    allowed_methods: Tuple[str, ...] = ()
    allowed_actions: Tuple[str, ...] = ()
    allowed_envs: Tuple[str, ...] = ()
    path_prefix: Optional[str] = None
    actor: Optional[str] = None

    def permits(self, scope: CredentialScope) -> Optional[str]:
        """Return a denial reason, or None if the scope is allowed (fail-closed:
        an empty allow-list for hosts/methods/actions/envs denies everything)."""
        if not self.allowed_hosts or not _host_match(scope.host, self.allowed_hosts):
            return "host out of credential scope"
        if self.allowed_ports and int(scope.port) not in self.allowed_ports:
            return "port out of credential scope"
        if not self.allowed_methods or scope.method.upper() not in \
                {m.upper() for m in self.allowed_methods}:
            return "method out of credential scope"
        if not self.allowed_actions or scope.action not in self.allowed_actions:
            return "action out of credential scope"
        if not self.allowed_envs or scope.env not in self.allowed_envs:
            return "environment out of credential scope"
        if self.path_prefix and not (scope.path or "/").startswith(self.path_prefix):
            return "path out of credential scope"
        if self.actor is not None and scope.actor != self.actor:
            return "actor out of credential scope"
        return None

    @classmethod
    def from_config(cls, data: Mapping[str, Any]) -> "CredentialBinding":
        return cls(
            allowed_hosts=tuple(h.lower() for h in data.get("allowed_hosts", [])),
            allowed_ports=tuple(int(p) for p in data.get("allowed_ports", [])),
            allowed_methods=tuple(data.get("allowed_methods", [])),
            allowed_actions=tuple(data.get("allowed_actions", [])),
            allowed_envs=tuple(data.get("allowed_envs", [])),
            path_prefix=data.get("path_prefix"),
            actor=data.get("actor"))


def _host_match(host: str, patterns: Tuple[str, ...]) -> bool:
    host = host.lower()
    return any(fnmatch.fnmatchcase(host, p.lower()) for p in patterns)


# --------------------------------------------------------------------------
# Resolved credential material (secrets) — repr/str never reveal the value.
# --------------------------------------------------------------------------

class _Redacted:
    type: str = "credential"

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"<{type(self).__name__} type={self.type} REDACTED>"

    __str__ = __repr__


@dataclass(frozen=True, repr=False)
class SecretHeaderCredential(_Redacted):
    header_name: str
    value: str
    ref: str = ""
    type: str = SECRET_HEADER


@dataclass(frozen=True, repr=False)
class ClientIdentityCredential(_Redacted):
    cert_pem: bytes
    key_pem: bytes
    ref: str = ""
    type: str = CLIENT_IDENTITY


@dataclass(frozen=True, repr=False)
class CABundleCredential(_Redacted):
    ca_pem: bytes
    ref: str = ""
    type: str = CA_BUNDLE


# --------------------------------------------------------------------------
# Provider interface + safe implementations
# --------------------------------------------------------------------------

class CredentialProvider(ABC):
    """Resolve a credential reference inside the trusted boundary.

    Implementations MUST: verify the reference exists; authorize the scope
    (``binding.permits``); verify the credential type matches the requested use;
    return typed material; and fail closed (raise :class:`CredentialError`,
    without secrets in the message) for anything unknown or unauthorized."""

    @abstractmethod
    async def resolve(self, ref: str, *, scope: CredentialScope, expected_type: str) -> Any:
        ...


@dataclass
class CredentialEntry:
    binding: CredentialBinding
    type: str
    # Material is supplied by a zero-arg loader so env-backed providers read the
    # raw value lazily (only at resolve time, inside the boundary).
    loader: Any  # Callable[[], Any]
    header_name: Optional[str] = None


class InMemoryCredentialProvider(CredentialProvider):
    """Deterministic provider for tests (material held in memory)."""

    def __init__(self, entries: Dict[str, CredentialEntry]) -> None:
        self._entries = dict(entries)

    async def resolve(self, ref, *, scope, expected_type):
        entry = self._entries.get(ref)
        if entry is None:
            raise CredentialError(f"unknown credential reference {ref!r}")
        if entry.type != expected_type:
            raise CredentialError(
                f"credential {ref!r} is type {entry.type!r}, not {expected_type!r}")
        denial = entry.binding.permits(scope)
        if denial:
            raise CredentialError(f"credential {ref!r} not authorized: {denial}")
        return _materialize(ref, entry)


class EnvCredentialProvider(CredentialProvider):
    """Local/pilot provider: scope/types come from a (committed, secret-free)
    config; raw values come from environment variables named by that config.
    **Not for production** — a real deployment swaps in an external adapter."""

    def __init__(self, entries: Dict[str, CredentialEntry]) -> None:
        self._entries = dict(entries)

    async def resolve(self, ref, *, scope, expected_type):
        entry = self._entries.get(ref)
        if entry is None:
            raise CredentialError(f"unknown credential reference {ref!r}")
        if entry.type != expected_type:
            raise CredentialError(
                f"credential {ref!r} is type {entry.type!r}, not {expected_type!r}")
        denial = entry.binding.permits(scope)
        if denial:
            raise CredentialError(f"credential {ref!r} not authorized: {denial}")
        return _materialize(ref, entry)


def _materialize(ref: str, entry: CredentialEntry):
    try:
        raw = entry.loader()
    except CredentialError:
        raise
    except Exception as exc:  # noqa: BLE001 — never leak the underlying value/source
        raise CredentialError(f"credential {ref!r} material unavailable") from None
    if raw is None:
        raise CredentialError(f"credential {ref!r} material missing")
    if entry.type == SECRET_HEADER:
        return SecretHeaderCredential(header_name=(entry.header_name or "authorization").lower(),
                                      value=str(raw), ref=ref)
    if entry.type == CLIENT_IDENTITY:
        cert, key = raw
        if not cert or not key:
            raise CredentialError(f"credential {ref!r} client identity incomplete")
        return ClientIdentityCredential(cert_pem=_b(cert), key_pem=_b(key), ref=ref)
    if entry.type == CA_BUNDLE:
        return CABundleCredential(ca_pem=_b(raw), ref=ref)
    raise CredentialError(f"credential {ref!r} unsupported type {entry.type!r}")


def _b(v: Any) -> bytes:
    return v if isinstance(v, (bytes, bytearray)) else str(v).encode("utf-8")


# --------------------------------------------------------------------------
# Config-driven construction (no secrets in the config; values via env)
# --------------------------------------------------------------------------

class CredentialConfigError(Exception):
    """The credential provider configuration is invalid (fail-closed startup)."""


def build_provider_from_config(provider: str, config: Optional[Dict[str, Any]],
                               env: Optional[Mapping[str, str]] = None) -> Optional[CredentialProvider]:
    """Build a provider from ``provider`` ('none'|'env'|'memory') + a secret-free
    config mapping. The 'env' provider reads raw values from environment variables
    named by the config (never from the committed config itself)."""
    provider = (provider or "none").strip().lower()
    if provider in ("", "none"):
        return None
    if config is None or "credentials" not in config:
        raise CredentialConfigError("credential provider configured but no 'credentials' config")
    env = os.environ if env is None else env
    entries: Dict[str, CredentialEntry] = {}
    for ref, spec in config["credentials"].items():
        ctype = spec.get("type")
        binding = CredentialBinding.from_config(spec.get("binding", {}))
        if ctype == SECRET_HEADER:
            var = spec.get("env_var")
            if not var:
                raise CredentialConfigError(f"{ref}: secret_header requires env_var")
            entries[ref] = CredentialEntry(
                binding=binding, type=ctype, header_name=(spec.get("header") or "authorization"),
                loader=_env_loader(env, var))
        elif ctype == CLIENT_IDENTITY:
            cvar, kvar = spec.get("cert_env_var"), spec.get("key_env_var")
            if not cvar or not kvar:
                raise CredentialConfigError(f"{ref}: client_identity requires cert/key env vars")
            entries[ref] = CredentialEntry(
                binding=binding, type=ctype,
                loader=_pair_loader(env, cvar, kvar))
        elif ctype == CA_BUNDLE:
            var = spec.get("env_var")
            if not var:
                raise CredentialConfigError(f"{ref}: ca_bundle requires env_var")
            entries[ref] = CredentialEntry(binding=binding, type=ctype,
                                           loader=_env_loader(env, var))
        else:
            raise CredentialConfigError(f"{ref}: unknown credential type {ctype!r}")
    if provider == "env":
        return EnvCredentialProvider(entries)
    if provider == "memory":
        return InMemoryCredentialProvider(entries)
    raise CredentialConfigError(f"unknown credential provider {provider!r}")


def _env_loader(env: Mapping[str, str], var: str):
    def load():
        val = env.get(var)
        return val if val else None
    return load


def _pair_loader(env: Mapping[str, str], cvar: str, kvar: str):
    def load():
        cert, key = env.get(cvar), env.get(kvar)
        # Values may be PEM text or a path to a PEM file (local pilot convenience).
        return (_read_pem(cert), _read_pem(key)) if cert and key else None
    return load


def _read_pem(value: Optional[str]) -> Optional[bytes]:
    if not value:
        return None
    if "BEGIN" in value:
        return value.encode("utf-8")
    if os.path.exists(value):
        return open(value, "rb").read()
    return value.encode("utf-8")
