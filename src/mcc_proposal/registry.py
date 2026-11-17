"""Proposal registry — durable inbox for logical operations that have been
PROPOSED but not yet admitted for execution.

Deliberately distinct from ``mcc_core.idempotency`` (Section 6): ``RESERVED``
there has a precise security meaning -- a durably admitted, pre-dispatch
logical operation on the real execution path. A proposal has not been
admitted for anything; it is purely informational bookkeeping proving "this
identity was already claimed for this exact binding." This module never
imports, calls, or wraps ``reserve``/``commit_dispatch``/``mark_executed``/
``mark_unknown``/``resolve_unknown`` -- those remain exclusively the
coordinator's.

Tenant isolation (Section 7): every operation is scoped by
``(tenant_id, logical_operation_id)``. ``tenant_id`` must be the caller's
AUTHENTICATED identity as established by the transport layer -- never a
value taken from proposal payload/actor fields.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Tuple


class ProposalRegisterStatus(str, Enum):
    REGISTERED = "REGISTERED"                    # first time; now PROPOSED
    IDEMPOTENT_DUPLICATE = "IDEMPOTENT_DUPLICATE"  # identical binding already registered
    BINDING_CONFLICT = "BINDING_CONFLICT"          # same key, different binding
    ERROR = "ERROR"                                # indeterminate -> fail closed


@dataclass(frozen=True)
class ProposalRegisterResult:
    status: ProposalRegisterStatus
    reason: str
    binding: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status in (ProposalRegisterStatus.REGISTERED, ProposalRegisterStatus.IDEMPOTENT_DUPLICATE)


@dataclass(frozen=True)
class ProposalRecord:
    tenant_id: str
    logical_operation_id: str
    binding: str
    created_at: float
    # Phase 2 (MCC_UNIVERSAL_PROPOSAL_SERVICE_PHASE2): the exact canonical
    # content this binding was computed over. Stored so a later authorization
    # decision has ONE source of truth for what it is authorizing -- never an
    # independently re-supplied action/resource/payload that could diverge
    # from what was actually proposed and bound. ``None`` for records written
    # before this field existed, or written directly via the low-level
    # registry API without content (Phase-1-only registration) -- callers
    # that need to execute MUST treat ``action is None`` as "no governable
    # content available" and fail closed rather than guess.
    action: Optional[str] = None
    resource: Optional[str] = None
    payload: Optional[Dict[str, Any]] = None
    # F1b: the individually authenticated principal that submitted this
    # proposal (server-resolved from its credential, never the body's
    # ``actor``). Only that principal may execute it or read its status.
    # ``None`` for records written before F1b / by legacy shared-key
    # callers -- a principal-bound executor treats those as not its own.
    principal_id: Optional[str] = None


class ProposalBackendUnavailable(Exception):
    """Raised by ``get`` when the backend cannot give a definite answer.
    Callers MUST NOT treat this as "not found" -- see ``ProposalStatus``
    composition rules (Section 8/19): backend uncertainty is UNAVAILABLE,
    never NOT_FOUND, never "safe to retry"."""


class ProposalConfigError(Exception):
    """Raised when the proposal backend is misconfigured (fail-closed start)."""


def _tenant_key(tenant_id: str, logical_operation_id: str) -> str:
    # Delimiter-safe: tenant_id/logical_operation_id are caller-controlled
    # strings, so an in-process dict key uses a tuple (no injection surface);
    # the Redis backend below hashes both segments instead of concatenating
    # raw strings with a guessable separator.
    return f"{tenant_id}\x00{logical_operation_id}"


class InMemoryProposalRegistry:
    """Single-process proposal inbox (dev / tests). Atomic the same way
    ``InMemoryIdempotencyRegistry`` is: the whole critical section runs
    without an ``await`` in between, so no other coroutine on this event
    loop can interleave a conflicting write. NOT durable and NOT
    multi-instance -- a real deployment configures the Redis backend."""

    def __init__(self) -> None:
        self._store: Dict[str, ProposalRecord] = {}

    async def register(
        self, *, tenant_id: str, logical_operation_id: str, binding: str,
        action: Optional[str] = None, resource: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None, principal_id: Optional[str] = None,
    ) -> ProposalRegisterResult:
        key = _tenant_key(tenant_id, logical_operation_id)
        existing = self._store.get(key)
        if existing is None:
            self._store[key] = ProposalRecord(
                tenant_id=tenant_id, logical_operation_id=logical_operation_id,
                binding=binding, created_at=time.time(),
                action=action, resource=resource, payload=payload, principal_id=principal_id,
            )
            return ProposalRegisterResult(ProposalRegisterStatus.REGISTERED, "registered", binding)
        if existing.principal_id != principal_id:
            # F1b: another principal (or a pre-F1b/legacy record) already owns
            # this identity -- never an idempotent duplicate for this caller.
            return ProposalRegisterResult(
                ProposalRegisterStatus.BINDING_CONFLICT,
                "logical_operation_id is already bound to a different principal",
                existing.binding,
            )
        if existing.binding == binding:
            return ProposalRegisterResult(
                ProposalRegisterStatus.IDEMPOTENT_DUPLICATE, "identical proposal already registered", binding,
            )
        return ProposalRegisterResult(
            ProposalRegisterStatus.BINDING_CONFLICT,
            "logical_operation_id is already bound to a different action/resource/payload",
            existing.binding,
        )

    async def get(self, *, tenant_id: str, logical_operation_id: str) -> Optional[ProposalRecord]:
        return self._store.get(_tenant_key(tenant_id, logical_operation_id))


_REGISTER_LUA = """
local cur = redis.call('GET', KEYS[1])
if not cur then
    redis.call('SET', KEYS[1], ARGV[1])
    return {'REGISTERED', ARGV[2]}
end
local ok, decoded = pcall(cjson.decode, cur)
if not ok or type(decoded) ~= 'table' or decoded.binding == nil then
    return {'ERROR', ''}
end
local owner = decoded.principal_id
if owner == nil or owner == cjson.null then owner = '' end
if owner ~= ARGV[3] then
    return {'BINDING_CONFLICT', decoded.binding}
end
if decoded.binding == ARGV[2] then
    return {'IDEMPOTENT_DUPLICATE', decoded.binding}
end
return {'BINDING_CONFLICT', decoded.binding}
"""


class RedisProposalRegistry:
    """Durable, multi-instance proposal inbox backed by Redis. The one atomic
    moment (first-writer-wins) is a single Lua script -- exactly one
    concurrent caller creates the key; every racing caller after that either
    observes IDEMPOTENT_DUPLICATE (same binding) or BINDING_CONFLICT
    (different binding), never a mixed/overwritten record.

    Phase 2 (MCC_UNIVERSAL_PROPOSAL_SERVICE_PHASE2): the stored value is a
    single JSON document (``{"binding", "created_at", "action", "resource",
    "payload"}``) rather than the Phase-1 ``binding|created_at`` pipe format
    -- a proposal's governable content (action/resource/canonical payload),
    not merely its binding hash, must be durably available so a later
    authorization decision has ONE source of truth and never accepts an
    independently re-supplied payload (Section 2). ``ARGV[1]`` is the full
    candidate record as JSON (used only when creating); ``ARGV[2]`` is the
    binding string alone (used for the idempotent-duplicate/conflict
    comparison against whatever is already stored, without needing to
    re-decode the candidate). The Lua script never trusts client-supplied
    JSON blindly for the *existing* value -- it decodes the STORED value
    itself and fails closed (``ERROR``) if that stored value is not
    well-formed JSON carrying a ``binding`` field."""

    def __init__(self, redis_client: Any, *, namespace: str) -> None:
        self._redis = redis_client
        self._namespace = namespace

    @classmethod
    def from_url(cls, url: str, *, namespace: str, connect_timeout_seconds: float = 1.0) -> "RedisProposalRegistry":
        import redis.asyncio as redis

        client = redis.from_url(
            url, socket_timeout=1.0, socket_connect_timeout=connect_timeout_seconds,
            decode_responses=True,
        )
        return cls(client, namespace=namespace)

    def _key(self, tenant_id: str, logical_operation_id: str) -> str:
        from mcc_core import redis_keys

        return (
            self._namespace
            + redis_keys.hash_component(tenant_id)
            + ":"
            + redis_keys.safe_segment(logical_operation_id)
        )

    async def register(
        self, *, tenant_id: str, logical_operation_id: str, binding: str,
        action: Optional[str] = None, resource: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None, principal_id: Optional[str] = None,
    ) -> ProposalRegisterResult:
        if not isinstance(binding, str) or not binding:
            return ProposalRegisterResult(ProposalRegisterStatus.ERROR, "invalid binding: must be a non-empty string")
        candidate = {
            "binding": binding, "created_at": time.time(),
            "action": action, "resource": resource, "payload": payload,
            "principal_id": principal_id,
        }
        try:
            candidate_json = json.dumps(candidate, sort_keys=True)
        except (TypeError, ValueError):
            return ProposalRegisterResult(
                ProposalRegisterStatus.ERROR, "proposal content is not JSON-serializable; fail-closed"
            )
        key = self._key(tenant_id, logical_operation_id)
        try:
            res = await asyncio.wait_for(
                self._redis.eval(_REGISTER_LUA, 1, key, candidate_json, binding, principal_id or ""),
                timeout=1.0,
            )
        except Exception:
            return ProposalRegisterResult(ProposalRegisterStatus.ERROR, "proposal registry unavailable; fail-closed")
        try:
            status = ProposalRegisterStatus(res[0])
            observed_binding = res[1]
        except (IndexError, ValueError, KeyError):
            return ProposalRegisterResult(ProposalRegisterStatus.ERROR, "malformed registry response; fail-closed")
        reason = {
            ProposalRegisterStatus.REGISTERED: "registered",
            ProposalRegisterStatus.IDEMPOTENT_DUPLICATE: "identical proposal already registered",
            ProposalRegisterStatus.BINDING_CONFLICT: "logical_operation_id is already bound to a "
                                                      "different action/resource/payload",
            ProposalRegisterStatus.ERROR: "malformed existing registry record; fail-closed",
        }[status]
        return ProposalRegisterResult(status, reason, observed_binding or None)

    async def get(self, *, tenant_id: str, logical_operation_id: str) -> Optional[ProposalRecord]:
        key = self._key(tenant_id, logical_operation_id)
        try:
            current = await asyncio.wait_for(self._redis.get(key), timeout=1.0)
        except Exception as exc:
            raise ProposalBackendUnavailable(f"proposal registry unavailable: {exc!r}") from exc
        if current is None:
            return None

        # Phase 2 JSON format (current write path) first.
        try:
            decoded = json.loads(current)
            binding = decoded["binding"]
            if not isinstance(binding, str) or not binding:
                raise ValueError("binding missing/empty")
            created_at = float(decoded["created_at"])
            action = decoded.get("action")
            resource = decoded.get("resource")
            payload = decoded.get("payload")
            principal_id = decoded.get("principal_id")
            if principal_id is not None and not isinstance(principal_id, str):
                raise ValueError("principal_id must be a string")
            return ProposalRecord(
                tenant_id=tenant_id, logical_operation_id=logical_operation_id,
                binding=binding, created_at=created_at,
                action=action, resource=resource, payload=payload, principal_id=principal_id,
            )
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            pass

        # Phase 1 legacy wire format: "binding|created_at" -- never valid
        # JSON (a JSON document always starts with '{'), so falling through
        # here means an upgraded deployment is reading a record written
        # before this field existed. Explicit, documented upgrade strategy
        # (Phase 2 remediation, "Upgrade issue"; see
        # docs/MCC_UNIVERSAL_PROPOSAL_SERVICE_PHASE2.md Section 12):
        # RECOGNIZED, not treated as corruption -- exposed as a proposal
        # with NO executable content. Status reads keep working (they only
        # ever read ``.binding``); ``ProposalExecutionService`` already
        # fails closed on ``record.action is None`` exactly as it does for
        # any other content-less record (Section 2) -- no separate code
        # path is needed there. Never guessed/widened/silently reinterpreted
        # as an executable Phase-2 proposal.
        try:
            binding, created = current.split("|", 1)
            if not binding:
                raise ValueError("empty binding")
            created_at = float(created)
        except (ValueError, AttributeError) as exc:
            raise ProposalBackendUnavailable(f"malformed proposal record for {key!r}") from exc
        return ProposalRecord(
            tenant_id=tenant_id, logical_operation_id=logical_operation_id,
            binding=binding, created_at=created_at,
            action=None, resource=None, payload=None,
        )


def proposal_registry_from_env(env: Optional[Mapping[str, str]] = None):
    """``MCC_PROPOSAL_BACKEND=memory`` (default) or ``redis`` (requires
    ``MCC_REDIS_URL``). Mirrors ``idempotency_registry_from_env``: refuses to
    silently fall back to in-memory when redis is requested but
    unconfigured, and refuses ``memory`` outright under
    ``MCC_DEPLOYMENT_MODE=enforcement``."""
    env = os.environ if env is None else env
    backend = env.get("MCC_PROPOSAL_BACKEND", "memory").strip().lower()
    if backend in ("memory", "inmemory", "in-memory"):
        from mcc_core.deployment_mode import is_enforcement_mode

        if is_enforcement_mode(env):
            raise ProposalConfigError(
                "MCC_DEPLOYMENT_MODE=enforcement refuses MCC_PROPOSAL_BACKEND=memory "
                "(explicit or default); enforcement deployments require "
                "MCC_PROPOSAL_BACKEND=redis with a usable MCC_REDIS_URL"
            )
        return InMemoryProposalRegistry()
    if backend == "redis":
        from mcc_core import redis_keys
        from mcc_core.redis_client import RedisConfigError, redis_client_from_env

        try:
            client = redis_client_from_env(env)
        except RedisConfigError as exc:
            raise ProposalConfigError(
                f"MCC_PROPOSAL_BACKEND=redis requires MCC_REDIS_URL; refusing to fall "
                f"back to in-memory proposal storage ({exc})"
            )
        return RedisProposalRegistry(client, namespace=redis_keys.prefix("proposal", env))
    raise ProposalConfigError(f"unknown MCC_PROPOSAL_BACKEND={backend!r}; expected 'memory' or 'redis'")


__all__ = [
    "ProposalRegisterStatus", "ProposalRegisterResult", "ProposalRecord",
    "ProposalBackendUnavailable", "ProposalConfigError",
    "InMemoryProposalRegistry", "RedisProposalRegistry", "proposal_registry_from_env",
]
