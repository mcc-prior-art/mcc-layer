"""ESCALATE — human-in-the-loop approval loop.

Turns the ESCALATE verdict from a dead end into a complete flow:

    proposal -> MCC evaluation -> ESCALATE
             -> human approval / denial
             -> a scoped, signed, single-use approval mandate
             -> re-evaluation -> gate -> audit-before-actuation -> execute / block

Key invariants:

* Approval never executes the action. It only mints a *bounded authority*.
* The approval mandate is signed (Ed25519), time-limited, bound to the exact
  actor, action hash, resource, transaction, policy version, and constraints,
  and is single-use (consumed atomically at actuation).
* Denial is terminal for that request.
* Expired, reused, altered, or mismatched approvals fail closed.

State machine:

    PENDING ──approve──► APPROVED ──consume──► CONSUMED   (single-use, terminal)
        │                    │
        ├──deny──► DENIED    └──(ttl)──► EXPIRED
        ├──(ttl)──► EXPIRED
        └──invalidate──► INVALIDATED
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping, Optional

from .mandate import issue_mandate
from .signing import SigningKey, hash_action

DEFAULT_TTL_SECONDS = 300
DEFAULT_OP_TIMEOUT_SECONDS = 0.5


class ApprovalState(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"
    INVALIDATED = "INVALIDATED"


@dataclass
class ApprovalRecord:
    request_id: str
    actor: str
    action: str
    action_hash: str
    resource: Optional[str]
    transaction_id: Optional[str]
    policy_hash: Optional[str]
    payload_hash: Optional[str]
    constraints: Dict[str, Any]
    state: str
    created_at: int
    expires_at: int

    def is_expired(self, now: int) -> bool:
        return now >= self.expires_at


@dataclass(frozen=True)
class ConsumeResult:
    ok: bool
    reason: str
    state: Optional[str] = None


# --------------------------------------------------------------------------
# Registries
# --------------------------------------------------------------------------

class InMemoryApprovalRegistry:
    """Single-process approval store (dev / tests). Atomic by running each
    critical section without awaiting."""

    def __init__(self) -> None:
        self._records: Dict[str, ApprovalRecord] = {}
        self._consumed: set = set()

    async def create(self, record: ApprovalRecord) -> bool:
        if record.request_id in self._records:
            return False
        self._records[record.request_id] = record
        return True

    async def get(self, request_id: str, *, now: int) -> Optional[ApprovalRecord]:
        rec = self._records.get(request_id)
        if rec is None:
            return None
        if rec.state == ApprovalState.PENDING.value and rec.is_expired(now):
            rec.state = ApprovalState.EXPIRED.value
        return rec

    async def set_state(self, request_id: str, *, expect, to: ApprovalState) -> bool:
        rec = self._records.get(request_id)
        if rec is None or rec.state not in {s.value for s in expect}:
            return False
        rec.state = to.value
        return True

    async def consume(self, request_id: str, *, now: int) -> ConsumeResult:
        rec = self._records.get(request_id)
        if rec is None:
            return ConsumeResult(False, "approval not found")
        if rec.state == ApprovalState.PENDING.value and rec.is_expired(now):
            rec.state = ApprovalState.EXPIRED.value
        if rec.state != ApprovalState.APPROVED.value:
            return ConsumeResult(False, f"approval not consumable in state {rec.state}", rec.state)
        if request_id in self._consumed:
            return ConsumeResult(False, "approval already consumed (replay)", ApprovalState.CONSUMED.value)
        self._consumed.add(request_id)
        rec.state = ApprovalState.CONSUMED.value
        return ConsumeResult(True, "consumed", rec.state)


class RedisApprovalRegistry:
    """Durable, multi-instance approval store. The record is a JSON value with a
    TTL; the single-use consume is an atomic ``SET NX`` on a separate consume
    key so exactly one caller can consume an approved request. Fail-closed on
    any Redis error/timeout."""

    def __init__(self, redis_client: Any, *, namespace: str = "mcc:appr:",
                 op_timeout_seconds: float = DEFAULT_OP_TIMEOUT_SECONDS) -> None:
        self._redis = redis_client
        self._ns = namespace
        self._op_timeout = op_timeout_seconds

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> "RedisApprovalRegistry":
        import redis.asyncio as redis
        op_timeout = kwargs.get("op_timeout_seconds", DEFAULT_OP_TIMEOUT_SECONDS)
        client = redis.from_url(
            url, socket_timeout=op_timeout,
            socket_connect_timeout=kwargs.pop("connect_timeout_seconds", 1.0),
            decode_responses=True,
        )
        return cls(client, **kwargs)

    def _k(self, request_id: str) -> str:
        return f"{self._ns}{request_id}"

    async def _c(self, coro):
        return await asyncio.wait_for(coro, timeout=self._op_timeout)

    async def create(self, record: ApprovalRecord) -> bool:
        ttl = max(1, record.expires_at - record.created_at)
        try:
            created = await self._c(self._redis.set(self._k(record.request_id),
                                                    json.dumps(asdict(record)), nx=True, ex=ttl))
            return created is True
        except Exception:
            return False

    async def _load(self, request_id: str) -> Optional[ApprovalRecord]:
        """Raw stored record, no logical expiry. State transitions read this;
        real expiry is enforced by the Redis key TTL (an expired key is gone)."""
        try:
            raw = await self._c(self._redis.get(self._k(request_id)))
        except Exception:
            return None
        return None if raw is None else ApprovalRecord(**json.loads(raw))

    async def get(self, request_id: str, *, now: int) -> Optional[ApprovalRecord]:
        rec = await self._load(request_id)
        if rec is None:
            return None
        if rec.state == ApprovalState.PENDING.value and rec.is_expired(now):
            rec.state = ApprovalState.EXPIRED.value
        return rec

    async def _save(self, rec: ApprovalRecord) -> bool:
        # Re-set with a relative TTL equal to the request's window (avoids
        # depending on Redis KEEPTTL); the window is bounded and idempotent.
        ttl = max(1, rec.expires_at - rec.created_at)
        try:
            await self._c(self._redis.set(self._k(rec.request_id), json.dumps(asdict(rec)), ex=ttl))
            return True
        except Exception:
            return False

    async def set_state(self, request_id: str, *, expect, to: ApprovalState) -> bool:
        rec = await self._load(request_id)
        if rec is None or rec.state not in {s.value for s in expect}:
            return False
        rec.state = to.value
        return await self._save(rec)

    async def consume(self, request_id: str, *, now: int) -> ConsumeResult:
        rec = await self._load(request_id)
        if rec is None:
            return ConsumeResult(False, "approval not found")
        if rec.state != ApprovalState.APPROVED.value:
            return ConsumeResult(False, f"approval not consumable in state {rec.state}", rec.state)
        try:
            won = await self._c(self._redis.set(self._k(request_id) + ":consumed", "1", nx=True))
        except Exception:
            return ConsumeResult(False, "approval registry unavailable; fail-closed")
        if won is not True:
            return ConsumeResult(False, "approval already consumed (replay)", ApprovalState.CONSUMED.value)
        rec.state = ApprovalState.CONSUMED.value
        await self._save(rec)
        return ConsumeResult(True, "consumed", rec.state)


class ApprovalConfigError(Exception):
    """Raised when the approval backend is misconfigured (fail-closed start)."""


def approval_registry_from_env(env: Optional[Mapping[str, str]] = None):
    env = os.environ if env is None else env
    backend = env.get("MCC_APPROVAL_BACKEND", "memory").strip().lower()
    if backend in ("memory", "inmemory", "in-memory"):
        return InMemoryApprovalRegistry()
    if backend == "redis":
        url = env.get("MCC_REDIS_URL", "").strip()
        if not url:
            raise ApprovalConfigError(
                "MCC_APPROVAL_BACKEND=redis requires MCC_REDIS_URL; refusing to "
                "fall back to in-memory approvals in an enforcement deployment"
            )
        return RedisApprovalRegistry.from_url(url)
    raise ApprovalConfigError(
        f"unknown MCC_APPROVAL_BACKEND={backend!r}; expected 'memory' or 'redis'"
    )


# --------------------------------------------------------------------------
# Service
# --------------------------------------------------------------------------

class ApprovalService:
    """The approval API/service boundary: request, approve, deny, consume.

    ``approver_key`` is the Ed25519 key the human-approval authority signs with;
    its public key must be in the verifier trust set used at re-evaluation.
    """

    def __init__(self, registry, approver_key: SigningKey, *,
                 issuer: str = "mcc/approvals", default_ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self.registry = registry
        self.approver_key = approver_key
        self.issuer = issuer
        self.default_ttl = default_ttl_seconds

    async def request(
        self, *, actor: str, action: str, resource: Optional[str] = None,
        transaction_id: Optional[str] = None, policy_hash: Optional[str] = None,
        payload_hash: Optional[str] = None, constraints: Optional[Dict[str, Any]] = None,
        ttl_seconds: Optional[int] = None, now: Optional[int] = None,
    ) -> str:
        now = int(now if now is not None else time.time())
        ttl = ttl_seconds or self.default_ttl
        request_id = f"req-{uuid.uuid4().hex}"
        rec = ApprovalRecord(
            request_id=request_id, actor=actor, action=action,
            action_hash=hash_action(action), resource=resource,
            transaction_id=transaction_id, policy_hash=policy_hash,
            payload_hash=payload_hash, constraints=dict(constraints or {}),
            state=ApprovalState.PENDING.value, created_at=now, expires_at=now + ttl,
        )
        if not await self.registry.create(rec):
            raise RuntimeError("could not create approval request")
        return request_id

    async def get(self, request_id: str, *, now: Optional[int] = None) -> Optional[ApprovalRecord]:
        return await self.registry.get(request_id, now=int(now if now is not None else time.time()))

    async def deny(self, request_id: str) -> bool:
        return await self.registry.set_state(
            request_id, expect=[ApprovalState.PENDING], to=ApprovalState.DENIED
        )

    async def invalidate(self, request_id: str) -> bool:
        return await self.registry.set_state(
            request_id,
            expect=[ApprovalState.PENDING, ApprovalState.APPROVED],
            to=ApprovalState.INVALIDATED,
        )

    async def approve(self, request_id: str, *, now: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Approve a PENDING request and mint a scoped, single-use, signed
        approval mandate bound to the exact operation. Returns the mandate, or
        None if the request is not approvable (expired / already decided)."""
        now = int(now if now is not None else time.time())
        rec = await self.registry.get(request_id, now=now)
        if rec is None or rec.state != ApprovalState.PENDING.value or rec.is_expired(now):
            return None
        if not await self.registry.set_state(
            request_id, expect=[ApprovalState.PENDING], to=ApprovalState.APPROVED
        ):
            return None
        return issue_mandate(
            self.approver_key, issuer=self.issuer, subject=rec.actor,
            action_scope=[rec.action], resource_scope=[rec.resource] if rec.resource else [],
            constraints=rec.constraints, not_before=now, not_after=rec.expires_at,
            issued_at=now, revocation_required=False, policy_hash=rec.policy_hash,
            mandate_id=f"apr-{request_id}",
            extra={
                "approval_id": request_id,
                "action_hash": rec.action_hash,
                "transaction_id": rec.transaction_id,
                "payload_hash": rec.payload_hash,
                "single_use": True,
            },
        )

    async def consume(
        self, request_id: str, *, action_hash: str, transaction_id: Optional[str],
        payload_hash: Optional[str], now: Optional[int] = None,
    ) -> ConsumeResult:
        """Atomically consume an APPROVED request, binding to the exact
        operation. Mismatched action/transaction/payload, replay, or a non-
        APPROVED state all fail closed."""
        now = int(now if now is not None else time.time())
        rec = await self.registry.get(request_id, now=now)
        if rec is None:
            return ConsumeResult(False, "approval not found")
        # Bind to the exact operation before consuming (approval substitution).
        if rec.action_hash != action_hash:
            return ConsumeResult(False, "ACTION_HASH_MISMATCH: approval not for this action")
        if rec.transaction_id != transaction_id:
            return ConsumeResult(False, "TRANSACTION_MISMATCH: approval not for this transaction")
        if rec.payload_hash is not None and rec.payload_hash != payload_hash:
            return ConsumeResult(False, "PAYLOAD_MISMATCH: approval not for this payload")
        return await self.registry.consume(request_id, now=now)
