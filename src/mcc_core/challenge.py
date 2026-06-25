"""Consensus challenge — the gateway issues the one-time nonce, not the client.

Multi-Context Consensus binds evaluator votes (and the decision token) to a
one-time ``nonce``. If the *client* picks that nonce, the client controls the
anti-replay material. A **consensus challenge** moves that authority to the
gateway: the gateway mints a cryptographically strong, single-use nonce inside
a signed-by-construction challenge bound to the exact operation, persists it
atomically with a TTL, and consumes it exactly once before actuation.

    client → POST /consensus/challenge {action, actor, resource, payload}
           → gateway issues {challenge_id, nonce, action, actor, resource,
                             payload_hash, policy_hash, issued_at, expires_at}
           → evaluators sign votes bound to *that* nonce
           → POST /consensus/execute {challenge_id, votes}
           → gateway re-binds, verifies N-of-M, CONSUMES the challenge once,
             issues the token (carrying the nonce), runs the coordinator path

Key invariants (all fail closed):

* The nonce is generated with ``secrets`` — the client never supplies it.
* A challenge is bound to action / actor / resource / payload_hash / policy_hash
  at issuance; execution must match all of them and the nonce.
* A challenge is single-use: consumed atomically exactly once. Unknown, expired,
  reused, or mismatched challenges are rejected.
* The store enforces the TTL (Redis key expiry; in-memory logical expiry).

State machine::

    ISSUED ──consume──► CONSUMED        (single-use, terminal)
       └────(ttl)─────► EXPIRED
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
import uuid
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional

from .approvals import ConsumeResult
from .signing import hash_action

DEFAULT_TTL_SECONDS = 120
DEFAULT_OP_TIMEOUT_SECONDS = 0.5
# 256 bits of entropy, URL-safe. The client never sees a way to influence this.
NONCE_BYTES = 32


class ChallengeState(str, Enum):
    ISSUED = "ISSUED"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"


@dataclass
class ChallengeRecord:
    challenge_id: str
    nonce: str
    action: str
    action_hash: str
    actor: str
    resource: Optional[str]
    payload_hash: str
    policy_hash: Optional[str]
    state: str
    issued_at: int
    expires_at: int

    def is_expired(self, now: int) -> bool:
        return now >= self.expires_at

    def public_view(self) -> Dict[str, Any]:
        """The challenge as returned to the client. Includes the nonce (the
        client needs it to gather votes) but is otherwise the binding the
        gateway will enforce. No key material."""
        return {
            "challenge_id": self.challenge_id,
            "nonce": self.nonce,
            "action": self.action,
            "actor": self.actor,
            "resource": self.resource,
            "payload_hash": self.payload_hash,
            "policy_hash": self.policy_hash,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


# --------------------------------------------------------------------------
# Registries
# --------------------------------------------------------------------------

class InMemoryChallengeRegistry:
    """Single-process challenge store (dev / tests). Atomic by running each
    critical section without awaiting."""

    def __init__(self) -> None:
        self._records: Dict[str, ChallengeRecord] = {}
        self._consumed: set = set()

    async def create(self, record: ChallengeRecord) -> bool:
        if record.challenge_id in self._records:
            return False
        self._records[record.challenge_id] = record
        return True

    async def get(self, challenge_id: str, *, now: int) -> Optional[ChallengeRecord]:
        rec = self._records.get(challenge_id)
        if rec is None:
            return None
        if rec.state == ChallengeState.ISSUED.value and rec.is_expired(now):
            rec.state = ChallengeState.EXPIRED.value
        return rec

    async def consume(self, challenge_id: str, *, now: int) -> ConsumeResult:
        rec = self._records.get(challenge_id)
        if rec is None:
            return ConsumeResult(False, "challenge not found")
        if rec.state == ChallengeState.ISSUED.value and rec.is_expired(now):
            rec.state = ChallengeState.EXPIRED.value
        if rec.state != ChallengeState.ISSUED.value:
            return ConsumeResult(False, f"challenge not consumable in state {rec.state}", rec.state)
        if challenge_id in self._consumed:
            return ConsumeResult(False, "challenge already consumed (replay)",
                                 ChallengeState.CONSUMED.value)
        self._consumed.add(challenge_id)
        rec.state = ChallengeState.CONSUMED.value
        return ConsumeResult(True, "consumed", rec.state)


class RedisChallengeRegistry:
    """Durable, multi-instance challenge store. The record is a JSON value with
    a TTL; single-use consume is an atomic ``SET NX`` on a separate consume key
    so exactly one caller across all instances can consume a challenge.
    Fail-closed on any Redis error/timeout."""

    def __init__(self, redis_client: Any, *, namespace: str = "mcc:chal:",
                 op_timeout_seconds: float = DEFAULT_OP_TIMEOUT_SECONDS) -> None:
        self._redis = redis_client
        self._ns = namespace
        self._op_timeout = op_timeout_seconds

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> "RedisChallengeRegistry":
        import redis.asyncio as redis
        op_timeout = kwargs.get("op_timeout_seconds", DEFAULT_OP_TIMEOUT_SECONDS)
        client = redis.from_url(
            url, socket_timeout=op_timeout,
            socket_connect_timeout=kwargs.pop("connect_timeout_seconds", 1.0),
            decode_responses=True,
        )
        return cls(client, **kwargs)

    def _k(self, challenge_id: str) -> str:
        return f"{self._ns}{challenge_id}"

    async def _c(self, coro):
        return await asyncio.wait_for(coro, timeout=self._op_timeout)

    async def create(self, record: ChallengeRecord) -> bool:
        ttl = max(1, record.expires_at - record.issued_at)
        try:
            created = await self._c(self._redis.set(
                self._k(record.challenge_id), json.dumps(asdict(record)), nx=True, ex=ttl))
            return created is True
        except Exception:
            return False

    async def _load(self, challenge_id: str) -> Optional[ChallengeRecord]:
        """Raw stored record. Logical expiry is read from the record; real
        expiry is the Redis key TTL (an expired key is simply gone)."""
        try:
            raw = await self._c(self._redis.get(self._k(challenge_id)))
        except Exception:
            return None
        return None if raw is None else ChallengeRecord(**json.loads(raw))

    async def get(self, challenge_id: str, *, now: int) -> Optional[ChallengeRecord]:
        rec = await self._load(challenge_id)
        if rec is None:
            return None
        if rec.state == ChallengeState.ISSUED.value and rec.is_expired(now):
            rec.state = ChallengeState.EXPIRED.value
        return rec

    async def _save(self, rec: ChallengeRecord) -> bool:
        ttl = max(1, rec.expires_at - rec.issued_at)
        try:
            await self._c(self._redis.set(self._k(rec.challenge_id), json.dumps(asdict(rec)), ex=ttl))
            return True
        except Exception:
            return False

    async def consume(self, challenge_id: str, *, now: int) -> ConsumeResult:
        rec = await self._load(challenge_id)
        if rec is None:
            return ConsumeResult(False, "challenge not found")
        if rec.state == ChallengeState.ISSUED.value and rec.is_expired(now):
            return ConsumeResult(False, "challenge not consumable in state EXPIRED",
                                 ChallengeState.EXPIRED.value)
        if rec.state != ChallengeState.ISSUED.value:
            return ConsumeResult(False, f"challenge not consumable in state {rec.state}", rec.state)
        try:
            won = await self._c(self._redis.set(self._k(challenge_id) + ":consumed", "1", nx=True))
        except Exception:
            return ConsumeResult(False, "challenge registry unavailable; fail-closed")
        if won is not True:
            return ConsumeResult(False, "challenge already consumed (replay)",
                                 ChallengeState.CONSUMED.value)
        rec.state = ChallengeState.CONSUMED.value
        await self._save(rec)
        return ConsumeResult(True, "consumed", rec.state)


class ChallengeConfigError(Exception):
    """Raised when the challenge backend is misconfigured (fail-closed start)."""


def challenge_registry_from_env(env: Optional[Mapping[str, str]] = None):
    env = os.environ if env is None else env
    backend = env.get("MCC_CHALLENGE_BACKEND", "memory").strip().lower()
    if backend in ("memory", "inmemory", "in-memory"):
        return InMemoryChallengeRegistry()
    if backend == "redis":
        from . import redis_keys
        from .redis_client import RedisConfigError, redis_client_from_env

        try:
            client = redis_client_from_env(env)
        except RedisConfigError as exc:
            raise ChallengeConfigError(
                "MCC_CHALLENGE_BACKEND=redis requires MCC_REDIS_URL; refusing to "
                f"fall back to in-memory challenges ({exc})"
            )
        return RedisChallengeRegistry(client, namespace=redis_keys.prefix("chal", env))
    raise ChallengeConfigError(
        f"unknown MCC_CHALLENGE_BACKEND={backend!r}; expected 'memory' or 'redis'"
    )


# --------------------------------------------------------------------------
# Service
# --------------------------------------------------------------------------

class ChallengeService:
    """Issues and consumes consensus challenges. The gateway owns the nonce."""

    def __init__(self, registry, *, issuer: str = "mcc/consensus",
                 default_ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self.registry = registry
        self.issuer = issuer
        self.default_ttl = default_ttl_seconds

    async def issue(
        self, *, action: str, actor: str, resource: Optional[str], payload_hash: str,
        policy_hash: Optional[str] = None, ttl_seconds: Optional[int] = None,
        now: Optional[int] = None,
    ) -> ChallengeRecord:
        now = int(now if now is not None else time.time())
        ttl = ttl_seconds or self.default_ttl
        rec = ChallengeRecord(
            challenge_id=f"chal-{uuid.uuid4().hex}",
            nonce=secrets.token_urlsafe(NONCE_BYTES),
            action=action, action_hash=hash_action(action), actor=actor, resource=resource,
            payload_hash=payload_hash, policy_hash=policy_hash,
            state=ChallengeState.ISSUED.value, issued_at=now, expires_at=now + ttl,
        )
        if not await self.registry.create(rec):
            raise RuntimeError("could not create consensus challenge")
        return rec

    async def get(self, challenge_id: str, *, now: Optional[int] = None) -> Optional[ChallengeRecord]:
        return await self.registry.get(challenge_id, now=int(now if now is not None else time.time()))

    async def consume(
        self, challenge_id: str, *, action: str, actor: str, resource: Optional[str],
        payload_hash: str, policy_hash: Optional[str], nonce: str, now: Optional[int] = None,
    ) -> ConsumeResult:
        """Atomically consume the challenge, binding to the exact operation.
        Unknown, expired, reused, or any mismatched dimension fails closed
        *before* the single-use consume is attempted."""
        now = int(now if now is not None else time.time())
        rec = await self.registry.get(challenge_id, now=now)
        if rec is None:
            return ConsumeResult(False, "UNKNOWN_CHALLENGE: not found")
        # Bind to the exact issued challenge before consuming.
        if rec.action_hash != hash_action(action):
            return ConsumeResult(False, "ACTION_MISMATCH: challenge not for this action")
        if rec.actor != actor:
            return ConsumeResult(False, "ACTOR_MISMATCH: challenge not for this actor")
        if rec.resource != resource:
            return ConsumeResult(False, "RESOURCE_MISMATCH: challenge not for this resource")
        if rec.payload_hash != payload_hash:
            return ConsumeResult(False, "PAYLOAD_MISMATCH: challenge not for this payload")
        if rec.policy_hash != policy_hash:
            return ConsumeResult(False, "POLICY_MISMATCH: challenge not for this policy")
        if rec.nonce != nonce:
            return ConsumeResult(False, "NONCE_MISMATCH: challenge nonce does not match")
        return await self.registry.consume(challenge_id, now=now)
