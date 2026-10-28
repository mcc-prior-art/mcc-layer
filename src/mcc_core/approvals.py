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

from .authority_policy import AuthorityPolicy
from .mandate import issue_mandate
from .signing import SigningKey, hash_action, hash_payload

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
    # Independent-authority-policy binding data (PROPOSAL != PERMISSION): the
    # trusted tenant identity and the ACTUAL requested payload, stored
    # verbatim so ``ApprovalService.approve()`` can evaluate an independently
    # configured ``AuthorityPolicy`` against the exact operation rather than
    # trusting any caller-supplied field at approval time. Both default to
    # the pre-existing shape (``None`` / ``{}``) so old callers/records are
    # unaffected when no authority_policy is configured.
    tenant_id: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self, now: int) -> bool:
        return now >= self.expires_at


@dataclass(frozen=True)
class ConsumeResult:
    ok: bool
    reason: str
    state: Optional[str] = None


_EXPIRABLE_STATES = {ApprovalState.PENDING.value, ApprovalState.APPROVED.value}


def _logically_expired(state: str, expires_at: int, now: int) -> bool:
    """Shared effective-state rule for BOTH registries and both Lua scripts
    (see ``_SET_STATE_LUA``/``_CONSUME_LUA``): PENDING and APPROVED are the
    only two non-terminal states, so they are the only ones whose eligibility
    for a transition must be re-checked against the ORIGINAL, immutable
    ``expires_at`` deadline, independently of whatever the physical Redis key
    TTL happens to be at the time of the check. Terminal states (DENIED /
    INVALIDATED / CONSUMED) are never affected by expiry -- a terminal
    outcome does not un-happen because time passed."""
    return state in _EXPIRABLE_STATES and now >= expires_at


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
        if _logically_expired(rec.state, rec.expires_at, now):
            rec.state = ApprovalState.EXPIRED.value
        return rec

    async def set_state(self, request_id: str, *, expect, to: ApprovalState, now: int) -> bool:
        rec = self._records.get(request_id)
        if rec is None:
            return False
        state = rec.state
        if _logically_expired(state, rec.expires_at, now):
            state = ApprovalState.EXPIRED.value
        if state not in {s.value for s in expect}:
            return False
        rec.state = to.value
        return True

    async def consume(self, request_id: str, *, now: int) -> ConsumeResult:
        rec = self._records.get(request_id)
        if rec is None:
            return ConsumeResult(False, "approval not found")
        # Replay is checked before expiry: a previously-consumed record
        # reports "replay", never "expired", regardless of how much real
        # time has since elapsed (matches the Redis path's priority).
        if rec.state != ApprovalState.CONSUMED.value and _logically_expired(rec.state, rec.expires_at, now):
            rec.state = ApprovalState.EXPIRED.value
        if rec.state != ApprovalState.APPROVED.value:
            return ConsumeResult(False, f"approval not consumable in state {rec.state}", rec.state)
        if request_id in self._consumed:
            return ConsumeResult(False, "approval already consumed (replay)", ApprovalState.CONSUMED.value)
        self._consumed.add(request_id)
        rec.state = ApprovalState.CONSUMED.value
        return ConsumeResult(True, "consumed", rec.state)


_SET_STATE_LUA = """
-- Security fix (red-team finding, 2026-10-24): set_state() used to be a
-- plain Lua-free GET -> (check in Python) -> SET, which is a classic
-- non-atomic read-modify-write: two concurrent transitions on the SAME
-- request_id (e.g. approve() racing deny()/invalidate()) could both
-- observe the pre-transition state before either write landed, and
-- whichever write happened to land LAST would silently clobber the
-- other's -- including a legitimate deny() being overwritten back to
-- APPROVED by a concurrently-racing approve() that read stale state.
-- This script performs the read, membership check, and write as ONE
-- atomic Redis operation (Redis executes Lua scripts without
-- interleaving other commands), closing that race deterministically.
--
-- Security fix (red-team finding, 2026-10-28, TTL-extension defect): this
-- script used to (a) never re-check ``expires_at`` at all -- a logically
-- expired PENDING/APPROVED record could still be transitioned (e.g.
-- approve()'d) purely because its physical Redis key had not yet been
-- deleted -- and (b) on every transition, reset the key's PHYSICAL TTL to
-- ``expires_at - created_at`` (the FULL original duration) applied from
-- "now", which extends the key's real-world lifetime by however much time
-- had already elapsed since creation, instead of preserving the original
-- absolute deadline. Both are fixed here: ``now`` (ARGV[3], the SAME clock
-- basis the Python caller uses -- real time in production, an injected
-- fake epoch in tests) is used to (a) promote the effective state to
-- EXPIRED for matching purposes when PENDING/APPROVED has passed its
-- ``expires_at`` (mirrors ``_logically_expired`` in approvals.py), which
-- makes an expired record simply fail to match any ``expect`` set given to
-- this script (no caller ever expects EXPIRED), and (b) compute the
-- REMAINING duration (``expires_at - now``), never the full original one,
-- when re-applying the key's TTL on a successful transition -- the
-- physical key can now never outlive its original absolute deadline by
-- more than clock-rounding. Deliberately NOT switched to Redis absolute-
-- time expiry (PXAT/EXAT): callers (including this repo's own test suite)
-- may pass a synthetic, non-wall-clock ``now``, and PXAT would take that
-- literally as a real Unix timestamp.
local cur = redis.call('GET', KEYS[1])
if not cur then return 0 end
local rec = cjson.decode(cur)
local expect = cjson.decode(ARGV[1])
local now = tonumber(ARGV[3])
local state = rec['state']
if (state == 'PENDING' or state == 'APPROVED') and now >= tonumber(rec['expires_at']) then
    state = 'EXPIRED'
end
local matched = false
for _, v in ipairs(expect) do
    if state == v then matched = true end
end
if not matched then return 0 end
rec['state'] = ARGV[2]
local remaining = tonumber(rec['expires_at']) - now
if remaining < 1 then remaining = 1 end
redis.call('SET', KEYS[1], cjson.encode(rec), 'EX', remaining)
return 1
"""


_CONSUME_LUA = """
-- Security fix (red-team finding, 2026-10-27): consume() used to be
-- GET -> (check APPROVED in Python) -> SET <id>:consumed NX -> SET <id>
-- (blind overwrite). The APPROVED check and the state-check-then-NX-claim
-- were two SEPARATE round trips: a concurrently-racing invalidate()/deny()
-- (itself an atomic set_state() CAS) could complete in the window between
-- consume()'s own stale read and its NX claim. consume() would then still
-- win the (now-uncontested) :consumed key, and its blind final SET would
-- overwrite the just-invalidated record back to CONSUMED -- destroying the
-- invalidation and letting the coordinator proceed to actuate an operation
-- that had just been revoked. This script performs the read, the
-- single-use/state check, and the write as ONE atomic Redis operation,
-- closing that window deterministically and eliminating the separate
-- ":consumed" key (the record's own ``state`` field is now the single
-- source of truth for single-use consumption, exactly like every other
-- transition in this file).
--
-- Security fix (red-team finding, 2026-10-28, TTL-extension defect): this
-- script used to never re-check ``expires_at`` at all, and reset the key's
-- PHYSICAL TTL to the FULL original duration (``expires_at - created_at``)
-- on every successful consume, extending the key's real-world lifetime by
-- however much time had already elapsed since creation. A record that was
-- APPROVED and then left untouched past its logical ``expires_at`` could
-- therefore still be consumed, relying entirely on the physical key's
-- (bugged, extended) TTL rather than any explicit expiry check -- see
-- ``ttl_bug_consume_after_logical_expiry.py`` for the empirical
-- reproduction. Fixed by: (a) checking ``now`` (ARGV[1], same clock basis
-- as the Python caller) against ``expires_at`` for an APPROVED record
-- BEFORE allowing the CONSUMED transition -- checked AFTER the existing
-- replay check (a previously-CONSUMED record always reports "replay", even
-- if also long past its deadline -- the more specific, already-decided
-- outcome), and (b) computing the REMAINING duration (``expires_at -
-- now``), never the full original one, when re-applying the TTL. As with
-- ``_SET_STATE_LUA``, deliberately NOT switched to Redis absolute-time
-- expiry (PXAT/EXAT) -- stays relative-``EX``, computed from the caller's
-- own (possibly synthetic, test-injected) ``now``.
--
-- Returns one of:
--   {0}        not found (never existed, or its Redis TTL already expired)
--   {1}        consumed successfully (was APPROVED; now CONSUMED)
--   {2}        already consumed (replay) -- was already CONSUMED
--   {3, state} wrong state (DENIED / INVALIDATED) -- never consumable from
--              here regardless of race outcome
--   {4, state} logically expired -- was APPROVED but ``now >= expires_at``;
--              distinguished from a generic {3} so callers can report a
--              precise reason instead of a misleading wrong-state message
local cur = redis.call('GET', KEYS[1])
if not cur then return {0} end
local rec = cjson.decode(cur)
local now = tonumber(ARGV[1])
if rec['state'] == 'CONSUMED' then return {2} end
if rec['state'] == 'APPROVED' and now >= tonumber(rec['expires_at']) then
    return {4, 'EXPIRED'}
end
if rec['state'] ~= 'APPROVED' then return {3, rec['state']} end
rec['state'] = 'CONSUMED'
local remaining = tonumber(rec['expires_at']) - now
if remaining < 1 then remaining = 1 end
redis.call('SET', KEYS[1], cjson.encode(rec), 'EX', remaining)
return {1}
"""


class RedisApprovalRegistry:
    """Durable, multi-instance approval store. The record is a JSON value with
    a TTL. EVERY state transition -- ``deny``/``invalidate``/the approve
    half-step (``_SET_STATE_LUA``) and the single-use ``consume`` (
    ``_CONSUME_LUA``) -- is an atomic Lua compare-and-swap: one Redis
    round trip that reads the current state, checks it, and writes the new
    state, with no other command able to interleave. There is no separate
    read-then-blind-write anywhere in this class, and no separate
    ``:consumed`` side key -- the record's own ``state`` field is the single
    source of truth for single-use consumption. Fail-closed on any Redis
    error/timeout."""

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
        if _logically_expired(rec.state, rec.expires_at, now):
            rec.state = ApprovalState.EXPIRED.value
        return rec

    async def set_state(self, request_id: str, *, expect, to: ApprovalState, now: int) -> bool:
        expect_json = json.dumps([s.value for s in expect])
        try:
            res = await self._c(self._redis.eval(
                _SET_STATE_LUA, 1, self._k(request_id), expect_json, to.value, str(int(now)),
            ))
            return int(res) == 1
        except Exception:
            return False

    async def consume(self, request_id: str, *, now: int) -> ConsumeResult:
        """Atomically transition APPROVED -> CONSUMED, single-use, in ONE
        Redis round trip (see ``_CONSUME_LUA``). Never reads the state in one
        step and writes it in another: a concurrently-racing ``invalidate()``
        (or ``deny()``) either fully precedes or fully follows this call --
        there is no window in which this method's own write can observe a
        state older than the current one and clobber it. Fail-closed (never
        a silent success) on any Redis error/timeout or unexpected reply."""
        try:
            res = await self._c(self._redis.eval(_CONSUME_LUA, 1, self._k(request_id), str(int(now))))
        except Exception:
            return ConsumeResult(False, "approval registry unavailable; fail-closed")
        if not isinstance(res, (list, tuple)) or not res:
            return ConsumeResult(False, "approval registry unavailable; fail-closed")
        code = res[0]
        if code == 1:
            return ConsumeResult(True, "consumed", ApprovalState.CONSUMED.value)
        if code == 2:
            return ConsumeResult(False, "approval already consumed (replay)", ApprovalState.CONSUMED.value)
        if code == 4:
            state = res[1] if len(res) > 1 else ApprovalState.EXPIRED.value
            return ConsumeResult(False, "approval expired", state)
        if code == 3:
            state = res[1] if len(res) > 1 else None
            return ConsumeResult(False, f"approval not consumable in state {state}", state)
        return ConsumeResult(False, "approval not found")


class ApprovalConfigError(Exception):
    """Raised when the approval backend is misconfigured (fail-closed start)."""


def approval_registry_from_env(env: Optional[Mapping[str, str]] = None):
    env = os.environ if env is None else env
    backend = env.get("MCC_APPROVAL_BACKEND", "memory").strip().lower()
    if backend in ("memory", "inmemory", "in-memory"):
        return InMemoryApprovalRegistry()
    if backend == "redis":
        from . import redis_keys
        from .redis_client import RedisConfigError, redis_client_from_env

        try:
            client = redis_client_from_env(env)
        except RedisConfigError as exc:
            raise ApprovalConfigError(
                "MCC_APPROVAL_BACKEND=redis requires MCC_REDIS_URL; refusing to "
                f"fall back to in-memory approvals ({exc})"
            )
        return RedisApprovalRegistry(client, namespace=redis_keys.prefix("appr", env))
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
                 issuer: str = "mcc/approvals", default_ttl_seconds: int = DEFAULT_TTL_SECONDS,
                 authority_policy: Optional[AuthorityPolicy] = None) -> None:
        self.registry = registry
        self.approver_key = approver_key
        self.issuer = issuer
        self.default_ttl = default_ttl_seconds
        # Independent authority-side policy (PROPOSAL != PERMISSION): when set,
        # ``approve()`` below REQUIRES this policy's own ALLOW before minting a
        # mandate -- the caller of approve() (an operator, attended or not)
        # never supplies the decision, only the request_id pointer. When
        # None, approve() behaves exactly as before this module was extended
        # (the bare "an authenticated human/operator says so" model) -- the
        # right choice for a genuinely attended human-approval deployment.
        self.authority_policy = authority_policy

    async def request(
        self, *, actor: str, action: str, resource: Optional[str] = None,
        transaction_id: Optional[str] = None, policy_hash: Optional[str] = None,
        payload_hash: Optional[str] = None, constraints: Optional[Dict[str, Any]] = None,
        ttl_seconds: Optional[int] = None, now: Optional[int] = None,
        tenant_id: Optional[str] = None, payload: Optional[Dict[str, Any]] = None,
    ) -> str:
        now = int(now if now is not None else time.time())
        ttl = ttl_seconds or self.default_ttl
        request_id = f"req-{uuid.uuid4().hex}"
        canonical_payload = dict(payload or {})
        # Security fix (red-team finding, 2026-10-24): the stored
        # ``payload_hash`` binding MUST be computed here, server-side, from
        # the SAME trusted ``payload`` this record stores -- never trusted
        # verbatim from a caller-supplied value (which may be omitted,
        # forged, or simply unrelated to ``payload``). Before this fix, a
        # caller that omitted ``payload_hash`` (the real, shipped
        # ``mcc_client.MCCClient.request_approval()`` never sends one) left
        # ``consume()``'s payload-binding check unenforceable, and a caller
        # that supplied a MISMATCHED ``payload_hash`` (hashing some other,
        # not-yet-proposed payload) could get an operation approved under
        # one payload while pre-arranging the hash of a different, later-
        # substituted one -- in both cases the independent authority
        # decision over THIS payload became disconnected from what the
        # resulting mandate could actually be used to execute. The
        # ``payload_hash`` parameter is kept for wire/API backward
        # compatibility (so an old caller that still sends it is not
        # rejected) but its value is now always ignored in favor of the
        # recomputed one. See tests/test_independent_authority_decision_adversarial.py
        # Case L (mandatory, non-vacuity) for the adversarial proof.
        payload_hash = hash_payload(canonical_payload)
        rec = ApprovalRecord(
            request_id=request_id, actor=actor, action=action,
            action_hash=hash_action(action), resource=resource,
            transaction_id=transaction_id, policy_hash=policy_hash,
            payload_hash=payload_hash, constraints=dict(constraints or {}),
            state=ApprovalState.PENDING.value, created_at=now, expires_at=now + ttl,
            tenant_id=tenant_id, payload=canonical_payload,
        )
        if not await self.registry.create(rec):
            raise RuntimeError("could not create approval request")
        return request_id

    async def get(self, request_id: str, *, now: Optional[int] = None) -> Optional[ApprovalRecord]:
        return await self.registry.get(request_id, now=int(now if now is not None else time.time()))

    async def deny(self, request_id: str, *, now: Optional[int] = None) -> bool:
        now = int(now if now is not None else time.time())
        return await self.registry.set_state(
            request_id, expect=[ApprovalState.PENDING], to=ApprovalState.DENIED, now=now,
        )

    async def invalidate(self, request_id: str, *, now: Optional[int] = None) -> bool:
        now = int(now if now is not None else time.time())
        return await self.registry.set_state(
            request_id,
            expect=[ApprovalState.PENDING, ApprovalState.APPROVED],
            to=ApprovalState.INVALIDATED,
            now=now,
        )

    async def approve(self, request_id: str, *, now: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Approve a PENDING request and mint a scoped, single-use, signed
        approval mandate bound to the exact operation. Returns the mandate, or
        None if the request is not approvable (expired / already decided), OR
        if an independent authority policy is configured and does not ALLOW
        this exact operation (request remains PENDING -- the caller gets no
        signal distinguishing "denied by policy" from "not yet decided",
        which is intentional: an unattended caller must not be able to probe
        policy internals by state-machine side channel)."""
        now = int(now if now is not None else time.time())
        rec = await self.registry.get(request_id, now=now)
        if rec is None or rec.state != ApprovalState.PENDING.value or rec.is_expired(now):
            return None
        if self.authority_policy is not None:
            # The ONLY fields consulted are the record's own server-stored,
            # authoritative values -- never anything supplied by the caller
            # of approve() at this call site. A compromised proposer that
            # created this record (directly or via forged coordination
            # state) gains nothing beyond what the independently configured
            # policy already permits for this exact tenant/actor/action/
            # resource/payload/logical_operation_id.
            decision = self.authority_policy.decide(
                tenant_id=rec.tenant_id, actor=rec.actor, action=rec.action,
                resource=rec.resource, payload=rec.payload, payload_hash=rec.payload_hash,
                policy_hash=rec.policy_hash,
                # The approval request_id itself: server-generated
                # (uuid4), never agent-chosen, never empty for any record
                # that genuinely exists. ``transaction_id`` is a distinct,
                # often-unset field with its own separate binding meaning at
                # actuation time (see EnforcementCoordinator.consume), so it
                # is deliberately NOT reused here.
                logical_operation_id=request_id, now=now,
            )
            if decision.verdict != "ALLOW":
                return None
        if not await self.registry.set_state(
            request_id, expect=[ApprovalState.PENDING], to=ApprovalState.APPROVED, now=now,
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
        # Security fix (red-team finding, 2026-10-24): fail closed, never
        # skip. ``request()`` now always computes a real ``payload_hash``
        # (see above), so a stored record with ``payload_hash is None`` can
        # only mean a record created by code that bypassed ``request()``
        # (e.g. a pre-fix durable record, or a direct ``ApprovalRecord``
        # construction) -- treat that ambiguity as a mismatch, never as
        # "nothing to check". A one-sided ``is not None`` guard here was
        # exactly what let an omitted/empty stored hash bypass this
        # binding entirely.
        if rec.payload_hash is None or rec.payload_hash != payload_hash:
            return ConsumeResult(False, "PAYLOAD_MISMATCH: approval not for this payload")
        return await self.registry.consume(request_id, now=now)
