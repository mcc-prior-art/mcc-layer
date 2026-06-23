"""Enforcement coordinator: the explicit, fail-closed execution order.

One place owns the sequence that turns a verified decision token into an
executed operation, so the ordering cannot drift:

    a. validate the decision token and its exact payload/operation binding
    b. consume the one-time nonce
    c. atomically reserve the idempotency key
    d. atomically reserve velocity / aggregate capacity
    e. durably record the pre-enforcement decision (audit-before-actuation)
    f. execute
    g. record the execution outcome
    h. finalize the idempotency state (EXECUTED)

Steps (a) and (b) are the execution gate. Any indeterminate infrastructure
failure *before* execution — a registry that cannot reserve, an audit write
that cannot be confirmed — fails closed: the operation does not run, and any
capacity already reserved is released.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional

from .audit import AuditLog
from .core import Verdict
from .idempotency import ReserveStatus
from .profiles import ProfileRegistry
from .velocity import VelocityLimit, VelocityOutcome


class ActuationStatus(str, Enum):
    EXECUTED = "EXECUTED"        # ran and finalized
    BLOCKED = "BLOCKED"          # refused before execution (fail-closed)
    EXECUTION_FAILED = "EXECUTION_FAILED"  # executor raised; idempotency freed for retry


@dataclass(frozen=True)
class ActuationResult:
    status: ActuationStatus
    reason: str
    decision: Optional[Verdict] = None
    audit_ref: Optional[str] = None
    execution: Any = None
    breaches: List[str] = field(default_factory=list)

    @property
    def executed(self) -> bool:
        return self.status == ActuationStatus.EXECUTED


# An executor performs the real side effect (e.g. forward upstream). It may
# raise; a raise is treated as an indeterminate execution outcome.
Executor = Callable[[], Awaitable[Any]]
LimitsResolver = Callable[[str], List[VelocityLimit]]


class EnforcementCoordinator:
    def __init__(
        self,
        *,
        gate,
        idempotency,
        velocity,
        audit: AuditLog,
        profiles: Optional[ProfileRegistry] = None,
        velocity_limits_for: Optional[LimitsResolver] = None,
        revocation_registry: Optional[Any] = None,
    ) -> None:
        self.gate = gate
        self.idempotency = idempotency
        self.velocity = velocity
        self.audit = audit
        self.profiles = profiles or ProfileRegistry()
        self.velocity_limits_for = velocity_limits_for or (lambda action: [])
        # Optional actuation-time revocation re-check: a mandate revoked between
        # decision and execution must still block. When configured, a token that
        # names a mandate_id is checked here; REVOKED or an unconfirmable status
        # fails closed.
        self.revocation_registry = revocation_registry

    def _record(self, **fields: Any) -> Optional[str]:
        try:
            entry = self.audit.append(fields)
            return entry["hash"]
        except Exception:
            return None

    async def enforce(
        self,
        *,
        token: Dict[str, Any],
        action: str,
        payload: Dict[str, Any],
        executor: Executor,
        request_binding: Optional[Dict[str, Any]] = None,
        now: Optional[int] = None,
    ) -> ActuationResult:
        # (a) validate token + operation binding, (b) consume nonce.
        gate_result = await self.gate.verify(
            token, action=action, payload=payload, binding=request_binding, now=now
        )
        if not gate_result.allowed:
            self._record(kind="actuation_rejected", action=action, reason=gate_result.reason)
            return ActuationResult(ActuationStatus.BLOCKED, gate_result.reason)

        # Actuation-time revocation re-check: a mandate revoked after the token
        # was issued must block here (fail-closed on REVOKED or unconfirmable).
        mandate_id = token.get("mandate_id")
        if self.revocation_registry is not None and mandate_id:
            from .mandate import RevocationStatus

            status = await self.revocation_registry.check(mandate_id)
            if status != RevocationStatus.ACTIVE:
                reason = f"mandate {mandate_id} {status.value.lower()} at actuation; fail-closed"
                self._record(kind="actuation_rejected", action=action, reason=reason)
                return ActuationResult(ActuationStatus.BLOCKED, reason)

        # Authoritative operation identity comes from the (now-verified) token.
        idem_key = token.get("idempotency_key")
        binding_ref = str(token.get("payload_hash", ""))
        actor_id = token.get("actor_id")
        resource_id = token.get("resource_id")
        policy_scope = token.get("policy_id")

        # (c) atomically reserve the idempotency key.
        if idem_key:
            reserved = await self.idempotency.reserve(idem_key, binding=binding_ref)
            if not reserved.ok:
                self._record(
                    kind="idempotency_block",
                    action=action,
                    idempotency_key=idem_key,
                    status=reserved.status.value,
                    reason=reserved.reason,
                )
                # ERROR is a fail-closed infra outcome; DUPLICATE_* are correct denials.
                return ActuationResult(ActuationStatus.BLOCKED, reason=reserved.reason)

        # (d) atomically reserve velocity / aggregate capacity.
        profile = self.profiles.for_action(action)
        descriptor = profile.velocity_descriptor(
            actor_id=actor_id,
            resource_id=resource_id,
            action=action,
            policy_scope=policy_scope,
            context=payload,
        )
        reserved_limits: List[VelocityLimit] = []
        for limit in self.velocity_limits_for(action):
            outcome: VelocityOutcome = await self.velocity.reserve(limit, descriptor, now=now)
            if outcome.reserved:
                reserved_limits.append(limit)
            if not outcome.ok:
                await self._release(reserved_limits, descriptor, idem_key, now)
                self._record(
                    kind="velocity_block",
                    action=action,
                    limit=limit.name,
                    decision=outcome.verdict.value,
                    reason=outcome.reason,
                )
                return ActuationResult(
                    ActuationStatus.BLOCKED, outcome.reason, decision=outcome.verdict,
                    breaches=outcome.breaches,
                )

        # (e) durably record the pre-enforcement decision (audit-before-actuation).
        pre_ref = self._record(
            kind="pre_actuation",
            action=action,
            actor_id=actor_id,
            resource_id=resource_id,
            transaction_id=token.get("transaction_id"),
            idempotency_key=idem_key,
            payload_hash=binding_ref,
            policy_hash=token.get("policy_hash"),
            decision=token.get("decision"),
        )
        if pre_ref is None:
            # Cannot confirm the pre-actuation record -> indeterminate before
            # execution -> fail closed and release everything reserved.
            await self._release(reserved_limits, descriptor, idem_key, now)
            return ActuationResult(
                ActuationStatus.BLOCKED, "audit-before-actuation failed; fail-closed"
            )

        # (f) execute.
        try:
            execution = await executor()
        except Exception as exc:  # noqa: BLE001 - any executor failure is indeterminate
            # The execution outcome is unknown. Free the idempotency key for a
            # deliberate retry, record the failure, and report fail-closed.
            if idem_key:
                await self.idempotency.mark_failed(idem_key)
            self._record(
                kind="actuation_failed",
                action=action,
                idempotency_key=idem_key,
                audit_ref=pre_ref,
                reason=f"{type(exc).__name__}: {exc}",
            )
            return ActuationResult(
                ActuationStatus.EXECUTION_FAILED, "execution failed", audit_ref=pre_ref
            )

        # (g) record the execution outcome.
        self._record(
            kind="actuation_result",
            action=action,
            idempotency_key=idem_key,
            audit_ref=pre_ref,
            status="EXECUTED",
        )
        # (h) finalize the idempotency state.
        if idem_key:
            await self.idempotency.mark_executed(idem_key, binding=binding_ref)

        return ActuationResult(
            ActuationStatus.EXECUTED, "executed", decision=Verdict(token.get("decision")),
            audit_ref=pre_ref, execution=execution,
        )

    async def _release(self, limits, descriptor, idem_key, now) -> None:
        for limit in limits:
            await self.velocity.release(limit, descriptor, now=now)
        if idem_key:
            await self.idempotency.release(idem_key)
