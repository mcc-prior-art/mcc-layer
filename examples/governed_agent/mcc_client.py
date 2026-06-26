"""GovernedMCCClient — the only path from an agent to an executor.

It does **not** decide anything itself. It submits a proposed action through the
*real* MCC-Core components already in the repository:

    AuthorityModel       -> the verdict (ALLOW / DENY / ESCALATE / CONSTRAIN)
    DecisionEngine       -> the signed decision token over the authorized body
    ExecutionGate        -> signature + audience + expiry + payload-hash + nonce
    EnforcementCoordinator -> idempotency + velocity + audit-before-actuation +
                             single-use approval consume + the executor call
    ApprovalService      -> the ESCALATE human-approval loop (single-use)
    registries           -> nonce / idempotency / velocity / approval state
                             (in-memory, or Redis-backed for multi-instance)

The verdict comes from ``AuthorityModel``; enforcement comes from the gate and
coordinator; approval comes from ``ApprovalService``. This module is wiring and
fail-closed dispatch only — no governance decision is re-implemented here.

Fail-closed: any timeout, malformed response, unknown verdict, unavailable
runtime, missing required field, or verification failure yields a non-executing
result. The executor is reached **only** via ``coordinator.enforce`` after the
gate verifies and the audit record is written.
"""

from __future__ import annotations

import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from mcc_core import (
    ActionPolicy,
    ActuationStatus,
    ApprovalService,
    AuditLog,
    AuthorityModel,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryApprovalRegistry,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryVelocityRegistry,
    Mandate,
    MandateRegistry,
    ProfileRegistry,
    SigningKey,
    Verdict,
    VelocityLimit,
    hash_payload,
)

from .agent import ProposedAction
from .mock_executor import MockExecutor

VERDICTS = {"ALLOW", "DENY", "ESCALATE", "CONSTRAIN"}
REQUIRED_FIELDS = ("actor", "action", "transaction_id", "idempotency_key", "nonce", "correlation_id")


@dataclass(frozen=True)
class GovernedResult:
    verdict: str                      # ALLOW / DENY / ESCALATE / CONSTRAIN / ERROR
    executed: bool
    status: str                       # COMPLETED / BLOCKED
    reason: str
    proposed_payload: Dict[str, Any]
    action: str = ""
    authorized_payload: Optional[Dict[str, Any]] = None
    applied_changes: List[str] = field(default_factory=list)
    audit_ref: Optional[str] = None
    correlation_id: Optional[str] = None
    transaction_id: Optional[str] = None
    approval_request_id: Optional[str] = None


def default_demo_authority() -> AuthorityModel:
    """A small, domain-neutral authority config for the demo.

    ``agent/ops`` holds a ``transfer`` mandate capped at ``max_amount=5000``.
    Generic actions only — the core stays domain-neutral (``amount`` is just a
    numeric field a constraint happens to bound)."""
    registry = MandateRegistry([
        Mandate(holder="agent/ops", authority="transfer", constraints={"max_amount": 5000}),
    ])
    policies = [
        ActionPolicy(action="transfer_resource", requires="transfer",
                     on_mandate=Verdict.ALLOW, on_violation=Verdict.CONSTRAIN,
                     without_mandate=Verdict.ESCALATE),
        # An irreversibly destructive action no mandate can authorize -> hard DENY.
        ActionPolicy(action="delete_resource", requires=None, without_mandate=Verdict.DENY),
    ]
    return AuthorityModel(registry=registry, policies=policies, default=Verdict.DENY)


class GovernedMCCClient:
    def __init__(
        self,
        *,
        executor: MockExecutor,
        authority: Optional[AuthorityModel] = None,
        signing_key: Optional[SigningKey] = None,
        policy_hash: str = "sha256:mcc-demo-policy-v1",
        audience: str = "mcc-demo-gate",
        nonce_registry: Optional[Any] = None,
        idempotency_registry: Optional[Any] = None,
        velocity_registry: Optional[Any] = None,
        approval_registry: Optional[Any] = None,
        velocity_limits: Optional[List[VelocityLimit]] = None,
        audit_path: Optional[str] = None,
        op_timeout_seconds: float = 2.0,
    ) -> None:
        self.executor = executor
        self.authority = authority or default_demo_authority()
        self.policy_hash = policy_hash
        self._op_timeout = op_timeout_seconds
        signing_key = signing_key or SigningKey.generate("mcc-demo-signer")
        self.engine = DecisionEngine(
            signing_key=signing_key, issuer="mcc/demo", audience=audience,
            policy_id="mcc.demo/v1", policy_hash=policy_hash, token_ttl_seconds=60)
        self.audit = AuditLog(audit_path or str(Path(tempfile.mkdtemp(prefix="mcc-demo-")) / "audit.jsonl"))
        self.gate = ExecutionGate(
            trusted_keys={signing_key.kid: signing_key.public_key()}, audience=audience,
            nonce_registry=nonce_registry or InMemoryNonceRegistry(), policy_hash=policy_hash)
        self._velocity_limits = list(velocity_limits or [])
        self.approvals = ApprovalService(
            approval_registry or InMemoryApprovalRegistry(), SigningKey.generate("mcc-demo-approver"))
        self.coordinator = EnforcementCoordinator(
            gate=self.gate,
            idempotency=idempotency_registry or InMemoryIdempotencyRegistry(),
            velocity=velocity_registry or InMemoryVelocityRegistry(),
            audit=self.audit, profiles=ProfileRegistry(),
            velocity_limits_for=lambda action: self._velocity_limits,
            approvals=self.approvals)

    # ---- helpers ----

    @staticmethod
    def _now() -> int:
        return int(time.time())

    def _missing_fields(self, p: ProposedAction) -> List[str]:
        d = p.to_dict()
        return [f for f in REQUIRED_FIELDS if not d.get(f)]

    async def _enforce(self, token: Dict[str, Any], action: str, payload: Dict[str, Any],
                       proposed: ProposedAction):
        """The single governed execution path: gate -> (approval consume) ->
        idempotency -> velocity -> audit-before-actuation -> executor."""
        async def executor():
            return await self.executor.execute(
                action, payload, authorization=token, correlation_id=proposed.correlation_id)

        return await self.coordinator.enforce(
            token=token, action=action, payload=payload, executor=executor,
            request_binding={"actor_id": proposed.actor, "resource_id": proposed.resource,
                             "transaction_id": proposed.transaction_id})

    def _issue_token(self, proposed: ProposedAction, verdict: Verdict,
                     forward_context: Dict[str, Any], constraints: Dict[str, Any],
                     *, audit_ref: Optional[str] = None, approval_id: Optional[str] = None):
        auth_claims = {"correlation_id": proposed.correlation_id}
        if approval_id:
            auth_claims["approval_id"] = approval_id
        return self.engine.issue_token(
            verdict=verdict.value, subject=proposed.actor, action=proposed.action,
            payload=forward_context, constraints=constraints, nonce=proposed.nonce,
            transaction_id=proposed.transaction_id, idempotency_key=proposed.idempotency_key,
            actor_id=proposed.actor, resource_id=proposed.resource,
            auth_claims=auth_claims, audit_ref=audit_ref)

    # ---- the public submit path ----

    async def submit(self, proposed: ProposedAction) -> GovernedResult:
        """Submit a proposed action. Returns a non-executing result for DENY /
        ESCALATE / any fail-closed condition; executes once (through the gate)
        for ALLOW / CONSTRAIN."""
        try:
            missing = self._missing_fields(proposed)
            if missing:
                return self._blocked("ERROR", proposed, f"missing required fields: {missing}; fail-closed")

            decision = self.authority.evaluate(
                identity=proposed.actor, action=proposed.action,
                context=proposed.payload, now=self._now())

            verdict = getattr(decision, "verdict", None)
            verdict_value = getattr(verdict, "value", None)
            if verdict_value not in VERDICTS:
                # Unknown / malformed verdict -> never execute.
                return self._blocked("ERROR", proposed, f"unknown verdict {verdict_value!r}; fail-closed")

            if verdict_value == "DENY":
                return self._blocked("DENY", proposed, decision.reason)
            if verdict_value == "ESCALATE":
                return GovernedResult(
                    verdict="ESCALATE", executed=False, status="BLOCKED",
                    reason=decision.reason or "approval required",
                    proposed_payload=dict(proposed.payload), action=proposed.action,
                    correlation_id=proposed.correlation_id, transaction_id=proposed.transaction_id)

            # ALLOW or CONSTRAIN -> issue token over the AUTHORIZED body and run
            # the one governed path.
            forward = dict(decision.forward_context or proposed.payload)
            token = self._issue_token(proposed, verdict, forward, decision.constraints)
            result = await self._enforce(token, proposed.action, forward, proposed)
            return self._from_actuation(verdict_value, proposed, forward, decision.applied_changes, result)
        except Exception as exc:  # noqa: BLE001 — any failure is fail-closed
            return self._blocked("ERROR", proposed, f"runtime error; fail-closed: {type(exc).__name__}")

    # ---- ESCALATE approval loop ----

    async def request_approval(self, proposed: ProposedAction) -> str:
        """Open a human-approval request bound to this exact operation."""
        return await self.approvals.request(
            actor=proposed.actor, action=proposed.action, resource=proposed.resource,
            transaction_id=proposed.transaction_id, policy_hash=self.policy_hash,
            payload_hash=hash_payload(proposed.payload))

    async def approve(self, approval_id: str) -> bool:
        """Operator action: grant a pending approval (mints a single-use,
        signed approval mandate inside the ApprovalService)."""
        return await self.approvals.approve(approval_id) is not None

    async def deny_approval(self, approval_id: str) -> bool:
        return await self.approvals.deny(approval_id)

    async def execute_with_approval(self, proposed: ProposedAction, approval_id: str) -> GovernedResult:
        """Execute an ESCALATEd action against a granted approval. The coordinator
        consumes the approval **single-use**, bound to action/transaction/payload;
        forged, expired, mismatched, or replayed approvals fail closed here."""
        try:
            forward = dict(proposed.payload)
            token = self._issue_token(proposed, Verdict.ALLOW, forward, {}, approval_id=approval_id)
            result = await self._enforce(token, proposed.action, forward, proposed)
            out = self._from_actuation("ALLOW", proposed, forward, [], result)
            if not out.executed:
                # Surface the approval rejection reason explicitly.
                return GovernedResult(
                    verdict="ESCALATE", executed=False, status="BLOCKED", reason=out.reason,
                    proposed_payload=dict(proposed.payload), action=proposed.action,
                    correlation_id=proposed.correlation_id,
                    transaction_id=proposed.transaction_id, approval_request_id=approval_id)
            return out
        except Exception as exc:  # noqa: BLE001
            return self._blocked("ERROR", proposed, f"approval execution error; fail-closed: {type(exc).__name__}")

    # ---- result mapping ----

    def _from_actuation(self, verdict_value, proposed, forward, applied_changes, result) -> GovernedResult:
        executed = result.status == ActuationStatus.EXECUTED
        # When the coordinator blocks with its own runtime verdict (e.g. velocity
        # on_exceed -> DENY), surface that runtime-defined verdict rather than the
        # earlier authority verdict.
        if not executed and getattr(result, "decision", None) is not None:
            verdict_value = result.decision.value
        return GovernedResult(
            verdict=verdict_value,
            executed=executed,
            status="COMPLETED" if executed else "BLOCKED",
            reason=result.reason,
            proposed_payload=dict(proposed.payload),
            action=proposed.action,
            authorized_payload=dict(forward) if executed else None,
            applied_changes=list(applied_changes or []),
            audit_ref=result.audit_ref,
            correlation_id=proposed.correlation_id,
            transaction_id=proposed.transaction_id,
        )

    @staticmethod
    def _blocked(verdict, proposed, reason) -> GovernedResult:
        return GovernedResult(
            verdict=verdict, executed=False, status="BLOCKED", reason=reason,
            proposed_payload=dict(proposed.payload), action=proposed.action,
            correlation_id=proposed.correlation_id, transaction_id=proposed.transaction_id)
