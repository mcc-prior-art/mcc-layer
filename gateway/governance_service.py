"""GovernanceService — wiring (not logic) for the governance HTTP layer.

This object holds the already-built governance primitives and exposes thin
orchestration methods the HTTP routers call. It contains **no** governance
decision logic: every decision is made by the existing components —
``MandateVerifier`` / ``MandateAuthority`` (authority), ``ExecutionGate``
(token + binding + nonce), ``EnforcementCoordinator`` (the a-h order, idempotency,
velocity, revocation re-check, approval consume, audit-before-actuation), and
the registries. The service only resolves trust, builds the per-request verifier
from trusted public keys, and routes governed execution through the one
coordinator path:

    authority verification -> decision token -> gate -> audit-before-actuation
    -> upstream execution

There is no second execution path: the only way these methods reach the
upstream is via ``coordinator.enforce(executor=...)``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, Optional

from mcc_core import (
    ActuationStatus,
    ApprovalService,
    DecisionEngine,
    EnforcementCoordinator,
    MandateAuthority,
    MandateVerifier,
    ProfileError,
    ProfileRegistry,
    RevocationStatus,
    Verdict,
)

from .trust import TrustSet

# An upstream executor performs the real side effect for governed execution.
# It is the *only* thing the coordinator's executor calls.
Upstream = Callable[[str, Dict[str, Any]], Awaitable[Any]]


@dataclass(frozen=True)
class VerifyOutcome:
    verified: bool
    reason: str
    mandate_id: Optional[str] = None
    issuer_id: Optional[str] = None
    constraints: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class ExecOutcome:
    status: str            # EXECUTED / BLOCKED / EXECUTION_FAILED
    reason: str
    decision: Optional[str] = None
    audit_ref: Optional[str] = None
    execution: Any = None


class GovernanceService:
    def __init__(
        self,
        *,
        engine: DecisionEngine,
        coordinator: EnforcementCoordinator,
        trust_set: TrustSet,
        revocation_registry: Any,
        approvals: ApprovalService,
        profiles: Optional[ProfileRegistry] = None,
        upstream: Optional[Upstream] = None,
        policy_hash: Optional[str] = None,
    ) -> None:
        self.engine = engine
        self.coordinator = coordinator
        self.trust_set = trust_set
        self.revocation_registry = revocation_registry
        self.approvals = approvals
        self.profiles = profiles or ProfileRegistry.default_pilot()
        self.upstream = upstream
        self.policy_hash = policy_hash

    # ---- helpers ----

    @staticmethod
    def _now() -> int:
        return int(time.time())

    def _authority_for(self, mandate: Any, now: int):
        """Resolve the mandate's kid against the trust set and return a
        MandateAuthority bound to exactly that trusted key — or a trust failure
        reason. Distinct trust statuses (unknown/disabled/expired/revoked) are
        reported verbatim; fail-closed."""
        kid = mandate.get("kid") if isinstance(mandate, dict) else None
        resolution = self.trust_set.resolve(kid, now=now)
        if not resolution.ok:
            return None, resolution
        verifier = MandateVerifier(
            trusted_keys={resolution.kid: resolution.public_key},
            revocation_registry=self.revocation_registry,
        )
        return MandateAuthority(verifier), resolution

    # ---- mandate operations ----

    async def verify_mandate(
        self, *, mandate: Any, subject: str, action: str,
        resource: Optional[str] = None, policy_hash: Optional[str] = None,
    ) -> VerifyOutcome:
        now = self._now()
        authority, resolution = self._authority_for(mandate, now)
        if authority is None:
            return VerifyOutcome(False, f"{resolution.status.value}: {resolution.reason}")
        result = await authority.verifier.verify(
            mandate, subject=subject, action=action, resource=resource,
            now=now, policy_hash=policy_hash,
        )
        return VerifyOutcome(
            verified=result.ok, reason=result.reason,
            mandate_id=result.mandate_id, issuer_id=resolution.issuer_id,
            constraints=result.constraints if result.ok else None,
        )

    async def revocation_status(self, mandate_id: str) -> str:
        return (await self.revocation_registry.check(mandate_id)).value

    async def revoke_mandate(self, mandate_id: str) -> bool:
        return await self.revocation_registry.revoke(mandate_id)

    async def execute_with_mandate(
        self, *, mandate: Any, actor: str, action: str, resource: Optional[str],
        context: Dict[str, Any], transaction_id: Optional[str] = None,
        idempotency_key: Optional[str] = None, headers: Optional[Dict[str, str]] = None,
    ) -> ExecOutcome:
        now = self._now()
        authority, resolution = self._authority_for(mandate, now)
        if authority is None:
            return ExecOutcome("BLOCKED", f"{resolution.status.value}: {resolution.reason}",
                               decision="DENY")

        # Canonicalize via the action profile (domain-specific shape stays in the
        # profile, never in this layer).
        try:
            profile = self.profiles.for_action(action)
            canonical = profile.canonical_payload(context)
        except ProfileError as exc:
            return ExecOutcome("BLOCKED", f"PROFILE_ERROR: {exc}", decision="DENY")

        decision = await authority.authorize(
            mandate, subject=actor, action=action, resource=resource,
            context=canonical, now=now, policy_hash=self.policy_hash,
        )
        if decision.verdict not in (Verdict.ALLOW, Verdict.CONSTRAIN):
            return ExecOutcome("BLOCKED", decision.reason, decision=decision.verdict.value)

        forward_context = decision.forward_context or canonical
        token = self.engine.issue_token(
            verdict=decision.verdict.value, subject=actor, action=action,
            payload=forward_context, constraints=decision.constraints,
            transaction_id=transaction_id, idempotency_key=idempotency_key,
            actor_id=actor, resource_id=resource,
            auth_claims=profile.auth_claims(forward_context), mandate_id=decision.mandate_id,
        )
        return await self._run(token, action, forward_context, actor, resource,
                               transaction_id, headers)

    # ---- the one governed execution path ----

    async def _run(self, token, action, forward_context, actor, resource,
                   transaction_id, headers) -> ExecOutcome:
        async def executor():
            if self.upstream is None:
                raise RuntimeError("no upstream configured")
            return await self.upstream(action, forward_context)

        result = await self.coordinator.enforce(
            token=token, action=action, payload=forward_context, executor=executor,
            request_binding={"actor_id": actor, "resource_id": resource,
                             "transaction_id": transaction_id},
        )
        status = (ActuationStatus.EXECUTED if result.status == ActuationStatus.EXECUTED
                  else result.status)
        return ExecOutcome(
            status=result.status.value, reason=result.reason,
            decision=result.decision.value if result.decision else None,
            audit_ref=result.audit_ref, execution=result.execution,
        )
