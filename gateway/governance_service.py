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
    DelegationAuthority,
    DelegationVerifier,
    EnforcementCoordinator,
    MandateAuthority,
    MandateVerifier,
    ProfileError,
    ProfileRegistry,
    RevocationStatus,
    Verdict,
    delegation_velocity_descriptor,
    delegation_velocity_limit,
    hash_payload,
)
from mcc_core.trusted_time import LocalTimeSource, TimeTrustError, TrustedTimeSource

from .pre_execution_control import PreExecutionControl


def _missing_logical_operation_id(idempotency_key: Optional[str]) -> bool:
    """Round 25 remediation — transport-layer defense-in-depth ONLY: the real,
    unavoidable enforcement point is ``EnforcementCoordinator.enforce()``
    itself (it fails closed on a missing/empty/whitespace idempotency_key
    regardless of what happens here). This early check exists purely so an
    execution request without a usable logical-operation identity is
    rejected before any authority is spent minting a signed token, never as
    a substitute for the coordinator's own check."""
    return not isinstance(idempotency_key, str) or not idempotency_key.strip()


def _missing_tenant_id(tenant_id: Optional[str]) -> bool:
    """PR #105 remediation — transport-layer defense-in-depth ONLY, mirroring
    ``_missing_logical_operation_id`` exactly: the real, unavoidable
    enforcement point is ``EnforcementCoordinator.enforce()`` itself (it
    fails closed on a missing/empty/whitespace ``tenant_id`` claim on the
    token regardless of what happens here). This early check exists purely
    so an execution request without a trusted tenant/security-domain
    identity is rejected before any authority is spent minting a signed
    token, never as a substitute for the coordinator's own check."""
    return not isinstance(tenant_id, str) or not tenant_id.strip()


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
        consensus_verifier: Optional[Any] = None,
        challenge_service: Optional[Any] = None,
        pre_execution_control: Optional[PreExecutionControl] = None,
        time_source: Optional[TrustedTimeSource] = None,
        delegation_verifier: Optional[DelegationVerifier] = None,
        integrity_monitor: Optional[Any] = None,
    ) -> None:
        self.engine = engine
        self.coordinator = coordinator
        # Clock-skew hardening (PR #122 round 3): the SINGLE source of
        # trusted ``now`` this gateway instance resolves per request --
        # see ``mcc_core.trusted_time``. Defaults to this process's own
        # clock (pre-existing behavior) when not configured; opts into a
        # shared, validated Redis clock via build_governance_service's
        # MCC_TIME_TRUST_BACKEND=redis. ``_now()`` below is the only place
        # this service resolves "now" for mandate/trust verification and
        # decision-token issuance -- it never falls back to an unchecked
        # ``time.time()`` when this source cannot vouch for the result.
        self.time_source: TrustedTimeSource = time_source or LocalTimeSource()
        # Optional pre-token Multi-Context Consensus step (None = disabled).
        self.consensus_verifier = consensus_verifier
        # Optional consensus-challenge service: the gateway issues the one-time
        # nonce (None = disabled; clients would supply their own nonce instead).
        self.challenge_service = challenge_service
        self.trust_set = trust_set
        self.revocation_registry = revocation_registry
        self.approvals = approvals
        self.profiles = profiles or ProfileRegistry.default_pilot()
        self.upstream = upstream
        self.policy_hash = policy_hash
        # PR-2: optional pre-execution attestation Control boundary (None =
        # disabled -> unchanged pre-PR-2 behavior for every action, since no
        # AttestationRequirement can ever be resolved without it configured).
        self.pre_execution_control = pre_execution_control
        # Verifiable Delegation & Intent Binding (planned PR #123 in the
        # roadmap/threat-model; the actual implementation PR number is
        # whatever GitHub assigns, since #123 itself was consumed by the
        # documentation handoff). None = disabled -> execute_with_delegation
        # fails closed with no configured delegation authority. Built from a
        # DEDICATED owner trust root (see delegation.py's module docstring,
        # point 2) -- never the same TrustSet instance as ``self.trust_set``
        # (mandate issuers), so an agent's own key, even if somehow trusted
        # for mandates, can never satisfy delegation verification.
        self.delegation_verifier = delegation_verifier
        # P2-A3: optional fail-closed audit-integrity ISSUANCE gate (an
        # ``mcc_core.audit_integrity.AuditIntegrityMonitor``; None =
        # disabled -> unchanged pre-P2-A3 behavior for every call site).
        # Independent of, and in addition to, EnforcementCoordinator's own
        # dispatch-boundary check -- see ``_integrity_gate`` below for why
        # both exist.
        self.integrity_monitor = integrity_monitor

    async def _integrity_gate(self) -> "Optional[ExecOutcome]":
        """P2-A3 issuance-boundary gate -- mirrors ``_attestation_gate``'s
        calling convention. Returns an ``ExecOutcome`` (BLOCKED) the caller
        must return immediately, WITHOUT ever calling
        ``DecisionEngine.issue_token``, when audit-chain integrity cannot
        currently be established as HEALTHY. A no-op (returns ``None``)
        when no ``integrity_monitor`` is configured.

        Deliberately a SEPARATE, independent check from
        ``EnforcementCoordinator.enforce()``'s own dispatch-boundary check,
        not a substitute for it: a caller that reaches the coordinator
        directly, bypassing this service entirely, must still be blocked --
        exactly what that other, independently-configured check guarantees.
        Losing either boundary would leave a bypass; this task requires
        both.
        """
        if self.integrity_monitor is None:
            return None
        from mcc_core.audit_integrity import IntegrityState

        state = await self.integrity_monitor.current_state()
        if state == IntegrityState.HEALTHY:
            return None
        return ExecOutcome(
            "BLOCKED",
            f"AUDIT_INTEGRITY_NOT_HEALTHY: audit-chain integrity state is {state.value}; "
            "refusing to issue executable authority; fail-closed",
            decision="DENY",
        )

    async def _attestation_gate(
        self, *, action: str, forward_context: Dict[str, Any], resource: Optional[str],
        attestation: Optional[Dict[str, Any]], now: Optional[int] = None,
    ) -> "tuple[Optional[ExecOutcome], Optional[str]]":
        """Shared PR-2/PR-3 gate. Returns ``(blocked, evidence_digest)``:

        * ``blocked`` is ``None`` when issuance may proceed, or an
          ``ExecOutcome`` (BLOCKED) the caller must return immediately
          without ever calling ``DecisionEngine.issue_token``.
        * ``evidence_digest`` (PR-3) is the trusted digest Control itself
          derived from the exact verified attestation, present if and only
          if a REQUIRED attestation was VERIFIED -- ``None`` when no Control
          boundary is configured, when the action has no configured
          AttestationRequirement (NOT_REQUIRED), and always when ``blocked``
          is not ``None``. This is the single Control operation: the
          attestation is verified here exactly once, and the same result
          that decides ALLOW/BLOCK also supplies the digest -- there is no
          second verification pass to "obtain" it.
        """
        if self.pre_execution_control is None:
            return None, None
        result = await self.pre_execution_control.evaluate(
            action=action, forward_context=forward_context, resource=resource,
            raw_attestation=attestation, policy_hash=self.policy_hash, now=now,
        )
        if result.ok:
            return None, result.evidence_digest
        return ExecOutcome(
            "BLOCKED", f"{result.reason_code.value}: {result.reason}", decision="DENY",
        ), None

    # ---- helpers ----

    async def _now(self) -> int:
        """The single trusted-``now`` resolution point for this service.
        Raises :class:`TimeTrustError` when ``self.time_source`` cannot
        currently vouch for a result -- every caller below catches this and
        fails closed (BLOCKED/denied), never substituting an unchecked
        local clock."""
        return await self.time_source.now()

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
            # Same shared, validated clock this service itself resolved
            # ``now`` from -- consistent even though ``verify()`` below is
            # always called with an explicit ``now`` (defense-in-depth for
            # any future call site that omits it).
            time_source=self.time_source,
        )
        return MandateAuthority(verifier), resolution

    # ---- mandate operations ----

    async def verify_mandate(
        self, *, mandate: Any, subject: str, action: str,
        resource: Optional[str] = None, policy_hash: Optional[str] = None,
    ) -> VerifyOutcome:
        try:
            now = await self._now()
        except TimeTrustError as exc:
            return VerifyOutcome(False, f"{exc.reason}: {exc.detail}")
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
        idempotency_key: Optional[str] = None, tenant_id: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        extra_auth_claims: Optional[Dict[str, Any]] = None,
        attestation: Optional[Dict[str, Any]] = None,
    ) -> ExecOutcome:
        try:
            now = await self._now()
        except TimeTrustError as exc:
            return ExecOutcome("BLOCKED", f"{exc.reason}: {exc.detail}", decision="DENY")
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

        # The EXACT final payload that would be executable -- after any
        # mandate CONSTRAIN rewrite. This, not the pre-constraint proposal, is
        # what an attestation must bind to (PR-2 exact-payload rule).
        forward_context = decision.forward_context or canonical

        # PR-2: no executable authority without required, valid attestation --
        # evaluated against the exact forward_context, BEFORE any token is
        # issued. A no-op when unconfigured or the action has no requirement.
        # PR-3: the same Control call also yields the trusted evidence_digest
        # for a VERIFIED required attestation (None otherwise).
        integrity_blocked = await self._integrity_gate()
        if integrity_blocked is not None:
            return integrity_blocked

        blocked, evidence_digest = await self._attestation_gate(
            action=action, forward_context=forward_context, resource=resource,
            attestation=attestation, now=now,
        )
        if blocked is not None:
            return blocked

        # Round 25 remediation — defense-in-depth only (see
        # ``_missing_logical_operation_id``): the coordinator itself is the
        # authoritative, unavoidable enforcement point for this invariant.
        if _missing_logical_operation_id(idempotency_key):
            return ExecOutcome(
                "BLOCKED",
                "MISSING_LOGICAL_OPERATION_ID: a valid, non-empty idempotency_key "
                "is required for protected execution; fail-closed",
                decision=decision.verdict.value,
            )

        # PR #105 remediation — defense-in-depth only (see
        # ``_missing_tenant_id``): the coordinator itself is the
        # authoritative, unavoidable enforcement point for this invariant.
        # ``tenant_id`` MUST already be the trusted server-side/authenticated
        # identity the HTTP layer (``governance_api.py``) resolved from the
        # caller's credential -- this method never derives, infers, or
        # accepts one from a request-body/payload field.
        if _missing_tenant_id(tenant_id):
            return ExecOutcome(
                "BLOCKED",
                "MISSING_TENANT_IDENTITY: a valid, non-empty tenant_id "
                "is required for protected execution; fail-closed",
                decision=decision.verdict.value,
            )

        auth_claims = dict(profile.auth_claims(forward_context))
        if extra_auth_claims:
            auth_claims.update(extra_auth_claims)
        token = self.engine.issue_token(
            verdict=decision.verdict.value, subject=actor, action=action,
            payload=forward_context, constraints=decision.constraints,
            transaction_id=transaction_id, idempotency_key=idempotency_key,
            tenant_id=tenant_id, actor_id=actor, resource_id=resource,
            auth_claims=auth_claims, mandate_id=decision.mandate_id,
            evidence_digest=evidence_digest, now=now,
            # PR #122 round 6, Finding 1: never let the issued token outlive
            # the mandate (or, via execute_with_approval, the approval-
            # minted mandate) that authorized it -- see
            # MandateAuthorityDecision.mandate_exp / issue_token's max_exp.
            max_exp=decision.mandate_exp,
        )
        # PR-3: the exact raw evidence artifact (when this token is
        # evidence-bound) follows the token down the SAME governed execution
        # path, to be checked by ExecutionGate against evidence_digest --
        # never a second, separate execution route.
        return await self._run(token, action, forward_context, actor, resource,
                               transaction_id, headers, tenant_id=tenant_id, evidence=attestation)

    # ---- Verifiable Delegation & Intent Binding ----

    async def execute_with_delegation(
        self, *, delegation: Any, actor: str, action: str, resource: Optional[str],
        purpose: str, context: Dict[str, Any], transaction_id: Optional[str] = None,
        idempotency_key: Optional[str] = None, tenant_id: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        extra_auth_claims: Optional[Dict[str, Any]] = None,
        attestation: Optional[Dict[str, Any]] = None,
    ) -> ExecOutcome:
        """Execute under a signed owner-to-agent :mod:`mcc_core.delegation`,
        through the SAME one governed execution path every other authority
        source uses (``self._run()`` -> ``EnforcementCoordinator.enforce()``)
        -- no second execution route, no changes to the coordinator itself.

        ``purpose`` is a TRUSTED, server-resolved parameter, exactly like
        ``tenant_id`` below -- never read from the agent-supplied ``context``
        (an agent must not be able to freely assert which delegated purpose
        its own proposal falls under).

        The recipient, currency, and amount ``DelegationAuthority`` checks
        against are deliberately NOT separate parameters here: they are
        read from ``canonical`` -- the SAME canonicalized payload that
        becomes ``forward_context`` and is bound into the token's
        ``payload_hash`` below. Accepting them as independent arguments
        would let a caller assert one (in-scope) value to the authority
        while the actual executed payload carried another -- exactly the
        T-03 payload-substitution risk this module exists to close. This
        currently requires the resolved action profile to be payment-shaped
        (``beneficiary_id``/``amount``/``currency`` -- see
        ``mcc_core.profiles.PaymentProfile``); a delegation for a non-
        payment action profile has no recipient/amount/currency to check
        and is out of this module's scope.
        """
        if self.delegation_verifier is None:
            return ExecOutcome(
                "BLOCKED", "delegation authority not configured; fail-closed", decision="DENY",
            )
        try:
            now = await self._now()
        except TimeTrustError as exc:
            return ExecOutcome("BLOCKED", f"{exc.reason}: {exc.detail}", decision="DENY")

        try:
            profile = self.profiles.for_action(action)
            canonical = profile.canonical_payload(context)
        except ProfileError as exc:
            return ExecOutcome("BLOCKED", f"PROFILE_ERROR: {exc}", decision="DENY")

        recipient = canonical.get("beneficiary_id")
        currency = canonical.get("currency")
        amount = canonical.get("amount")

        authority = DelegationAuthority(self.delegation_verifier)
        decision = await authority.authorize(
            delegation, subject=actor, tenant_id=tenant_id or "", action=action,
            resource=resource, recipient=recipient, currency=currency, amount=amount,
            purpose=purpose, now=now, policy_hash=self.policy_hash,
        )
        if decision.verdict != Verdict.ALLOW:
            return ExecOutcome("BLOCKED", decision.reason, decision=decision.verdict.value)

        integrity_blocked = await self._integrity_gate()
        if integrity_blocked is not None:
            return integrity_blocked

        blocked, evidence_digest = await self._attestation_gate(
            action=action, forward_context=canonical, resource=resource,
            attestation=attestation, now=now,
        )
        if blocked is not None:
            return blocked

        if _missing_logical_operation_id(idempotency_key):
            return ExecOutcome(
                "BLOCKED",
                "MISSING_LOGICAL_OPERATION_ID: a valid, non-empty idempotency_key "
                "is required for protected execution; fail-closed",
                decision=decision.verdict.value,
            )
        if _missing_tenant_id(tenant_id):
            return ExecOutcome(
                "BLOCKED",
                "MISSING_TENANT_IDENTITY: a valid, non-empty tenant_id "
                "is required for protected execution; fail-closed",
                decision=decision.verdict.value,
            )

        # Atomic, cumulative spend reservation -- BEFORE any token is issued,
        # so a budget breach never reaches the coordinator or the actuator.
        # Reuses EnforcementCoordinator's own VelocityRegistry instance (the
        # SAME atomic Redis-Lua primitive PR #122 already proved safe
        # against transaction splitting and cross-instance races); no
        # parallel accounting system is introduced. Deliberately never
        # passes an explicit ``now=`` (see ``_run()``'s own rationale,
        # just below -- InMemoryVelocityRegistry's window bookkeeping is
        # monotonic-clock based and must never be threaded a wall-clock
        # value from here).
        velocity = self.coordinator.velocity
        limit = delegation_velocity_limit(delegation)
        vel_descriptor = delegation_velocity_descriptor(
            delegation, amount=amount, currency=currency, recipient=recipient,
        )
        vel_outcome = await velocity.reserve(limit, vel_descriptor)
        if not vel_outcome.ok:
            return ExecOutcome("BLOCKED", vel_outcome.reason, decision="DENY")

        auth_claims = dict(profile.auth_claims(canonical))
        auth_claims["delegation_id"] = decision.delegation_id
        auth_claims["purpose"] = purpose
        if extra_auth_claims:
            auth_claims.update(extra_auth_claims)
        token = self.engine.issue_token(
            verdict=Verdict.ALLOW.value, subject=actor, action=action, payload=canonical,
            transaction_id=transaction_id, idempotency_key=idempotency_key,
            tenant_id=tenant_id, actor_id=actor, resource_id=resource,
            auth_claims=auth_claims, mandate_id=decision.delegation_id,
            evidence_digest=evidence_digest, now=now,
            # Never let the issued token outlive the delegation that
            # authorized it -- the same max_exp clamp PR #122 round 6
            # applies to mandates (see DecisionEngine.issue_token).
            max_exp=decision.delegation_exp,
        )
        result = await self._run(token, action, canonical, actor, resource, transaction_id,
                                 headers, tenant_id=tenant_id, evidence=attestation)
        if result.status == ActuationStatus.BLOCKED.value:
            # Pre-dispatch failure: no external effect occurred (the
            # coordinator's own fail-closed ordering guarantees this), so
            # releasing the reservation is safe and lets a legitimate retry
            # proceed without permanently losing that budget. Passes back
            # the EXACT now vel_outcome.reserve() stored the reservation
            # under (never a freshly re-resolved one) -- see
            # VelocityOutcome.now's docstring for why a mismatched now
            # silently fails to find the event to release.
            await velocity.release(limit, vel_descriptor, now=vel_outcome.now)
        # A durable EXECUTION_FAILED/UNKNOWN outcome deliberately does NOT
        # release the reservation: the external side effect may have
        # happened, and releasing budget here could let a genuine double-
        # spend occur if the operation actually succeeded despite the
        # ambiguous result -- mirroring the EXECUTED-vs-UNKNOWN distinction
        # EnforcementCoordinator itself already enforces for idempotency
        # and dispatch ownership.
        return result

    # ---- approval operations (ESCALATE loop) ----

    async def create_approval(
        self, *, actor: str, action: str, resource: Optional[str] = None,
        transaction_id: Optional[str] = None, policy_hash: Optional[str] = None,
        payload_hash: Optional[str] = None, constraints: Optional[Dict[str, Any]] = None,
        ttl_seconds: Optional[int] = None, tenant_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        request_id = await self.approvals.request(
            actor=actor, action=action, resource=resource, transaction_id=transaction_id,
            policy_hash=policy_hash, payload_hash=payload_hash, constraints=constraints,
            ttl_seconds=ttl_seconds, tenant_id=tenant_id, payload=payload,
        )
        rec = await self.approvals.get(request_id)
        return {"request_id": request_id, "state": rec.state}

    async def get_approval(self, request_id: str) -> Optional[Dict[str, Any]]:
        rec = await self.approvals.get(request_id)
        if rec is None:
            return None
        # Non-sensitive view (hashes are not secrets; no key material).
        return {
            "request_id": rec.request_id, "state": rec.state, "actor": rec.actor,
            "action": rec.action, "resource": rec.resource,
            "transaction_id": rec.transaction_id, "created_at": rec.created_at,
            "expires_at": rec.expires_at,
        }

    async def approve(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Human approval mints a scoped, signed, single-use approval mandate.
        It does not execute anything."""
        return await self.approvals.approve(request_id)

    async def deny(self, request_id: str) -> bool:
        return await self.approvals.deny(request_id)

    async def invalidate(self, request_id: str) -> bool:
        return await self.approvals.invalidate(request_id)

    async def execute_with_approval(
        self, *, mandate: Any, actor: str, action: str, resource: Optional[str],
        context: Dict[str, Any], transaction_id: Optional[str] = None,
        idempotency_key: Optional[str] = None, tenant_id: Optional[str] = None,
        attestation: Optional[Dict[str, Any]] = None,
    ) -> ExecOutcome:
        """Re-evaluate against the approval mandate and execute through the one
        coordinator path. The token carries the approval_id, so the coordinator
        consumes the approval single-use at actuation. Delegates to
        ``execute_with_mandate``, so the PR-2 attestation gate applies here too
        -- there is exactly one place that calls ``issue_token`` for either."""
        approval_id = mandate.get("approval_id") if isinstance(mandate, dict) else None
        return await self.execute_with_mandate(
            mandate=mandate, actor=actor, action=action, resource=resource,
            context=context, transaction_id=transaction_id, idempotency_key=idempotency_key,
            tenant_id=tenant_id,
            extra_auth_claims={"approval_id": approval_id} if approval_id else None,
            attestation=attestation,
        )

    # ---- consensus challenge (gateway-issued one-time nonce) ----

    async def issue_challenge(
        self, *, action: str, actor: str, resource: Optional[str],
        context: Dict[str, Any], ttl_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Mint a single-use consensus challenge bound to the canonical payload.
        The gateway owns the nonce; the client receives it (plus the binding) to
        gather evaluator votes. Fail-closed if no challenge service / profile."""
        if self.challenge_service is None:
            return {"error": "challenge service not configured; fail-closed"}
        profile = self.profiles.for_action(action)          # may raise ProfileError
        canonical = profile.canonical_payload(context)
        rec = await self.challenge_service.issue(
            action=action, actor=actor, resource=resource,
            payload_hash=hash_payload(canonical), policy_hash=self.policy_hash,
            ttl_seconds=ttl_seconds,
        )
        return rec.public_view()

    # ---- multi-context consensus (pre-token authority step) ----

    def _consensus(self, votes, action, context, actor, resource=None, nonce=None, now=None):
        profile = self.profiles.for_action(action)
        canonical = profile.canonical_payload(context)  # may raise ProfileError
        result = self.consensus_verifier.verify(
            votes, action=action, payload=canonical, actor=actor,
            resource=resource, policy_hash=self.policy_hash, nonce=nonce, now=now)
        return profile, canonical, result

    async def verify_consensus(self, *, votes, action, context, actor,
                               resource=None, nonce=None) -> Dict[str, Any]:
        if self.consensus_verifier is None:
            return {"verdict": "DENY", "reason": "consensus not configured; fail-closed",
                    "agreement": 0, "threshold": 0, "evaluators": [], "rejected_votes": 0}
        try:
            now = await self._now()
        except TimeTrustError as exc:
            return {"verdict": "DENY", "reason": f"{exc.reason}: {exc.detail}", "agreement": 0,
                    "threshold": 0, "evaluators": [], "rejected_votes": 0}
        try:
            _, _, result = self._consensus(votes, action, context, actor, resource, nonce, now)
        except ProfileError as exc:
            return {"verdict": "DENY", "reason": f"PROFILE_ERROR: {exc}", "agreement": 0,
                    "threshold": 0, "evaluators": [], "rejected_votes": 0}
        return {"verdict": result.verdict.value, "reason": result.reason,
                "agreement": result.agreement, "threshold": result.threshold,
                "evaluators": result.allow_evaluators, "rejected_votes": result.rejected_votes}

    async def execute_with_consensus(
        self, *, votes, actor: str, action: str, resource: Optional[str],
        context: Dict[str, Any], transaction_id: Optional[str] = None,
        idempotency_key: Optional[str] = None, tenant_id: Optional[str] = None,
        nonce: Optional[str] = None,
        challenge_id: Optional[str] = None, attestation: Optional[Dict[str, Any]] = None,
    ) -> ExecOutcome:
        """Require N-of-M independent signed evaluators to agree — bound to the
        exact action/actor/payload/resource/policy/nonce — then issue the token
        (carrying that same nonce) and run the one coordinator path, which
        re-verifies consensus before any actuation. No consensus -> no token,
        and a token with no/invalid consensus never actuates.

        When ``challenge_id`` is supplied, the gateway-issued challenge is the
        authority for the nonce: it is resolved and re-bound here (unknown or
        expired -> fail closed), its nonce is used to verify the votes and issue
        the token, and the coordinator consumes it single-use before actuation."""
        try:
            now = await self._now()
        except TimeTrustError as exc:
            return ExecOutcome("BLOCKED", f"{exc.reason}: {exc.detail}", decision="DENY")
        if self.consensus_verifier is None:
            return ExecOutcome("BLOCKED", "consensus not configured; fail-closed", decision="DENY")

        auth_claims_extra: Dict[str, Any] = {}
        if challenge_id is not None:
            if self.challenge_service is None:
                return ExecOutcome("BLOCKED", "challenge service not configured; fail-closed",
                                   decision="DENY")
            rec = await self.challenge_service.get(challenge_id)
            if rec is None:
                return ExecOutcome("BLOCKED", "UNKNOWN_CHALLENGE: not found", decision="DENY")
            if rec.state != "ISSUED":
                return ExecOutcome("BLOCKED", f"CHALLENGE_NOT_OPEN: state {rec.state}",
                                   decision="DENY")
            # The gateway-issued nonce is authoritative; ignore any client nonce.
            nonce = rec.nonce
            auth_claims_extra["challenge_id"] = challenge_id

        try:
            profile, canonical, result = self._consensus(votes, action, context, actor, resource, nonce, now)
        except ProfileError as exc:
            return ExecOutcome("BLOCKED", f"PROFILE_ERROR: {exc}", decision="DENY")
        if not result.ok:
            return ExecOutcome("BLOCKED", result.reason, decision=result.verdict.value)

        # Consensus carries no mandate CONSTRAIN rewrite step, so the exact
        # final payload is simply the canonicalized one -- still resolved via
        # the action profile, never the raw caller-supplied context.
        integrity_blocked = await self._integrity_gate()
        if integrity_blocked is not None:
            return integrity_blocked

        blocked, evidence_digest = await self._attestation_gate(
            action=action, forward_context=canonical, resource=resource,
            attestation=attestation, now=now,
        )
        if blocked is not None:
            return blocked

        # Round 25 remediation — defense-in-depth only; see
        # ``_missing_logical_operation_id`` / execute_with_mandate.
        if _missing_logical_operation_id(idempotency_key):
            return ExecOutcome(
                "BLOCKED",
                "MISSING_LOGICAL_OPERATION_ID: a valid, non-empty idempotency_key "
                "is required for protected execution; fail-closed",
                decision=result.verdict.value,
            )

        # PR #105 remediation — defense-in-depth only; see
        # ``_missing_tenant_id`` / execute_with_mandate.
        if _missing_tenant_id(tenant_id):
            return ExecOutcome(
                "BLOCKED",
                "MISSING_TENANT_IDENTITY: a valid, non-empty tenant_id "
                "is required for protected execution; fail-closed",
                decision=result.verdict.value,
            )

        auth_claims = dict(profile.auth_claims(canonical))
        auth_claims["consensus"] = result.summary()
        auth_claims.update(auth_claims_extra)
        token = self.engine.issue_token(
            verdict="ALLOW", subject=actor, action=action, payload=canonical,
            transaction_id=transaction_id, idempotency_key=idempotency_key,
            tenant_id=tenant_id, actor_id=actor, resource_id=resource,
            auth_claims=auth_claims, nonce=nonce,
            evidence_digest=evidence_digest, now=now)
        return await self._run(token, action, canonical, actor, resource, transaction_id, None,
                               tenant_id=tenant_id, consensus_votes=votes, evidence=attestation)

    # ---- the one governed execution path ----

    async def _run(self, token, action, forward_context, actor, resource,
                   transaction_id, headers, tenant_id=None, consensus_votes=None,
                   evidence: Optional[Dict[str, Any]] = None) -> ExecOutcome:
        async def executor():
            if self.upstream is None:
                raise RuntimeError("no upstream configured")
            return await self.upstream(action, forward_context)

        # Deliberately NEVER pass ``now=`` into ``coordinator.enforce()``
        # here (see tests/test_velocity.py::
        # test_no_production_call_site_passes_an_explicit_now_to_velocity_
        # reserve): that single parameter also reaches
        # ``VelocityRegistry.reserve()``, and ``InMemoryVelocityRegistry``
        # deliberately uses ``time.monotonic()`` (not epoch time) for its
        # window bookkeeping -- a wall-clock ``now`` threaded in from here
        # would be silently incomparable to it. The gate's token-validity
        # check and ``ApprovalService.consume()`` each resolve their own
        # trusted ``now`` independently instead (``ExecutionGate``'s own
        # ``time_source``; ``ApprovalService.time_source`` -- see
        # ``trusted_time.py``), which keeps this invariant intact while
        # still closing the clock-skew gap in each of those components.
        result = await self.coordinator.enforce(
            token=token, action=action, payload=forward_context, executor=executor,
            request_binding={"actor_id": actor, "resource_id": resource,
                             "transaction_id": transaction_id, "tenant_id": tenant_id},
            consensus_votes=consensus_votes, evidence=evidence,
        )
        status = (ActuationStatus.EXECUTED if result.status == ActuationStatus.EXECUTED
                  else result.status)
        return ExecOutcome(
            status=result.status.value, reason=result.reason,
            decision=result.decision.value if result.decision else None,
            audit_ref=result.audit_ref, execution=result.execution,
        )
