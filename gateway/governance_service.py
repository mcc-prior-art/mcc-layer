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
    hash_payload,
)

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
    ) -> None:
        self.engine = engine
        self.coordinator = coordinator
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

    async def _attestation_gate(
        self, *, action: str, forward_context: Dict[str, Any], resource: Optional[str],
        attestation: Optional[Dict[str, Any]],
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
            raw_attestation=attestation, policy_hash=self.policy_hash,
        )
        if result.ok:
            return None, result.evidence_digest
        return ExecOutcome(
            "BLOCKED", f"{result.reason_code.value}: {result.reason}", decision="DENY",
        ), None

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
        idempotency_key: Optional[str] = None, tenant_id: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        extra_auth_claims: Optional[Dict[str, Any]] = None,
        attestation: Optional[Dict[str, Any]] = None,
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

        # The EXACT final payload that would be executable -- after any
        # mandate CONSTRAIN rewrite. This, not the pre-constraint proposal, is
        # what an attestation must bind to (PR-2 exact-payload rule).
        forward_context = decision.forward_context or canonical

        # PR-2: no executable authority without required, valid attestation --
        # evaluated against the exact forward_context, BEFORE any token is
        # issued. A no-op when unconfigured or the action has no requirement.
        # PR-3: the same Control call also yields the trusted evidence_digest
        # for a VERIFIED required attestation (None otherwise).
        blocked, evidence_digest = await self._attestation_gate(
            action=action, forward_context=forward_context, resource=resource,
            attestation=attestation,
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
            evidence_digest=evidence_digest,
        )
        # PR-3: the exact raw evidence artifact (when this token is
        # evidence-bound) follows the token down the SAME governed execution
        # path, to be checked by ExecutionGate against evidence_digest --
        # never a second, separate execution route.
        return await self._run(token, action, forward_context, actor, resource,
                               transaction_id, headers, tenant_id=tenant_id, evidence=attestation)

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

    def _consensus(self, votes, action, context, actor, resource=None, nonce=None):
        profile = self.profiles.for_action(action)
        canonical = profile.canonical_payload(context)  # may raise ProfileError
        result = self.consensus_verifier.verify(
            votes, action=action, payload=canonical, actor=actor,
            resource=resource, policy_hash=self.policy_hash, nonce=nonce)
        return profile, canonical, result

    async def verify_consensus(self, *, votes, action, context, actor,
                               resource=None, nonce=None) -> Dict[str, Any]:
        if self.consensus_verifier is None:
            return {"verdict": "DENY", "reason": "consensus not configured; fail-closed",
                    "agreement": 0, "threshold": 0, "evaluators": [], "rejected_votes": 0}
        try:
            _, _, result = self._consensus(votes, action, context, actor, resource, nonce)
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
            profile, canonical, result = self._consensus(votes, action, context, actor, resource, nonce)
        except ProfileError as exc:
            return ExecOutcome("BLOCKED", f"PROFILE_ERROR: {exc}", decision="DENY")
        if not result.ok:
            return ExecOutcome("BLOCKED", result.reason, decision=result.verdict.value)

        # Consensus carries no mandate CONSTRAIN rewrite step, so the exact
        # final payload is simply the canonicalized one -- still resolved via
        # the action profile, never the raw caller-supplied context.
        blocked, evidence_digest = await self._attestation_gate(
            action=action, forward_context=canonical, resource=resource,
            attestation=attestation,
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
            evidence_digest=evidence_digest)
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
