"""Enforcement coordinator: the explicit, fail-closed execution order.

One place owns the sequence that turns a verified decision token into an
executed operation, so the ordering cannot drift:

    a. validate the decision token and its exact payload/operation binding
    b. consume the one-time nonce
    c. atomically admit the logical operation (idempotency key bound to the
       EXACT action + resource + canonical payload_hash — not payload_hash
       alone; a mismatch on any of the three is a BINDING_CONFLICT)
    d. atomically reserve velocity / aggregate capacity
    e. durably record the pre-enforcement decision (audit-before-actuation)
    f. durably commit dispatch ownership of the logical operation — the
       point of no return; nothing after this may release the key back to
       an admittable state
    g. execute
    h. durably record the outcome: EXECUTED on confirmed success, UNKNOWN on
       any exception, timeout, or failure to durably persist success

Steps (a) and (b) are the execution gate. Any indeterminate infrastructure
failure strictly *before* step (f) — a registry that cannot admit, an audit
write that cannot be confirmed, a velocity reservation that fails — fails
closed: the operation does not run, and any capacity/logical-operation
reservation already held is released (safe, because no external call could
possibly have been attempted yet). Once step (f) has durably committed,
failure is never again treated as "safe to release" — see
``docs/DURABLE_OPERATION_SAFETY.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional

from .audit import AuditLog
from .core import Verdict
from .idempotency import ReserveStatus
from .profiles import ProfileRegistry
from .signing import hash_document
from .trusted_time import (
    LocalTimeSource,
    TimeTrustError,
    TrustedTimeSource,
    _validate_positive_finite,
)
from .velocity import VelocityLimit, VelocityOutcome


class ActuationStatus(str, Enum):
    EXECUTED = "EXECUTED"        # ran and durably confirmed
    BLOCKED = "BLOCKED"          # refused before dispatch commitment (fail-closed; safe to retry)
    EXECUTION_FAILED = "EXECUTION_FAILED"  # outcome indeterminate (UNKNOWN); ownership
    # retained, NOT freed for retry -- the external side effect may have happened. Resolving
    # this requires independent positive evidence (reconciliation), never a fresh dispatch.


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
        approvals: Optional[Any] = None,
        consensus_verifier: Optional[Any] = None,
        require_consensus: bool = False,
        challenges: Optional[Any] = None,
        require_challenge: bool = False,
        time_source: Optional[TrustedTimeSource] = None,
        max_dispatch_staleness_seconds: Optional[float] = None,
    ) -> None:
        self.gate = gate
        self.idempotency = idempotency
        self.velocity = velocity
        self.audit = audit
        self.profiles = profiles or ProfileRegistry()
        self.velocity_limits_for = velocity_limits_for or (lambda action: [])
        # Clock-skew hardening (PR #122 round 5): bounds the real-time gap
        # between the trusted `now` this call authorized gate/consensus/
        # challenge/approval AGAINST (resolved once, near the top of
        # ``enforce()``) and the point of durable dispatch commit (step f)
        # below. Every authorization check above is correctly evaluated
        # against ONE consistent, trusted timestamp -- but a slow
        # idempotency/velocity/audit backend between that resolution and
        # actual dispatch could otherwise let a token/mandate/approval that
        # was valid at the moment it was checked reach actuation long after
        # it would have genuinely expired by true wall-clock time. This
        # does NOT re-verify or re-consume the token/mandate/approval/
        # challenge (that would mean a second consumption of a single-use
        # grant) -- it only re-samples the SAME trusted time source and
        # measures elapsed real time, failing closed (and releasing
        # whatever capacity/logical-operation reservation is still safely
        # releasable -- see ``_release``) if that gap is excessive. ``None``
        # (default) disables the check entirely, matching this class's
        # pre-existing behavior exactly.
        #
        # PR #122 round 6, Finding 2: validated here (not just at the
        # env-parsing boundary in gateway/governance_api.py) so EVERY
        # construction path -- direct, test, or env-driven -- is protected.
        # A bare ``float("nan")``/``float("inf")`` parses without raising,
        # and ``staleness > nan`` and ``staleness > inf`` are BOTH always
        # False in Python -- either would SILENTLY DISABLE this protection
        # entirely (a configuration that looks "on" but never fires) rather
        # than refusing to start. Reuses the same helper RedisTimeSource
        # already uses for its own threshold validation (see
        # ``trusted_time.py``) -- one validated-positive-finite-seconds
        # contract across every clock-trust threshold in this codebase.
        self.max_dispatch_staleness_seconds: Optional[float] = (
            None if max_dispatch_staleness_seconds is None
            else _validate_positive_finite(
                max_dispatch_staleness_seconds, "max_dispatch_staleness_seconds"
            )
        )
        # Clock-skew hardening (PR #122 round 4): the trusted-time source
        # this coordinator resolves ITS OWN `now` from, for its internal
        # fan-out to consensus/challenge verification below, WHEN THE
        # CALLER passes no explicit `now` (the production case -- see
        # tests/test_velocity.py's static guard, which forbids
        # governance_service.py et al. from ever passing an explicit now=
        # into .enforce()). Deliberately NEVER substituted for the `now`
        # passed to VelocityRegistry.reserve()/release() below, which keeps
        # using the caller's own (always-None-in-production) `now`
        # unchanged, so InMemoryVelocityRegistry's deliberate
        # time.monotonic() semantics are untouched -- see that same guard's
        # rationale. Defaults to this process's own clock (pre-existing
        # behavior) when not configured.
        self.time_source: TrustedTimeSource = time_source or LocalTimeSource()
        # Mandatory Multi-Context Consensus: when ``require_consensus`` is set, no
        # action reaches actuation unless a valid N-of-M consensus, bound to the
        # token's exact action/actor/payload/resource/policy_hash/nonce, is
        # supplied. Missing or invalid consensus fails closed before any
        # reservation or execution.
        self.consensus_verifier = consensus_verifier
        self.require_consensus = require_consensus
        # Optional consensus-challenge consumption: a token issued against a
        # gateway-issued challenge names a challenge_id in its auth_claims; the
        # challenge is consumed single-use here, bound to the exact operation
        # (action/actor/resource/payload_hash/policy_hash/nonce). Unknown,
        # expired, reused, or mismatched challenges fail closed before execution.
        self.challenges = challenges
        self.require_challenge = require_challenge
        # Optional actuation-time revocation re-check: a mandate revoked between
        # decision and execution must still block. When configured, a token that
        # names a mandate_id is checked here; REVOKED or an unconfirmable status
        # fails closed.
        self.revocation_registry = revocation_registry
        # Optional human-approval consumption: a token issued under an ESCALATE
        # approval names an approval_id in its auth_claims; the approval is
        # consumed single-use here, bound to the exact operation. Replay,
        # mismatch, or backend failure fails closed before execution.
        self.approvals = approvals

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
        consensus_votes: Optional[Any] = None,
        evidence: Optional[Dict[str, Any]] = None,
        now: Optional[int] = None,
    ) -> ActuationResult:
        # Clock-skew hardening (PR #122 round 4): resolve ONE trusted `now`
        # for this call's gate/consensus/challenge/approval checks below --
        # never for VelocityRegistry.reserve()/release(), which keeps using
        # the raw, unresolved `now` parameter exactly as before (see
        # __init__'s time_source comment / tests/test_velocity.py's static
        # guard). ``now`` is always None from every production caller
        # today (governance_service.py never passes it -- same guard), so
        # this always resolves via ``self.time_source`` in production;
        # fails closed (BLOCKED) rather than falling back to an unchecked
        # local clock.
        now_was_explicit = now is not None
        if now_was_explicit:
            trusted_now = int(now)
        else:
            try:
                trusted_now = await self.time_source.now()
            except TimeTrustError as exc:
                reason = f"{exc.reason}: {exc.detail}"
                self._record(kind="actuation_rejected", action=action, reason=reason)
                return ActuationResult(ActuationStatus.BLOCKED, reason)

        # (a) validate token + operation binding + PR-3 evidence-bound
        # execution ticket binding, (b) consume nonce. ``evidence`` is the
        # exact raw evidence artifact for this operation (when the caller
        # has one); the gate itself decides whether the token even requires
        # one -- passing None here for a non-evidence-bound token is a no-op.
        gate_result = await self.gate.verify(
            token, action=action, payload=payload, binding=request_binding,
            evidence=evidence, now=trusted_now,
        )
        if not gate_result.allowed:
            self._record(kind="actuation_rejected", action=action, reason=gate_result.reason)
            return ActuationResult(ActuationStatus.BLOCKED, gate_result.reason)

        # Round 25 remediation — mandatory logical-operation identity. A
        # valid, signed, executable token that carries no usable
        # idempotency_key must never reach durable admission, dispatch
        # commitment, or the executor: "if idem_key:" used to make every
        # downstream durable-safety step OPTIONAL, so a token issued with no
        # idempotency_key (or "" / whitespace) could actuate with zero
        # replay/duplicate protection -- an execution contract violation, not
        # a legacy/optional mode. This is checked here, unconditionally,
        # BEFORE any consensus challenge consumption, approval consumption,
        # durable admission, velocity reservation, audit-before-actuation, or
        # executor invocation -- the identity is never silently generated;
        # a missing one fails closed. See docs/DURABLE_OPERATION_SAFETY.md.
        idem_key = token.get("idempotency_key")
        if not isinstance(idem_key, str) or not idem_key.strip():
            reason = ("MISSING_LOGICAL_OPERATION_ID: a valid, non-empty "
                      "idempotency_key is required for protected execution; fail-closed")
            self._record(kind="actuation_rejected", action=action, reason=reason)
            return ActuationResult(ActuationStatus.BLOCKED, reason)

        # PR #105 remediation — mandatory tenant/security-domain scoping of
        # durable operation identity. The raw idempotency_key alone is NOT a
        # sufficient admission identity: two different tenants may
        # legitimately use the identical logical_operation_id (and, for the
        # identical action/resource/payload, the identical binding too), so
        # durable identity must be the PAIR (tenant_id, idempotency_key), not
        # idempotency_key in isolation. tenant_id is a signed token claim
        # (like idempotency_key) -- it is established by the trusted
        # server-side caller BEFORE token issuance (GovernanceService /
        # GovernancePipeline resolve it from authenticated context, never
        # from a model-controlled payload field) and is never generated,
        # inferred from actor/payload/logical_operation_id/binding, or
        # defaulted here. Checked unconditionally, immediately alongside the
        # idempotency_key check, before any consensus/challenge/approval
        # consumption, durable admission, velocity reservation,
        # audit-before-actuation, or executor invocation.
        tenant_id = token.get("tenant_id")
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            reason = ("MISSING_TENANT_IDENTITY: a valid, non-empty tenant_id "
                      "is required for protected execution; fail-closed")
            self._record(kind="actuation_rejected", action=action, reason=reason)
            return ActuationResult(ActuationStatus.BLOCKED, reason)

        # Mandatory Multi-Context Consensus — no actuation without a valid N-of-M
        # authorization bound to this exact (now gate-verified) token: action,
        # actor, payload, resource, policy hash, and one-time nonce. Runs before
        # any idempotency/velocity reservation or execution.
        if self.require_consensus:
            result = None
            if self.consensus_verifier is not None and consensus_votes is not None:
                result = self.consensus_verifier.verify(
                    consensus_votes, action=action, payload=payload,
                    actor=token.get("actor_id"), resource=token.get("resource_id"),
                    policy_hash=token.get("policy_hash"), nonce=token.get("nonce"), now=trusted_now)
            if result is None or result.verdict != Verdict.ALLOW:
                reason = ("consensus required: " +
                          (result.reason if result is not None else
                           "no consensus evidence supplied; fail-closed"))
                self._record(kind="actuation_rejected", action=action, reason=reason)
                return ActuationResult(ActuationStatus.BLOCKED, reason)
            self._record(kind="consensus_verified", action=action,
                         evaluators=result.allow_evaluators, consensus_hash=result.consensus_hash)

        # Consume the gateway-issued consensus challenge exactly once, bound to
        # this exact (gate-verified) operation. The one-time nonce came from the
        # challenge, so consuming it here makes the whole evidence package
        # single-use at the actuation boundary — before any reservation or
        # execution. Unknown/expired/reused/mismatched fails closed.
        challenge_id = (token.get("auth_claims") or {}).get("challenge_id")
        if self.require_challenge and not (self.challenges is not None and challenge_id):
            reason = "challenge required: no gateway-issued consensus challenge supplied; fail-closed"
            self._record(kind="actuation_rejected", action=action, reason=reason)
            return ActuationResult(ActuationStatus.BLOCKED, reason)
        if self.challenges is not None and challenge_id:
            consumed = await self.challenges.consume(
                challenge_id,
                action=action,
                actor=token.get("actor_id"),
                resource=token.get("resource_id"),
                payload_hash=token.get("payload_hash"),
                policy_hash=token.get("policy_hash"),
                nonce=token.get("nonce"),
                now=trusted_now,
            )
            if not consumed.ok:
                reason = f"challenge {challenge_id} not consumable: {consumed.reason}"
                self._record(kind="actuation_rejected", action=action, reason=reason)
                return ActuationResult(ActuationStatus.BLOCKED, reason)
            self._record(kind="challenge_consumed", action=action, challenge_id=challenge_id)

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

        # Single-use approval consumption (ESCALATE loop): consume the approval
        # bound to this exact operation before doing anything else stateful.
        approval_id = (token.get("auth_claims") or {}).get("approval_id")
        if self.approvals is not None and approval_id:
            consumed = await self.approvals.consume(
                approval_id,
                action_hash=token.get("action_hash"),
                transaction_id=token.get("transaction_id"),
                payload_hash=token.get("payload_hash"),
                now=trusted_now,
            )
            if not consumed.ok:
                reason = f"approval {approval_id} not consumable: {consumed.reason}"
                self._record(kind="actuation_rejected", action=action, reason=reason)
                return ActuationResult(ActuationStatus.BLOCKED, reason)

        # Authoritative operation identity comes from the (now-verified) token
        # (``idem_key`` was already validated as present/non-empty above).
        # The logical-operation binding is the exact (action, resource,
        # payload_hash) triple -- NOT payload_hash alone -- so the same
        # idempotency_key can never be silently reused for a different
        # action or a different resource; either is a BINDING_CONFLICT,
        # rejected before any reservation or execution.
        payload_hash = str(token.get("payload_hash", ""))
        actor_id = token.get("actor_id")
        resource_id = token.get("resource_id")
        policy_scope = token.get("policy_id")
        binding_ref = hash_document({
            "action": action, "resource": resource_id, "payload_hash": payload_hash,
        })
        idem_fence: Optional[str] = None

        # (c) atomically admit the logical operation. Structurally mandatory
        # now that idem_key is guaranteed present/non-empty above -- a
        # protected execution can never reach the executor without first
        # successfully reserving this logical operation.
        reserved = await self.idempotency.reserve(idem_key, tenant_id=tenant_id, binding=binding_ref)
        if not reserved.ok:
            self._record(
                kind="idempotency_block",
                action=action,
                idempotency_key=idem_key,
                status=reserved.status.value,
                reason=reserved.reason,
            )
            # ERROR/BINDING_CONFLICT are fail-closed infra/contract outcomes;
            # DUPLICATE_* (INFLIGHT/UNKNOWN/EXECUTED) are correct denials --
            # in particular DUPLICATE_UNKNOWN means a fresh, independently
            # valid authorization for this same logical operation must NOT
            # trigger a second actuation while the prior attempt's outcome
            # is unresolved (AUTHORIZED != SAFE_TO_ACTUATE).
            return ActuationResult(ActuationStatus.BLOCKED, reason=reserved.reason)
        idem_fence = reserved.fence

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
                # Pre-dispatch: no external call has been attempted, so
                # releasing everything reserved (including the logical
                # operation) back to an admittable state is safe.
                await self._release(reserved_limits, descriptor, idem_key, tenant_id, idem_fence, now)
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
        # ``evidence_digest`` (PR-3), when the token carries one, is already
        # proven above (gate verification) to match the exact evidence
        # artifact just presented -- recording the digest here (never the
        # attestation itself or its semantic claims) completes the audit
        # chain: signed attestation -> evidence_digest -> signed execution
        # authority -> this pre_actuation record -> the side effect below.
        pre_ref = self._record(
            kind="pre_actuation",
            action=action,
            actor_id=actor_id,
            resource_id=resource_id,
            transaction_id=token.get("transaction_id"),
            idempotency_key=idem_key,
            payload_hash=payload_hash,
            operation_binding=binding_ref,
            policy_hash=token.get("policy_hash"),
            decision=token.get("decision"),
            evidence_digest=token.get("evidence_digest"),
        )
        if pre_ref is None:
            # Cannot confirm the pre-actuation record -> indeterminate before
            # execution -> fail closed and release everything reserved. Still
            # pre-dispatch (the durable dispatch boundary is the NEXT step),
            # so releasing is safe -- zero actuator calls have occurred.
            await self._release(reserved_limits, descriptor, idem_key, tenant_id, idem_fence, now)
            return ActuationResult(
                ActuationStatus.BLOCKED, "audit-before-actuation failed; fail-closed"
            )

        # Clock-skew hardening (PR #122 round 5, hardened round 6): the LAST
        # safe point to check staleness -- still strictly before step (f)'s
        # point of no return, so releasing is still safe, and as close to
        # actual dispatch as this method gets. Every authorization check
        # above (gate/consensus/challenge/approval) was evaluated against
        # ``trusted_now``, resolved once near the top of this call; the
        # idempotency reserve, velocity reserve, and audit write just above
        # may each have taken real wall-clock time (a slow backend,
        # contention, a network hiccup). Skipped entirely when this call
        # resolved its own trusted ``now`` (``now_was_explicit`` is False
        # guards every branch below) -- a caller that supplied an explicit
        # ``now`` (tests, or any future direct caller) is using its own
        # clock contract and is not second-guessed here.
        if not now_was_explicit:
            try:
                dispatch_now = await self.time_source.now()
            except TimeTrustError as exc:
                await self._release(reserved_limits, descriptor, idem_key, tenant_id, idem_fence, now)
                reason = f"{exc.reason}: {exc.detail}"
                self._record(kind="actuation_rejected", action=action, reason=reason)
                return ActuationResult(ActuationStatus.BLOCKED, reason)

            # PR #122 round 6, Finding 1: re-check the TOKEN'S OWN signed
            # exp/nbf against this fresh ``dispatch_now`` -- UNCONDITIONALLY,
            # never gated behind ``max_dispatch_staleness_seconds``. This is
            # a plain comparison against claims the gate already
            # cryptographically verified at the top of this call (``ts >=
            # exp`` / ``ts < nbf`` in ``ExecutionGate.verify()``); it never
            # re-verifies the signature, never re-consumes the nonce, and
            # never consults the gate again. Why it is necessary even with
            # the elapsed-gap check below: that check only bounds the GAP
            # against a fixed, configured threshold (default 30s) -- it says
            # nothing about the token's OWN, possibly much shorter, TTL. A
            # token issued with a 5-second TTL that is still "fresh" by a
            # generous 30-second staleness bound has nonetheless, by true
            # wall-clock time, already expired by the time dispatch reaches
            # this point -- the gap-only check cannot see that, because it
            # was never comparing against the token's own validity window in
            # the first place. Confirmed via reproduction before this fix:
            # see tests/test_dispatch_staleness.py's
            # test_token_expired_before_dispatch_blocks_even_within_staleness_bound.
            exp = token.get("exp")
            if isinstance(exp, int) and dispatch_now >= exp:
                await self._release(reserved_limits, descriptor, idem_key, tenant_id, idem_fence, now)
                reason = (
                    f"TOKEN_EXPIRED_BEFORE_DISPATCH: token exp={exp} has passed by dispatch "
                    f"(dispatch_now={dispatch_now}), even though it was valid when the gate "
                    f"verified it (trusted_now={trusted_now}); fail-closed"
                )
                self._record(kind="actuation_rejected", action=action, reason=reason)
                return ActuationResult(ActuationStatus.BLOCKED, reason)
            nbf = token.get("nbf")
            if isinstance(nbf, int) and dispatch_now < nbf:
                await self._release(reserved_limits, descriptor, idem_key, tenant_id, idem_fence, now)
                reason = (
                    f"TOKEN_NOT_YET_VALID_AT_DISPATCH: token nbf={nbf} is still in the future "
                    f"at dispatch (dispatch_now={dispatch_now}); fail-closed"
                )
                self._record(kind="actuation_rejected", action=action, reason=reason)
                return ActuationResult(ActuationStatus.BLOCKED, reason)

            # The pre-existing elapsed-gap check: bounds real time spent in
            # the idempotency/velocity/audit steps above against a fixed,
            # configured threshold -- a SEPARATE, opt-in, defense-in-depth
            # control from the unconditional token-expiry recheck above, not
            # a replacement for it. Reuses the SAME ``dispatch_now`` sample
            # (no second round trip to the time source).
            if self.max_dispatch_staleness_seconds is not None:
                staleness = dispatch_now - trusted_now
                if staleness > self.max_dispatch_staleness_seconds:
                    await self._release(reserved_limits, descriptor, idem_key, tenant_id, idem_fence, now)
                    reason = (
                        f"AUTHORIZATION_STALE: {staleness}s elapsed between authorization "
                        f"(trusted_now={trusted_now}) and dispatch (dispatch_now={dispatch_now}), "
                        f"exceeding the {self.max_dispatch_staleness_seconds}s bound; fail-closed"
                    )
                    self._record(kind="actuation_rejected", action=action, reason=reason)
                    return ActuationResult(ActuationStatus.BLOCKED, reason)

        # (f) durably commit dispatch ownership -- THE point of no return.
        # From here on, no failure (exception, timeout, disconnect, process
        # crash) may release the logical operation for another admission:
        # the external side effect may already be in flight or complete by
        # the time any failure is observed. If this commitment itself cannot
        # be confirmed, nothing has been dispatched yet, so it is still safe
        # to release and fail closed.
        committed = await self.idempotency.commit_dispatch(idem_key, tenant_id=tenant_id, fence=idem_fence)
        if not committed:
            await self._release(reserved_limits, descriptor, idem_key, tenant_id, idem_fence, now)
            self._record(
                kind="actuation_rejected", action=action, idempotency_key=idem_key,
                reason="durable dispatch ownership commit failed; fail-closed",
            )
            return ActuationResult(
                ActuationStatus.BLOCKED, "durable dispatch ownership commit failed; fail-closed",
            )

        # (g) execute.
        try:
            execution = await executor()
        except Exception as exc:  # noqa: BLE001 - any executor failure is indeterminate
            # Durable dispatch ownership was already committed: the external
            # call may have been sent (or even completed) despite the raise.
            # The operation moves to UNKNOWN -- NOT released, NOT retryable --
            # and stays there until independently verified evidence
            # (reconciliation) proves the outcome one way or the other.
            await self.idempotency.mark_unknown(idem_key, tenant_id=tenant_id, fence=idem_fence)
            self._record(
                kind="actuation_unknown",
                action=action,
                idempotency_key=idem_key,
                audit_ref=pre_ref,
                reason=f"{type(exc).__name__}: {exc}",
            )
            return ActuationResult(
                ActuationStatus.EXECUTION_FAILED,
                "execution outcome unknown after dispatch; ownership retained pending reconciliation",
                audit_ref=pre_ref,
            )

        # (h) durably record the outcome. Only a CONFIRMED durable EXECUTED
        # write is reported as EXECUTED -- if the executor succeeded but this
        # registry cannot durably persist that fact, the honest answer is
        # UNKNOWN (never a false EXECUTED, and never retry-eligible either).
        result_ref = hash_document({"execution": _safe_execution_marker(execution)})
        finalized = await self.idempotency.mark_executed(
            idem_key, tenant_id=tenant_id, fence=idem_fence, binding=binding_ref, result_ref=result_ref,
        )
        if not finalized:
            await self.idempotency.mark_unknown(idem_key, tenant_id=tenant_id, fence=idem_fence)
            self._record(
                kind="actuation_unknown",
                action=action,
                idempotency_key=idem_key,
                audit_ref=pre_ref,
                reason="durable EXECUTED persistence failed after external success",
            )
            return ActuationResult(
                ActuationStatus.EXECUTION_FAILED,
                "execution succeeded but durable EXECUTED persistence failed; outcome UNKNOWN",
                audit_ref=pre_ref,
            )

        self._record(
            kind="actuation_result",
            action=action,
            idempotency_key=idem_key,
            audit_ref=pre_ref,
            status="EXECUTED",
        )

        return ActuationResult(
            ActuationStatus.EXECUTED, "executed", decision=Verdict(token.get("decision")),
            audit_ref=pre_ref, execution=execution,
        )

    async def _release(self, limits, descriptor, idem_key, tenant_id, idem_fence, now) -> None:
        """Release capacity reserved so far. Only ever called BEFORE the
        durable dispatch boundary (step f) -- releasing the logical
        operation here is safe because no external call could have been
        attempted yet."""
        for limit in limits:
            await self.velocity.release(limit, descriptor, now=now)
        if idem_fence is not None:
            await self.idempotency.release(idem_key, tenant_id=tenant_id, fence=idem_fence)


def _safe_execution_marker(execution: Any) -> Any:
    """A JSON-hashable marker for the execution result, used only to bind
    the durable EXECUTED record to *this* outcome for reconciliation/status
    purposes -- never the raw result itself (which may carry upstream
    response content out of scope for the audit chain)."""
    if execution is None or isinstance(execution, (str, int, float, bool)):
        return execution
    if isinstance(execution, dict):
        return {str(k): _safe_execution_marker(v) for k, v in sorted(execution.items(), key=lambda kv: str(kv[0]))}
    if isinstance(execution, (list, tuple)):
        return [_safe_execution_marker(v) for v in execution]
    return repr(execution)
