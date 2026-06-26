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
    ChallengeService,
    ConsensusPolicy,
    ConsensusVerifier,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryApprovalRegistry,
    InMemoryChallengeRegistry,
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
        # --- consensus-required mode (Multi-Context Consensus + challenge) ---
        consensus_required: bool = False,
        consensus_threshold: int = 3,
        trusted_evaluators: Optional[Dict[str, Any]] = None,
        challenge_registry: Optional[Any] = None,
        challenge_ttl_seconds: int = 120,
    ) -> None:
        self.executor = executor
        self.authority = authority or default_demo_authority()
        self.policy_hash = policy_hash
        self._op_timeout = op_timeout_seconds
        self.consensus_required = consensus_required
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

        # Consensus wiring — fail closed if required but unconfigured (no silent
        # fallback to a non-consensus path).
        self.challenges: Optional[ChallengeService] = None
        consensus_verifier = None
        if consensus_required:
            if not trusted_evaluators:
                raise ValueError(
                    "consensus_required=True but no trusted_evaluators were configured; "
                    "refusing to start a consensus runtime without a trust set (fail-closed)")
            if consensus_threshold < 1 or consensus_threshold > len(trusted_evaluators):
                raise ValueError(
                    f"consensus_threshold={consensus_threshold} is not satisfiable by "
                    f"{len(trusted_evaluators)} trusted evaluators; fail-closed")
            consensus_verifier = ConsensusVerifier(
                trusted_keys=dict(trusted_evaluators),
                policy=ConsensusPolicy(threshold=consensus_threshold))
            self.challenges = ChallengeService(
                challenge_registry or InMemoryChallengeRegistry(),
                default_ttl_seconds=challenge_ttl_seconds)
            self.consensus_threshold = consensus_threshold

        self.coordinator = EnforcementCoordinator(
            gate=self.gate,
            idempotency=idempotency_registry or InMemoryIdempotencyRegistry(),
            velocity=velocity_registry or InMemoryVelocityRegistry(),
            audit=self.audit, profiles=ProfileRegistry(),
            velocity_limits_for=lambda action: self._velocity_limits,
            approvals=self.approvals,
            consensus_verifier=consensus_verifier, require_consensus=consensus_required,
            challenges=self.challenges, require_challenge=consensus_required)

    # ---- helpers ----

    @staticmethod
    def _now() -> int:
        return int(time.time())

    def _missing_fields(self, p: ProposedAction) -> List[str]:
        d = p.to_dict()
        return [f for f in REQUIRED_FIELDS if not d.get(f)]

    async def _enforce(self, token: Dict[str, Any], action: str, payload: Dict[str, Any],
                       proposed: ProposedAction, *, consensus_votes: Optional[Any] = None):
        """The single governed execution path: gate -> [require_consensus] ->
        [challenge consume] -> (approval consume) -> idempotency -> velocity ->
        audit-before-actuation -> executor. When consensus is required the
        coordinator verifies the N-of-M votes and consumes the challenge before
        anything else runs — consensus is an *additional* predicate, never a
        replacement for the rest of the path."""
        async def executor():
            return await self.executor.execute(
                action, payload, authorization=token, correlation_id=proposed.correlation_id)

        return await self.coordinator.enforce(
            token=token, action=action, payload=payload, executor=executor,
            request_binding={"actor_id": proposed.actor, "resource_id": proposed.resource,
                             "transaction_id": proposed.transaction_id},
            consensus_votes=consensus_votes)

    def _issue_token(self, proposed: ProposedAction, verdict: Verdict,
                     forward_context: Dict[str, Any], constraints: Dict[str, Any],
                     *, audit_ref: Optional[str] = None, approval_id: Optional[str] = None,
                     nonce: Optional[str] = None, challenge_id: Optional[str] = None):
        auth_claims = {"correlation_id": proposed.correlation_id}
        if approval_id:
            auth_claims["approval_id"] = approval_id
        if challenge_id:
            auth_claims["challenge_id"] = challenge_id
        return self.engine.issue_token(
            verdict=verdict.value, subject=proposed.actor, action=proposed.action,
            payload=forward_context, constraints=constraints,
            nonce=nonce if nonce is not None else proposed.nonce,
            transaction_id=proposed.transaction_id, idempotency_key=proposed.idempotency_key,
            actor_id=proposed.actor, resource_id=proposed.resource,
            auth_claims=auth_claims, audit_ref=audit_ref)

    # ---- consensus: the gateway issues the challenge (agent never controls it) ----

    async def issue_challenge(self, proposed: ProposedAction, *,
                              payload: Optional[Dict[str, Any]] = None):
        """Gateway-issued, one-time, nonce-bound challenge for this proposal.
        Bound to action/actor/resource/payload_hash/policy_hash. The agent does
        not call this and cannot forge it. Only available in consensus mode.

        ``payload`` defaults to the proposal's payload. The CONSTRAIN re-consensus
        path (Path B) passes the *authority-constrained* body here, so the second
        challenge binds to the clamped payload — a challenge issued for the
        original (over-cap) body can never authorize the constrained execution."""
        if self.challenges is None:
            raise RuntimeError("challenge service not configured (consensus_required=False)")
        body = proposed.payload if payload is None else payload
        return await self.challenges.issue(
            action=proposed.action, actor=proposed.actor, resource=proposed.resource,
            payload_hash=hash_payload(body), policy_hash=self.policy_hash)

    # ---- the public submit path ----

    async def submit(self, proposed: ProposedAction, *, challenge: Optional[Any] = None,
                     votes: Optional[Any] = None) -> GovernedResult:
        """Submit a proposed action. Returns a non-executing result for DENY /
        ESCALATE / any fail-closed condition; executes once (through the gate)
        for ALLOW / CONSTRAIN.

        In consensus mode a gateway-issued ``challenge`` and N-of-M evaluator
        ``votes`` are required: the coordinator verifies the consensus and
        consumes the challenge as part of the same governed path. Missing
        challenge/votes fail closed."""
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
            # the one governed path. Consensus, when required, is enforced inside
            # that same path (it does not bypass authority, gate, nonce, idem,
            # velocity, or audit).
            forward = dict(decision.forward_context or proposed.payload)
            if self.consensus_required:
                if challenge is None or not votes:
                    return self._blocked(
                        "DENY", proposed,
                        "consensus required: missing gateway challenge or evaluator votes; fail-closed")
                if verdict_value == "CONSTRAIN":
                    # Path B: the consensus we hold was taken over the ORIGINAL
                    # (over-cap) body. It does NOT authorize the clamped body, and
                    # the runtime must not let it: the challenge/votes bind to the
                    # original payload_hash while the token would carry the
                    # constrained one — the coordinator would reject the mismatch
                    # anyway. Rather than silently fail closed, surface the
                    # authority-constrained body and require a FRESH challenge +
                    # fresh consensus bound to it (see execute_constrained). The
                    # original payload is never executed.
                    return GovernedResult(
                        verdict="CONSTRAIN", executed=False, status="RECONSENSUS_REQUIRED",
                        reason=("authority constrained the request; the original consensus does "
                                "not authorize the constrained body — fresh consensus required"),
                        proposed_payload=dict(proposed.payload), action=proposed.action,
                        authorized_payload=dict(forward), applied_changes=list(decision.applied_changes or []),
                        correlation_id=proposed.correlation_id, transaction_id=proposed.transaction_id)
                token = self._issue_token(proposed, verdict, forward, decision.constraints,
                                          nonce=challenge.nonce, challenge_id=challenge.challenge_id)
                result = await self._enforce(token, proposed.action, forward, proposed,
                                             consensus_votes=votes)
            else:
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

    async def execute_with_approval(self, proposed: ProposedAction, approval_id: str, *,
                                    challenge: Optional[Any] = None,
                                    votes: Optional[Any] = None) -> GovernedResult:
        """Execute an ESCALATEd action against a granted approval. The coordinator
        consumes the approval **single-use**, bound to action/transaction/payload;
        forged, expired, mismatched, or replayed approvals fail closed here.

        Path A (consensus + ESCALATE): when consensus is required, the final
        execution must carry BOTH a valid single-use approval AND a valid N-of-M
        consensus bound to a gateway-issued ``challenge``. The two predicates are
        independent and additive — the approval does not bypass consensus, the
        consensus does not bypass the approval, and the token names both. Missing
        consensus evidence fails closed here (the approval alone cannot execute)."""
        try:
            forward = dict(proposed.payload)
            if self.consensus_required:
                if challenge is None or not votes:
                    # An approved ESCALATE still cannot execute without consensus.
                    return GovernedResult(
                        verdict="ESCALATE", executed=False, status="BLOCKED",
                        reason=("consensus required: approved ESCALATE still needs a gateway "
                                "challenge and N-of-M votes; fail-closed"),
                        proposed_payload=dict(proposed.payload), action=proposed.action,
                        correlation_id=proposed.correlation_id,
                        transaction_id=proposed.transaction_id, approval_request_id=approval_id)
                token = self._issue_token(
                    proposed, Verdict.ALLOW, forward, {}, approval_id=approval_id,
                    nonce=challenge.nonce, challenge_id=challenge.challenge_id)
                result = await self._enforce(token, proposed.action, forward, proposed,
                                             consensus_votes=votes)
            else:
                token = self._issue_token(proposed, Verdict.ALLOW, forward, {}, approval_id=approval_id)
                result = await self._enforce(token, proposed.action, forward, proposed)
            out = self._from_actuation("ALLOW", proposed, forward, [], result)
            if not out.executed:
                # Surface the approval/consensus rejection reason explicitly.
                return GovernedResult(
                    verdict="ESCALATE", executed=False, status="BLOCKED", reason=out.reason,
                    proposed_payload=dict(proposed.payload), action=proposed.action,
                    correlation_id=proposed.correlation_id,
                    transaction_id=proposed.transaction_id, approval_request_id=approval_id)
            return out
        except Exception as exc:  # noqa: BLE001
            return self._blocked("ERROR", proposed, f"approval execution error; fail-closed: {type(exc).__name__}")

    # ---- CONSTRAIN re-consensus (Path B) ----

    async def execute_constrained(self, proposed: ProposedAction,
                                  constrained_payload: Dict[str, Any], *,
                                  challenge: Optional[Any] = None,
                                  votes: Optional[Any] = None) -> GovernedResult:
        """Execute the authority-constrained body against FRESH consensus.

        Path B (consensus + CONSTRAIN): the first round produced a CONSTRAIN over
        the original (over-cap) request; ``submit`` exposed the clamped body but
        refused to execute it on the strength of the original consensus. Here the
        gateway has issued a NEW challenge bound to the constrained body and the
        evaluators have signed NEW votes over it; this method re-evaluates
        authority on the constrained body and runs the one governed path.

        Fail-closed guards specific to this path:

        * Authority is re-run on ``constrained_payload``. It must resolve to a
          clean ALLOW with the SAME body (no further rewrite). That is what
          forbids passing the original over-cap body here: it would re-constrain
          (forward != input) and be refused — the original amount never executes.
        * The token is signed over the constrained body, so its payload-hash binds
          the challenge consume and the consensus verify to exactly that body.
          Original votes / the original challenge bind to the original payload-hash
          and are rejected by the coordinator's mismatch checks.
        """
        try:
            if not self.consensus_required:
                return self._blocked(
                    "ERROR", proposed,
                    "execute_constrained is a consensus-mode path; fail-closed")
            if challenge is None or not votes:
                return self._blocked(
                    "DENY", proposed,
                    "consensus required: missing gateway challenge or evaluator votes; fail-closed")

            decision = self.authority.evaluate(
                identity=proposed.actor, action=proposed.action,
                context=constrained_payload, now=self._now())
            verdict = getattr(decision, "verdict", None)
            verdict_value = getattr(verdict, "value", None)
            if verdict_value not in VERDICTS:
                return self._blocked("ERROR", proposed, f"unknown verdict {verdict_value!r}; fail-closed")
            if verdict_value != "ALLOW":
                # The constrained body must already be within bounds. A residual
                # CONSTRAIN/DENY/ESCALATE here means the caller did not supply the
                # authority-clamped body (e.g. resubmitted the original) -> refuse.
                return self._blocked(
                    verdict_value, proposed,
                    f"constrained body is not already compliant (verdict={verdict_value}); fail-closed")
            forward = dict(decision.forward_context or {})
            if forward != dict(constrained_payload) or decision.applied_changes:
                return self._blocked(
                    "DENY", proposed,
                    "constrained body would be rewritten again; not the authorized constrained body; fail-closed")

            token = self._issue_token(
                proposed, Verdict.CONSTRAIN, forward, decision.constraints,
                nonce=challenge.nonce, challenge_id=challenge.challenge_id)
            result = await self._enforce(token, proposed.action, forward, proposed,
                                         consensus_votes=votes)
            return self._from_actuation("CONSTRAIN", proposed, forward, [], result)
        except Exception as exc:  # noqa: BLE001
            return self._blocked("ERROR", proposed, f"constrained execution error; fail-closed: {type(exc).__name__}")

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
