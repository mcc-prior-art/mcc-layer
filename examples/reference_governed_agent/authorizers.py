"""Execution authorizers: obtain the authorization *material* an executable
verdict needs to run through the governed path.

Governance decides (ALLOW / CONSTRAIN); it does not hand out a bearer token to
execute. A separate authority still has to produce material the gate will verify:
N-of-M evaluator votes bound to a gateway-issued challenge (consensus), or a
signed mandate. This module supplies that material for the reference demo — it is
an *authorization-material provider*, playing the evaluator role.

This is NOT a governance bypass or a re-implementation of the decision engine:

* the agent still evaluates through the gateway and only executes the decision's
  authoritative payload;
* the gateway independently verifies every vote (signature, issuer trust,
  threshold, veto, and binding to action/actor/payload/resource/policy/nonce)
  before the governed executor runs;
* a wrong, missing, duplicate, or unbound vote fails closed at the gate.

In production this role is a real, independent consensus/mandate service; here it
is a deterministic local stand-in so the reference agent can demonstrate a genuine
EXECUTED result end-to-end.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol, Sequence, runtime_checkable

from mcc_core import ProfileRegistry, SigningKey, issue_vote

from mcc_client import ConsensusAuthorization
from mcc_client.client import Authorization
from mcc_client.models import Decision

FAR_FUTURE = 4_000_000_000


@runtime_checkable
class ExecutionAuthorizer(Protocol):
    """Produce authorization material for an executable (ALLOW/CONSTRAIN) decision.

    ``client`` is the SDK (used only to obtain a gateway-issued challenge); the
    authorizer never executes and never bypasses the gate."""

    def material(self, client: Any, decision: Decision) -> Authorization: ...


class ConsensusAuthorizer:
    """Play a fixed pool of independent evaluators and sign N-of-M votes.

    Holds the evaluators' Ed25519 signing keys and the gateway's policy hash. For
    an executable decision it asks the gateway for a one-time challenge, signs
    votes over the decision's **authoritative** payload (the clamped body for
    CONSTRAIN) bound to that challenge's nonce, and returns the material. The
    gateway verifies everything; the agent cannot substitute a body.
    """

    def __init__(
        self,
        evaluators: Sequence[SigningKey],
        *,
        policy_hash: str,
        threshold: Optional[int] = None,
        verdict: str = "ALLOW",
        profiles: Optional[ProfileRegistry] = None,
    ) -> None:
        if not evaluators:
            raise ValueError("ConsensusAuthorizer requires at least one evaluator key")
        self._evaluators = list(evaluators)
        self._policy_hash = policy_hash
        self._threshold = threshold if threshold is not None else len(evaluators)
        self._verdict = verdict
        self._profiles = profiles or ProfileRegistry.default_pilot()

    def material(self, client: Any, decision: Decision) -> Authorization:
        challenge = client.issue_challenge(decision)
        nonce = challenge["nonce"]
        # F1: sign only for the tenant + principal the GATEWAY authenticated
        # and recorded on the challenge -- never for a caller's claim.
        tenant_id = challenge.get("tenant_id")
        principal_id = challenge.get("principal_id")
        if not tenant_id or not principal_id or principal_id != decision.actor_id:
            raise ValueError("challenge is not bound to the authenticated principal of this "
                             "decision; evaluators refuse to vote (fail-closed)")
        canonical = self._profiles.for_action(decision.action).canonical_payload(
            dict(decision.authorized_payload)
        )
        votes: List[Dict[str, Any]] = [
            issue_vote(
                self._evaluators[i], evaluator_id=self._evaluators[i].kid,
                verdict=self._verdict, action=decision.action, payload=canonical,
                actor=decision.actor_id, not_before=0, not_after=FAR_FUTURE,
                resource=decision.resource_id, policy_hash=self._policy_hash, nonce=nonce,
                tenant_id=tenant_id,
            )
            for i in range(self._threshold)
        ]
        return ConsensusAuthorization(
            votes=votes, challenge_id=challenge["challenge_id"], nonce=nonce
        )


__all__ = ["ExecutionAuthorizer", "ConsensusAuthorizer", "FAR_FUTURE"]
