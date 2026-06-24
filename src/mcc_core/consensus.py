"""Multi-Context Consensus — N-of-M independent signed evaluations.

A single authority source (a policy, a mandate, an approval) is one opinion.
Multi-Context Consensus requires several *independent* evaluators — each its own
trust context with its own Ed25519 key — to agree before authority is granted.
No single evaluator, and no single compromised key, can manufacture a decision.

This is a **pre-token authority step**: consensus produces the verdict that
justifies issuing a decision token. It does not change the four verdicts, the
token, the gate, or the coordinator — the token (and the existing execution
path) only runs once consensus is reached.

Each evaluator emits a signed ``ConsensusVote`` bound to the exact operation
(``action_hash``, ``payload_hash``, ``actor``) within a validity window. The
``ConsensusVerifier`` accepts only votes signed by trusted evaluator keys that
bind to *this* operation, counts the **distinct** evaluators that voted ALLOW,
and applies the policy (e.g. 3-of-3 unanimous, or N-of-M). Fail-closed: a
forged, mismatched, expired, or duplicate-evaluator vote is ignored; a DENY from
any trusted evaluator vetoes; below threshold denies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .core import Verdict
from .signing import SigningKey, hash_action, hash_payload, sha256_hex, verify_token, canonical_bytes

REQUIRED_VOTE_FIELDS = ("evaluator_id", "verdict", "action_hash", "payload_hash",
                        "actor", "nbf", "exp", "iat")


def issue_vote(
    signing_key: SigningKey,
    *,
    evaluator_id: str,
    verdict: "Verdict | str",
    action: str,
    payload: Dict[str, Any],
    actor: str,
    not_before: int,
    not_after: int,
    issued_at: Optional[int] = None,
    reason: str = "",
    resource: Optional[str] = None,
    policy_hash: Optional[str] = None,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """Sign one evaluator's vote, bound to the exact operation. The evaluator's
    ``signing_key`` kid is what the verifier must trust.

    ``resource``, ``policy_hash``, and ``nonce`` are optional extra binding
    dimensions (added to the signed claims only when provided). The mandatory
    execution path binds all of them — the ``nonce`` (one-time) makes the
    evidence itself non-replayable."""
    iat = int(issued_at if issued_at is not None else time.time())
    claims = {
        "vote_id": f"vote-{uuid.uuid4().hex}",
        "evaluator_id": evaluator_id,
        "verdict": Verdict(verdict).value,
        "action_hash": hash_action(action),
        "payload_hash": hash_payload(payload),
        "actor": actor,
        "reason": reason,
        "iat": iat,
        "nbf": int(not_before),
        "exp": int(not_after),
    }
    if resource is not None:
        claims["resource"] = resource
    if policy_hash is not None:
        claims["policy_hash"] = policy_hash
    if nonce is not None:
        claims["nonce"] = nonce
    return signing_key.sign_token(claims)


@dataclass(frozen=True)
class ConsensusPolicy:
    """How many independent evaluators must agree.

    ``threshold`` distinct trusted ALLOW votes are required. ``veto_on_deny``
    (default True) makes any trusted DENY vote decisive. ``on_fail`` is the
    verdict when the threshold is not met (default DENY). ``3-of-3 unanimous``
    is ``ConsensusPolicy(threshold=3)`` paired with three evaluators.
    """

    threshold: int = 3
    veto_on_deny: bool = True
    on_fail: Verdict = Verdict.DENY


@dataclass(frozen=True)
class ConsensusResult:
    verdict: Verdict
    reason: str
    threshold: int
    agreement: int                       # distinct trusted ALLOW evaluators
    allow_evaluators: List[str] = field(default_factory=list)
    deny_evaluators: List[str] = field(default_factory=list)
    rejected_votes: int = 0              # forged/mismatched/expired/duplicate
    consensus_hash: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.verdict in (Verdict.ALLOW, Verdict.CONSTRAIN)

    def summary(self) -> Dict[str, Any]:
        """Compact, signature-coverable record to embed in the token's
        auth_claims for audit (no key material)."""
        return {
            "threshold": self.threshold,
            "agreement": self.agreement,
            "evaluators": list(self.allow_evaluators),
            "consensus_hash": self.consensus_hash,
        }


class ConsensusVerifier:
    """Verifies a set of signed votes against a trust set of evaluator keys and a
    policy. Synchronous (signature verification only); fail-closed throughout."""

    def __init__(self, *, trusted_keys: Dict[str, Ed25519PublicKey], policy: ConsensusPolicy) -> None:
        self.trusted_keys = trusted_keys
        self.policy = policy

    def verify(
        self, votes: Any, *, action: str, payload: Dict[str, Any], actor: str,
        resource: Optional[str] = None, policy_hash: Optional[str] = None,
        nonce: Optional[str] = None, now: Optional[int] = None,
    ) -> ConsensusResult:
        """Verify N-of-M consensus bound to the operation. ``resource``,
        ``policy_hash``, and ``nonce``, when provided, are *required* to match
        on every counted vote — a vote that lacks or mismatches a required
        dimension is rejected. The one-time ``nonce`` makes the evidence
        non-replayable across operations."""
        try:
            return self._verify(votes, action=action, payload=payload, actor=actor,
                                 resource=resource, policy_hash=policy_hash, nonce=nonce, now=now)
        except Exception:
            return ConsensusResult(Verdict.DENY, "CONSENSUS_ERROR: fail-closed",
                                   self.policy.threshold, 0)

    def _verify(self, votes, *, action, payload, actor, resource, policy_hash, nonce, now) -> ConsensusResult:
        ts = int(now if now is not None else time.time())
        expected_action = hash_action(action)
        expected_payload = hash_payload(payload)

        # Map distinct evaluator_id -> verdict, accepting only the first valid
        # vote per evaluator so one evaluator cannot cast multiple ballots.
        allow: Dict[str, bool] = {}
        deny: Dict[str, bool] = {}
        seen: set = set()
        rejected = 0

        if not isinstance(votes, list):
            return ConsensusResult(Verdict.DENY, "MALFORMED_VOTES: expected a list",
                                   self.policy.threshold, 0)

        for vote in votes:
            if not isinstance(vote, dict):
                rejected += 1
                continue
            public_key = self.trusted_keys.get(vote.get("kid"))
            if public_key is None or not verify_token(vote, public_key):
                rejected += 1
                continue
            if any(f not in vote for f in REQUIRED_VOTE_FIELDS):
                rejected += 1
                continue
            # Bind to the exact operation (prevents vote substitution / replay
            # onto another action/payload/actor).
            if (vote.get("action_hash") != expected_action
                    or vote.get("payload_hash") != expected_payload
                    or vote.get("actor") != actor):
                rejected += 1
                continue
            # Extra binding dimensions, required only when the operation supplies
            # them: resource, policy version, and the one-time nonce.
            if (resource is not None and vote.get("resource") != resource) \
                    or (policy_hash is not None and vote.get("policy_hash") != policy_hash) \
                    or (nonce is not None and vote.get("nonce") != nonce):
                rejected += 1
                continue
            nbf, exp = vote.get("nbf"), vote.get("exp")
            if not isinstance(nbf, int) or not isinstance(exp, int) or ts < nbf or ts >= exp:
                rejected += 1
                continue
            evaluator_id = vote.get("evaluator_id")
            if evaluator_id in seen:  # one ballot per evaluator
                rejected += 1
                continue
            seen.add(evaluator_id)
            try:
                verdict = Verdict(vote.get("verdict"))
            except ValueError:
                rejected += 1
                continue
            if verdict == Verdict.DENY:
                deny[evaluator_id] = True
            elif verdict == Verdict.ALLOW:
                allow[evaluator_id] = True
            # ESCALATE / CONSTRAIN votes count as "not ALLOW" toward the threshold.

        allow_ids = sorted(allow)
        deny_ids = sorted(deny)
        consensus_hash = sha256_hex(canonical_bytes(
            {"action_hash": expected_action, "payload_hash": expected_payload,
             "actor": actor, "resource": resource, "policy_hash": policy_hash,
             "nonce": nonce, "evaluators": allow_ids}))

        if self.policy.veto_on_deny and deny_ids:
            return ConsensusResult(Verdict.DENY, f"VETO: {deny_ids[0]} voted DENY",
                                   self.policy.threshold, len(allow_ids), allow_ids, deny_ids,
                                   rejected, consensus_hash)
        if len(allow_ids) >= self.policy.threshold:
            return ConsensusResult(Verdict.ALLOW,
                                   f"CONSENSUS: {len(allow_ids)}/{self.policy.threshold} evaluators agree",
                                   self.policy.threshold, len(allow_ids), allow_ids, deny_ids,
                                   rejected, consensus_hash)
        return ConsensusResult(self.policy.on_fail,
                               f"NO_CONSENSUS: {len(allow_ids)}/{self.policy.threshold} agreed",
                               self.policy.threshold, len(allow_ids), allow_ids, deny_ids,
                               rejected, consensus_hash)
