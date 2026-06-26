"""Independent evaluator pool for the consensus-required governed path.

Multi-Context Consensus requires N-of-M **independent** evaluators — each its
own trust context with its own Ed25519 key — to sign a vote bound to the exact
operation. This module models that pool. It is deliberately separate from the
agent: **the agent never signs a vote and never controls the challenge**, so it
cannot self-authorize consensus.

Votes are produced with the real ``mcc_core.issue_vote`` and verified by the
real ``ConsensusVerifier`` inside the coordinator — no demo-only verifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from mcc_core import SigningKey, issue_vote
from mcc_core.challenge import ChallengeRecord

FAR_FUTURE = 4_000_000_000


@dataclass
class Evaluator:
    evaluator_id: str
    key: SigningKey


class EvaluatorPool:
    """A fixed set of independent, trusted evaluators. The gateway issues a
    challenge; each evaluator signs a vote bound to that challenge's nonce and
    the operation. The pool exposes only public keys to the trust set."""

    def __init__(self, n: int = 3) -> None:
        self.evaluators = [Evaluator(f"eval-{i}", SigningKey.generate(f"eval-{i}")) for i in range(n)]

    def trusted_keys(self) -> Dict[str, Any]:
        return {e.key.kid: e.key.public_key() for e in self.evaluators}

    def sign(
        self,
        evaluator: Evaluator,
        challenge: ChallengeRecord,
        *,
        action: str,
        payload: Dict[str, Any],
        actor: str,
        resource: Optional[str],
        policy_hash: Optional[str],
        verdict: str = "ALLOW",
        not_before: int = 0,
        not_after: int = FAR_FUTURE,
        issued_at: Optional[int] = None,
        nonce: Optional[str] = None,
        evaluator_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """One evaluator's signed vote, bound (by default) to *this* challenge's
        nonce and the operation. Parameters let tests craft adversarial votes
        (wrong nonce/action/payload/actor, expired window, veto, duplicate id)."""
        return issue_vote(
            evaluator.key,
            evaluator_id=evaluator_id or evaluator.evaluator_id,
            verdict=verdict, action=action, payload=payload, actor=actor,
            not_before=not_before, not_after=not_after, issued_at=issued_at,
            resource=resource, policy_hash=policy_hash,
            nonce=nonce if nonce is not None else challenge.nonce,
        )

    def unanimous(
        self,
        challenge: ChallengeRecord,
        *,
        action: str,
        payload: Dict[str, Any],
        actor: str,
        resource: Optional[str],
        policy_hash: Optional[str],
        count: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """A clean N (or ``count``) ALLOW votes from distinct trusted evaluators,
        each bound to the challenge — the positive-path evidence."""
        n = len(self.evaluators) if count is None else count
        return [
            self.sign(e, challenge, action=action, payload=payload, actor=actor,
                      resource=resource, policy_hash=policy_hash)
            for e in self.evaluators[:n]
        ]
