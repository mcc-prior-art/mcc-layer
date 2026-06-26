"""The agent for the governed-agent demo.

A minimal stand-in for an AI agent. It *proposes* an action — it never decides
whether the action may run, and it has no path to the executor. Per the
doctrine: **the model proposes; MCC decides; the gate enforces; the audit chain
records.**

The agent holds no credentials, no signing keys, and no executor reference. It
emits a structured ``ProposedAction`` and hands it to the ``GovernedMCCClient``.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class ProposedAction:
    """A structured proposal. Everything MCC needs to bind a decision to this
    exact operation — and nothing that lets the agent execute it."""

    actor: str                       # who proposes (identity, not authority)
    action: str                      # what they want to do
    resource: Optional[str]          # the target
    payload: Dict[str, Any]          # the proposed (un-authorized) body
    # Operation-binding identifiers (one-time / deduplicating / correlating):
    transaction_id: str
    idempotency_key: str
    nonce: str
    correlation_id: str
    # Policy / authority context the agent is operating under (a hint, not a
    # grant — MCC verifies authority independently):
    policy_ref: Optional[str] = None
    authority_context: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "payload": dict(self.payload),
            "transaction_id": self.transaction_id,
            "idempotency_key": self.idempotency_key,
            "nonce": self.nonce,
            "correlation_id": self.correlation_id,
            "policy_ref": self.policy_ref,
            "authority_context": self.authority_context,
        }


class Agent:
    """Proposes actions. No credentials, no executor, no decisions."""

    def __init__(self, actor: str, *, policy_ref: str = "mcc.demo/v1") -> None:
        self.actor = actor
        self.policy_ref = policy_ref

    def propose(
        self,
        action: str,
        *,
        resource: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        # Identifiers may be supplied for deterministic demos/tests; otherwise
        # fresh values are generated. The agent reuses ids only when explicitly
        # told to (e.g. to demonstrate replay / idempotency).
        transaction_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        nonce: Optional[str] = None,
        correlation_id: Optional[str] = None,
        authority_context: Optional[str] = None,
    ) -> ProposedAction:
        return ProposedAction(
            actor=self.actor,
            action=action,
            resource=resource,
            payload=dict(payload or {}),
            transaction_id=transaction_id or f"txn-{uuid.uuid4().hex}",
            idempotency_key=idempotency_key or f"idem-{uuid.uuid4().hex}",
            nonce=nonce or f"nonce-{uuid.uuid4().hex}",
            correlation_id=correlation_id or f"corr-{uuid.uuid4().hex}",
            policy_ref=self.policy_ref,
            authority_context=authority_context,
        )
