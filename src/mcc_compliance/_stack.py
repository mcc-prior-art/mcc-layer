"""Real, in-process governed stack + per-scenario authorization variants.

Underscore-prefixed: this is certification scaffolding, not a public API. It reuses
the existing in-process ``LocalGovernedStack`` (real gateway + gate + N-of-M
consensus + append-only audit + receipt-verifying governed executor over loopback)
so compliance cases run against genuine governance — never a mock — while staying
fully offline and deterministic. The authorization variants mirror the tamper
authorizers already proven fail-closed in ``tests/test_reference_governed_agent``.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, Optional, Tuple

from mcc_core import issue_vote
from mcc_core.signing import SIGNATURE_FIELD

from mcc_client import MCCClient
from mcc_client.models import ConsensusAuthorization, Decision

from examples.reference_governed_agent._localstack import (
    API_KEY,
    OPERATOR_KEY,
    LocalGovernedStack,
    agent_key,
)
from examples.reference_governed_agent.authorizers import FAR_FUTURE
from examples.reference_governed_agent.operator import ProgrammaticOperator

from pilot_notify import recorded_receipts, reset_receipts

from .protocol import AdapterContext

REQUEST = "Notify customer-123 that the appointment is confirmed"

# Verdict driver -> deterministic provider configuration (matches the proven
# reference-agent four-verdict scenarios).
_DRIVER_PROVIDER: Dict[str, Dict[str, str]] = {
    "allow": {"actor_id": "agent/notify-bot", "priority": "normal", "channel": "email"},
    "deny": {"actor_id": "agent/notify-bot", "priority": "normal", "channel": "pager"},
    "constrain": {"actor_id": "agent/notify-bot", "priority": "high", "channel": "email"},
    "escalate": {"actor_id": "agent/unknown", "priority": "normal", "channel": "email"},
}


class _ScenarioAuthorizer:
    """Authorization-material source for one scenario. In ``valid`` mode it produces
    correctly-bound N-of-M consensus votes; every other mode injects a single,
    specific defect so the gate must fail closed. A conforming adapter uses this
    faithfully — it does not get to choose honest material."""

    def __init__(self, stack: LocalGovernedStack, mode: str, *, capture: bool = False) -> None:
        self._stack = stack
        self._mode = mode
        self._capture = capture
        self.captured: Optional[Tuple[Decision, ConsensusAuthorization]] = None

    def material(self, client: MCCClient, decision: Decision) -> ConsensusAuthorization:
        ch = client.issue_challenge(decision)
        payload = dict(decision.authorized_payload)
        if self._mode == "tamper":
            payload = {**payload, "message": "COMPLIANCE-ALTERED"}
        canonical = self._stack.profiles.for_action(decision.action).canonical_payload(payload)

        actor = decision.actor_id
        resource = decision.resource_id
        policy_hash = self._stack.policy_hash
        not_after = FAR_FUTURE
        if self._mode == "actor":
            actor = "agent/compliance-wrong"
        elif self._mode == "scope":
            resource = "compliance-wrong-resource"
        elif self._mode == "policy_hash":
            policy_hash = "sha256:compliance-wrong"
        elif self._mode == "expired":
            not_after = 1  # in the past

        votes = [
            issue_vote(e, evaluator_id=e.kid, verdict="ALLOW", action=decision.action,
                       payload=canonical, actor=actor, not_before=0, not_after=not_after,
                       resource=resource, policy_hash=policy_hash, nonce=ch["nonce"],
                       # F1: the tenant the gateway recorded on the challenge.
                       tenant_id=ch.get("tenant_id"))
            for e in self._stack.evaluators
        ]
        if self._mode == "signature":
            for v in votes:
                raw = base64.b64decode(v[SIGNATURE_FIELD])
                flipped = bytes([raw[0] ^ 0xFF]) + raw[1:]
                v[SIGNATURE_FIELD] = base64.b64encode(flipped).decode()

        material = ConsensusAuthorization(
            votes=votes, challenge_id=ch["challenge_id"], nonce=ch["nonce"])
        if self._capture:
            self.captured = (decision, material)
        return material


class ComplianceStack:
    """Owns one governed stack for a certification run and builds a fresh
    ``AdapterContext`` per scenario, with ground-truth access for cross-checking."""

    def __init__(self) -> None:
        self.stack = LocalGovernedStack()

    def close(self) -> None:
        self.stack.close()

    def __enter__(self) -> "ComplianceStack":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def client(self, actor_id: Optional[str] = None) -> MCCClient:
        # V05 (part 2): an agent acting as ``actor_id`` presents its OWN
        # registered credential (required on /approvals + the execute routes);
        # without an actor, the tenant's shared key (read-only routes only;
        # F1: /evaluate-as-an-agent and /consensus/* need the agent's own key).
        key = agent_key(actor_id) if actor_id else API_KEY
        return MCCClient(self.stack.base_url, api_key=key, operator_key=OPERATOR_KEY,
                         timeout=15.0)

    def reset_ground_truth(self) -> None:
        reset_receipts()

    def recorded_executions(self) -> int:
        return len(recorded_receipts())

    def build_context(self, scenario: Dict[str, Any]) -> Tuple[AdapterContext, Optional[_ScenarioAuthorizer]]:
        driver = scenario["driver"]
        provider_config = dict(_DRIVER_PROVIDER[driver])
        request_mode = scenario.get("request", "normal")
        request = "" if request_mode == "malformed" else REQUEST

        op_mode = scenario.get("operator")
        operator = ProgrammaticOperator(approve=(op_mode != "reject"))

        auth_mode = scenario.get("authorization", "valid")
        authorizer: Optional[_ScenarioAuthorizer] = None
        if auth_mode == "none":
            authorizer = None
        else:
            capture = auth_mode == "replay"
            mode = "valid" if auth_mode == "replay" else auth_mode
            authorizer = _ScenarioAuthorizer(self.stack, mode, capture=capture)

        ctx = AdapterContext(
            request=request, client=self.client(provider_config["actor_id"]),
            provider_config=provider_config,
            operator=operator, authorizer=authorizer)
        return ctx, authorizer


__all__ = ["ComplianceStack", "REQUEST"]
