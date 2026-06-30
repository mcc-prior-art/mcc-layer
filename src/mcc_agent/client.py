"""The supported MCC-Core client used by the governed agent.

This module is *wiring and adaptation only* — it implements no governance. It
reuses the authoritative implementation already in the repository:

* ``AuthorityModel`` (``src/mcc_core``) for the verdict — configured here with a
  per-action pilot policy (configuration, not a new engine);
* ``GovernedMCCClient`` (the existing decision-engine / execution-gate /
  enforcement-coordinator / approval-service wiring) for the one governed path;
* ``HTTPEgressExecutor`` (``egress_proxy``) — the existing governed HTTPS
  executor — as the *only* thing that performs the external request;
* ``validate_destination`` / ``build_canonical_action`` (``egress_proxy``) for
  SSRF rejection and canonical action + payload-hash binding.

The client cleanly separates the four stages:

* **propose / decide / execute** — :meth:`submit` builds the proposal, gets the
  MCC verdict, and (for ALLOW / CONSTRAIN) runs the single governed execution.
  Decide and execute are fused at the gate by design: there is no window in which
  a decision is treated as permission without the gate enforcing it.
* **approve** — :meth:`approve` performs the operator approval through the
  existing ``ApprovalService``.
* **execute (after approval)** — :meth:`execute_after_approval` consumes the
  single-use approval through the gate.

It exposes no private signing key and requires no caller to reconstruct internal
MCC authorization objects. There are **no** direct ``httpx`` / ``requests`` /
``urllib`` / ``socket`` imports here: the only outbound HTTP is performed inside
the governed ``HTTPEgressExecutor``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol

from mcc_core import (
    ActionPolicy,
    AuthorityModel,
    Mandate,
    MandateRegistry,
    Verdict,
    approval_registry_from_env,
    hash_payload,
    idempotency_registry_from_env,
    nonce_registry_from_env,
    velocity_registry_from_env,
)

from egress_proxy.canonical_action import (
    CanonicalActionError,
    action_hash,
    build_canonical_action,
    reconstruct_request,
)
from egress_proxy.config import EgressSettings
from egress_proxy.runtime import build_executor
from egress_proxy.ssrf import SSRFError, validate_destination

from examples.governed_agent.agent import Agent
from examples.governed_agent.mcc_client import GovernedMCCClient

from .errors import GovernanceClientError
from .models import ActionProposal, Decision, GovernanceOutcome

# Pilot identities: the trusted CRM agent holds standing mandates; the restricted
# identity holds none for a sensitive budget *increase*, so that action escalates.
TRUSTED_ACTOR = "agent/crm"

DEFAULT_MAX_BUDGET = 5000


def build_pilot_authority(*, max_budget: int = DEFAULT_MAX_BUDGET) -> AuthorityModel:
    """A per-action pilot authority configuration (NOT a new engine).

    * ``create_lead`` / ``send_notification`` / ``create_task`` /
      ``trigger_webhook`` — the trusted agent holds the mandate → ALLOW.
    * ``set_campaign_budget`` — held with ``max_body.amount`` cap; over-cap →
      CONSTRAIN (the body's ``amount`` is clamped to the cap).
    * ``increase_campaign_budget`` — requires a *high-value* budget authority the
      agent does not hold → ESCALATE (human approval required).
    * ``export_customer_data`` — admits no mandate (``requires=None``) →
      hard DENY.
    * anything else → deny-by-default.
    """
    registry = MandateRegistry([
        Mandate(holder=TRUSTED_ACTOR, authority="crm.lead"),
        Mandate(holder=TRUSTED_ACTOR, authority="crm.notify"),
        Mandate(holder=TRUSTED_ACTOR, authority="crm.task"),
        Mandate(holder=TRUSTED_ACTOR, authority="crm.webhook"),
        Mandate(holder=TRUSTED_ACTOR, authority="crm.budget",
                constraints={"max_body.amount": max_budget}),
    ])
    policies = [
        ActionPolicy(action="create_lead", requires="crm.lead"),
        ActionPolicy(action="send_notification", requires="crm.notify"),
        ActionPolicy(action="create_task", requires="crm.task"),
        ActionPolicy(action="trigger_webhook", requires="crm.webhook"),
        ActionPolicy(action="set_campaign_budget", requires="crm.budget",
                     on_mandate=Verdict.ALLOW, on_violation=Verdict.CONSTRAIN),
        # The agent holds no 'crm.budget.high' mandate -> ESCALATE to a human.
        ActionPolicy(action="increase_campaign_budget", requires="crm.budget.high",
                     without_mandate=Verdict.ESCALATE),
        # An action no mandate can authorize -> hard DENY.
        ActionPolicy(action="export_customer_data", requires=None,
                     without_mandate=Verdict.DENY),
    ]
    return AuthorityModel(registry=registry, policies=policies, default=Verdict.DENY)


class GovernanceClient(Protocol):
    """The supported client surface the agent depends on (transport-agnostic)."""

    async def submit(self, proposal: ActionProposal) -> GovernanceOutcome: ...
    async def approve(self, approval_request_id: str) -> bool: ...
    async def deny_approval(self, approval_request_id: str) -> bool: ...
    async def execute_after_approval(
        self, proposal: ActionProposal, approval_request_id: str) -> GovernanceOutcome: ...
    def verify_audit_chain(self) -> bool: ...
    @property
    def audit_path(self) -> str: ...


class EmbeddedGovernanceClient:
    """In-process governance client: drives the real MCC-Core runtime directly.

    The external request is performed only by the governed ``HTTPEgressExecutor``
    after a verified decision and durable audit. This client never makes an
    outbound call itself.
    """

    def __init__(
        self,
        *,
        pilot_api_base: str,
        max_budget: int = DEFAULT_MAX_BUDGET,
        audit_path: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        require_https: bool = False,
        allow_loopback: bool = True,
    ) -> None:
        host = _host_of(pilot_api_base)
        # EgressSettings here configures only the executor's transport policy
        # (allowed destinations, TLS, loopback) — the verdict comes from the
        # pilot AuthorityModel below, not from these settings.
        settings = EgressSettings(
            mcc_env="dev", api_key="agent-key", operator_api_key="op-key",
            allowed_hosts=host, allowed_methods="get,post",
            allow_loopback=allow_loopback, allow_http=not require_https,
            require_https=require_https, require_consensus=False)
        self.executor = build_executor(settings)
        self.policy = self.executor.policy

        # Redis-backed registries when the environment selects them (Scenario 7
        # uses this and fails closed when Redis is down — no silent fallback);
        # otherwise the runtime's in-memory defaults.
        env = env or {}
        registries: Dict[str, Any] = {}
        if env:
            registries = dict(
                nonce_registry=nonce_registry_from_env(env),
                idempotency_registry=idempotency_registry_from_env(env),
                velocity_registry=velocity_registry_from_env(env),
                approval_registry=approval_registry_from_env(env),
            )

        self._mcc = GovernedMCCClient(
            executor=self.executor,
            authority=build_pilot_authority(max_budget=max_budget),
            policy_hash="sha256:mcc-agent-pilot-v0.1",
            audit_path=audit_path,
            consensus_required=False,
            **registries,
        )
        # Share the audit chain so the executor appends post-actuation evidence to
        # the SAME hash chain (the durable pre-actuation record is the
        # coordinator's responsibility).
        self.executor.audit = self._mcc.audit

    # -- internals --

    def _canonical(self, proposal: ActionProposal) -> Dict[str, Any]:
        return build_canonical_action(
            method=proposal.method, url=proposal.url, headers={}, body=proposal.body)

    def _proposed(self, proposal: ActionProposal, canonical: Dict[str, Any]):
        return Agent(proposal.actor).propose(
            proposal.action_type, resource=proposal.resource, payload=canonical,
            transaction_id=proposal.transaction_id, idempotency_key=proposal.idempotency_key)

    def _ssrf_precheck(self, canonical: Dict[str, Any]) -> Optional[GovernanceOutcome]:
        """Reject an unsafe destination before any execution attempt (reusing the
        existing SSRF validator) — blocked before connection."""
        try:
            validate_destination(canonical["host"], int(canonical["port"]), policy=self.policy)
        except SSRFError:
            return GovernanceOutcome(
                decision=Decision.DENY, executed=False,
                reason="destination rejected (SSRF/unsafe)", error_code="SSRF_DENIED",
                final_payload=None)
        return None

    _AUTHORITY_STATE = {
        "ALLOW": "verified mandate satisfied",
        "CONSTRAIN": "mandate held; constraint applied (clamped)",
        "ESCALATE": "no standing mandate; human approval required",
        "DENY": "no authorizing mandate (deny-by-default / hard deny)",
    }

    @property
    def policy_hash(self) -> str:
        return self._mcc.policy_hash

    def _evidence(self, proposed, canonical, *, decision, r, authorized) -> Dict[str, Any]:
        """The per-decision audit evidence (hashes, ids, verdict, linkage)."""
        body = authorized if authorized is not None else canonical
        return {
            "proposal_id": proposed.transaction_id,
            "actor": proposed.actor,
            "resource": proposed.resource,
            "action_hash": action_hash(canonical),
            "payload_hash": hash_payload(body),
            "policy_hash": self.policy_hash,
            "authority_state": self._AUTHORITY_STATE.get(decision.value, decision.value),
            "verdict": decision.value,
            "constraints": list(r.applied_changes or []) if r is not None else [],
            "execution_result": "EXECUTED" if (r is not None and r.executed) else "BLOCKED",
            "audit_ref": getattr(r, "audit_ref", None) if r is not None else None,
        }

    def _outcome(self, r, proposed, canonical) -> GovernanceOutcome:
        verdict = r.verdict
        decision = {
            "ALLOW": Decision.ALLOW, "DENY": Decision.DENY,
            "ESCALATE": Decision.ESCALATE, "CONSTRAIN": Decision.CONSTRAIN,
        }.get(verdict, Decision.BLOCKED)
        reason_l = (r.reason or "").lower()
        dependency_down = any(s in reason_l for s in
                              ("redis", "registry unavailable", "registry down",
                               "could not reserve", "registry_unavailable"))
        if verdict == "ERROR":
            decision = Decision.DEPENDENCY_UNAVAILABLE if dependency_down else Decision.BLOCKED
        elif not r.executed and dependency_down:
            # The authority may have ALLOWed, but a Redis-backed registry was
            # unavailable and the gate/coordinator failed closed — surface that.
            decision = Decision.DEPENDENCY_UNAVAILABLE
        upstream_status: Optional[int] = None
        upstream_body: Any = None
        final_payload: Optional[Dict[str, Any]] = None
        authorized = None
        if r.executed and r.authorized_payload is not None:
            authorized = r.authorized_payload
            resp = self.executor.pop_response(proposed.correlation_id) or {}
            upstream_status = resp.get("upstream_status")
            upstream_body = resp.get("upstream_body")
            _, _, _, final_payload = reconstruct_request(r.authorized_payload)
        return GovernanceOutcome(
            decision=decision, executed=bool(r.executed), reason=r.reason,
            action_hash=action_hash(canonical),
            audit_ref=r.audit_ref, correlation_id=r.correlation_id,
            applied_constraints=list(r.applied_changes or []),
            upstream_status=upstream_status, upstream_body=upstream_body,
            final_payload=final_payload,
            audit_evidence=self._evidence(proposed, canonical, decision=decision, r=r,
                                          authorized=authorized))

    # -- the four stages --

    async def submit(self, proposal: ActionProposal) -> GovernanceOutcome:
        try:
            canonical = self._canonical(proposal)
        except CanonicalActionError:
            return GovernanceOutcome(
                decision=Decision.INVALID_REQUEST, executed=False,
                reason="request could not be canonicalized (malformed url / missing host)",
                error_code="INVALID_REQUEST")
        ssrf = self._ssrf_precheck(canonical)
        if ssrf is not None:
            return ssrf

        proposed = self._proposed(proposal, canonical)
        r = await self._mcc.submit(proposed)
        if r.verdict == "ESCALATE" and not r.executed:
            rid = await self._mcc.request_approval(proposed)
            return GovernanceOutcome(
                decision=Decision.ESCALATE, executed=False, reason=r.reason,
                action_hash=action_hash(canonical),
                approval_request_id=rid, correlation_id=r.correlation_id,
                final_payload=None,
                audit_evidence=self._evidence(proposed, canonical,
                                              decision=Decision.ESCALATE, r=r, authorized=None))
        return self._outcome(r, proposed, canonical)

    async def approve(self, approval_request_id: str) -> bool:
        return await self._mcc.approve(approval_request_id)

    async def deny_approval(self, approval_request_id: str) -> bool:
        return await self._mcc.deny_approval(approval_request_id)

    async def execute_after_approval(
        self, proposal: ActionProposal, approval_request_id: str) -> GovernanceOutcome:
        canonical = self._canonical(proposal)
        proposed = self._proposed(proposal, canonical)
        r = await self._mcc.execute_with_approval(proposed, approval_request_id)
        return self._outcome(r, proposed, canonical)

    # -- audit --

    def verify_audit_chain(self) -> bool:
        from mcc_core import AuditLog
        return AuditLog.verify_chain(self._mcc.audit.path)

    @property
    def audit_path(self) -> str:
        return self._mcc.audit.path


def _host_of(base: str) -> str:
    """Extract the host from a base URL without urllib (forbidden import).

    ``http://127.0.0.1:9100`` -> ``127.0.0.1``. Falls back to the raw value."""
    s = base.split("://", 1)[-1]
    s = s.split("/", 1)[0]
    s = s.rsplit("@", 1)[-1]            # strip any creds
    if s.startswith("["):              # [::1]:port
        return s[1:s.index("]")]
    return s.split(":", 1)[0]
