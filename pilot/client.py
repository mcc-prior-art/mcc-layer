"""MCCGatewayClient — a minimal, supported Python client for the deployed gateway.

This is transport only. Every decision and every enforcement step happens inside
the runtime behind the gateway (``AuthorityModel`` → ``DecisionEngine`` →
``EnforcementCoordinator`` → ``ExecutionGate`` → audit). The client:

* submits an action proposal               → :meth:`propose`  (POST /evaluate)
* reads ALLOW / DENY / ESCALATE / CONSTRAIN → :class:`ProposalResult`
* submits required approvals                → :meth:`request_approval` /
  :meth:`approve` / :meth:`execute_with_approval`
* submits required consensus material       → :meth:`issue_challenge` /
  :meth:`verify_consensus` / :meth:`execute_with_consensus`
* executes ONLY through governed endpoints  → ``/…/execute`` (one coordinator path)

There is deliberately **no** ``execute(action, payload)`` that reaches a side
effect directly: the only execution methods post to governed endpoints that run
``coordinator.enforce``. Operator-only actions (approve/deny/revoke/trust) require
the operator key; without it they fail closed server-side.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"
    CONSTRAIN = "CONSTRAIN"


@dataclass(frozen=True)
class ProposalResult:
    """The gateway's verdict for a proposal (POST /evaluate)."""

    decision: Decision
    reason: str
    audit_id: str
    # The body the verdict authorizes: original for ALLOW, clamped for CONSTRAIN.
    forward_context: Dict[str, Any] = field(default_factory=dict)
    applied_constraints: List[str] = field(default_factory=list)
    # The signed Ed25519 decision token (ALLOW/CONSTRAIN only); the artifact the
    # execution gate verifies. None for DENY/ESCALATE.
    decision_token: Optional[Dict[str, Any]] = None
    constraints: Dict[str, Any] = field(default_factory=dict)
    authority_required: Optional[str] = None
    policy_ref: str = ""
    transaction_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    actor_id: Optional[str] = None
    resource_id: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def executable(self) -> bool:
        return self.decision in (Decision.ALLOW, Decision.CONSTRAIN)

    @property
    def needs_approval(self) -> bool:
        return self.decision == Decision.ESCALATE


@dataclass(frozen=True)
class ExecutionOutcome:
    """The result of a governed execution (an /…/execute endpoint)."""

    status: str                       # EXECUTED / BLOCKED / EXECUTION_FAILED
    reason: str
    decision: Optional[str] = None
    audit_ref: Optional[str] = None
    execution: Any = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def executed(self) -> bool:
        return self.status == "EXECUTED"


class MCCGatewayError(RuntimeError):
    """Transport-level failure talking to the gateway (not a governance DENY)."""


class MCCGatewayClient:
    """A synchronous client for a running MCC-Core gateway."""

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str,
        operator_key: Optional[str] = None,
        timeout: float = 10.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.operator_key = operator_key
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=timeout)

    # ---- context management ----

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "MCCGatewayClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ---- low-level ----

    def _headers(self, *, operator: bool = False) -> Dict[str, str]:
        headers = {"x-api-key": self.api_key}
        if operator:
            if not self.operator_key:
                raise MCCGatewayError(
                    "operator action requires an operator key; none configured (fail-closed)")
            headers["x-operator-key"] = self.operator_key
        return headers

    def _post(self, path: str, json: Dict[str, Any], *, operator: bool = False) -> httpx.Response:
        try:
            return self._client.post(
                f"{self.base_url}{path}", json=json, headers=self._headers(operator=operator))
        except httpx.HTTPError as exc:
            raise MCCGatewayError(f"gateway POST {path} failed: {exc}") from exc

    def _get(self, path: str, *, operator: bool = False, params: Optional[Dict[str, Any]] = None):
        try:
            return self._client.get(
                f"{self.base_url}{path}", headers=self._headers(operator=operator), params=params)
        except httpx.HTTPError as exc:
            raise MCCGatewayError(f"gateway GET {path} failed: {exc}") from exc

    @staticmethod
    def _json(resp: httpx.Response) -> Dict[str, Any]:
        try:
            return resp.json()
        except Exception as exc:  # noqa: BLE001
            raise MCCGatewayError(f"non-JSON response (HTTP {resp.status_code})") from exc

    # ---- health / readiness ----

    def health(self) -> Dict[str, Any]:
        return self._json(self._get("/health"))

    def ready(self) -> Dict[str, Any]:
        """Readiness probe. Returns the JSON body; callers can check
        ``resp["ready"]``. A 503 still returns the body (not an exception)."""
        return self._json(self._get("/ready"))

    def is_ready(self) -> bool:
        try:
            return bool(self.ready().get("ready"))
        except MCCGatewayError:
            return False

    # ---- propose (the four verdicts) ----

    def propose(
        self, *, identity: str, action: str, context: Optional[Dict[str, Any]] = None,
        transaction_id: Optional[str] = None, idempotency_key: Optional[str] = None,
        actor_id: Optional[str] = None, resource_id: Optional[str] = None,
        mode: Optional[str] = None,
    ) -> ProposalResult:
        """Submit a proposal. Returns the verdict (ALLOW/DENY/ESCALATE/CONSTRAIN),
        the authorized body, and — for ALLOW/CONSTRAIN — the signed decision token."""
        body: Dict[str, Any] = {"identity": identity, "action": action,
                                "context": dict(context or {})}
        for k, v in (("transaction_id", transaction_id), ("idempotency_key", idempotency_key),
                     ("actor_id", actor_id), ("resource_id", resource_id), ("mode", mode)):
            if v is not None:
                body[k] = v
        resp = self._post("/evaluate", body)
        if resp.status_code == 401:
            raise MCCGatewayError("INVALID_API_KEY")
        data = self._json(resp)
        return ProposalResult(
            decision=Decision(data["decision"]),
            reason=data.get("reason", ""),
            audit_id=data.get("audit_id", ""),
            forward_context=data.get("forward_context", {}) or {},
            applied_constraints=data.get("applied_constraints", []) or [],
            decision_token=data.get("decision_token"),
            constraints=data.get("constraints", {}) or {},
            authority_required=data.get("authority_required"),
            policy_ref=data.get("policy_ref", ""),
            transaction_id=data.get("transaction_id"),
            idempotency_key=data.get("idempotency_key"),
            actor_id=data.get("actor_id"),
            resource_id=data.get("resource_id"),
            raw=data,
        )

    # ---- ESCALATE: approvals ----

    def request_approval(
        self, *, actor: str, action: str, resource: Optional[str] = None,
        transaction_id: Optional[str] = None, policy_hash: Optional[str] = None,
        payload_hash: Optional[str] = None, constraints: Optional[Dict[str, Any]] = None,
        ttl_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        body = {"actor": actor, "action": action}
        for k, v in (("resource", resource), ("transaction_id", transaction_id),
                     ("policy_hash", policy_hash), ("payload_hash", payload_hash),
                     ("constraints", constraints), ("ttl_seconds", ttl_seconds)):
            if v is not None:
                body[k] = v
        return self._json(self._post("/approvals", body))

    def get_approval(self, request_id: str) -> Optional[Dict[str, Any]]:
        resp = self._get(f"/approvals/{request_id}")
        if resp.status_code == 404:
            return None
        return self._json(resp)

    def approve(self, request_id: str) -> Dict[str, Any]:
        """Operator action: grant a pending approval (mints a single-use mandate)."""
        return self._json(self._post(f"/approvals/{request_id}/approve", {}, operator=True))

    def deny_approval(self, request_id: str) -> Dict[str, Any]:
        return self._json(self._post(f"/approvals/{request_id}/deny", {}, operator=True))

    def execute_with_approval(
        self, request_id: str, *, mandate: Dict[str, Any], actor: str, action: str,
        resource: Optional[str] = None, context: Optional[Dict[str, Any]] = None,
        transaction_id: Optional[str] = None, idempotency_key: Optional[str] = None,
    ) -> ExecutionOutcome:
        body = {"mandate": mandate, "actor": actor, "action": action,
                "context": dict(context or {})}
        for k, v in (("resource", resource), ("transaction_id", transaction_id),
                     ("idempotency_key", idempotency_key)):
            if v is not None:
                body[k] = v
        return self._exec_outcome(self._post(f"/approvals/{request_id}/execute", body))

    # ---- consensus material ----

    def issue_challenge(
        self, *, actor: str, action: str, resource: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None, ttl_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        body = {"actor": actor, "action": action, "context": dict(context or {})}
        for k, v in (("resource", resource), ("ttl_seconds", ttl_seconds)):
            if v is not None:
                body[k] = v
        return self._json(self._post("/consensus/challenge", body))

    def verify_consensus(
        self, *, votes: List[Dict[str, Any]], actor: str, action: str,
        resource: Optional[str] = None, context: Optional[Dict[str, Any]] = None,
        nonce: Optional[str] = None,
    ) -> Dict[str, Any]:
        body = {"votes": votes, "actor": actor, "action": action,
                "context": dict(context or {})}
        for k, v in (("resource", resource), ("nonce", nonce)):
            if v is not None:
                body[k] = v
        return self._json(self._post("/consensus/verify", body))

    def execute_with_consensus(
        self, *, votes: List[Dict[str, Any]], actor: str, action: str,
        resource: Optional[str] = None, context: Optional[Dict[str, Any]] = None,
        transaction_id: Optional[str] = None, idempotency_key: Optional[str] = None,
        nonce: Optional[str] = None, challenge_id: Optional[str] = None,
    ) -> ExecutionOutcome:
        body = {"votes": votes, "actor": actor, "action": action,
                "context": dict(context or {})}
        for k, v in (("resource", resource), ("transaction_id", transaction_id),
                     ("idempotency_key", idempotency_key), ("nonce", nonce),
                     ("challenge_id", challenge_id)):
            if v is not None:
                body[k] = v
        return self._exec_outcome(self._post("/consensus/execute", body))

    # ---- mandates ----

    def verify_mandate(
        self, *, mandate: Dict[str, Any], subject: str, action: str,
        resource: Optional[str] = None, policy_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        body = {"mandate": mandate, "subject": subject, "action": action}
        for k, v in (("resource", resource), ("policy_hash", policy_hash)):
            if v is not None:
                body[k] = v
        return self._json(self._post("/mandates/verify", body))

    def execute_with_mandate(
        self, *, mandate: Dict[str, Any], actor: str, action: str,
        resource: Optional[str] = None, context: Optional[Dict[str, Any]] = None,
        transaction_id: Optional[str] = None, idempotency_key: Optional[str] = None,
    ) -> ExecutionOutcome:
        body = {"mandate": mandate, "actor": actor, "action": action,
                "context": dict(context or {})}
        for k, v in (("resource", resource), ("transaction_id", transaction_id),
                     ("idempotency_key", idempotency_key)):
            if v is not None:
                body[k] = v
        return self._exec_outcome(self._post("/mandates/execute", body))

    def revoke_mandate(self, mandate_id: str) -> Dict[str, Any]:
        return self._json(self._post(f"/mandates/{mandate_id}/revoke", {}, operator=True))

    # ---- audit chain ----

    def verify_chain(self) -> Dict[str, Any]:
        return self._json(self._get("/verify"))

    def export_audit(self, *, fmt: str = "jsonl") -> str:
        resp = self._get("/export", params={"fmt": fmt})
        return resp.text

    # ---- helpers ----

    def _exec_outcome(self, resp: httpx.Response) -> ExecutionOutcome:
        data = self._json(resp)
        return ExecutionOutcome(
            status=data.get("status", "BLOCKED"), reason=data.get("reason", ""),
            decision=data.get("decision"), audit_ref=data.get("audit_ref"),
            execution=data.get("execution"), raw=data,
        )
