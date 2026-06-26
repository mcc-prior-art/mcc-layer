"""Mock executor for the governed-agent demo.

Stands in for a real external action (a payment API, a robot actuator, an infra
command). It deliberately models the one rule that matters:

    The executor acts only after a verified MCC decision.

It accepts work **only** through the governed path: every call must carry an
``authorization`` (the signed decision token issued by MCC-Core for *this* exact
operation). A direct or unauthorized invocation is rejected — there is no
agent-to-executor shortcut. The executor records what it actually ran so tests
can prove whether (and with which payload) execution occurred, and it keeps the
*authorized* payload distinct from whatever the agent originally proposed.

It performs no governance decisions of its own — it is the thing *being*
governed, not a second gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class UnauthorizedExecution(Exception):
    """Raised when the executor is invoked without a verified MCC authorization."""


@dataclass
class ExecutionRecord:
    action: str
    authorized_payload: Dict[str, Any]
    audit_ref: Optional[str]
    correlation_id: Optional[str]
    transaction_id: Optional[str]


class MockExecutor:
    """Records governed executions. Never runs without a decision token."""

    def __init__(self) -> None:
        self._records: List[ExecutionRecord] = []

    @property
    def calls(self) -> List[ExecutionRecord]:
        return list(self._records)

    @property
    def executed(self) -> bool:
        return bool(self._records)

    def count(self) -> int:
        return len(self._records)

    def last(self) -> Optional[ExecutionRecord]:
        return self._records[-1] if self._records else None

    async def execute(
        self,
        action: str,
        authorized_payload: Dict[str, Any],
        *,
        authorization: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """The ONLY entrypoint, and only the governed path supplies a valid
        ``authorization`` — the Ed25519 decision token MCC issued for this exact
        operation (verdict ALLOW or CONSTRAIN). A missing/invalid token is a
        direct/unauthorized call and is refused (fail-closed)."""
        if not self._is_authorized(authorization, action, authorized_payload):
            raise UnauthorizedExecution(
                "executor invoked without a verified MCC decision token; refused"
            )
        record = ExecutionRecord(
            action=action,
            authorized_payload=dict(authorized_payload),
            audit_ref=authorization.get("audit_ref") if isinstance(authorization, dict) else None,
            correlation_id=correlation_id,
            transaction_id=authorization.get("transaction_id") if isinstance(authorization, dict) else None,
        )
        self._records.append(record)
        return {"executed": True, "action": action}

    @staticmethod
    def _is_authorized(token: Any, action: str, payload: Dict[str, Any]) -> bool:
        # The token must exist, name an executable verdict, and bind to the exact
        # action being run. (The gate has already verified the signature, nonce,
        # audience, expiry, and payload-hash binding before we get here; this is
        # the executor's own defence against a direct, ungoverned call.)
        if not isinstance(token, dict):
            return False
        if token.get("decision") not in ("ALLOW", "CONSTRAIN"):
            return False
        if token.get("action") != action:
            return False
        return True
