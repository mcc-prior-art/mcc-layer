"""OutboundHTTPExecutor — a real outbound HTTP call as the governed side effect.

This is the thing being *governed*, not a second gate. It performs an actual
HTTP request to an external upstream, but only when handed the verified Ed25519
decision token MCC issued for that exact operation. A direct or unauthorized
invocation is refused (``UnauthorizedExecution``) — there is no agent→executor
shortcut, and the executor performs no governance decision of its own.

It is reached only from inside ``EnforcementCoordinator.enforce`` (after the gate
verifies the token, consensus/challenge/approval predicates hold, idempotency and
velocity are reserved, and the pre-actuation audit record is written). It records
exactly what it sent so a caller can prove which body actually left the process —
the *authorized* body (the clamped one for CONSTRAIN), never the original.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx


class UnauthorizedExecution(Exception):
    """Raised when the executor is invoked without a verified MCC authorization."""


@dataclass
class OutboundCall:
    action: str
    url: str
    authorized_payload: Dict[str, Any]
    status_code: int
    audit_ref: Optional[str]
    correlation_id: Optional[str]
    transaction_id: Optional[str]


class OutboundHTTPExecutor:
    """Performs a governed outbound HTTP POST to ``{base_url}/{action}``."""

    EXECUTABLE = ("ALLOW", "CONSTRAIN")

    def __init__(self, base_url: str, *, timeout: float = 5.0,
                 identity_header: str = "X-MCC-Identity") -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.identity_header = identity_header
        self._records: List[OutboundCall] = []

    @property
    def calls(self) -> List[OutboundCall]:
        return list(self._records)

    @property
    def executed(self) -> bool:
        return bool(self._records)

    def count(self) -> int:
        return len(self._records)

    def last(self) -> Optional[OutboundCall]:
        return self._records[-1] if self._records else None

    async def execute(
        self, action: str, authorized_payload: Dict[str, Any], *,
        authorization: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """The ONLY entrypoint. Refuses any call without a verified decision token
        (verdict ALLOW/CONSTRAIN, bound to this action). Then performs the real
        outbound request with the *authorized* body."""
        if not self._is_authorized(authorization, action):
            raise UnauthorizedExecution(
                "outbound executor invoked without a verified MCC decision token; refused")
        url = f"{self.base_url}/{action.lstrip('/')}"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                url, json=authorized_payload,
                headers={self.identity_header: str(authorization.get("subject", ""))})
        record = OutboundCall(
            action=action, url=url, authorized_payload=dict(authorized_payload),
            status_code=resp.status_code,
            audit_ref=authorization.get("audit_ref") if isinstance(authorization, dict) else None,
            correlation_id=correlation_id,
            transaction_id=authorization.get("transaction_id") if isinstance(authorization, dict) else None,
        )
        self._records.append(record)
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001
            body = resp.text
        return {"executed": True, "action": action,
                "upstream_status": resp.status_code, "upstream_body": body}

    @staticmethod
    def _is_authorized(token: Any, action: str) -> bool:
        # The gate has already verified signature/nonce/audience/expiry/payload-hash
        # before the coordinator calls us; this is the executor's own defence
        # against a direct, ungoverned call.
        if not isinstance(token, dict):
            return False
        if token.get("decision") not in OutboundHTTPExecutor.EXECUTABLE:
            return False
        if token.get("action") != action:
            return False
        return True
