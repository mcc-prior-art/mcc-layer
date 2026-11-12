"""Receipt-verifying governed-executor adapter.

This is the "real governed executor adapter": it is the outbound side effect that
``GovernanceService`` runs *inside* ``coordinator.enforce`` (after the gate has
verified the decision token — signature, issuer, action/payload hash, actor,
resource, policy hash, nonce, replay, validity window, authorization scope — and
after the durable audit-before-execution record is written). It never decides or
bypasses governance.

It performs the real HTTP call to the mock notification service and confirms the
receipt. If the call is non-2xx, the receipt is missing/false, the correlation id
does not match, or the receipt's payload hash does not match the payload actually
sent, it raises :class:`UpstreamReceiptError` — which makes ``coordinator.enforce``
record a NON-executed result. EXECUTED is only ever returned for a confirmed,
matching receipt.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Awaitable, Callable, Dict

Upstream = Callable[[str, Dict[str, Any]], Awaitable[Dict[str, Any]]]


class UpstreamReceiptError(Exception):
    """The external service did not return a valid receipt matching the executed
    payload + correlation id (fail-closed: the action is not EXECUTED)."""


def payload_sha256(payload: Dict[str, Any]) -> str:
    """Deterministic hash of a JSON payload — the executed-payload fingerprint the
    mock service echoes back and the adapter re-derives (shared canonicalization)."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def receipt_verifying_upstream(base: str, *, timeout: float = 10.0) -> Upstream:
    """Build a governed upstream that POSTs to ``{base}/{action}`` and confirms the
    receipt before allowing EXECUTED."""
    import httpx

    from mcc_core.action_name import action_endpoint_url

    base = base.rstrip("/")

    async def upstream(action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        # R4: the action is one validated path segment; ActionNameError is
        # raised BEFORE any connection -- never stripped or encoded.
        url = action_endpoint_url(base, action)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, json=payload)
        except httpx.HTTPError as exc:  # transport failure -> not executed
            raise UpstreamReceiptError(
                f"notification transport failed: {type(exc).__name__}") from exc

        if resp.status_code != 200:
            raise UpstreamReceiptError(
                f"notification not accepted (HTTP {resp.status_code}); not executed")
        try:
            receipt = resp.json()
        except Exception as exc:  # noqa: BLE001
            raise UpstreamReceiptError("notification receipt was not JSON") from exc
        if not isinstance(receipt, dict) or receipt.get("received") is not True:
            raise UpstreamReceiptError("notification receipt did not confirm receipt")

        expected_corr = payload.get("correlation_id")
        if receipt.get("correlation_id") != expected_corr:
            raise UpstreamReceiptError(
                "receipt correlation_id does not match the executed payload")
        expected_hash = payload_sha256(payload)
        if receipt.get("payload_sha256") != expected_hash:
            raise UpstreamReceiptError(
                "receipt payload hash does not match the executed payload")

        # Confirmed, matching receipt -> genuine external effect.
        return {"upstream_status": 200, "receipt_verified": True, "body": receipt}

    return upstream
