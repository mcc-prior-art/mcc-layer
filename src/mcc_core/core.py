"""Decision engine: turns a policy verdict into a signed Ed25519 decision token.

The model proposes.
MCC-Core decides.
The gate enforces.
The audit chain records.

Only ALLOW and CONSTRAIN carry execution authority. DENY and ESCALATE
never produce a token: no verified decision token — no execution.
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Dict, Optional

from .signing import SigningKey, hash_action, hash_payload


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"
    CONSTRAIN = "CONSTRAIN"


EXECUTABLE_VERDICTS = (Verdict.ALLOW, Verdict.CONSTRAIN)


class TokenNotIssuable(Exception):
    """Raised when a verdict does not carry execution authority."""


class DecisionEngine:
    def __init__(
        self,
        *,
        signing_key: SigningKey,
        issuer: str,
        audience: str,
        policy_id: str,
        policy_hash: str,
        token_ttl_seconds: int = 60,
    ) -> None:
        self.signing_key = signing_key
        self.issuer = issuer
        self.audience = audience
        self.policy_id = policy_id
        self.policy_hash = policy_hash
        self.token_ttl_seconds = token_ttl_seconds

    def issue_token(
        self,
        *,
        verdict: "Verdict | str",
        subject: str,
        action: str,
        payload: Dict[str, Any],
        constraints: Optional[Dict[str, Any]] = None,
        audit_ref: Optional[str] = None,
        nonce: Optional[str] = None,
        now: Optional[int] = None,
        transaction_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        actor_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        auth_claims: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        verdict = Verdict(verdict)
        if verdict not in EXECUTABLE_VERDICTS:
            raise TokenNotIssuable(f"{verdict.value} does not authorize execution")

        issued_at = int(now if now is not None else time.time())
        claims = {
            "iss": self.issuer,
            "sub": subject,
            "aud": self.audience,
            "jti": str(uuid.uuid4()),
            "iat": issued_at,
            "nbf": issued_at,
            "exp": issued_at + self.token_ttl_seconds,
            "decision": verdict.value,
            "action": action,
            "action_hash": hash_action(action),
            "payload_hash": hash_payload(payload),
            "constraints": constraints or {},
            "policy_id": self.policy_id,
            "policy_hash": self.policy_hash,
            "nonce": nonce or uuid.uuid4().hex,
            "audit_ref": audit_ref,
            # Generic, domain-neutral operation binding. These tie the token to
            # the exact authorized operation regardless of action type. Payment
            # specifics (beneficiary/amount/currency/source) are not here — they
            # live in the canonical payload (covered by payload_hash) and, when a
            # profile supplies them, in the opaque ``auth_claims`` map below,
            # which the Ed25519 signature covers like every other claim.
            "transaction_id": transaction_id,
            "idempotency_key": idempotency_key,
            "actor_id": actor_id,
            "resource_id": resource_id,
            "auth_claims": auth_claims or {},
        }
        return self.signing_key.sign_token(claims)
