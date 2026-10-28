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

from .signing import SigningKey, hash_action, hash_payload, is_valid_digest


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
        tenant_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        auth_claims: Optional[Dict[str, Any]] = None,
        mandate_id: Optional[str] = None,
        evidence_digest: Optional[str] = None,
        max_exp: Optional[int] = None,
    ) -> Dict[str, Any]:
        verdict = Verdict(verdict)
        if verdict not in EXECUTABLE_VERDICTS:
            raise TokenNotIssuable(f"{verdict.value} does not authorize execution")

        issued_at = int(now if now is not None else time.time())
        # PR #122 round 6, Finding 1: a decision token must never carry MORE
        # time-bounded execution authority than the source authority (a
        # signed mandate or an approval-minted mandate) that justified it.
        # ``self.token_ttl_seconds`` is a fixed, server-wide default,
        # independent of any individual mandate/approval's own remaining
        # validity -- without this clamp, a mandate with (say) 10 seconds
        # left before its own ``exp`` could still justify a token valid for
        # the full 60-second default, letting the newly issued token
        # outlive the authority it was derived from. ``max_exp``, when
        # supplied by a caller that verified such an authority (see
        # ``MandateAuthorityDecision.mandate_exp``), only ever LOWERS the
        # computed expiry, never raises it -- callers that pass no
        # ``max_exp`` (e.g. the consensus path, which has no single
        # mandate/approval to clamp against; each vote's own window is
        # independently re-verified at actuation) get exactly the
        # pre-existing behavior.
        computed_exp = issued_at + self.token_ttl_seconds
        if max_exp is not None:
            computed_exp = min(computed_exp, int(max_exp))
        claims = {
            "iss": self.issuer,
            "sub": subject,
            "aud": self.audience,
            "jti": str(uuid.uuid4()),
            "iat": issued_at,
            "nbf": issued_at,
            "exp": computed_exp,
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
            # PR #105: the trusted tenant/security-domain identity that,
            # together with idempotency_key, forms the mandatory durable
            # operation identity EnforcementCoordinator requires. Signed like
            # every other claim -- the caller cannot forge or omit it once
            # issued. Optional HERE (this engine issues tokens for many
            # non-actuating/legacy callers too); the coordinator, not this
            # engine, is what makes it mandatory before actuation.
            "tenant_id": tenant_id,
            "actor_id": actor_id,
            "resource_id": resource_id,
            "auth_claims": auth_claims or {},
            # The id of the signed mandate whose authority justified this token
            # (when issued under a verified mandate). Binds token <-> authority
            # for audit and actuation-time revocation re-checks.
            "mandate_id": mandate_id,
        }
        # PR-3: Evidence-Bound Execution Ticket. A first-class,
        # signature-covered claim -- deliberately NOT folded into the
        # caller-controlled ``auth_claims`` map -- binding this token to the
        # exact complete signed EvidenceAttestation Control verified before
        # issuance (mcc_core.signing.hash_document over that document,
        # "sha256:<64 lowercase hex>"). Omitted entirely (not merely null)
        # for legacy/non-attested issuance, so a token issued for an action
        # with no configured AttestationRequirement is byte-for-byte
        # unaffected: existing behavior is unchanged. This is never a
        # semantic claim -- ExecutionGate compares only the digest.
        if evidence_digest is not None:
            # Fail closed at the issuance boundary: a malformed evidence_digest
            # must never become a signed, executable claim. This is
            # defense-in-depth (Control's own hash_document() call always
            # produces a well-formed value) -- it guards against a future or
            # alternate caller passing a caller-controlled, unvalidated, or
            # corrupted string here, which would otherwise be signed as if it
            # were a trusted binding.
            if not is_valid_digest(evidence_digest):
                raise TokenNotIssuable(
                    "evidence_digest must be 'sha256:<64 lowercase hex characters>'; "
                    f"got {evidence_digest!r}"
                )
            claims["evidence_digest"] = evidence_digest
        return self.signing_key.sign_token(claims)
