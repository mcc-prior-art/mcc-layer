"""Verifiable Delegation & Intent Binding.

A **Delegation** is a cryptographically signed, owner-issued grant of
authority to one specific agent — richer than a signed ``Mandate``
(``mandate.py``) in exactly the ways payment-adjacent delegation requires:

* it binds **purpose**, **recipient**, and **currency** as exact,
  non-clampable authorization facts (a mismatch on any of these DENIES —
  it is never silently rewritten);
* it carries an explicit ``consent_ref`` — a reference to independently
  stored consent evidence (e.g. a UI confirmation record's hash) that the
  owner's own signature covers, so the delegation is attributable to a
  specific consent event, not merely to "whoever held the key";
* each operation's amount is checked against both the delegation's own
  per-operation ceiling (``max_amount``) and an **atomic, cumulative**
  spending ceiling shared across every concurrent use of the same
  delegation, on every concurrent gateway instance — by reusing
  ``VelocityRegistry.reserve()`` (``velocity.py``), the same atomic
  Redis-Lua primitive PR #122 already proved safe against transaction
  splitting and cross-instance races. No new accounting primitive is
  introduced.

Doctrine — why an agent can never mint, expand, transfer, or reuse its own
authority:

1. ``issue_delegation()`` takes an owner's :class:`~.signing.SigningKey`.
   An agent never holds this key; nothing in this module, the gateway, or
   the governed agent packages ever calls it with an agent-controlled key.
2. :class:`DelegationVerifier` is constructed with a ``trusted_owner_keys``
   map that MUST be a dedicated trust root for owners — disjoint, by
   deployment convention, from any mandate-issuer or agent-held key (see
   ``gateway/governance_api.py``'s wiring, which never merges the two). A
   delegation signed by a key outside this map is ``UNTRUSTED_ISSUER``,
   full stop — there is no path by which an agent's own key, however
   obtained, can satisfy this check.
3. Every authorization-bearing field (subject, tenant, purpose, action,
   resource, recipient, currency, amount ceiling, validity window) is read
   from the SIGNED delegation document and independently re-derived by
   :class:`DelegationAuthority`, never trusted from the caller's proposed
   context. An agent can propose any context it likes; the exact-match /
   ceiling checks below decide, from the signed document alone, whether
   that proposal is within what was actually delegated.
4. ``subject`` binds the delegation to exactly one agent identity
   (mirroring ``MandateVerifier``'s ``SUBJECT_MISMATCH`` check) — a
   delegation issued to agent A can never be presented successfully by
   agent B (no transfer).
5. "Reuse" across multiple operations within scope and budget is the
   delegation's intended, documented behavior (it is a standing grant, not
   single-use like an ESCALATE approval) — but reuse OUTSIDE scope/budget
   is exactly what items 3 and the atomic cumulative ceiling prevent, and
   reuse of the same logical OPERATION is independently prevented by the
   existing nonce + idempotency machinery in ``EnforcementCoordinator``,
   unchanged and untouched by this module.

This module introduces no changes to ``coordinator.py``, ``gate.py``, or
``trusted_time.py`` — every PR #122 guarantee (TrustedTime coverage, Redis
atomicity, revocation, durable execution, token-expiry enforcement,
fail-closed behavior) is inherited unmodified by routing delegated
execution through the SAME ``EnforcementCoordinator.enforce()`` call every
other authority path already uses.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .mandate import RevocationRegistry, RevocationStatus
from .profiles import VelocityDescriptor
from .signing import SigningKey, verify_token
from .trusted_time import LocalTimeSource, TimeTrustError, TrustedTimeSource
from .velocity import VelocityLimit

REQUIRED_FIELDS = (
    "delegation_id", "owner_id", "subject", "tenant_id", "purpose",
    "action_scope", "resource_scope", "recipient_scope", "currency",
    "max_amount", "nbf", "exp", "iat", "revocation_required", "consent_ref",
)

# A delegation's cumulative velocity ceiling must span the delegation's own
# FULL validity window, not an arbitrary fixed window -- otherwise the
# sliding-window ceiling in velocity.py would "forget" old spend before the
# delegation itself expires, letting cumulative spend exceed max_amount
# within one still-valid delegation. Clamped to a sane minimum so a
# zero/negative-duration delegation (already rejected by the validity-window
# check elsewhere) can never produce a degenerate zero-width window.
_MIN_VELOCITY_WINDOW_SECONDS = 1


def issue_delegation(
    owner_key: SigningKey,
    *,
    owner_id: str,
    subject: str,
    tenant_id: str,
    purpose: str,
    action_scope: List[str],
    resource_scope: List[str],
    recipient_scope: List[str],
    currency: str,
    max_amount: float,
    not_before: int,
    not_after: int,
    issued_at: Optional[int] = None,
    revocation_required: bool = True,
    policy_hash: Optional[str] = None,
    delegation_id: Optional[str] = None,
    consent_ref: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Issue a signed delegation. ``owner_key`` is the OWNER's signing key —
    never an agent's. ``consent_ref`` is a reference (e.g. a hash) to
    independently stored consent evidence; it is covered by this same
    signature, so the delegation is attributable to a specific consent
    event. ``currency`` is a single exact string (never a scope/glob) —
    currency substitution is a hard DENY, never a clampable dimension.

    Unlike ``issue_mandate``'s optional ``resource_scope``, every exact-
    binding dimension here is mandatory and validated at issuance time:
    a delegation that omitted one (e.g. an empty ``recipient_scope``) would
    let :class:`DelegationAuthority` skip that check entirely later --
    failing closed HERE, at signing time, means no such delegation can ever
    exist for a verifier to be tricked by.
    """
    if not isinstance(consent_ref, str) or not consent_ref.strip():
        raise ValueError("issue_delegation requires a non-empty consent_ref (consent evidence binding)")
    if not isinstance(purpose, str) or not purpose.strip():
        raise ValueError("issue_delegation requires a non-empty purpose")
    if not action_scope:
        raise ValueError("issue_delegation requires a non-empty action_scope")
    if not resource_scope:
        raise ValueError("issue_delegation requires a non-empty resource_scope")
    if not recipient_scope:
        raise ValueError("issue_delegation requires a non-empty recipient_scope")
    if not isinstance(currency, str) or not currency.strip():
        raise ValueError("issue_delegation requires a non-empty currency")
    if not isinstance(max_amount, (int, float)) or isinstance(max_amount, bool) or max_amount <= 0:
        raise ValueError(f"issue_delegation requires a positive max_amount, got {max_amount!r}")
    if not isinstance(not_before, int) or not isinstance(not_after, int) or not_after <= not_before:
        raise ValueError("issue_delegation requires not_after > not_before (both integer seconds)")
    iat = int(issued_at if issued_at is not None else time.time())
    claims = {
        "delegation_id": delegation_id or f"deleg-{uuid.uuid4().hex}",
        "owner_id": owner_id,
        "subject": subject,
        "tenant_id": tenant_id,
        "purpose": purpose,
        "action_scope": list(action_scope),
        "resource_scope": list(resource_scope),
        "recipient_scope": list(recipient_scope),
        "currency": str(currency).upper(),
        "max_amount": float(max_amount),
        "iat": iat,
        "nbf": int(not_before),
        "exp": int(not_after),
        "revocation_required": bool(revocation_required),
        "policy_hash": policy_hash,
        "consent_ref": consent_ref,
    }
    if extra:
        for key in extra:
            if key in claims or key in ("kid", "sig"):
                raise ValueError(f"extra delegation claim '{key}' is reserved")
        claims.update(extra)
    return owner_key.sign_token(claims)


@dataclass(frozen=True)
class DelegationResult:
    ok: bool
    reason: str
    delegation_id: Optional[str] = None
    owner_id: Optional[str] = None
    subject: Optional[str] = None
    max_amount: Optional[float] = None
    exp: Optional[int] = None


def _scope_match(value: Optional[str], scope: List[str]) -> bool:
    import fnmatch

    if value is None:
        return False
    return any(fnmatch.fnmatchcase(value, pat) for pat in scope)


class DelegationVerifier:
    """Verifies a signed delegation against the operation it is meant to
    authorize. ``trusted_owner_keys`` MUST be a dedicated owner trust root
    (see module docstring, point 2) -- never merged with a mandate-issuer or
    agent-held key set by this module or its callers.

    Order: signature & trusted owner -> structural completeness -> validity
    window -> subject match -> tenant match -> action scope -> resource
    scope -> policy binding -> revocation. Any failure denies; any exception
    denies (fail-closed).
    """

    def __init__(
        self,
        *,
        trusted_owner_keys: Dict[str, Ed25519PublicKey],
        revocation_registry: Optional[RevocationRegistry] = None,
        time_source: Optional[TrustedTimeSource] = None,
    ) -> None:
        self.trusted_owner_keys = trusted_owner_keys
        self.revocation_registry = revocation_registry
        self.time_source: TrustedTimeSource = time_source or LocalTimeSource()

    async def verify(
        self,
        delegation: Any,
        *,
        subject: str,
        tenant_id: str,
        action: str,
        resource: Optional[str],
        now: Optional[int] = None,
        policy_hash: Optional[str] = None,
    ) -> DelegationResult:
        try:
            return await self._verify(
                delegation, subject=subject, tenant_id=tenant_id, action=action,
                resource=resource, now=now, policy_hash=policy_hash,
            )
        except Exception:
            return DelegationResult(False, "DELEGATION_ERROR: fail-closed")

    async def _verify(self, delegation, *, subject, tenant_id, action, resource, now, policy_hash) -> DelegationResult:
        if not isinstance(delegation, dict) or not delegation:
            return DelegationResult(False, "NO_DELEGATION: no authority presented")

        public_key = self.trusted_owner_keys.get(delegation.get("kid"))
        if public_key is None:
            return DelegationResult(False, "UNTRUSTED_ISSUER: unknown or revoked owner key")
        if not verify_token(delegation, public_key):
            return DelegationResult(False, "INVALID_DELEGATION_SIGNATURE: Ed25519 verification failed")

        for required in REQUIRED_FIELDS:
            if required not in delegation:
                return DelegationResult(False, f"MALFORMED_DELEGATION: missing {required}")

        if now is not None:
            ts = int(now)
        else:
            try:
                ts = await self.time_source.now()
            except TimeTrustError as exc:
                return DelegationResult(False, f"{exc.reason}: {exc.detail}")
        nbf, exp = delegation.get("nbf"), delegation.get("exp")
        if not isinstance(nbf, int) or not isinstance(exp, int):
            return DelegationResult(False, "MALFORMED_DELEGATION: invalid validity window")
        if ts < nbf:
            return DelegationResult(False, "DELEGATION_NOT_YET_VALID")
        if ts >= exp:
            return DelegationResult(False, "DELEGATION_EXPIRED")

        if delegation.get("subject") != subject:
            return DelegationResult(False, "SUBJECT_MISMATCH: delegation not issued to this agent")

        if delegation.get("tenant_id") != tenant_id:
            return DelegationResult(False, "TENANT_MISMATCH: delegation bound to another tenant")

        if not _scope_match(action, delegation.get("action_scope", [])):
            return DelegationResult(False, "ACTION_SCOPE_MISMATCH: action outside delegated scope")

        # Unconditional (never ``if resource_scope:`` guarded): unlike
        # MandateVerifier's optional resource_scope, issue_delegation()
        # refuses to sign a delegation with an empty one, so a verified
        # delegation always has a real scope to check resource against.
        if not _scope_match(resource, delegation.get("resource_scope", [])):
            return DelegationResult(False, "RESOURCE_SCOPE_MISMATCH: resource outside delegated scope")

        bound_policy = delegation.get("policy_hash")
        if bound_policy is not None and policy_hash is not None and bound_policy != policy_hash:
            return DelegationResult(False, "POLICY_BINDING_MISMATCH: delegation bound to another policy")

        if delegation.get("revocation_required"):
            if self.revocation_registry is None:
                return DelegationResult(False, "REVOCATION_REQUIRED: no revocation service configured; fail-closed")
            status = await self.revocation_registry.check(delegation["delegation_id"])
            if status == RevocationStatus.REVOKED:
                return DelegationResult(False, "DELEGATION_REVOKED")
            if status != RevocationStatus.ACTIVE:
                return DelegationResult(False, "REVOCATION_UNAVAILABLE: cannot confirm delegation active; fail-closed")

        return DelegationResult(
            True, "DELEGATION_VERIFIED",
            delegation_id=delegation["delegation_id"], owner_id=delegation.get("owner_id"),
            subject=subject, max_amount=delegation.get("max_amount"), exp=exp,
        )


@dataclass(frozen=True)
class DelegationAuthorityDecision:
    """Deliberately binary (ALLOW or DENY) -- unlike ``MandateAuthorityDecision``,
    a Delegation never CONSTRAINs (silently rewrites) a payment-adjacent
    amount, recipient, or currency. A proposal outside what was delegated is
    refused outright; the caller may resubmit a conforming proposal, but
    this module never invents or clamps a value on its behalf."""

    verdict: Any  # Verdict.ALLOW or Verdict.DENY
    reason: str
    delegation_id: Optional[str] = None
    delegation_exp: Optional[int] = None


class DelegationAuthority:
    """Turns a verified signed delegation + a proposed exact operation into
    ALLOW/DENY. Every authorization-bearing fact (purpose, recipient,
    currency, amount ceiling) is re-derived from the SIGNED delegation and
    compared against the caller's proposal -- never the reverse."""

    def __init__(self, verifier: DelegationVerifier) -> None:
        self.verifier = verifier

    async def authorize(
        self,
        delegation: Any,
        *,
        subject: str,
        tenant_id: str,
        action: str,
        resource: Optional[str],
        recipient: Optional[str],
        currency: Optional[str],
        amount: Optional[float],
        purpose: Optional[str],
        now: Optional[int] = None,
        policy_hash: Optional[str] = None,
    ) -> DelegationAuthorityDecision:
        from .core import Verdict

        res = await self.verifier.verify(
            delegation, subject=subject, tenant_id=tenant_id, action=action,
            resource=resource, now=now, policy_hash=policy_hash,
        )
        if not res.ok:
            return DelegationAuthorityDecision(Verdict.DENY, res.reason)

        # Every check below is UNCONDITIONAL (never ``if delegation.get(...):``
        # guarded) -- issue_delegation() already refuses to sign a delegation
        # missing any of these fields, so a well-formed, successfully-verified
        # delegation always has them. Guarding on presence here would turn a
        # (structurally impossible, but never assume) empty field into a
        # silent skip of the exact-binding check it exists to enforce.
        delegated_purpose = delegation.get("purpose")
        if purpose != delegated_purpose:
            return DelegationAuthorityDecision(
                Verdict.DENY,
                f"PURPOSE_MISMATCH: delegated for {delegated_purpose!r}, proposed {purpose!r}",
                delegation_id=res.delegation_id,
            )

        recipient_scope = delegation.get("recipient_scope", [])
        if not _scope_match(recipient, recipient_scope):
            return DelegationAuthorityDecision(
                Verdict.DENY,
                f"RECIPIENT_SCOPE_MISMATCH: {recipient!r} outside delegated recipient scope",
                delegation_id=res.delegation_id,
            )

        delegated_currency = delegation.get("currency")
        proposed_currency = str(currency).upper() if currency is not None else None
        if proposed_currency != delegated_currency:
            return DelegationAuthorityDecision(
                Verdict.DENY,
                f"CURRENCY_MISMATCH: delegated in {delegated_currency!r}, proposed {proposed_currency!r}",
                delegation_id=res.delegation_id,
            )

        max_amount = res.max_amount
        if not isinstance(amount, (int, float)) or isinstance(amount, bool):
            return DelegationAuthorityDecision(
                Verdict.DENY, f"INVALID_AMOUNT: {amount!r} is not a usable numeric amount",
                delegation_id=res.delegation_id,
            )
        if amount <= 0 or amount > max_amount:
            return DelegationAuthorityDecision(
                Verdict.DENY,
                f"AMOUNT_EXCEEDS_DELEGATION: {amount!r} outside (0, {max_amount!r}] ceiling",
                delegation_id=res.delegation_id,
            )

        return DelegationAuthorityDecision(
            Verdict.ALLOW, f"verified delegation {res.delegation_id}",
            delegation_id=res.delegation_id, delegation_exp=res.exp,
        )


def delegation_velocity_limit(delegation: Mapping[str, Any]) -> VelocityLimit:
    """The atomic, cumulative spending ceiling for ONE delegation, shared
    across every concurrent use and every concurrent gateway instance.
    Reuses ``VelocityRegistry.reserve()`` -- the same atomic Redis-Lua
    sliding-window primitive PR #122 already proved safe against
    transaction splitting and cross-instance races; no new accounting
    primitive is introduced.

    The window spans the delegation's OWN full validity period
    (``exp - nbf``), not an arbitrary fixed window: a shorter window would
    let the sliding log "forget" old spend before the delegation itself
    expires, allowing cumulative spend to exceed ``max_amount`` within one
    still-valid delegation. Once the delegation's own ``exp`` passes,
    ``DelegationVerifier`` denies regardless of this window's state."""
    nbf = int(delegation["nbf"])
    exp = int(delegation["exp"])
    window = max(_MIN_VELOCITY_WINDOW_SECONDS, exp - nbf)
    # on_exceed defaults to Verdict.DENY on VelocityLimit itself -- a breach
    # of the cumulative ceiling is never silently clamped or constrained,
    # consistent with DelegationAuthorityDecision's binary ALLOW/DENY above.
    return VelocityLimit(
        name=f"delegation:{delegation['delegation_id']}",
        window_seconds=window,
        max_amount=float(delegation["max_amount"]),
        aggregate_by=("delegation",),
    )


def delegation_velocity_descriptor(
    delegation: Mapping[str, Any], *, amount: float, currency: Optional[str], recipient: Optional[str],
) -> VelocityDescriptor:
    return VelocityDescriptor(
        dimensions={"delegation": delegation["delegation_id"]},
        amount=float(amount),
        currency=str(currency).upper() if currency is not None else None,
        destination=recipient,
    )


__all__ = [
    "REQUIRED_FIELDS",
    "DelegationAuthority",
    "DelegationAuthorityDecision",
    "DelegationResult",
    "DelegationVerifier",
    "delegation_velocity_descriptor",
    "delegation_velocity_limit",
    "issue_delegation",
]
