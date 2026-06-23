"""Signed, revocable mandates — a cryptographically verifiable authority object.

A mandate is *not* an identity and *not* an execution decision token. It is a
standing, Ed25519-signed grant from an issuer to a subject: "this subject may
take these actions on these resources, within these constraints, for this
window." The decision engine consumes a *verified* mandate and binds its
``mandate_id`` into the issued decision token, so the authority that justified
the token is auditable and revocable.

Domain-neutral by construction: a mandate speaks only of generic action and
resource *scopes* (glob patterns) and an opaque ``constraints`` map. It knows
nothing about payments, robots, or infrastructure.

Fail-closed: a mandate that is missing, malformed, expired, not-yet-valid,
signed by an untrusted key, mismatched in subject/action/resource/policy, or
revoked yields no authority. When a mandate requires a revocation check and the
revocation service cannot answer, that is also a denial — never a silent
"assume active".
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .signing import SigningKey, canonical_bytes, verify_token

REQUIRED_FIELDS = (
    "mandate_id", "issuer", "subject", "action_scope", "resource_scope",
    "constraints", "nbf", "exp", "iat", "revocation_required",
)

DEFAULT_OP_TIMEOUT_SECONDS = 0.5


def issue_mandate(
    signing_key: SigningKey,
    *,
    issuer: str,
    subject: str,
    action_scope: List[str],
    resource_scope: List[str],
    constraints: Optional[Dict[str, Any]] = None,
    not_before: int,
    not_after: int,
    issued_at: Optional[int] = None,
    revocation_required: bool = False,
    policy_hash: Optional[str] = None,
    mandate_id: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Issue a signed mandate. The issuer's ``signing_key`` carries the kid that
    a verifier must trust. ``policy_hash`` optionally binds the mandate to a
    trust-set / policy version. ``extra`` adds further signature-covered claims
    (e.g. an approval's action_hash / transaction_id) without changing the
    universal verification path, which ignores unknown fields."""
    iat = int(issued_at if issued_at is not None else time.time())
    claims = {
        "mandate_id": mandate_id or f"mdt-{uuid.uuid4().hex}",
        "issuer": issuer,
        "subject": subject,
        "action_scope": list(action_scope),
        "resource_scope": list(resource_scope),
        "constraints": dict(constraints or {}),
        "iat": iat,
        "nbf": int(not_before),
        "exp": int(not_after),
        "revocation_required": bool(revocation_required),
        "policy_hash": policy_hash,
    }
    if extra:
        # Reserved fields cannot be overridden by extra claims.
        for key in extra:
            if key in claims or key in ("kid", "sig"):
                raise ValueError(f"extra mandate claim '{key}' is reserved")
        claims.update(extra)
    return signing_key.sign_token(claims)


@dataclass(frozen=True)
class MandateAuthorityDecision:
    verdict: Any  # Verdict
    reason: str
    constraints: Dict[str, Any] = field(default_factory=dict)
    mandate_id: Optional[str] = None
    forward_context: Dict[str, Any] = field(default_factory=dict)
    applied_changes: List[str] = field(default_factory=list)


class MandateAuthority:
    """Turns a *verified signed mandate* into an execution verdict, reusing the
    same constraint semantics as the config-driven AuthorityModel: within the
    mandate's bounds -> ALLOW; clampable breach -> CONSTRAIN (body rewritten);
    unclampable breach or failed verification -> DENY. Domain-neutral."""

    def __init__(self, verifier: "MandateVerifier") -> None:
        self.verifier = verifier

    async def authorize(
        self,
        mandate: Any,
        *,
        subject: str,
        action: str,
        resource: Optional[str],
        context: Dict[str, Any],
        now: Optional[int] = None,
        policy_hash: Optional[str] = None,
    ) -> MandateAuthorityDecision:
        from .authority import _constraint_violations, apply_constraints
        from .core import Verdict

        res = await self.verifier.verify(
            mandate, subject=subject, action=action, resource=resource,
            now=now, policy_hash=policy_hash,
        )
        if not res.ok:
            return MandateAuthorityDecision(Verdict.DENY, res.reason)

        violations = _constraint_violations(res.constraints, context)
        if not violations:
            return MandateAuthorityDecision(
                Verdict.ALLOW, f"verified mandate {res.mandate_id}",
                constraints=res.constraints, mandate_id=res.mandate_id,
                forward_context=dict(context),
            )
        constrained, changes = apply_constraints(res.constraints, context)
        if _constraint_violations(res.constraints, constrained):
            return MandateAuthorityDecision(
                Verdict.DENY,
                f"mandate {res.mandate_id} held but request cannot be constrained into compliance",
                constraints=res.constraints, mandate_id=res.mandate_id,
            )
        return MandateAuthorityDecision(
            Verdict.CONSTRAIN, f"mandate {res.mandate_id} bounds applied: {'; '.join(changes)}",
            constraints=res.constraints, mandate_id=res.mandate_id,
            forward_context=constrained, applied_changes=changes,
        )


class RevocationStatus(str, Enum):
    ACTIVE = "ACTIVE"            # confirmed not revoked
    REVOKED = "REVOKED"         # confirmed revoked
    UNAVAILABLE = "UNAVAILABLE"  # could not confirm -> fail closed


@dataclass(frozen=True)
class MandateResult:
    ok: bool
    reason: str
    mandate_id: Optional[str] = None
    subject: Optional[str] = None
    constraints: Dict[str, Any] = field(default_factory=dict)


def _scope_match(value: Optional[str], scope: List[str]) -> bool:
    import fnmatch
    if value is None:
        # A mandate that scopes a dimension requires that dimension to be named.
        return False
    return any(fnmatch.fnmatchcase(value, pat) for pat in scope)


class MandateVerifier:
    """Verifies a signed mandate against the operation it is meant to authorize.

    Order: signature & trusted issuer -> structural completeness -> validity
    window -> subject match -> action scope -> resource scope -> policy binding
    -> revocation. Any failure denies; any exception denies (fail-closed).
    """

    def __init__(
        self,
        *,
        trusted_keys: Dict[str, Ed25519PublicKey],
        revocation_registry: "Optional[RevocationRegistry]" = None,
    ) -> None:
        self.trusted_keys = trusted_keys
        self.revocation_registry = revocation_registry

    async def verify(
        self,
        mandate: Any,
        *,
        subject: str,
        action: str,
        resource: Optional[str],
        now: Optional[int] = None,
        policy_hash: Optional[str] = None,
    ) -> MandateResult:
        try:
            return await self._verify(
                mandate, subject=subject, action=action, resource=resource,
                now=now, policy_hash=policy_hash,
            )
        except Exception:
            return MandateResult(False, "MANDATE_ERROR: fail-closed")

    async def _verify(self, mandate, *, subject, action, resource, now, policy_hash) -> MandateResult:
        if not isinstance(mandate, dict) or not mandate:
            return MandateResult(False, "NO_MANDATE: no authority presented")

        public_key = self.trusted_keys.get(mandate.get("kid"))
        if public_key is None:
            return MandateResult(False, "UNTRUSTED_ISSUER: unknown or revoked issuer key")
        if not verify_token(mandate, public_key):
            return MandateResult(False, "INVALID_MANDATE_SIGNATURE: Ed25519 verification failed")

        for required in REQUIRED_FIELDS:
            if required not in mandate:
                return MandateResult(False, f"MALFORMED_MANDATE: missing {required}")

        ts = int(now if now is not None else time.time())
        nbf, exp = mandate.get("nbf"), mandate.get("exp")
        if not isinstance(nbf, int) or not isinstance(exp, int):
            return MandateResult(False, "MALFORMED_MANDATE: invalid validity window")
        if ts < nbf:
            return MandateResult(False, "MANDATE_NOT_YET_VALID")
        if ts >= exp:
            return MandateResult(False, "MANDATE_EXPIRED")

        if mandate.get("subject") != subject:
            return MandateResult(False, "SUBJECT_MISMATCH: mandate not issued to this subject")

        if not _scope_match(action, mandate.get("action_scope", [])):
            return MandateResult(False, "ACTION_SCOPE_MISMATCH: action outside mandate scope")

        # Resource scope is enforced whenever the mandate constrains resources.
        resource_scope = mandate.get("resource_scope", [])
        if resource_scope and not _scope_match(resource, resource_scope):
            return MandateResult(False, "RESOURCE_SCOPE_MISMATCH: resource outside mandate scope")

        bound_policy = mandate.get("policy_hash")
        if bound_policy is not None and policy_hash is not None and bound_policy != policy_hash:
            return MandateResult(False, "POLICY_BINDING_MISMATCH: mandate bound to another policy")

        if mandate.get("revocation_required"):
            if self.revocation_registry is None:
                return MandateResult(False, "REVOCATION_REQUIRED: no revocation service configured; fail-closed")
            status = await self.revocation_registry.check(mandate["mandate_id"])
            if status == RevocationStatus.REVOKED:
                return MandateResult(False, "MANDATE_REVOKED")
            if status != RevocationStatus.ACTIVE:
                return MandateResult(False, "REVOCATION_UNAVAILABLE: cannot confirm mandate active; fail-closed")

        return MandateResult(
            True, "MANDATE_VERIFIED",
            mandate_id=mandate["mandate_id"], subject=subject,
            constraints=dict(mandate.get("constraints", {})),
        )


# --------------------------------------------------------------------------
# Revocation registry
# --------------------------------------------------------------------------

class RevocationRegistry:
    """Interface marker. Implementations return RevocationStatus from ``check``."""


class InMemoryRevocationRegistry(RevocationRegistry):
    """Single-process revocation list (dev / tests)."""

    def __init__(self) -> None:
        self._revoked: set = set()

    async def revoke(self, mandate_id: str) -> bool:
        self._revoked.add(mandate_id)
        return True

    async def check(self, mandate_id: str) -> RevocationStatus:
        if not mandate_id or not isinstance(mandate_id, str):
            return RevocationStatus.UNAVAILABLE
        return RevocationStatus.REVOKED if mandate_id in self._revoked else RevocationStatus.ACTIVE


class RedisRevocationRegistry(RevocationRegistry):
    """Durable, multi-instance revocation list backed by a Redis set.

    Fail-closed: a Redis error/timeout yields ``UNAVAILABLE`` (the verifier
    treats that as a denial for revocation-required mandates), never a silent
    "assume active"."""

    def __init__(self, redis_client: Any, *, key: str = "mcc:revoked",
                 op_timeout_seconds: float = DEFAULT_OP_TIMEOUT_SECONDS) -> None:
        self._redis = redis_client
        self._key = key
        self._op_timeout = op_timeout_seconds

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> "RedisRevocationRegistry":
        import redis.asyncio as redis
        op_timeout = kwargs.get("op_timeout_seconds", DEFAULT_OP_TIMEOUT_SECONDS)
        client = redis.from_url(
            url, socket_timeout=op_timeout,
            socket_connect_timeout=kwargs.pop("connect_timeout_seconds", 1.0),
            decode_responses=True,
        )
        return cls(client, **kwargs)

    async def revoke(self, mandate_id: str) -> bool:
        try:
            await asyncio.wait_for(self._redis.sadd(self._key, mandate_id), timeout=self._op_timeout)
            return True
        except Exception:
            return False

    async def check(self, mandate_id: str) -> RevocationStatus:
        if not mandate_id or not isinstance(mandate_id, str):
            return RevocationStatus.UNAVAILABLE
        try:
            is_member = await asyncio.wait_for(
                self._redis.sismember(self._key, mandate_id), timeout=self._op_timeout
            )
        except Exception:
            return RevocationStatus.UNAVAILABLE
        return RevocationStatus.REVOKED if is_member else RevocationStatus.ACTIVE


class RevocationConfigError(Exception):
    """Raised when the revocation backend is misconfigured (fail-closed start)."""


def revocation_registry_from_env(env: Optional[Mapping[str, str]] = None):
    """``MCC_REVOCATION_BACKEND`` = ``memory`` (default) or ``redis`` (requires
    ``MCC_REDIS_URL``). No silent fallback from redis to in-memory."""
    env = os.environ if env is None else env
    backend = env.get("MCC_REVOCATION_BACKEND", "memory").strip().lower()
    if backend in ("memory", "inmemory", "in-memory"):
        return InMemoryRevocationRegistry()
    if backend == "redis":
        url = env.get("MCC_REDIS_URL", "").strip()
        if not url:
            raise RevocationConfigError(
                "MCC_REVOCATION_BACKEND=redis requires MCC_REDIS_URL; refusing to "
                "fall back to in-memory revocation in an enforcement deployment"
            )
        return RedisRevocationRegistry.from_url(url)
    raise RevocationConfigError(
        f"unknown MCC_REVOCATION_BACKEND={backend!r}; expected 'memory' or 'redis'"
    )
