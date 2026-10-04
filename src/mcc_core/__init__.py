"""MCC-Core runtime security primitives.

The model proposes.
MCC-Core decides.
The gate enforces.
The audit chain records.

Import model (PR #50 decoupling)
--------------------------------
This package exposes the same public names as before, but resolves them **lazily**
(PEP 562 ``__getattr__``). Importing ``mcc_core`` — or importing a single pure
submodule such as ``from mcc_core.signing import canonical_bytes`` — no longer
eagerly loads the whole governance engine (gate, coordinator, authority, consensus,
mandate, audit, …). Each public name is imported on first access, so existing
usages like ``from mcc_core import ExecutionGate`` keep working unchanged while the
canonical-protocol / Adapter-SDK import path stays lightweight and governance-free.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

# Public name -> submodule that defines it. This is the single source of truth for
# what ``mcc_core`` re-exports; ``__all__`` is derived from it so the two never drift.
_EXPORTS: dict[str, str] = {
    # approvals
    "ApprovalConfigError": "approvals", "ApprovalRecord": "approvals",
    "ApprovalService": "approvals", "ApprovalState": "approvals",
    "ConsumeResult": "approvals", "InMemoryApprovalRegistry": "approvals",
    "RedisApprovalRegistry": "approvals", "approval_registry_from_env": "approvals",
    # audit
    "AuditLog": "audit",
    # authority
    "ActionPolicy": "authority", "AuthorityDecision": "authority",
    "AuthorityModel": "authority", "Mandate": "authority",
    "MandateRegistry": "authority", "apply_constraints": "authority",
    # authority_policy (independent authority-side ESCALATE auto-approval policy)
    "AuthorityPolicy": "authority_policy", "AuthorityPolicyDecision": "authority_policy",
    "AuthorityPolicyError": "authority_policy", "AuthorityRule": "authority_policy",
    "authority_policy_from_env": "authority_policy",
    # challenge
    "ChallengeConfigError": "challenge", "ChallengeRecord": "challenge",
    "ChallengeService": "challenge", "ChallengeState": "challenge",
    "InMemoryChallengeRegistry": "challenge", "RedisChallengeRegistry": "challenge",
    "challenge_registry_from_env": "challenge",
    # coordinator
    "ActuationResult": "coordinator", "ActuationStatus": "coordinator",
    "EnforcementCoordinator": "coordinator",
    # core
    "EXECUTABLE_VERDICTS": "core", "DecisionEngine": "core",
    "TokenNotIssuable": "core", "Verdict": "core",
    # gate
    "ExecutionGate": "gate", "GateResult": "gate",
    # idempotency
    "IdempotencyBackendUnavailable": "idempotency", "IdempotencyConfigError": "idempotency",
    "IdempotencyState": "idempotency", "InMemoryIdempotencyRegistry": "idempotency",
    "ReconcileResult": "idempotency", "ReconcileStatus": "idempotency",
    "RedisIdempotencyRegistry": "idempotency", "ReserveResult": "idempotency",
    "ReserveStatus": "idempotency", "StateRecord": "idempotency",
    "idempotency_registry_from_env": "idempotency",
    # mandate
    "InMemoryRevocationRegistry": "mandate", "MandateAuthority": "mandate",
    "MandateAuthorityDecision": "mandate", "MandateResult": "mandate",
    "MandateVerifier": "mandate", "RedisRevocationRegistry": "mandate",
    "RevocationConfigError": "mandate", "RevocationRegistry": "mandate",
    "RevocationStatus": "mandate", "issue_mandate": "mandate",
    "revocation_registry_from_env": "mandate",
    # nonce
    "InMemoryNonceRegistry": "nonce", "NonceConfigError": "nonce",
    "NonceRegistry": "nonce", "RedisNonceRegistry": "nonce",
    "nonce_registry_from_env": "nonce",
    # deployment_mode
    "DeploymentModeConfigError": "deployment_mode",
    "deployment_mode_from_env": "deployment_mode",
    "is_enforcement_mode": "deployment_mode",
    # consensus
    "ConsensusPolicy": "consensus", "ConsensusResult": "consensus",
    "ConsensusVerifier": "consensus", "issue_vote": "consensus",
    # policy
    "PolicyBundle": "policy", "PolicyBundleError": "policy",
    # redis_client
    "RedisConfigError": "redis_client", "build_redis_client": "redis_client",
    "redis_client_from_env": "redis_client",
    # version
    "RUNTIME_VERSION": "version", "runtime_version": "version",
    # profiles
    "ActionProfile": "profiles", "InfraProfile": "profiles",
    "PaymentProfile": "profiles", "ProfileError": "profiles",
    "ProfileRegistry": "profiles", "RoboticsProfile": "profiles",
    "VelocityDescriptor": "profiles",
    # velocity
    "InMemoryVelocityRegistry": "velocity", "RedisVelocityRegistry": "velocity",
    "VelocityConfigError": "velocity", "VelocityLimit": "velocity",
    "VelocityOutcome": "velocity", "velocity_registry_from_env": "velocity",
    # signing (pure — no governance engine)
    "SigningKey": "signing", "canonical_bytes": "signing", "hash_action": "signing",
    "hash_document": "signing", "hash_payload": "signing", "is_valid_digest": "signing",
    "public_key_from_b64": "signing", "sha256_hex": "signing", "verify_token": "signing",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    """Lazily resolve a public name to its defining submodule (PEP 562)."""
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib
    submodule = importlib.import_module(f".{module}", __name__)
    value = getattr(submodule, name)
    globals()[name] = value  # cache so subsequent lookups skip __getattr__
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_EXPORTS))


if TYPE_CHECKING:  # help static type-checkers see the re-exported names
    from .approvals import (  # noqa: F401
        ApprovalConfigError,
        ApprovalRecord,
        ApprovalService,
        ApprovalState,
        ConsumeResult,
        InMemoryApprovalRegistry,
        RedisApprovalRegistry,
        approval_registry_from_env,
    )
    from .audit import AuditLog  # noqa: F401
    from .authority import (  # noqa: F401
        ActionPolicy,
        AuthorityDecision,
        AuthorityModel,
        Mandate,
        MandateRegistry,
        apply_constraints,
    )
    from .authority_policy import (  # noqa: F401
        AuthorityPolicy,
        AuthorityPolicyDecision,
        AuthorityPolicyError,
        AuthorityRule,
        authority_policy_from_env,
    )
    from .challenge import (  # noqa: F401
        ChallengeConfigError,
        ChallengeRecord,
        ChallengeService,
        ChallengeState,
        InMemoryChallengeRegistry,
        RedisChallengeRegistry,
        challenge_registry_from_env,
    )
    from .consensus import (  # noqa: F401
        ConsensusPolicy,
        ConsensusResult,
        ConsensusVerifier,
        issue_vote,
    )
    from .coordinator import (  # noqa: F401
        ActuationResult,
        ActuationStatus,
        EnforcementCoordinator,
    )
    from .core import (  # noqa: F401
        EXECUTABLE_VERDICTS,
        DecisionEngine,
        TokenNotIssuable,
        Verdict,
    )
    from .gate import ExecutionGate, GateResult  # noqa: F401
    from .idempotency import (  # noqa: F401
        IdempotencyBackendUnavailable,
        IdempotencyConfigError,
        IdempotencyState,
        InMemoryIdempotencyRegistry,
        ReconcileResult,
        ReconcileStatus,
        RedisIdempotencyRegistry,
        ReserveResult,
        ReserveStatus,
        StateRecord,
        idempotency_registry_from_env,
    )
    from .mandate import (  # noqa: F401
        InMemoryRevocationRegistry,
        MandateAuthority,
        MandateAuthorityDecision,
        MandateResult,
        MandateVerifier,
        RedisRevocationRegistry,
        RevocationConfigError,
        RevocationRegistry,
        RevocationStatus,
        issue_mandate,
        revocation_registry_from_env,
    )
    from .deployment_mode import (  # noqa: F401
        DeploymentModeConfigError,
        deployment_mode_from_env,
        is_enforcement_mode,
    )
    from .nonce import (  # noqa: F401
        InMemoryNonceRegistry,
        NonceConfigError,
        NonceRegistry,
        RedisNonceRegistry,
        nonce_registry_from_env,
    )
    from .policy import PolicyBundle, PolicyBundleError  # noqa: F401
    from .profiles import (  # noqa: F401
        ActionProfile,
        InfraProfile,
        PaymentProfile,
        ProfileError,
        ProfileRegistry,
        RoboticsProfile,
        VelocityDescriptor,
    )
    from .redis_client import (  # noqa: F401
        RedisConfigError,
        build_redis_client,
        redis_client_from_env,
    )
    from .signing import (  # noqa: F401
        SigningKey,
        canonical_bytes,
        hash_action,
        hash_document,
        hash_payload,
        is_valid_digest,
        public_key_from_b64,
        sha256_hex,
        verify_token,
    )
    from .velocity import (  # noqa: F401
        InMemoryVelocityRegistry,
        RedisVelocityRegistry,
        VelocityConfigError,
        VelocityLimit,
        VelocityOutcome,
        velocity_registry_from_env,
    )
    from .version import RUNTIME_VERSION, runtime_version  # noqa: F401
