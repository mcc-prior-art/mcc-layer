"""MCC-Core runtime security primitives.

The model proposes.
MCC-Core decides.
The gate enforces.
The audit chain records.
"""

from .approvals import (
    ApprovalConfigError,
    ApprovalRecord,
    ApprovalService,
    ApprovalState,
    ConsumeResult,
    InMemoryApprovalRegistry,
    RedisApprovalRegistry,
    approval_registry_from_env,
)
from .audit import AuditLog
from .authority import (
    ActionPolicy,
    AuthorityDecision,
    AuthorityModel,
    Mandate,
    MandateRegistry,
    apply_constraints,
)
from .challenge import (
    ChallengeConfigError,
    ChallengeRecord,
    ChallengeService,
    ChallengeState,
    InMemoryChallengeRegistry,
    RedisChallengeRegistry,
    challenge_registry_from_env,
)
from .coordinator import ActuationResult, ActuationStatus, EnforcementCoordinator
from .core import EXECUTABLE_VERDICTS, DecisionEngine, TokenNotIssuable, Verdict
from .gate import ExecutionGate, GateResult
from .idempotency import (
    IdempotencyConfigError,
    IdempotencyState,
    InMemoryIdempotencyRegistry,
    RedisIdempotencyRegistry,
    ReserveResult,
    ReserveStatus,
    idempotency_registry_from_env,
)
from .mandate import (
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
from .nonce import (
    InMemoryNonceRegistry,
    NonceConfigError,
    NonceRegistry,
    RedisNonceRegistry,
    nonce_registry_from_env,
)
from .consensus import (
    ConsensusPolicy,
    ConsensusResult,
    ConsensusVerifier,
    issue_vote,
)
from .policy import PolicyBundle, PolicyBundleError
from .redis_client import (
    RedisConfigError,
    build_redis_client,
    redis_client_from_env,
)
from .version import RUNTIME_VERSION, runtime_version
from .profiles import (
    ActionProfile,
    InfraProfile,
    PaymentProfile,
    ProfileError,
    ProfileRegistry,
    RoboticsProfile,
    VelocityDescriptor,
)
from .velocity import (
    InMemoryVelocityRegistry,
    RedisVelocityRegistry,
    VelocityConfigError,
    VelocityLimit,
    VelocityOutcome,
    velocity_registry_from_env,
)
from .signing import (
    SigningKey,
    canonical_bytes,
    hash_action,
    hash_payload,
    public_key_from_b64,
    sha256_hex,
    verify_token,
)

__all__ = [
    "ActionPolicy",
    "ActionProfile",
    "ActuationResult",
    "ActuationStatus",
    "ApprovalConfigError",
    "ApprovalRecord",
    "ApprovalService",
    "ApprovalState",
    "ConsumeResult",
    "InMemoryApprovalRegistry",
    "RedisApprovalRegistry",
    "approval_registry_from_env",
    "AuditLog",
    "ChallengeConfigError",
    "ChallengeRecord",
    "ChallengeService",
    "ChallengeState",
    "InMemoryChallengeRegistry",
    "RedisChallengeRegistry",
    "challenge_registry_from_env",
    "AuthorityDecision",
    "AuthorityModel",
    "DecisionEngine",
    "EXECUTABLE_VERDICTS",
    "EnforcementCoordinator",
    "IdempotencyConfigError",
    "IdempotencyState",
    "InMemoryIdempotencyRegistry",
    "InMemoryVelocityRegistry",
    "InfraProfile",
    "Mandate",
    "MandateRegistry",
    "ExecutionGate",
    "GateResult",
    "InMemoryNonceRegistry",
    "InMemoryRevocationRegistry",
    "MandateAuthority",
    "MandateAuthorityDecision",
    "MandateResult",
    "MandateVerifier",
    "NonceConfigError",
    "NonceRegistry",
    "PaymentProfile",
    "RedisRevocationRegistry",
    "RevocationConfigError",
    "RevocationRegistry",
    "RevocationStatus",
    "issue_mandate",
    "revocation_registry_from_env",
    "ConsensusPolicy",
    "ConsensusResult",
    "ConsensusVerifier",
    "issue_vote",
    "ProfileError",
    "ProfileRegistry",
    "RoboticsProfile",
    "RedisIdempotencyRegistry",
    "RedisNonceRegistry",
    "RedisVelocityRegistry",
    "ReserveResult",
    "ReserveStatus",
    "VelocityConfigError",
    "VelocityDescriptor",
    "VelocityLimit",
    "VelocityOutcome",
    "idempotency_registry_from_env",
    "nonce_registry_from_env",
    "velocity_registry_from_env",
    "PolicyBundle",
    "PolicyBundleError",
    "RedisConfigError",
    "build_redis_client",
    "redis_client_from_env",
    "RUNTIME_VERSION",
    "runtime_version",
    "SigningKey",
    "TokenNotIssuable",
    "Verdict",
    "apply_constraints",
    "canonical_bytes",
    "hash_action",
    "hash_payload",
    "public_key_from_b64",
    "sha256_hex",
    "verify_token",
]
