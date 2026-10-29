"""Shared stack construction for the P2-A benchmark harness and its
negative-control tests (``tests/test_p2a_authority_plane_negative_controls.py``).

Builds the REAL, unmodified governed stack -- the same classes and the
same ``GovernanceService`` methods production code calls -- never a
parallel or simplified reimplementation. The only thing "mocked" is the
final actuator (the external side effect), which is a cheap in-process
counter -- there is no real network call anywhere in this module.

Two backends:

* ``"memory"`` (default): ``InMemory*`` registries, no external process.
* ``"redis"``: real ``redis-server`` backed registries, via
  ``MCC_REDIS_URL`` (default ``redis://127.0.0.1:6379/0``), the same
  convention ``tests/test_delegation_governance_service.py`` and
  ``scripts/redis_*_smoke.py`` already use. Caller is responsible for a
  reachable Redis instance; this module does not start one.
"""

from __future__ import annotations

import os
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from gateway.governance_service import GovernanceService
from gateway.trust import Issuer, IssuerKey, TrustSet
from mcc_core import (
    ApprovalService,
    AuditLog,
    DecisionEngine,
    DelegationVerifier,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryApprovalRegistry,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryRevocationRegistry,
    InMemoryVelocityRegistry,
    ProfileRegistry,
    RedisIdempotencyRegistry,
    RedisVelocityRegistry,
    SigningKey,
    VelocityLimit,
    issue_delegation,
    issue_mandate,
)

ACTION = "send_payment"
RESOURCE = "acct-1"
RECIPIENT = "vendor-42"
TENANT = "tenant-1"
PURPOSE = "vendor_payment"
POLICY_HASH = "sha256:" + "0" * 64
REDIS_URL = os.environ.get("MCC_REDIS_URL", "redis://127.0.0.1:6379/0")


def _redis_client():
    import redis.asyncio as redis_async

    return redis_async.from_url(REDIS_URL)


def context(**overrides: Any) -> Dict[str, Any]:
    ctx = {"source": RESOURCE, "beneficiary_id": RECIPIENT, "amount": 25.0, "currency": "EUR"}
    ctx.update(overrides)
    return ctx


def audit_log() -> AuditLog:
    d = tempfile.mkdtemp(prefix="mcc-bench-")
    return AuditLog(str(Path(d) / "audit.jsonl"))


@dataclass
class Stack:
    """A fully wired, real governed stack plus the issuance material needed
    to drive it (a trusted mandate issuer and a trusted delegation owner),
    and an instrumented actuator so every scenario can assert an exact
    call count."""

    backend: str
    engine: DecisionEngine
    gate: ExecutionGate
    coordinator: EnforcementCoordinator
    audit: AuditLog
    service: GovernanceService
    mandate_issuer_key: SigningKey
    delegation_owner_key: SigningKey
    seen: List[Any] = field(default_factory=list)

    def reset_seen(self) -> None:
        self.seen.clear()

    def mandate(self, *, now: int, **overrides: Any) -> Dict[str, Any]:
        kw = dict(
            issuer="partner/acme", subject="agent/payments-bot",
            action_scope=[ACTION], resource_scope=[RESOURCE],
            constraints={"max_amount": 10_000.0},
            not_before=now - 10, not_after=now + 3600, issued_at=now - 10,
            policy_hash=POLICY_HASH,
        )
        kw.update(overrides)
        return issue_mandate(self.mandate_issuer_key, **kw)

    def delegation(self, *, now: int, **overrides: Any) -> Dict[str, Any]:
        kw = dict(
            owner_id="owner/alex", subject="agent/payments-bot", tenant_id=TENANT,
            purpose=PURPOSE, action_scope=[ACTION], resource_scope=[RESOURCE],
            recipient_scope=["vendor-*"], currency="EUR", max_amount=10_000.0,
            not_before=now - 10, not_after=now + 3600, issued_at=now - 10,
            consent_ref="sha256:consent-" + uuid.uuid4().hex,
        )
        kw.update(overrides)
        return issue_delegation(self.delegation_owner_key, **kw)

    async def exec_mandate(self, mandate: Dict[str, Any], *, idempotency_key: str, **overrides: Any):
        kw = dict(mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
                  context=context(), tenant_id=TENANT)
        kw.update(overrides)
        return await self.service.execute_with_mandate(idempotency_key=idempotency_key, **kw)

    async def exec_delegation(self, delegation: Dict[str, Any], *, idempotency_key: str, **overrides: Any):
        kw = dict(delegation=delegation, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
                  purpose=PURPOSE, context=context(), tenant_id=TENANT)
        kw.update(overrides)
        return await self.service.execute_with_delegation(idempotency_key=idempotency_key, **kw)


def build_stack(
    *,
    backend: str = "memory",
    velocity_limits: Optional[Callable[[str], List[VelocityLimit]]] = None,
    revocation_registry: Optional[Any] = None,
) -> Stack:
    """Build one fully independent stack instance -- a fresh signing key,
    audit log (own temp file), and (for the memory backend) fresh
    in-process registries every call, so concurrent callers in the same
    process never share mutable state by accident. For the Redis backend,
    every instance shares the SAME Redis keyspace by design (that is what
    is being measured) -- callers that need isolation should flush the DB
    themselves or use distinct key prefixes via distinct ``AuditLog``
    paths and a dedicated test/benchmark Redis DB index.
    """
    if backend not in ("memory", "redis"):
        raise ValueError(f"unknown backend {backend!r}")

    signing_key = SigningKey.generate(f"bench-gw-{uuid.uuid4().hex[:8]}")
    engine = DecisionEngine(
        signing_key=signing_key, issuer="mcc/bench", audience="bench",
        policy_id="bench/v1", policy_hash=POLICY_HASH, token_ttl_seconds=60,
    )
    nonce_registry = InMemoryNonceRegistry()
    gate = ExecutionGate(
        trusted_keys={signing_key.kid: signing_key.public_key()}, audience="bench",
        nonce_registry=nonce_registry, policy_hash=POLICY_HASH,
    )
    audit = audit_log()
    revocation = revocation_registry if revocation_registry is not None else InMemoryRevocationRegistry()

    if backend == "memory":
        idempotency = InMemoryIdempotencyRegistry()
        velocity = InMemoryVelocityRegistry()
    else:
        client = _redis_client()
        idempotency = RedisIdempotencyRegistry(client)
        velocity = RedisVelocityRegistry(client)

    mandate_issuer_key = SigningKey.generate(f"bench-issuer-{uuid.uuid4().hex[:8]}")
    trust_set = TrustSet()
    trust_set.add_issuer(Issuer(issuer_id="partner/acme", keys=[
        IssuerKey(kid=mandate_issuer_key.kid, public_key=mandate_issuer_key.public_key()),
    ]))

    delegation_owner_key = SigningKey.generate(f"bench-owner-{uuid.uuid4().hex[:8]}")
    delegation_verifier = DelegationVerifier(
        trusted_owner_keys={delegation_owner_key.kid: delegation_owner_key.public_key()},
        revocation_registry=revocation,
    )

    approver_key = SigningKey.generate(f"bench-approver-{uuid.uuid4().hex[:8]}")
    # The gateway is itself the approval issuer: trust its own approver
    # public key by construction (mirrors build_governance_service()'s
    # add_runtime_issuer call), so execute_with_approval's re-resolution
    # of the signed approval mandate's kid against trust_set succeeds.
    trust_set.add_runtime_issuer("mcc/approvals", approver_key.kid, approver_key.public_key())
    # ONE ApprovalService instance, shared by the coordinator (which
    # consumes the single-use approval_id at actuation -- see
    # EnforcementCoordinator.enforce()) and the GovernanceService (which
    # mints it via approve()). Passing two separate instances would split
    # the single-use state in two and silently defeat replay protection --
    # confirmed by reproduction while building this harness: the coordinator
    # must hold the SAME approvals object the service mints approvals from.
    approvals = ApprovalService(InMemoryApprovalRegistry(), approver_key)
    seen: List[Any] = []

    async def upstream(action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        seen.append((action, dict(payload)))
        return {"ok": True}

    coordinator = EnforcementCoordinator(
        gate=gate, idempotency=idempotency, velocity=velocity, audit=audit,
        profiles=ProfileRegistry.default_pilot(),
        velocity_limits_for=velocity_limits or (lambda action: []),
        revocation_registry=revocation, approvals=approvals,
    )

    service = GovernanceService(
        engine=engine, coordinator=coordinator, trust_set=trust_set,
        revocation_registry=revocation, approvals=approvals,
        profiles=ProfileRegistry.default_pilot(), upstream=upstream, policy_hash=POLICY_HASH,
        delegation_verifier=delegation_verifier,
    )

    return Stack(
        backend=backend, engine=engine, gate=gate, coordinator=coordinator, audit=audit,
        service=service, mandate_issuer_key=mandate_issuer_key,
        delegation_owner_key=delegation_owner_key, seen=seen,
    )


def now() -> int:
    return int(time.time())
