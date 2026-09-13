"""Shared test stack for the MCC-Core Constitution invariant suite.

Builds the EXISTING, unmodified MCC-Core components (``SigningKey``,
``DecisionEngine``, ``ExecutionGate``, ``AuthorityModel``,
``EnforcementCoordinator``) exactly as ``tests/test_coordinator.py`` and
``tests/test_mcc_core.py`` already do -- no new authorization framework,
no new decision logic, nothing this suite invents. Every invariant test
in ``tests/constitution/`` builds its scenario from these same primitives
so the suite exercises the real engine, not a stand-in for it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from mcc_core import (
    ActionPolicy,
    AuditLog,
    AuthorityModel,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryVelocityRegistry,
    Mandate,
    MandateRegistry,
    SigningKey,
    Verdict,
)

NOW = 1_790_000_000
AUDIENCE = "constitution-gate"
POLICY_ID = "constitution/v1"
POLICY_HASH = "sha256:" + "c" * 64


class DownDependency:
    """A registry/backend stand-in that always fails -- used to prove
    fail-closed behavior when MCC-Core's own infrastructure is
    unavailable (INV-02)."""

    def __getattr__(self, _name: str) -> Callable[..., Any]:
        async def boom(*_args: Any, **_kwargs: Any) -> Any:
            raise ConnectionError("constitution-test: backend unavailable")
        return boom


class Stack:
    """One real, wired MCC-Core stack: signing key, decision engine, gate,
    audit log, and enforcement coordinator, all backed by the existing
    in-memory registries. ``untrusted_key`` is a SECOND, valid Ed25519
    key that is deliberately NOT in the gate's trust store -- used to
    simulate a token an agent forged/self-signed rather than one MCC-Core
    actually issued."""

    def __init__(
        self,
        tmp_path: Path,
        *,
        nonce_registry: Optional[Any] = None,
        idempotency: Optional[Any] = None,
        velocity: Optional[Any] = None,
        audit: Optional[AuditLog] = None,
        policy_hash: Optional[str] = POLICY_HASH,
    ) -> None:
        self.signing_key = SigningKey.generate("constitution-k1")
        self.untrusted_key = SigningKey.generate("untrusted-k1")
        self.engine = DecisionEngine(
            signing_key=self.signing_key, issuer="mcc/constitution-test", audience=AUDIENCE,
            policy_id=POLICY_ID, policy_hash=POLICY_HASH, token_ttl_seconds=60,
        )
        self.nonce_registry = nonce_registry or InMemoryNonceRegistry()
        self.gate = ExecutionGate(
            trusted_keys={self.signing_key.kid: self.signing_key.public_key()},
            audience=AUDIENCE, nonce_registry=self.nonce_registry, policy_hash=policy_hash,
        )
        self.audit_path = tmp_path / "audit.jsonl"
        self.audit = audit or AuditLog(str(self.audit_path))
        self.idempotency = idempotency or InMemoryIdempotencyRegistry()
        self.velocity = velocity or InMemoryVelocityRegistry()
        self.coordinator = EnforcementCoordinator(
            gate=self.gate, idempotency=self.idempotency, velocity=self.velocity,
            audit=self.audit, velocity_limits_for=lambda action: [],
        )

    def issue_allow(
        self,
        *,
        action: str = "send_email",
        payload: Optional[Dict[str, Any]] = None,
        subject: str = "actor-1",
        tenant_id: str = "tenant-1",
        actor_id: str = "actor-1",
        resource_id: Optional[str] = "resource-1",
        idempotency_key: Optional[str] = None,
        nonce: Optional[str] = None,
        now: int = NOW,
        signing_key: Optional[SigningKey] = None,
    ) -> Dict[str, Any]:
        payload = payload if payload is not None else {"body": "hello"}
        key = signing_key or self.signing_key
        engine = self.engine if key is self.signing_key else DecisionEngine(
            signing_key=key, issuer="mcc/constitution-test", audience=AUDIENCE,
            policy_id=POLICY_ID, policy_hash=POLICY_HASH, token_ttl_seconds=60,
        )
        return engine.issue_token(
            verdict=Verdict.ALLOW, subject=subject, action=action, payload=payload,
            tenant_id=tenant_id, actor_id=actor_id, resource_id=resource_id,
            idempotency_key=idempotency_key, nonce=nonce, now=now,
        )

    def read_audit_entries(self) -> List[Dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        import json

        return [json.loads(line) for line in self.audit_path.read_text().splitlines() if line.strip()]


def build_authority(
    *,
    mandates: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    policies: Optional[List[Dict[str, Any]]] = None,
    default: Verdict = Verdict.DENY,
) -> AuthorityModel:
    """A minimal, declarative AuthorityModel -- the same construction
    ``gateway/pilot_policy.py`` and every existing authority test use.
    Defaults to deny-by-default with no mandates and no policies, so a
    test must explicitly grant whatever authority its scenario needs."""
    registry = MandateRegistry.from_config(mandates or {})
    policy_objs = [ActionPolicy.from_config(p) for p in (policies or [])]
    return AuthorityModel(registry=registry, policies=policy_objs, default=default)
