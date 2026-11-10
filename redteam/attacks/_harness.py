"""Shared red-team harness.

Builds the REAL enforcement stack in-process (no mocks of the gate, signature
verification, authority evaluation, or coordinator):

    GovernanceService -> MandateAuthority/MandateVerifier -> DecisionEngine
        -> EnforcementCoordinator -> ExecutionGate -> upstream actuator

The only test double is the upstream actuator itself: it records every call it
receives. A bypass is counted ONLY when that actuator was actually invoked for
an action/payload that policy should have blocked.
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for p in (str(ROOT / "src"), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from gateway.governance_service import GovernanceService  # noqa: E402
from gateway.trust import TrustSet  # noqa: E402
from mcc_core import (  # noqa: E402
    ApprovalService,
    AuditLog,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryApprovalRegistry,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryRevocationRegistry,
    InMemoryVelocityRegistry,
    ProfileRegistry,
    SigningKey,
)
from mcc_core.mandate import issue_mandate  # noqa: E402

run = asyncio.run
POLICY_HASH = "sha256:" + "0" * 64
TENANT = "tenant-1"
ACTOR = "agent/payments-bot"
ACTION = "send_payment"
RESOURCE = "acct-1"


class Stack:
    """One isolated, fully wired MCC-Core enforcement stack."""

    def __init__(self, *, velocity_limits_for=None, nonce_registry=None,
                 idempotency=None, audit_path=None, upstream_raises=False):
        self.signing_key = SigningKey.generate("gw-signing-1")
        self.issuer_key = SigningKey.generate("issuer-1")
        self.approver_key = SigningKey.generate("approver-1")
        self.engine = DecisionEngine(
            signing_key=self.signing_key, issuer="mcc/core", audience="pilot",
            policy_id="pilot/v1", policy_hash=POLICY_HASH,
        )
        self.nonces = nonce_registry or InMemoryNonceRegistry()
        self.gate = ExecutionGate(
            trusted_keys={self.signing_key.kid: self.signing_key.public_key()},
            audience="pilot", nonce_registry=self.nonces, policy_hash=POLICY_HASH,
        )
        self.audit_path = audit_path or str(
            Path(tempfile.mkdtemp(prefix="mcc-redteam-")) / "audit.jsonl")
        self.audit = AuditLog(self.audit_path)
        self.revocation = InMemoryRevocationRegistry()
        self.approval_registry = InMemoryApprovalRegistry()
        self.approvals = ApprovalService(self.approval_registry, self.approver_key)
        self.idempotency = idempotency or InMemoryIdempotencyRegistry()
        self.velocity = InMemoryVelocityRegistry()
        self.coordinator = EnforcementCoordinator(
            gate=self.gate, idempotency=self.idempotency, velocity=self.velocity,
            audit=self.audit, profiles=ProfileRegistry.default_pilot(),
            revocation_registry=self.revocation, approvals=self.approvals,
            velocity_limits_for=velocity_limits_for,
        )
        self.trust = TrustSet()
        self.trust.add_runtime_issuer("issuer/treasury", self.issuer_key.kid,
                                      self.issuer_key.public_key())
        self.trust.add_runtime_issuer("issuer/approver", self.approver_key.kid,
                                      self.approver_key.public_key())
        self.executed: list = []   # every call that REACHED the actuator
        self.upstream_raises = upstream_raises

        async def upstream(action, payload):
            self.executed.append((action, dict(payload)))
            if self.upstream_raises:
                raise RuntimeError("upstream failure")
            return {"ok": True}

        self.upstream = upstream
        self.service = GovernanceService(
            engine=self.engine, coordinator=self.coordinator, trust_set=self.trust,
            revocation_registry=self.revocation, approvals=self.approvals,
            profiles=ProfileRegistry.default_pilot(), upstream=upstream,
            policy_hash=POLICY_HASH,
        )

    def mandate(self, **overrides):
        now = int(time.time())
        kw = dict(
            issuer="issuer/treasury", subject=ACTOR, action_scope=[ACTION],
            resource_scope=[RESOURCE], constraints={"max_amount": 5000},
            not_before=now - 10, not_after=now + 3600, issued_at=now - 10,
            policy_hash=POLICY_HASH,
        )
        kw.update(overrides)
        return issue_mandate(self.issuer_key, **kw)

    async def execute(self, mandate, *, idempotency_key, **overrides):
        kw = dict(mandate=mandate, actor=ACTOR, action=ACTION, resource=RESOURCE,
                  context=payment(), tenant_id=TENANT)
        kw.update(overrides)
        return await self.service.execute_with_mandate(
            idempotency_key=idempotency_key, **kw)


def payment(**overrides):
    ctx = {"source": RESOURCE, "beneficiary_id": "vendor-42",
           "amount": 100.0, "currency": "EUR"}
    ctx.update(overrides)
    return ctx


# --------------------------------------------------------------------------
# Result metadata + helpers shared by every attack file
# --------------------------------------------------------------------------
def attack(*, vector: int, severity: str, kind: str = "bypass", title: str = ""):
    """Tag a test. Every test ASSERTS THE SECURE PROPERTY, so:
        test passes  -> attack was blocked        (bypassed = no)
        test fails   -> attack succeeded           (bypassed = yes)
    kind: bypass | design-gap | known-limitation | hardening
    """
    def deco(fn):
        fn._rt = {"vector": vector, "severity": severity, "kind": kind,
                  "title": title or fn.__name__}
        return fn
    return deco


def pilot_limits_for():
    """Same resolver gateway/governance_api.build_governance_service wires
    (that module cannot be imported here: FastAPI is not installed)."""
    import fnmatch
    from gateway.pilot_policy import PILOT_VELOCITY
    from mcc_core import VelocityLimit
    limits = {pat: [VelocityLimit.from_config(i) for i in items]
              for pat, items in PILOT_VELOCITY.items()}

    def limits_for(action):
        for pat, lst in limits.items():
            if fnmatch.fnmatchcase(action, pat):
                return lst
        return []
    return limits_for


def spy_tokens(stack):
    """Record every decision token the real engine signs (a spy, not a mock:
    the real issue_token still runs and its real output is what is used)."""
    captured = []
    real = stack.engine.issue_token

    def issue_token(**kw):
        tok = real(**kw)
        captured.append(tok)
        return tok
    stack.engine.issue_token = issue_token
    return captured


class Boom:
    """Dependency-failure injector: every awaited method raises."""
    def __init__(self, exc=None):
        self._exc = exc or ConnectionError("backend down")

    def __getattr__(self, name):
        async def fail(*a, **kw):
            raise self._exc
        return fail
