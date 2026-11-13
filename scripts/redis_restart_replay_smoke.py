#!/usr/bin/env python3
"""End-to-end Redis restart-replay smoke (Production Trust Hardening Phase 1,
Workstream 1, requirement R5).

Run against a real Redis (CI provides one as a service container):

    MCC_REDIS_URL=redis://127.0.0.1:6379/0 python scripts/redis_restart_replay_smoke.py

Proves that replay protection for the attestation-aware governed execution
chain survives a full Gateway/Control restart when the shared nonce
registry is Redis-backed, mirroring the production wiring
(``gateway.governance_api.build_governance_service``'s ``shared_nonce_registry``,
used by both ``PreExecutionControl`` and ``ExecutionGate``):

    1. Build "instance A": a real independent Attester (in-process, using
       the unmodified PR-1/PR-4 signing path) issues a genuine signed
       EvidenceAttestation; a real PreExecutionControl + DecisionEngine +
       ExecutionGate + EnforcementCoordinator + GovernanceService, wired to
       ONE shared RedisNonceRegistry, executes it through the full governed
       chain to a simulated actuator. Dual oracle: the reported outcome
       AND an independent actuation counter.
    2. Destroy every Python object instance A held (Control, Gate,
       Coordinator, GovernanceService, its own Redis client) -- the process
       state a Gateway restart would lose.
    3. Build "instance B" from scratch: a brand-new RedisNonceRegistry
       pointed at the SAME Redis URL (a fresh client, exactly as a
       restarted process would create), a brand-new Control/Gate/
       Coordinator/GovernanceService.
    4. Replay the EXACT SAME raw attestation, mandate, and context against
       instance B.
    5. Assert: BLOCKED, not EXECUTED -- and the actuation counter is still
       1, never 2. Nonce state lived in Redis, not in the Python process,
       so instance B rejects the replay it never itself observed the first
       use of.

Exits non-zero on any miss.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway.governance_service import GovernanceService  # noqa: E402
from gateway.pre_execution_control import (  # noqa: E402
    AttestationRequirement,
    AttestationRequirementRegistry,
    PreExecutionControl,
)
from gateway.trust import TrustSet  # noqa: E402
from mcc_attestation import AttesterTrustAnchor, AttesterTrustStore  # noqa: E402
from mcc_attester_service import (  # noqa: E402
    AssessmentResult,
    AttesterService,
    AttesterServiceConfig,
    DeterministicTestProvider,
)
from mcc_core import (  # noqa: E402
    ApprovalService,
    AuditLog,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryApprovalRegistry,
    InMemoryIdempotencyRegistry,
    InMemoryRevocationRegistry,
    InMemoryVelocityRegistry,
    ProfileRegistry,
    RedisNonceRegistry,
    SigningKey,
    issue_mandate,
)

run = asyncio.run

URL = os.environ.get("MCC_REDIS_URL", "redis://127.0.0.1:6379/0")
ACTION = "send_payment"
RESOURCE = "vendor-1"
POLICY_HASH = "sha256:" + "0" * 64
ATTESTER_ID = "attester.restart-smoke.v1"
SCOPE_TEMPLATE = "payment:{resource}"
AUTH_SECRET = "restart-smoke-auth-secret-0123456789"


def _now() -> int:
    return int(time.time())


def _tmp_audit() -> AuditLog:
    d = tempfile.mkdtemp(prefix="mcc-restart-smoke-")
    return AuditLog(str(Path(d) / "audit.jsonl"))


def _requirement() -> AttestationRequirement:
    return AttestationRequirement(
        action_pattern=ACTION, evidence_type="risk_assessment",
        scope_template=SCOPE_TEMPLATE, required_claims={"risk_class": ("low",)},
    )


class _Actuator:
    """The dual-oracle side of this proof: an independent counter of real
    actuations, entirely separate from whatever GovernanceService reports."""

    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, action, payload):
        self.calls += 1
        return {"ok": True, "action": action, "payload": payload}


def _build_instance(
    *, shared_nonce_registry, attester_key: SigningKey, mandate_key: SigningKey, actuator: _Actuator,
) -> GovernanceService:
    """Build one full governed stack sharing ONE nonce registry between
    PreExecutionControl and ExecutionGate -- the same sharing
    ``build_governance_service`` uses in production."""
    control = PreExecutionControl(
        requirements=AttestationRequirementRegistry([_requirement()]),
        trust_store=AttesterTrustStore([
            AttesterTrustAnchor(ATTESTER_ID, attester_key.kid, attester_key.public_key(),
                                frozenset({"risk_assessment"})),
        ]),
        nonce_registry=shared_nonce_registry,
    )
    signing_key = SigningKey.generate("gw-signing-restart-smoke")
    engine = DecisionEngine(
        signing_key=signing_key, issuer="mcc/core", audience="restart-smoke",
        policy_id="restart-smoke/v1", policy_hash=POLICY_HASH,
    )
    gate = ExecutionGate(
        trusted_keys={signing_key.kid: signing_key.public_key()}, audience="restart-smoke",
        nonce_registry=shared_nonce_registry, policy_hash=POLICY_HASH,
    )
    coordinator = EnforcementCoordinator(
        gate=gate, idempotency=InMemoryIdempotencyRegistry(),
        velocity=InMemoryVelocityRegistry(), audit=_tmp_audit(),
        profiles=ProfileRegistry.default_pilot(), revocation_registry=InMemoryRevocationRegistry(),
    )
    trust_set = TrustSet()
    trust_set.add_runtime_issuer("axlogiq/restart-smoke", mandate_key.kid, mandate_key.public_key())
    approver_key = SigningKey.generate("approver-restart-smoke")
    trust_set.add_runtime_issuer("mcc/approvals", approver_key.kid, approver_key.public_key())
    approvals = ApprovalService(InMemoryApprovalRegistry(), approver_key)

    return GovernanceService(
        engine=engine, coordinator=coordinator, trust_set=trust_set,
        revocation_registry=InMemoryRevocationRegistry(), approvals=approvals,
        profiles=ProfileRegistry.default_pilot(), upstream=actuator, policy_hash=POLICY_HASH,
        pre_execution_control=control,
    )


async def main() -> int:
    mandate_key = SigningKey.generate("issuer-restart-smoke")
    attester_key = SigningKey.generate("attester.restart-smoke.v1-key-01")

    context = {"source": "acct-1", "beneficiary_id": RESOURCE, "amount": 100, "currency": "eur"}
    canonical = ProfileRegistry.default_pilot().for_action(ACTION).canonical_payload(context)

    provider = DeterministicTestProvider({
        ACTION: AssessmentResult(
            evidence_type="risk_assessment", claims={"risk_class": "low"},
            provenance={"model": "restart-smoke"},
        ),
    })
    attester_config = AttesterServiceConfig(
        attester_id=ATTESTER_ID, signing_key=attester_key, auth_secret=AUTH_SECRET,
        scope_template=SCOPE_TEMPLATE, validity_seconds=900,
    )
    attester_service = AttesterService(config=attester_config, provider=provider)
    raw_attestation = await attester_service.attest(action=ACTION, resource=RESOURCE, payload=canonical)

    mandate = issue_mandate(
        mandate_key, issuer="axlogiq/restart-smoke", subject="agent/payments-bot",
        action_scope=[ACTION], resource_scope=[RESOURCE], constraints={},
        not_before=_now() - 10, not_after=_now() + 3600, issued_at=_now(),
        tenant_id="redis-restart-smoke-tenant",  # V05: the tenant both instances execute in
    )

    # ---- Instance A: first, legitimate use. ----
    registry_a = RedisNonceRegistry.from_url(URL)
    actuator = _Actuator()
    service_a = _build_instance(
        shared_nonce_registry=registry_a, attester_key=attester_key,
        mandate_key=mandate_key, actuator=actuator,
    )
    first = await service_a.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=raw_attestation, idempotency_key="op-restart-replay-smoke",
        tenant_id="redis-restart-smoke-tenant",
    )

    # ---- Simulated restart: destroy every instance-A Python object. ----
    del service_a, registry_a
    import gc
    gc.collect()

    # ---- Instance B: brand-new objects, same Redis URL, same artifacts. ----
    registry_b = RedisNonceRegistry.from_url(URL)
    service_b = _build_instance(
        shared_nonce_registry=registry_b, attester_key=attester_key,
        mandate_key=mandate_key, actuator=actuator,
    )
    replay = await service_b.execute_with_mandate(
        mandate=mandate, actor="agent/payments-bot", action=ACTION, resource=RESOURCE,
        context=context, attestation=raw_attestation, idempotency_key="op-restart-replay-smoke",
        tenant_id="redis-restart-smoke-tenant",
    )

    print(f"instance A first use:      status={first.status}  decision={first.decision}  ({first.reason})")
    print(f"instance B post-restart replay: status={replay.status}  ({replay.reason})")
    print(f"independent actuation count:    {actuator.calls}")

    failures = []
    if first.status != "EXECUTED":
        failures.append(f"first legitimate use on instance A was not EXECUTED: {first.status} ({first.reason})")
    if replay.status == "EXECUTED":
        failures.append("post-restart replay on instance B was EXECUTED (nonce state did not survive restart)")
    if actuator.calls != 1:
        failures.append(f"actuator was called {actuator.calls} times; expected exactly 1 (replay must not actuate)")

    if failures:
        print("\nREDIS RESTART-REPLAY SMOKE FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nREDIS RESTART-REPLAY SMOKE PASSED: replay protection survives a full restart via shared Redis state.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
