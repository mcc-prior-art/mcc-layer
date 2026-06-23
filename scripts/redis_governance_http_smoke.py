#!/usr/bin/env python3
"""End-to-end Redis smoke for the governance HTTP service layer.

    MCC_REDIS_URL=redis://127.0.0.1:6379/0 python scripts/redis_governance_http_smoke.py

Two GovernanceService instances share one Redis (nonce, idempotency, velocity,
revocation, approval). Proves, through the *full* coordinator+gate path:

* a mandate revoked on instance A is blocked when executed on instance B
  (cross-instance revocation re-check);
* an approval consumed on instance A cannot be executed again on instance B
  (cross-instance single-use).

Exits non-zero on any miss.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcc_core import (  # noqa: E402
    ApprovalService,
    AuditLog,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    ProfileRegistry,
    RedisApprovalRegistry,
    RedisIdempotencyRegistry,
    RedisNonceRegistry,
    RedisRevocationRegistry,
    RedisVelocityRegistry,
    SigningKey,
    hash_payload,
    issue_mandate,
)

from gateway.governance_service import GovernanceService  # noqa: E402
from gateway.trust import TrustSet  # noqa: E402

URL = os.environ.get("MCC_REDIS_URL", "redis://127.0.0.1:6379/0")
POLICY = "sha256:p"
FUTURE = 4_000_000_000

# Shared keys + trust across both "instances".
DK = SigningKey.generate("dk-shared")
APPROVER = SigningKey.generate("apr-shared")
CALLS = []


async def upstream(action, payload):
    CALLS.append((action, payload))
    return {"ok": True}


def build_service():
    trust = TrustSet()
    trust.add_runtime_issuer("mcc/issuers", DK.kid, DK.public_key())  # issuer = DK for mandates
    trust.add_runtime_issuer("mcc/approvals", APPROVER.kid, APPROVER.public_key())
    engine = DecisionEngine(signing_key=DK, issuer="mcc", audience="gate",
                            policy_id="p", policy_hash=POLICY, token_ttl_seconds=60)
    gate = ExecutionGate(trusted_keys={DK.kid: DK.public_key()}, audience="gate",
                         nonce_registry=RedisNonceRegistry.from_url(URL), policy_hash=POLICY)
    revocation = RedisRevocationRegistry.from_url(URL)
    approvals = ApprovalService(RedisApprovalRegistry.from_url(URL), APPROVER)
    audit = AuditLog(str(Path(tempfile.mkdtemp(prefix="mcc-httpredis-")) / "a.jsonl"))
    coord = EnforcementCoordinator(
        gate=gate, idempotency=RedisIdempotencyRegistry.from_url(URL),
        velocity=RedisVelocityRegistry.from_url(URL), audit=audit,
        profiles=ProfileRegistry.default_pilot(), revocation_registry=revocation,
        approvals=approvals)
    return GovernanceService(engine=engine, coordinator=coord, trust_set=trust,
                             revocation_registry=revocation, approvals=approvals,
                             upstream=upstream, policy_hash=POLICY), revocation, approvals


async def main() -> int:
    run_id = uuid.uuid4().hex[:8]
    a, rev_a, _ = build_service()
    b, _, _ = build_service()
    failures = []
    ctx = {"value": 1}

    # --- cross-instance revocation ---
    m = issue_mandate(DK, issuer="mcc/issuers", subject="agent/x", action_scope=["generic_op"],
                      resource_scope=["res-1"], constraints={}, not_before=1, not_after=FUTURE,
                      revocation_required=True, mandate_id=f"mdt-{run_id}")
    ok = await a.execute_with_mandate(mandate=m, actor="agent/x", action="generic_op",
                                      resource="res-1", context=ctx, idempotency_key=f"i-{run_id}-1")
    await rev_a.revoke(m["mandate_id"])
    blocked = await b.execute_with_mandate(mandate=m, actor="agent/x", action="generic_op",
                                           resource="res-1", context=ctx, idempotency_key=f"i-{run_id}-2")
    print(f"mandate: A execute={ok.status}  B after revoke={blocked.status}")
    if ok.status != "EXECUTED":
        failures.append("instance A execute should succeed")
    if blocked.status != "BLOCKED":
        failures.append("instance B should block a cross-instance revoked mandate")

    # --- cross-instance single-use approval ---
    rid = await a.create_approval(actor="agent/x", action="generic_op", resource="res-1",
                                  transaction_id=f"t-{run_id}", policy_hash=POLICY,
                                  payload_hash=hash_payload(ctx))
    mandate = await a.approve(rid["request_id"])
    first = await a.execute_with_approval(mandate=mandate, actor="agent/x", action="generic_op",
                                          resource="res-1", context=ctx, transaction_id=f"t-{run_id}",
                                          idempotency_key=f"a-{run_id}-1")
    second = await b.execute_with_approval(mandate=mandate, actor="agent/x", action="generic_op",
                                           resource="res-1", context=ctx, transaction_id=f"t-{run_id}",
                                           idempotency_key=f"a-{run_id}-2")
    print(f"approval: A execute={first.status}  B replay={second.status}")
    if first.status != "EXECUTED":
        failures.append("instance A approval execute should succeed")
    if second.status != "BLOCKED":
        failures.append("instance B should block a cross-instance approval replay")

    if failures:
        print("\nREDIS GOVERNANCE HTTP SMOKE FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("\nREDIS GOVERNANCE HTTP SMOKE PASSED: cross-instance revocation + single-use held.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
