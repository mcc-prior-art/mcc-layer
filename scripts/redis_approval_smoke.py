#!/usr/bin/env python3
"""End-to-end Redis approval smoke: cross-instance single-use consumption.

    MCC_REDIS_URL=redis://127.0.0.1:6379/0 python scripts/redis_approval_smoke.py

An approval approved through a shared Redis store can be consumed exactly once,
even when two independent service instances race to consume it. Exits non-zero
on any miss.
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcc_core import (  # noqa: E402
    ApprovalService,
    RedisApprovalRegistry,
    SigningKey,
    hash_action,
)

URL = os.environ.get("MCC_REDIS_URL", "redis://127.0.0.1:6379/0")
NOW = 1_780_000_000


async def main() -> int:
    failures = []
    key = SigningKey.generate("approver-smoke")
    reg_a = RedisApprovalRegistry.from_url(URL)
    reg_b = RedisApprovalRegistry.from_url(URL)
    svc_a = ApprovalService(reg_a, key)
    svc_b = ApprovalService(reg_b, key)

    action = "send_payment"
    rid = await svc_a.request(actor="agent/x", action=action, resource="acct-1",
                              transaction_id="txn-1", now=NOW)
    mandate = await svc_a.approve(rid, now=NOW)
    if mandate is None:
        print("FAILED: approve returned no mandate")
        return 1

    # Two instances race to consume the same approval.
    args = dict(action_hash=hash_action(action), transaction_id="txn-1", payload_hash=None, now=NOW)
    a, b = await asyncio.gather(svc_a.consume(rid, **args), svc_b.consume(rid, **args))
    wins = [r for r in (a, b) if r.ok]
    print(f"instance A consume ok={a.ok} ({a.reason})")
    print(f"instance B consume ok={b.ok} ({b.reason})")

    if len(wins) != 1:
        failures.append(f"expected exactly one consumer, got {len(wins)}")

    if failures:
        print("\nREDIS APPROVAL SMOKE FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("\nREDIS APPROVAL SMOKE PASSED: cross-instance single-use consume held.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
