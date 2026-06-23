#!/usr/bin/env python3
"""End-to-end Redis governance smoke: cross-instance idempotency + aggregate ceiling.

Run against a real Redis (CI provides one as a service container):

    MCC_REDIS_URL=redis://127.0.0.1:6379/0 python scripts/redis_governance_smoke.py

Proves, against a shared Redis, the properties in-memory state cannot provide:

* idempotency dedup holds across independent instances — an operation reserved
  and executed on instance A cannot execute again on instance B;
* a cumulative velocity ceiling holds across separately-signed transactions and
  across instances — four valid 4000 reservations cannot exceed a 10000 ceiling.

Exits non-zero on any miss.
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcc_core import (  # noqa: E402
    RedisIdempotencyRegistry,
    RedisVelocityRegistry,
    ReserveStatus,
    VelocityDescriptor,
    VelocityLimit,
    Verdict,
)

URL = os.environ.get("MCC_REDIS_URL", "redis://127.0.0.1:6379/0")


async def main() -> int:
    run_id = uuid.uuid4().hex[:8]
    failures = []

    # --- Cross-instance idempotency ---
    idem_a = RedisIdempotencyRegistry.from_url(URL)
    idem_b = RedisIdempotencyRegistry.from_url(URL)
    key = f"op-{run_id}"
    first = await idem_a.reserve(key)
    await idem_a.mark_executed(key)
    cross = await idem_b.reserve(key)  # different instance, same Redis
    print(f"idempotency: instance A first={first.status.value}  instance B replay={cross.status.value}")
    if not first.ok:
        failures.append("first reservation on instance A should succeed")
    if cross.status != ReserveStatus.DUPLICATE_EXECUTED:
        failures.append(f"cross-instance replay should be DUPLICATE_EXECUTED, got {cross.status.value}")

    # --- Aggregate ceiling across instances ---
    vel_a = RedisVelocityRegistry.from_url(URL)
    vel_b = RedisVelocityRegistry.from_url(URL)
    limit = VelocityLimit(name=f"amt-{run_id}", window_seconds=3600, max_amount=10000,
                          aggregate_by=("actor",))

    def desc():
        return VelocityDescriptor(dimensions={"actor": f"a-{run_id}"}, amount=4000)

    verdicts = []
    for reg in (vel_a, vel_b, vel_a, vel_b):  # alternate instances
        verdicts.append((await reg.reserve(limit, desc())).verdict)
    allowed = [v for v in verdicts if v == Verdict.ALLOW]
    print(f"velocity: verdicts={[v.value for v in verdicts]}  allowed={len(allowed)}")
    if len(allowed) * 4000 > 10000:
        failures.append("cumulative ceiling bypassed across instances")
    if verdicts[:2] != [Verdict.ALLOW, Verdict.ALLOW] or verdicts[2] != Verdict.DENY:
        failures.append(f"expected ALLOW, ALLOW, DENY, ...; got {[v.value for v in verdicts]}")

    if failures:
        print("\nREDIS GOVERNANCE SMOKE FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("\nREDIS GOVERNANCE SMOKE PASSED: cross-instance dedup + cumulative ceiling held.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
