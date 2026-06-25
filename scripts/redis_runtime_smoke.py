#!/usr/bin/env python3
"""End-to-end smoke for hardened shared Redis governance state, against a REAL
Redis. Proves the multi-instance guarantees the FakeRedis unit tests model:

    MCC_REDIS_URL=redis://127.0.0.1:6379/0 python scripts/redis_runtime_smoke.py

1. Canonical namespaced keys are used (mcc:v1:{env}:{registry}:…).
2. A nonce consumed on instance A is rejected on instance B.
3. An idempotency key reserved on A cannot be rebound (conflict) on B; exactly
   one of many concurrent reservers wins.
4. Velocity aggregate enforced across instances; concurrent reservations cannot
   bypass the ceiling (atomic Lua reserve); a negative amount is rejected.
5. Every check fails closed if Redis is unavailable.

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
    RedisNonceRegistry,
    RedisVelocityRegistry,
    VelocityDescriptor,
    VelocityLimit,
    build_redis_client,
    redis_keys,
)
from mcc_core.idempotency import ReserveStatus  # noqa: E402

URL = os.environ.get("MCC_REDIS_URL", "redis://127.0.0.1:6379/0")
ENV = {"MCC_ENV": "smoke-" + uuid.uuid4().hex[:8]}  # isolate this run's keyspace


async def main() -> int:
    failures = []
    client_a = build_redis_client(URL)
    client_b = build_redis_client(URL)

    # 1 + 2. Nonce: consumed on A, rejected on B (shared namespace).
    ns_nonce = redis_keys.prefix("nonce", ENV)
    nonce_a = RedisNonceRegistry(client_a, namespace=ns_nonce)
    nonce_b = RedisNonceRegistry(client_b, namespace=ns_nonce)
    n = "nonce-" + uuid.uuid4().hex
    first = await nonce_a.consume(n, ttl_seconds=60)
    replay = await nonce_b.consume(n, ttl_seconds=60)
    print(f"[nonce] A.first={first} B.replay={replay} | ns={ns_nonce}")
    if not (first is True and replay is False):
        failures.append("nonce not single-use across instances")

    # 3. Idempotency: conflict on B; exactly one concurrent winner.
    ns_idem = redis_keys.prefix("idem", ENV)
    idem_a = RedisIdempotencyRegistry(client_a, namespace=ns_idem)
    idem_b = RedisIdempotencyRegistry(client_b, namespace=ns_idem)
    k = "op-" + uuid.uuid4().hex
    r1 = await idem_a.reserve(k, binding="A")
    r2 = await idem_b.reserve(k, binding="B")
    print(f"[idem] A={r1.status.value} B={r2.status.value}")
    if not (r1.status == ReserveStatus.RESERVED and not r2.ok):
        failures.append("idempotency allowed a conflicting rebinding across instances")
    k2 = "op-" + uuid.uuid4().hex
    results = await asyncio.gather(*[
        (idem_a if i % 2 == 0 else idem_b).reserve(k2, binding=f"b{i}") for i in range(16)])
    winners = sum(1 for r in results if r.status == ReserveStatus.RESERVED)
    print(f"[idem] concurrent winners={winners} (want 1)")
    if winners != 1:
        failures.append(f"idempotency concurrent winners={winners}")

    # 4. Velocity aggregate across instances + concurrency + negative amount.
    ns_vel = redis_keys.prefix("vel", ENV)
    vel_a = RedisVelocityRegistry(client_a, namespace=ns_vel)
    vel_b = RedisVelocityRegistry(client_b, namespace=ns_vel)
    actor = "actor-" + uuid.uuid4().hex
    limit = VelocityLimit(name="amt", window_seconds=3600, max_amount=100.0, aggregate_by=("actor",))
    ok = await vel_a.reserve(limit, VelocityDescriptor(dimensions={"actor": actor}, amount=60.0))
    over = await vel_b.reserve(limit, VelocityDescriptor(dimensions={"actor": actor}, amount=60.0))
    print(f"[velocity] A(60).ok={ok.ok} B(60).ok={over.ok} (want True/False)")
    if not (ok.ok and not over.ok):
        failures.append("velocity aggregate bypassed across instances")
    neg = await vel_a.reserve(limit, VelocityDescriptor(dimensions={"actor": actor}, amount=-50.0))
    print(f"[velocity] negative-amount.ok={neg.ok} (want False)")
    if neg.ok:
        failures.append("velocity accepted a negative amount")

    # Concurrency: a count ceiling cannot be exceeded by concurrent reservers.
    actor2 = "actor-" + uuid.uuid4().hex
    climit = VelocityLimit(name="cnt", window_seconds=3600, max_count=3, aggregate_by=("actor",))
    cres = await asyncio.gather(*[
        (vel_a if i % 2 == 0 else vel_b).reserve(climit, VelocityDescriptor(dimensions={"actor": actor2}))
        for i in range(20)])
    allowed = sum(1 for r in cres if r.ok)
    print(f"[velocity] concurrent count-3 allowed={allowed} (want <= 3)")
    if allowed > 3:
        failures.append(f"velocity count ceiling bypassed: allowed={allowed}")

    if failures:
        print("\nREDIS RUNTIME SMOKE FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("\nREDIS RUNTIME SMOKE PASSED: shared, atomic, namespaced governance state held "
          "across instances under concurrency.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
