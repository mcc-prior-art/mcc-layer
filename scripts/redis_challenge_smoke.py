#!/usr/bin/env python3
"""End-to-end Redis consensus-challenge smoke: cross-instance single-use consume.

    MCC_REDIS_URL=redis://127.0.0.1:6379/0 python scripts/redis_challenge_smoke.py

A challenge issued on one service instance is visible on another through the
shared Redis store, and can be consumed exactly once even when two instances
race to consume it. Exits non-zero on any miss.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcc_core import (  # noqa: E402
    ChallengeService,
    RedisChallengeRegistry,
    hash_payload,
)

URL = os.environ.get("MCC_REDIS_URL", "redis://127.0.0.1:6379/0")
NOW = 1_780_000_000
ACTION = "deploy_release"
ACTOR = "agent/ops"
RESOURCE = "cluster-1"
POLICY_HASH = "sha256:p"
PH = hash_payload({"target": "cluster-1"})


async def main() -> int:
    failures = []
    svc_a = ChallengeService(RedisChallengeRegistry.from_url(URL))
    svc_b = ChallengeService(RedisChallengeRegistry.from_url(URL))

    # Issue on A; it must be visible on B (the gateway owns the nonce).
    rec = await svc_a.issue(action=ACTION, actor=ACTOR, resource=RESOURCE, payload_hash=PH,
                            policy_hash=POLICY_HASH, ttl_seconds=120, now=NOW)
    seen = await svc_b.get(rec.challenge_id, now=NOW)
    if seen is None or seen.nonce != rec.nonce:
        print("FAILED: challenge issued on A not visible (or nonce differs) on B")
        return 1
    print(f"challenge {rec.challenge_id} issued on A, visible on B (nonce matches)")

    args = dict(action=ACTION, actor=ACTOR, resource=RESOURCE, payload_hash=PH,
                policy_hash=POLICY_HASH, nonce=rec.nonce, now=NOW)
    a, b = await asyncio.gather(svc_a.consume(rec.challenge_id, **args),
                                svc_b.consume(rec.challenge_id, **args))
    wins = [r for r in (a, b) if r.ok]
    print(f"instance A consume ok={a.ok} ({a.reason})")
    print(f"instance B consume ok={b.ok} ({b.reason})")
    if len(wins) != 1:
        failures.append(f"expected exactly one consumer, got {len(wins)}")

    # A third attempt (challenge now spent) must fail closed.
    third = await svc_a.consume(rec.challenge_id, **args)
    if third.ok:
        failures.append("spent challenge consumed again")

    if failures:
        print("\nREDIS CHALLENGE SMOKE FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("\nREDIS CHALLENGE SMOKE PASSED: cross-instance issue + single-use consume held.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
