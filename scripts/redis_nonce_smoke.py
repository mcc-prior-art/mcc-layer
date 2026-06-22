#!/usr/bin/env python3
"""End-to-end Redis nonce smoke: cross-instance replay protection.

Run against a real Redis (CI provides one as a service container):

    MCC_REDIS_URL=redis://127.0.0.1:6379/0 python scripts/redis_nonce_smoke.py

Two independent ExecutionGate instances share one Redis through
RedisNonceRegistry. A token verified on gate 1 must be rejected when replayed
on gate 2 (the property in-memory protection cannot provide), while a fresh
token still verifies. Exits non-zero on any miss.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcc_core import (  # noqa: E402
    DecisionEngine,
    ExecutionGate,
    RedisNonceRegistry,
    SigningKey,
)

URL = os.environ.get("MCC_REDIS_URL", "redis://127.0.0.1:6379/0")
AUDIENCE = "smoke-gate"
POLICY_HASH = "sha256:smoke"


def make_gate(key):
    return ExecutionGate(
        trusted_keys={key.kid: key.public_key()},
        audience=AUDIENCE,
        nonce_registry=RedisNonceRegistry.from_url(URL),
        policy_hash=POLICY_HASH,
    )


async def main() -> int:
    key = SigningKey.generate("smoke-key")
    engine = DecisionEngine(
        signing_key=key, issuer="mcc/smoke", audience=AUDIENCE,
        policy_id="smoke/v1", policy_hash=POLICY_HASH, token_ttl_seconds=60,
    )
    gate_one, gate_two = make_gate(key), make_gate(key)

    token = engine.issue_token(
        verdict="ALLOW", subject="agent/smoke", action="act", payload={"x": 1}
    )
    first = await gate_one.verify(token, action="act", payload={"x": 1})
    replay = await gate_two.verify(token, action="act", payload={"x": 1})

    fresh = engine.issue_token(
        verdict="ALLOW", subject="agent/smoke", action="act", payload={"x": 1}
    )
    fresh_ok = await gate_two.verify(fresh, action="act", payload={"x": 1})

    print(f"gate1 first use:        allowed={first.allowed}  ({first.reason})")
    print(f"gate2 cross-instance:   allowed={replay.allowed}  ({replay.reason})")
    print(f"gate2 fresh token:      allowed={fresh_ok.allowed}  ({fresh_ok.reason})")

    failures = []
    if not first.allowed:
        failures.append("first legitimate use on gate1 was rejected")
    if replay.allowed:
        failures.append("cross-instance replay on gate2 was ACCEPTED (no shared protection)")
    elif "NONCE_REJECTED" not in replay.reason:
        failures.append(f"replay blocked for the wrong reason: {replay.reason}")
    if not fresh_ok.allowed:
        failures.append("a fresh token was rejected on gate2")

    if failures:
        print("\nREDIS NONCE SMOKE FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nREDIS NONCE SMOKE PASSED: shared Redis rejects cross-instance replay.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
