#!/usr/bin/env python3
"""End-to-end Redis revocation smoke: cross-instance mandate revocation.

    MCC_REDIS_URL=redis://127.0.0.1:6379/0 python scripts/redis_mandate_smoke.py

A mandate verified as ACTIVE on one verifier instance must verify as REVOKED on
another instance after it is revoked through a shared Redis revocation list —
the property in-process revocation cannot provide across instances. Exits
non-zero on any miss.
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcc_core import (  # noqa: E402
    MandateVerifier,
    RedisRevocationRegistry,
    SigningKey,
    issue_mandate,
)

URL = os.environ.get("MCC_REDIS_URL", "redis://127.0.0.1:6379/0")
NOW = 1_780_000_000


async def main() -> int:
    failures = []
    key = SigningKey.generate("issuer-smoke")
    trusted = {key.kid: key.public_key()}

    rev_a = RedisRevocationRegistry.from_url(URL)
    rev_b = RedisRevocationRegistry.from_url(URL)
    v_a = MandateVerifier(trusted_keys=trusted, revocation_registry=rev_a)
    v_b = MandateVerifier(trusted_keys=trusted, revocation_registry=rev_b)

    m = issue_mandate(
        key, issuer="axlogiq", subject="agent/x", action_scope=["act"],
        resource_scope=["res-1"], constraints={}, not_before=NOW - 10,
        not_after=NOW + 3600, issued_at=NOW, revocation_required=True,
        mandate_id=f"mdt-{uuid.uuid4().hex[:8]}",
    )
    args = dict(subject="agent/x", action="act", resource="res-1", now=NOW)

    before = await v_a.verify(m, **args)
    await rev_a.revoke(m["mandate_id"])          # revoke via instance A
    after_other = await v_b.verify(m, **args)     # observe via instance B

    print(f"instance A before revoke: ok={before.ok} ({before.reason})")
    print(f"instance B after revoke:  ok={after_other.ok} ({after_other.reason})")

    if not before.ok:
        failures.append("active mandate should verify before revocation")
    if after_other.ok:
        failures.append("revoked mandate should be rejected cross-instance")
    elif "REVOKED" not in after_other.reason:
        failures.append(f"expected REVOKED, got {after_other.reason}")

    if failures:
        print("\nREDIS MANDATE SMOKE FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("\nREDIS MANDATE SMOKE PASSED: cross-instance revocation held.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
