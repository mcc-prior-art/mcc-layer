"""Real OS-process worker for the P2-B crash/recovery fault matrix.

Invoked as a genuine subprocess:

    python -m tests.ha._crash_worker --redis-url URL --tenant T --key K \
        --crash-point {reserve|dispatch}

It builds its own full governed stack (own signing key, own gate) against
the given REAL Redis instance, issues one payment token, and calls
``EnforcementCoordinator.enforce()`` exactly once. Depending on
``--crash-point`` it SIGKILLs itself either:

* ``reserve`` -- immediately after the real idempotency reservation
  succeeds (Redis durably holds ``RESERVED``), but before dispatch
  ownership is committed: models a gateway process dying between
  admission and the point of no return.
* ``dispatch`` -- inside the executor callback, which
  ``EnforcementCoordinator.enforce()`` only ever invokes AFTER durable
  dispatch ownership (``DISPATCH_OWNED``) has been committed: models a
  gateway process dying exactly as (or immediately after) it begins
  actuating, leaving the external outcome ambiguous.

The parent test process never reads this worker's stdout for correctness
-- it inspects the REAL, SHARED Redis state afterward, which is the whole
point: the fault is a real process death, and the proof is durable
external state, not an in-process return value.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from mcc_core import RedisIdempotencyRegistry, RedisVelocityRegistry  # noqa: E402

from tests.ha._redis_lab import build_coordinator, killer_executor, payment_token  # noqa: E402


class _KillAfterReserve:
    """Wraps a REAL RedisIdempotencyRegistry. The moment its ``reserve()``
    genuinely succeeds against real Redis, this process SIGKILLs itself --
    the real durable RESERVED record is already written; only the
    in-process continuation (commit_dispatch) never happens."""

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

    async def reserve(self, *args, **kwargs):
        result = await self._inner.reserve(*args, **kwargs)
        if result.ok:
            os.kill(os.getpid(), signal.SIGKILL)
        return result


async def main(args: argparse.Namespace) -> None:
    idem = RedisIdempotencyRegistry.from_url(args.redis_url)
    vel = RedisVelocityRegistry.from_url(args.redis_url)
    if args.crash_point == "reserve":
        idem = _KillAfterReserve(idem)

    engine, coordinator, _audit = build_coordinator(idempotency=idem, velocity=vel)
    token, payload = payment_token(
        engine, idem=args.key, tenant=args.tenant, amount=args.amount,
        beneficiary=args.beneficiary,
    )
    seen: list = []
    executor = killer_executor(None, record=seen) if args.crash_point == "dispatch" else None
    if executor is None:
        async def executor():
            seen.append("executed")
            return "ok"

    await coordinator.enforce(token=token, action="send_payment", payload=payload, executor=executor)
    # Only reachable if crash_point didn't actually fire (a bug in the
    # harness, not the system under test) -- exit distinctly so the parent
    # can tell the difference from a real SIGKILL.
    sys.exit(97)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--redis-url", required=True)
    ap.add_argument("--tenant", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--crash-point", choices=["reserve", "dispatch"], required=True)
    ap.add_argument("--amount", type=float, default=100.0)
    ap.add_argument("--beneficiary", default="ben-1")
    asyncio.run(main(ap.parse_args()))
