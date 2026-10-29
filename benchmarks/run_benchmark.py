"""P2-A Low-Latency Authority Plane: reproducible benchmark CLI.

Drives the REAL governed stack (see ``benchmarks/workload.py``) through a
mocked-actuator workload and reports latency/throughput. Two measurement
modes, always kept separate:

* ``--mode auth``  -- pure authority: token issuance + ``ExecutionGate.verify()``
  in isolation (no idempotency/velocity/audit/dispatch).
* ``--mode e2e``   -- full path: decision -> Gate -> nonce/idempotency ->
  velocity -> audit -> dispatch -> receipt, through the real
  ``EnforcementCoordinator.enforce()`` (via ``GovernanceService``).

Usage (see docs/LOW_LATENCY_AUTHORITY_PLANE.md for full reproduction
instructions):

    PYTHONPATH=src:.:sdk/python/src:. python benchmarks/run_benchmark.py \\
        --mode e2e --authority mandate --backend memory \\
        --samples 2000 --warmup 200 --concurrency 1 \\
        --output benchmarks/results/e2e_memory_c1.json

No real network call is ever made; the actuator is an in-process counter
(see ``Stack.seen`` in ``workload.py``). This is NOT a production load
test and reports NO service-level-agreement -- see the doc for the exact
scope and caveats of every number this script prints.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.workload import build_stack, now  # noqa: E402


def _percentile(sorted_samples: List[float], pct: float) -> float:
    """Nearest-rank percentile over an already-sorted list. With N samples
    this has a real, bounded error for the extreme tails (p99 of 200
    samples is just the 198th-ranked value, not a smoothed estimate) --
    reported sample sizes must be read with that in mind, which is why
    the CLI refuses to compute p99 below a minimum sample size (see
    ``MIN_SAMPLES_FOR_P99`` below) rather than silently printing a
    low-confidence number.
    """
    if not sorted_samples:
        return float("nan")
    k = max(0, min(len(sorted_samples) - 1, int(round(pct / 100.0 * (len(sorted_samples) - 1)))))
    return sorted_samples[k]


MIN_SAMPLES_FOR_P99 = 100


async def _auth_only_once(stack, mandate: Dict[str, Any]) -> bool:
    """Pure authority overhead: issue a token under the mandate's authority
    model and verify it at the Gate -- no idempotency/velocity/audit/
    dispatch. Mirrors exactly what ``execute_with_mandate`` does up to
    (but not including) ``EnforcementCoordinator.enforce()``."""
    from mcc_core import MandateAuthority, MandateVerifier

    n = now()
    authority = MandateAuthority(MandateVerifier(
        trusted_keys={stack.mandate_issuer_key.kid: stack.mandate_issuer_key.public_key()},
    ))
    decision = await authority.authorize(
        mandate, subject="agent/payments-bot", action="send_payment", resource="acct-1",
        context={"source": "acct-1", "beneficiary_id": "vendor-42", "amount": 25.0, "currency": "EUR"},
        now=n,
    )
    from mcc_core import Verdict
    if decision.verdict not in (Verdict.ALLOW, Verdict.CONSTRAIN):
        return False
    token = stack.engine.issue_token(
        verdict=decision.verdict.value, subject="agent/payments-bot", action="send_payment",
        payload={"source": "acct-1", "beneficiary_id": "vendor-42", "amount": 25.0, "currency": "EUR"},
        idempotency_key="auth-only", actor_id="agent/payments-bot", resource_id="acct-1",
        tenant_id="tenant-1", now=n,
    )
    result = await stack.gate.verify(
        token, action="send_payment",
        payload={"source": "acct-1", "beneficiary_id": "vendor-42", "amount": 25.0, "currency": "EUR"},
        now=n,
    )
    return result.allowed


async def _e2e_once(stack, authority_kind: str, idem_key: str) -> bool:
    n = now()
    if authority_kind == "mandate":
        grant = stack.mandate(now=n)
        out = await stack.exec_mandate(grant, idempotency_key=idem_key)
    else:
        grant = stack.delegation(now=n)
        out = await stack.exec_delegation(grant, idempotency_key=idem_key)
    return out.status == "EXECUTED"


async def _run_samples(coro_factory, samples: int, concurrency: int) -> List[float]:
    """Run ``samples`` operations at the given concurrency, returning the
    per-operation wall-clock durations in seconds (``time.perf_counter()``
    deltas -- monotonic, immune to system clock adjustments)."""
    durations: List[float] = []
    sem = asyncio.Semaphore(concurrency)

    async def one(i: int) -> None:
        async with sem:
            t0 = time.perf_counter()
            ok = await coro_factory(i)
            t1 = time.perf_counter()
            if not ok:
                raise RuntimeError(f"operation {i} did not complete as expected (ok={ok})")
            durations.append(t1 - t0)

    await asyncio.gather(*(one(i) for i in range(samples)))
    return durations


def _environment_info() -> Dict[str, Any]:
    cpu_count = os.cpu_count()
    try:
        git_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(Path(__file__).resolve().parent.parent),
        ).decode().strip()
    except Exception:
        git_sha = "unknown"
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "cpu_count": cpu_count,
        "git_sha": git_sha,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["auth", "e2e"], required=True)
    parser.add_argument("--authority", choices=["mandate", "delegation"], default="mandate",
                        help="only used by --mode e2e")
    parser.add_argument("--backend", choices=["memory", "redis"], default="memory")
    parser.add_argument("--samples", type=int, default=500)
    parser.add_argument("--warmup", type=int, default=50)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--output", type=str, default=None, help="write raw JSON results here")
    args = parser.parse_args()

    async def run_all() -> List[float]:
        # Built and driven inside ONE event loop for the whole run (warmup
        # and measured samples alike): an async Redis client's connection
        # pool binds to the loop it first runs on, so tearing down and
        # recreating the loop between warmup and measurement (two separate
        # ``asyncio.run()`` calls) breaks the real-Redis backend. The
        # in-memory backend has no such constraint, but one loop for the
        # whole run keeps both backends' code path identical.
        stack = build_stack(backend=args.backend)

        if args.mode == "auth":
            grant = stack.mandate(now=now())

            async def factory(i: int) -> bool:
                return await _auth_only_once(stack, grant)
        else:
            # A fresh uuid4 run id per invocation -- not just per operation --
            # is required for the Redis backend: the idempotency registry's
            # (tenant_id, idempotency_key) replay protection is durable in a
            # REAL Redis instance across separate process runs. Re-running
            # this script against the same Redis target with a counter that
            # restarts from 1 each time replays the exact same key the
            # previous run already marked EXECUTED, and the coordinator
            # CORRECTLY refuses to re-actuate it (DUPLICATE_EXECUTED) --
            # observed directly while building this harness, not a defect in
            # the governed stack.
            run_id = uuid.uuid4().hex[:12]
            counter = {"n": 0}

            async def factory(i: int) -> bool:
                counter["n"] += 1
                return await _e2e_once(
                    stack, args.authority, f"bench-{run_id}-{args.mode}-{args.authority}-{counter['n']}"
                )

        if args.warmup:
            await _run_samples(factory, args.warmup, args.concurrency)

        if args.mode == "e2e":
            stack.reset_seen()
        samples = await _run_samples(factory, args.samples, args.concurrency)
        result_box["actuator_calls_observed"] = len(stack.seen) if args.mode == "e2e" else None
        return samples

    if args.warmup:
        warm_note = f"warmup: {args.warmup} discarded operations run first"
    else:
        warm_note = "warmup: NONE -- these are COLD numbers (first-call JIT/cache effects included)"

    result_box: Dict[str, Any] = {}
    durations = asyncio.run(run_all())
    durations_sorted = sorted(durations)
    total_wall = sum(durations)

    result: Dict[str, Any] = {
        "mode": args.mode,
        "authority": args.authority if args.mode == "e2e" else None,
        "backend": args.backend,
        "sample_size": len(durations_sorted),
        "concurrency": args.concurrency,
        "warm_or_cold": warm_note,
        "actuator_calls_observed": result_box.get("actuator_calls_observed"),
        "latency_seconds": {
            "p50": _percentile(durations_sorted, 50),
            "p95": _percentile(durations_sorted, 95),
            "p99": (_percentile(durations_sorted, 99)
                    if len(durations_sorted) >= MIN_SAMPLES_FOR_P99
                    else None),
            "p99_caveat": (None if len(durations_sorted) >= MIN_SAMPLES_FOR_P99 else
                           f"sample_size {len(durations_sorted)} < {MIN_SAMPLES_FOR_P99}: "
                           f"p99 not reported, would not be statistically meaningful"),
            "min": durations_sorted[0] if durations_sorted else None,
            "max": durations_sorted[-1] if durations_sorted else None,
        },
        "throughput_ops_per_sec": (len(durations_sorted) / total_wall) if total_wall > 0 else None,
        "throughput_caveat": (
            "computed from summed per-operation wall time under asyncio concurrency, "
            "NOT a dedicated-process wall-clock total-run throughput measurement"
        ),
        "environment": _environment_info(),
    }

    print(json.dumps(result, indent=2))
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"\nwritten to {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
