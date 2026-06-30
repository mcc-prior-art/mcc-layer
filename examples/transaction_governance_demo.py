#!/usr/bin/env python3
"""End-to-end transaction-governance demo.

Drives real traffic through the full stack — upstream + MCC gateway + MCC egress
proxy running the EnforcementCoordinator — and proves, at the HTTP boundary:

* a payment executes once and reaches the upstream;
* a duplicate idempotency key never executes again;
* four individually-valid payments cannot bypass the cumulative velocity ceiling.

Run:  python examples/transaction_governance_demo.py   (exits non-zero on any miss)
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import httpx
from fastapi import FastAPI, Request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from examples._demo_server import DemoServers  # noqa: E402

os.environ["MCC_GATEWAY_MODE"] = "inline"
os.environ["MCC_GATEWAY_AUDIT_LOG_PATH"] = os.path.join(
    tempfile.mkdtemp(prefix="mcc-gov-gw-"), "audit.jsonl"
)

import gateway.app as gw  # noqa: E402
from gateway.pilot_policy import PILOT_VELOCITY  # noqa: E402
from interceptors.egress_proxy import (  # noqa: E402
    ActionMapper,
    EgressGovernor,
    Route,
    build_coordinator,
    build_decide_via_http,
    build_gate_from_health,
    build_proxy_app,
)

GATEWAY_PORT, PROXY_PORT, UPSTREAM_PORT = 8001, 8080, 9009

upstream = FastAPI()
SEEN: list[dict] = []


@upstream.api_route("/{path:path}", methods=["GET", "POST", "DELETE"])
async def echo(request: Request, path: str):
    try:
        body = await request.json()
    except Exception:
        body = {}
    SEEN.append({"path": f"/{path}", "body": body})
    return {"upstream_reached": True, "received": body}


def main() -> int:
    servers = DemoServers()
    try:
        return _run(servers)
    finally:
        # Deterministic teardown: stop + join every embedded server before the
        # interpreter exits, on success and on exception alike.
        servers.stop_all()


def _run(servers: DemoServers) -> int:
    # DemoServers.start() blocks until each server is ready (server.started); the
    # gateway must be up before build_gate_from_health probes its /health.
    servers.start(upstream, UPSTREAM_PORT)
    servers.start(gw.app, GATEWAY_PORT)

    gateway_url = f"http://127.0.0.1:{GATEWAY_PORT}"
    gate = build_gate_from_health(gateway_url)
    coordinator = build_coordinator(
        gate,
        velocity_config=PILOT_VELOCITY,
        audit_path=os.path.join(tempfile.mkdtemp(prefix="mcc-gov-px-"), "audit.jsonl"),
    )
    governor = EgressGovernor(
        mapper=ActionMapper([Route(action="send_payment", method="POST", host="*", path="*charge*")]),
        decide=build_decide_via_http(gateway_url, "demo-key"),
        gate=gate,
    )
    proxy = build_proxy_app(
        governor, upstream_base=f"http://127.0.0.1:{UPSTREAM_PORT}", coordinator=coordinator
    )
    servers.start(proxy, PROXY_PORT)

    base = f"http://127.0.0.1:{PROXY_PORT}"

    def pay(idem, amount, beneficiary="ben-1"):
        return httpx.post(
            base + "/charge",
            json={"source": "acct-1", "beneficiary_id": beneficiary,
                  "amount": amount, "currency": "USD"},
            headers={"X-MCC-Identity": "agent/payments-bot",
                     "X-MCC-Idempotency-Key": idem,
                     "X-MCC-Transaction-Id": f"txn-{idem}"},
            timeout=5.0,
        )

    cases = [
        ("op-1 $4000 (first payment)", lambda: pay("op-1", 4000), True, "executes"),
        ("op-1 $4000 REPLAYED (same idempotency key)", lambda: pay("op-1", 4000), False, "idempotency dedup"),
        ("op-2 $4000 (cumulative 8000)", lambda: pay("op-2", 4000), True, "within ceiling"),
        ("op-3 $4000 (cumulative 12000 > 10000)", lambda: pay("op-3", 4000), False, "velocity ceiling"),
    ]

    print("\n=== Transaction governance through MCC (gateway + coordinator proxy) ===\n")
    failures = []
    for label, call, expect_exec, why in cases:
        r = call()
        reached = r.status_code == 200 and r.json().get("upstream_reached")
        mark = "→ EXECUTED (upstream reached)" if reached else "✗ BLOCKED before upstream"
        print(f"[{r.status_code}] {label}\n        {mark}  [{why}]")
        if reached != expect_exec:
            failures.append(f"{label}: expected {'exec' if expect_exec else 'block'}, got HTTP {r.status_code}")

    payments = [s for s in SEEN if "amount" in s["body"]]
    print(f"\nUpstream actually executed {len(payments)} payment(s).")
    if len(payments) != 2:
        failures.append(f"expected exactly 2 executed payments at upstream, saw {len(payments)}")

    if failures:
        print("\nGOVERNANCE SMOKE FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("\nGOVERNANCE SMOKE PASSED: once-only execution + cumulative ceiling held end-to-end.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
