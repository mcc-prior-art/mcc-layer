#!/usr/bin/env python3
"""End-to-end demo: an agent's outbound calls physically pass through MCC.

Starts three real services on loopback —

    upstream echo  (the thing the agent is trying to reach)
    MCC gateway    (POST /evaluate, inline mode)
    MCC egress proxy (the one interceptor)

— and drives traffic through the proxy. The point it proves: a DENY is a
connection the upstream never sees. DENY means DENY because MCC owns the path.

Run:  python examples/egress_proxy_demo.py
"""

from __future__ import annotations

import asyncio
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

# Gateway settings must be set before importing the gateway module.
os.environ["MCC_GATEWAY_MODE"] = "inline"
os.environ["MCC_GATEWAY_AUDIT_LOG_PATH"] = os.path.join(
    tempfile.mkdtemp(prefix="mcc-demo-"), "audit.jsonl"
)

import gateway.app as gw  # noqa: E402
from interceptors.egress_proxy import (  # noqa: E402
    ActionMapper,
    EgressGovernor,
    Route,
    build_decide_via_http,
    build_gate_from_health,
    build_proxy_app,
)

GATEWAY_PORT = 8001
PROXY_PORT = 8080
UPSTREAM_PORT = 9009

# Upstream the agent wants to reach. It records every call it actually sees,
# including the body — so we can prove CONSTRAIN rewrote it before it arrived.
upstream = FastAPI()
SEEN: list[dict] = []


@upstream.api_route("/{path:path}", methods=["GET", "POST", "DELETE"])
async def echo(request: Request, path: str):
    try:
        body = await request.json()
    except Exception:
        body = {}
    SEEN.append({"method": request.method, "path": f"/{path}", "body": body})
    return {"upstream_reached": True, "path": f"/{path}", "received": body}


def main() -> int:
    servers = DemoServers()
    try:
        return _run(servers)
    finally:
        # Deterministic teardown: stop + join every embedded server (and fail
        # loudly if one will not stop) before the interpreter exits. Runs on
        # success and on exception — never relies on daemon-thread termination.
        servers.stop_all()


def _run(servers: DemoServers) -> int:
    # Start the gateway and upstream first; the proxy's ExecutionGate is keyed
    # from the gateway's /health, so the gateway must be up before we build it.
    # DemoServers.start() blocks until each server is ready (server.started).
    servers.start(upstream, UPSTREAM_PORT)
    servers.start(gw.app, GATEWAY_PORT)

    gateway_url = f"http://127.0.0.1:{GATEWAY_PORT}"
    governor = EgressGovernor(
        mapper=ActionMapper(
            [
                Route(action="send_payment", method="POST", host="*", path="*charge*"),
                Route(action="read_account", method="GET", host="*", path="*"),
                Route(action="delete_resource", method="DELETE", host="*", path="*"),
            ]
        ),
        decide=build_decide_via_http(gateway_url, "demo-key"),
        gate=build_gate_from_health(gateway_url),  # verifies signature + nonce
    )
    proxy = build_proxy_app(governor, upstream_base=f"http://127.0.0.1:{UPSTREAM_PORT}")
    servers.start(proxy, PROXY_PORT)

    base = f"http://127.0.0.1:{PROXY_PORT}"
    cases = [
        ("payments-bot, $100 charge (mandate, within cap)",
         "POST", "/charge", {"amount": 100}, "agent/payments-bot", "ALLOW"),
        ("payments-bot, $99k charge (mandate, OVER cap -> clamp to 5000)",
         "POST", "/charge", {"amount": 99000}, "agent/payments-bot", "CONSTRAIN"),
        ("ops-bot, DELETE resource (no mandate can authorize)",
         "DELETE", "/db/users", {}, "agent/ops-bot", "DENY"),
        ("unknown-bot, payment (no mandate)",
         "POST", "/charge", {"amount": 1}, "agent/unknown", "ESCALATE"),
    ]

    print("\n=== Driving traffic through the MCC egress proxy (inline) ===\n")
    failures = []
    for label, method, path, body, identity, expected in cases:
        r = httpx.request(
            method, base + path, json=body,
            headers={"X-MCC-Identity": identity}, timeout=5.0,
        )
        decision = r.headers.get("X-MCC-Decision", "?")
        reached = r.status_code == 200 and r.json().get("upstream_reached")
        mark = "→ upstream REACHED" if reached else "✗ BLOCKED at proxy"
        extra = ""
        if decision == "CONSTRAIN":
            extra = f"  body rewritten to: {r.json().get('received')}"
        print(f"[{decision:9}] {label}\n            {mark} (HTTP {r.status_code}){extra}")

        # Assertions for the smoke test.
        if decision != expected:
            failures.append(f"{label}: decision {decision} != expected {expected}")
        if expected in ("ALLOW", "CONSTRAIN") and not reached:
            failures.append(f"{label}: executable verdict did not reach upstream")
        if expected in ("DENY", "ESCALATE") and reached:
            failures.append(f"{label}: blocked verdict reached upstream")
        if expected == "CONSTRAIN":
            got = (r.json().get("received") or {}).get("amount")
            if got != 5000:
                failures.append(f"{label}: amount not clamped (got {got!r}, want 5000)")

    print(f"\nUpstream actually saw: {SEEN}")
    print("Only ALLOW/CONSTRAIN reached upstream. DENY/ESCALATE never opened the path.")

    # Replay protection: a captured, validly-signed token cannot be used twice.
    # Mint one token, then verify it through the proxy's gate twice — the nonce
    # must make the second attempt fail.
    print("\n=== Replay protection (single-use nonce) ===")
    ev = httpx.post(
        f"{gateway_url}/evaluate",
        json={"identity": "agent/payments-bot", "action": "send_payment",
              "context": {"amount": 42}, "mode": "inline"},
        headers={"x-api-key": "demo-key"}, timeout=5.0,
    ).json()
    token, fctx = ev["decision_token"], ev["forward_context"]
    first = asyncio.run(governor.gate.verify(token, action="send_payment", payload=fctx))
    second = asyncio.run(governor.gate.verify(token, action="send_payment", payload=fctx))
    print(f"first use:  allowed={first.allowed}  ({first.reason})")
    print(f"replayed:   allowed={second.allowed}  ({second.reason})")
    if not first.allowed:
        failures.append("replay: first legitimate use was rejected")
    if second.allowed:
        failures.append("replay: a reused token was accepted (no replay protection)")

    if failures:
        print("\nSMOKE TEST FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nSMOKE TEST PASSED: ALLOW passes, CONSTRAIN rewrites body, DENY/ESCALATE blocked.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
