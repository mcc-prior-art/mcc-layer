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

import os
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, Request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

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
    build_proxy_app,
)

GATEWAY_PORT = 8001
PROXY_PORT = 8080
UPSTREAM_PORT = 9009

# Upstream the agent wants to reach. It records every call it actually sees.
upstream = FastAPI()
SEEN: list[str] = []


@upstream.api_route("/{path:path}", methods=["GET", "POST", "DELETE"])
async def echo(request: Request, path: str):
    SEEN.append(f"{request.method} /{path}")
    return {"upstream_reached": True, "path": f"/{path}"}


def serve(app, port):
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")


def wait_for(url: str, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            httpx.get(url, timeout=0.5)
            return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError(f"service at {url} did not come up")


def main() -> None:
    governor = EgressGovernor(
        mapper=ActionMapper(
            [
                Route(action="send_payment", method="POST", host="*", path="*charge*"),
                Route(action="read_account", method="GET", host="*", path="*"),
                Route(action="delete_resource", method="DELETE", host="*", path="*"),
            ]
        ),
        decide=build_decide_via_http(f"http://127.0.0.1:{GATEWAY_PORT}", "demo-key"),
    )
    proxy = build_proxy_app(
        governor, upstream_base=f"http://127.0.0.1:{UPSTREAM_PORT}"
    )

    for app, port in [
        (upstream, UPSTREAM_PORT),
        (gw.app, GATEWAY_PORT),
        (proxy, PROXY_PORT),
    ]:
        threading.Thread(target=serve, args=(app, port), daemon=True).start()

    wait_for(f"http://127.0.0.1:{GATEWAY_PORT}/health")
    wait_for(f"http://127.0.0.1:{UPSTREAM_PORT}/")
    wait_for(f"http://127.0.0.1:{PROXY_PORT}/", timeout=10.0)

    base = f"http://127.0.0.1:{PROXY_PORT}"
    cases = [
        ("payments-bot, $100 charge (mandate, within cap)",
         "POST", "/charge", {"amount": 100}, "agent/payments-bot"),
        ("payments-bot, $99k charge (mandate, OVER cap)",
         "POST", "/charge", {"amount": 99000}, "agent/payments-bot"),
        ("ops-bot, DELETE resource (no mandate can authorize)",
         "DELETE", "/db/users", {}, "agent/ops-bot"),
        ("unknown-bot, payment (no mandate)",
         "POST", "/charge", {"amount": 1}, "agent/unknown"),
    ]

    print("\n=== Driving traffic through the MCC egress proxy (inline) ===\n")
    for label, method, path, body, identity in cases:
        r = httpx.request(
            method,
            base + path,
            json=body,
            headers={"X-MCC-Identity": identity},
            timeout=5.0,
        )
        decision = r.headers.get("X-MCC-Decision", "?")
        reached = r.status_code == 200 and r.json().get("upstream_reached")
        verdict_mark = "→ upstream REACHED" if reached else "✗ BLOCKED at proxy"
        print(f"[{decision:9}] {label}\n            {verdict_mark} (HTTP {r.status_code})")

    print(f"\nUpstream actually saw: {SEEN}")
    print("Only ALLOW/CONSTRAIN reached upstream. DENY/ESCALATE never opened the path.\n")


if __name__ == "__main__":
    main()
