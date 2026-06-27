#!/usr/bin/env python3
"""Compose reference agent: outbound HTTP only via the MCC egress proxy.

Runs inside the pilot's application network, which has NO route to the upstream.
It proves:

1. a direct call to the upstream is impossible from the agent network;
2. the same call succeeds through the egress proxy after MCC authorizes it;
3. an over-cap request is CONSTRAINed (clamped) before it reaches the upstream;
4. a disallowed action is denied and never reaches the upstream.

The proxy here runs in non-consensus authority mode (one-shot ALLOW/DENY/
CONSTRAIN) so the boundary is demonstrable without evaluator-vote choreography;
the full consensus + re-consensus path is covered by
``examples/enforced_egress_agent.py`` and the test suite.

Env:
    MCC_EGRESS_PROXY_URL   e.g. http://mcc-egress-proxy:8090
    MCC_EGRESS_API_KEY     agent X-API-Key
    MCC_UPSTREAM_DIRECT    e.g. http://upstream-echo:9100/charge (must be unreachable)
    MCC_UPSTREAM_VIA_PROXY e.g. http://upstream-echo:9100/charge (reached via proxy)
"""

from __future__ import annotations

import os
import sys
import time

import httpx


def _post(proxy: str, key: str, **fields):
    return httpx.post(f"{proxy}/v1/http/execute", headers={"x-api-key": key},
                      json=fields, timeout=10.0).json()


def main() -> int:
    proxy = os.environ.get("MCC_EGRESS_PROXY_URL", "http://mcc-egress-proxy:8090")
    key = os.environ.get("MCC_EGRESS_API_KEY", "egress-demo-key")
    direct = os.environ.get("MCC_UPSTREAM_DIRECT", "http://upstream-echo:9100/charge")
    via = os.environ.get("MCC_UPSTREAM_VIA_PROXY", "http://upstream-echo:9100/charge")

    # Wait for the proxy to be ready.
    for _ in range(60):
        try:
            if httpx.get(f"{proxy}/ready", timeout=2.0).json().get("ready"):
                break
        except Exception:
            pass
        time.sleep(1)

    failures = []

    # 1. Direct egress must be impossible from this network.
    try:
        httpx.post(direct, json={"amount": 1}, timeout=3.0)
        failures.append("DIRECT upstream call SUCCEEDED — network boundary not enforced")
        print("[DIRECT]   upstream reachable directly (BAD)")
    except Exception as exc:
        print(f"[DIRECT]   blocked: {type(exc).__name__} (no route to upstream)")

    # 2. ALLOW via the proxy.
    a = _post(proxy, key, method="POST", url=via, body={"amount": 1000}, actor="agent/egress",
              transaction_id="c-allow", idempotency_key="c-allow")
    print(f"[ALLOW]    {a['outcome']} executed={a.get('executed')} upstream={a.get('upstream_status')}")
    if not (a["outcome"] == "ALLOW" and a.get("executed")):
        failures.append("ALLOW via proxy did not execute")

    # 3. CONSTRAIN (over cap) -> clamped.
    c = _post(proxy, key, method="POST", url=via, body={"amount": 999999}, actor="agent/egress",
              transaction_id="c-con", idempotency_key="c-con")
    print(f"[CONSTRAIN] {c['outcome']} executed={c.get('executed')}")
    if c["outcome"] != "CONSTRAIN":
        failures.append("over-cap request was not constrained")

    # 4. DENY (disallowed method).
    d = _post(proxy, key, method="DELETE", url=via, body={}, actor="agent/egress",
              transaction_id="c-deny", idempotency_key="c-deny")
    print(f"[DENY]     {d['outcome']} executed={d.get('executed')}")
    if d.get("executed"):
        failures.append("DENY executed")

    if failures:
        print("\nFAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nPASSED: agent reaches upstream only through the governed proxy; direct egress blocked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
