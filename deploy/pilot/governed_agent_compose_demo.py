"""Compose runner for the governed-agent pilot (mcc-agent service).

Runs inside the ``mcc-agent`` container. It drives the governed path over the
network: it submits proposals to the MCC gateway (the egress proxy) and the
gateway's governed HTTPS executor performs the real request to the separate
``pilot-api`` service. The agent container has **no** route to ``pilot-api`` —
only the gateway does — so a direct call is impossible (the bypass check).

This runner is deployment glue, not part of the ``mcc_agent`` package: it uses
an HTTP client to reach the gateway. It reuses ``mcc_agent.DeterministicPlanner``
to build proposal bodies/URLs. Verdicts come from the gateway's MCC-Core
authority (host/method/amount), demonstrating ALLOW / DENY / ESCALATE / CONSTRAIN
plus a bypass attempt over a real network boundary.
"""

from __future__ import annotations

import os
import sys
import time

import httpx

sys.path.insert(0, "/app/src")
sys.path.insert(0, "/app")

from mcc_agent import DeterministicPlanner  # noqa: E402

GATEWAY = os.environ.get("MCC_GATEWAY_URL", "http://mcc-gateway:8090")
PILOT_API = os.environ.get("PILOT_API_BASE", "http://pilot-api:9100")
API_KEY = os.environ.get("MCC_EGRESS_API_KEY", "agent-key")
OP_KEY = os.environ.get("MCC_EGRESS_OPERATOR_API_KEY", "op-key")
TRUSTED = os.environ.get("MCC_EGRESS_EGRESS_ACTOR_MANDATE", "agent/crm")
RESTRICTED = "agent/intern"

H = {"x-api-key": API_KEY}
OPH = {"x-operator-key": OP_KEY}


def _wait(client: httpx.Client, url: str, *, timeout: float = 60.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if client.get(url, timeout=2.0).status_code in (200, 503):
                return
        except Exception:
            time.sleep(1.0)
    raise RuntimeError(f"service at {url} did not become reachable")


def _execute(client, *, method, url, body, actor, resource, idem, approval_id=None):
    payload = {"method": method, "url": url, "body": body, "actor": actor,
               "resource": resource, "transaction_id": f"txn-{idem}",
               "idempotency_key": idem}
    if approval_id:
        payload["approval_id"] = approval_id
    r = client.post(f"{GATEWAY}/v1/http/execute", headers=H, json=payload, timeout=15.0)
    return r.json()


def main() -> int:
    planner = DeterministicPlanner(pilot_api_base=PILOT_API)
    failures = []
    with httpx.Client() as client:
        # Wait for the gateway readiness gate. The agent does NOT wait on (or have
        # a route to) pilot-api — only the gateway reaches it.
        _wait(client, f"{GATEWAY}/ready")

        print("\n=== Governed agent pilot over the network boundary ===\n")

        # ALLOW — trusted agent creates a CRM lead.
        p = planner.plan("Create a CRM lead for Alice with a campaign budget of 500 EUR")
        out = _execute(client, method="POST", url=p.url, body=p.body, actor=TRUSTED,
                       resource=p.resource, idem="allow-1")
        print(f"[ALLOW    ] outcome={out['outcome']} executed={out.get('executed')}")
        failures += [] if out.get("executed") else ["ALLOW did not execute"]

        # DENY — a method the mandate does not permit (not clampable -> DENY).
        out = _execute(client, method="DELETE", url=f"{PILOT_API}/leads", body=None,
                       actor=TRUSTED, resource="crm:lead", idem="deny-1")
        print(f"[DENY     ] outcome={out['outcome']} executed={out.get('executed')}")
        failures += [] if not out.get("executed") else ["DENY executed"]

        # CONSTRAIN — over-cap budget clamped to the mandate cap; original never sent.
        p = planner.plan("Set campaign budget to 10000 EUR")
        out = _execute(client, method="POST", url=p.url, body=p.body, actor=TRUSTED,
                       resource=p.resource, idem="constrain-1")
        sent = (out.get("upstream_body") or {}).get("budget", {}).get("amount")
        print(f"[CONSTRAIN] outcome={out['outcome']} executed={out.get('executed')} sent_amount={sent}")
        failures += [] if (out.get("executed") and sent == 5000) else ["CONSTRAIN not clamped"]

        # ESCALATE — restricted identity holds no mandate -> approval required.
        p = planner.plan("Increase campaign budget to 4000 EUR")
        out = _execute(client, method="POST", url=p.url, body=p.body, actor=RESTRICTED,
                       resource=p.resource, idem="escalate-1")
        rid = out.get("approval_request_id")
        print(f"[ESCALATE ] outcome={out['outcome']} approval={rid}")
        if rid and OP_KEY:
            client.post(f"{GATEWAY}/v1/approvals/{rid}/approve", headers=OPH, timeout=10.0)
            out2 = _execute(client, method="POST", url=p.url, body=p.body, actor=RESTRICTED,
                            resource=p.resource, idem="escalate-1", approval_id=rid)
            print(f"[ESCALATE ] after approval executed={out2.get('executed')}")
            failures += [] if out2.get("executed") else ["ESCALATE did not execute after approval"]
        else:
            failures.append("ESCALATE produced no approval request")

        # BYPASS — the agent has no network route to pilot-api directly.
        bypassed = False
        try:
            client.post(f"{PILOT_API}/leads", json={"name": "Mallory", "campaign_budget_eur": 1},
                        timeout=3.0)
            bypassed = True
        except Exception:
            print("[BYPASS   ] direct pilot-api call from agent failed (no route) ✓")
        failures += ["BYPASS reached pilot-api directly"] if bypassed else []

        # External state inspection is best-effort: the agent is NOT on the
        # gateway<->pilot-api network, so this typically fails (isolation proof).
        # Inspect from the host instead:  curl http://localhost:9100/operations
        try:
            ops = client.get(f"{PILOT_API}/operations", timeout=2.0)
            print(f"\npilot-api operations (unexpectedly reachable): {ops.json().get('count')}")
        except Exception:
            print("\npilot-api not reachable from the agent (network isolation) ✓")

    if failures:
        print("\nPILOT FAILED:", "; ".join(failures))
        return 1
    print("\nPILOT PASSED: ALLOW / DENY / ESCALATE / CONSTRAIN governed over the network.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
