"""Compose runner for the governed-agent pilot (mcc-agent service).

Runs inside the ``mcc-agent`` container. It drives the governed path over the
network: it submits proposals to the MCC gateway (the egress proxy) and the
gateway's governed HTTPS executor performs the real request to the separate
``pilot-api`` service. The agent container has **no** route to ``pilot-api`` —
only the gateway does — so a direct call is impossible (the bypass check).

Authority principal separation: this process holds ONLY its own per-agent
credential (F1b; ``MCC_AGENT_CREDENTIAL_FILE``). One container per principal:
``mcc-agent`` is agent/crm (ALLOW/DENY/CONSTRAIN), ``mcc-agent-escalate`` is
agent/intern (ESCALATE -> approval -> its own execution). It never holds, reads, or derives an operator key --
the ``mcc-operator`` service (``governed_agent_pilot_operator.py``) is a
separate process, running in a separate container, that holds
``MCC_EGRESS_OPERATOR_API_KEY``. For ESCALATE, this agent only writes a
non-secret pending-approval record (the approval ``request_id``, never a
credential) to a shared state file and then polls by resubmitting its own
original proposal -- a resubmission against a not-yet-approved request fails
cleanly (``APPROVAL_INVALID``, not an error), so this is a safe retry loop,
not a bypass. The agent cannot self-approve: it has no operator key to do so
even if its own code were compromised.

This runner is deployment glue, not part of the ``mcc_agent`` package: it uses
an HTTP client to reach the gateway. It reuses ``mcc_agent.DeterministicPlanner``
to build proposal bodies/URLs. Verdicts come from the gateway's MCC-Core
authority (host/method/amount), demonstrating ALLOW / DENY / ESCALATE / CONSTRAIN
plus a bypass attempt over a real network boundary.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, "/app/src")
sys.path.insert(0, "/app")

from mcc_agent import DeterministicPlanner  # noqa: E402

GATEWAY = os.environ.get("MCC_GATEWAY_URL", "http://mcc-gateway:8090")
PILOT_API = os.environ.get("PILOT_API_BASE", "http://pilot-api:9100")
TRUSTED = os.environ.get("MCC_EGRESS_EGRESS_ACTOR_MANDATE", "agent/crm")
RESTRICTED = "agent/intern"
STATE_DIR = Path(os.environ.get("MCC_PILOT_STATE_DIR", "/pilot-state"))
APPROVAL_WAIT_TIMEOUT_S = float(os.environ.get("MCC_APPROVAL_WAIT_TIMEOUT_S", "60.0"))
APPROVAL_POLL_INTERVAL_S = float(os.environ.get("MCC_APPROVAL_POLL_INTERVAL_S", "1.0"))



def _credential():
    """F1b: this container IS one principal. Its OWN provisioned credential
    (``MCC_AGENT_CREDENTIAL_FILE``) is the only key it holds; the gateway
    resolves the principal from it and refuses an ``actor`` naming anyone
    else. (``MCC_EGRESS_API_KEY`` + ``MCC_PILOT_PRINCIPAL`` remain only for
    an explicitly legacy-shared-key gateway.)"""
    path = os.environ.get("MCC_AGENT_CREDENTIAL_FILE", "").strip()
    if path:
        cred = json.loads(Path(path).read_text(encoding="utf-8"))
        key, principal = cred.get("api_key"), cred.get("principal_id")
        if not (isinstance(key, str) and key and isinstance(principal, str) and principal):
            sys.exit("MCC_AGENT_CREDENTIAL_FILE is malformed; fail-closed")
        return key, principal
    key = os.environ.get("MCC_EGRESS_API_KEY", "")
    if not key:
        sys.exit("set MCC_AGENT_CREDENTIAL_FILE (this agent's own credential); fail-closed")
    return key, os.environ.get("MCC_PILOT_PRINCIPAL", TRUSTED)


API_KEY, PRINCIPAL = _credential()
H = {"x-api-key": API_KEY}


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

        print(f"\n=== Governed agent pilot over the network boundary ({PRINCIPAL}) ===\n")

        # F1b: this agent's own key cannot act as another principal.
        other = RESTRICTED if PRINCIPAL == TRUSTED else TRUSTED
        r = client.post(f"{GATEWAY}/v1/http/execute", headers=H, timeout=15.0, json={
            "method": "POST", "url": f"{PILOT_API}/leads", "body": {"name": "x"},
            "actor": other, "resource": "crm:lead", "transaction_id": f"txn-imp-{PRINCIPAL}",
            "idempotency_key": f"imp-{PRINCIPAL}"})
        print(f"[IMPERSONATE] as {other}: HTTP {r.status_code}")
        failures += [] if r.status_code == 403 else [f"impersonating {other} was not refused"]

    if PRINCIPAL == TRUSTED:
        failures += _trusted_phases(planner)
    elif PRINCIPAL == RESTRICTED:
        failures += _restricted_phases(planner)
    else:
        failures.append(f"unexpected principal {PRINCIPAL!r}")

    if failures:
        print("\nPILOT FAILED:", "; ".join(failures))
        return 1
    print(f"\nPILOT PASSED ({PRINCIPAL}): governed over the network.")
    return 0


def _trusted_phases(planner) -> list:
    failures = []
    with httpx.Client() as client:
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
        failures += _bypass_checks(client)
    return failures


def _restricted_phases(planner) -> list:
    failures = []
    with httpx.Client() as client:
        # ESCALATE — restricted identity holds no mandate -> approval required.
        # This agent does not hold the operator key and cannot self-approve.
        # It records the (non-secret) request_id for the separate mcc-operator
        # process, then polls by resubmitting its OWN original proposal.
        p = planner.plan("Increase campaign budget to 4000 EUR")
        out = _execute(client, method="POST", url=p.url, body=p.body, actor=RESTRICTED,
                       resource=p.resource, idem="escalate-1")
        rid = out.get("approval_request_id")
        print(f"[ESCALATE ] outcome={out['outcome']} approval={rid}")
        if rid:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            (STATE_DIR / "escalation.json").write_text(
                json.dumps({"requestId": rid}), encoding="utf-8"
            )
            print(f"[ESCALATE ] recorded pending approval for the operator sidecar: {rid}")

            out2 = None
            deadline = time.time() + APPROVAL_WAIT_TIMEOUT_S
            while time.time() < deadline:
                out2 = _execute(client, method="POST", url=p.url, body=p.body, actor=RESTRICTED,
                                resource=p.resource, idem="escalate-1", approval_id=rid)
                if out2.get("executed"):
                    break
                if out2.get("error_code") != "APPROVAL_INVALID":
                    # Not a "still pending" response -- a real denial/failure.
                    break
                time.sleep(APPROVAL_POLL_INTERVAL_S)

            print(f"[ESCALATE ] after approval executed={out2.get('executed') if out2 else None}")
            failures += [] if (out2 and out2.get("executed")) else ["ESCALATE did not execute after approval"]
        else:
            failures.append("ESCALATE produced no approval request")
        failures += _bypass_checks(client)
    return failures


def _bypass_checks(client) -> list:
    failures = []
    if True:
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
    return failures


if __name__ == "__main__":
    sys.exit(main())
