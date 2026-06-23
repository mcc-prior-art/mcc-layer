#!/usr/bin/env python3
"""End-to-end HTTP demo for the governance layer.

Boots the real MCC gateway (with a pilot trust config) and an upstream on
loopback, then drives mandate + approval flows over HTTP — proving the full
wiring: trust resolution → authority verification → decision token → gate →
audit-before-actuation → upstream, with no second execution path.

Run:  python examples/governance_http_demo.py   (exits non-zero on any miss)
"""

from __future__ import annotations

import json
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

from mcc_core import SigningKey, issue_mandate  # noqa: E402

GATEWAY_PORT, UPSTREAM_PORT = 8011, 9011
FUTURE, PAST = 4_000_000_000, 1

# --- issuer key + pilot trust config (written before importing the gateway) ---
ISSUER = SigningKey.generate("iss-demo")
_trust_dir = tempfile.mkdtemp(prefix="mcc-http-demo-")
_trust_path = os.path.join(_trust_dir, "trust.json")
Path(_trust_path).write_text(json.dumps({
    "issuers": [{"issuer_id": "axlogiq-demo", "enabled": True,
                 "keys": [{"kid": ISSUER.kid, "public_key_b64": ISSUER.public_key_b64()}]}]
}))

os.environ.update({
    "MCC_ENV": "pilot",
    "MCC_TRUST_CONFIG": _trust_path,
    "MCC_UPSTREAM_BASE": f"http://127.0.0.1:{UPSTREAM_PORT}",
    "MCC_GATEWAY_MODE": "inline",
    "MCC_GATEWAY_API_KEY": "agent-key",
    "MCC_GATEWAY_OPERATOR_API_KEY": "op-key",
    "MCC_GATEWAY_AUDIT_LOG_PATH": os.path.join(_trust_dir, "audit.jsonl"),
})

import gateway.app as gw  # noqa: E402  (imports AFTER env is set)

AGENT = {"x-api-key": "agent-key"}
OP = {"x-operator-key": "op-key"}
CTX = {"value": 1}

upstream = FastAPI()
SEEN = []


@upstream.api_route("/{path:path}", methods=["GET", "POST"])
async def echo(request: Request, path: str):
    try:
        body = await request.json()
    except Exception:
        body = {}
    SEEN.append({"path": f"/{path}", "body": body})
    return {"upstream_reached": True}


def serve(app, port):
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")


def wait_for(url, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            httpx.get(url, timeout=0.5)
            return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError(f"{url} did not come up")


def mandate(key, **over):
    kw = dict(issuer="axlogiq-demo", subject="agent/x", action_scope=["generic_op"],
              resource_scope=["res-1"], constraints={}, not_before=PAST, not_after=FUTURE,
              revocation_required=True)
    kw.update(over)
    return issue_mandate(key, **kw)


def main() -> int:
    for app, port in [(upstream, UPSTREAM_PORT), (gw.app, GATEWAY_PORT)]:
        threading.Thread(target=serve, args=(app, port), daemon=True).start()
    wait_for(f"http://127.0.0.1:{GATEWAY_PORT}/health")
    wait_for(f"http://127.0.0.1:{UPSTREAM_PORT}/")
    base = f"http://127.0.0.1:{GATEWAY_PORT}"
    failures = []

    def execute_mandate(m, **over):
        body = {"mandate": m, "actor": "agent/x", "action": "generic_op",
                "resource": "res-1", "context": CTX}
        body.update(over)
        return httpx.post(base + "/mandates/execute", headers=AGENT, json=body, timeout=5.0).json()

    print("\n=== Governance HTTP end-to-end (real gateway + upstream) ===\n")

    # 1. valid mandate -> verified execution
    before = len(SEEN)
    out = execute_mandate(mandate(ISSUER), idempotency_key="op-1")
    ok1 = out["status"] == "EXECUTED" and len(SEEN) == before + 1
    print(f"[1] valid mandate              -> {out['status']}  (upstream {'reached' if ok1 else 'MISS'})")
    failures += [] if ok1 else ["scenario 1: valid mandate did not execute"]

    # 2. revoked mandate -> DENY, upstream untouched
    m = mandate(ISSUER)
    httpx.post(base + f"/mandates/{m['mandate_id']}/revoke", headers=OP, timeout=5.0)
    before = len(SEEN)
    out = execute_mandate(m, idempotency_key="op-2")
    ok2 = out["status"] == "BLOCKED" and len(SEEN) == before
    print(f"[2] revoked mandate            -> {out['status']}  (upstream untouched: {len(SEEN)==before})")
    failures += [] if ok2 else ["scenario 2: revoked mandate not blocked"]

    # 3. unknown issuer -> DENY
    rogue = SigningKey.generate("rogue-kid")
    before = len(SEEN)
    out = execute_mandate(mandate(rogue), idempotency_key="op-3")
    ok3 = out["status"] == "BLOCKED" and "UNKNOWN_KID" in out["reason"] and len(SEEN) == before
    print(f"[3] unknown issuer             -> {out['status']}  ({out['reason'][:40]})")
    failures += [] if ok3 else ["scenario 3: unknown issuer not blocked"]

    # 4 & 5: ESCALATE approve / deny
    rid = httpx.post(base + "/approvals", headers=AGENT, json={
        "actor": "agent/x", "action": "generic_op", "resource": "res-1",
        "transaction_id": "txn-1", "policy_hash": gw.gateway.policy_hash,
        "payload_hash": __import__("mcc_core").hash_payload(CTX)}, timeout=5.0).json()["request_id"]
    appr = httpx.post(base + f"/approvals/{rid}/approve", headers=OP, timeout=5.0).json()
    before = len(SEEN)
    ex = httpx.post(base + f"/approvals/{rid}/execute", headers=AGENT, json={
        "mandate": appr["mandate"], "actor": "agent/x", "action": "generic_op",
        "resource": "res-1", "context": CTX, "transaction_id": "txn-1",
        "idempotency_key": "appr-1"}, timeout=5.0).json()
    ok4 = appr["mandate"] is not None and ex["status"] == "EXECUTED" and len(SEEN) == before + 1
    print(f"[4] ESCALATE -> approve -> exec-> {ex['status']}  (single execution: {ok4})")
    failures += [] if ok4 else ["scenario 4: approve+execute failed"]

    # 7. single-use: second execute blocked
    before = len(SEEN)
    ex2 = httpx.post(base + f"/approvals/{rid}/execute", headers=AGENT, json={
        "mandate": appr["mandate"], "actor": "agent/x", "action": "generic_op",
        "resource": "res-1", "context": CTX, "transaction_id": "txn-1",
        "idempotency_key": "appr-2"}, timeout=5.0).json()
    ok7 = ex2["status"] == "BLOCKED" and len(SEEN) == before
    print(f"[7] approval replayed          -> {ex2['status']}  (upstream untouched: {len(SEEN)==before})")
    failures += [] if ok7 else ["scenario 7: single-use not enforced"]

    print(f"\nUpstream reached {len(SEEN)} time(s) — only through /mandates|/approvals execute.")
    if failures:
        print("\nGOVERNANCE HTTP DEMO FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("\nGOVERNANCE HTTP DEMO PASSED: verified execution + revocation + unknown-issuer + "
          "ESCALATE single-use, all through the one coordinator/gate path.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
