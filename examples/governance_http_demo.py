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
import shutil
import sys
import tempfile
from pathlib import Path

import httpx
from fastapi import FastAPI, Request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from examples._demo_server import DemoServers  # noqa: E402

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


def mandate(key, **over):
    kw = dict(issuer="axlogiq-demo", subject="agent/x", action_scope=["generic_op"],
              resource_scope=["res-1"], constraints={}, not_before=PAST, not_after=FUTURE,
              revocation_required=True)
    kw.update(over)
    return issue_mandate(key, **kw)


def main() -> int:
    client = httpx.Client(timeout=5.0)
    servers = DemoServers()

    base = f"http://127.0.0.1:{GATEWAY_PORT}"
    failures = []

    def execute_mandate(m, **over):
        body = {"mandate": m, "actor": "agent/x", "action": "generic_op",
                "resource": "res-1", "context": CTX}
        body.update(over)
        return client.post(base + "/mandates/execute", headers=AGENT, json=body).json()

    try:
        # DemoServers.start() blocks until each server is ready (server.started).
        servers.start(upstream, UPSTREAM_PORT)
        servers.start(gw.app, GATEWAY_PORT)

        print("\n=== Governance HTTP end-to-end (real gateway + upstream) ===\n")

        # 1. valid mandate -> verified execution
        before = len(SEEN)
        out = execute_mandate(mandate(ISSUER), idempotency_key="op-1")
        ok1 = out["status"] == "EXECUTED" and len(SEEN) == before + 1
        print(f"[1] valid mandate              -> {out['status']}  (upstream {'reached' if ok1 else 'MISS'})")
        failures += [] if ok1 else ["scenario 1: valid mandate did not execute"]

        # 2. revoked mandate -> DENY, upstream untouched
        m = mandate(ISSUER)
        client.post(base + f"/mandates/{m['mandate_id']}/revoke", headers=OP)
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
        rid = client.post(base + "/approvals", headers=AGENT, json={
            "actor": "agent/x", "action": "generic_op", "resource": "res-1",
            "transaction_id": "txn-1", "policy_hash": gw.gateway.policy_hash,
            "payload_hash": __import__("mcc_core").hash_payload(CTX)}).json()["request_id"]
        appr = client.post(base + f"/approvals/{rid}/approve", headers=OP).json()
        before = len(SEEN)
        ex = client.post(base + f"/approvals/{rid}/execute", headers=AGENT, json={
            "mandate": appr["mandate"], "actor": "agent/x", "action": "generic_op",
            "resource": "res-1", "context": CTX, "transaction_id": "txn-1",
            "idempotency_key": "appr-1"}).json()
        ok4 = appr["mandate"] is not None and ex["status"] == "EXECUTED" and len(SEEN) == before + 1
        print(f"[4] ESCALATE -> approve -> exec-> {ex['status']}  (single execution: {ok4})")
        failures += [] if ok4 else ["scenario 4: approve+execute failed"]

        # 7. single-use: second execute blocked
        before = len(SEEN)
        ex2 = client.post(base + f"/approvals/{rid}/execute", headers=AGENT, json={
            "mandate": appr["mandate"], "actor": "agent/x", "action": "generic_op",
            "resource": "res-1", "context": CTX, "transaction_id": "txn-1",
            "idempotency_key": "appr-2"}).json()
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
    finally:
        # Deterministic teardown, while the interpreter is still healthy: stop +
        # join every embedded server (failing loudly if one will not stop), then
        # release the HTTP client and temp resources. Because the server threads
        # are joined here, no uvloop/libuv loop is still live at interpreter exit
        # — so no os._exit() workaround is needed to dodge a finalizer segfault.
        try:
            servers.stop_all()
        finally:
            client.close()
            shutil.rmtree(_trust_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
