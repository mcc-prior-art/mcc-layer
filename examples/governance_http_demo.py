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


def make_server(app, port):
    """Start a uvicorn server in a daemon thread and return (server, thread)
    handles so it can be shut down *explicitly* — ``uvicorn.run()`` gives no
    handle to stop the server, which is what forces a process to rely on native
    finalizers at exit."""
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None  # not the main thread
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    return server, thread


def shutdown(servers, threads, client, temp_dir):
    """Explicitly release everything the demo started, in order, before the
    process exits:

    * close the HTTP client (connection pool);
    * ask each uvicorn server to stop (``should_exit`` triggers its graceful
      shutdown, including the app's lifespan/shutdown);
    * join the server threads;
    * remove the temp trust + audit directory.

    The audit log holds no persistent file handle — ``AuditLog`` opens, writes,
    fsyncs and closes on every append — so removing the directory is a clean
    delete with nothing left open."""
    if client is not None:
        client.close()
    for server in servers:
        server.should_exit = True
    for thread in threads:
        thread.join(timeout=5.0)
    shutil.rmtree(temp_dir, ignore_errors=True)


def wait_for(client, url, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            client.get(url, timeout=0.5)
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
    client = httpx.Client(timeout=5.0)
    servers, threads = [], []
    for app, port in [(upstream, UPSTREAM_PORT), (gw.app, GATEWAY_PORT)]:
        server, thread = make_server(app, port)
        servers.append(server)
        threads.append(thread)

    base = f"http://127.0.0.1:{GATEWAY_PORT}"
    failures = []

    def execute_mandate(m, **over):
        body = {"mandate": m, "actor": "agent/x", "action": "generic_op",
                "resource": "res-1", "context": CTX}
        body.update(over)
        return client.post(base + "/mandates/execute", headers=AGENT, json=body).json()

    try:
        wait_for(client, f"http://127.0.0.1:{GATEWAY_PORT}/health")
        wait_for(client, f"http://127.0.0.1:{UPSTREAM_PORT}/")

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
        # Tear down everything we started, in order, while the interpreter is
        # still healthy — servers stopped, threads joined, client and temp
        # resources released — so process exit has nothing live left to finalize.
        shutdown(servers, threads, client, _trust_dir)


if __name__ == "__main__":
    rc = main()
    # All resources are explicitly released in main()'s finally block above.
    # The servers run uvloop/OpenSSL in (now-joined) threads; to remove any
    # residual chance of a native-finalizer race segfaulting at shutdown *after*
    # a successful run (intermittent exit 139), flush and exit immediately with
    # the real status code rather than running the interpreter's finalizers.
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(rc)
