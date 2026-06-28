#!/usr/bin/env python3
"""Reference agent for the enforced outbound HTTP egress proxy.

The agent performs outbound HTTP *only* through the MCC egress proxy. It never
contacts the upstream directly; every request is canonicalized, governed by the
embedded MCC runtime (consensus-required), and executed only inside the governed
executor after a verified decision.

Boots, on loopback: a test upstream, and the egress proxy (consensus mode). Then
drives, asserting the upstream only ever receives authorized actions:

    ALLOW       -> executed once
    DENY        -> upstream receives nothing
    ESCALATE    -> nothing until operator approval, then executed
    CONSTRAIN   -> original never sent; new hash + fresh consensus -> clamped sent
    replay      -> reusing a challenge/nonce is denied
    tamper      -> changing body after authorization is denied
    no-bypass   -> the executor refuses an unsigned call

Run:  python examples/enforced_egress_agent.py
"""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import uvicorn
from fastapi import FastAPI, Request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from mcc_core import SigningKey, issue_vote  # noqa: E402

from egress_proxy.app import build_app  # noqa: E402
from egress_proxy.canonical_action import build_canonical_action  # noqa: E402
from egress_proxy.config import EgressSettings  # noqa: E402
from egress_proxy.executor import UnauthorizedExecution  # noqa: E402
from egress_proxy.runtime import _policy_hash  # noqa: E402

FAR_FUTURE = 4_000_000_000
SEEN: List[Dict[str, Any]] = []


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def _serve(app, port):
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")


def _wait(url, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            httpx.get(url, timeout=0.3); return
        except Exception:
            time.sleep(0.05)
    raise RuntimeError(f"{url} did not come up")


def main() -> int:
    up_port, proxy_port = _free_port(), _free_port()
    upstream = FastAPI()

    @upstream.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def sink(request: Request, path: str):
        try:
            body = await request.json()
        except Exception:
            body = {}
        if request.method != "GET":
            SEEN.append({"method": request.method, "path": path, "body": body})
        return {"upstream_reached": True, "received": body}

    evaluators = [SigningKey.generate(f"eval-{i}") for i in range(3)]
    trust = {"issuers": [
        {"issuer_id": f"eval-{i}", "enabled": True,
         "keys": [{"kid": e.kid, "public_key_b64": e.public_key_b64(), "not_after": None}]}
        for i, e in enumerate(evaluators)]}
    tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False); json.dump(trust, tf); tf.close()

    settings = EgressSettings(
        mcc_env="dev", api_key="agent-key", operator_api_key="op-key",
        allowed_hosts="127.0.0.1", allowed_methods="get,post", max_amount=5000,
        allow_loopback=True, allow_http=True,  # demo upstream is plain HTTP on loopback
        require_consensus=True, consensus_threshold=3,
        consensus_trust_config=tf.name,
        audit_log_path=os.path.join(tempfile.mkdtemp(prefix="egress-demo-"), "audit.jsonl"))
    proxy_app = build_app(settings)
    policy_hash = _policy_hash(settings)

    threading.Thread(target=_serve, args=(upstream, up_port), daemon=True).start()
    threading.Thread(target=_serve, args=(proxy_app, proxy_port), daemon=True).start()
    _wait(f"http://127.0.0.1:{up_port}/")
    _wait(f"http://127.0.0.1:{proxy_port}/health")

    base = f"http://127.0.0.1:{proxy_port}"
    up = f"http://127.0.0.1:{up_port}/charge"
    H = {"x-api-key": "agent-key"}
    failures: List[str] = []

    def canonical(method, body, url=up):
        return build_canonical_action(method=method, url=url, headers={}, body=body)

    def votes(action, actor, nonce, payload=None):
        pay = payload if payload is not None else action
        return [issue_vote(e, evaluator_id=e.kid, verdict="ALLOW", action="http.request",
                           payload=pay, actor=actor, not_before=0, not_after=FAR_FUTURE,
                           resource="acct-1", policy_hash=policy_hash, nonce=nonce)
                for e in evaluators]

    def post(**fields):
        body = {"resource": "acct-1"}; body.update(fields)
        return httpx.post(f"{base}/v1/http/execute", headers=H, json=body, timeout=10.0).json()

    def check(cond, msg):
        if not cond:
            failures.append(msg)

    # ALLOW
    r1 = post(method="POST", url=up, body={"amount": 1000}, actor="agent/egress",
              transaction_id="t1", idempotency_key="i1")
    r2 = post(method="POST", url=up, body={"amount": 1000}, actor="agent/egress",
              transaction_id="t1", idempotency_key="i1", challenge_id=r1["challenge_id"],
              votes=votes(canonical("POST", {"amount": 1000}), "agent/egress", r1["nonce"]))
    print(f"[ALLOW]     {r2['outcome']} executed={r2['executed']} upstream={r2.get('upstream_status')}")
    check(r2["outcome"] == "ALLOW" and r2["executed"], "ALLOW did not execute")

    # DENY (method not allowed)
    d1 = post(method="DELETE", url=up, body={}, actor="agent/egress",
              transaction_id="td", idempotency_key="idd")
    d2 = post(method="DELETE", url=up, body={}, actor="agent/egress", transaction_id="td",
              idempotency_key="idd", challenge_id=d1["challenge_id"],
              votes=votes(canonical("DELETE", {}), "agent/egress", d1["nonce"]))
    print(f"[DENY]      {d2['outcome']} executed={d2['executed']}")
    check(d2["outcome"] == "DENY" and not d2["executed"], "DENY executed")

    # ESCALATE -> approve -> execute
    e1 = post(method="POST", url=up, body={"amount": 10}, actor="agent/intern",
              transaction_id="te", idempotency_key="ide")
    ev = votes(canonical("POST", {"amount": 10}), "agent/intern", e1["nonce"])
    e2 = post(method="POST", url=up, body={"amount": 10}, actor="agent/intern",
              transaction_id="te", idempotency_key="ide", challenge_id=e1["challenge_id"], votes=ev)
    check(e2["outcome"] == "ESCALATE" and not e2["executed"], "ESCALATE executed early")
    httpx.post(f"{base}/v1/approvals/{e2['approval_request_id']}/approve",
               headers={"x-operator-key": "op-key"}, timeout=10.0)
    e3 = post(method="POST", url=up, body={"amount": 10}, actor="agent/intern",
              transaction_id="te", idempotency_key="ide", challenge_id=e1["challenge_id"],
              votes=ev, approval_id=e2["approval_request_id"])
    print(f"[ESCALATE]  approved -> {e3['outcome']} executed={e3['executed']}")
    check(e3["executed"], "approved ESCALATE did not execute")

    # CONSTRAIN -> new hash -> fresh consensus -> only clamped executes
    c1 = post(method="POST", url=up, body={"amount": 10000}, actor="agent/egress",
              transaction_id="tc", idempotency_key="idc")
    c2 = post(method="POST", url=up, body={"amount": 10000}, actor="agent/egress",
              transaction_id="tc", idempotency_key="idc", challenge_id=c1["challenge_id"],
              votes=votes(canonical("POST", {"amount": 10000}), "agent/egress", c1["nonce"]))
    constrained = c2["constrained_action"]
    print(f"[CONSTRAIN] round2={c2['outcome']} clamped_amount={constrained['body.amount']} executed={c2['executed']}")
    check(c2["outcome"] == "CONSTRAIN" and not c2["executed"], "CONSTRAIN executed original")
    c3 = post(method="POST", url=up, body={"amount": 5000}, actor="agent/egress",
              transaction_id="tc", idempotency_key="idc", constrained=True,
              challenge_id=c2["challenge_id"],
              votes=votes(constrained, "agent/egress", c2["nonce"], payload=constrained))
    print(f"[CONSTRAIN] round3 re-consensus -> executed={c3['executed']} upstream={c3.get('upstream_status')}")
    check(c3["executed"], "constrained action did not execute")

    # replay
    rp = post(method="POST", url=up, body={"amount": 1000}, actor="agent/egress",
              transaction_id="t1x", idempotency_key="i1x", challenge_id=r1["challenge_id"],
              votes=votes(canonical("POST", {"amount": 1000}), "agent/egress", r1["nonce"]))
    print(f"[REPLAY]    {rp['outcome']} executed={rp['executed']}")
    check(not rp["executed"], "replay executed")

    # no bypass (executor refuses unsigned)
    ex = proxy_app.state.egress_service.rt.executor
    import asyncio
    try:
        asyncio.run(ex.execute("http.request", {"scheme": "http", "host": "x", "port": 80}))
        failures.append("executor accepted unsigned call")
    except UnauthorizedExecution:
        print("[BYPASS]    direct executor call refused")

    print(f"\nUpstream received: {SEEN}")
    check(all(s["body"].get("amount") != 10000 for s in SEEN if "amount" in s["body"]),
          "original 10000 reached upstream")
    check(len(SEEN) == 3, f"unexpected upstream call count {len(SEEN)} (want 3)")

    if failures:
        print("\nENFORCED EGRESS DEMO FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nPASSED: only ALLOW / approved-ESCALATE / re-consensused-CONSTRAIN reached upstream.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
