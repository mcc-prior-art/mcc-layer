"""Test harness for the enforced egress proxy.

Spins up a live loopback upstream (records what it actually receives), generates
an independent evaluator pool + consensus trust config, and builds the real
egress app in consensus-required mode via ``build_app`` with injected settings.
Drives the proxy over its HTTP API exactly as a remote agent would, signing
evaluator votes with the local evaluator keys (the harness plays agent +
evaluators + operator).

Test scaffolding only — never imported by runtime code.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from mcc_core import SigningKey, issue_vote

from egress_proxy.app import build_app
from egress_proxy.canonical_action import build_canonical_action
from egress_proxy.config import EgressSettings
from egress_proxy.runtime import _policy_hash

FAR_FUTURE = 4_000_000_000


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class EgressHarness:
    def __init__(self, *, max_amount: int = 5000, allowed_methods: str = "get,post",
                 threshold: int = 3, n_evaluators: int = 3, env: Optional[Dict[str, str]] = None,
                 require_consensus: bool = True) -> None:
        self.upstream_port = _free_port()
        self.seen: List[Dict[str, Any]] = []
        self._start_upstream()

        self.evaluators = [SigningKey.generate(f"eval-{i}") for i in range(n_evaluators)]
        trust = {"issuers": [
            {"issuer_id": f"eval-{i}", "enabled": True,
             "keys": [{"kid": e.kid, "public_key_b64": e.public_key_b64(), "not_after": None}]}
            for i, e in enumerate(self.evaluators)]}
        tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(trust, tf); tf.close()

        self.settings = EgressSettings(
            mcc_env="dev", api_key="agent-key", operator_api_key="op-key",
            allowed_hosts="127.0.0.1", allowed_methods=allowed_methods, max_amount=max_amount,
            allow_loopback=True, require_consensus=require_consensus,
            consensus_threshold=threshold, consensus_trust_config=tf.name,
            audit_log_path=os.path.join(tempfile.mkdtemp(prefix="egress-test-"), "audit.jsonl"))
        self.app = build_app(self.settings, env=env or {})
        self.policy_hash = _policy_hash(self.settings)
        self.client = TestClient(self.app)
        self.H = {"x-api-key": "agent-key"}

    # -- upstream --

    def _start_upstream(self) -> None:
        up = FastAPI()
        seen = self.seen

        @up.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
        async def sink(request: Request, path: str):
            try:
                body = await request.json()
            except Exception:
                body = {}
            if request.method != "GET":
                seen.append({"method": request.method, "path": path, "body": body})
            return {"upstream_reached": True, "path": path, "received": body}

        threading.Thread(
            target=lambda: uvicorn.run(up, host="127.0.0.1", port=self.upstream_port,
                                       log_level="error"),
            daemon=True).start()
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                httpx.get(f"http://127.0.0.1:{self.upstream_port}/", timeout=0.3)
                return
            except Exception:
                time.sleep(0.05)
        raise RuntimeError("upstream did not start")

    def url(self, path: str = "/charge") -> str:
        return f"http://127.0.0.1:{self.upstream_port}{path}"

    @property
    def executor(self):
        return self.app.state.egress_service.rt.executor

    # -- helpers --

    def canonical(self, *, method: str, url: str, body: Any = None,
                  headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        return build_canonical_action(method=method, url=url, headers=headers or {}, body=body)

    def votes(self, action: Dict[str, Any], *, actor: str, nonce: str,
              payload: Optional[Dict[str, Any]] = None, count: Optional[int] = None,
              verdicts: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        pay = payload if payload is not None else action
        n = count if count is not None else len(self.evaluators)
        vs = verdicts or ["ALLOW"] * n
        return [issue_vote(self.evaluators[i], evaluator_id=self.evaluators[i].kid,
                           verdict=vs[i], action="http.request", payload=pay, actor=actor,
                           not_before=0, not_after=FAR_FUTURE, resource="acct-1",
                           policy_hash=self.policy_hash, nonce=nonce)
                for i in range(n)]

    def post(self, **fields) -> httpx.Response:
        base = {"resource": "acct-1"}
        base.update(fields)
        return self.client.post("/v1/http/execute", headers=self.H, json=base)

    def approve(self, request_id: str) -> httpx.Response:
        return self.client.post(f"/v1/approvals/{request_id}/approve",
                                headers={"x-operator-key": "op-key"})
