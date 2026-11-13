"""Private demo harness: a self-contained, in-process governed stack for the CLI.

This is NOT part of the agent. Like ``examples/_demo_server.py`` and
``tests/_notify_harness.py`` it is demo/test scaffolding whose job is to stand up
the *environment* the agent runs against — the real MCC gateway, a mock external
notification service, and the receipt-verifying governed executor — on loopback,
so ``python -m examples.reference_governed_agent.cli`` works with zero setup.

The agent still only talks to the gateway through the SDK. The governed executor
(inside the gateway) is the only thing that calls the mock service. Underscore-
prefixed on purpose: the bypass-resistance guard scans the agent modules, not this
harness (standing up a governed gateway is not the agent executing).
"""

from __future__ import annotations

import json
import socket
import tempfile

from fastapi import Depends, FastAPI, Header, HTTPException

from mcc_core import AuditLog, ProfileRegistry, SigningKey

import gateway.app as gwmod
from gateway.governance_api import (
    build_governance_service,
    mount_approval_routes,
    mount_consensus_routes,
    mount_mandate_routes,
)

import pilot_notify.service as notify_service
from pilot_notify import receipt_verifying_upstream, reset_receipts

from examples._demo_server import DemoServer

from .authorizers import ConsensusAuthorizer

API_KEY = "demo-key"
OPERATOR_KEY = "op-key"

# V05 (part 2): per-agent identity. API_KEY stays the tenant's SHARED key
# (accepted on /evaluate, /verify, /consensus/*, /mandates/verify, GET
# /approvals/{id}); it grants NO agent identity on the identity routes
# (/mandates/execute, /approvals, /approvals/{id}/execute). There, each
# principal below presents its OWN registered credential, agent_key(principal).
TENANT_ID = "pilot"
AGENT_PRINCIPALS = ("agent/notify-bot", "agent/unknown", "agent/other-unknown",
                    "agent/axflow-clinic", "agent/ATTACKER")


def agent_key(principal_id: str) -> str:
    """The per-agent credential ``principal_id`` presents as X-API-Key."""
    return f"{API_KEY}::agent::{principal_id}"


def _agent_registry():
    from gateway.agent_identity import AgentCredentialRegistry, hash_agent_key
    return AgentCredentialRegistry.from_config({"agents": [
        {"credential_id": f"cred-{p}", "tenant_id": TENANT_ID, "principal_id": p,
         "key_sha256": hash_agent_key(agent_key(p)), "status": "active"}
        for p in AGENT_PRINCIPALS]})


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


class LocalGovernedStack:
    """A loopback MCC gateway + mock notification service + governed executor."""

    def __init__(self, *, n_evaluators: int = 3, threshold: int = 3) -> None:
        reset_receipts()
        self.profiles = ProfileRegistry.default_pilot()

        # 1. Mock external notification service (loopback).
        self.notify_port = _free_port()
        self.notify_base = f"http://127.0.0.1:{self.notify_port}"

        # 2. Evaluator trust (consensus authorization material).
        self.evaluators = [SigningKey.generate(f"eval-{i}") for i in range(n_evaluators)]
        trust = {"issuers": [
            {"issuer_id": f"eval-{i}", "enabled": True,
             "keys": [{"kid": e.kid, "public_key_b64": e.public_key_b64(), "not_after": None}]}
            for i, e in enumerate(self.evaluators)]}
        tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(trust, tf)
        tf.close()

        # 3. Real gateway decision engine with an isolated audit chain.
        self.gateway = gwmod.Gateway()
        self._audit_path = tempfile.mkdtemp(prefix="refagent-audit-") + "/audit.jsonl"
        self.gateway.audit = AuditLog(self._audit_path)
        self.policy_hash = self.gateway.policy_hash

        # 4. Governed execution service with the receipt-verifying upstream.
        env = {"MCC_CONSENSUS_TRUST_CONFIG": tf.name,
               "MCC_CONSENSUS_THRESHOLD": str(threshold)}
        self.upstream = receipt_verifying_upstream(self.notify_base)
        self.service = build_governance_service(
            engine=self.gateway.engine, signing_key=self.gateway.signing_key,
            audit=self.gateway.audit, policy_hash=self.policy_hash,
            token_audience=gwmod.settings.token_audience, env=env, upstream=self.upstream)

        # 5. Assemble the app and start both servers.
        self.app = self._build_app()
        self.gw_port = _free_port()
        self.servers = [
            DemoServer(notify_service.app, self.notify_port),
            DemoServer(self.app, self.gw_port),
        ]
        for s in self.servers:
            s.start()
        self.base_url = f"http://127.0.0.1:{self.gw_port}"

    def _build_app(self) -> FastAPI:
        app = FastAPI()
        registry = _agent_registry()

        def require_api_key(x_api_key: str = Header(...)) -> str:
            # The shared tenant key, or any registered agent credential of
            # this tenant (an agent needs only its own key).
            if x_api_key != API_KEY and registry.resolve(x_api_key, tenant_id=TENANT_ID).agent is None:
                raise HTTPException(status_code=401, detail="INVALID_API_KEY")
            return "agent"

        @app.post("/evaluate", response_model=gwmod.EvaluateResponse)
        def evaluate(req: gwmod.EvaluateRequest, _=Depends(require_api_key)):
            return self.gateway.evaluate(req)

        @app.get("/verify")
        def verify(_=Depends(require_api_key)):
            return {"valid": AuditLog.verify_chain(self.gateway.audit.path)}

        @app.get("/ready")
        def ready():
            return {"ready": True}

        mount_mandate_routes(app, self.service, api_key=API_KEY, operator_key=OPERATOR_KEY,
                         tenant_id=TENANT_ID, agent_credentials=registry)
        mount_approval_routes(app, self.service, api_key=API_KEY, operator_key=OPERATOR_KEY,
                         tenant_id=TENANT_ID, agent_credentials=registry)
        mount_consensus_routes(app, self.service, api_key=API_KEY, operator_key=OPERATOR_KEY,
                         tenant_id=TENANT_ID, agent_credentials=registry)
        return app

    def authorizer(self) -> ConsensusAuthorizer:
        return ConsensusAuthorizer(
            self.evaluators, policy_hash=self.policy_hash,
            threshold=len(self.evaluators), profiles=self.profiles)

    def close(self) -> None:
        for s in self.servers:
            s.stop()

    def __enter__(self) -> "LocalGovernedStack":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


__all__ = ["LocalGovernedStack", "API_KEY", "OPERATOR_KEY"]
