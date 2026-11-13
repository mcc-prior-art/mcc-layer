"""Harness for the Real Governed Executor Pilot integration tests.

Builds the REAL gateway governance path in-process and drives it over real HTTP
with the supported SDK (``mcc_client``):

* the real ``Gateway`` (``/evaluate``) — authority verdicts + signed decision token;
* the real ``GovernanceService`` governed-execute routes (mandate / approval /
  consensus) via ``build_governance_service``;
* the **receipt-verifying governed-executor adapter** injected as the service's
  upstream, pointed at a real loopback mock notification service.

Nothing governance-related is stubbed or bypassed: the gate verifies the token
(signature/issuer/hashes/actor/resource/policy/nonce/replay/validity/scope), the
coordinator writes the audit-before-execution record, and only a confirmed,
matching receipt yields EXECUTED. The harness plays agent + evaluators + operator
(as the pilot driver does) so the consensus path can be exercised deterministically.

Test scaffolding only — never imported by runtime code.
"""

from __future__ import annotations

import json
import socket
import tempfile
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException

from mcc_core import ProfileRegistry, SigningKey, issue_vote

import gateway.app as gwmod
from gateway.governance_api import (
    mount_approval_routes,
    mount_consensus_routes,
    mount_mandate_routes,
)
from gateway.governance_api import build_governance_service

from examples._demo_server import DemoServer
import pilot_notify.service as notify_service
from pilot_notify import receipt_verifying_upstream, reset_receipts

FAR_FUTURE = 4_000_000_000
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
    p = s.getsockname()[1]
    s.close()
    return p


class NotifyPilotHarness:
    def __init__(self, *, n_evaluators: int = 3, threshold: int = 3,
                 upstream=None, env: Optional[Dict[str, str]] = None) -> None:
        reset_receipts()
        self.profiles = ProfileRegistry.default_pilot()

        # 1. Mock notification service (a real loopback HTTP service).
        self.notify_port = _free_port()
        self.notify_base = f"http://127.0.0.1:{self.notify_port}"

        # 2. Evaluator trust config (consensus).
        self.evaluators = [SigningKey.generate(f"eval-{i}") for i in range(n_evaluators)]
        trust = {"issuers": [
            {"issuer_id": f"eval-{i}", "enabled": True,
             "keys": [{"kid": e.kid, "public_key_b64": e.public_key_b64(), "not_after": None}]}
            for i, e in enumerate(self.evaluators)]}
        tf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(trust, tf)
        tf.close()

        # 3. The real gateway decision engine (issues + verifies the token). Give
        # it an ISOLATED audit chain (a fresh file) so parallel gateway apps in the
        # test session cannot interleave into the same hash chain.
        from mcc_core import AuditLog
        self.gateway = gwmod.Gateway()
        self._audit_path = tempfile.mkdtemp(prefix="notify-audit-") + "/audit.jsonl"
        self.gateway.audit = AuditLog(self._audit_path)
        self.policy_hash = self.gateway.policy_hash

        # 4. The governed execution service, with the receipt-verifying upstream.
        base_env = {"MCC_CONSENSUS_TRUST_CONFIG": tf.name,
                    "MCC_CONSENSUS_THRESHOLD": str(threshold)}
        if env:
            base_env.update(env)
        self.upstream = upstream or receipt_verifying_upstream(self.notify_base)
        self.service = build_governance_service(
            engine=self.gateway.engine, signing_key=self.gateway.signing_key,
            audit=self.gateway.audit, policy_hash=self.policy_hash,
            token_audience=gwmod.settings.token_audience, env=base_env, upstream=self.upstream)

        # 5. Assemble a real app: /evaluate + governed execute routes.
        self.app = self._build_app()

        # 6. Start the mock service + the gateway on loopback.
        self.servers = [DemoServer(notify_service.app, self.notify_port)]
        self.gw_port = _free_port()
        self.servers.append(DemoServer(self.app, self.gw_port))
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
            return "pilot"

        @app.post("/evaluate", response_model=gwmod.EvaluateResponse)
        def evaluate(req: gwmod.EvaluateRequest, _=Depends(require_api_key)):
            return self.gateway.evaluate(req)

        @app.get("/verify")
        def verify(_=Depends(require_api_key)):
            from mcc_core import AuditLog
            return {"valid": AuditLog.verify_chain(self.gateway.audit.path)}

        @app.get("/health")
        def health():
            return {"status": "ok", "policy_hash": self.gateway.policy_hash}

        mount_mandate_routes(app, self.service, api_key=API_KEY, operator_key=OPERATOR_KEY,
                         tenant_id=TENANT_ID, agent_credentials=registry)
        mount_approval_routes(app, self.service, api_key=API_KEY, operator_key=OPERATOR_KEY,
                         tenant_id=TENANT_ID, agent_credentials=registry)
        mount_consensus_routes(app, self.service, api_key=API_KEY, operator_key=OPERATOR_KEY,
                         tenant_id=TENANT_ID, agent_credentials=registry)
        return app

    # -- consensus votes (the harness plays the evaluators) --

    def votes(self, *, action: str, payload: Dict[str, Any], actor: str, nonce: str,
              resource: Optional[str] = None, count: Optional[int] = None,
              verdict: str = "ALLOW") -> List[Dict[str, Any]]:
        canonical = self.profiles.for_action(action).canonical_payload(payload)
        n = count if count is not None else len(self.evaluators)
        return [issue_vote(self.evaluators[i], evaluator_id=self.evaluators[i].kid,
                           verdict=verdict, action=action, payload=canonical, actor=actor,
                           not_before=0, not_after=FAR_FUTURE, resource=resource,
                           policy_hash=self.policy_hash, nonce=nonce)
                for i in range(n)]

    def close(self) -> None:
        for s in self.servers:
            s.stop()

    def __enter__(self) -> "NotifyPilotHarness":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
