#!/usr/bin/env python3
"""In-process governed stack for the VoltAgent integration tests.

Stands up, on fixed loopback ports, the REAL MCC governance path plus the two
independent MCC-side roles the VoltAgent integration runs against:

    gateway  (:GW)   real Gateway (/evaluate) + governed execute routes
                     (mandate/approval/consensus) + receipt-verifying executor,
                     with consensus enabled (evaluator trust config).
    quorum   (:Q)    independent N-of-M evaluator quorum (holds evaluator keys).
    notify   (:N)    mock external notification service (the governed target).

The VoltAgent TypeScript tests talk ONLY to the gateway + quorum over HTTP; the
mock notification service is reachable by the governed executor, never by the
agent. Nothing governance-related is stubbed or bypassed.

Prints ``MCC_TESTSERVER_READY <json>`` once all three are serving, then blocks
until terminated. Ports come from the environment (defaults below).
"""

from __future__ import annotations

import json
import os
import signal
import sys
import tempfile
import threading
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from mcc_core import AuditLog  # noqa: E402

import gateway.app as gwmod  # noqa: E402
from gateway.governance_api import (  # noqa: E402
    build_governance_service,
    mount_approval_routes,
    mount_consensus_routes,
    mount_mandate_routes,
)

import pilot_notify.service as notify_service  # noqa: E402
from pilot_notify import receipt_verifying_upstream, reset_receipts  # noqa: E402

from examples._demo_server import DemoServer  # noqa: E402

from integrations.voltagent.mcc_side.evaluator_quorum import (  # noqa: E402
    QuorumSettings,
    build_quorum_app,
    load_evaluator_keys,
)
from integrations.voltagent.mcc_side.generate_config import generate  # noqa: E402

API_KEY = os.environ.get("MCC_GATEWAY_API_KEY", "demo-key")
OPERATOR_KEY = os.environ.get("MCC_GATEWAY_OPERATOR_API_KEY", "op-key")

# V05 (part 2): per-agent identity. API_KEY stays the tenant's SHARED key
# (/evaluate, /verify, /consensus/*); on the identity routes (/mandates/execute,
# /approvals, /approvals/{id}/execute) each principal presents its OWN
# registered credential, agent_key(principal) -- mirrored by agentKey() in
# integrations/voltagent/tests/_config.ts.
TENANT_ID = "pilot"
AGENT_PRINCIPALS = ("agent/notify-bot", "agent/unknown", "agent/axflow-clinic")


def agent_key(principal_id: str) -> str:
    return f"{API_KEY}::agent::{principal_id}"


def _agent_registry():
    from gateway.agent_identity import AgentCredentialRegistry, hash_agent_key
    return AgentCredentialRegistry.from_config({"agents": [
        {"credential_id": f"cred-{p}", "tenant_id": TENANT_ID, "principal_id": p,
         "key_sha256": hash_agent_key(agent_key(p)), "status": "active"}
        for p in AGENT_PRINCIPALS]})


def _build_gateway_app(gw: "gwmod.Gateway", service, audit_path: str) -> FastAPI:
    app = FastAPI(title="MCC Gateway (voltagent test)")
    registry = _agent_registry()

    def require_api_key(x_api_key: str = Header(...)) -> str:
        # The shared tenant key, or any registered agent credential of this tenant.
        if x_api_key != API_KEY and registry.resolve(x_api_key, tenant_id=TENANT_ID).agent is None:
            raise HTTPException(status_code=401, detail="INVALID_API_KEY")
        return "agent"

    @app.post("/evaluate", response_model=gwmod.EvaluateResponse)
    def evaluate(req: gwmod.EvaluateRequest, _=Depends(require_api_key)):
        return gw.evaluate(req)

    @app.get("/health")
    def health():
        return {"status": "ok", "policy_hash": gw.policy_hash}

    @app.get("/ready")
    def ready():
        return {"ready": True}

    @app.get("/verify")
    def verify(_=Depends(require_api_key)):
        return {"valid": AuditLog.verify_chain(gw.audit.path)}

    mount_mandate_routes(app, service, api_key=API_KEY, operator_key=OPERATOR_KEY,
                     tenant_id=TENANT_ID, agent_credentials=registry)
    mount_approval_routes(app, service, api_key=API_KEY, operator_key=OPERATOR_KEY,
                     tenant_id=TENANT_ID, agent_credentials=registry)
    mount_consensus_routes(app, service, api_key=API_KEY, operator_key=OPERATOR_KEY,
                     tenant_id=TENANT_ID, agent_credentials=registry)
    return app


def main() -> int:
    gw_port = int(os.environ.get("MCC_GATEWAY_PORT", "8801"))
    q_port = int(os.environ.get("MCC_QUORUM_PORT", "8802"))
    n_port = int(os.environ.get("MCC_NOTIFY_PORT", "8803"))
    threshold = int(os.environ.get("MCC_CONSENSUS_THRESHOLD", "3"))

    reset_receipts()

    # 1. Evaluator keyset (private pems + public consensus trust config).
    workdir = Path(tempfile.mkdtemp(prefix="voltagent-testsrv-"))
    keys_dir = workdir / "keys"
    trust_path = generate(keys_dir, evaluators=threshold, force=True)

    # 2. Real gateway with an isolated audit chain + consensus + receipt-verify.
    gw = gwmod.Gateway()
    gw.audit = AuditLog(str(workdir / "audit.jsonl"))
    notify_base = f"http://127.0.0.1:{n_port}"
    env = {"MCC_CONSENSUS_TRUST_CONFIG": str(trust_path),
           "MCC_CONSENSUS_THRESHOLD": str(threshold)}
    service = build_governance_service(
        engine=gw.engine, signing_key=gw.signing_key, audit=gw.audit,
        policy_hash=gw.policy_hash, token_audience=gwmod.settings.token_audience,
        env=env, upstream=receipt_verifying_upstream(notify_base))
    gateway_app = _build_gateway_app(gw, service, str(gw.audit.path))

    # 3. Independent evaluator quorum (holds the private keys).
    q_settings = QuorumSettings({
        "MCC_QUORUM_GATEWAY_URL": f"http://127.0.0.1:{gw_port}",
        "MCC_GATEWAY_API_KEY": API_KEY})
    quorum_app = build_quorum_app(load_evaluator_keys(str(keys_dir)), q_settings)

    servers = [
        DemoServer(notify_service.app, n_port),
        DemoServer(gateway_app, gw_port),
        DemoServer(quorum_app, q_port),
    ]
    for s in servers:
        s.start()

    info = {"gateway": f"http://127.0.0.1:{gw_port}", "quorum": f"http://127.0.0.1:{q_port}",
            "notify": notify_base, "api_key": API_KEY, "operator_key": OPERATOR_KEY,
            "policy_hash": gw.policy_hash, "threshold": threshold}
    print("MCC_TESTSERVER_READY " + json.dumps(info), flush=True)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        stop.wait()
    finally:
        for s in servers:
            s.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
