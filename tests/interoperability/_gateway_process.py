"""Real MCC Gateway server process for the interoperability proof (PR #48).

Booted as a genuine OS subprocess (``python -m tests.interoperability._gateway_process
--port N``) so every adapter proof crosses a real HTTP transport boundary against
one shared, out-of-process Gateway — never an in-process ASGI/handler/service call.

It builds the SAME governed stack the pilot uses (the real ``Gateway`` decision
engine + ``build_governance_service`` consensus/approval/mandate routes + the
receipt-verifying governed executor pointed at the mock notification upstream), all
configured from environment variables written by the harness:

    MCC_GATEWAY_AUDIT_LOG_PATH   isolated audit chain (never the prior-art chain)
    MCC_CONSENSUS_TRUST_CONFIG   evaluator trust set (PUBLIC keys only)
    MCC_CONSENSUS_THRESHOLD      N-of-M threshold
    MCC_REQUIRE_CONSENSUS=1      mandatory consensus at the coordinator
    MCC_REQUIRE_CHALLENGE=1      gateway-issued single-use challenge
    MCC_INTEROP_NOTIFY_BASE      loopback URL of the mock upstream service
    MCC_INTEROP_API_KEY / MCC_INTEROP_OPERATOR_KEY
    MCC_TRUST_CONFIG             optional signed-mandate issuer trust set (PR #71
                                  Workstream C mandate-forgery-containment tests;
                                  absent by default -- see mandate/trust.py)
    MCC_AGENT_CREDENTIALS_CONFIG / MCC_AGENT_IDENTITY_MODE
                                 V05 per-agent identity (registry written by the harness)
    MCC_ATTESTATION_REQUIREMENTS_CONFIG / MCC_ATTESTATION_TRUST_CONFIG
                                  optional PR-2 Pre-Execution Attestation Control
                                  (PR-5 Workstream attestation-chain tests; absent by
                                  default -- see gateway/pre_execution_control.py and
                                  gateway/governance_api.py's own
                                  _build_pre_execution_control, unmodified here)

No adapter-specific behavior lives here: this is the one shared Gateway for all five
adapters.
"""

from __future__ import annotations

import argparse
import os

from fastapi import Depends, FastAPI, Header, HTTPException

import gateway.app as gwmod
from gateway.governance_api import (
    build_governance_service,
    mount_approval_routes,
    mount_consensus_routes,
    mount_mandate_routes,
)

from mcc_core import AuditLog

from pilot_notify import receipt_verifying_upstream

API_KEY = os.environ.get("MCC_INTEROP_API_KEY", "demo-key")
OPERATOR_KEY = os.environ.get("MCC_INTEROP_OPERATOR_KEY", "op-key")


def build_app() -> FastAPI:
    # Gateway() reads MCC_GATEWAY_AUDIT_LOG_PATH from the env at construction, so the
    # audit chain is isolated from the repository's prior-art chain.
    gw = gwmod.Gateway()
    env = {
        "MCC_CONSENSUS_TRUST_CONFIG": os.environ["MCC_CONSENSUS_TRUST_CONFIG"],
        "MCC_CONSENSUS_THRESHOLD": os.environ.get("MCC_CONSENSUS_THRESHOLD", "3"),
        "MCC_REQUIRE_CONSENSUS": os.environ.get("MCC_REQUIRE_CONSENSUS", "1"),
        "MCC_REQUIRE_CHALLENGE": os.environ.get("MCC_REQUIRE_CHALLENGE", "1"),
    }
    if "MCC_TRUST_CONFIG" in os.environ:
        env["MCC_TRUST_CONFIG"] = os.environ["MCC_TRUST_CONFIG"]
    if "MCC_ATTESTATION_REQUIREMENTS_CONFIG" in os.environ:
        env["MCC_ATTESTATION_REQUIREMENTS_CONFIG"] = os.environ["MCC_ATTESTATION_REQUIREMENTS_CONFIG"]
    if "MCC_ATTESTATION_TRUST_CONFIG" in os.environ:
        env["MCC_ATTESTATION_TRUST_CONFIG"] = os.environ["MCC_ATTESTATION_TRUST_CONFIG"]
    # V05 (part 2): per-agent credential registry + identity mode (server-side).
    for name in ("MCC_AGENT_CREDENTIALS_CONFIG", "MCC_AGENT_IDENTITY_MODE"):
        if name in os.environ:
            env[name] = os.environ[name]
    service = build_governance_service(
        engine=gw.engine, signing_key=gw.signing_key, audit=gw.audit,
        policy_hash=gw.policy_hash, token_audience=gwmod.settings.token_audience,
        env=env, upstream=receipt_verifying_upstream(os.environ["MCC_INTEROP_NOTIFY_BASE"]))

    app = FastAPI(title="MCC-Core Interop Gateway")

    def require_api_key(x_api_key: str = Header(...)) -> str:
        if x_api_key != API_KEY:
            raise HTTPException(status_code=401, detail="INVALID_API_KEY")
        return "interop"

    @app.post("/evaluate", response_model=gwmod.EvaluateResponse)
    def evaluate(req: gwmod.EvaluateRequest, _=Depends(require_api_key)):
        return gw.evaluate(req)

    @app.get("/verify")
    def verify(_=Depends(require_api_key)):
        return {"valid": AuditLog.verify_chain(gw.audit.path)}

    @app.get("/health")
    def health():
        return {"status": "ok", "policy_hash": gw.policy_hash,
                "signing_kid": gw.signing_key.kid,
                "public_key_b64": gw.signing_key.public_key_b64(),
                "gateway_impl": "gateway.app.Gateway",
                "gate_impl": "mcc_core.coordinator.EnforcementCoordinator",
                "audit_impl": "mcc_core.audit.AuditLog"}

    @app.get("/ready")
    def ready():
        return {"ready": True,
                "consensus_verifier": service.consensus_verifier is not None,
                "challenge_service": service.challenge_service is not None}

    mount_mandate_routes(app, service, api_key=API_KEY, operator_key=OPERATOR_KEY)
    mount_approval_routes(app, service, api_key=API_KEY, operator_key=OPERATOR_KEY)
    mount_consensus_routes(app, service, api_key=API_KEY, operator_key=OPERATOR_KEY)
    return app


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    import uvicorn
    uvicorn.run(build_app(), host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
