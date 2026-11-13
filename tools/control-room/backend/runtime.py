"""Boots the REAL MCC-Core gateway for the Control Room demonstration.

This is the ONE module in the Control Room that imports ``gateway`` /
``mcc_core``, and it imports them only the way any ordinary external actor
already does elsewhere in this repository:

* ``gateway.app`` is imported and served as an ASGI app -- exactly what
  ``deploy/pilot/Dockerfile`` (``uvicorn gateway.app:app``) and
  ``examples/governance_http_demo.py`` already do to run the real gateway
  for a live HTTP demo. No gateway code is modified, wrapped, or forked.
* ``mcc_core.SigningKey`` is used only to generate the ephemeral consensus
  evaluator keypairs the demo needs to play the "independent evaluator"
  role -- the identical pattern ``deploy/pilot/generate_pilot_config.py``
  and ``deploy/pilot/pilot_driver.py`` already use for the Docker pilot.

This module never calls ``AuthorityModel.evaluate()``,
``DecisionEngine.issue_token()``, ``ExecutionGate.verify_token()``,
``EnforcementCoordinator.enforce()``, or ``AuditLog.append()`` directly.
Every decision, every signature, every gate check, and every audit write
happens inside the real ``gateway.app`` HTTP process this module starts;
the Control Room backend (``server.py``) talks to that process only over
HTTP, through ``pilot.client.MCCGatewayClient`` -- the repository's
existing, supported, transport-only public client.

Nothing here is persisted: keys, trust configs, and the audit log all live
in a per-run temporary directory that is safe to delete once the demo
stops. Nothing here contacts any real external system -- the "upstream"
governed execution forwards to is a local, loopback-only mock echo
service, the same pattern ``deploy/pilot/docker-compose.yml``'s
``upstream-echo`` service and ``examples/governance_http_demo.py``'s
in-process ``upstream`` app already use.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

_HERE = Path(__file__).resolve()
ROOT = _HERE.parents[3]
for _p in (str(ROOT), str(ROOT / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from examples._demo_server import DemoServers, free_port  # noqa: E402
from fastapi import FastAPI, Request  # noqa: E402

from mcc_core import SigningKey  # noqa: E402

EVALUATOR_COUNT = 3
CONSENSUS_THRESHOLD = 3
# Non-destructive, informative default TTL for gateway-issued decision tokens.
TOKEN_TTL_SECONDS = "60"
# Demo agents that act on identity routes (V05 part 2) -- incl. consensus
# execution and /evaluate as themselves (F1): each gets its OWN credential.
DEMO_AGENT_PRINCIPALS = ("agent/nobody", "agent/payments-bot", "agent/control-room-demo")


def _build_upstream_app(seen: List[Dict[str, Any]]) -> FastAPI:
    """A local, loopback-only mock actuation target.

    This is the *only* thing governed execution ever reaches -- never a real
    banking, payment, cloud, email, or database system. It only records what
    it received (for the Control Room's own "actuation result" display) and
    echoes success; the same shape as ``examples/governance_http_demo.py``'s
    ``upstream`` app and ``deploy/pilot``'s ``upstream-echo`` service.
    """
    app = FastAPI(title="control-room-mock-upstream (loopback only, non-production)")

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def _echo(request: Request, path: str) -> Dict[str, Any]:
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001 -- empty/non-JSON body is fine for a demo echo
            body = {}
        record = {"path": f"/{path}", "body": body}
        seen.append(record)
        return {"upstream_reached": True, "echo": record}

    return app


@dataclass
class DemoRuntime:
    """Handle to the running, real MCC-Core demonstration stack.

    Every field here describes a genuine external HTTP process or the
    demo-scoped, never-committed credentials needed to act as an ordinary
    external client of it. Nothing here is a decision, a token, or a gate --
    those only ever exist inside the gateway process.
    """

    gateway_url: str
    api_key: str
    operator_key: str
    evaluator_keys: List[SigningKey]
    # V05 part 2: each demo agent's OWN per-agent credential ({principal: key});
    # the gateway's registry holds only their SHA-256 hashes.
    agent_keys: Dict[str, str]
    state_dir: Path
    audit_log_path: str
    upstream_seen: List[Dict[str, Any]]
    _servers: DemoServers = field(repr=False)

    def stop(self) -> None:
        try:
            self._servers.stop_all()
        finally:
            shutil.rmtree(self.state_dir, ignore_errors=True)


def start_demo_runtime() -> DemoRuntime:
    """Start the real gateway + a local mock upstream and return a handle.

    Idempotent per call: a fresh state directory, fresh ephemeral keys, and
    fresh free ports are used every time, so repeated demo runs never
    collide and never reuse credentials from a previous run.
    """
    state_dir = Path(tempfile.mkdtemp(prefix="mcc-control-room-"))
    os.chmod(state_dir, 0o700)

    upstream_seen: List[Dict[str, Any]] = []
    upstream_app = _build_upstream_app(upstream_seen)

    gateway_port = free_port()
    upstream_port = free_port()

    # Ephemeral consensus evaluator identities -- the demo plays the role of
    # N independent evaluators exactly the way pilot_driver.py already does;
    # these private keys never leave this backend process (never serialized
    # to the browser, never written outside this run's temp directory).
    evaluator_keys = [SigningKey.generate(f"control-room-evaluator-{i + 1}")
                       for i in range(EVALUATOR_COUNT)]
    consensus_trust = {
        "issuers": [
            {"issuer_id": f"control-room-evaluator-{i + 1}", "enabled": True,
             "keys": [{"kid": k.kid, "public_key_b64": k.public_key_b64(), "not_after": None}]}
            for i, k in enumerate(evaluator_keys)
        ]
    }
    consensus_trust_path = state_dir / "consensus_trust.json"
    consensus_trust_path.write_text(json.dumps(consensus_trust, indent=2), encoding="utf-8")

    api_key = secrets.token_urlsafe(24)
    operator_key = secrets.token_urlsafe(24)
    # V05 part 2: the shared tenant key above cannot act as an agent on
    # /mandates/execute, /approvals or /approvals/{id}/execute; the ESCALATE
    # scenario's agent presents its own registered credential instead.
    agent_keys = {principal: secrets.token_urlsafe(24) for principal in DEMO_AGENT_PRINCIPALS}
    agent_credentials_path = state_dir / "agent_credentials.json"
    agent_credentials_path.write_text(json.dumps({"agents": [
        {"credential_id": f"control-room-{i + 1}", "tenant_id": "pilot", "principal_id": principal,
         "key_sha256": hashlib.sha256(key.encode("utf-8")).hexdigest(), "status": "active"}
        for i, (principal, key) in enumerate(sorted(agent_keys.items()))]}, indent=2),
        encoding="utf-8")
    audit_log_path = str(state_dir / "audit.jsonl")

    # Every one of these is a genuine, already-documented gateway setting
    # (see docs/GOVERNANCE_HTTP_API.md, deploy/pilot/RUNBOOK.md) -- nothing
    # invented for the demo. Setting them before ``import gateway.app`` is
    # required because the gateway builds its policy engine and the
    # governance HTTP layer at import time.
    os.environ.update({
        "MCC_GATEWAY_MODE": "inline",
        "MCC_GATEWAY_API_KEY": api_key,
        "MCC_GATEWAY_OPERATOR_API_KEY": operator_key,
        "MCC_AGENT_CREDENTIALS_CONFIG": str(agent_credentials_path),
        "MCC_GATEWAY_AUDIT_LOG_PATH": audit_log_path,
        "MCC_GATEWAY_TOKEN_TTL_SECONDS": TOKEN_TTL_SECONDS,
        "MCC_UPSTREAM_BASE": f"http://127.0.0.1:{upstream_port}",
        # The consensus verifier is configured and fully enforced whenever a
        # scenario submits it (POST /consensus/execute always requires valid
        # N-of-M votes -- that check is unconditional in
        # gateway/governance_service.py, not gated by this flag). It is
        # deliberately NOT made coordinator-wide mandatory
        # (MCC_REQUIRE_CONSENSUS) here, for the same reason
        # deploy/pilot/docker-compose.yml runs its egress proxy with
        # MCC_EGRESS_REQUIRE_CONSENSUS=false and deploy/pilot/RUNBOOK.md
        # calls it out explicitly: making consensus coordinator-wide
        # mandatory blocks every OTHER governed path (including
        # /approvals/{id}/execute, the ESCALATE -> human-approval loop this
        # demo also needs) from ever actuating, per
        # tests/test_consensus_enforcement_http.py::
        # test_mandate_path_blocked_under_mandatory_consensus. This Control
        # Room demonstrates mandatory-consensus enforcement directly against
        # /consensus/execute (see the replay/tamper/expired/bad-signature
        # scenarios) without disabling the separate ESCALATE/approval path.
        # MCC_REQUIRE_CHALLENGE is coordinator-wide the same way: it
        # requires a gateway-issued challenge on EVERY governed execution,
        # not only consensus ones, which would also block
        # /approvals/{id}/execute (that path has no challenge_id parameter
        # to supply one). Every consensus scenario below still voluntarily
        # uses a real gateway-issued challenge (POST /consensus/challenge)
        # for every /consensus/execute call regardless of this flag.
        "MCC_CONSENSUS_TRUST_CONFIG": str(consensus_trust_path),
        "MCC_CONSENSUS_THRESHOLD": str(CONSENSUS_THRESHOLD),
    })

    # Import AFTER the environment is set (gateway/app.py wires the policy
    # engine and governance HTTP layer from process env at import time).
    import gateway.app as gw  # noqa: E402

    servers = DemoServers()
    servers.start(upstream_app, upstream_port)
    servers.start(gw.app, gateway_port)

    return DemoRuntime(
        gateway_url=f"http://127.0.0.1:{gateway_port}",
        api_key=api_key,
        operator_key=operator_key,
        evaluator_keys=evaluator_keys,
        agent_keys=agent_keys,
        state_dir=state_dir,
        audit_log_path=audit_log_path,
        upstream_seen=upstream_seen,
        _servers=servers,
    )
