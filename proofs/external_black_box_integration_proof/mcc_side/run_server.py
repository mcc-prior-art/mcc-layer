#!/usr/bin/env python3
"""MCC-side server for the Live Astra Black-Box External Integration Proof
(PR #114).

Lives INSIDE mcc-layer and is free to import MCC internals -- this is the
SERVER under test, not the external consumer (that lives entirely outside
this repository; see ``../README.md``). Starts a REAL governed stack,
composed exclusively from EXISTING, unmodified components:

* ``examples.external_pilot.server.build_external_pilot_app`` (PR #113)
  -- itself reusing ``gateway.proposal_execution_stack.
  build_proposal_execution_stack`` (the ONE place AuthorityModel/
  DecisionEngine/ExecutionGate/EnforcementCoordinator/
  ProposalExecutionService are constructed) and
  ``gateway.proposal_api``/``gateway.proposal_execution_api``'s real
  ``POST /v1/proposals`` / ``POST /v1/operations/{id}/execute`` routes.
* ``examples.phase2_live_sandbox.actuator.GitHubSandboxUpstream`` wrapping
  ``examples.gpt6_astra_reference.github_actuator.GitHubIssueActuator``
  -- the SAME real, reviewed GitHub actuator PR #108/#110/#112 already
  use, configured live against the existing sandbox repository via the
  SAME ``examples.phase2_live_sandbox.config.SandboxConfig`` live-safety
  gate (refuses ``mcc-prior-art/mcc-layer`` itself regardless of
  configuration).
* Real Redis-backed durable registries (``RedisProposalRegistry`` /
  ``RedisIdempotencyRegistry`` / ``RedisNonceRegistry``) -- so replay/
  idempotency in this proof exercises the SAME durable code path the
  repository's own Redis-backed test suite already covers.

No new decision logic, no second Gate, no second EnforcementCoordinator,
no second actuator architecture, no special-cased endpoint for this
proof. Prints ONE line of JSON connection info to stdout (base_url,
api_key, tenant hint, action, resource) then blocks until SIGTERM/SIGINT
-- the orchestrator (``../run_black_box_proof.py``) reads that line,
launches the external consumer with it as plain CLI arguments (exactly
as a real integrator would receive an API key out-of-band, never by
importing this repository), and terminates this process when done.
"""

from __future__ import annotations

import json
import secrets
import signal
import sys
import tempfile
import threading
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from examples._demo_server import DemoServer, free_port  # noqa: E402
from examples.external_pilot.server import build_external_pilot_app  # noqa: E402
from examples.gpt6_astra_reference.github_actuator import GitHubActuatorConfig, GitHubIssueActuator  # noqa: E402
from examples.gpt6_astra_reference.issue_contract import GITHUB_ISSUE_ACTION  # noqa: E402
from examples.phase2_live_sandbox.actuator import GitHubSandboxUpstream  # noqa: E402
from examples.phase2_live_sandbox.config import SandboxConfig, SandboxConfigError  # noqa: E402


def main() -> int:
    try:
        config = SandboxConfig.from_env()
    except SandboxConfigError as exc:
        print(json.dumps({"error": f"NOT EXECUTED — CREDENTIALS NOT AVAILABLE ({exc})"}), flush=True)
        return 1
    if not config.live:
        print(json.dumps({"error": "NOT EXECUTED — MCC_PHASE2_LIVE_SANDBOX not set"}), flush=True)
        return 1

    import redis as redis_sync
    import redis.asyncio as redis

    from mcc_core import RedisIdempotencyRegistry, RedisNonceRegistry
    from mcc_proposal import RedisProposalRegistry

    run_id = uuid.uuid4().hex[:8]

    try:
        redis_sync.from_url(config.redis_url, socket_connect_timeout=2.0).ping()
    except Exception as exc:
        print(json.dumps({"error": f"NOT EXECUTED — REDIS UNAVAILABLE ({exc!r})"}), flush=True)
        return 1

    client_redis = redis.from_url(config.redis_url, decode_responses=True)
    proposals = RedisProposalRegistry(client_redis, namespace=f"mcc:v1:blackbox-{run_id}:proposal:")
    idempotency = RedisIdempotencyRegistry(client_redis, namespace=f"mcc:idem:blackbox-{run_id}:")
    nonces = RedisNonceRegistry(client_redis, namespace=f"mcc:nonce:blackbox-{run_id}:")

    actuator_config = GitHubActuatorConfig(mode="live", repo=config.repo, base_url=config.base_url, token=config.token)
    upstream = GitHubSandboxUpstream(GitHubIssueActuator(actuator_config))

    # A fresh, cryptographically-random, single-use API key -- never a
    # literal/hardcoded value, never committed anywhere; printed once to
    # stdout for the orchestrator to hand to the external consumer
    # out-of-band, exactly as a real deployment would issue a real
    # integrator a real credential.
    api_key = secrets.token_urlsafe(24)
    tenant_id = f"blackbox-tenant-{run_id}"
    audit_log_path = str(Path(tempfile.mkdtemp(prefix="mcc-blackbox-audit-")) / "audit.jsonl")

    app = build_external_pilot_app(
        proposals=proposals, idempotency=idempotency, nonces=nonces,
        tenants_credentials={api_key: tenant_id}, tenants_authority={tenant_id: {}},
        upstream=upstream, audit_log_path=audit_log_path, action=GITHUB_ISSUE_ACTION,
    )

    port = free_port()
    server = DemoServer(app, port).start()
    base_url = f"http://127.0.0.1:{port}"

    connection_info = {
        "base_url": base_url,
        "api_key": api_key,
        "tenant_hint": tenant_id,
        "action": GITHUB_ISSUE_ACTION,
        "resource": config.repo,
        "run_id": run_id,
    }
    print(json.dumps(connection_info), flush=True)

    stop_event = threading.Event()

    def _handle_stop(signum, frame):  # noqa: ANN001
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)
    stop_event.wait()
    server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
