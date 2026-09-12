#!/usr/bin/env python3
"""Universal Execution Authority — real, HTTP-traversing live proof (PR #112).

Traverses PR #111's ACTUAL HTTP surface end to end against a REAL,
running server (a real ``uvicorn`` process on a real TCP port, hit with a
real ``httpx`` client -- never an in-process ASGI transport for this
script):

    POST /v1/proposals
    POST /v1/operations/{logical_operation_id}/execute

against a real, durable Redis backend and (when explicitly enabled) the
real GitHub REST API, via the existing, UNMODIFIED
``GitHubIssueActuator``/``GitHubSandboxUpstream`` (reused unchanged from
``examples/phase2_live_sandbox`` and ``examples/gpt6_astra_reference``).

Reuses the SAME live-safety gate as the Phase 2 live sandbox proof
(``examples.phase2_live_sandbox.config.SandboxConfig`` -- unchanged):
defaults fully disabled; requires ``MCC_PHASE2_LIVE_SANDBOX=1``,
``MCC_PHASE2_SANDBOX_REPO``, ``GITHUB_TOKEN``, ``MCC_REDIS_URL`` all
explicitly set; refuses ``mcc-prior-art/mcc-layer`` as a target. No new
environment variables are introduced for this proof.

Independent evidence correlation reuses
``examples.phase2_live_sandbox.evidence.make_sandbox_evidence_verifier``
as a PLAIN function call -- this is evidence INSPECTION (a read-only GET
against GitHub, looking for the operation-bound composite marker), never
a reconciliation API call and never a mutation of durable state. There is
no ``POST /v1/operations/{id}/reconcile`` route in this repository at all
(PR #111 removed it) and this script does not reintroduce one.
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx  # noqa: E402

from examples._demo_server import DemoServer, free_port  # noqa: E402
from examples.gpt6_astra_reference.github_actuator import GitHubActuatorConfig, GitHubIssueActuator  # noqa: E402
from examples.phase2_live_sandbox.actuator import GitHubSandboxUpstream  # noqa: E402
from examples.phase2_live_sandbox.config import SandboxConfig, SandboxConfigError  # noqa: E402
from examples.phase2_live_sandbox.evidence import make_sandbox_evidence_verifier  # noqa: E402
from examples.phase2_live_sandbox.marker import prepare_sandbox_issue_payload  # noqa: E402
from examples.universal_execution_proof import build_universal_proof_stack  # noqa: E402


async def main() -> int:
    try:
        config = SandboxConfig.from_env()
    except SandboxConfigError as exc:
        print(f"LIVE EXTERNAL SANDBOX: NOT EXECUTED — CREDENTIALS NOT AVAILABLE ({exc})")
        return 1
    if not config.live:
        print("LIVE EXTERNAL SANDBOX: NOT EXECUTED — CREDENTIALS NOT AVAILABLE (MCC_PHASE2_LIVE_SANDBOX not set)")
        return 1

    import redis as redis_sync
    import redis.asyncio as redis

    from mcc_core import RedisIdempotencyRegistry, RedisNonceRegistry
    from mcc_proposal import RedisProposalRegistry

    run_id = uuid.uuid4().hex[:8]

    # Connectivity pre-check uses a SEPARATE, SYNC redis client -- the
    # actual async client handed to the registries below must never be
    # awaited from this function's event loop. The real HTTP server this
    # script starts (DemoServer) runs uvicorn on its OWN dedicated thread
    # with its OWN event loop; the async redis client's connection pool
    # binds lazily to whichever loop FIRST awaits it, so pre-pinging it
    # here (this function's loop) would wrongly bind it to the wrong
    # thread's loop, and every real request (handled on the server
    # thread's loop) would then fail as "backend unavailable".
    try:
        redis_sync.from_url(config.redis_url, socket_connect_timeout=2.0).ping()
    except Exception as exc:
        print(f"LIVE EXTERNAL SANDBOX: NOT EXECUTED — REDIS UNAVAILABLE ({exc!r})")
        return 1

    client_redis = redis.from_url(config.redis_url, decode_responses=True)
    proposals = RedisProposalRegistry(client_redis, namespace=f"mcc:v1:universal-proof-{run_id}:proposal:")
    idem = RedisIdempotencyRegistry(client_redis, namespace=f"mcc:idem:universal-proof-{run_id}:")
    nonces = RedisNonceRegistry(client_redis, namespace=f"mcc:nonce:universal-proof-{run_id}:")

    actuator_config = GitHubActuatorConfig(mode="live", repo=config.repo, base_url=config.base_url, token=config.token)
    upstream = GitHubSandboxUpstream(GitHubIssueActuator(actuator_config))

    tenant_id = f"universal-proof-tenant-{run_id}"
    api_key = f"universal-proof-key-{run_id}"
    logical_operation_id = f"universal-proof-op-{run_id}"

    import tempfile

    audit_path = str(Path(tempfile.mkdtemp(prefix="mcc-universal-proof-")) / "audit.jsonl")

    proof = build_universal_proof_stack(
        proposals=proposals, idempotency=idem, nonces=nonces,
        tenants_credentials={api_key: tenant_id}, tenants_authority={tenant_id: {}},
        upstream=upstream, action="create_github_issue", audit_log_path=audit_path,
    )

    port = free_port()
    server = DemoServer(proof.app, port).start()
    base_url = f"http://127.0.0.1:{port}"

    failures = []
    result: dict = {"logical_operation_id": logical_operation_id, "tenant_id": tenant_id, "repo": config.repo}

    try:
        payload = prepare_sandbox_issue_payload(
            {"title": "MCC Universal Execution Authority Proof", "body": f"universal proof run {run_id}"},
            tenant_id=tenant_id, logical_operation_id=logical_operation_id,
        )
        async with httpx.AsyncClient(base_url=base_url, timeout=15.0) as client:
            r_submit = await client.post("/v1/proposals", headers={"x-api-key": api_key}, json={
                "logical_operation_id": logical_operation_id, "actor": "universal-proof-client/v1",
                "action": "create_github_issue", "resource": config.repo, "payload": payload,
            })
            print(f"POST /v1/proposals -> {r_submit.status_code} {r_submit.json()}")
            if r_submit.status_code != 200 or r_submit.json().get("status") != "PROPOSED":
                failures.append("proposal submission did not report PROPOSED")

            r_exec = await client.post(f"/v1/operations/{logical_operation_id}/execute",
                                        headers={"x-api-key": api_key})
            exec_body = r_exec.json()
            print(f"POST /v1/operations/{logical_operation_id}/execute -> {r_exec.status_code} {exec_body}")
            result["execution_status"] = exec_body.get("status")
            result["audit_ref"] = exec_body.get("audit_ref")
            if r_exec.status_code != 200 or exec_body.get("status") != "EXECUTED":
                failures.append(f"execute did not report EXECUTED ({exec_body})")

            # ---- Independent evidence inspection (NOT a reconciliation
            # API call -- a plain, read-only GET against GitHub). Bounded
            # retry ONLY here: the real GitHub REST API's issue-listing
            # endpoint can lag its own just-completed write by a short,
            # variable interval (observed empirically against the real
            # API; the local mock service has no such lag). This affects
            # only how quickly THIS SCRIPT'S post-hoc read-only
            # observation converges -- it is not part of, and does not
            # weaken, any MCC-Core authority/durability decision, all of
            # which already completed synchronously before this point. ----
            verify = make_sandbox_evidence_verifier(base_url=config.base_url, repo=config.repo, token=config.token)
            evidence = None
            for attempt in range(5):
                evidence = await verify(
                    tenant_id=tenant_id, logical_operation_id=logical_operation_id,
                    action="create_github_issue", resource=config.repo, payload_hash="",
                )
                if evidence is not None:
                    break
                await asyncio.sleep(1.0)
            print(f"independent evidence lookup -> {evidence} (attempt {attempt + 1})")
            if evidence is None:
                failures.append("independent evidence lookup found no matching issue")
            else:
                result["evidence_matched"] = True
                result["evidence_body_snippet"] = (evidence.get("payload") or {}).get("body")

            # ---- At-most-once proof: replay over the SAME HTTP endpoint. ----
            r_replay = await client.post(f"/v1/operations/{logical_operation_id}/execute",
                                          headers={"x-api-key": api_key})
            replay_body = r_replay.json()
            print(f"replay POST /execute -> {r_replay.status_code} {replay_body}")
            result["replay_status"] = replay_body.get("status")
            if replay_body.get("status") == "EXECUTED":
                failures.append("replay wrongly reported EXECUTED a second time")

        # ---- Independently query GitHub for the actual issue list, and
        # confirm the count did not grow due to replay. Same bounded-retry
        # rationale as the evidence-inspection step above. ----
        headers = {"Accept": "application/vnd.github+json"}
        if config.token:
            headers["Authorization"] = f"Bearer {config.token}"
        matching: list = []
        async with httpx.AsyncClient(timeout=15.0) as gh_client:
            for attempt in range(5):
                r_issues = await gh_client.get(f"{config.base_url}/repos/{config.repo}/issues", headers=headers)
                data = r_issues.json()
                # Matches examples.phase2_live_sandbox.evidence's own shape
                # handling: this repo's local mock service wraps the list
                # as {"issues": [...]}; the real GitHub REST API returns a
                # bare list.
                issues = data.get("issues") if isinstance(data, dict) else data
                if not isinstance(issues, list):
                    issues = []
                matching = [
                    i for i in issues
                    if isinstance(i, dict) and f"{tenant_id}::{logical_operation_id}" in (i.get("body") or "")
                ]
                if matching:
                    break
                await asyncio.sleep(1.0)
            print(f"GitHub issues matching this operation: {len(matching)}")
            result["external_issue_count_for_this_operation"] = len(matching)
            if len(matching) != 1:
                failures.append(f"expected exactly 1 external issue for this operation, found {len(matching)}")
            if matching:
                result["external_issue_number"] = matching[0].get("number")
                result["external_issue_url"] = matching[0].get("html_url")
    finally:
        server.stop()
        # Deliberately no client_redis.aclose() here: the connection pool
        # is bound to the server thread's event loop (see above), which is
        # already stopped by this point -- closing it from THIS loop would
        # reproduce the exact cross-loop error this design avoids.

    print("\n=== RESULT ===")
    for k, v in result.items():
        print(f"{k}: {v}")

    if failures:
        print("\nLIVE EXTERNAL EXECUTION PROOF FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("\nLIVE EXTERNAL EXECUTION PROOF PASSED: HTTP proposal -> HTTP execute -> real external "
          "GitHub issue -> independently observed -> replay-safe.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
