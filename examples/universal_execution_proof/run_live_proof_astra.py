#!/usr/bin/env python3
"""Universal Execution Authority — real, HTTP-traversing live proof with
GPT-6 Astra as the concrete upstream producer (PR #112 correction
addendum).

Identical wiring and safety gate to ``run_live_proof.py`` (real
``uvicorn`` server on a real TCP port, real ``httpx`` client, the SAME
``examples.phase2_live_sandbox.config.SandboxConfig`` live-safety gate,
the SAME unmodified GitHub actuator) -- the ONLY difference is where the
outbound proposal's ``action``/``resource``/``payload`` come from: instead
of a hardcoded dict, they come from
``examples.universal_execution_proof.astra_upstream.propose_via_astra``,
which calls the EXISTING, unmodified
``examples.gpt6_astra_reference.astra_provider.DeterministicAstraProvider``
(the reference/offline Astra provider this repository's own demos and
tests already default to -- no live model call, no credential).

This demonstrates, concretely: Astra produces a proposal; Astra has no
path to signing/authority/the Gate/the coordinator (see
``tests/test_gpt6_astra_reference_architecture_guards.py``, unmodified);
the proposal reaches EXECUTED and a real external side effect ONLY after
crossing PR #111's real HTTP boundary and MCC-Core's full, unmodified
authority chain.
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
from examples.gpt6_astra_reference.issue_contract import GITHUB_ISSUE_ACTION  # noqa: E402
from examples.phase2_live_sandbox.actuator import GitHubSandboxUpstream  # noqa: E402
from examples.phase2_live_sandbox.config import SandboxConfig, SandboxConfigError  # noqa: E402
from examples.phase2_live_sandbox.evidence import make_sandbox_evidence_verifier  # noqa: E402
from examples.phase2_live_sandbox.marker import prepare_sandbox_issue_payload  # noqa: E402
from examples.universal_execution_proof import build_universal_proof_stack  # noqa: E402
from examples.universal_execution_proof.astra_upstream import (  # noqa: E402
    astra_proposal_to_http_request,
    build_astra_provider,
    propose_via_astra,
)


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

    try:
        redis_sync.from_url(config.redis_url, socket_connect_timeout=2.0).ping()
    except Exception as exc:
        print(f"LIVE EXTERNAL SANDBOX: NOT EXECUTED — REDIS UNAVAILABLE ({exc!r})")
        return 1

    client_redis = redis.from_url(config.redis_url, decode_responses=True)
    proposals = RedisProposalRegistry(client_redis, namespace=f"mcc:v1:astra-proof-{run_id}:proposal:")
    idem = RedisIdempotencyRegistry(client_redis, namespace=f"mcc:idem:astra-proof-{run_id}:")
    nonces = RedisNonceRegistry(client_redis, namespace=f"mcc:nonce:astra-proof-{run_id}:")

    actuator_config = GitHubActuatorConfig(mode="live", repo=config.repo, base_url=config.base_url, token=config.token)
    upstream = GitHubSandboxUpstream(GitHubIssueActuator(actuator_config))

    tenant_id = f"astra-proof-tenant-{run_id}"
    api_key = f"astra-proof-key-{run_id}"
    logical_operation_id = f"astra-proof-op-{run_id}"

    import tempfile

    audit_path = str(Path(tempfile.mkdtemp(prefix="mcc-astra-proof-")) / "audit.jsonl")

    proof = build_universal_proof_stack(
        proposals=proposals, idempotency=idem, nonces=nonces,
        tenants_credentials={api_key: tenant_id}, tenants_authority={tenant_id: {}},
        upstream=upstream, action=GITHUB_ISSUE_ACTION, audit_log_path=audit_path,
    )

    # ---- GPT-6 Astra (reference/offline provider) produces the proposal. ----
    task = f"astra-live-proof-{run_id}"
    astra_provider = build_astra_provider(
        task, action=GITHUB_ISSUE_ACTION, resource=config.repo,
        payload={"title": "MCC Universal Execution Authority Proof (Astra upstream)",
                 "body": f"proposed by GPT-6 Astra reference provider, run {run_id}"},
    )
    astra_proposal = await propose_via_astra(astra_provider, task)
    http_request = astra_proposal_to_http_request(astra_proposal)
    print(f"Astra proposed: {astra_proposal}")

    # The marker is embedded in the payload BEFORE submission, exactly
    # like run_live_proof.py -- Astra's own payload content passes
    # through unchanged; only the required marker/schema preparation step
    # (identical for every producer) is applied.
    marked_payload = prepare_sandbox_issue_payload(
        http_request["payload"], tenant_id=tenant_id, logical_operation_id=logical_operation_id,
    )

    port = free_port()
    server = DemoServer(proof.app, port).start()
    base_url = f"http://127.0.0.1:{port}"

    failures = []
    result: dict = {
        "logical_operation_id": logical_operation_id, "tenant_id": tenant_id, "repo": config.repo,
        "astra_proposal_action": astra_proposal.action, "astra_proposal_resource": astra_proposal.resource,
    }

    try:
        async with httpx.AsyncClient(base_url=base_url, timeout=15.0) as client:
            r_submit = await client.post("/v1/proposals", headers={"x-api-key": api_key}, json={
                "logical_operation_id": logical_operation_id, "actor": http_request["actor"],
                "action": http_request["action"], "resource": http_request["resource"], "payload": marked_payload,
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

            verify = make_sandbox_evidence_verifier(base_url=config.base_url, repo=config.repo, token=config.token)
            evidence = None
            for attempt in range(5):
                evidence = await verify(
                    tenant_id=tenant_id, logical_operation_id=logical_operation_id,
                    action=GITHUB_ISSUE_ACTION, resource=config.repo, payload_hash="",
                )
                if evidence is not None:
                    break
                await asyncio.sleep(1.0)
            print(f"independent evidence lookup -> {evidence} (attempt {attempt + 1})")
            if evidence is None:
                failures.append("independent evidence lookup found no matching issue")
            else:
                result["evidence_matched"] = True

            r_replay = await client.post(f"/v1/operations/{logical_operation_id}/execute",
                                          headers={"x-api-key": api_key})
            replay_body = r_replay.json()
            print(f"replay POST /execute -> {r_replay.status_code} {replay_body}")
            result["replay_status"] = replay_body.get("status")
            if replay_body.get("status") == "EXECUTED":
                failures.append("replay wrongly reported EXECUTED a second time")

        headers = {"Accept": "application/vnd.github+json"}
        if config.token:
            headers["Authorization"] = f"Bearer {config.token}"
        matching: list = []
        async with httpx.AsyncClient(timeout=15.0) as gh_client:
            for attempt in range(5):
                r_issues = await gh_client.get(f"{config.base_url}/repos/{config.repo}/issues", headers=headers)
                data = r_issues.json()
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

    print("\n=== RESULT (Astra upstream) ===")
    for k, v in result.items():
        print(f"{k}: {v}")

    if failures:
        print("\nASTRA-TO-REAL-ACTUATOR LIVE PROOF FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("\nASTRA-TO-REAL-ACTUATOR LIVE PROOF PASSED: GPT-6 Astra proposal -> HTTP boundary -> verified "
          "authority -> real external GitHub issue -> independently observed -> replay-safe.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
