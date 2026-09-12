#!/usr/bin/env python3
"""Universal Execution Authority — REAL LIVE OpenAI-backed GPT-6 Astra
upstream (PR #112 live-Astra-provenance remediation).

``run_live_proof_astra.py`` (unchanged, still valid) proves the generic
upstream-adapter *shape* using ``DeterministicAstraProvider`` — an
explicitly offline/reference fixture, by that module's own docstring. It
does NOT prove that a REAL live model call can drive this chain. This
script closes exactly that gap, and only that gap:

    REAL OpenAI-compatible Chat Completions call (``OpenAIAstraProvider``,
    the SAME real adapter ``examples/gpt6_astra_reference`` already ships
    and ``live_redteam.py`` already uses for LIVE-F)
      -> AstraResponse with is_live == True
      -> AstraProposal
      -> PR #111's real HTTP boundary (POST /v1/proposals ->
         POST /v1/operations/{id}/execute)
      -> MCC-Core's unmodified authority chain
      -> the SAME real, reviewed GitHub sandbox actuator
      -> a real external GitHub issue.

No new Astra provider is introduced. ``OpenAIAstraProvider`` is imported
and used exactly as it already exists; this module's only job is the same
thin HTTP-boundary wiring ``run_live_proof.py``/``run_live_proof_astra.py``
already do.

Provenance / no-fallback guarantee (structural, not just documentary):
this file never imports or references ``DeterministicAstraProvider`` at
all (see
``tests/test_universal_execution_proof_astra_openai_provenance.py``,
which statically asserts this). If ``OPENAI_API_KEY``/``OPENAI_MODEL``
are not both configured, :meth:`OpenAIAstraProvider.from_env` raises
``AstraProviderError`` and this script prints exactly
``LIVE ASTRA PROOF — NOT EXECUTED`` and exits non-zero -- there is no
code path from that failure to a deterministic/offline proposal. The
``AstraResponse.is_live`` flag returned by the real call is also checked
explicitly before anything is submitted to MCC-Core, as a second,
independent structural guarantee that a non-live response can never be
reported as this proof's live evidence.

Secrets: ``OPENAI_API_KEY`` and ``GITHUB_TOKEN`` are read only by
``OpenAIAstraProvider.from_env()`` / ``SandboxConfig.from_env()``
respectively (both pre-existing, unmodified) and are never read,
printed, or logged directly by this script. Any raw model text this
script does print is passed through ``live_redteam.scan_and_redact``
first, the SAME secret-scrubbing utility LIVE-F already uses.
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
from examples.gpt6_astra_reference.astra_provider import AstraResponse, OpenAIAstraProvider  # noqa: E402
from examples.gpt6_astra_reference.astra_provider import AstraProviderError  # noqa: E402
from examples.gpt6_astra_reference.github_actuator import GitHubActuatorConfig, GitHubIssueActuator  # noqa: E402
from examples.gpt6_astra_reference.issue_contract import GITHUB_ISSUE_ACTION  # noqa: E402
from examples.gpt6_astra_reference.live_redteam import scan_and_redact  # noqa: E402
from examples.phase2_live_sandbox.actuator import GitHubSandboxUpstream  # noqa: E402
from examples.phase2_live_sandbox.config import SandboxConfig, SandboxConfigError  # noqa: E402
from examples.phase2_live_sandbox.evidence import make_sandbox_evidence_verifier  # noqa: E402
from examples.phase2_live_sandbox.marker import prepare_sandbox_issue_payload  # noqa: E402
from examples.universal_execution_proof import build_universal_proof_stack  # noqa: E402
from examples.universal_execution_proof.astra_upstream import (  # noqa: E402
    AstraUpstreamError,
    astra_proposal_to_http_request,
)
from examples.gpt6_astra_reference.models import AstraError, AstraSelfRefusal  # noqa: E402

LIVE_ASTRA_ACTOR = "gpt-6-astra-live-openai/v1"
NOT_EXECUTED_MARKER = "LIVE ASTRA PROOF — NOT EXECUTED"


def require_live_response(response: AstraResponse) -> None:
    """Structural guarantee, independent of ``OpenAIAstraProvider``'s own
    behavior: this script refuses to treat any non-``is_live`` response as
    evidence for the live-Astra proof, even if some future change to the
    provider ever produced one. Raises :class:`AstraUpstreamError`
    (never silently proceeds)."""
    if not response.is_live:
        raise AstraUpstreamError(
            "refusing to report a live-Astra proof from a non-live AstraResponse "
            "(is_live was False) -- this would misattribute an offline/fixture "
            "result as live evidence"
        )


def _proposal_from_response(response: AstraResponse):
    outcome = response.outcome
    if isinstance(outcome, AstraSelfRefusal):
        raise AstraUpstreamError(f"Astra declined to propose: {scan_and_redact(outcome.reason)}")
    if isinstance(outcome, AstraError):
        raise AstraUpstreamError(f"Astra output could not be used: {scan_and_redact(outcome.detail)}")
    if not outcome:
        raise AstraUpstreamError("Astra produced no proposals")
    return outcome[0]


async def main() -> int:
    # ---- Astra (LIVE OpenAI-backed) credential gate -- checked FIRST and
    # unconditionally, before any sandbox/Redis/HTTP setup, so a missing
    # OPENAI_API_KEY/OPENAI_MODEL never has a chance to fall through to
    # anything else. No fallback: on failure this function returns here. ----
    try:
        astra_provider = OpenAIAstraProvider.from_env()
    except AstraProviderError as exc:
        print(f"{NOT_EXECUTED_MARKER} ({exc})")
        return 1

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
    proposals = RedisProposalRegistry(client_redis, namespace=f"mcc:v1:astra-openai-proof-{run_id}:proposal:")
    idem = RedisIdempotencyRegistry(client_redis, namespace=f"mcc:idem:astra-openai-proof-{run_id}:")
    nonces = RedisNonceRegistry(client_redis, namespace=f"mcc:nonce:astra-openai-proof-{run_id}:")

    actuator_config = GitHubActuatorConfig(mode="live", repo=config.repo, base_url=config.base_url, token=config.token)
    upstream = GitHubSandboxUpstream(GitHubIssueActuator(actuator_config))

    tenant_id = f"astra-openai-proof-tenant-{run_id}"
    api_key = f"astra-openai-proof-key-{run_id}"
    logical_operation_id = f"astra-openai-proof-op-{run_id}"

    import tempfile

    audit_path = str(Path(tempfile.mkdtemp(prefix="mcc-astra-openai-proof-")) / "audit.jsonl")

    proof = build_universal_proof_stack(
        proposals=proposals, idempotency=idem, nonces=nonces,
        tenants_credentials={api_key: tenant_id}, tenants_authority={tenant_id: {}},
        upstream=upstream, action=GITHUB_ISSUE_ACTION, audit_log_path=audit_path,
    )

    # ---- REAL live OpenAI-compatible call. Astra decides the JSON
    # content; we only tell it, as any real operator would, which
    # resource/action this run targets (the actuator's own fixed
    # destination) -- we never construct or override the proposal
    # ourselves. ----
    task = (
        f"Propose creating exactly one GitHub issue in the repository '{config.repo}' "
        f"using the action identifier '{GITHUB_ISSUE_ACTION}'. The issue should have a "
        f"title of 'MCC Universal Execution Authority Proof (live OpenAI Astra upstream)' "
        f"and a body mentioning that it was proposed by a real, live GPT-6 Astra model "
        f"call as part of run {run_id}."
    )
    response = await astra_provider.propose(task)
    print(f"Astra response: is_live={response.is_live} model={response.model!r}")
    if response.raw_content is not None:
        print(f"Astra raw content (redacted): {scan_and_redact(response.raw_content)}")

    result: dict = {
        "logical_operation_id": logical_operation_id, "tenant_id": tenant_id, "repo": config.repo,
        "astra_is_live": response.is_live, "astra_model": response.model,
    }

    try:
        require_live_response(response)
        astra_proposal = _proposal_from_response(response)
    except AstraUpstreamError as exc:
        result["astra_error"] = scan_and_redact(str(exc))
        print("\n=== RESULT (live OpenAI Astra upstream) ===")
        for k, v in result.items():
            print(f"{k}: {v}")
        print(f"\n{NOT_EXECUTED_MARKER} (Astra call completed but produced no usable proposal: {result['astra_error']})")
        return 1

    http_request = astra_proposal_to_http_request(astra_proposal, actor=LIVE_ASTRA_ACTOR)
    print(f"Astra proposed (redacted): action={http_request['action']!r} resource={http_request['resource']!r}")
    result["astra_proposal_action"] = astra_proposal.action
    result["astra_proposal_resource"] = astra_proposal.resource

    marked_payload = prepare_sandbox_issue_payload(
        http_request["payload"], tenant_id=tenant_id, logical_operation_id=logical_operation_id,
    )

    port = free_port()
    server = DemoServer(proof.app, port).start()
    base_url = f"http://127.0.0.1:{port}"

    failures = []

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
            attempt = 0
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

    print("\n=== RESULT (live OpenAI Astra upstream) ===")
    for k, v in result.items():
        print(f"{k}: {v}")

    if failures:
        print("\nLIVE OPENAI ASTRA -> REAL ACTUATOR PROOF FAILED:")
        for f in failures:
            print("  -", f)
        return 1
    print("\nLIVE OPENAI ASTRA -> REAL ACTUATOR PROOF PASSED: a real, live GPT-6 Astra model call "
          "(is_live=True) -> HTTP boundary -> verified authority -> real external GitHub issue -> "
          "independently observed -> replay-safe.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))


__all__ = ["main", "require_live_response", "LIVE_ASTRA_ACTOR", "NOT_EXECUTED_MARKER"]
