#!/usr/bin/env python3
"""External Black-Box Integration Proof — external consumer.

THIS FILE LIVES OUTSIDE THE mcc-layer REPOSITORY AND IS NOT PART OF IT.
It is a standalone script an external integrator could write having read
only mcc-layer's public documentation (docs/EXTERNAL_PILOT_INTEGRATION.md,
PR #113), never having seen or imported any of mcc-layer's source code.

Scope note (important): this proof demonstrates the EXTERNAL INTEGRATION
BOUNDARY ITSELF — a genuinely external, isolated process using a real,
live OpenAI model to generate a proposal, submitted only through MCC's
documented public HTTP contract, resulting in a real, independently
verified external side effect. It is deliberately model-neutral. It does
NOT claim anything about a model called "GPT-6 Astra" — that specific
claim could not be independently verified against any reachable source in
this environment (see ../README.md and ../LIVE_PROOF_REPORT.md for the
full record of that separate investigation) and is explicitly NOT made
here. The live model used by this proof is named plainly in its own
output/evidence, whatever it is (default: ``gpt-4o-mini``, matching the
already-corrected record in this repository's own tracked sandbox issue
#5 in ``mcc-prior-art/mcc-phase2-sandbox``).

Imports: Python standard library, plus ``httpx`` (a plain HTTP client
library — not an MCC SDK, not a governance library, not a GitHub write
client). Nothing from ``mcc_core``, ``gateway``, ``mcc_proposal``, or any
other mcc-layer package. This is verified two ways:

1. Structurally, at the start of ``main()`` below: an explicit attempt to
   import ``mcc_core`` is expected to fail (this process's own
   ``sys.path`` contains no mcc-layer path, and mcc-layer is not
   pip-installed here) — the result is captured as isolation evidence,
   never silently ignored.
2. Independently, by
   ``tests/test_external_black_box_proof_architecture_guards.py`` inside
   mcc-layer, which statically scans a byte-identical COPY of this file
   (``proofs/external_black_box_integration_proof/external_consumer_snapshot/consumer.py``
   -- i.e. this specific file's bytes are copied verbatim into the repo
   for scanning; this is a claim about the copy operation, not about
   HTTP wire-level identity, see ``canonical_hash`` below for that
   distinction) for forbidden imports/references — with non-vacuity
   probes proving the guard actually catches a planted violation.

This script:

  1. Makes a REAL, live HTTP call to OpenAI's Chat Completions API
     requesting the model named by ``--model`` (default ``gpt-4o-mini``)
     — no local fixture, no mock, no deterministic table, no silent
     substitution. The model's own output materially determines the
     proposal's action/resource/payload content (constrained only to the
     generic MCC proposal JSON shape and an operator-supplied unique
     proof identifier it is instructed to include, so the resulting side
     effect can be independently located later — the model still decides
     everything else). A canonical SHA-256 hash over the proposal's
     action/resource/payload fields is captured at parse time and
     re-verified immediately before submission, proving those fields
     were not altered in between (see ``canonical_hash`` docstring for
     exactly what this does and does not establish).
  2. Submits that proposal to MCC's PUBLIC HTTP boundary only:
     POST {mcc_base_url}/v1/proposals, then
     POST {mcc_base_url}/v1/operations/{id}/execute — the SAME two
     endpoints documented in docs/EXTERNAL_PILOT_INTEGRATION.md. This
     script possesses no signing key, no MCC authority-token constructor,
     no Gate/coordinator reference, and no GitHub actuator reference —
     there is no code path in this file that could construct one, since
     none of those types are imported or defined here.
  3. Runs the required negative controls (replay, invalid auth,
     unauthorized action, malformed input) against the SAME running
     server.
  4. Evaluates ALL of the conditions in ``REQUIRED_CHECKS`` below and
     reports ``result: "PROVEN"`` (exit 0) only if every one of them
     holds; otherwise reports ``result: "NOT PROVEN"`` (exit non-zero)
     with the specific ``failed_checks`` named explicitly. There is no
     path through this script that reaches ``result: "PROVEN"`` without
     every required condition having been positively confirmed --
     an unevaluated condition counts as failed, never as passed.
  5. Prints ONE line of JSON evidence to stdout. Never prints the OpenAI
     API key or the MCC API key it was given — both are received via
     command-line arguments/environment variables (exactly as a real
     integrator receives credentials out-of-band) and are redacted in
     all output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import uuid
from typing import Any, Dict, Optional

import httpx

DEFAULT_MODEL = "gpt-4o-mini"
OPENAI_CHAT_COMPLETIONS_URL = "https://api.openai.com/v1/chat/completions"

_SYSTEM_PROMPT = (
    "You propose exactly one action for an execution-governance system to "
    "evaluate. You do not have authority to execute anything yourself, and "
    "you have no direct access to any external system — your proposal is "
    "only ever a request; a separate, independent authority decides whether "
    "it is ever carried out. Respond with ONLY a JSON object of the exact "
    'shape {"action": string, "resource": string, "payload": {"title": '
    'string, "body": string}}. Never include any field other than action, '
    "resource, payload, payload.title, payload.body."
)

# The complete set of conditions that must ALL hold for this proof to be
# reported PROVEN. Each is set to False at the start and only ever set to
# True at the point in ``main()`` where it is positively confirmed --
# never defaulted to True, never inferred from the absence of an error.
REQUIRED_CHECKS = (
    "live_model_call_succeeded",
    "proof_id_in_model_output",
    "proposal_hash_binding_verified",
    "submit_http_200",
    "submit_status_proposed",
    "execute_http_200",
    "execute_status_executed",
    "replay_http_200",
    "replay_status_blocked",
    "invalid_auth_submit_401",
    "invalid_auth_execute_401",
    "unauthorized_submit_accepted",
    "unauthorized_execute_denied",
    "malformed_submit_422",
)


def canonical_hash(obj: Any) -> str:
    """SHA-256 over a canonical (sorted-key, no-whitespace-ambiguity) JSON
    encoding of ``obj``. Used to bind the model-produced proposal's
    action/resource/payload fields as captured to the same fields as
    submitted to MCC, proving those FIELDS were not rewritten or injected
    in between.

    What this DOES establish: the canonical (semantic) content of
    action/resource/payload is unchanged from capture to submission.

    What this does NOT establish: literal HTTP wire-level byte identity
    of the outbound request. This script serializes the same in-memory
    Python objects for both the hash and the request body, so wire bytes
    are in practice derived from the same source -- but no independent
    wire-level capture is performed here, so this function's guarantee is
    scoped to canonical field equality, not asserted as byte-for-byte
    network evidence."""
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def redact(secret: Optional[str]) -> str:
    if not secret:
        return "<absent>"
    if len(secret) <= 8:
        return "<redacted>"
    return f"{secret[:4]}...<redacted>...{secret[-4:]}"


def check_mcc_internals_unavailable() -> Dict[str, Any]:
    """Structural isolation evidence: this process must NOT be able to
    import mcc-layer internals. Never assumed — actually attempted."""
    results = {}
    for module_name in ("mcc_core", "gateway.proposal_execution_service", "mcc_proposal"):
        try:
            __import__(module_name)
            results[module_name] = "IMPORT SUCCEEDED (ISOLATION VIOLATION)"
        except ImportError as exc:
            results[module_name] = f"import failed as expected: {type(exc).__name__}: {exc}"
    results["mcc_layer_path_in_sys_path"] = any("mcc-layer" in p or "mcc_layer" in p for p in sys.path)
    results["cwd"] = os.getcwd()
    return results


def call_live_model(*, openai_api_key: str, task_prompt: str, model: str,
                     timeout: float = 60.0) -> Dict[str, Any]:
    """Real, live HTTP call to OpenAI's Chat Completions API. No fixture,
    no mock, no cache, no silent substitution — if this call fails, it
    fails; nothing in this function substitutes a different model or a
    pre-written response."""
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": task_prompt},
        ],
        "response_format": {"type": "json_object"},
    }
    resp = httpx.post(
        OPENAI_CHAT_COMPLETIONS_URL,
        headers={"Authorization": f"Bearer {openai_api_key}", "Content-Type": "application/json"},
        json=body, timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    return {
        "requested_model": model,
        "returned_model": data.get("model"),
        "response_id": data.get("id"),
        "created": data.get("created"),
        "openai_request_id": resp.headers.get("x-request-id"),
        "content": data["choices"][0]["message"]["content"],
        "is_live": True,  # this function only ever performs a real network call
        "usage": data.get("usage"),
    }


def mcc_submit_proposal(*, base_url: str, api_key: str, logical_operation_id: str, actor: str,
                         action: str, resource: Optional[str], payload: Dict[str, Any],
                         timeout: float = 15.0) -> Dict[str, Any]:
    r = httpx.post(
        f"{base_url}/v1/proposals", headers={"x-api-key": api_key},
        json={"logical_operation_id": logical_operation_id, "actor": actor, "action": action,
              "resource": resource, "payload": payload},
        timeout=timeout,
    )
    return {"status_code": r.status_code, "body": _safe_json(r)}


def mcc_execute(*, base_url: str, api_key: str, logical_operation_id: str, timeout: float = 15.0) -> Dict[str, Any]:
    r = httpx.post(
        f"{base_url}/v1/operations/{logical_operation_id}/execute", headers={"x-api-key": api_key}, timeout=timeout,
    )
    return {"status_code": r.status_code, "body": _safe_json(r)}


def _safe_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text


def _effective_status(response: Dict[str, Any]) -> Optional[str]:
    """Extracts the ``status`` field, unwrapping FastAPI's ``{"detail":
    ...}`` envelope on 4xx/5xx responses. Returns None (never a guessed
    default) when the body is not a dict or carries no status field."""
    body = response["body"]
    if not isinstance(body, dict):
        return None
    if response["status_code"] >= 400:
        body = body.get("detail", body)
    return body.get("status") if isinstance(body, dict) else None


def _finalize(evidence: Dict[str, Any], checks: Dict[str, bool], evidence_out: Optional[str] = None) -> int:
    """Computes the final PROVEN/NOT PROVEN verdict from ``checks`` --
    the ONLY place in this script that decides the overall result and
    exit code -- prints the evidence, optionally writes it to
    ``evidence_out``, and returns the process exit code. Every return
    path in ``main()`` goes through this single function, so the
    evidence file is always written regardless of where the run stopped.

    A check absent from ``checks`` (never reached, e.g. because an
    earlier step aborted) is treated as failed, never as passed:
    ``checks`` is seeded with every name in REQUIRED_CHECKS set to False
    before any step runs, and only ever flipped to True at the exact
    point a condition is positively confirmed -- see main()."""
    missing = set(REQUIRED_CHECKS) - set(checks)
    assert not missing, f"internal error: checks dict missing entries {missing}"
    failed_checks = [name for name in REQUIRED_CHECKS if not checks[name]]
    evidence["proof_checks"] = {name: checks[name] for name in REQUIRED_CHECKS}
    evidence["failed_checks"] = failed_checks
    evidence["result"] = "PROVEN" if not failed_checks else "NOT PROVEN"
    output = json.dumps(evidence)
    print(output)
    if evidence_out:
        with open(evidence_out, "w", encoding="utf-8") as f:
            f.write(output)
    return 0 if not failed_checks else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mcc-base-url", required=True)
    parser.add_argument("--mcc-api-key", required=True)
    parser.add_argument("--action", required=True, help="the governed action this MCC deployment authorized")
    parser.add_argument("--resource", required=True, help="the GitHub repo (owner/repo) the actuator targets")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="the live OpenAI model id to request (no fallback if unavailable)")
    parser.add_argument("--openai-api-key", default=os.environ.get("OPENAI_API_KEY", ""))
    parser.add_argument("--evidence-out", default=None, help="optional path to also write the JSON evidence")
    args = parser.parse_args()

    # Seeded to all-False; only ever flipped to True at the exact point a
    # condition is positively confirmed below. Never defaulted to True.
    checks: Dict[str, bool] = {name: False for name in REQUIRED_CHECKS}

    isolation = check_mcc_internals_unavailable()

    evidence: Dict[str, Any] = {
        "isolation_check": isolation,
        "mcc_base_url": args.mcc_base_url,
        "mcc_api_key_redacted": redact(args.mcc_api_key),
        "openai_api_key_redacted": redact(args.openai_api_key),
    }

    if not args.openai_api_key:
        evidence["error"] = "OPENAI_API_KEY not provided"
        return _finalize(evidence, checks, args.evidence_out)

    proof_id = f"mcc-blackbox-{uuid.uuid4().hex}"
    logical_operation_id = proof_id
    actor_label = f"live-{args.model}-external-consumer/v1"
    evidence["proof_id"] = proof_id
    evidence["logical_operation_id"] = logical_operation_id

    task_prompt = (
        f"Propose creating exactly one GitHub issue in the repository '{args.resource}' "
        f"using the action identifier '{args.action}'. The issue's body MUST contain, "
        f"verbatim, this exact literal string so the resulting issue can be located "
        f"later: {proof_id}. Choose the issue title and the rest of the body content "
        f"yourself, describing that this issue was created by a real, live external "
        f"integration proof."
    )

    # ---- Live model call ----
    try:
        model_result = call_live_model(openai_api_key=args.openai_api_key, task_prompt=task_prompt, model=args.model)
    except httpx.HTTPStatusError as exc:
        evidence["model_call_error"] = f"{exc!r}"
        evidence["model_call_error_body"] = _safe_json(exc.response)
        return _finalize(evidence, checks, args.evidence_out)
    except httpx.HTTPError as exc:
        evidence["model_call_error"] = f"transport failure: {exc!r}"
        return _finalize(evidence, checks, args.evidence_out)

    checks["live_model_call_succeeded"] = True

    evidence["requested_model"] = model_result["requested_model"]
    evidence["returned_model"] = model_result["returned_model"]
    evidence["model_response_id"] = model_result["response_id"]
    evidence["model_openai_request_id"] = model_result["openai_request_id"]
    evidence["model_created"] = model_result["created"]
    evidence["model_is_live"] = model_result["is_live"]
    evidence["model_usage"] = model_result["usage"]
    evidence["model_identity_match"] = model_result["requested_model"] == model_result["returned_model"]

    try:
        proposal = json.loads(model_result["content"])
    except json.JSONDecodeError as exc:
        evidence["proposal_parse_error"] = f"{exc!r}"
        evidence["model_raw_content"] = model_result["content"]
        return _finalize(evidence, checks, args.evidence_out)

    action = proposal.get("action")
    resource = proposal.get("resource")
    payload = proposal.get("payload") or {}
    body_text = payload.get("body") or ""

    captured_proposal_hash = canonical_hash({"action": action, "resource": resource, "payload": payload})

    evidence["proposal_action"] = action
    evidence["proposal_resource"] = resource
    evidence["proposal_payload_title"] = payload.get("title")
    evidence["proposal_payload_body"] = body_text
    evidence["proof_id_present_in_model_output"] = proof_id in body_text
    evidence["captured_proposal_sha256"] = captured_proposal_hash

    checks["proof_id_in_model_output"] = proof_id in body_text
    if not checks["proof_id_in_model_output"]:
        evidence["error"] = "model output did not include the required unique proof identifier"
        return _finalize(evidence, checks, args.evidence_out)

    # ---- A. Happy path: submit + execute over the PUBLIC HTTP boundary ----
    submitted_proposal_hash = canonical_hash({"action": action, "resource": resource, "payload": payload})
    evidence["submitted_proposal_sha256"] = submitted_proposal_hash
    checks["proposal_hash_binding_verified"] = submitted_proposal_hash == captured_proposal_hash
    evidence["proposal_hash_binding_verified"] = checks["proposal_hash_binding_verified"]

    r_submit = mcc_submit_proposal(
        base_url=args.mcc_base_url, api_key=args.mcc_api_key, logical_operation_id=logical_operation_id,
        actor=actor_label, action=action, resource=resource, payload=payload,
    )
    evidence["submit_status_code"] = r_submit["status_code"]
    evidence["submit_body"] = r_submit["body"]
    checks["submit_http_200"] = r_submit["status_code"] == 200
    submit_body = r_submit["body"] if isinstance(r_submit["body"], dict) else {}
    checks["submit_status_proposed"] = submit_body.get("status") == "PROPOSED"

    r_exec = mcc_execute(base_url=args.mcc_base_url, api_key=args.mcc_api_key, logical_operation_id=logical_operation_id)
    evidence["execute_status_code"] = r_exec["status_code"]
    evidence["execute_body"] = r_exec["body"]
    evidence["execute_status"] = _effective_status(r_exec)
    checks["execute_http_200"] = r_exec["status_code"] == 200
    checks["execute_status_executed"] = evidence["execute_status"] == "EXECUTED"

    # ---- Negative control A: replay ----
    r_replay = mcc_execute(base_url=args.mcc_base_url, api_key=args.mcc_api_key, logical_operation_id=logical_operation_id)
    evidence["replay_status_code"] = r_replay["status_code"]
    evidence["replay_body"] = r_replay["body"]
    evidence["replay_status"] = _effective_status(r_replay)
    checks["replay_http_200"] = r_replay["status_code"] == 200
    checks["replay_status_blocked"] = evidence["replay_status"] == "BLOCKED"

    # ---- Negative control B: missing/invalid authentication ----
    bad_op_id = f"mcc-blackbox-unauth-{uuid.uuid4().hex}"
    r_bad_submit = mcc_submit_proposal(
        base_url=args.mcc_base_url, api_key="not-a-real-api-key", logical_operation_id=bad_op_id,
        actor=actor_label, action=action, resource=resource,
        payload={"title": "should never be accepted", "body": "unauthenticated attempt"},
    )
    r_bad_exec = mcc_execute(base_url=args.mcc_base_url, api_key="not-a-real-api-key", logical_operation_id=bad_op_id)
    evidence["invalid_auth_submit_status_code"] = r_bad_submit["status_code"]
    evidence["invalid_auth_execute_status_code"] = r_bad_exec["status_code"]
    checks["invalid_auth_submit_401"] = r_bad_submit["status_code"] == 401
    checks["invalid_auth_execute_401"] = r_bad_exec["status_code"] == 401

    # ---- Negative control C: unauthorized action (valid caller, no authority) ----
    unauthorized_op_id = f"mcc-blackbox-unauthorized-{uuid.uuid4().hex}"
    r_unauth_submit = mcc_submit_proposal(
        base_url=args.mcc_base_url, api_key=args.mcc_api_key, logical_operation_id=unauthorized_op_id,
        actor=actor_label, action="unauthorized_black_box_action",
        resource=resource, payload={"title": "should be denied", "body": "no authority for this action"},
    )
    r_unauth_exec = mcc_execute(base_url=args.mcc_base_url, api_key=args.mcc_api_key, logical_operation_id=unauthorized_op_id)
    evidence["unauthorized_submit_status_code"] = r_unauth_submit["status_code"]
    evidence["unauthorized_submit_body"] = r_unauth_submit["body"]
    evidence["unauthorized_execute_status_code"] = r_unauth_exec["status_code"]
    evidence["unauthorized_execute_status"] = _effective_status(r_unauth_exec)
    unauth_submit_body = r_unauth_submit["body"] if isinstance(r_unauth_submit["body"], dict) else {}
    # "Expected accepted/proposed response": submission itself is only
    # schema/tenant validation -- authority is evaluated at execute time
    # -- so an unauthorized action is still accepted at PROPOSED here,
    # and denied only when execution is attempted (asserted below).
    checks["unauthorized_submit_accepted"] = (
        r_unauth_submit["status_code"] == 200 and unauth_submit_body.get("status") == "PROPOSED"
    )
    checks["unauthorized_execute_denied"] = evidence["unauthorized_execute_status"] == "DENIED"

    # ---- Negative control D: malformed proposal (missing required field) ----
    malformed_op_id = f"mcc-blackbox-malformed-{uuid.uuid4().hex}"
    r_malformed = httpx.post(
        f"{args.mcc_base_url}/v1/proposals", headers={"x-api-key": args.mcc_api_key},
        json={"logical_operation_id": malformed_op_id, "actor": actor_label},
        # deliberately omits the required "action" field
        timeout=15.0,
    )
    evidence["malformed_submit_status_code"] = r_malformed.status_code
    evidence["malformed_submit_body"] = _safe_json(r_malformed)
    checks["malformed_submit_422"] = r_malformed.status_code == 422

    return _finalize(evidence, checks, args.evidence_out)


if __name__ == "__main__":
    sys.exit(main())
