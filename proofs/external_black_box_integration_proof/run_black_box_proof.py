#!/usr/bin/env python3
"""Orchestrator for the External Black-Box Integration Proof.

Lives INSIDE mcc-layer and is free to import/spawn MCC internals -- it is
the PRIVILEGED test-harness side, never the consumer under proof. Wires
together two SEPARATE OS processes:

1. ``mcc_side/run_server.py`` -- the real governed HTTP server, started as
   a subprocess of THIS process (which may freely import MCC internals,
   since it launches, never runs as, the server).
2. The external consumer (``/tmp/mcc-live-external-consumer/consumer.py``
   by default, overridable via ``--consumer-path``) -- started as a
   SEPARATE subprocess with:
   * ``cwd`` set to the consumer's own directory (never mcc-layer);
   * an environment with no ``PYTHONPATH`` pointing at mcc-layer and no
     mcc-layer path prepended to anything;
   * connection info (base URL, API key, action, resource) passed as
     plain CLI arguments -- exactly how a real integrator receives
     credentials out-of-band, never by importing the provider's source.

This script performs no governance decision of its own. It starts one
process, starts a second, relays a URL/API-key/action/resource that the
first process printed, waits for the second to finish, and then performs
an INDEPENDENT read-back of the real external side effect via the GitHub
REST API -- a THIRD, separate code path from both the actuator (inside
the server subprocess) and the consumer's own submission.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_SCRIPT = Path(__file__).resolve().parent / "mcc_side" / "run_server.py"


def _read_connection_info(proc: subprocess.Popen, timeout: float = 30.0) -> Dict[str, Any]:
    """Reads stdout lines from the server subprocess until it prints its
    one line of JSON connection info, or the process exits/times out."""
    deadline = time.monotonic() + timeout
    assert proc.stdout is not None
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                raise RuntimeError(f"server subprocess exited before printing connection info (code {proc.returncode})")
            continue
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            # not the connection-info line (could be a log line); keep reading
            continue
    raise TimeoutError("timed out waiting for server subprocess connection info")


def _independent_github_read_back(*, repo: str, token: str, proof_id: str, retries: int = 5, delay: float = 2.0) -> Dict[str, Any]:
    """Independent verification of the real GitHub side effect, via a
    THIRD code path distinct from (a) the actuator inside the server
    subprocess and (b) the external consumer's own HTTP calls to MCC.
    Uses the plain GitHub REST search API directly over urllib -- no MCC
    code, no actuator code, no consumer code."""
    owner, name = repo.split("/", 1)
    # Repo-scoped endpoint, not the global /search/issues endpoint: this
    # environment's GITHUB_TOKEN is a Claude-Code-issued, repository-scoped
    # credential -- global search returns 403 ("sessions are bound to
    # their configured repositories"). Listing + client-side filtering is
    # the repo-scoped equivalent and is exactly as independent a check.
    url = f"https://api.github.com/repos/{owner}/{name}/issues?state=all&per_page=50"
    last_error: Optional[str] = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "mcc-black-box-proof-independent-readback",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15.0) as resp:
                items = json.loads(resp.read().decode("utf-8"))
            matching = [i for i in items if proof_id in (i.get("body") or "")]
            if matching:
                return {
                    "verified": True,
                    "attempt": attempt,
                    "total_count": len(matching),
                    "issues": [{"number": i["number"], "url": i["html_url"], "title": i["title"]} for i in matching],
                }
        except Exception as exc:  # noqa: BLE001 -- record and retry (GitHub read-after-write lag)
            last_error = repr(exc)
        time.sleep(delay)
    return {"verified": False, "attempts": retries, "last_error": last_error}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consumer-path", default="/tmp/mcc-live-external-consumer/consumer.py")
    parser.add_argument(
        "--consumer-python", default="/tmp/mcc-live-external-consumer/.venv/bin/python3",
        help="interpreter for the consumer subprocess -- MUST be a clean venv with no mcc-layer "
             "editable install on sys.path (this repo's own interpreter may have one from "
             "unrelated SDK development work; using it here would contaminate the externality proof)",
    )
    parser.add_argument("--model", default="gpt-4o-mini")
    parser.add_argument("--evidence-out", default=str(Path(__file__).resolve().parent / "sanitized_live_run.json"))
    args = parser.parse_args()

    server_env = dict(os.environ)
    # Server subprocess is free to import MCC internals -- it launches
    # from this repo, with this repo's own sys.path additions handled by
    # run_server.py itself.
    server_proc = subprocess.Popen(
        [sys.executable, str(SERVER_SCRIPT)],
        cwd=str(REPO_ROOT), env=server_env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
    )

    report: Dict[str, Any] = {"phase": "startup"}
    try:
        connection_info = _read_connection_info(server_proc)
    except Exception as exc:
        server_proc.terminate()
        report["error"] = f"server startup failed: {exc!r}"
        print(json.dumps(report))
        return 1

    if "error" in connection_info:
        server_proc.terminate()
        report["error"] = connection_info["error"]
        print(json.dumps(report))
        return 1

    report["connection_info"] = {k: v for k, v in connection_info.items() if k != "api_key"}
    report["connection_info"]["api_key_redacted"] = (
        connection_info["api_key"][:4] + "...<redacted>...")

    consumer_path = Path(args.consumer_path)
    consumer_env = {
        key: value for key, value in os.environ.items()
        if key not in ("PYTHONPATH",)
    }
    consumer_env["OPENAI_API_KEY"] = os.environ.get("OPENAI_API_KEY", "")

    consumer_evidence_path = consumer_path.parent / f"evidence-{connection_info['run_id']}.json"

    try:
        consumer_result = subprocess.run(
            [
                args.consumer_python, str(consumer_path),
                "--mcc-base-url", connection_info["base_url"],
                "--mcc-api-key", connection_info["api_key"],
                "--action", connection_info["action"],
                "--resource", connection_info["resource"],
                "--model", args.model,
                "--evidence-out", str(consumer_evidence_path),
            ],
            cwd=str(consumer_path.parent),
            env=consumer_env,
            capture_output=True, text=True, timeout=180.0,
        )
    finally:
        server_proc.send_signal(signal.SIGTERM)
        try:
            server_proc.wait(timeout=10.0)
        except subprocess.TimeoutExpired:
            server_proc.kill()

    report["consumer_returncode"] = consumer_result.returncode
    report["consumer_stderr_tail"] = consumer_result.stderr[-4000:] if consumer_result.stderr else ""

    consumer_evidence: Optional[Dict[str, Any]] = None
    if consumer_evidence_path.exists():
        consumer_evidence = json.loads(consumer_evidence_path.read_text())
    else:
        # fall back to parsing stdout's last JSON line
        for line in reversed(consumer_result.stdout.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                consumer_evidence = json.loads(line)
                break
            except json.JSONDecodeError:
                continue

    report["consumer_evidence"] = consumer_evidence

    proof_id = (consumer_evidence or {}).get("proof_id")
    if proof_id and (consumer_evidence or {}).get("execute_status") == "EXECUTED":
        github_token = os.environ.get("GITHUB_TOKEN", "")
        if github_token:
            report["independent_readback"] = _independent_github_read_back(
                repo=connection_info["resource"], token=github_token, proof_id=proof_id,
            )
        else:
            report["independent_readback"] = {"verified": False, "error": "GITHUB_TOKEN not available to orchestrator"}
    else:
        report["independent_readback"] = {"verified": False, "skipped": "no EXECUTED proof_id from consumer"}

    Path(args.evidence_out).write_text(json.dumps(report, indent=2, sort_keys=True))
    print(json.dumps(report))
    return 0 if consumer_result.returncode == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
