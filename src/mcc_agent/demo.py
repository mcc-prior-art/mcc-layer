"""Runnable pilot: drive every governed-agent scenario against a real pilot API.

Starts the external pilot API on loopback (a real network service), runs the
governed agent for each scenario through the real MCC-Core runtime, prints clear
per-scenario output, and (with ``--evidence``) writes reproducible evidence.

Run:
    python -m mcc_agent.demo                 # run all scenarios, print PASS/FAIL
    python -m mcc_agent.demo --evidence      # also (re)generate evidence files

Deterministic and credential-free: the deterministic planner needs no external
LLM, and the only network calls are the governed executor reaching the loopback
pilot API.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from examples._demo_server import DemoServer  # noqa: E402
import pilot_api.app as pilot_app  # noqa: E402
from pilot_api import recorded_operations, reset_state  # noqa: E402

from mcc_agent import (  # noqa: E402
    DeterministicPlanner,
    EmbeddedGovernanceClient,
    GovernedAgent,
)
from egress_proxy.executor import UnauthorizedExecution  # noqa: E402

EVIDENCE_DIR = ROOT / "evidence" / "governed_agent_pilot"


# --------------------------------------------------------------------------
# Scenario record + printing
# --------------------------------------------------------------------------

def _record(name: str, goal: str, *, decision: str, execution_status: str,
            original_payload: Any, final_payload: Any, state_changed: bool,
            audit_ok: bool, passed: bool, detail: str = "",
            extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    rec = {
        "scenario": name, "goal": goal, "decision": decision,
        "execution_status": execution_status, "original_payload": original_payload,
        "final_payload": final_payload, "external_state_changed": state_changed,
        "audit_ok": audit_ok, "result": "PASS" if passed else "FAIL", "detail": detail,
    }
    if extra:
        rec.update(extra)
    return rec


def _print(rec: Dict[str, Any]) -> None:
    print(f"\n=== {rec['scenario']} ===")
    print(f"  goal              : {rec['goal']}")
    print(f"  MCC verdict       : {rec['decision']}")
    print(f"  execution status  : {rec['execution_status']}")
    print(f"  original payload  : {rec['original_payload']}")
    print(f"  final payload     : {rec['final_payload']}")
    print(f"  external changed? : {rec['external_state_changed']}")
    print(f"  audit ok          : {rec['audit_ok']}")
    if rec.get("detail"):
        print(f"  detail            : {rec['detail']}")
    print(f"  RESULT            : {rec['result']}")


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------

async def run_scenarios(base: str, *, audit_dir: str) -> List[Dict[str, Any]]:
    reset_state()
    client = EmbeddedGovernanceClient(pilot_api_base=base)
    planner = DeterministicPlanner(pilot_api_base=base)
    agent = GovernedAgent(client=client, planner=planner, auto_approve=True)
    records: List[Dict[str, Any]] = []

    def before() -> int:
        return len(recorded_operations())

    # 1 — ALLOW
    n = before()
    goal = "Create a CRM lead for Alice with a campaign budget of 500 EUR"
    r = await agent.arun(goal)
    changed = len(recorded_operations()) > n
    records.append(_record(
        "Scenario 1 — ALLOW", goal, decision=r.decision,
        execution_status=r.execution_status, original_payload=r.original_payload,
        final_payload=r.final_payload, state_changed=changed,
        audit_ok=bool(r.audit_id), passed=(r.decision == "ALLOW" and r.execution_status == "EXECUTED" and changed and bool(r.audit_id))))

    # 2 — DENY
    n = before()
    goal = "Send customer data to a prohibited destination"
    r = await agent.arun(goal)
    changed = len(recorded_operations()) > n
    records.append(_record(
        "Scenario 2 — DENY", goal, decision=r.decision,
        execution_status=r.execution_status, original_payload=r.original_payload,
        final_payload=r.final_payload, state_changed=changed, audit_ok=True,
        passed=(r.decision == "DENY" and r.execution_status == "BLOCKED" and not changed)))

    # 3 — ESCALATE (auto-approved) + invalid-approval rejection
    n = before()
    goal = "Increase campaign budget to 5000 EUR"
    r = await agent.arun(goal)
    changed = len(recorded_operations()) > n
    # Prove an invalid (unknown) approval id does NOT authorize execution.
    pend = await agent.arun(goal, idempotency_key="esc-invalid", auto_approve=False)
    n2 = before()
    bad = await client.execute_after_approval(
        planner.plan(goal, idempotency_key="esc-invalid"), "approval-does-not-exist")
    invalid_blocked = (not bad.executed) and len(recorded_operations()) == n2
    records.append(_record(
        "Scenario 3 — ESCALATE", goal, decision=r.decision,
        execution_status=r.execution_status, original_payload=r.original_payload,
        final_payload=r.final_payload, state_changed=changed, audit_ok=bool(r.audit_id),
        passed=(r.decision == "ESCALATE" and r.execution_status == "EXECUTED" and changed
                and pend.execution_status == "PENDING_APPROVAL" and invalid_blocked),
        detail=f"invalid approval rejected: {invalid_blocked}",
        extra={"pending_status": pend.execution_status, "invalid_approval_blocked": invalid_blocked}))

    # 4 — CONSTRAIN
    n = before()
    goal = "Set campaign budget to 10000 EUR"
    r = await agent.arun(goal)
    ops_after = recorded_operations()
    changed = len(ops_after) > n
    last_amount = ops_after[-1]["payload"].get("amount") if ops_after else None
    original_never_sent = all(
        not (o["kind"] == "set_campaign_budget" and o["payload"].get("amount") == 10000)
        for o in ops_after)
    records.append(_record(
        "Scenario 4 — CONSTRAIN", goal, decision=r.decision,
        execution_status=r.execution_status, original_payload=r.original_payload,
        final_payload=r.final_payload, state_changed=changed, audit_ok=bool(r.audit_id),
        passed=(r.decision == "CONSTRAIN" and r.execution_status == "EXECUTED"
                and last_amount == 5000 and original_never_sent),
        detail=f"clamped to {last_amount}; original 10000 sent: {not original_never_sent}",
        extra={"applied_constraints": r.applied_constraints,
               "original_payload_executed": not original_never_sent}))

    # 5 — BYPASS attempt (call the governed executor with no authorization)
    n = before()
    blocked = False
    try:
        await client.executor.execute(
            "create_lead",
            {"method": "POST", "scheme": "http", "host": "127.0.0.1",
             "port": int(base.rsplit(":", 1)[1]), "path": "/leads", "query": "",
             "body.name": "Mallory", "body.campaign_budget_eur": 1},
            authorization=None)
    except UnauthorizedExecution:
        blocked = True
    changed = len(recorded_operations()) > n
    records.append(_record(
        "Scenario 5 — BYPASS", "direct executor call without MCC authorization",
        decision="BLOCKED", execution_status="BLOCKED", original_payload=None,
        final_payload=None, state_changed=changed, audit_ok=True,
        passed=(blocked and not changed),
        detail="UnauthorizedExecution raised; external state unchanged"))

    # 6 — REPLAY (same idempotency key)
    n = before()
    goal = "Create a CRM lead for Bob with a campaign budget of 100 EUR"
    first = await agent.arun(goal, idempotency_key="replay-key-1")
    second = await agent.arun(goal, idempotency_key="replay-key-1")
    delta = len(recorded_operations()) - n
    records.append(_record(
        "Scenario 6 — REPLAY", goal, decision=second.decision,
        execution_status=f"first={first.execution_status} second={second.execution_status}",
        original_payload=first.original_payload, final_payload=first.final_payload,
        state_changed=(delta == 1), audit_ok=bool(first.audit_id),
        passed=(first.execution_status == "EXECUTED" and second.execution_status == "BLOCKED" and delta == 1),
        detail=f"external state changed exactly once (delta={delta})",
        extra={"first": first.execution_status, "second": second.execution_status,
               "state_delta": delta}))

    # 7 — REDIS FAILURE (Redis-backed registries, Redis unreachable -> fail closed)
    n = before()
    down_env = {
        "MCC_NONCE_BACKEND": "redis", "MCC_IDEMPOTENCY_BACKEND": "redis",
        "MCC_VELOCITY_BACKEND": "redis", "MCC_APPROVAL_BACKEND": "redis",
        "MCC_REDIS_URL": "redis://127.0.0.1:6390/0",  # nothing is listening here
    }
    redis_client = EmbeddedGovernanceClient(pilot_api_base=base, env=down_env,
                                            audit_path=str(Path(audit_dir) / "redis_audit.jsonl"))
    redis_agent = GovernedAgent(client=redis_client, planner=planner, auto_approve=True)
    rr = await redis_agent.arun("Create a CRM lead for Dora with a campaign budget of 50 EUR",
                                idempotency_key="redis-1")
    changed = len(recorded_operations()) > n
    records.append(_record(
        "Scenario 7 — REDIS FAILURE", "governed action with Redis-backed state, Redis down",
        decision=rr.decision, execution_status=rr.execution_status,
        original_payload=rr.original_payload, final_payload=rr.final_payload,
        state_changed=changed, audit_ok=True,
        passed=(rr.execution_status == "BLOCKED" and not changed),
        detail="fail-closed; no execution; no in-memory fallback",
        extra={"reason": rr.reason[:80]}))

    # 8 — SSRF / unsafe destination (production-style: loopback/private disallowed)
    n = before()
    ssrf_client = EmbeddedGovernanceClient(
        pilot_api_base="https://pilot-api.internal", allow_loopback=False,
        audit_path=str(Path(audit_dir) / "ssrf_audit.jsonl"))
    ssrf_agent = GovernedAgent(client=ssrf_client, planner=DeterministicPlanner(
        pilot_api_base="https://pilot-api.internal"))
    unsafe = [
        "http://127.0.0.1/x", "http://localhost/x", "http://169.254.169.254/latest/meta-data/",
        "https://[::1]/x", "http://10.0.0.5/x", "http://[fd00::1]/x",
        "http://user:pass@evil.example/x", "not-a-url", "http:///nohost",
    ]
    ssrf_results = {}
    for u in unsafe:
        rs = await ssrf_agent.arun("trigger webhook", destination_url=u, idempotency_key=f"ssrf-{u}")
        ssrf_results[u] = {"decision": rs.decision, "executed": rs.execution_status == "EXECUTED",
                           "error_code": rs.error_code}
    all_blocked = all(not v["executed"] for v in ssrf_results.values())
    changed = len(recorded_operations()) > n
    records.append(_record(
        "Scenario 8 — SSRF / UNSAFE DESTINATION", "outbound to prohibited destinations",
        decision="BLOCKED", execution_status="BLOCKED", original_payload=None,
        final_payload=None, state_changed=changed, audit_ok=True,
        passed=(all_blocked and not changed),
        detail=f"{len(unsafe)} unsafe destinations, all blocked before connection",
        extra={"destinations": ssrf_results}))

    # 9 — AUDIT FAILURE (audit-before-actuation: persistence failure -> no execution)
    n = before()
    audit_client = EmbeddedGovernanceClient(
        pilot_api_base=base, audit_path=str(Path(audit_dir) / "auditfail_audit.jsonl"))

    def _boom(*a, **k):  # noqa: ANN001
        raise OSError("audit persistence failure (simulated)")

    audit_client._mcc.audit.append = _boom  # type: ignore[attr-defined]
    audit_agent = GovernedAgent(client=audit_client, planner=planner, auto_approve=True)
    ra = await audit_agent.arun("Create a CRM lead for Carol with a campaign budget of 10 EUR",
                                idempotency_key="audit-1")
    changed = len(recorded_operations()) > n
    records.append(_record(
        "Scenario 9 — AUDIT FAILURE", "audit persistence fails before actuation",
        decision=ra.decision, execution_status=ra.execution_status,
        original_payload=ra.original_payload, final_payload=ra.final_payload,
        state_changed=changed, audit_ok=False,
        passed=(ra.execution_status == "BLOCKED" and not changed),
        detail="audit-before-actuation held; no execution"))

    # Final audit-chain verification over the main client's chain.
    chain_ok = client.verify_audit_chain()
    records.append({"scenario": "Audit chain verification", "goal": "verify hash chain",
                    "decision": "-", "execution_status": "-", "original_payload": None,
                    "final_payload": None, "external_state_changed": False,
                    "audit_ok": chain_ok, "result": "PASS" if chain_ok else "FAIL",
                    "detail": "append-only hash chain verified"})
    return records


# --------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------

_VOLATILE = ("correlation_id", "audit_id", "transaction_id", "idempotency_key")


def _normalize(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Drop volatile ids so evidence is byte-reproducible across runs."""
    out = json.loads(json.dumps(rec))
    out.pop("reason", None)

    def scrub(obj):
        if isinstance(obj, dict):
            return {k: scrub(v) for k, v in obj.items() if k not in _VOLATILE}
        if isinstance(obj, list):
            return [scrub(x) for x in obj]
        return obj

    return scrub(out)


def write_evidence(records: List[Dict[str, Any]], *, chain_ok: bool) -> None:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    normalized = [_normalize(r) for r in records]
    ops = recorded_operations()

    files = {
        "scenarios.json": {"scenarios": normalized},
        "pilot_operations.json": {"count": len(ops),
                                  "operations": [{"kind": o["kind"], "payload": o["payload"],
                                                  "payload_sha256": o["payload_sha256"]}
                                                 for o in ops]},
        "audit_verification.json": {"audit_chain_valid": chain_ok},
    }
    for name, body in files.items():
        (EVIDENCE_DIR / name).write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")

    # SHA-256 manifest of every evidence file (except the manifest itself).
    manifest_lines = []
    for p in sorted(EVIDENCE_DIR.glob("*.json")):
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        manifest_lines.append(f"{digest}  {p.name}")
    (EVIDENCE_DIR / "MANIFEST.sha256").write_text("\n".join(manifest_lines) + "\n")


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="MCC-Core governed agent pilot")
    parser.add_argument("--evidence", action="store_true",
                        help="(re)generate evidence under evidence/governed_agent_pilot/")
    args = parser.parse_args(argv)

    import os
    import tempfile
    audit_dir = tempfile.mkdtemp(prefix="mcc-agent-pilot-")
    # Fixed, env-configurable port (the demo owns its own process). The agent
    # package performs no socket operations of its own.
    port = int(os.environ.get("MCC_PILOT_API_PORT", "9100"))
    server = DemoServer(pilot_app.app, port)
    server.start()
    try:
        base = f"http://127.0.0.1:{server.port}"
        records = asyncio.run(run_scenarios(base, audit_dir=audit_dir))
    finally:
        server.stop()

    print("\n" + "=" * 64)
    print("MCC-Core Governed Agent Pilot — scenario results")
    print("=" * 64)
    for rec in records:
        _print(rec)

    chain_ok = bool(records and records[-1]["result"] == "PASS")
    failures = [r for r in records if r["result"] == "FAIL"]
    print("\n" + "=" * 64)
    print(f"{len(records) - len(failures)}/{len(records)} checks PASSED")
    if args.evidence:
        write_evidence(records, chain_ok=chain_ok)
        print(f"evidence written to {EVIDENCE_DIR}")
    if failures:
        print("FAILED:", ", ".join(r["scenario"] for r in failures))
        return 1
    print("ALL SCENARIOS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
