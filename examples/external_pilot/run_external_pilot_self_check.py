#!/usr/bin/env python3
"""External Pilot Integration Pack -- end-to-end self-check (PR #113).

    PYTHONPATH=src:.:sdk/python/src python3 examples/external_pilot/run_external_pilot_self_check.py

Runs ALL required pilot scenarios (A-H) against a REAL ``uvicorn`` server
on a real TCP port, hit with a real ``httpx.AsyncClient`` -- never an
in-process ASGI transport, never a direct Python call into
``ProposalExecutionService``. Uses
``examples.external_pilot.scenarios.build_scenario_stack``'s in-memory,
zero-external-I/O composition (fixed, non-secret demo API keys and an
isolated, obviously non-production ``DemoLedgerActuator`` -- see
``examples/external_pilot/actuator/demo_actuator.py``): no Redis, no real
credentials, no real actuator, safe to run immediately after a fresh
clone with zero configuration.

Exits 0 only if every scenario passes; exits 1 and prints exactly what
failed otherwise -- this script never fakes success. Prints a
machine-readable JSON evidence summary (tenant identifiers,
logical_operation_ids, actions, resources, authority decisions,
execution statuses, audit references, reconciliation outcomes, and
actuator dispatch counts) followed by a short human-readable summary.
Never prints a private key, bearer token, API secret, or raw sensitive
environment value -- the demo composition has none to leak; its fixed
demo API keys (``scenario-key-a`` etc.) are non-secret literals used
nowhere outside this zero-I/O demo path.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx  # noqa: E402

from examples._demo_server import DemoServer, free_port  # noqa: E402
from examples.external_pilot.client.mcc_pilot_client import MCCPilotClient  # noqa: E402
from examples.external_pilot.scenarios import ALL_SCENARIOS, build_scenario_stack  # noqa: E402


async def main() -> int:
    stack = build_scenario_stack()
    port = free_port()
    server = DemoServer(stack.app, port).start()
    base_url = f"http://127.0.0.1:{port}"
    clients: list = []

    def make_client(api_key: str) -> MCCPilotClient:
        client = MCCPilotClient(base_url=base_url, api_key=api_key)
        clients.append(client)
        return client

    results = []
    try:
        for scenario_fn in ALL_SCENARIOS:
            result = await scenario_fn(make_client, stack)
            results.append(result)
            marker = "PASS" if result.passed else "FAIL"
            print(f"[{marker}] {result.name}" + (f" -- {result.failures}" if result.failures else ""))
    finally:
        for c in clients:
            await c.aclose()
        server.stop()

    evidence = {
        "scenarios": [
            {
                "name": r.name,
                "passed": r.passed,
                "failures": r.failures,
                "detail": r.detail,
            }
            for r in results
        ],
        "actuator_dispatch_count_total": len(stack.ledger.entries),
        "actuator_resource": stack.resource,
    }
    print("\n=== EVIDENCE (JSON) ===")
    print(json.dumps(evidence, indent=2, default=str))

    failed = [r for r in results if not r.passed]
    print("\n=== SUMMARY ===")
    print(f"scenarios passed: {len(results) - len(failed)}/{len(results)}")
    if failed:
        print("EXTERNAL PILOT SELF-CHECK FAILED:")
        for r in failed:
            print(f"  - {r.name}: {r.failures}")
        return 1

    print(
        "EXTERNAL PILOT SELF-CHECK PASSED: generic external producer -> real HTTP "
        "boundary -> verified authority -> real controlled actuator, across all "
        "required scenarios (happy path, denial, replay, tenant isolation, "
        "resource binding, payload/action binding, UNKNOWN/reconciliation, "
        "unauthenticated fail-closed)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
