"""Runnable demo/CLI for the reference pilot integration.

Connects to an ALREADY-RUNNING MCC-Core Gateway (see
``docs/PILOT_RUNBOOK.md`` for how to start one) and submits a small, fixed
set of representative candidate actions through :class:`PilotIntegration`,
then exports a pilot evidence bundle.

This script performs NO real external action -- every "execution" is the
local :class:`~pilot.reference_python.actuator.SimulatedActuator`. It does
not claim, and must never be presented as, a completed or externally
validated pilot; see ``docs/PILOT_ACCEPTANCE_CHECKLIST.md``.

Usage::

    # 1. start a Gateway in a separate terminal (repo root):
    uvicorn gateway.app:app --host 127.0.0.1 --port 8001

    # 2. run the demo (defaults match the Gateway's own dev defaults):
    python -m pilot.reference_python.runner \\
        --gateway-url http://127.0.0.1:8001 --api-key demo-key --mode observe

Every value is also settable via ``MCC_PILOT_*`` environment variables
(see :meth:`pilot.reference_python.config.PilotConfig.from_env`); CLI flags
take precedence when both are given.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from mcc_sdk import MCCConfigurationError, MCCSDKError

from .config import PilotConfig, PilotConfigError
from .integration import PilotIntegration

# A small, fixed set of candidate actions chosen only to exercise each of
# the four canonical verdicts under the Gateway's default pilot policy
# (gateway/pilot_policy.py) -- the SAME scenarios already proven in
# tests/mcc_sdk/test_integration.py and tests/pilot/test_pilot_acceptance.py.
# This is a demo fixture set, not a claim about any partner's real traffic.
DEMO_SCENARIOS: list[dict[str, Any]] = [
    {"identity": "agent/payments-bot", "action": "send_payment", "context": {"amount": 1000}},
    {"identity": "agent/ops-bot", "action": "delete_database", "context": {}},
    {"identity": "agent/nobody", "action": "send_payment", "context": {"amount": 1}},
    {"identity": "agent/payments-bot", "action": "send_payment", "context": {"amount": 99999}},
]


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reference pilot integration demo runner (PR #82). "
        "Prepares a pilot connection; does not itself constitute a completed pilot."
    )
    parser.add_argument("--gateway-url", default=None, help="MCC Gateway base URL")
    parser.add_argument("--api-key", default=None, help="Gateway X-API-Key, if required")
    parser.add_argument("--agent-keys-file", default=None,
                        help="JSON {identity: key}: each identity's OWN registered credential "
                             "(required by a strict Gateway; the shared key obtains no decision)")
    parser.add_argument("--timeout-seconds", type=float, default=None)
    parser.add_argument("--mode", choices=["observe", "enforced"], default=None)
    parser.add_argument("--pilot-id", default=None)
    parser.add_argument("--integration-id", default=None)
    parser.add_argument("--evidence-dir", default=None)
    parser.add_argument("--run-correlation-id", default=None)
    return parser.parse_args(argv)


def _build_config(args: argparse.Namespace) -> PilotConfig:
    try:
        base = PilotConfig.from_env()
    except PilotConfigError:
        if args.gateway_url is None:
            raise PilotConfigError(
                "no MCC_PILOT_GATEWAY_URL in the environment and no --gateway-url given"
            ) from None
        base = PilotConfig(gateway_url=args.gateway_url)

    overrides: dict[str, Any] = {}
    if args.gateway_url is not None:
        overrides["gateway_url"] = args.gateway_url
    if args.api_key is not None:
        overrides["api_key"] = args.api_key
    if args.agent_keys_file is not None:
        from .config import load_agent_keys
        overrides["agent_keys"] = load_agent_keys(args.agent_keys_file)
    if args.timeout_seconds is not None:
        overrides["timeout_seconds"] = args.timeout_seconds
    if args.mode is not None:
        overrides["mode"] = args.mode
    if args.pilot_id is not None:
        overrides["pilot_id"] = args.pilot_id
    if args.integration_id is not None:
        overrides["integration_id"] = args.integration_id
    if args.evidence_dir is not None:
        overrides["evidence_dir"] = args.evidence_dir
    if args.run_correlation_id is not None:
        overrides["run_correlation_id"] = args.run_correlation_id
    if not overrides:
        return base

    from dataclasses import replace

    return replace(base, **overrides)


def run(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        config: PilotConfig = _build_config(args)
    except (PilotConfigError, MCCConfigurationError) as exc:
        print(f"pilot configuration error: {exc}", file=sys.stderr)
        return 2

    print(f"pilot run starting: pilot_id={config.pilot_id!r} mode={config.mode!r} "
          f"gateway={config.gateway_url!r} correlation={config.run_correlation_id!r}")

    with PilotIntegration(config) as pilot:
        for scenario in DEMO_SCENARIOS:
            try:
                outcome = pilot.submit(**scenario)
            except MCCSDKError as exc:
                print(f"  {scenario['action']!r} -> FAILED CLOSED: {type(exc).__name__}: {exc}")
                continue
            print(
                f"  {scenario['action']!r} by {scenario['identity']!r} -> "
                f"{outcome.decision.decision.value} (actuated={outcome.actuated})"
            )

        path = pilot.evidence.finalize_and_export()

    evidence = json.loads(path.read_text())
    print(f"\nevidence written to: {path}")
    print(json.dumps(evidence, indent=2, sort_keys=True))
    print(f"\nstatus: {evidence['status']} -- {evidence['status_reason']}")
    print(
        "\nNOTE: this run is a reference-integration demo against a locally "
        "reachable Gateway. It is not, and must not be presented as, a "
        "completed or externally validated production pilot -- see "
        "docs/PILOT_ACCEPTANCE_CHECKLIST.md."
    )
    return 0 if evidence["status"] == "PASS" else 1


if __name__ == "__main__":  # pragma: no cover -- manual/CI invocation only
    raise SystemExit(run())
