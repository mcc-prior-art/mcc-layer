"""Command-line demonstration of the reference governed agent.

    python -m examples.reference_governed_agent.cli \
        --scenario allow|deny|escalate|constrain --request "..."

By default it stands up a self-contained, in-process governed stack (real MCC
gateway + mock notification service + receipt-verifying governed executor) so the
demo runs with zero setup, then drives one full governed cycle and prints:

    user request -> structured proposal -> MCC verdict (+ reason, constraints)
      -> approval status (when required) -> execution result
      -> external receipt summary -> audit verification.

No signing keys, secrets, or complete internal tokens are printed.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from mcc_client import MCCClient

from .agent import ReferenceGovernedAgent
from .authorizers import ExecutionAuthorizer
from .models import AgentRunResult
from .operator import CLIOperator, Operator, ProgrammaticOperator
from .providers import DeterministicProvider

# Each scenario pins the provider so the demo deterministically drives one verdict.
#   allow      : within-policy notification            -> ALLOW
#   deny       : disallowed channel (not clampable)    -> DENY
#   constrain  : priority over the cap (clampable)     -> CONSTRAIN (clamp to 3)
#   escalate   : an actor holding no mandate           -> ESCALATE (ask operator)
_SCENARIOS = {
    "allow": dict(actor_id="agent/notify-bot", priority="normal", channel="email"),
    "deny": dict(actor_id="agent/notify-bot", priority="normal", channel="pager"),
    "constrain": dict(actor_id="agent/notify-bot", priority="high", channel="email"),
    "escalate": dict(actor_id="agent/unknown", priority="normal", channel="email"),
}

_DEFAULT_REQUEST = "Notify customer-123 that the appointment is confirmed"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m examples.reference_governed_agent.cli",
        description="Framework-neutral reference governed agent demo.")
    p.add_argument("--scenario", choices=sorted(_SCENARIOS), default="allow",
                   help="which verdict flow to demonstrate (default: allow)")
    p.add_argument("--request", default=_DEFAULT_REQUEST,
                   help="the natural-language request the agent reasons about")
    p.add_argument("--gateway", default=None,
                   help="target a running gateway URL instead of the in-process stack")
    p.add_argument("--operator", choices=("prompt", "auto", "reject"), default="auto",
                   help="ESCALATE operator: prompt a human, auto-approve, or reject "
                        "(default: auto, so the demo is non-interactive)")
    return p


def _operator(kind: str) -> Operator:
    if kind == "prompt":
        return CLIOperator()
    return ProgrammaticOperator(approve=(kind == "auto"))


def _print_result(scenario: str, result: AgentRunResult) -> None:
    line = "=" * 66
    print(f"\n{line}\nMCC-Core Reference Governed Agent — scenario: {scenario}\n{line}")
    print(f"  user request       : {result.request}")
    proposal = result.proposal or {}
    print(f"  proposed action    : {proposal.get('action', '-')} "
          f"by {proposal.get('actor_id', '-')} on {proposal.get('resource', '-')}")
    print(f"  proposed payload   : {proposal.get('payload', {})}")
    print(f"  MCC verdict        : {result.verdict}")
    print(f"  verdict reason     : {result.reason}")
    if result.applied_constraints:
        print(f"  applied constraints: {', '.join(result.applied_constraints)}")
    if result.approval_status is not None:
        print(f"  approval status    : {result.approval_status}")
    if result.final_payload is not None:
        print(f"  executed payload   : {result.final_payload}")
    print(f"  execution result   : {result.execution_status}")
    if result.receipt is not None:
        print(f"  external receipt   : {result.receipt}")
    if result.audit_valid is not None:
        print(f"  audit verification : valid={result.audit_valid}")
    if result.error:
        print(f"  detail             : {result.error}")


def _run_against(base_url: str, api_key: str, operator_key: str, *,
                 authorizer: Optional[ExecutionAuthorizer], scenario: str, request: str,
                 operator_kind: str) -> AgentRunResult:
    provider = DeterministicProvider(**_SCENARIOS[scenario])
    with MCCClient(base_url, api_key=api_key, operator_key=operator_key, timeout=15.0) as client:
        agent = ReferenceGovernedAgent(
            client, provider=provider, operator=_operator(operator_kind),
            authorizer=authorizer)
        return agent.handle(request)


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.gateway:
        # Remote gateway: the agent cannot self-authorize ALLOW/CONSTRAIN (it holds
        # no consensus material), so those will report BLOCKED for lack of
        # authorization — never a bypass. ESCALATE still executes via the operator.
        import os
        result = _run_against(
            args.gateway, os.environ.get("MCC_GATEWAY_API_KEY", "demo-key"),
            os.environ.get("MCC_GATEWAY_OPERATOR_API_KEY", "op-key"),
            authorizer=None, scenario=args.scenario, request=args.request,
            operator_kind=args.operator)
        _print_result(args.scenario, result)
        return 0 if result.execution_status != "ERROR" else 1

    # Self-contained in-process governed stack (default).
    from ._localstack import OPERATOR_KEY, LocalGovernedStack, agent_key
    stack = LocalGovernedStack()
    try:
        # V05/F1: the agent presents its OWN credential (the scenario actor's).
        result = _run_against(
            stack.base_url, agent_key(_SCENARIOS[args.scenario]["actor_id"]), OPERATOR_KEY,
            authorizer=stack.authorizer(),
            scenario=args.scenario, request=args.request, operator_kind=args.operator)
    finally:
        stack.close()
    _print_result(args.scenario, result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
