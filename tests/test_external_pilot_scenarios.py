"""External Pilot Integration Pack -- pilot scenarios A-H (PR #113),
offline, deterministic.

Each scenario in ``examples.external_pilot.scenarios`` is exercised here
through an ``httpx.AsyncClient`` bound via ``httpx.ASGITransport`` -- a
genuine HTTP request/response cycle through FastAPI's real routing/
dependency/validation layer (the SAME transport mechanism
``examples.external_pilot.client.mcc_pilot_client.MCCPilotClient`` uses
against a real TCP socket in ``run_external_pilot_self_check.py``), never
a direct Python call into ``ProposalExecutionService``.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from examples.external_pilot.client.mcc_pilot_client import MCCPilotClient
from examples.external_pilot.scenarios import ALL_SCENARIOS, build_scenario_stack

run = asyncio.run


@pytest.fixture()
def stack():
    return build_scenario_stack()


def _make_client_factory(app):
    transport = httpx.ASGITransport(app=app)
    clients = []

    def make_client(api_key: str) -> MCCPilotClient:
        client = httpx.AsyncClient(transport=transport, base_url="http://external-pilot-test")
        clients.append(client)
        return MCCPilotClient(client=client, api_key=api_key)

    return make_client, clients


async def _close_all(clients):
    for c in clients:
        await c.aclose()


@pytest.mark.parametrize("scenario_fn", ALL_SCENARIOS, ids=lambda fn: fn.__name__)
def test_scenario(scenario_fn, stack):
    make_client, clients = _make_client_factory(stack.app)
    try:
        result = run(scenario_fn(make_client, stack))
    finally:
        run(_close_all(clients))
    assert result.passed, f"{result.name} failed: {result.failures}\ndetail={result.detail}"


def test_all_scenarios_together_share_one_stack():
    """Reproduces the same sequence the self-check script runs, on ONE
    shared server instance -- proving the scenarios remain correct when
    they are not each given a pristine stack (exactly how a real
    integrator's own end-to-end smoke test would run them)."""
    stack_shared = build_scenario_stack()
    make_client, clients = _make_client_factory(stack_shared.app)
    try:
        results = [run(fn(make_client, stack_shared)) for fn in ALL_SCENARIOS]
    finally:
        run(_close_all(clients))
    failed = [r for r in results if not r.passed]
    assert not failed, f"scenarios failed when run together: {[(r.name, r.failures) for r in failed]}"
