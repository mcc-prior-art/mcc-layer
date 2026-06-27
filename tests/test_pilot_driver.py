"""The runbook driver (deploy/pilot/pilot_driver.py) drives the real consensus
path via the SDK. Loaded by path because deploy/pilot is a deploy dir, not a
package. Reuses the in-process consensus app builder from the SDK tests.
"""

import importlib.util
from pathlib import Path

from fastapi.testclient import TestClient

from pilot.client import MCCGatewayClient
from tests.test_pilot_client import _consensus_app

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "pilot_driver", ROOT / "deploy" / "pilot" / "pilot_driver.py")
driver = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(driver)


def test_driver_consensus_execute_reaches_upstream():
    evals, app, calls = _consensus_app()
    client = MCCGatewayClient("http://testserver", api_key="agent-key",
                              operator_key="op-key", client=TestClient(app))
    out = driver.consensus_execute(
        client, evals, actor="agent/x", action="generic_op", context={"value": 1},
        policy_hash="sha256:p", idempotency_key="driver-op-1")
    assert out.executed and len(calls) == 1


def test_driver_sign_votes_bind_to_nonce_and_policy():
    evals, _, _ = _consensus_app()
    votes = driver.sign_votes(evals, action="generic_op", payload={"value": 1},
                              actor="agent/x", policy_hash="sha256:p", nonce="n-123")
    assert len(votes) == 3
    assert all(v["evaluator_id"] in {"eval-0", "eval-1", "eval-2"} for v in votes)
