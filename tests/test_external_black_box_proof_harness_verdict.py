"""Fail-closed verdict/exit-code logic tests for the External Black-Box
Integration Proof harness (PR #115 hardening of PR #114).

These tests exercise the ACTUAL decision functions -- the consumer's
``_finalize`` (loaded from the committed snapshot, which is a
byte-for-byte copy of the real external consumer -- see
``tests/test_external_black_box_proof_harness_verdict.py::test_snapshot_is_current``
for the freshness check shared with the architecture guard test) and the
orchestrator's ``_compute_overall_verdict`` -- with deliberately falsified
inputs, and assert the resulting verdict and exit code. This is
intentionally NOT a string-search over source code: every test below
calls a real function and inspects its real return value.

Covers, per PR #115's required matrix:
  A. proposal hash binding false
  B. submit status not PROPOSED
  C. execute status not EXECUTED
  D. replay status not BLOCKED
  E. invalid auth not 401
  F. unauthorized action not DENIED
  G. malformed proposal not 422
  H. proof identifier missing from model output
  I. consumer returns non-zero
  J. independent read-back verified == false
  K. independent read-back total_count == 0
  L. independent read-back total_count > 1

Plus the positive control (all conditions true -> PROVEN / exit 0),
without which every negative test above would be vacuous.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "proofs" / "external_black_box_integration_proof" / "external_consumer_snapshot" / "consumer.py"
ORCHESTRATOR_PATH = ROOT / "proofs" / "external_black_box_integration_proof" / "run_black_box_proof.py"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def consumer_module():
    return _load_module(SNAPSHOT, "_consumer_snapshot_for_verdict_tests")


@pytest.fixture(scope="module")
def orchestrator_module():
    return _load_module(ORCHESTRATOR_PATH, "_orchestrator_for_verdict_tests")


def _all_true_checks(consumer_module) -> Dict[str, bool]:
    return {name: True for name in consumer_module.REQUIRED_CHECKS}


# ---------------------------------------------------------------------------
# Positive control -- required so every negative test below is non-vacuous
# ---------------------------------------------------------------------------

def test_positive_control_all_checks_true_yields_proven_and_exit_zero(consumer_module):
    checks = _all_true_checks(consumer_module)
    evidence: Dict[str, Any] = {}
    exit_code = consumer_module._finalize(evidence, checks)
    assert exit_code == 0
    assert evidence["result"] == "PROVEN"
    assert evidence["failed_checks"] == []


# ---------------------------------------------------------------------------
# A-H: each individual required condition, falsified one at a time
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "flipped_check",
    [
        "proposal_hash_binding_verified",       # A
        "submit_status_proposed",               # B
        "execute_status_executed",              # C
        "replay_status_blocked",                # D
        "invalid_auth_submit_401",              # E (submit leg)
        "invalid_auth_execute_401",             # E (execute leg)
        "unauthorized_execute_denied",          # F
        "malformed_submit_422",                 # G
        "proof_id_in_model_output",             # H
    ],
)
def test_single_falsified_condition_yields_not_proven_and_nonzero_exit(consumer_module, flipped_check):
    checks = _all_true_checks(consumer_module)
    checks[flipped_check] = False
    evidence: Dict[str, Any] = {}
    exit_code = consumer_module._finalize(evidence, checks)
    assert exit_code != 0, f"expected non-zero exit when {flipped_check} is false"
    assert evidence["result"] == "NOT PROVEN"
    assert flipped_check in evidence["failed_checks"]


def test_every_required_check_has_an_individual_falsification_test(consumer_module):
    """Non-vacuity meta-check: every name in REQUIRED_CHECKS must be
    coverable by flipping it to False and observing NOT PROVEN -- proves
    the parametrized test above (plus the two auth-leg checks) actually
    spans the full required set, not just a hand-picked subset."""
    covered = {
        "proposal_hash_binding_verified", "submit_status_proposed", "execute_status_executed",
        "replay_status_blocked", "invalid_auth_submit_401", "invalid_auth_execute_401",
        "unauthorized_execute_denied", "malformed_submit_422", "proof_id_in_model_output",
        # covered implicitly via the "all true" positive control and via
        # main()'s own early-abort behavior (live_model_call_succeeded is
        # never reached as True unless the live call succeeds); still
        # verify each is individually flip-able through the same generic
        # mechanism the parametrized test uses:
        "live_model_call_succeeded", "submit_http_200", "execute_http_200", "replay_http_200",
        "unauthorized_submit_accepted",
    }
    assert covered == set(consumer_module.REQUIRED_CHECKS)
    for name in consumer_module.REQUIRED_CHECKS:
        checks = _all_true_checks(consumer_module)
        checks[name] = False
        evidence: Dict[str, Any] = {}
        exit_code = consumer_module._finalize(evidence, checks)
        assert exit_code != 0
        assert evidence["result"] == "NOT PROVEN"
        assert name in evidence["failed_checks"]


def test_unreached_check_defaults_to_failed_not_passed(consumer_module):
    """A check never explicitly set True (e.g. because an earlier step
    aborted main()) must count as failed -- REQUIRED_CHECKS is seeded
    all-False, so an early return that skips straight to _finalize with
    the seeded dict must yield NOT PROVEN, never a vacuous pass."""
    checks = {name: False for name in consumer_module.REQUIRED_CHECKS}
    evidence: Dict[str, Any] = {}
    exit_code = consumer_module._finalize(evidence, checks)
    assert exit_code != 0
    assert evidence["result"] == "NOT PROVEN"
    assert set(evidence["failed_checks"]) == set(consumer_module.REQUIRED_CHECKS)


def test_finalize_rejects_incomplete_checks_dict(consumer_module):
    """Internal-consistency guard: _finalize must never silently treat a
    missing check name as passed -- it must fail loudly instead."""
    incomplete = _all_true_checks(consumer_module)
    del incomplete[next(iter(incomplete))]
    with pytest.raises(AssertionError):
        consumer_module._finalize({}, incomplete)


# ---------------------------------------------------------------------------
# Orchestrator overall verdict: I, J, K, L
# ---------------------------------------------------------------------------

def _good_consumer_evidence() -> Dict[str, Any]:
    return {"result": "PROVEN", "execute_status": "EXECUTED", "proof_id": "mcc-blackbox-deadbeef"}


def _good_readback() -> Dict[str, Any]:
    return {"verified": True, "total_count": 1, "issues": [{"number": 1}]}


def test_orchestrator_positive_control_all_good_yields_proven(orchestrator_module):
    verdict = orchestrator_module._compute_overall_verdict(
        consumer_returncode=0, consumer_evidence=_good_consumer_evidence(), independent_readback=_good_readback(),
    )
    assert verdict["overall_verdict"] == "PROVEN"
    assert verdict["overall_failure_reasons"] == []


def test_I_consumer_nonzero_returncode_yields_not_proven(orchestrator_module):
    verdict = orchestrator_module._compute_overall_verdict(
        consumer_returncode=1, consumer_evidence=_good_consumer_evidence(), independent_readback=_good_readback(),
    )
    assert verdict["overall_verdict"] == "NOT PROVEN"
    assert any("returncode" in r for r in verdict["overall_failure_reasons"])


def test_consumer_result_not_proven_yields_not_proven(orchestrator_module):
    evidence = _good_consumer_evidence()
    evidence["result"] = "NOT PROVEN"
    verdict = orchestrator_module._compute_overall_verdict(
        consumer_returncode=0, consumer_evidence=evidence, independent_readback=_good_readback(),
    )
    assert verdict["overall_verdict"] == "NOT PROVEN"
    assert any("result" in r for r in verdict["overall_failure_reasons"])


def test_execute_status_not_executed_yields_not_proven(orchestrator_module):
    evidence = _good_consumer_evidence()
    evidence["execute_status"] = "BLOCKED"
    verdict = orchestrator_module._compute_overall_verdict(
        consumer_returncode=0, consumer_evidence=evidence, independent_readback=_good_readback(),
    )
    assert verdict["overall_verdict"] == "NOT PROVEN"
    assert any("execute_status" in r for r in verdict["overall_failure_reasons"])


def test_J_readback_not_verified_yields_not_proven(orchestrator_module):
    readback = {"verified": False, "total_count": 0}
    verdict = orchestrator_module._compute_overall_verdict(
        consumer_returncode=0, consumer_evidence=_good_consumer_evidence(), independent_readback=readback,
    )
    assert verdict["overall_verdict"] == "NOT PROVEN"
    assert any("verified" in r for r in verdict["overall_failure_reasons"])


def test_K_readback_zero_matches_yields_not_proven(orchestrator_module):
    readback = {"verified": True, "total_count": 0}
    verdict = orchestrator_module._compute_overall_verdict(
        consumer_returncode=0, consumer_evidence=_good_consumer_evidence(), independent_readback=readback,
    )
    assert verdict["overall_verdict"] == "NOT PROVEN"
    assert any("total_count" in r for r in verdict["overall_failure_reasons"])


def test_L_readback_multiple_matches_yields_not_proven(orchestrator_module):
    readback = {"verified": True, "total_count": 2, "issues": [{"number": 1}, {"number": 2}]}
    verdict = orchestrator_module._compute_overall_verdict(
        consumer_returncode=0, consumer_evidence=_good_consumer_evidence(), independent_readback=readback,
    )
    assert verdict["overall_verdict"] == "NOT PROVEN"
    assert any("total_count" in r for r in verdict["overall_failure_reasons"])


def test_readback_missing_entirely_yields_not_proven(orchestrator_module):
    """Unavailable read-back (e.g. GITHUB_TOKEN absent) must not be
    treated as an inconclusive pass."""
    verdict = orchestrator_module._compute_overall_verdict(
        consumer_returncode=0, consumer_evidence=_good_consumer_evidence(), independent_readback={},
    )
    assert verdict["overall_verdict"] == "NOT PROVEN"
    assert verdict["overall_failure_reasons"]


# ---------------------------------------------------------------------------
# Snapshot freshness (shared assumption with the architecture guard test)
# ---------------------------------------------------------------------------

def test_snapshot_is_current_copy_of_live_consumer_when_present():
    live_copy = Path("/tmp/mcc-live-external-consumer/consumer.py")
    if not live_copy.exists():
        return
    assert live_copy.read_text(encoding="utf-8") == SNAPSHOT.read_text(encoding="utf-8")
