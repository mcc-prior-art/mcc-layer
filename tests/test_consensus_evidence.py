"""Tests for the Multi-Context Consensus 3-of-3 evidence package.

Confirms the harness is deterministic/reproducible, every scenario behaves as
recorded (positive → ALLOW, adversarial → DENY), the committed artifacts match a
fresh generation, and the independent verifier passes on the committed evidence.
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "evidence" / "consensus_3of3"
ARTIFACTS = PKG / "artifacts"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, PKG / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


harness = _load("harness")


def test_all_scenarios_behave_as_expected(tmp_path):
    summary = harness.generate(tmp_path)
    assert summary["all_pass"] is True
    results = json.loads((tmp_path / "results.json").read_text())
    # One positive consensus, the rest adversarial denials.
    assert results["unanimous_3of3"]["actual"] == "ALLOW"
    adversarial = [r for r in results.values() if r["adversarial"]]
    assert adversarial and all(r["actual"] == "DENY" for r in adversarial)


def test_generation_is_deterministic(tmp_path):
    a = harness.generate(tmp_path / "a")
    b = harness.generate(tmp_path / "b")
    assert a["manifest_sha256"] == b["manifest_sha256"]
    assert a["files"] == b["files"]


def test_committed_artifacts_match_fresh_generation(tmp_path):
    fresh = harness.generate(tmp_path)
    for rel, sha in fresh["files"].items():
        committed = ARTIFACTS / rel
        assert committed.exists(), f"missing committed artifact {rel}"
        assert harness._sha256(committed.read_bytes()) == sha, f"drift in {rel}"


def test_harness_check_passes():
    r = subprocess.run([sys.executable, str(PKG / "harness.py"), "--check"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_independent_verifier_passes():
    r = subprocess.run([sys.executable, str(PKG / "verify_independent.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "INDEPENDENT VERIFICATION PASSED" in r.stdout


def test_manifest_covers_every_artifact():
    listed = {line.split("  ", 1)[1] for line in
              (ARTIFACTS / "MANIFEST.sha256").read_text().splitlines() if line.strip()}
    on_disk = {str(p.relative_to(ARTIFACTS)) for p in ARTIFACTS.rglob("*")
               if p.is_file() and p.name != "MANIFEST.sha256"}
    assert listed == on_disk
