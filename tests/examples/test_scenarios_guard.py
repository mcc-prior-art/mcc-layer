"""Regression guard for the governed-agent demo (``scenarios.py``).

The demo prints, for each scenario, the number of times the executor actually
ran alongside the number it *should* have run:

    executor calls: N (want M)

This guard runs the script end-to-end and asserts every such line has N == M —
so a regression that lets the executor run too often (or not at all) fails CI,
not just the unit tests. It also asserts the script ran to completion and
covered all the scenarios (no early crash).
"""

import re
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "examples" / "governed_agent" / "scenarios.py"
LINE = re.compile(r"executor calls:\s*(\d+)\s*\(want\s*(\d+)\)")
# 12 scenarios print an explicit executor-call count today; new scenarios only
# raise this floor. Pin a lower bound so a truncated/early-exit run is caught.
MIN_COUNTED_SCENARIOS = 12


def test_scenarios_executor_counts_match_expected():
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, f"scenarios.py exited {proc.returncode}\n{proc.stderr}"
    out = proc.stdout
    matches = LINE.findall(out)
    assert len(matches) >= MIN_COUNTED_SCENARIOS, (
        f"expected >= {MIN_COUNTED_SCENARIOS} 'executor calls' lines, got {len(matches)}; "
        "did the demo crash early?")
    mismatches = [(observed, want) for observed, want in matches if observed != want]
    assert not mismatches, f"executor call count mismatch (observed, want): {mismatches}"
    # The demo must end on its terminal line — proves it ran to completion.
    assert "No verified decision" in out
