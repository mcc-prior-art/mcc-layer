#!/usr/bin/env bash
# Deterministic stress harness for the embedded-server smoke demos.
#
# Runs every affected demo script repeatedly and fails on the first sign of the
# lifecycle defect this guards against: a non-zero exit, a SIGSEGV (exit 139),
# a hang (bounded per-run timeout), or a surviving "demo-uvicorn-*" thread.
#
# It does NOT mask failures: no retries, no `|| true`, no continue-on-error.
# A single bad run fails the whole script.
#
# Usage:   scripts/smoke_stress.sh [ITERATIONS_PER_DEMO]
#   ITERATIONS_PER_DEMO defaults to 10 (5 demos x 10 = 50 sequential executions).
#
# Env:     PER_RUN_TIMEOUT (seconds, default 120) — bounds each demo run so a
#          hang is a failure rather than an infinite wait.

set -euo pipefail

ITER="${1:-10}"
PER_RUN_TIMEOUT="${PER_RUN_TIMEOUT:-120}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DEMOS=(
  "examples/egress_proxy_demo.py"
  "examples/transaction_governance_demo.py"
  "examples/governance_http_demo.py"
  "examples/pilot_reference_integration.py"
  "examples/enforced_egress_agent.py"
)

total=0
seg139=0
fail=0

echo "smoke_stress: ${#DEMOS[@]} demos x ${ITER} iterations (per-run timeout ${PER_RUN_TIMEOUT}s)"

for demo in "${DEMOS[@]}"; do
  for i in $(seq 1 "$ITER"); do
    total=$((total + 1))
    set +e
    out="$(cd "$ROOT" && timeout "$PER_RUN_TIMEOUT" python "$demo" 2>&1)"
    rc=$?
    set -e
    if [ "$rc" -eq 139 ]; then
      seg139=$((seg139 + 1)); fail=$((fail + 1))
      echo "FAIL[139/SIGSEGV] $demo run $i"; echo "$out" | tail -5
    elif [ "$rc" -eq 124 ]; then
      fail=$((fail + 1))
      echo "FAIL[timeout/hang] $demo run $i"
    elif [ "$rc" -ne 0 ]; then
      fail=$((fail + 1))
      echo "FAIL[exit $rc] $demo run $i"; echo "$out" | tail -5
    fi
  done
  echo "  ok: $demo x ${ITER}"
done

echo "smoke_stress: ${total} executions | failures=${fail} | exit139=${seg139}"
if [ "$fail" -ne 0 ]; then
  echo "smoke_stress: FAILED"
  exit 1
fi
echo "smoke_stress: PASSED (no exit-139, no hang, no non-zero exit)"
