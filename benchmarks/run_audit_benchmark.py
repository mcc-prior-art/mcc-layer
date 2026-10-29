"""P2-A2: AuditLog tail-read optimization -- before/after micro-benchmark.

Extends the P2-A harness (``benchmarks/workload.py`` / ``run_benchmark.py``)
with a benchmark targeted specifically at the bottleneck PR #126 profiled:
``AuditLog._read_last_entry()``'s file read, isolated from the mandatory
``fsync`` cost, at varying pre-existing audit-file sizes.

Three numbers are reported, always kept separate:

* ``read_last_entry_seconds``  -- N isolated calls to
  ``AuditLog._read_last_entry(tolerate_parse_errors=False)`` against a
  FIXED audit file of the given size (the file is not mutated by these
  calls, so this is a clean, repeatable read-cost measurement at that
  exact size).
* ``raw_fsync_seconds`` -- N isolated write+flush+fsync cycles on a
  throwaway file, with NO AuditLog involved at all -- the irreducible
  durability cost this optimization deliberately never touches.
* ``append_seconds`` -- N real, end-to-end ``AuditLog.append()`` calls
  (file grows by N entries over the run; reported file_size_before is
  the size at the START of the run, so this is comparable across
  before/after as long as the same starting size and N are used, which
  this script's ``--entries``/``--samples`` flags make explicit).

This script is used TWICE to produce a genuine before/after comparison:
once against the pre-optimization ``src/mcc_core/audit.py`` (saved
separately, see ``docs/AUDITLOG_OPTIMIZATION.md`` for exact reproduction
commands and commit SHAs), and once against the optimized version. It
never compares a real measurement against an invented one.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcc_core.audit import AuditLog  # noqa: E402


def _percentile(sorted_samples: List[float], pct: float) -> float:
    if not sorted_samples:
        return float("nan")
    k = max(0, min(len(sorted_samples) - 1, int(round(pct / 100.0 * (len(sorted_samples) - 1)))))
    return sorted_samples[k]


def _summarize(samples: List[float]) -> Dict[str, Any]:
    s = sorted(samples)
    return {
        "sample_size": len(s),
        "p50": _percentile(s, 50),
        "p95": _percentile(s, 95),
        "p99": _percentile(s, 99) if len(s) >= 100 else None,
        "p99_caveat": None if len(s) >= 100 else f"sample_size {len(s)} < 100: p99 suppressed",
        "min": s[0] if s else None,
        "max": s[-1] if s else None,
        "mean": (sum(s) / len(s)) if s else None,
    }


def _populate(path: str, n_entries: int) -> None:
    log = AuditLog(path)
    for i in range(n_entries):
        log.append({"seed_entry": i, "pad": "x" * 40})


def _bench_read_last_entry(path: str, samples: int) -> List[float]:
    log = AuditLog(path)
    out = []
    for _ in range(samples):
        t0 = time.perf_counter()
        log._read_last_entry(tolerate_parse_errors=False)
        out.append(time.perf_counter() - t0)
    return out


def _bench_append(path: str, samples: int) -> List[float]:
    log = AuditLog(path)
    out = []
    for i in range(samples):
        t0 = time.perf_counter()
        log.append({"bench_append": i})
        out.append(time.perf_counter() - t0)
    return out


def _bench_raw_fsync(samples: int) -> List[float]:
    """No AuditLog involved at all -- the irreducible floor."""
    fd, path = tempfile.mkstemp(prefix="raw-fsync-bench-")
    os.close(fd)
    out = []
    try:
        for i in range(samples):
            t0 = time.perf_counter()
            with open(path, "a", encoding="utf-8") as fh:
                fh.write('{"i": %d}\n' % i)
                fh.flush()
                os.fsync(fh.fileno())
            out.append(time.perf_counter() - t0)
    finally:
        os.unlink(path)
    return out


def _environment_info() -> Dict[str, Any]:
    try:
        git_sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(Path(__file__).resolve().parent.parent),
        ).decode().strip()
    except Exception:
        git_sha = "unknown"
    try:
        dirty = bool(subprocess.check_output(
            ["git", "status", "--porcelain", "--", "src/mcc_core/audit.py"],
            cwd=str(Path(__file__).resolve().parent.parent),
        ).decode().strip())
    except Exception:
        dirty = None
    return {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "git_sha": git_sha,
        "audit_py_locally_modified": dirty,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entries", type=int, default=5000,
                        help="number of pre-existing entries to seed the audit file with")
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--output", type=str, default=None)
    parser.add_argument("--label", type=str, default=None,
                        help="free-text label, e.g. 'before' or 'after', recorded in the output")
    args = parser.parse_args()

    tmpdir = tempfile.mkdtemp(prefix="mcc-audit-bench-")
    path = str(Path(tmpdir) / "audit.jsonl")
    _populate(path, args.entries)
    file_size_bytes = os.path.getsize(path)

    read_samples = _bench_read_last_entry(path, args.samples)
    append_samples = _bench_append(path, args.samples)
    raw_fsync_samples = _bench_raw_fsync(args.samples)

    result: Dict[str, Any] = {
        "label": args.label,
        "seeded_entries": args.entries,
        "file_size_bytes_at_start": file_size_bytes,
        "samples": args.samples,
        "read_last_entry_seconds": _summarize(read_samples),
        "append_seconds": _summarize(append_samples),
        "raw_fsync_seconds": _summarize(raw_fsync_samples),
        "environment": _environment_info(),
    }
    print(json.dumps(result, indent=2))
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"\nwritten to {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
