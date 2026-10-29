"""Real OS-process worker for AuditLog fault-injection tests
(tests/test_audit_optimization_regression.py). Invoked as a genuine
subprocess so the fcntl.flock cross-process lock and real process-death
semantics (SIGKILL releases the OS-held lock automatically; nothing the
dying process's own Python exception handlers do) are genuinely
exercised, not simulated in-process.

Modes:

* ``append``     -- one normal append of {"worker": <id>}, then exit 0.
* ``hold-lock``  -- acquire AuditLog._locked() and sleep until killed
  (models a writer that died, or hung, while holding the lock).
* ``crash-before-fsync`` -- monkeypatches os.fsync to SIGKILL this
  process on its first call, then attempts one append(). The write()
  and flush() calls run normally first (so their bytes reach the OS
  page cache); only the fsync() call itself never returns. This process
  never exits normally in this mode -- it is always killed.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcc_core.audit import AuditLog  # noqa: E402


def _append(path: str, worker_id: str) -> None:
    log = AuditLog(path)
    log.append({"worker": worker_id})


def _hold_lock(path: str) -> None:
    log = AuditLog(path)
    with log._locked():
        sys.stdout.write("LOCK_HELD\n")
        sys.stdout.flush()
        time.sleep(3600)


def _crash_before_fsync(path: str, worker_id: str) -> None:
    real_fsync = os.fsync

    def killing_fsync(fd):
        os.kill(os.getpid(), signal.SIGKILL)
        return real_fsync(fd)  # unreachable

    os.fsync = killing_fsync
    log = AuditLog(path)
    log.append({"worker": worker_id})
    sys.exit(97)  # unreachable if the kill actually fired


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", required=True)
    ap.add_argument("--mode", choices=["append", "hold-lock", "crash-before-fsync"], required=True)
    ap.add_argument("--worker-id", default="w")
    args = ap.parse_args()

    if args.mode == "append":
        _append(args.path, args.worker_id)
    elif args.mode == "hold-lock":
        _hold_lock(args.path)
    else:
        _crash_before_fsync(args.path, args.worker_id)


if __name__ == "__main__":
    main()
