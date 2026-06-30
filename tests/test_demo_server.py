"""Regression tests for the deterministic demo-server lifecycle helper.

These prove the property that removes the intermittent exit-139 smoke failure:
every embedded uvicorn server is explicitly shut down and its thread joined
before the interpreter exits — daemon-thread interpreter termination is never
relied upon. Tests are deterministic (no timing luck): readiness and shutdown
use bounded waits with explicit failure, and the leak checks assert on the exact
named server threads.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from fastapi import FastAPI

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from examples._demo_server import DemoServer, DemoServers  # noqa: E402


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _demo_threads():
    """The live server threads this helper creates are named ``demo-uvicorn-*``."""
    return [t for t in threading.enumerate() if t.name.startswith("demo-uvicorn-")]


# --------------------------------------------------------------------------
# 1/2/3: shutdown requested, thread terminates, none survive a successful run
# --------------------------------------------------------------------------

def test_start_then_stop_requests_shutdown_and_joins_thread():
    assert _demo_threads() == []
    server = DemoServer(FastAPI(), _free_port())
    server.start(timeout=10.0)
    assert server.server.started is True       # readiness was deterministic
    assert server.thread.is_alive()
    server.stop(timeout=5.0)
    assert server.server.should_exit is True   # (1) shutdown was requested
    assert not server.thread.is_alive()        # (2) the server thread terminated
    assert _demo_threads() == []               # (3) no server thread survives


# --------------------------------------------------------------------------
# 4: cleanup runs when the scenario raises
# --------------------------------------------------------------------------

def test_cleanup_runs_when_scenario_raises():
    servers = DemoServers()
    started = {}
    with pytest.raises(ValueError):
        with servers:
            started["s"] = servers.start(FastAPI(), _free_port())
            assert started["s"].thread.is_alive()
            raise ValueError("scenario blew up")
    # __exit__ stopped + joined the server despite the exception.
    assert not started["s"].thread.is_alive()
    assert _demo_threads() == []


# --------------------------------------------------------------------------
# 5: startup failure is reported clearly (bounded, explicit)
# --------------------------------------------------------------------------

# uvicorn calls sys.exit(1) inside its worker thread on a bind failure; pytest
# surfaces that as a thread-exception warning. It is exactly the failure we
# detect (the thread dies, start() raises) — silence only that benign warning.
@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_startup_failure_is_reported_clearly():
    port = _free_port()
    holder = DemoServer(FastAPI(), port)
    holder.start(timeout=10.0)
    try:
        # A second server on the same port cannot bind; its thread exits during
        # startup and start() must fail loudly rather than hang.
        clash = DemoServer(FastAPI(), port)
        with pytest.raises(RuntimeError, match="failed to start"):
            clash.start(timeout=5.0)
    finally:
        holder.stop(timeout=5.0)
    assert _demo_threads() == []


# --------------------------------------------------------------------------
# 6: shutdown timeout fails explicitly (never silently)
# --------------------------------------------------------------------------

def test_shutdown_timeout_fails_explicitly():
    server = DemoServer(FastAPI(), _free_port())
    # Swap in a thread that ignores should_exit so the join cannot complete.
    release = threading.Event()
    server.thread = threading.Thread(
        target=release.wait, name="demo-uvicorn-stuck", daemon=True)
    server.thread.start()
    try:
        with pytest.raises(RuntimeError, match="did not shut down"):
            server.stop(timeout=0.2)
    finally:
        release.set()
        server.thread.join(timeout=2.0)
    assert not server.thread.is_alive()


# --------------------------------------------------------------------------
# 7: repeated start/stop cycles do not leak threads
# --------------------------------------------------------------------------

def test_repeated_start_stop_does_not_leak_threads():
    assert _demo_threads() == []
    for _ in range(20):
        server = DemoServer(FastAPI(), _free_port())
        server.start(timeout=10.0)
        server.stop(timeout=5.0)
        assert not server.thread.is_alive()
    assert _demo_threads() == []


# --------------------------------------------------------------------------
# multi-server: a failed start in a group is still torn down
# --------------------------------------------------------------------------

def test_demoservers_tears_down_even_if_a_later_start_fails():
    port = _free_port()
    servers = DemoServers()
    servers.start(FastAPI(), port)            # ok
    with pytest.raises(RuntimeError):
        servers.start(FastAPI(), port)        # clash -> raises, but is tracked
    servers.stop_all()                        # stops both the ok and the failed one
    assert _demo_threads() == []


# --------------------------------------------------------------------------
# 8/10: a representative demo script exits 0 with its assertions intact
# --------------------------------------------------------------------------

@pytest.mark.parametrize("script", ["egress_proxy_demo.py", "enforced_egress_agent.py"])
def test_demo_script_exits_zero(script):
    proc = subprocess.run(
        [sys.executable, str(ROOT / "examples" / script)],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, f"{script} exit={proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    assert "PASSED" in proc.stdout
    # The smoke assertions are still active (the script still computes failures).
    assert "FAILED" not in proc.stdout


# --------------------------------------------------------------------------
# 9: a genuine demo failure still produces a non-zero exit (no masking)
# --------------------------------------------------------------------------

_FAILING_DEMO = '''
import sys
ROOT = {root!r}
sys.path.insert(0, ROOT); sys.path.insert(0, ROOT + "/src")
import socket
from fastapi import FastAPI
from examples._demo_server import DemoServers

def _port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def main() -> int:
    servers = DemoServers()
    try:
        servers.start(FastAPI(), _port())
        # A genuine scenario miss: return non-zero, exactly like a real demo.
        return 1
    finally:
        servers.stop_all()

if __name__ == "__main__":
    sys.exit(main())
'''


def test_demo_failure_still_exits_nonzero(tmp_path):
    script = tmp_path / "failing_demo.py"
    script.write_text(_FAILING_DEMO.format(root=str(ROOT)))
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, timeout=60,
    )
    # Non-zero (not 139/segfault), and it did not hang (timeout would have raised).
    assert proc.returncode == 1, f"exit={proc.returncode}\n{proc.stderr}"
