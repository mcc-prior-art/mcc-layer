"""Deterministic lifecycle for the embedded uvicorn servers the demo / smoke
scripts run.

Why this exists
---------------
A demo that calls ``uvicorn.run(...)`` inside a daemon thread and then lets the
interpreter exit relies on *interpreter finalization* to tear the server down.
uvicorn's default event loop is uvloop (a libuv C-extension); finalizing libuv
state while the loop thread is still alive is a well-known cause of an
intermittent ``Segmentation fault`` (process exit code 139) at shutdown — it
surfaces *after* the scenario has already printed success, which is exactly the
flaky smoke failure this module removes.

The fix is to own the lifecycle explicitly:

* keep a handle to the :class:`uvicorn.Server` and to its thread;
* wait deterministically for ``server.started`` before driving the scenario
  (no arbitrary sleep, bounded timeout, explicit failure);
* on teardown set ``server.should_exit = True`` — uvicorn's supported graceful
  stop, which closes the event loop *inside the server thread* — then **join
  the thread** and verify it actually exited, failing loudly if it did not.

Joining the server thread before the interpreter exits means the event-loop /
libuv resources are released on that thread while it is still running, so there
are no active loop resources left for finalization to race against. This is why
no event-loop override is needed: deterministic join, not loop choice, is the
fix.

Daemon-thread termination is **not** a safe shutdown mechanism and is never
relied upon here. The ``daemon=True`` flag is only a backstop so that a genuine
shutdown bug fails as a raised :class:`RuntimeError` (and, worst case, a killed
backstop thread) instead of hanging CI forever — the primary mechanism is always
``should_exit`` + ``join`` + liveness verification.
"""

from __future__ import annotations

import threading
import time
from typing import List

import uvicorn

__all__ = ["DemoServer", "DemoServers"]


class DemoServer:
    """One embedded uvicorn server with an explicit, joinable lifecycle."""

    def __init__(self, app, port: int, *, host: str = "127.0.0.1",
                 log_level: str = "error") -> None:
        config = uvicorn.Config(app, host=host, port=port, log_level=log_level)
        self.server = uvicorn.Server(config)
        # Signal handlers can only be installed on the main thread; this server
        # runs on a worker thread and is stopped via ``should_exit`` instead.
        self.server.install_signal_handlers = lambda: None
        self.host = host
        self.port = port
        self.thread = threading.Thread(
            target=self.server.run, name=f"demo-uvicorn-{port}", daemon=True)

    def start(self, *, timeout: float = 10.0) -> "DemoServer":
        """Start the server thread and block until it is ready to serve.

        Readiness is the uvicorn ``server.started`` flag (set once the socket is
        bound and the ASGI startup has completed) — not a fixed sleep. Raises
        :class:`RuntimeError` on a bounded timeout or if the server thread dies
        during startup (e.g. the port is already in use)."""
        self.thread.start()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.server.started:
                return self
            if not self.thread.is_alive():
                raise RuntimeError(
                    f"demo server on {self.host}:{self.port} failed to start "
                    "(server thread exited before it became ready)")
            time.sleep(0.02)
        # Readiness timed out: tear the half-started server down, then fail loudly.
        self.stop(timeout=timeout)
        raise RuntimeError(
            f"demo server on {self.host}:{self.port} did not become ready "
            f"within {timeout:.1f}s")

    def stop(self, *, timeout: float = 5.0) -> None:
        """Request graceful shutdown and join the server thread.

        Sets ``should_exit`` (uvicorn's supported stop signal), joins the thread
        within ``timeout``, and raises :class:`RuntimeError` if the thread is
        still alive afterwards — shutdown failure is never silent."""
        self.server.should_exit = True
        self.thread.join(timeout=timeout)
        if self.thread.is_alive():
            raise RuntimeError(
                f"demo server on {self.host}:{self.port} did not shut down "
                f"within {timeout:.1f}s (server thread still alive)")

    def __enter__(self) -> "DemoServer":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


class DemoServers:
    """Manage several :class:`DemoServer` instances with all-or-nothing teardown.

    Servers are tracked the moment they are created (before ``start`` returns) so
    a failed start is still torn down, and they are stopped in reverse start
    order. Per-server shutdown errors are collected and re-raised together — they
    are surfaced, never swallowed."""

    def __init__(self) -> None:
        self._servers: List[DemoServer] = []

    def start(self, app, port: int, *, timeout: float = 10.0, **kw) -> DemoServer:
        server = DemoServer(app, port, **kw)
        self._servers.append(server)
        server.start(timeout=timeout)
        return server

    def stop_all(self, *, timeout: float = 5.0) -> None:
        errors: List[str] = []
        for server in reversed(self._servers):
            try:
                server.stop(timeout=timeout)
            except Exception as exc:  # keep stopping the rest, then re-raise all
                errors.append(str(exc))
        self._servers.clear()
        if errors:
            raise RuntimeError("; ".join(errors))

    def __enter__(self) -> "DemoServers":
        return self

    def __exit__(self, *exc) -> None:
        self.stop_all()
