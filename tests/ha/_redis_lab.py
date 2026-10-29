"""Real-process, real-Redis fault-injection lab for the P2-B HA fault matrix.

Everything here either (a) spawns a genuine OS subprocess (a real
``redis-server`` binary, or a real Python worker process that issues one
governed operation and can SIGKILL itself at a controlled point), or
(b) wraps a REAL ``redis.asyncio`` client with a thin proxy that performs a
real disruptive action (kill the real redis-server process, or really read
a forged clock sample from it) as a side effect of being called -- never a
bare ``raise ConnectionError(...)`` double standing in for the whole fault.
Where a true multi-host network partition genuinely cannot be built in this
single-host sandbox, that is called out explicitly at the call site, not
papered over.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from mcc_core import (  # noqa: E402
    AuditLog,
    DecisionEngine,
    ExecutionGate,
    InMemoryNonceRegistry,
    ProfileRegistry,
    SigningKey,
)
from mcc_core.coordinator import EnforcementCoordinator  # noqa: E402

REDIS_SERVER_BIN = shutil.which("redis-server") or "/usr/bin/redis-server"
POLICY_HASH = "sha256:" + "a" * 64


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class RealRedisServer:
    """A genuine ``redis-server`` OS process on an isolated port/data dir.

    This is NOT a mock: ``kill()``/``restart()`` send real signals to a real
    process, and a client talking to a killed instance hits a real severed
    TCP connection, not a monkeypatched exception.
    """

    def __init__(self) -> None:
        self.port = free_port()
        self.url = f"redis://127.0.0.1:{self.port}/0"
        self._dir = Path(tempfile.mkdtemp(prefix="mcc-ha-redis-"))
        self.proc: Optional[subprocess.Popen] = None

    def start(self, *, wait_seconds: float = 5.0) -> "RealRedisServer":
        self.proc = subprocess.Popen(
            [
                REDIS_SERVER_BIN, "--port", str(self.port), "--bind", "127.0.0.1",
                "--daemonize", "no", "--save", "", "--appendonly", "no",
                "--dir", str(self._dir), "--logfile", str(self._dir / "redis.log"),
            ],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            if self._ping():
                return self
            if self.proc.poll() is not None:
                raise RuntimeError("redis-server exited during startup")
            time.sleep(0.05)
        raise RuntimeError(f"redis-server did not become ready on port {self.port}")

    def _ping(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=0.2) as s:
                s.sendall(b"PING\r\n")
                return s.recv(16).startswith(b"+PONG")
        except OSError:
            return False

    def kill(self) -> None:
        """A real, hard process kill -- the closest single-host analogue to
        an instance actually dying, not a graceful shutdown."""
        if self.proc is not None and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGKILL)
            self.proc.wait(timeout=5.0)

    def restart(self, *, wait_seconds: float = 5.0) -> None:
        """Real restart on the SAME port. Data is NOT preserved (``--save
        ""``, no AOF) -- a genuine from-empty recovery, not a resumed
        snapshot; this is deliberate so recovery tests prove "a fresh
        operation can proceed again", not "old state silently survived"."""
        self.kill()
        self.start(wait_seconds=wait_seconds)

    def stop(self) -> None:
        try:
            self.kill()
        except Exception:
            pass
        shutil.rmtree(self._dir, ignore_errors=True)


def redis_reachable(url: str = "redis://127.0.0.1:6379/0", timeout: float = 0.3) -> bool:
    try:
        import redis as redis_sync

        client = redis_sync.from_url(url, socket_timeout=timeout, socket_connect_timeout=timeout)
        return bool(client.ping())
    except Exception:
        return False


REDIS_AVAILABLE = shutil.which("redis-server") is not None


class KillRedisOnFirstCall:
    """Wraps a REAL registry/client. The first call to ``trigger_attr``
    performs a REAL kill of ``server`` (an actual OS process signal, not a
    monkeypatched exception) and then genuinely attempts the real
    underlying call against the now-dead process -- the resulting failure
    is a real severed-connection error from the real redis client library,
    not a synthetic double."""

    def __init__(self, inner: Any, server: RealRedisServer, trigger_attr: str) -> None:
        self._inner = inner
        self._server = server
        self._trigger_attr = trigger_attr
        self._fired = False

    def __getattr__(self, name: str):
        attr = getattr(self._inner, name)
        if name != self._trigger_attr or not callable(attr):
            return attr

        async def _wrapped(*args, **kwargs):
            if not self._fired:
                self._fired = True
                self._server.kill()
            return await attr(*args, **kwargs)

        return _wrapped


class ForgedClockRedisClient:
    """Wraps a REAL ``redis.asyncio`` client. Every method is forwarded to
    the real client UNCHANGED except ``time()``, which returns an
    attacker/clock-fault-controlled value instead of the real server's
    reply -- modelling a compromised or badly-drifted Redis clock without
    needing a second real Redis instance with a manually skewed system
    clock (not practical in this sandbox). This is the one genuinely
    mocked primitive in this lab, and only for the single value
    ``trusted_time.RedisTimeSource`` is explicitly designed not to trust
    blindly; every other fault in this suite is a real process/network
    action."""

    def __init__(self, real_client: Any, forged_seconds: int) -> None:
        self._real = real_client
        self._forged = forged_seconds

    def __getattr__(self, name: str):
        return getattr(self._real, name)

    async def time(self):
        return (self._forged, 0)


def build_coordinator(
    *,
    idempotency: Any,
    velocity: Any,
    revocation_registry: Optional[Any] = None,
    time_source: Optional[Any] = None,
    audit: Optional[AuditLog] = None,
    limits=None,
    audit_path: Optional[str] = None,
):
    """One self-consistent governed stack (own signing key, own gate) --
    see module docstring: the property under test is the SHARED DURABLE
    STATE (idempotency/velocity/revocation, all pointed at one real Redis),
    not cross-instance signature trust (already covered by
    ``gateway/trust.py``'s own multi-issuer tests)."""
    key = SigningKey.generate("ha-lab-" + os.urandom(4).hex())
    engine = DecisionEngine(
        signing_key=key, issuer="mcc/ha-lab", audience="gate",
        policy_id="ha-lab/v1", policy_hash=POLICY_HASH, token_ttl_seconds=120,
    )
    gate = ExecutionGate(
        trusted_keys={key.kid: key.public_key()}, audience="gate",
        nonce_registry=InMemoryNonceRegistry(), policy_hash=POLICY_HASH,
    )
    if audit is None:
        d = tempfile.mkdtemp(prefix="mcc-ha-audit-")
        audit = AuditLog(audit_path or str(Path(d) / "audit.jsonl"))
    coordinator = EnforcementCoordinator(
        gate=gate, idempotency=idempotency, velocity=velocity, audit=audit,
        profiles=ProfileRegistry.default_pilot(),
        velocity_limits_for=(lambda action: (limits or [])),
        revocation_registry=revocation_registry,
        time_source=time_source,
    )
    return engine, coordinator, audit


def payment_token(engine, *, idem, tenant, amount=100.0, actor="actor-1",
                   beneficiary="ben-1", resource="acct-1", currency="usd",
                   mandate_id=None, txn=None):
    from mcc_core import PaymentProfile

    profile = PaymentProfile()
    ctx = {"source": resource, "beneficiary_id": beneficiary, "amount": amount, "currency": currency}
    payload = profile.canonical_payload(ctx)
    token = engine.issue_token(
        verdict="ALLOW", subject=actor, action="send_payment", payload=payload,
        transaction_id=txn or idem, idempotency_key=idem, actor_id=actor,
        resource_id=resource, auth_claims=profile.auth_claims(ctx), tenant_id=tenant,
        mandate_id=mandate_id,
    )
    return token, payload


def runner(record):
    async def executor():
        record.append("executed")
        return "upstream-ok"
    return executor


def killer_executor(server_or_proc, *, record=None):
    """An executor that performs the real side effect's crash point: it is
    only ever invoked by ``EnforcementCoordinator.enforce()`` AFTER durable
    dispatch ownership (step f) has been committed, so killing the process
    right here genuinely reproduces "the gateway process died exactly as
    (or immediately after) it started actuating the operation, with the
    external outcome now ambiguous" -- not a crash at an arbitrary,
    unrepresentative point."""
    async def executor():
        if record is not None:
            record.append("executed-before-crash")
        os.kill(os.getpid(), signal.SIGKILL)
        return "unreachable"  # pragma: no cover
    return executor
