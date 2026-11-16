"""Workstream E System-Under-Test: two actuator instances sharing one real
Redis backend (PR #71).

Boots a genuine ``redis-server`` subprocess plus TWO independent
``egress_proxy`` actuator subprocesses (distinct OS processes, distinct
ports), both configured with ``MCC_NONCE_BACKEND=redis`` /
``MCC_CHALLENGE_BACKEND=redis`` pointed at the SAME Redis instance -- the
same cross-instance nonce/challenge sharing a real multi-replica deployment
would use behind a load balancer. This lets ``assurance/tests/
test_replay_resistance.py`` prove replay rejection is enforced by the
SHARED backend, not merely by one process's own local memory.

Scope, stated honestly (see ``docs/ASSUMPTIONS_AND_LIMITS.md``): this is
single-HOST, single-Redis-node replay resistance across two OS processes --
not a multi-node cluster, and not Redis Sentinel/Cluster failover (both
require infrastructure -- Docker image pulls, multiple hosts -- unavailable
in this environment). It DOES now include a genuine, host-local network
partition (``partition_from_redis()``/``heal_partition()``, an ``iptables``
DROP rule against the shared Redis port) in addition to process-kill
(``kill_redis()``) -- two independent fault-injection mechanisms against the
same shared backend, not a substitute for a real inter-host partition. This
module proves the property that is available: two independent processes
sharing one Redis instance cannot be tricked into double-honoring a nonce
or challenge, and the actuator fails closed whether that shared backend
becomes unreachable because the process died or because the network path to
it went dark, and recovers once the path heals.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from assurance.sut.harness import (
    FAR_FUTURE,
    REPO_ROOT,
    _Process,
    _wait_ready,
    actuator_agent_key,
    free_port,
    write_actuator_agent_registry,
)

# ``iptables`` requires CAP_NET_ADMIN/CAP_NET_RAW. This process runs as root
# in some environments (this session's sandbox) and as an unprivileged user
# with passwordless sudo in others (GitHub Actions' ubuntu-latest runners,
# which already use ``sudo apt-get install`` elsewhere in this same
# workflow) -- prepend ``sudo -n`` only when not already root (see
# ``assurance/sut/network_segmentation.py``'s identical pattern and rationale).
_PRIV: List[str] = [] if os.geteuid() == 0 else ["sudo", "-n"]


class RedisUnavailableError(RuntimeError):
    """The dedicated test Redis instance did not come up in time."""


def _start_redis(port: int) -> subprocess.Popen:
    proc = subprocess.Popen(
        ["redis-server", "--port", str(port), "--daemonize", "no", "--save", "", "--appendonly", "no"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 15.0
    while time.time() < deadline:
        try:
            r = subprocess.run(["redis-cli", "-p", str(port), "ping"], capture_output=True, text=True, timeout=2.0)
            if r.stdout.strip() == "PONG":
                return proc
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.1)
    proc.terminate()
    raise RedisUnavailableError(f"redis-server on port {port} did not become ready in time")


@dataclass
class ReplayResistanceCluster:
    """Two actuator instances, one shared Redis, one shared notify sink."""

    actuator_a_url: str
    actuator_b_url: str
    notify_url: str
    actuator_api_key: str
    policy_hash: str
    redis_port: int
    _tmpdir: str
    _procs: List[_Process] = field(default_factory=list)
    _redis_proc: Optional[subprocess.Popen] = None
    _evaluators: List[Any] = field(default_factory=list)

    def votes(self, *, payload: Dict[str, Any], nonce: str, actor: str = "agent/egress",
               resource: str = "notify", verdict: str = "ALLOW") -> List[Dict[str, Any]]:
        from mcc_core.consensus import issue_vote

        return [
            issue_vote(e, evaluator_id=e.kid, verdict=verdict, action="http.request", payload=payload,
                       actor=actor, not_before=0, not_after=FAR_FUTURE, resource=resource,
                       policy_hash=self.policy_hash, nonce=nonce)
            for e in self._evaluators
        ]

    def canonical_action(self, request: Dict[str, Any]) -> Dict[str, Any]:
        from egress_proxy.canonical_action import build_canonical_action

        return build_canonical_action(method=request["method"], url=request["url"],
                                       headers=request["headers"], body=request["body"])

    def propose(self, *, actuator_url: str, transaction_id: str, idempotency_key: str,
                actor: str = "agent/egress", resource: str = "notify") -> Dict[str, Any]:
        body = {"recipient": "ops", "message": "assurance-replay-probe", "correlation_id": transaction_id}
        req = {"method": "POST", "url": f"{self.notify_url}/send_notification", "headers": {}, "body": body,
               "actor": actor, "resource": resource, "transaction_id": transaction_id,
               "idempotency_key": idempotency_key}
        r = httpx.post(f"{actuator_url}/v1/http/execute", headers={"x-api-key": actuator_agent_key(self.actuator_api_key, req.get("actor"))},
                        json=req, timeout=10.0)
        payload = r.json()
        payload["_request"] = req
        payload["_status_code"] = r.status_code
        return payload

    def submit(self, *, actuator_url: str, proposal: Dict[str, Any],
               votes: List[Dict[str, Any]]) -> Dict[str, Any]:
        req = dict(proposal["_request"])
        req["challenge_id"] = proposal["challenge_id"]
        req["votes"] = votes
        r = httpx.post(f"{actuator_url}/v1/http/execute", headers={"x-api-key": actuator_agent_key(self.actuator_api_key, req.get("actor"))},
                        json=req, timeout=10.0)
        payload = r.json()
        payload["_status_code"] = r.status_code
        return payload

    def notification_receipt_count(self) -> int:
        return httpx.get(f"{self.notify_url}/receipts", timeout=5.0).json()["count"]

    def kill_redis(self) -> None:
        """Fault injection: the shared backend becomes unreachable because
        the process dies."""
        if self._redis_proc is not None:
            self._redis_proc.terminate()
            try:
                self._redis_proc.wait(timeout=10)
            except Exception:  # noqa: BLE001
                self._redis_proc.kill()

    def partition_from_redis(self) -> None:
        """Fault injection: the shared backend becomes unreachable because
        the NETWORK path to it is severed, not because the process dies --
        a genuine (host-local) network partition, distinct from
        ``kill_redis()``. Implemented as a host ``iptables`` rule dropping
        outbound TCP packets to the Redis port; this environment has no
        multi-host network to partition (see ``docs/ASSUMPTIONS_AND_LIMITS.md``),
        so this is the strongest partition simulation available: the
        redis-server process stays alive and healthy throughout, only the
        path to it goes dark, exercising the client's connect/read timeout
        path (see ``src/mcc_core/redis_client.py``'s
        ``socket_connect_timeout``/``socket_timeout``) rather than an
        immediate connection-refused error. Always pair with
        ``heal_partition()`` in a ``finally`` block -- this is a host-wide
        firewall rule, not scoped to a network namespace."""
        subprocess.run(
            _PRIV + ["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", str(self.redis_port), "-j", "DROP"],
            check=True, capture_output=True,
        )

    def heal_partition(self) -> None:
        """Reverse ``partition_from_redis()``. Safe to call even if no
        partition rule is currently installed (rule deletion is attempted
        at most once; failure is not raised so cleanup in a ``finally``
        block can never itself mask the original test failure)."""
        subprocess.run(
            _PRIV + ["iptables", "-D", "OUTPUT", "-p", "tcp", "--dport", str(self.redis_port), "-j", "DROP"],
            check=False, capture_output=True,
        )

    def close(self) -> None:
        for p in self._procs:
            p.stop()
        self.heal_partition()
        self.kill_redis()

    def __enter__(self) -> "ReplayResistanceCluster":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def build_replay_resistance_cluster(*, n_evaluators: int = 3, threshold: int = 3) -> ReplayResistanceCluster:
    from mcc_core.signing import SigningKey

    tmpdir = tempfile.mkdtemp(prefix="mcc-assurance-replay-")
    env_base = dict(os.environ)
    env_base["PYTHONPATH"] = os.pathsep.join(
        filter(None, [str(REPO_ROOT / "src"), str(REPO_ROOT), str(REPO_ROOT / "sdk" / "python" / "src"),
                       env_base.get("PYTHONPATH")])
    )

    redis_port = free_port()
    redis_proc = _start_redis(redis_port)
    redis_url = f"redis://127.0.0.1:{redis_port}/0"

    notify_port = free_port()
    notify_proc = subprocess.Popen(
        [sys.executable, "-m", "assurance.sut.notify_process", "--port", str(notify_port)],
        cwd=str(REPO_ROOT), env=env_base,
    )
    notify_url = f"http://127.0.0.1:{notify_port}"
    _wait_ready(f"{notify_url}/health")

    evaluators = [SigningKey.generate(f"assurance-replay-eval-{i}") for i in range(n_evaluators)]
    trust = {"issuers": [
        {"issuer_id": e.kid, "enabled": True,
         "keys": [{"kid": e.kid, "public_key_b64": e.public_key_b64(), "not_after": None}]}
        for e in evaluators
    ]}
    trust_path = os.path.join(tmpdir, "trust.json")
    with open(trust_path, "w") as f:
        json.dump(trust, f)

    procs: List[_Process] = [_Process(notify_proc, notify_port)]
    actuator_urls = []
    actuator_env = dict(env_base)
    actuator_env["MCC_ASSURANCE_ACTUATOR_API_KEY"] = "assurance-replay-actuator-key"
    actuator_env["MCC_ASSURANCE_AGENT_CREDENTIALS"] = write_actuator_agent_registry(
        tmpdir, "assurance-replay-actuator-key")
    actuator_env["MCC_ASSURANCE_OPERATOR_KEY"] = "assurance-replay-operator-key"
    actuator_env["MCC_ASSURANCE_THRESHOLD"] = str(threshold)
    for label in ("a", "b"):
        port = free_port()
        audit_path = os.path.join(tmpdir, f"actuator-{label}-audit.jsonl")
        proc = subprocess.Popen(
            [sys.executable, "-m", "assurance.sut.actuator_process", "--port", str(port),
             "--notify-base", notify_url, "--trust-config", trust_path, "--audit-log", audit_path,
             "--redis-url", redis_url],
            cwd=str(REPO_ROOT), env=actuator_env,
        )
        procs.append(_Process(proc, port))
        url = f"http://127.0.0.1:{port}"
        _wait_ready(f"{url}/ready")
        actuator_urls.append(url)

    health = httpx.get(f"{actuator_urls[0]}/health", timeout=5.0).json()
    policy_hash = health.get("policy_hash") or ""

    return ReplayResistanceCluster(
        actuator_a_url=actuator_urls[0], actuator_b_url=actuator_urls[1], notify_url=notify_url,
        actuator_api_key="assurance-replay-actuator-key", policy_hash=policy_hash, redis_port=redis_port,
        _tmpdir=tmpdir, _procs=procs, _redis_proc=redis_proc, _evaluators=evaluators,
    )
