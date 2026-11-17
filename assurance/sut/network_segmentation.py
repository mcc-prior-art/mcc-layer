"""Workstream A extension: a genuinely network-segmented deployment (PR #71).

``docs/EXCLUSIVE_EXECUTION_PATH.md``'s A6 attack proves the actuator's OWN
application-level SSRF/allowlist works, but explicitly states a limitation:
it "does NOT prove that an attacker with raw network access to the notify
sink (bypassing the actuator's process entirely) could not reach it
directly -- that is a network-segmentation property this single-host test
cannot observe (there is no real network boundary between processes on one
machine)." This module closes that gap for real, using genuine Linux
network namespaces and veth links (``ip netns``/``ip link``) -- not Docker
(this environment's Docker Hub pulls are policy-blocked, see
``docs/ASSUMPTIONS_AND_LIMITS.md``), but a real kernel-enforced network
boundary all the same.

Topology (three network namespaces / routing domains):

    host (default netns)  <--veth-->  actuator-netns  <--veth-->  upstream-netns
    "legitimate caller"                "the actuator"              "the protected
     + this test's attacker                                        upstream sink"

* The ACTUATOR (``egress_proxy``) runs inside ``actuator-netns``, with ONE
  veth leg reachable from the host (its inbound HTTP API) and a SECOND,
  separate veth leg into ``upstream-netns`` (its only path to the notify
  sink).
* The UPSTREAM (``pilot_notify``) runs inside ``upstream-netns``, which has
  a veth link ONLY to ``actuator-netns`` -- no interface, no route, and no
  default gateway pointing at the host's default namespace at all.
* The HOST (default netns, where this test process and an "attacker"
  process both run) can reach the actuator's inbound API (that link
  exists), but has **no route whatsoever** to the upstream's private
  subnet -- the kernel itself has no interface for that traffic, so a
  direct connection attempt fails at the network layer (`ConnectError`),
  not because of an application-level allow/deny decision.

This proves the stronger claim A6 explicitly disclaimed: it is not merely
that the actuator's own code chooses not to forward disallowed
destinations -- an attacker on the same host, with a real HTTP client and
no cooperation from the actuator's code at all, cannot open a TCP
connection to the protected upstream sink. The boundary is enforced by the
kernel's routing tables, independent of any governance decision.

Honest limits, stated up front (see ``docs/ASSUMPTIONS_AND_LIMITS.md``):
this is still one physical machine -- a process with `CAP_SYS_ADMIN` (e.g.
another root process, or this same test's own teardown code) COULD join
``upstream-netns`` via ``ip netns exec`` and reach the sink directly; this
is a genuine network-layer boundary for an unprivileged or
differently-privileged attacker process, not a claim that no process
anywhere on the host could ever reach the upstream namespace. It also does
not model a real multi-host network (see Workstream E's equivalent,
narrower disclaimer for the analogous limitation there).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

from assurance.sut.harness import (
    FAR_FUTURE,
    REPO_ROOT,
    actuator_agent_key,
    free_port,
    write_actuator_agent_registry,
)

HOST_ACTUATOR_SUBNET = "10.201.0.0/30"
ACTUATOR_UPSTREAM_SUBNET = "10.201.1.0/30"
HOST_IP = "10.201.0.1"
ACTUATOR_HOST_SIDE_IP = "10.201.0.2"
ACTUATOR_UPSTREAM_SIDE_IP = "10.201.1.1"
UPSTREAM_IP = "10.201.1.2"

# ``ip netns``/``ip link`` require CAP_NET_ADMIN. This process runs as root in
# some environments (this session's sandbox) and as an unprivileged user with
# passwordless sudo in others (GitHub Actions' ubuntu-latest runners, which
# already use ``sudo apt-get install`` elsewhere in this same workflow) --
# prepend ``sudo -n`` only when not already root, and fail fast (``-n``,
# non-interactive) rather than hang on a password prompt if sudo isn't
# actually passwordless.
_PRIV: List[str] = [] if os.geteuid() == 0 else ["sudo", "-n"]


def _ip(*args: str) -> List[str]:
    return _PRIV + ["ip", *args]


class NetnsUnavailableError(RuntimeError):
    """``ip netns``/veth setup failed -- this environment cannot build the
    segmented topology (e.g. no ``CAP_NET_ADMIN``, no ``iproute2``, no
    passwordless ``sudo``)."""


def _run(cmd: List[str], *, timeout: float = 10.0) -> None:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise NetnsUnavailableError(f"{' '.join(cmd)} failed: {r.stderr.strip()}")


def _run_ok(cmd: List[str], *, timeout: float = 10.0) -> bool:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _wait_ready_curl(*, netns: Optional[str], url: str, timeout: float = 30.0) -> None:
    """Poll readiness with ``curl`` (optionally inside a network namespace via
    ``ip netns exec``) -- ``httpx`` in THIS process cannot reach addresses
    that only exist inside another namespace, so waiting must happen from
    inside that namespace too."""
    cmd = (_ip("netns", "exec", netns) if netns else []) + [
        "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "2", url,
    ]
    deadline = time.time() + timeout
    last: Optional[str] = None
    while time.time() < deadline:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=3.0)
            if r.returncode == 0 and r.stdout.strip() and r.stdout.strip()[0] in "234":
                return
            last = f"rc={r.returncode} stdout={r.stdout!r} stderr={r.stderr!r}"
        except Exception as e:  # noqa: BLE001
            last = str(e)
        time.sleep(0.2)
    raise RuntimeError(f"{url} (netns={netns}) did not become ready in time: {last}")


@dataclass
class SegmentedTopology:
    """A real, three-namespace network topology: host -> actuator-netns ->
    upstream-netns, with the upstream reachable ONLY through the actuator's
    namespace, never directly from the host."""

    actuator_url: str          # reachable from the HOST default namespace
    actuator_api_key: str
    policy_hash: str
    upstream_private_url: str  # NOT reachable from the host -- for the oracle/bypass tests only
    ns_actuator: str
    ns_upstream: str
    veth_host_side: str
    _tmpdir: str
    _actuator_proc: Optional[subprocess.Popen] = None
    _notify_proc: Optional[subprocess.Popen] = None
    _evaluators: List[Any] = field(default_factory=list)

    # -- governed-flow helpers, matching the shape of the other SUT clusters --

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

    def propose(self, *, transaction_id: Optional[str] = None) -> Dict[str, Any]:
        tx = transaction_id or str(uuid.uuid4())
        body = {"recipient": "ops", "message": "network-segmentation-probe", "correlation_id": tx}
        req = {"method": "POST", "url": f"{self.upstream_private_url}/send_notification", "headers": {},
               "body": body, "actor": "agent/egress", "resource": "notify", "transaction_id": tx,
               "idempotency_key": tx}
        r = httpx.post(f"{self.actuator_url}/v1/http/execute", headers={"x-api-key": actuator_agent_key(self.actuator_api_key, req.get("actor"))},
                        json=req, timeout=10.0)
        payload = r.json()
        payload["_request"] = req
        payload["_status_code"] = r.status_code
        return payload

    def submit(self, *, proposal: Dict[str, Any], votes: List[Dict[str, Any]]) -> Dict[str, Any]:
        req = dict(proposal["_request"])
        req["challenge_id"] = proposal["challenge_id"]
        req["votes"] = votes
        r = httpx.post(f"{self.actuator_url}/v1/http/execute", headers={"x-api-key": actuator_agent_key(self.actuator_api_key, req.get("actor"))},
                        json=req, timeout=10.0)
        payload = r.json()
        payload["_status_code"] = r.status_code
        return payload

    # -- the "trusted auditor" oracle: reads the upstream's own receipt count
    #    from INSIDE its namespace, the way an operator with legitimate
    #    exec-into-the-deployment access could, but a network attacker could not

    def receipt_count_privileged(self) -> int:
        r = subprocess.run(
            _ip("netns", "exec", self.ns_upstream, "curl", "-sS", "--max-time", "3",
                f"{self.upstream_private_url}/receipts"),
            capture_output=True, text=True, timeout=5.0,
        )
        if r.returncode != 0:
            raise RuntimeError(f"privileged receipt check failed: {r.stderr}")
        return json.loads(r.stdout)["count"]

    # -- the bypass-resistance proof --

    def attempt_direct_bypass_from_host(self) -> Optional[str]:
        """Attempt to reach the protected upstream directly from the HOST's
        default network namespace -- no actuator, no governance, no
        cooperation from any MCC-Core code at all. Returns the exception's
        class name (e.g. ``"ConnectError"``) if the connection genuinely
        failed at the network layer, or ``None`` if it somehow succeeded
        (which would mean the segmentation boundary is NOT enforced)."""
        try:
            httpx.get(f"{self.upstream_private_url}/receipts", timeout=2.0)
            return None
        except httpx.ConnectError as e:
            return type(e).__name__
        except httpx.ConnectTimeout as e:
            return type(e).__name__

    def close(self) -> None:
        for proc in (self._actuator_proc, self._notify_proc):
            if proc is None:
                continue
            try:
                proc.terminate()
                proc.wait(timeout=10)
            except Exception:  # noqa: BLE001
                try:
                    proc.kill()
                except Exception:  # noqa: BLE001
                    pass
        # Deleting the namespaces also tears down every veth leg that lives
        # inside them; the host-side leg is deleted explicitly since one end
        # of a veth pair always survives in whichever namespace was NOT removed.
        _run_ok(_ip("netns", "del", self.ns_actuator))
        _run_ok(_ip("netns", "del", self.ns_upstream))
        _run_ok(_ip("link", "del", self.veth_host_side))

    def __enter__(self) -> "SegmentedTopology":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _check_prereqs() -> None:
    if not _run_ok(["ip", "-V"]):
        raise NetnsUnavailableError("iproute2 ('ip') is not available in this environment")
    if _PRIV and not _run_ok(["sudo", "-n", "true"]):
        raise NetnsUnavailableError(
            "not running as root and passwordless sudo is unavailable -- "
            "CAP_NET_ADMIN cannot be obtained to build a genuine network-segmented topology"
        )
    # A throwaway create/delete proves CAP_NET_ADMIN is genuinely available,
    # not merely that the binary exists -- fail closed with a clear reason
    # rather than a confusing failure three steps into real provisioning.
    probe_ns = f"mcc-assurance-probe-{uuid.uuid4().hex[:8]}"
    if not _run_ok(_ip("netns", "add", probe_ns)):
        raise NetnsUnavailableError(
            "'ip netns add' failed -- CAP_NET_ADMIN (or root) is required to build "
            "a genuine network-segmented topology; this environment/user cannot"
        )
    _run_ok(_ip("netns", "del", probe_ns))


def build_segmented_topology(*, n_evaluators: int = 3, threshold: int = 3) -> SegmentedTopology:
    """Boots the real, three-namespace topology described in this module's
    docstring. Raises :class:`NetnsUnavailableError` (fail-closed, callers
    should ``pytest.skip`` on it, matching this baseline's existing
    environment-gating convention for e.g. Workstream K's framework
    adapters) if this environment cannot build real network namespaces."""
    _check_prereqs()

    suffix = uuid.uuid4().hex[:6]
    ns_actuator = f"mcc-act-{suffix}"
    ns_upstream = f"mcc-up-{suffix}"
    # Linux interface names are capped at 15 chars (IFNAMSIZ=16 incl. NUL).
    veth_host = f"veth-h-{suffix}"     # 13 chars
    veth_act_h = f"veth-ah-{suffix}"   # 14 chars
    veth_act_up = f"veth-au-{suffix}"  # 14 chars
    veth_up_act = f"veth-ua-{suffix}"  # 14 chars

    created: List[str] = []
    try:
        _run(_ip("netns", "add", ns_actuator)); created.append("ns_actuator")
        _run(_ip("netns", "add", ns_upstream)); created.append("ns_upstream")

        _run(_ip("link", "add", veth_host, "type", "veth", "peer", "name", veth_act_h))
        _run(_ip("link", "add", veth_act_up, "type", "veth", "peer", "name", veth_up_act))
        _run(_ip("link", "set", veth_act_h, "netns", ns_actuator))
        _run(_ip("link", "set", veth_act_up, "netns", ns_actuator))
        _run(_ip("link", "set", veth_up_act, "netns", ns_upstream))

        # host <-> actuator-netns
        _run(_ip("addr", "add", f"{HOST_IP}/30", "dev", veth_host))
        _run(_ip("link", "set", veth_host, "up"))
        _run(_ip("netns", "exec", ns_actuator, "ip", "addr", "add", f"{ACTUATOR_HOST_SIDE_IP}/30", "dev", veth_act_h))
        _run(_ip("netns", "exec", ns_actuator, "ip", "link", "set", veth_act_h, "up"))

        # actuator-netns <-> upstream-netns
        _run(_ip("netns", "exec", ns_actuator, "ip", "addr", "add", f"{ACTUATOR_UPSTREAM_SIDE_IP}/30", "dev", veth_act_up))
        _run(_ip("netns", "exec", ns_actuator, "ip", "link", "set", veth_act_up, "up"))
        _run(_ip("netns", "exec", ns_upstream, "ip", "addr", "add", f"{UPSTREAM_IP}/30", "dev", veth_up_act))
        _run(_ip("netns", "exec", ns_upstream, "ip", "link", "set", veth_up_act, "up"))

        _run(_ip("netns", "exec", ns_actuator, "ip", "link", "set", "lo", "up"))
        _run(_ip("netns", "exec", ns_upstream, "ip", "link", "set", "lo", "up"))

        # The upstream namespace's ONLY route anywhere is through the
        # actuator's namespace -- deliberately no route back to the host's
        # default-namespace subnet at all, so this is not merely "unrouted
        # by convention," it is topologically absent.
        _run(_ip("netns", "exec", ns_upstream, "ip", "route", "add", "default", "via", ACTUATOR_UPSTREAM_SIDE_IP))

        pythonpath = os.pathsep.join(
            filter(None, [str(REPO_ROOT / "src"), str(REPO_ROOT), str(REPO_ROOT / "sdk" / "python" / "src"),
                           os.environ.get("PYTHONPATH")])
        )

        def _popen_in_netns(ns: str, argv: List[str], *, extra_env: Dict[str, str]) -> subprocess.Popen:
            # A ``sudo`` boundary (see ``_PRIV``) may reset the ambient
            # environment by policy, dropping PYTHONPATH/etc before they'd
            # reach the exec'd process -- forward the SPECIFIC vars needed
            # explicitly via ``env KEY=VALUE ...`` inside the privileged
            # command itself, which works regardless of sudoers' env_reset
            # setting (never the whole ``os.environ`` -- keeps secrets out
            # of the argv other host processes can observe via ``ps``).
            all_env = {"PYTHONPATH": pythonpath, **extra_env}
            assignments = [f"{k}={v}" for k, v in all_env.items()]
            cmd = _ip("netns", "exec", ns, "env", *assignments, *argv)
            return subprocess.Popen(cmd, cwd=str(REPO_ROOT))

        tmpdir = tempfile.mkdtemp(prefix="mcc-assurance-netseg-")
        upstream_port = free_port()
        actuator_port = free_port()

        notify_proc = _popen_in_netns(
            ns_upstream,
            [sys.executable, "-m", "assurance.sut.notify_process", "--port", str(upstream_port),
             "--host", UPSTREAM_IP],
            extra_env={},
        )
        upstream_private_url = f"http://{UPSTREAM_IP}:{upstream_port}"
        _wait_ready_curl(netns=ns_actuator, url=f"{upstream_private_url}/health")

        from mcc_core.signing import SigningKey

        evaluators = [SigningKey.generate(f"assurance-netseg-eval-{i}") for i in range(n_evaluators)]
        trust = {"issuers": [
            {"issuer_id": e.kid, "enabled": True,
             "keys": [{"kid": e.kid, "public_key_b64": e.public_key_b64(), "not_after": None}]}
            for e in evaluators
        ]}
        trust_path = os.path.join(tmpdir, "trust.json")
        with open(trust_path, "w") as f:
            json.dump(trust, f)
        audit_path = os.path.join(tmpdir, "actuator-audit.jsonl")

        actuator_proc = _popen_in_netns(
            ns_actuator,
            [sys.executable, "-m", "assurance.sut.actuator_process", "--port", str(actuator_port),
             "--host", ACTUATOR_HOST_SIDE_IP, "--notify-base", upstream_private_url,
             "--trust-config", trust_path, "--audit-log", audit_path,
             "--allowed-hosts", UPSTREAM_IP, "--allow-private"],
            extra_env={
                "MCC_ASSURANCE_ACTUATOR_API_KEY": "assurance-netseg-actuator-key",
                "MCC_ASSURANCE_AGENT_CREDENTIALS": write_actuator_agent_registry(
                    tmpdir, "assurance-netseg-actuator-key"),
                "MCC_ASSURANCE_OPERATOR_KEY": "assurance-netseg-operator-key",
                "MCC_ASSURANCE_THRESHOLD": str(threshold),
            },
        )
        actuator_url = f"http://{ACTUATOR_HOST_SIDE_IP}:{actuator_port}"
        _wait_ready_curl(netns=None, url=f"{actuator_url}/ready")

        health = httpx.get(f"{actuator_url}/health", timeout=5.0).json()
        policy_hash = health.get("policy_hash") or ""

        return SegmentedTopology(
            actuator_url=actuator_url, actuator_api_key="assurance-netseg-actuator-key",
            policy_hash=policy_hash, upstream_private_url=upstream_private_url,
            ns_actuator=ns_actuator, ns_upstream=ns_upstream, veth_host_side=veth_host,
            _tmpdir=tmpdir, _actuator_proc=actuator_proc, _notify_proc=notify_proc, _evaluators=evaluators,
        )
    except Exception:
        _run_ok(_ip("netns", "del", ns_actuator))
        _run_ok(_ip("netns", "del", ns_upstream))
        _run_ok(_ip("link", "del", veth_host))
        raise
