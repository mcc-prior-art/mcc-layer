"""Deployment-level pilot guarantees for the VoltAgent + MCC-Core pilot.

Two things are proven here that are specific to the *deployment*:

1. **Fail-closed without valid execution authority.** The pilot's execution
   authorization is consensus (evaluator trust) + gateway-minted single-use
   approvals — NOT the external-mandate path. This asserts that, with the pilot's
   trust posture (no ``MCC_TRUST_CONFIG`` — an empty external-mandate trust set),
   nothing executes without valid authority: no votes, forged votes, a forged
   approval mandate, and an untrusted external mandate all fail closed.

   This is why ``MCC_ENV=pilot``'s mandate-trust requirement is not applicable to
   this pilot, and why ``MCC_REDIS_NAMESPACE=pilot`` (Redis key isolation only)
   grants no authority: the two authorization mechanisms the pilot DOES use each
   have their own configured trust, and the mandate path is empty → reject-all.

2. **Bypass topology.** The pilot compose file is parsed to prove the network
   trust boundary is enforced by deployment, not documentation: the external
   service is unreachable by the agent, and the agent holds no operator key.

The cryptographic / replay / receipt failure modes themselves are covered by the
existing suites (test_mcc_core, test_consensus_enforcement,
test_governed_executor_pilot, test_voltagent_quorum, and the TypeScript suite);
this file adds the pilot-specific deployment assertions without duplicating them.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

from pilot.client import MCCGatewayClient  # noqa: E402
from pilot_notify import recorded_receipts, reset_receipts  # noqa: E402

from tests._notify_harness import (  # noqa: E402
    API_KEY,
    OPERATOR_KEY,
    NotifyPilotHarness,
    _free_port,
    agent_key,
)
from integrations.voltagent.mcc_side.evaluator_quorum import QuorumSettings, build_quorum_app  # noqa: E402
from examples._demo_server import DemoServer  # noqa: E402

COMPOSE = ROOT / "docker-compose.pilot-voltagent.yml"
ENV_EXAMPLE = ROOT / ".env.pilot.example"


# --------------------------------------------------------------------------- #
# 1. Fail-closed without valid execution authority.                           #
#                                                                             #
# NotifyPilotHarness builds the gateway with the pilot's trust posture: an     #
# empty external-mandate trust set (no MCC_TRUST_CONFIG) plus the runtime       #
# approver issuer and the evaluator consensus trust.                           #
# --------------------------------------------------------------------------- #

@pytest.fixture()
def stack():
    reset_receipts()
    hz = NotifyPilotHarness()
    q_settings = QuorumSettings({"MCC_QUORUM_GATEWAY_URL": hz.base_url, "MCC_GATEWAY_API_KEY": API_KEY})
    q_app = build_quorum_app(hz.evaluators, q_settings)
    q_port = _free_port()
    q_server = DemoServer(q_app, q_port)
    q_server.start()
    client = MCCGatewayClient(hz.base_url, api_key=API_KEY, operator_key=OPERATOR_KEY)
    try:
        yield hz, client, f"http://127.0.0.1:{q_port}"
    finally:
        q_server.stop()
        hz.close()


def _ctx(corr):
    return {"recipient": "customer-1", "message": "hi", "priority": 2, "channel": "email",
            "correlation_id": corr}


def test_consensus_without_votes_fails_closed(stack):
    hz, client, _ = stack
    d = client.propose(identity="agent/notify-bot", action="send_notification", resource_id="crm",
                       actor_id="agent/notify-bot", context=_ctx("corr-noauth"))
    assert d.decision.value == "ALLOW"
    ch = client.issue_challenge(actor="agent/notify-bot", action="send_notification",
                                resource="crm", context=d.forward_context)
    out = client.execute_with_consensus(votes=[], actor="agent/notify-bot",
                                        action="send_notification", resource="crm",
                                        context=d.forward_context, nonce=ch["nonce"],
                                        challenge_id=ch["challenge_id"])
    assert not out.executed
    assert recorded_receipts() == []


def test_consensus_with_forged_votes_fails_closed(stack):
    hz, client, _ = stack
    d = client.propose(identity="agent/notify-bot", action="send_notification", resource_id="crm",
                       actor_id="agent/notify-bot", context=_ctx("corr-forged"))
    ch = client.issue_challenge(actor="agent/notify-bot", action="send_notification",
                                resource="crm", context=d.forward_context)
    forged = [{"evaluator_id": "eval-0", "verdict": "ALLOW", "sig": "not-a-real-signature"}]
    out = client.execute_with_consensus(votes=forged, actor="agent/notify-bot",
                                        action="send_notification", resource="crm",
                                        context=d.forward_context, nonce=ch["nonce"],
                                        challenge_id=ch["challenge_id"])
    assert not out.executed
    assert recorded_receipts() == []


def test_forged_approval_mandate_fails_closed(stack):
    hz, _, _ = stack
    # V05 (part 2): agent/unknown presents its OWN credential, so the forged
    # mandate -- not the per-agent identity check -- is what blocks execution.
    client = MCCGatewayClient(hz.base_url, api_key=agent_key("agent/unknown"),
                              operator_key=OPERATOR_KEY)
    d = client.propose(identity="agent/unknown", action="send_notification", resource_id="crm",
                       actor_id="agent/unknown", context=_ctx("corr-escf"))
    assert d.decision.value == "ESCALATE"
    appr = client.request_approval(actor="agent/unknown", action="send_notification", resource="crm")
    # Execute with a forged (unsigned) mandate instead of an operator-granted one.
    out = client.execute_with_approval(
        appr["request_id"], mandate={"forged": True, "approval_id": appr["request_id"]},
        actor="agent/unknown", action="send_notification", resource="crm",
        context=_ctx("corr-escf"))
    assert not out.executed
    assert recorded_receipts() == []


def test_untrusted_external_mandate_rejected(stack):
    """The pilot has no MCC_TRUST_CONFIG, so the external-mandate path trusts no
    issuer: any presented mandate is rejected (strictly fail-closed)."""
    hz, _, _ = stack
    # V05 (part 2): presented with agent/notify-bot's OWN credential, so the
    # untrusted issuer -- not the per-agent identity check -- blocks it.
    client = MCCGatewayClient(hz.base_url, api_key=agent_key("agent/notify-bot"),
                              operator_key=OPERATOR_KEY)
    out = client.execute_with_mandate(
        mandate={"issuer": "whoever", "subject": "agent/notify-bot", "sig": "x"},
        actor="agent/notify-bot", action="send_notification", resource="crm",
        context=_ctx("corr-mand"))
    assert not out.executed
    assert recorded_receipts() == []


# --------------------------------------------------------------------------- #
# 2. Bypass topology — enforced by the deployment, not documentation.          #
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def _networks(service) -> set:
    nets = service.get("networks", [])
    return set(nets) if isinstance(nets, list) else set(nets.keys())


def test_agent_has_no_network_path_to_external_service(compose):
    services = compose["services"]
    agent_nets = _networks(services["voltagent-agent"])
    external_nets = _networks(services["external-service"])
    # The agent and the external service must share NO network.
    assert agent_nets.isdisjoint(external_nets), (
        f"agent nets {agent_nets} must not overlap external-service nets {external_nets}")
    # And the external service is not exposed on the agent's edge network.
    assert "agent_edge" not in external_nets


def test_only_the_gateway_bridges_the_two_networks(compose):
    services = compose["services"]
    # The gateway (governed executor) is the only service on BOTH networks.
    bridged = {name for name, svc in services.items()
               if {"agent_edge", "gov_internal"}.issubset(_networks(svc))}
    assert "mcc-gateway" in bridged
    assert "external-service" not in bridged
    assert "voltagent-agent" not in bridged


def test_agent_service_holds_no_operator_key(compose):
    agent = compose["services"]["voltagent-agent"]
    env = agent.get("environment", {}) or {}
    if isinstance(env, list):
        env = dict(e.split("=", 1) for e in env if "=" in e)
    assert "MCC_GATEWAY_OPERATOR_API_KEY" not in env, "agent must not be given the operator key inline"
    # No external-service endpoint is handed to the agent either.
    assert "MCC_UPSTREAM_BASE" not in env


def test_pilot_profile_does_not_disable_governance(compose):
    gw = compose["services"]["mcc-gateway"]
    env = gw.get("environment", {}) or {}
    if isinstance(env, list):
        env = dict(e.split("=", 1) for e in env if "=" in e)
    # Enforcing mode + Redis-backed (fail-closed) state — never observe/in-memory.
    assert env.get("MCC_GATEWAY_MODE") == "inline"
    for backend in ("MCC_NONCE_BACKEND", "MCC_IDEMPOTENCY_BACKEND", "MCC_APPROVAL_BACKEND"):
        assert env.get(backend) == "redis", f"{backend} must be redis (fail-closed) in the pilot"


DOCKERFILE_MCC = ROOT / "integrations" / "voltagent" / "docker" / "Dockerfile.mcc"
DOCKERFILE_AGENT = ROOT / "integrations" / "voltagent" / "docker" / "Dockerfile.agent"
SHARED_GID = "10990"


def test_pilot_state_uses_least_privilege_shared_group_not_world_writable():
    """The shared ESCALATE-state volume must be least-privilege: a fixed shared
    group both non-root services join, mode 2770 (setgid, group-only) — NEVER
    world-writable. An unrelated user (not in the shared group) gets no access."""
    mcc = DOCKERFILE_MCC.read_text(encoding="utf-8")
    agent = DOCKERFILE_AGENT.read_text(encoding="utf-8")

    # Same fixed shared GID in both images (GIDs, not names, cross containers).
    for text, who in ((mcc, "gateway"), (agent, "agent")):
        assert f"groupadd -g {SHARED_GID} mcc-shared" in text, f"{who}: shared group GID missing"
        assert "chmod 2770 /pilot-state" in text, f"{who}: /pilot-state must be 2770 (setgid, group-only)"
        # Never world-writable / world-accessible.
        assert "0777" not in text and "chmod 777" not in text, f"{who}: /pilot-state must not be world-writable"
        assert "o+w" not in text, f"{who}: /pilot-state must not grant other-write"

    # Each service user is a member of the shared group.
    assert "usermod -aG mcc-shared mcc" in mcc, "gateway user 'mcc' not in the shared group"
    assert "usermod -aG mcc-shared node" in agent, "agent user 'node' not in the shared group"

    # 2770 = rwx for owner + group, nothing for others: exactly the two intended
    # services (in mcc-shared) can access it; an unrelated user cannot.
    assert oct(0o2770) == "0o2770"


def _fork_as(uid: int, gids: list, action) -> int:
    """Run ``action()`` in a child process dropped to (uid, primary gid=gids[0],
    supplementary=gids). Returns the child exit code: 0 ok, 3 PermissionError,
    4 other error. Requires root (to switch uid/gid)."""
    pid = os.fork()
    if pid == 0:  # child
        try:
            os.setgroups(gids)
            os.setgid(gids[0])
            os.setuid(uid)
            action()
            os._exit(0)
        except PermissionError:
            os._exit(3)
        except Exception:  # noqa: BLE001
            os._exit(4)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status)


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to exercise multi-user access")
def test_pilot_state_shared_group_runtime_access():
    """Prove the 2770 setgid shared-group model at runtime: only members of the
    shared group can create/read/unlink escalation.json; an unrelated user cannot
    write — matching the gateway (mcc) + agent (node) + operator (mcc) topology."""
    import shutil
    import stat as _stat
    import tempfile

    shared, unrelated = 10990, 10991
    member_agent, member_operator, outsider = 4002, 4003, 4001
    # A base under /tmp (world-traversable), made o+x so the dropped-privilege
    # children can traverse INTO it — but NOT o+w — so the test isolates the
    # /pilot-state group permissions rather than the parent chain.
    base = tempfile.mkdtemp(dir="/tmp", prefix="pilot-state-perm-")
    os.chmod(base, 0o755)
    try:
        d = os.path.join(base, "pilot-state")
        os.mkdir(d)
        os.chown(d, 0, shared)          # root:mcc-shared, like the gateway-owned volume
        os.chmod(d, 0o2770)             # setgid + group rwx, NOTHING for others
        mode = _stat.S_IMODE(os.stat(d).st_mode)
        assert mode & 0o007 == 0 and mode & _stat.S_ISGID  # no world access; setgid

        state = os.path.join(d, "escalation.json")

        def _write():
            with open(state, "w") as fh:
                fh.write("{}")

        # (2) An unrelated user (not in the shared group) CANNOT write.
        assert _fork_as(outsider, [unrelated], _write) == 3
        assert not os.path.exists(state)

        # (1a) The agent (a shared-group member) CAN create the state file, and
        # setgid makes it inherit the shared group so the operator can act on it.
        assert _fork_as(member_agent, [shared], _write) == 0
        assert os.stat(state).st_gid == shared

        # (1b) The operator (another shared-group member) can read AND unlink it
        # (consume-on-approve), without anyone being granted world access.
        def _read_and_unlink():
            with open(state) as fh:
                fh.read()
            os.unlink(state)

        assert _fork_as(member_operator, [shared], _read_and_unlink) == 0
        assert not os.path.exists(state)
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_env_example_has_no_secrets_and_is_fail_closed():
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    # The template must not disable governance and must default to the offline model.
    assert "MCC_GATEWAY_MODE=inline" in text
    assert "MCC_VOLTAGENT_MODEL_PROVIDER=deterministic" in text
    # No real-looking secret values (placeholders only).
    assert "sk-" not in text.replace("# OPENAI_API_KEY", "")
