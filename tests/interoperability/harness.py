"""Shared interoperability harness (PR #48).

One reusable harness — not five copied suites. It stands up **one** real MCC Gateway
as an out-of-process server, exposes a common ``AdapterProof`` boundary that each
adapter implements, and runs the **same** seven governance scenarios against the
shared Gateway for every adapter. Framework-specific code stops at proposal
normalization; everything past submission is the one shared governance path.

The model or framework proposes. MCC decides. The gate enforces. The audit chain
records.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

import httpx

from mcc_core import ProfileRegistry, SigningKey, issue_vote

from examples._demo_server import DemoServer
import pilot_notify.service as notify_service
from pilot_notify import recorded_receipts, reset_receipts

ROOT = Path(__file__).resolve().parents[2]
FAR_FUTURE = 4_000_000_000
API_KEY = "demo-key"
OPERATOR_KEY = "op-key"

# V05 (part 2): the shared Gateway's identity routes (/mandates/execute,
# /approvals, /approvals/{id}/execute) require a registered per-agent
# credential. API_KEY stays the mount's shared tenant key (still valid on
# /evaluate, /consensus/*, /verify); each principal below gets its OWN key
# (SharedGovernedGateway.agent_key). Tests act as honest agents presenting
# their own credential; identity attacks live in test_v05_agent_identity_http.
GATEWAY_TENANT_ID = "pilot"
AGENT_PRINCIPALS = (
    "agent/notify-bot", "agent/egress", "agent/mandate-bot", "agent/the-real-holder",
    "agent/an-impostor", "agent/attestation-assurance-bot", "agent/checkpoint-bot",
    "agent/negative-control-bot", "agent/ops-bot", "agent/interop-wrong",
    "agent/pr6-pilot-test-partner",
)

CONTRACT_VERSION = "1.0"

# Scenario identifiers (the common suite every adapter runs).
SCENARIOS = ("ALLOW", "DENY", "REPLAY", "MISMATCH", "AUDIT",
             "GATEWAY_UNAVAILABLE", "INVALID_OR_EXPIRED")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


@dataclass
class CanonicalProposal:
    """The one canonical Integration Contract proposal shape all adapters emit."""

    actor_id: str
    action: str
    resource: str
    payload: Dict[str, Any]
    # A stable logical-operation identity for this proposal, generated here
    # (never by the gateway/coordinator -- Round 25 made this mandatory at
    # EnforcementCoordinator.enforce()). Fresh per proposal by default.
    idempotency_key: str = field(default_factory=lambda: f"interop-{uuid.uuid4().hex}")

    def hash(self) -> str:
        from mcc_core.signing import canonical_bytes, sha256_hex
        return sha256_hex(canonical_bytes(
            {"actor_id": self.actor_id, "action": self.action,
             "resource": self.resource, "payload": self.payload}))


@runtime_checkable
class AdapterProof(Protocol):
    """The common proof boundary each of the five adapters implements. Framework
    adapters exercise their native framework inside ``proposal_for`` and stop at
    normalization; the Generic HTTP adapter builds the proposal framework-neutrally.
    No adapter authorizes, executes, verifies, or mints decisions — that is all the
    shared governance path reached through ``submit`` over real HTTP."""

    adapter_name: str
    adapter_classification: str          # "REAL FRAMEWORK INTEGRATION" | "FRAMEWORK-NEUTRAL HTTP INTEGRATION"
    framework_name: str
    framework_distribution: Optional[str]
    framework_version: Optional[str]
    native_object_type: Optional[str]
    native_api_entrypoint: Optional[str]
    adapter_module: str
    adapter_version: str

    def framework_provenance(self) -> Dict[str, Any]: ...

    def capability_profile(self) -> Dict[str, Any]: ...

    def proposal_for(self, scenario: str) -> CanonicalProposal:
        """Originate a canonical proposal for a scenario. A framework adapter runs
        its native workflow here and normalizes; Generic HTTP builds it directly."""
        ...


# --------------------------------------------------------------------------- #
# Shared Gateway (real out-of-process server).                               #
# --------------------------------------------------------------------------- #

class SharedGovernedGateway:
    """One configured MCC Gateway server process shared by all adapters. Real
    loopback endpoint; every adapter connects with a real HTTP client. The harness
    plays the evaluators (holds their private keys) to mint consensus material, and
    runs the mock upstream in-process so the out-of-process Gateway calls it over
    loopback — exactly as a real deployment would."""

    def __init__(self, *, n_evaluators: int = 3, threshold: int = 3,
                 extra_env: Optional[Dict[str, str]] = None,
                 agent_principals=AGENT_PRINCIPALS) -> None:
        reset_receipts()
        self.profiles = ProfileRegistry.default_pilot()
        self._threshold = threshold
        self._extra_env = dict(extra_env or {})
        self._tmp = tempfile.mkdtemp(prefix="interop-")

        # Mock upstream (the governed side effect target) on a real loopback port.
        self.notify_port = _free_port()
        self.notify_base = f"http://127.0.0.1:{self.notify_port}"
        self._notify_server = DemoServer(notify_service.app, self.notify_port)
        self._notify_server.start()

        # Evaluator keys: PRIVATE stay here (to mint votes); PUBLIC go to the trust
        # config the out-of-process Gateway loads.
        self.evaluators = [SigningKey.generate(f"eval-{i}") for i in range(n_evaluators)]
        trust = {"issuers": [
            {"issuer_id": f"eval-{i}", "enabled": True,
             "keys": [{"kid": e.kid, "public_key_b64": e.public_key_b64(), "not_after": None}]}
            for i, e in enumerate(self.evaluators)]}
        self._trust_path = Path(self._tmp) / "consensus_trust.json"
        self._trust_path.write_text(json.dumps(trust))
        self._audit_path = str(Path(self._tmp) / "audit.jsonl")

        from tests._agent_credentials import write_registry_file
        self._agent_creds_path = write_registry_file(
            Path(self._tmp) / "agent_credentials.json", GATEWAY_TENANT_ID,
            {p: self.agent_key(p) for p in agent_principals})

        # Spawn the real Gateway subprocess and health-gate it.
        self.port = _free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._proc = self._spawn()
        self._await_ready()
        self.deployment_id = f"interop-gateway-{self.port}"
        self._identity = self._read_identity()
        self.policy_hash = self._identity["policy_hash"]

    @staticmethod
    def agent_key(principal_id: str) -> str:
        """The per-agent credential ``principal_id`` presents as X-API-Key on
        identity routes (registered only if listed in ``agent_principals``)."""
        from tests._agent_credentials import derived_agent_key
        return derived_agent_key(API_KEY, principal_id)

    def _spawn(self) -> subprocess.Popen:
        env = {
            "PYTHONPATH": f"{ROOT/'src'}:{ROOT/'sdk'/'python'/'src'}:{ROOT}",
            "PATH": __import__("os").environ.get("PATH", ""),
            "MCC_USE_OPA": "false",
            "MCC_GATEWAY_AUDIT_LOG_PATH": self._audit_path,
            "MCC_CONSENSUS_TRUST_CONFIG": str(self._trust_path),
            "MCC_CONSENSUS_THRESHOLD": str(self._threshold),
            "MCC_REQUIRE_CONSENSUS": "1",
            "MCC_REQUIRE_CHALLENGE": "1",
            "MCC_INTEROP_NOTIFY_BASE": self.notify_base,
            "MCC_INTEROP_API_KEY": API_KEY,
            "MCC_INTEROP_OPERATOR_KEY": OPERATOR_KEY,
            "MCC_AGENT_CREDENTIALS_CONFIG": self._agent_creds_path,
        }
        env.update(self._extra_env)
        return subprocess.Popen(
            [sys.executable, "-m", "tests.interoperability._gateway_process",
             "--port", str(self.port)],
            cwd=str(ROOT), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _await_ready(self, timeout: float = 30.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(f"gateway process exited early (rc={self._proc.returncode})")
            try:
                r = httpx.get(f"{self.base_url}/ready", timeout=1.0)
                if r.status_code == 200 and r.json().get("consensus_verifier"):
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        raise RuntimeError("gateway did not become ready in time")

    def _read_identity(self) -> Dict[str, Any]:
        r = httpx.get(f"{self.base_url}/health", headers={"x-api-key": API_KEY}, timeout=5.0)
        r.raise_for_status()
        return r.json()

    def identity(self) -> Dict[str, Any]:
        """The shared-instance provenance every adapter's evidence must reference."""
        return {
            "gateway_impl": self._identity["gateway_impl"],
            "gate_impl": self._identity["gate_impl"],
            "audit_impl": self._identity["audit_impl"],
            "deployment_id": self.deployment_id,
            "endpoint": self.base_url,
            "policy_hash": self.policy_hash,
            "signing_kid": self._identity["signing_kid"],
            "nonce_registry_impl": "mcc_core.nonce",
            "trust_set_id": f"consensus-{len(self.evaluators)}-of-{self._threshold}",
        }

    def votes(self, *, action: str, payload: Dict[str, Any], actor: str, nonce: str,
              resource: Optional[str], not_after: int = FAR_FUTURE,
              policy_hash: Optional[str] = None) -> List[Dict[str, Any]]:
        canonical = self.profiles.for_action(action).canonical_payload(dict(payload))
        return [issue_vote(e, evaluator_id=e.kid, verdict="ALLOW", action=action,
                           payload=canonical, actor=actor, not_before=0,
                           not_after=not_after, resource=resource,
                           policy_hash=policy_hash or self.policy_hash, nonce=nonce)
                for e in self.evaluators]

    def close(self) -> None:
        try:
            self._proc.terminate()
            self._proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            self._proc.kill()
        self._notify_server.stop()

    def __enter__(self) -> "SharedGovernedGateway":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# --------------------------------------------------------------------------- #
# The seven common governance scenarios (shared for every adapter).           #
# --------------------------------------------------------------------------- #

@dataclass
class ScenarioResult:
    scenario: str
    status: str                       # "PASS" | "FAIL"
    executed: bool
    verdict: Optional[str] = None
    decision_id: Optional[str] = None
    audit_ref: Optional[str] = None
    audit_chain_valid: Optional[bool] = None
    detail: str = ""
    proposal_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"scenario": self.scenario, "status": self.status,
                "executed": self.executed, "verdict": self.verdict,
                "decision_id": self.decision_id, "audit_ref": self.audit_ref,
                "audit_chain_valid": self.audit_chain_valid,
                "proposal_hash": self.proposal_hash, "detail": self.detail}


@dataclass
class AdapterEvidence:
    adapter_name: str
    classification: str
    scenarios: List[ScenarioResult] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)
    capability_profile_version: Optional[str] = None

    @property
    def passed(self) -> bool:
        return len(self.scenarios) == len(SCENARIOS) and all(
            s.status == "PASS" for s in self.scenarios)


def _client(base_url: str):
    from mcc_client import MCCClient
    return MCCClient(base_url, api_key=API_KEY, operator_key=OPERATOR_KEY, timeout=15.0)


def _consensus(client, decision, gw: SharedGovernedGateway, *, not_after: int = FAR_FUTURE,
               tamper: Optional[str] = None):
    from mcc_client.models import ConsensusAuthorization
    ch = client.issue_challenge(decision)
    actor = decision.actor_id
    resource = decision.resource_id
    payload = dict(decision.authorized_payload)
    if tamper == "actor":
        actor = "agent/interop-wrong"
    elif tamper == "resource":
        resource = "interop-wrong-resource"
    elif tamper == "payload":
        payload = {**payload, "message": "INTEROP-ALTERED"}
    votes = gw.votes(action=decision.action, payload=payload, actor=actor,
                     nonce=ch["nonce"], resource=resource, not_after=not_after)
    return ConsensusAuthorization(votes=votes, challenge_id=ch["challenge_id"],
                                  nonce=ch["nonce"])


def run_common_scenarios(proof: AdapterProof, gw: SharedGovernedGateway) -> AdapterEvidence:
    """Run the same seven governance scenarios for one adapter through the shared
    out-of-process Gateway over real HTTP. Every adapter feeds this identical suite."""
    from mcc_client import MCCClient
    from mcc_client.exceptions import MCCError

    ev = AdapterEvidence(adapter_name=proof.adapter_name,
                         classification=proof.adapter_classification,
                         provenance=proof.framework_provenance(),
                         capability_profile_version=proof.capability_profile().get("profile_version"))

    def record(scn: str, *, ok: bool, executed: bool, verdict=None, decision=None,
               audit_valid=None, detail="", proposal=None) -> None:
        ev.scenarios.append(ScenarioResult(
            scenario=scn, status="PASS" if ok else "FAIL", executed=executed,
            verdict=verdict, decision_id=getattr(decision, "audit_id", None),
            audit_ref=getattr(decision, "audit_id", None), audit_chain_valid=audit_valid,
            detail=detail, proposal_hash=proposal.hash() if proposal else None))

    # 1. ALLOW — executes only after a verified decision passes the gate.
    reset_receipts()
    prop = proof.proposal_for("ALLOW")
    c = _client(gw.base_url)
    d = c.evaluate(actor_id=prop.actor_id, action=prop.action, resource=prop.resource,
                   payload=prop.payload, idempotency_key=prop.idempotency_key)
    before = len(recorded_receipts())
    result = c.execute(d, _consensus(c, d, gw))
    executed = result.executed and len(recorded_receipts()) == 1 and before == 0
    record("ALLOW", ok=(d.verdict.value == "ALLOW" and executed), executed=executed,
           verdict=d.verdict.value, decision=d, proposal=prop,
           detail="executed only after verified decision + gate")

    # 2. DENY — policy rejects; the governed operation is never invoked.
    reset_receipts()
    prop = proof.proposal_for("DENY")
    c = _client(gw.base_url)
    denied = False
    verdict = None
    try:
        d = c.evaluate(actor_id=prop.actor_id, action=prop.action,
                       resource=prop.resource, payload=prop.payload,
                       idempotency_key=prop.idempotency_key)
        verdict = d.verdict.value
        if verdict == "DENY":
            denied = True
        else:
            c.execute(d, _consensus(c, d, gw))
    except MCCError:
        denied = True
    record("DENY", ok=(denied and recorded_receipts() == []), executed=False,
           verdict=verdict or "DENY", proposal=prop, detail="no execution, no fallback")

    # 3. REPLAY — the same challenge/votes cannot execute twice.
    reset_receipts()
    prop = proof.proposal_for("REPLAY")
    c = _client(gw.base_url)
    d = c.evaluate(actor_id=prop.actor_id, action=prop.action, resource=prop.resource,
                   payload=prop.payload, idempotency_key=prop.idempotency_key)
    material = _consensus(c, d, gw)
    first = c.execute(d, material)
    replay_blocked = False
    try:
        c.execute(d, material)
    except MCCError:
        replay_blocked = True
    at_most_once = len(recorded_receipts()) == 1
    record("REPLAY", ok=(first.executed and replay_blocked and at_most_once),
           executed=first.executed, verdict="ALLOW", decision=d, proposal=prop,
           detail="single-use nonce; executed at most once")

    # 4. MISMATCH — votes bound to a mutated actor/resource/payload are rejected.
    reset_receipts()
    prop = proof.proposal_for("MISMATCH")
    c = _client(gw.base_url)
    d = c.evaluate(actor_id=prop.actor_id, action=prop.action, resource=prop.resource,
                   payload=prop.payload, idempotency_key=prop.idempotency_key)
    rejected = False
    try:
        c.execute(d, _consensus(c, d, gw, tamper="payload"))
    except MCCError:
        rejected = True
    record("MISMATCH", ok=(rejected and recorded_receipts() == []), executed=False,
           verdict="ALLOW", decision=d, proposal=prop, detail="gate rejects binding mismatch")

    # 5. AUDIT — decision + enforcement recorded; the shared chain verifies.
    reset_receipts()
    prop = proof.proposal_for("AUDIT")
    c = _client(gw.base_url)
    d = c.evaluate(actor_id=prop.actor_id, action=prop.action, resource=prop.resource,
                   payload=prop.payload, idempotency_key=prop.idempotency_key)
    r = c.execute(d, _consensus(c, d, gw))
    chain_valid = bool(c.verify_audit_chain().get("valid"))
    record("AUDIT", ok=(r.executed and chain_valid and d.audit_id is not None),
           executed=r.executed, verdict="ALLOW", decision=d, audit_valid=chain_valid,
           proposal=prop, detail="decision+enforcement in shared audit chain; chain verifies")

    # 6. GATEWAY UNAVAILABLE — the adapter fails closed, no local fallback.
    reset_receipts()
    prop = proof.proposal_for("GATEWAY_UNAVAILABLE")
    dead = MCCClient("http://127.0.0.1:9", api_key=API_KEY, timeout=2.0)
    failed_closed = False
    try:
        dead.evaluate(actor_id=prop.actor_id, action=prop.action,
                      resource=prop.resource, payload=prop.payload,
                      idempotency_key=prop.idempotency_key)
    except MCCError:
        failed_closed = True
    record("GATEWAY_UNAVAILABLE", ok=(failed_closed and recorded_receipts() == []),
           executed=False, proposal=prop, detail="transport failure -> fail closed, no execution")

    # 7. INVALID OR EXPIRED — expired authorization material is rejected.
    reset_receipts()
    prop = proof.proposal_for("INVALID_OR_EXPIRED")
    c = _client(gw.base_url)
    d = c.evaluate(actor_id=prop.actor_id, action=prop.action, resource=prop.resource,
                   payload=prop.payload, idempotency_key=prop.idempotency_key)
    rejected = False
    try:
        c.execute(d, _consensus(c, d, gw, not_after=1))  # not_after in the past
    except MCCError:
        rejected = True
    record("INVALID_OR_EXPIRED", ok=(rejected and recorded_receipts() == []),
           executed=False, verdict="ALLOW", decision=d, proposal=prop,
           detail="expired decision material rejected by the shared gate")

    return ev


__all__ = [
    "AdapterProof", "CanonicalProposal", "SharedGovernedGateway",
    "ScenarioResult", "AdapterEvidence", "run_common_scenarios",
    "SCENARIOS", "CONTRACT_VERSION", "API_KEY", "OPERATOR_KEY",
]
