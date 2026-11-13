"""System-Under-Test provisioning (PR #71).

Boots the real MCC Gateway, the real ``egress_proxy`` protected actuator,
and the real ``pilot_notify`` external-effect sink as three genuine,
independent OS subprocesses communicating only over real loopback HTTP --
never in-process ASGI calls, never a shared Python object. This file
constructs the deployment; it is provisioning code, not assurance-suite
test code, and imports internals accordingly (exactly as
``tests/interoperability/_gateway_process.py`` and
``tests/interoperability/harness.py`` already do for the same purpose --
reused here directly rather than duplicated). No file under
``assurance/tests/`` imports this module's internal construction helpers;
every workstream test reaches the SUT only through ``SystemUnderTest``'s
public HTTP-facing attributes (``gateway_url``, ``actuator_url``,
``notify_url``) via ``httpx``/``mcc_client``.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
FAR_FUTURE = 4_000_000_000
# V05: the trusted, server-side tenant of the SUT gateway (set explicitly on
# its process below). Genuine mandates are issued for exactly this tenant,
# because a strict-tenant gateway refuses any mandate without a matching
# signed tenant_id.
SUT_TENANT_ID = "pilot"
#: The actuator's body.amount CONSTRAIN cap (Workstream F needs a genuine
#: clampable constraint to attack; the actuator ships with none by default).
DEFAULT_MAX_AMOUNT = 1000


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def _wait_ready(url: str, *, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    last_error: Optional[Exception] = None
    while time.time() < deadline:
        try:
            r = httpx.get(url, timeout=1.0)
            if r.status_code < 500:
                return
        except Exception as e:  # noqa: BLE001
            last_error = e
        time.sleep(0.1)
    raise RuntimeError(f"service at {url} did not become ready in time: {last_error}")


@dataclass
class _Process:
    proc: subprocess.Popen
    port: int

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def stop(self) -> None:
        try:
            self.proc.terminate()
            self.proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            self.proc.kill()


@dataclass
class SystemUnderTest:
    """The real, three-process MCC deployment under test. Every attribute
    an assurance test module touches is a plain HTTP base URL or a
    deliberately narrow signing helper for constructing REQUESTS (never a
    handle into the running gateway/actuator's own internal state)."""

    gateway_url: str
    actuator_url: str
    notify_url: str
    api_key: str
    operator_key: str
    actuator_api_key: str
    policy_hash: str
    _tmpdir: str
    _procs: List[_Process] = field(default_factory=list)
    _evaluators: List[Any] = field(default_factory=list)
    _actuator_evaluators: List[Any] = field(default_factory=list)
    _actuator_policy_hash: str = ""
    _gateway_harness: Any = None
    _gateway_notify_base: str = ""
    _mandate_issuer_key: Any = None
    _mandate_issuer_id: str = ""
    _threshold: int = 3
    max_amount: Optional[int] = None
    _notify_process: Optional[_Process] = None
    _notify_env: Any = None

    def gateway_votes(self, *, action: str, payload: Dict[str, Any], actor: str, nonce: str,
                       resource: Optional[str] = None, not_after: int = FAR_FUTURE,
                       count: Optional[int] = None, verdict: str = "ALLOW") -> List[Dict[str, Any]]:
        from mcc_core.consensus import issue_vote

        n = count if count is not None else len(self._evaluators)
        return [
            issue_vote(self._evaluators[i], evaluator_id=self._evaluators[i].kid, verdict=verdict,
                       action=action, payload=payload, actor=actor, not_before=0, not_after=not_after,
                       resource=resource, policy_hash=self.policy_hash, nonce=nonce)
            for i in range(n)
        ]

    def actuator_votes(self, *, action: str, payload: Dict[str, Any], actor: str, nonce: str,
                        resource: Optional[str] = None, not_after: int = FAR_FUTURE,
                        count: Optional[int] = None, verdict: str = "ALLOW",
                        policy_hash: Optional[str] = None) -> List[Dict[str, Any]]:
        from mcc_core.consensus import issue_vote

        n = count if count is not None else len(self._actuator_evaluators)
        return [
            issue_vote(self._actuator_evaluators[i], evaluator_id=self._actuator_evaluators[i].kid,
                       verdict=verdict, action=action, payload=payload, actor=actor, not_before=0,
                       not_after=not_after, resource=resource,
                       policy_hash=policy_hash or self._actuator_policy_hash, nonce=nonce)
            for i in range(n)
        ]

    def forge_vote(self, *, action: str, payload: Dict[str, Any], actor: str, nonce: str,
                    resource: Optional[str] = None, not_after: int = FAR_FUTURE,
                    verdict: str = "ALLOW", policy_hash: Optional[str] = None,
                    evaluator_id: str = "self-appointed-evaluator") -> Dict[str, Any]:
        """Mint one syntactically valid, correctly bound, but UNTRUSTED vote
        -- signed with a freshly generated key that was never registered in
        any trust store. This is attacker tooling, not a governance bypass:
        it uses only the same PUBLIC signing primitives (Ed25519 + the
        documented vote schema) any real attacker already has; it never
        reads or touches the SUT's own trusted evaluator keys. Exists so
        ``assurance/tests/`` workstream modules never need to import
        ``mcc_core`` directly (kept out of the allowed-import list by
        ``test_boundary_guards.py`` on purpose)."""
        from mcc_core.consensus import issue_vote
        from mcc_core.signing import SigningKey

        forger = SigningKey.generate(evaluator_id)
        return issue_vote(
            forger, evaluator_id=forger.kid, verdict=verdict, action=action, payload=payload,
            actor=actor, not_before=0, not_after=not_after, resource=resource,
            policy_hash=policy_hash if policy_hash is not None else self._actuator_policy_hash,
            nonce=nonce,
        )

    @staticmethod
    def tamper_signature(vote: Dict[str, Any]) -> Dict[str, Any]:
        """Flip the trailing characters of a vote's signature -- pure string
        manipulation, no cryptographic module needed."""
        tampered = dict(vote)
        sig = tampered["sig"]
        tampered["sig"] = sig[:-4] + ("AAAA" if not sig.endswith("AAAA") else "BBBB")
        return tampered

    def issue_mandate(self, *, subject: str, action_scope: List[str], resource_scope: List[str],
                       constraints: Optional[Dict[str, Any]] = None, not_before: int = 0,
                       not_after: int = FAR_FUTURE, revocation_required: bool = False,
                       mandate_id: Optional[str] = None) -> Dict[str, Any]:
        """Mint a GENUINE, correctly signed mandate from the Gateway's own
        trusted issuer key (the private half never leaves this process --
        the Gateway subprocess only ever received the PUBLIC half via the
        ``MCC_TRUST_CONFIG`` file ``build_system_under_test`` wrote). This
        is the positive baseline Workstream C's C8 test documented as
        absent; ``forge_mandate``/``tamper_mandate`` below are its
        adversarial counterparts, over the SAME trust configuration."""
        from mcc_core.mandate import issue_mandate as _issue

        return _issue(
            self._mandate_issuer_key, issuer=self._mandate_issuer_id, subject=subject,
            action_scope=action_scope, resource_scope=resource_scope,
            constraints=constraints, not_before=not_before, not_after=not_after,
            revocation_required=revocation_required, mandate_id=mandate_id,
            tenant_id=SUT_TENANT_ID,
        )

    def forge_mandate(self, *, subject: str, action_scope: List[str], resource_scope: List[str],
                       constraints: Optional[Dict[str, Any]] = None, not_before: int = 0,
                       not_after: int = FAR_FUTURE,
                       issuer_id: str = "self-appointed-mandate-issuer") -> Dict[str, Any]:
        """Mint one syntactically valid, correctly bound, but UNTRUSTED
        mandate -- signed with a freshly generated key never registered in
        the Gateway's mandate trust config. Same attacker-tooling posture
        as ``forge_vote``: only public primitives, never the SUT's real
        issuer key."""
        from mcc_core.mandate import issue_mandate as _issue
        from mcc_core.signing import SigningKey

        forger = SigningKey.generate(f"{issuer_id}-key")
        return _issue(
            forger, issuer=issuer_id, subject=subject, action_scope=action_scope,
            resource_scope=resource_scope, constraints=constraints,
            not_before=not_before, not_after=not_after,
            # Correct tenant, so the ONLY defect is the untrusted signer.
            tenant_id=SUT_TENANT_ID,
        )

    @staticmethod
    def tamper_mandate(mandate: Dict[str, Any], **claim_overrides: Any) -> Dict[str, Any]:
        """Take a GENUINELY signed mandate and rewrite one or more claims
        after the fact (e.g. ``subject=`` a different actor, or a widened
        ``action_scope``) WITHOUT re-signing -- the signature no longer
        covers the mutated claims, so verification must fail. Proves the
        Gateway checks the signature over the claims actually used, not
        merely "a valid signature was present somewhere"."""
        tampered = dict(mandate)
        tampered.update(claim_overrides)
        return tampered

    def revoke_mandate(self, mandate_id: str) -> bool:
        """Revoke a mandate through the Gateway's real, operator-authenticated
        ``POST /mandates/{id}/revoke`` -- the same HTTP surface a real
        operator would use, never a direct call into the revocation
        registry object."""
        r = httpx.post(f"{self.gateway_url}/mandates/{mandate_id}/revoke",
                        headers={"x-operator-key": self.operator_key}, timeout=10.0)
        r.raise_for_status()
        return bool(r.json()["ok"])

    def notification_receipt_count(self) -> int:
        return httpx.get(f"{self.notify_url}/receipts", timeout=5.0).json()["count"]

    def kill_notify(self) -> None:
        """Workstream B fault injection: hard-kill the real OS process
        behind the external-effect sink, mid-scenario, so an in-flight
        governed dispatch genuinely cannot reach it -- not a mock returning
        an error, a real severed connection."""
        if self._notify_process is not None:
            self._notify_process.stop()

    def restart_notify(self) -> None:
        """Bring the external-effect sink back up on the SAME port (so the
        actuator's already-configured ``--notify-base`` needs no change),
        as a genuinely fresh process (its in-memory receipt count resets to
        zero -- callers comparing before/after must account for that)."""
        proc = subprocess.Popen(
            [sys.executable, "-m", "assurance.sut.notify_process", "--port", str(self._notify_process.port)],
            cwd=str(REPO_ROOT), env=self._notify_env,
        )
        self._notify_process = _Process(proc, self._notify_process.port)
        for i, p in enumerate(self._procs):
            if p.port == self._notify_process.port:
                self._procs[i] = self._notify_process
        _wait_ready(f"{self.notify_url}/health")

    def agent_key(self, principal_id: str) -> str:
        """V05 (part 2): the per-agent credential ``principal_id`` presents as
        ``X-API-Key`` on the Gateway's identity routes (``/mandates/execute``,
        ``/approvals``, ``/approvals/{id}/execute``). ``api_key`` remains the
        tenant's shared key, which grants no agent identity there. The
        in-process SUT registers these keys for
        ``tests.interoperability.harness.AGENT_PRINCIPALS``; an external
        gateway (``connect_external``) must register the same derivation."""
        from tests._agent_credentials import derived_agent_key
        return derived_agent_key(self.api_key, principal_id)

    def gateway_audit_chain_valid(self) -> bool:
        """The Gateway's own ``GET /verify`` -- real HTTP, independently
        recomputes and checks the append-only hash-chain audit log.
        Workstream G's primary observation surface."""
        r = httpx.get(f"{self.gateway_url}/verify", headers={"x-api-key": self.api_key}, timeout=10.0)
        r.raise_for_status()
        return bool(r.json()["valid"])

    def corrupt_gateway_audit_chain(self) -> None:
        """Directly tamper the Gateway's on-disk audit log, bypassing the
        application entirely -- simulating a compromised-storage insider
        threat (a DIFFERENT threat model than a network attacker; see
        ``ASSUMPTIONS_AND_LIMITS.md``). Exists so Workstream G can prove
        ``/verify`` is genuinely tamper-EVIDENT (flips to invalid) rather
        than a check that always reports success. Self-contained mode
        only -- see ``connect_external``'s docstring for why a genuine
        third party's audit log filesystem is out of reach by design."""
        if self._gateway_harness is None:
            raise RuntimeError(
                "corrupt_gateway_audit_chain requires direct filesystem access to the "
                "Gateway's audit log, only available in self-contained mode -- a genuine "
                "external/third-party deployment cannot be expected to hand this over "
                "(see connect_external's docstring); this is a permanent external-mode "
                "limitation, not a bug"
            )
        path = self._gateway_harness._audit_path  # noqa: SLF001 -- provisioning-layer access, by design
        with open(path, "a", encoding="utf-8") as f:
            f.write('{"tampered": true, "not-a-real-audit-entry": "' + "x" * 64 + '"}\n')

    def gateway_notification_receipt_count(self) -> int:
        """The GATEWAY's own mock upstream (a separate ``pilot_notify``
        instance from the actuator's -- see ``SharedGovernedGateway``),
        observed independently over real HTTP. Used by Workstream C tests
        that exercise the Gateway's own ``/consensus/*``/``/mandates/*``
        HTTP API directly, rather than through the actuator. Reads
        ``self._gateway_notify_base`` (set for BOTH self-contained and
        genuine external-mode deployments -- see ``connect_external``'s
        ``gateway_notify_url`` parameter), never the self-contained-only
        ``_gateway_harness`` handle, so this works identically against a
        real third party's own deployment -- PROVIDED that party supplied
        ``gateway_notify_url`` to ``connect_external`` (optional; see its
        docstring)."""
        if not self._gateway_notify_base:
            raise RuntimeError(
                "gateway_notification_receipt_count requires the Gateway's own "
                "external-effect-sink URL, which this deployment was not given "
                "(self-contained mode always has one; external mode needs "
                "gateway_notify_url / MCC_ASSURANCE_GATEWAY_NOTIFY_URL) -- "
                "fails closed rather than silently observing the wrong sink"
            )
        return httpx.get(f"{self._gateway_notify_base}/receipts", timeout=5.0).json()["count"]

    def gateway_vote_as(self, *, evaluator_index: int, verdict: str, action: str, payload: Dict[str, Any],
                         actor: str, nonce: str, resource: Optional[str] = None,
                         policy_hash: Optional[str] = None) -> Dict[str, Any]:
        """One vote from a specific, genuinely TRUSTED gateway evaluator
        (identified by index into the pool the Gateway's own trust config
        was built from), with an explicit verdict -- e.g. a trusted DENY
        vote for a veto test, which ``gateway_consensus_votes`` (uniformly
        ALLOW) cannot produce. Uses ``self._evaluators`` -- populated
        identically in self-contained and external mode -- not
        ``_gateway_harness``, so this works in both."""
        from mcc_core.consensus import issue_vote

        evaluator = self._evaluators[evaluator_index]
        return issue_vote(
            evaluator, evaluator_id=evaluator.kid, verdict=verdict, action=action, payload=payload,
            actor=actor, not_before=0, not_after=FAR_FUTURE, resource=resource,
            policy_hash=policy_hash, nonce=nonce,
        )

    def gateway_consensus_votes(self, *, action: str, payload: Dict[str, Any], actor: str, nonce: str,
                                 resource: Optional[str] = None,
                                 policy_hash: Optional[str] = None) -> List[Dict[str, Any]]:
        """Genuine votes for the GATEWAY's own consensus policy. Applies the
        same ``ActionProfile`` canonicalization the Gateway itself uses
        server-side to compute the authoritative payload hash (the
        registry is a stateless, universal mapping -- not something unique
        to a particular running Gateway process -- so this is exactly the
        canonicalization any deployment, self-contained or a genuine third
        party's, actually applies), using ``self._evaluators`` rather than
        reaching into the self-contained-only ``_gateway_harness``."""
        from mcc_core import ProfileRegistry
        from mcc_core.consensus import issue_vote

        canonical = ProfileRegistry.default_pilot().for_action(action).canonical_payload(dict(payload))
        return [
            issue_vote(e, evaluator_id=e.kid, verdict="ALLOW", action=action, payload=canonical,
                       actor=actor, not_before=0, not_after=FAR_FUTURE, resource=resource,
                       policy_hash=policy_hash or self.policy_hash, nonce=nonce)
            for e in self._evaluators
        ]

    def propose_notification(self, *, actor: str = "agent/egress", resource: str = "notify",
                              transaction_id: str, idempotency_key: str,
                              recipient: str = "ops", message: str = "assurance-probe",
                              correlation_id: Optional[str] = None,
                              amount: Optional[int] = None,
                              api_key: Optional[str] = None) -> Dict[str, Any]:
        """Step 1 of the real actuator flow: propose the governed action,
        get back a consensus challenge. Returns the raw JSON response.

        ``amount``, when given, is bound into the canonical action as
        ``body.amount`` -- the one clampable field the actuator's default
        authority config constrains (``max_amount``, see
        ``assurance/sut/actuator_process.py``) -- so Workstream F's
        constraint-enforcement tests can request an excessive amount and
        observe the CONSTRAIN clamp."""
        body: Dict[str, Any] = {"recipient": recipient, "message": message,
                                 "correlation_id": correlation_id or transaction_id}
        if amount is not None:
            body["amount"] = amount
        req = {"method": "POST", "url": f"{self.notify_url}/send_notification", "headers": {}, "body": body,
               "actor": actor, "resource": resource, "transaction_id": transaction_id,
               "idempotency_key": idempotency_key}
        r = httpx.post(f"{self.actuator_url}/v1/http/execute",
                        headers={"x-api-key": api_key or self.actuator_api_key}, json=req, timeout=10.0)
        payload = r.json()
        payload["_request"] = req
        payload["_status_code"] = r.status_code
        return payload

    def submit_notification_votes(self, proposal: Dict[str, Any], *, votes: List[Dict[str, Any]],
                                   api_key: Optional[str] = None, override_request: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Step 2: submit the challenge id + votes for the SAME request. Returns
        the raw JSON response (never asserts anything -- callers decide)."""
        req = dict(proposal["_request"]) if override_request is None else dict(override_request)
        req["challenge_id"] = proposal["challenge_id"]
        req["votes"] = votes
        r = httpx.post(f"{self.actuator_url}/v1/http/execute",
                        headers={"x-api-key": api_key or self.actuator_api_key}, json=req, timeout=10.0)
        payload = r.json()
        payload["_request"] = req
        payload["_status_code"] = r.status_code
        return payload

    def submit_constrained_votes(self, first_round: Dict[str, Any], *, clamped_amount: int,
                                  votes: List[Dict[str, Any]], api_key: Optional[str] = None,
                                  clamped_body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Round 2 of a CONSTRAIN flow: ``first_round`` is the response from
        ``submit_notification_votes`` whose ``outcome`` was ``CONSTRAIN``
        (it carries a NEW ``challenge_id``/``nonce`` bound to the clamped
        payload). The caller resubmits with ``constrained=True`` and a
        request body that reflects the clamp -- ``execute_constrained``
        fail-closed-refuses a body that still needs further clamping (see
        ``examples/governed_agent/mcc_client.py``), so submitting the
        original over-cap body here proves nothing except that the fail-
        closed refusal itself works."""
        req = dict(first_round["_request"]) if clamped_body is None else dict(clamped_body)
        req["body"] = dict(req["body"])
        req["body"]["amount"] = clamped_amount
        req["challenge_id"] = first_round["challenge_id"]
        req["votes"] = votes
        req["constrained"] = True
        r = httpx.post(f"{self.actuator_url}/v1/http/execute",
                        headers={"x-api-key": api_key or self.actuator_api_key}, json=req, timeout=10.0)
        payload = r.json()
        payload["_request"] = req
        payload["_status_code"] = r.status_code
        return payload

    def canonical_notification_action(self, proposal: Dict[str, Any]) -> Dict[str, Any]:
        from egress_proxy.canonical_action import build_canonical_action

        req = proposal["_request"]
        return build_canonical_action(method=req["method"], url=req["url"], headers=req["headers"], body=req["body"])

    def close(self) -> None:
        for p in self._procs:
            p.stop()

    def __enter__(self) -> "SystemUnderTest":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def export_evaluator_keys_for_external_mode(sut: "SystemUnderTest", directory: str) -> Dict[str, str]:
    """Serialize a self-contained SUT's evaluator private keys to PEM files
    plus the ``[{"kid": ..., "pem_path": ...}, ...]`` index JSON
    ``_load_evaluator_keys``/``connect_external`` expect -- so a test can
    stand up a real deployment via ``build_system_under_test`` and then
    genuinely exercise the SEPARATE ``connect_external``/CLI ``--target``
    code path against it as if it were a third party's own deployment
    (never a mock of the external-mode mechanism itself). Returns
    ``{"evaluator_keys_path": ..., "actuator_evaluator_keys_path": ...}``.
    Provisioning-layer only -- never imported from ``assurance/tests/``."""
    from cryptography.hazmat.primitives import serialization

    def _export(evaluators: List[Any], subdir: str) -> str:
        keys_dir = os.path.join(directory, subdir)
        os.makedirs(keys_dir, exist_ok=True)
        index = []
        for ev in evaluators:
            pem_path = os.path.join(keys_dir, f"{ev.kid}.pem")
            pem = ev._private_key.private_bytes(  # noqa: SLF001 -- provisioning-layer export, by design
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            with open(pem_path, "wb") as f:
                f.write(pem)
            index.append({"kid": ev.kid, "pem_path": pem_path})
        index_path = os.path.join(keys_dir, "index.json")
        with open(index_path, "w", encoding="utf-8") as f:
            json.dump(index, f)
        return index_path

    return {
        "evaluator_keys_path": _export(sut._evaluators, "gateway-evaluators"),  # noqa: SLF001
        "actuator_evaluator_keys_path": _export(sut._actuator_evaluators, "actuator-evaluators"),  # noqa: SLF001
    }


def _load_evaluator_keys(keys_path: str) -> List[Any]:
    """Load evaluator SigningKeys from a JSON file of
    ``[{"kid": "...", "pem_path": "..."}, ...]``. Only a file PATH crosses
    the process boundary here (via an env var the caller sets, e.g.
    ``MCC_ASSURANCE_EVALUATOR_KEYS_PATH``) -- never raw key material as a
    CLI argument, mirroring the production signing-ceremony convention in
    ``docs/certification/OFFICIAL_SIGNING_CEREMONY.md``."""
    from mcc_core.signing import SigningKey

    entries = json.loads(Path(keys_path).read_text(encoding="utf-8"))
    return [SigningKey.from_pem_file(e["pem_path"], e["kid"]) for e in entries]


def connect_external(*, gateway_url: str, actuator_url: str, notify_url: str, api_key: str,
                      operator_key: str, actuator_api_key: str, policy_hash: str,
                      actuator_policy_hash: str, evaluator_keys_path: str,
                      actuator_evaluator_keys_path: str, threshold: int = 3,
                      gateway_notify_url: Optional[str] = None) -> SystemUnderTest:
    """Attach to an ALREADY-RUNNING, externally provisioned MCC deployment
    instead of spawning one. This is the genuine third-party mode: the
    operator of the target deployment runs their own Gateway/actuator/
    external-effect sink, generates their own evaluator keypairs, registers
    the PUBLIC halves in their OWN trust config, and hands this process the
    PRIVATE key PEM paths (never the key material itself) plus the deployment's
    URLs/API keys/policy hash via environment variables.

    No subprocess is spawned and ``.close()`` is a no-op -- this function
    connects to infrastructure it does not own and must not tear down.

    ``gateway_notify_url`` is the Gateway's OWN external-effect sink -- a
    SEPARATE service from ``notify_url`` (the actuator's), used
    independently by Workstream C/K tests that exercise the Gateway's
    ``/consensus/*``/``/mandates/*`` HTTP API directly
    (``gateway_notification_receipt_count``). Optional: a third party who
    only exposes one sink can omit it, in which case those specific tests
    fail closed with a clear, explicit error (see
    ``gateway_notification_receipt_count``) rather than a silent wrong
    answer or a confusing internal AttributeError.

    Limitation (documented in ``ASSUMPTIONS_AND_LIMITS.md``): the assurance
    suite still requires the operator to hand it valid evaluator credentials
    for the positive-path (ALLOW/CONSTRAIN) scenarios -- a system cannot
    prove "valid authorization works" without being handed valid authorization
    by its own operator. This is a stated, honest boundary, not a gap the
    suite hides. A second, separate limitation: ``corrupt_gateway_audit_chain``
    (Workstream G's filesystem-tamper test) requires direct filesystem access
    to the Gateway's audit log, which a genuine third party cannot be expected
    to hand over -- it is unavailable in external mode by design, not a bug."""
    evaluators = _load_evaluator_keys(evaluator_keys_path)
    actuator_evaluators = _load_evaluator_keys(actuator_evaluator_keys_path)
    return SystemUnderTest(
        gateway_url=gateway_url, actuator_url=actuator_url, notify_url=notify_url,
        api_key=api_key, operator_key=operator_key, actuator_api_key=actuator_api_key,
        policy_hash=policy_hash, _tmpdir="", _procs=[], _evaluators=evaluators,
        _actuator_evaluators=actuator_evaluators, _threshold=threshold,
        _actuator_policy_hash=actuator_policy_hash,
        _gateway_notify_base=gateway_notify_url or "",
    )


def _generate_trust_config(evaluators) -> str:
    trust = {"issuers": [
        {"issuer_id": e.kid, "enabled": True,
         "keys": [{"kid": e.kid, "public_key_b64": e.public_key_b64(), "not_after": None}]}
        for e in evaluators
    ]}
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(trust, f)
    return path


def build_system_under_test(*, n_evaluators: int = 3, threshold: int = 3,
                             max_amount: Optional[int] = None,
                             require_consensus: bool = True,
                             extra_env: Optional[Dict[str, str]] = None) -> SystemUnderTest:
    """Boot the three real subprocesses and return a live SystemUnderTest.
    Caller is responsible for ``.close()`` (or use as a context manager).

    ``max_amount`` is None (no ``body.amount`` constraint at all) by default
    -- most workstreams' proposals never set an ``amount`` field, and a
    ``max_`` constraint on a field that is simply absent from a given
    request counts as an unclampable VIOLATION (see
    ``mcc_core.authority._constraint_violations``'s fail-closed-on-missing-
    field rule), which would turn every such proposal from ALLOW into DENY.
    Workstream F (``assurance/tests/test_constraint_enforcement.py``) builds
    its OWN isolated SUT with ``max_amount`` set, rather than mutating the
    shared session-scoped fixture every other workstream also depends on.

    ``require_consensus`` is True (matching every other workstream's shared
    Gateway topology) by default. The Gateway's ``EnforcementCoordinator``
    requires N-of-M consensus at the coordinator UNCONDITIONALLY when this
    is set -- for EVERY authority source, including a genuinely verified
    signed mandate (``execute_with_mandate`` never supplies consensus
    votes; see ``coordinator.py``'s ``require_consensus`` gate) -- so a
    deployment testing mandate-authority ALONE (Workstream C's
    ``test_mandate_containment.py``) passes ``require_consensus=False``
    here, exactly mirroring how the existing ``tests/test_mandate_http.py``
    constructs its own coordinator (``EnforcementCoordinator``'s default is
    already ``require_consensus=False``) -- a legitimate, precedented
    alternative deployment topology, not a workaround.

    ``extra_env`` (PR-5): additional environment variables merged into the
    Gateway subprocess's env, on top of (never overriding) the mandate-trust
    and consensus/challenge variables this function already sets --
    currently used only by ``assurance.sut.attestation_harness`` to wire
    ``MCC_ATTESTATION_REQUIREMENTS_CONFIG``/``MCC_ATTESTATION_TRUST_CONFIG``
    (PR-2's own, unmodified env-driven Control wiring). ``None`` (the
    default) is byte-for-byte the pre-PR-5 behavior for every existing
    caller."""
    from mcc_core.signing import SigningKey

    tmpdir = tempfile.mkdtemp(prefix="mcc-assurance-")
    procs: List[_Process] = []
    env_base = dict(os.environ)
    env_base["PYTHONPATH"] = os.pathsep.join(
        filter(None, [str(REPO_ROOT / "src"), str(REPO_ROOT), str(REPO_ROOT / "sdk" / "python" / "src"), env_base.get("PYTHONPATH")])
    )

    # -- notify (the observable external world) --------------------------
    notify_port = free_port()
    notify_proc = subprocess.Popen(
        [sys.executable, "-m", "assurance.sut.notify_process", "--port", str(notify_port)],
        cwd=str(REPO_ROOT), env=env_base,
    )
    notify_process = _Process(notify_proc, notify_port)
    procs.append(notify_process)
    notify_url = f"http://127.0.0.1:{notify_port}"
    _wait_ready(f"{notify_url}/health")

    # -- gateway (reuses the existing, already-proven PR #48 harness) ----
    from tests.interoperability.harness import API_KEY as GATEWAY_API_KEY
    from tests.interoperability.harness import OPERATOR_KEY as GATEWAY_OPERATOR_KEY
    from tests.interoperability.harness import SharedGovernedGateway

    # A genuine, trusted signed-mandate issuer for the Gateway's own
    # /mandates/* API (Workstream C mandate-forgery-containment: see
    # SystemUnderTest.issue_mandate/forge_mandate/tamper_mandate below).
    # This is the ONLY place this key's private half exists; the trust
    # config written to disk carries only its PUBLIC half, exactly the
    # config/trust.pilot.example.json convention a real operator would use.
    mandate_issuer_key = SigningKey.generate("assurance-mandate-issuer-2026a")
    mandate_issuer_id = "assurance-mandates"
    mandate_trust_path = os.path.join(tmpdir, "mandate_trust.json")
    with open(mandate_trust_path, "w", encoding="utf-8") as f:
        json.dump({"issuers": [{
            "issuer_id": mandate_issuer_id, "enabled": True,
            "keys": [{"kid": mandate_issuer_key.kid,
                      "public_key_b64": mandate_issuer_key.public_key_b64(),
                      "not_after": None}],
        }]}, f)

    gateway_extra_env = {"MCC_TRUST_CONFIG": mandate_trust_path,
                         "MCC_GATEWAY_TENANT_ID": SUT_TENANT_ID}
    if not require_consensus:
        # A mandate-authority-only deployment topology (see the
        # require_consensus docstring above): the coordinator's mandatory
        # consensus/challenge gates are an orthogonal OPERATIONAL policy
        # from which authority source is used, and execute_with_mandate
        # never supplies consensus evidence.
        gateway_extra_env["MCC_REQUIRE_CONSENSUS"] = "0"
        gateway_extra_env["MCC_REQUIRE_CHALLENGE"] = "0"
    if extra_env:
        gateway_extra_env.update(extra_env)
    gw = SharedGovernedGateway(n_evaluators=n_evaluators, threshold=threshold,
                                extra_env=gateway_extra_env)

    # -- actuator (the real protected egress_proxy executor) -------------
    actuator_evaluators = [SigningKey.generate(f"assurance-eval-{i}") for i in range(n_evaluators)]
    actuator_trust_path = _generate_trust_config(actuator_evaluators)
    actuator_port = free_port()
    actuator_audit = os.path.join(tmpdir, "actuator-audit.jsonl")
    actuator_env = dict(env_base)
    actuator_env["MCC_ASSURANCE_ACTUATOR_API_KEY"] = "assurance-actuator-key"
    actuator_env["MCC_ASSURANCE_OPERATOR_KEY"] = "assurance-operator-key"
    actuator_env["MCC_ASSURANCE_THRESHOLD"] = str(threshold)
    actuator_cmd = [sys.executable, "-m", "assurance.sut.actuator_process", "--port", str(actuator_port),
                     "--notify-base", notify_url, "--trust-config", actuator_trust_path,
                     "--audit-log", actuator_audit]
    if max_amount is not None:
        actuator_cmd += ["--max-amount", str(max_amount)]
    actuator_proc = subprocess.Popen(actuator_cmd, cwd=str(REPO_ROOT), env=actuator_env)
    procs.append(_Process(actuator_proc, actuator_port))
    actuator_url = f"http://127.0.0.1:{actuator_port}"
    _wait_ready(f"{actuator_url}/ready")

    actuator_health = httpx.get(f"{actuator_url}/health", timeout=5.0).json()
    actuator_policy_hash = actuator_health.get("policy_hash") or ""

    sut = SystemUnderTest(
        gateway_url=gw.base_url, actuator_url=actuator_url, notify_url=notify_url,
        api_key=GATEWAY_API_KEY, operator_key=GATEWAY_OPERATOR_KEY,
        actuator_api_key="assurance-actuator-key",
        policy_hash=gw.policy_hash, _tmpdir=tmpdir, _procs=procs,
        _evaluators=gw.evaluators, _actuator_evaluators=actuator_evaluators,
        _threshold=threshold, max_amount=max_amount,
        _notify_process=notify_process, _notify_env=env_base,
    )
    sut._actuator_policy_hash = actuator_policy_hash  # type: ignore[attr-defined]
    sut._gateway_harness = gw  # type: ignore[attr-defined]  # kept alive; closed by SystemUnderTest.close()
    sut._gateway_notify_base = gw.notify_base  # type: ignore[attr-defined]
    sut._mandate_issuer_key = mandate_issuer_key  # type: ignore[attr-defined]
    sut._mandate_issuer_id = mandate_issuer_id  # type: ignore[attr-defined]
    original_close = sut.close

    def close_all() -> None:
        gw.close()
        original_close()

    sut.close = close_all  # type: ignore[method-assign]
    return sut
