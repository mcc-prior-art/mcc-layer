"""System-Under-Test provisioning for the PR-1->4 attestation-to-execution
chain (PR-5).

Extends ``assurance.sut.harness`` (reused, not duplicated) with:

* a real Independent Attester Service (PR-4) OS subprocess, wired to a
  deterministic test provider;
* PR-2's own, unmodified env-driven ``PreExecutionControl`` wiring
  (``MCC_ATTESTATION_REQUIREMENTS_CONFIG``/``MCC_ATTESTATION_TRUST_CONFIG``)
  on the SAME real Gateway subprocess ``build_system_under_test`` already
  boots;
* attacker tooling mirroring ``forge_mandate``/``forge_vote``/
  ``tamper_mandate``'s existing conventions, adapted to
  ``EvidenceAttestation``: ``forge_attestation`` (syntactically valid,
  correctly bound, but signed by a key never registered in the Attester
  trust config) and ``tamper_attestation`` (mutate a genuinely signed
  attestation's claims without re-signing).

Provisioning code, not assurance-suite test code -- imports MCC-Core /
``mcc_attestation`` internals accordingly, exactly as
``assurance/sut/harness.py``'s own module docstring establishes for this
directory. No file under ``assurance/tests/`` imports this module's
internal construction helpers directly; every attestation-chain workstream
test reaches the SUT only through ``AttestationSystemUnderTest``'s public
HTTP-facing attributes/methods.
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
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from .harness import SystemUnderTest, _Process, _wait_ready, build_system_under_test, free_port

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The one action this harness configures an AttestationRequirement for.
#: Reuses the existing "send_notification" action Workstream C already
#: exercises via the Gateway's own /mandates/execute, so canonicalization
#: (ProfileRegistry.default_pilot()) is already an established, understood
#: quantity -- no new action profile is introduced.
ATTESTED_ACTION = "send_notification"
ATTESTED_RESOURCE = "notifications"
ATTESTER_ID = "assurance-attester.risk.v1"
EVIDENCE_TYPE = "risk_assessment"
SCOPE_TEMPLATE = "notify:{resource}"
ATTESTER_AUTH_SECRET = "assurance-attester-service-auth-secret-01"


def _canonical_payload(context: Dict[str, Any]) -> Dict[str, Any]:
    """The exact canonicalization the real Gateway applies server-side
    before computing the authoritative payload_hash -- reused here (not
    reimplemented) so an attestation this harness obtains binds to exactly
    what PreExecutionControl will expect, mirroring
    ``SystemUnderTest.gateway_consensus_votes``'s identical reuse of
    ``ProfileRegistry`` for the same reason."""
    from mcc_core import ProfileRegistry

    return ProfileRegistry.default_pilot().for_action(ATTESTED_ACTION).canonical_payload(dict(context))


@dataclass
class AttestationSystemUnderTest:
    """Wraps a real ``SystemUnderTest`` (Gateway + actuator + notify, PR
    #71) with a real, separate Independent Attester Service process and
    attestation-specific attacker tooling. Every method below reaches its
    target ONLY over real HTTP -- no in-process shortcut into either the
    Gateway's or the Attester's internals."""

    sut: SystemUnderTest
    attester_url: str
    attester_public_key: Any  # cryptography Ed25519PublicKey -- PUBLIC only
    attester_kid: str
    _attester_process: _Process = field(repr=False)
    _tmpdir: str = field(repr=False, default="")

    @property
    def gateway_url(self) -> str:
        return self.sut.gateway_url

    @property
    def api_key(self) -> str:
        return self.sut.api_key

    def get_attestation(self, *, action: str = ATTESTED_ACTION, resource: str = ATTESTED_RESOURCE,
                         context: Dict[str, Any]) -> Dict[str, Any]:
        """Obtain a GENUINE signed EvidenceAttestation from the real,
        separate Independent Attester Service process, over real HTTP --
        the positive-baseline path every negative test below is compared
        against. ``context`` is canonicalized the SAME way the Gateway
        will canonicalize it server-side, so the returned attestation's
        ``payload_hash`` binds to exactly what PreExecutionControl expects."""
        canonical = _canonical_payload(context) if action == ATTESTED_ACTION else dict(context)
        r = httpx.post(
            f"{self.attester_url}/attest",
            json={"action": action, "resource": resource, "payload": canonical},
            headers={"X-Attester-Auth": ATTESTER_AUTH_SECRET}, timeout=10.0,
        )
        r.raise_for_status()
        return r.json()

    def forge_attestation(self, *, action: str = ATTESTED_ACTION, resource: str = ATTESTED_RESOURCE,
                           context: Dict[str, Any], claims: Optional[Dict[str, Any]] = None,
                           attester_id: str = "self-appointed-attester") -> Dict[str, Any]:
        """Mint one syntactically valid, correctly bound, but UNTRUSTED
        attestation -- signed with a freshly generated key that was never
        registered in the Attester trust config the real Gateway subprocess
        loaded. Attacker tooling, same posture as
        ``SystemUnderTest.forge_vote``/``forge_mandate``: uses only public,
        documented attestation-construction primitives (PR-1's own
        ``LocalAttester``), never the SUT's real Attester private key."""
        from mcc_attestation import LocalAttester
        from mcc_core.signing import SigningKey, hash_action, hash_payload

        canonical = _canonical_payload(context) if action == ATTESTED_ACTION else dict(context)
        forger_key = SigningKey.generate(f"{attester_id}-key")
        attester = LocalAttester(attester_id, forger_key)
        now = int(time.time())
        att = attester.attest(
            evidence_type=EVIDENCE_TYPE, claims=claims or {"risk_class": "low"},
            action_hash=hash_action(action), scope=SCOPE_TEMPLATE.format(action=action, resource=resource),
            provenance={"model": "forged"}, issued_at=now, not_before=now, expires_at=now + 900,
            nonce=f"forged-{now}-{id(forger_key)}", payload_hash=hash_payload(canonical),
        )
        return att.to_dict()

    @staticmethod
    def tamper_attestation(raw: Dict[str, Any], **claim_overrides: Any) -> Dict[str, Any]:
        """Take a GENUINELY signed attestation and rewrite one or more
        claims after the fact WITHOUT re-signing -- the signature no longer
        covers the mutated fields, so verification must fail. Mirrors
        ``SystemUnderTest.tamper_mandate`` exactly."""
        tampered = dict(raw)
        tampered.update(claim_overrides)
        return tampered

    def execute_with_mandate_and_attestation(
        self, *, mandate: Dict[str, Any], attestation: Optional[Dict[str, Any]],
        actor: str, action: str = ATTESTED_ACTION, resource: str = ATTESTED_RESOURCE,
        context: Dict[str, Any], idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Drive the real Gateway's ``POST /mandates/execute`` -- the SAME
        HTTP surface ``assurance/tests/test_mandate_containment.py`` already
        uses -- with an optional raw ``attestation`` document attached
        (PR-2's existing, unmodified HTTP field). Returns the raw JSON
        response; callers decide what it means.

        ``idempotency_key`` defaults to a fresh, unique value per call (never
        reused unless a caller explicitly passes one) -- Round 25 made this a
        mandatory logical-operation identity at the coordinator; callers whose
        test is about something else entirely (attestation nonce replay,
        payload substitution, ...) should not have to supply one just to
        avoid an unrelated MISSING_LOGICAL_OPERATION_ID block."""
        body: Dict[str, Any] = {
            "mandate": mandate, "actor": actor, "action": action, "resource": resource,
            "context": context,
            "idempotency_key": idempotency_key or f"assurance-auto-{uuid.uuid4()}",
        }
        if attestation is not None:
            body["attestation"] = attestation
        # V05 (part 2): the caller acts as ``actor`` with that agent's own credential.
        r = httpx.post(f"{self.gateway_url}/mandates/execute",
                        headers={"x-api-key": self.sut.agent_key(actor)},
                        json=body, timeout=10.0)
        return r.json()

    def issue_mandate(self, *, subject: str, action_scope: List[str], resource_scope: List[str]) -> Dict[str, Any]:
        return self.sut.issue_mandate(subject=subject, action_scope=action_scope, resource_scope=resource_scope)

    def gateway_notification_receipt_count(self) -> int:
        return self.sut.gateway_notification_receipt_count()

    def close(self) -> None:
        self._attester_process.stop()
        self.sut.close()

    def __enter__(self) -> "AttestationSystemUnderTest":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _write_attestation_configs(tmpdir: str, *, attester_kid: str, public_key_b64: str,
                                required_claims: Dict[str, List[str]]) -> Dict[str, str]:
    """Write the two JSON config files
    ``gateway.governance_api._build_pre_execution_control`` expects --
    reusing that function's EXACT, unmodified schema (no new config format).
    Returns the two file paths."""
    requirements_path = os.path.join(tmpdir, "attestation_requirements.json")
    with open(requirements_path, "w", encoding="utf-8") as f:
        json.dump([{
            "action": ATTESTED_ACTION, "evidence_type": EVIDENCE_TYPE, "scope": SCOPE_TEMPLATE,
            "require_payload_binding": True, "require_policy_binding": False,
            "required_claims": required_claims,
        }], f)

    trust_path = os.path.join(tmpdir, "attestation_trust.json")
    with open(trust_path, "w", encoding="utf-8") as f:
        json.dump([{
            "attester_id": ATTESTER_ID, "kid": attester_kid, "public_key_b64": public_key_b64,
            "evidence_types": [EVIDENCE_TYPE],
        }], f)

    return {"requirements": requirements_path, "trust": trust_path}


def build_attestation_system_under_test(
    *, required_claims: Optional[Dict[str, List[str]]] = None,
    validity_seconds: int = 900,
) -> AttestationSystemUnderTest:
    """Boot a real Independent Attester Service subprocess AND a real
    Gateway (via ``build_system_under_test(require_consensus=False)``,
    reused unchanged) configured to REQUIRE a verified attestation for
    ``ATTESTED_ACTION`` via PR-2's own env-driven wiring. Caller is
    responsible for ``.close()`` (or use as a context manager).

    ``required_claims`` defaults to ``{"risk_class": ["low"]}`` -- the same
    convention every PR-2/PR-3 unit test already uses.

    ``validity_seconds`` (PR-5): the Attester's own configured validity
    window (``MCC_ATTESTER_VALIDITY_SECONDS``). Defaults to 900 (matching
    every unit-level attestation test's convention); pass a small value
    (e.g. 2) plus a real ``time.sleep`` past it to test genuine wall-clock
    expiry through the real HTTP surface, rather than simulating staleness
    by tampering a signed field (which would only re-exercise signature
    tamper-detection, not the time-window check specifically).
    """
    from mcc_core.signing import SigningKey

    tmpdir = tempfile.mkdtemp(prefix="mcc-assurance-attestation-")

    # The Attester's own signing key. Generated directly in this
    # provisioning process (the SAME convention build_system_under_test
    # already uses for the mandate issuer key just above this function in
    # harness.py) -- this harness exists to provision a WORKING
    # attestation-requiring deployment, not to re-prove PR-4's private-key
    # process-isolation claim (that is tests/test_attester_service_process_
    # isolation.py's job, cited rather than duplicated here -- see the PR-5
    # gap matrix in docs/ATTESTATION_INDEPENDENT_ASSURANCE.md).
    attester_key = SigningKey.generate("assurance-attester-key-01")
    key_path = os.path.join(tmpdir, "attester_private.pem")
    from cryptography.hazmat.primitives import serialization

    pem = attester_key._private_key.private_bytes(  # noqa: SLF001 -- provisioning-layer export, by design
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    )
    with open(key_path, "wb") as f:
        f.write(pem)

    claims = required_claims or {"risk_class": ["low"]}
    configs = _write_attestation_configs(
        tmpdir, attester_kid=attester_key.kid, public_key_b64=attester_key.public_key_b64(),
        required_claims=claims,
    )

    # -- boot the real Independent Attester Service subprocess -----------
    assessment_table_path = os.path.join(tmpdir, "assessment_table.json")
    default_claim_value = next(iter(claims.get("risk_class", ["low"])), "low")
    with open(assessment_table_path, "w", encoding="utf-8") as f:
        json.dump({
            # "*" (fnmatch wildcard): the real, trusted Attester will sign
            # for ANY action string the caller describes -- deliberately
            # permissive, so this harness's attacker tooling can obtain
            # GENUINELY signed material bound to a DIFFERENT action than
            # ATTESTED_ACTION (test_b: wrong action binding), isolating
            # PreExecutionControl's own action-binding check from signature/
            # trust. This does not weaken anything: which action a REAL
            # deployment's Attester is willing to assess is a matter for
            # its own AssessmentProvider configuration (PR-4's own scope),
            # not something this test harness's permissiveness bears on.
            "*": {
                "evidence_type": EVIDENCE_TYPE, "claims": {"risk_class": default_claim_value},
                "provenance": {"model": "assurance-reference-provider"},
            },
        }, f)

    attester_port = free_port()
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        filter(None, [str(REPO_ROOT / "src"), str(REPO_ROOT), env.get("PYTHONPATH")])
    )
    env.update({
        "MCC_ATTESTER_ID": ATTESTER_ID,
        "MCC_ATTESTER_SIGNING_KEY_PATH": key_path,
        "MCC_ATTESTER_KEY_ID": attester_key.kid,
        "MCC_ATTESTER_SERVICE_AUTH_SECRET": ATTESTER_AUTH_SECRET,
        "MCC_ATTESTER_SCOPE_TEMPLATE": SCOPE_TEMPLATE,
        "MCC_ATTESTER_VALIDITY_SECONDS": str(validity_seconds),
        "MCC_ATTESTER_TEST_ASSESSMENT_TABLE": assessment_table_path,
        "MCC_ATTESTER_HOST": "127.0.0.1",
        "MCC_ATTESTER_PORT": str(attester_port),
    })
    attester_proc = subprocess.Popen(
        [sys.executable, "-m", "mcc_attester_service"], cwd=str(REPO_ROOT), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    attester_url = f"http://127.0.0.1:{attester_port}"
    _wait_ready(f"{attester_url}/health")

    # -- boot the real Gateway, configured to REQUIRE this attestation ----
    sut = build_system_under_test(
        require_consensus=False,
        extra_env={
            "MCC_ATTESTATION_REQUIREMENTS_CONFIG": configs["requirements"],
            "MCC_ATTESTATION_TRUST_CONFIG": configs["trust"],
        },
    )

    return AttestationSystemUnderTest(
        sut=sut, attester_url=attester_url, attester_public_key=attester_key.public_key(),
        attester_kid=attester_key.kid, _attester_process=_Process(attester_proc, attester_port),
        _tmpdir=tmpdir,
    )
