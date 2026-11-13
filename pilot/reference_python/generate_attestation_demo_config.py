"""Generate LOCAL, self-contained demo keys and configs for the
attestation-aware full-chain reference pilot (PR-6).

Mirrors ``deploy/pilot/generate_pilot_config.py``'s existing convention
exactly (same key format, same "public keys only in JSON trust configs"
rule) rather than inventing a second one. Writes everything into
``pilot/reference_python/.secrets-attestation-demo/`` (git-ignored -- see
``pilot/reference_python/.gitignore``):

    attester_signing.pem            the DEMO Attester's Ed25519 signing key
    mandate_issuer_signing.pem      a DEMO mandate issuer key
    attestation_requirements.json   for MCC_ATTESTATION_REQUIREMENTS_CONFIG
    attestation_trust.json          for MCC_ATTESTATION_TRUST_CONFIG
    mandate_trust.json              for MCC_TRUST_CONFIG (mandate trust set)
    demo_assessment_table.json      for MCC_ATTESTER_TEST_ASSESSMENT_TABLE
    demo_mandate.json               ONE demo mandate, signed, ready to pass
                                     to AttestationChainPilot.submit(mandate=...)

This is demo/operator tooling, exactly like ``deploy/pilot/generate_pilot_config.py``
-- it is NOT part of the AttestationChainPilot integration surface itself
(which never mints a mandate; see ``attestation_integration.py``'s module
docstring), and it is NOT a production key-management procedure. The
DETERMINISTIC test provider this demo wires the Attester to
(``mcc_attester_service.provider.DeterministicTestProvider``) is reference/
test infrastructure only -- see ``docs/PILOT_RUNBOOK.md`` §18 and
``specs/MCC-AT-004.md`` for the explicit "not a production assessment
provider" disclaimer.

Usage:
    python -m pilot.reference_python.generate_attestation_demo_config [--force]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SECRETS = HERE / ".secrets-attestation-demo"
sys.path.insert(0, str(ROOT / "src"))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcc_core import SigningKey
from mcc_core.mandate import issue_mandate

DEMO_ACTION = "send_notification"
DEMO_RESOURCE = "notifications"
DEMO_ATTESTER_ID = "pilot-demo-attester.risk.v1"
DEMO_EVIDENCE_TYPE = "risk_assessment"
DEMO_SCOPE_TEMPLATE = "notify:{resource}"
DEMO_MANDATE_ISSUER_ID = "pilot-demo-mandate-issuer"
DEMO_ATTESTER_AUTH_SECRET = "pilot-demo-attester-auth-secret-CHANGE-ME"
FAR_FUTURE = 4_102_444_800  # 2100-01-01T00:00:00Z


def _write_key(path: Path, force: bool) -> SigningKey:
    if path.exists() and not force:
        sys.exit(f"refusing to overwrite existing key: {path} (use --force)")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    if path.exists():
        path.unlink()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    return SigningKey.from_pem_file(str(path), path.stem)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--mandate-subject", default="pilot-demo-partner")
    # V05: a strict-tenant gateway (the default) only accepts a mandate whose
    # signed tenant_id equals its own MCC_GATEWAY_TENANT_ID ("pilot" unless set).
    ap.add_argument("--tenant-id", default="pilot",
                    help="the pilot gateway's MCC_GATEWAY_TENANT_ID (default: pilot)")
    args = ap.parse_args()

    SECRETS.mkdir(parents=True, exist_ok=True)
    os.chmod(SECRETS, 0o700)

    attester_key = _write_key(SECRETS / "attester_signing.pem", args.force)
    mandate_issuer_key = _write_key(SECRETS / "mandate_issuer_signing.pem", args.force)

    (SECRETS / "attestation_requirements.json").write_text(json.dumps([{
        "action": DEMO_ACTION, "evidence_type": DEMO_EVIDENCE_TYPE,
        "scope": DEMO_SCOPE_TEMPLATE, "require_payload_binding": True,
        "require_policy_binding": False,
        "required_claims": {"risk_class": ["low"]},
    }], indent=2) + "\n")

    (SECRETS / "attestation_trust.json").write_text(json.dumps([{
        "attester_id": DEMO_ATTESTER_ID, "kid": attester_key.kid,
        "public_key_b64": attester_key.public_key_b64(),
        "evidence_types": [DEMO_EVIDENCE_TYPE],
    }], indent=2) + "\n")

    (SECRETS / "mandate_trust.json").write_text(json.dumps({
        "issuers": [{
            "issuer_id": DEMO_MANDATE_ISSUER_ID, "enabled": True,
            "keys": [{"kid": mandate_issuer_key.kid,
                      "public_key_b64": mandate_issuer_key.public_key_b64(),
                      "not_after": None}],
        }],
    }, indent=2) + "\n")

    (SECRETS / "demo_assessment_table.json").write_text(json.dumps({
        DEMO_ACTION: {
            "evidence_type": DEMO_EVIDENCE_TYPE, "claims": {"risk_class": "low"},
            "provenance": {"model": "pilot-reference-demo-provider"},
        },
    }, indent=2) + "\n")

    now = int(time.time())
    demo_mandate = issue_mandate(
        mandate_issuer_key, issuer=DEMO_MANDATE_ISSUER_ID, subject=args.mandate_subject,
        action_scope=[DEMO_ACTION], resource_scope=[DEMO_RESOURCE],
        not_before=now, not_after=now + 30 * 24 * 3600,
        tenant_id=args.tenant_id,
    )
    (SECRETS / "demo_mandate.json").write_text(json.dumps(demo_mandate, indent=2) + "\n")

    print(f"wrote demo attestation-chain config to {SECRETS}")
    print()
    print("Attester service env (see docs/PILOT_RUNBOOK.md §18):")
    print(f"  MCC_ATTESTER_ID={DEMO_ATTESTER_ID}")
    print(f"  MCC_ATTESTER_SIGNING_KEY_PATH={SECRETS / 'attester_signing.pem'}")
    print(f"  MCC_ATTESTER_KEY_ID={attester_key.kid}")
    print(f"  MCC_ATTESTER_SERVICE_AUTH_SECRET={DEMO_ATTESTER_AUTH_SECRET}")
    print(f"  MCC_ATTESTER_SCOPE_TEMPLATE={DEMO_SCOPE_TEMPLATE}")
    print("  MCC_ATTESTER_VALIDITY_SECONDS=900")
    print(f"  MCC_ATTESTER_TEST_ASSESSMENT_TABLE={SECRETS / 'demo_assessment_table.json'}")
    print()
    print("Gateway env (in addition to its own normal startup config):")
    print(f"  MCC_ATTESTATION_REQUIREMENTS_CONFIG={SECRETS / 'attestation_requirements.json'}")
    print(f"  MCC_ATTESTATION_TRUST_CONFIG={SECRETS / 'attestation_trust.json'}")
    print(f"  MCC_TRUST_CONFIG={SECRETS / 'mandate_trust.json'}")
    print()
    print(f"Demo mandate (pass to attestation_runner.py --mandate-file): "
          f"{SECRETS / 'demo_mandate.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
