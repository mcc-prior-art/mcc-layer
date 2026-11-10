"""V14 - Key exposure: can agent/LLM context read or use a signing key."""
import json
import re

from _harness import *

RUNTIME_DIRS = ["gateway", "src/mcc_core", "egress_proxy", "interceptors", "src/mcc_agent", "pilot_api"]


@attack(vector=14, severity="critical", title="No runtime module serializes a private key")
def test_no_private_key_serialization_in_runtime():
    hits = []
    for d in RUNTIME_DIRS:
        for p in (ROOT / d).rglob("*.py"):
            for i, line in enumerate(p.read_text().splitlines(), 1):
                if re.search(r"private_bytes\(|_private_key\b(?!\s*=)", line) and "signing.py" not in p.name:
                    hits.append(f"{p.relative_to(ROOT)}:{i}")
    assert hits == [], f"private key material referenced outside signing.py: {hits}"


@attack(vector=14, severity="critical", title="Agent package holds no signing capability")
def test_agent_package_cannot_sign():
    hits = []
    for p in (ROOT / "src" / "mcc_agent").rglob("*.py"):
        text = p.read_text()
        if re.search(r"SigningKey|sign_token|issue_token|issue_mandate|DecisionEngine", text):
            hits.append(str(p.relative_to(ROOT)))
    assert hits == [], f"agent code references signing primitives: {hits}"


@attack(vector=14, severity="critical", title="No key material in outcomes, tokens or the audit chain")
def test_no_key_material_in_outputs():
    from cryptography.hazmat.primitives import serialization
    s = Stack()
    toks = spy_tokens(s)
    out = run(s.execute(s.mandate(), idempotency_key="k"))
    secrets = []
    for key in (s.signing_key, s.issuer_key, s.approver_key):
        raw = key._private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                             serialization.NoEncryption())
        import base64
        secrets += [raw.hex(), base64.b64encode(raw).decode()]
    blob = json.dumps([out.__dict__, toks, open(s.audit_path).read()], default=str)
    assert not any(sec in blob for sec in secrets)


@attack(vector=14, severity="medium", kind="hardening",
        title="Decision service starts with an ephemeral signing key when none is configured")
def test_service_refuses_to_start_without_configured_signing_key():
    src = (ROOT / "main.py").read_text()
    falls_back = "SigningKey.generate(settings.signing_key_id)" in src
    assert not falls_back, "main.py falls back to SigningKey.generate() (warning only) when MCC_SIGNING_KEY_PATH is unset"
