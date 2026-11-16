import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

# Keep test runs away from the repository's audit.jsonl prior-art chain,
# and keep main.py import free of any live OPA dependency.
os.environ.setdefault(
    "MCC_AUDIT_LOG_PATH",
    os.path.join(tempfile.mkdtemp(prefix="mcc-test-"), "audit.jsonl"),
)
os.environ.setdefault("MCC_USE_OPA", "false")

# Keep the gateway's audit log off the prior-art chain as well.
os.environ.setdefault(
    "MCC_GATEWAY_AUDIT_LOG_PATH",
    os.path.join(tempfile.mkdtemp(prefix="mcc-gw-test-"), "audit.jsonl"),
)

# F1b: module-level gateway.app and main.py now authenticate INDIVIDUAL
# principals (strict mode refuses the shared "demo-key" on every
# authority-issuing route). Give the test process a hash-only registry of the
# principals those tests act as; each presents its OWN key,
# tests._agent_credentials.module_key(principal). The shared key itself is
# never registered. Tests that need another registry pass their own env.
MODULE_TEST_PRINCIPALS = (
    "agent/payments-bot", "agent/ops-bot", "agent/nobody", "agent/x", "agent/a", "agent/b",
    "agent/alice", "agent/bob", "agent/notify-bot", "agent/unknown", "agent/intern",
    "agent/demo", "agent/t", "agent/s1", "agent/test", "agent/sess-1", "agent/axflow-clinic",
)


def _write_module_test_registry() -> str:
    import json as _json

    from mcc_core.agent_identity import hash_agent_key
    path = os.path.join(tempfile.mkdtemp(prefix="mcc-test-agents-"), "agents.json")
    with open(path, "w", encoding="utf-8") as f:
        _json.dump({"agents": [
            {"credential_id": f"module-test-{i}", "tenant_id": "pilot", "principal_id": p,
             "key_sha256": hash_agent_key(f"demo-key::agent::{p}"), "status": "active"}
            for i, p in enumerate(MODULE_TEST_PRINCIPALS)] + [
            # a REVOKED credential, for refusal tests (agent/revoked)
            {"credential_id": "module-test-revoked", "tenant_id": "pilot",
             "principal_id": "agent/revoked",
             "key_sha256": hash_agent_key("demo-key::agent::agent/revoked"), "status": "revoked"}]}, f)
    return path


os.environ.setdefault("MCC_AGENT_CREDENTIALS_CONFIG", _write_module_test_registry())
