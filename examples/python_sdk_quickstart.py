#!/usr/bin/env python3
"""Quickstart for the MCC-Core Python client SDK (``mcc_client``).

Runs self-contained against the real MCC gateway on loopback (the Pilot v0.1
environment), demonstrating the canonical integration path:

    Agent -> MCCClient -> MCC Gateway -> Governance Decision -> Execution Gate
          -> Governed Executor -> External System

It shows: client init; evaluation; ALLOW / DENY / ESCALATE / CONSTRAIN handling;
explicit governed execution; and that there is no direct executor / external
target access. No external credentials are required.

Run:  python examples/python_sdk_quickstart.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

# Configure the gateway BEFORE importing it: an operator key (so ESCALATE can be
# approved), inline enforcement, a private audit log, and a loopback external API.
_audit = tempfile.mkdtemp(prefix="sdk-quickstart-")
os.environ.setdefault("MCC_GATEWAY_OPERATOR_API_KEY", "op-key")
os.environ.setdefault("MCC_GATEWAY_MODE", "inline")
os.environ.setdefault("MCC_GATEWAY_AUDIT_LOG_PATH", os.path.join(_audit, "audit.jsonl"))

# V05/F1: each demo agent has its OWN credential; the gateway registry stores
# only SHA-256 hashes. Identity routes (/approvals, execute) and /evaluate as
# a registered agent require that agent's own key.
import json as _json  # noqa: E402
import secrets as _secrets  # noqa: E402

sys.path.insert(0, str(ROOT))
from gateway.agent_identity import hash_agent_key  # noqa: E402

AGENT_KEYS = {p: _secrets.token_urlsafe(24) for p in ("agent/payments-bot", "agent/nobody")}
_registry = os.path.join(_audit, "agent_credentials.json")
with open(_registry, "w", encoding="utf-8") as _f:
    _json.dump({"agents": [
        {"credential_id": f"quickstart-{i}", "tenant_id": "pilot", "principal_id": p,
         "key_sha256": hash_agent_key(k), "status": "active"}
        for i, (p, k) in enumerate(sorted(AGENT_KEYS.items()))]}, _f)
os.environ.setdefault("MCC_AGENT_CREDENTIALS_CONFIG", _registry)

from examples._demo_server import DemoServer  # noqa: E402
import pilot_api.app as pilot_app  # noqa: E402


def _free_port() -> int:
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def main() -> int:
    pilot_port = _free_port()
    os.environ.setdefault("MCC_UPSTREAM_BASE", f"http://127.0.0.1:{pilot_port}")

    import gateway.app as gw  # imported AFTER env is set
    from mcc_client import (
        MCCClient, Verdict, MCCDeniedError, MCCApprovalRequiredError, MCCError,
        MandateAuthorization,
    )

    servers = [DemoServer(pilot_app.app, pilot_port)]
    gw_port = _free_port()
    servers.append(DemoServer(gw.app, gw_port))
    for s in servers:
        s.start()

    try:
        # 1. Client initialization.
        base = f"http://127.0.0.1:{gw_port}"
        client = MCCClient(base, api_key=gw.settings.api_key, operator_key="op-key", timeout=10.0)

        def client_for(actor: str) -> MCCClient:
            """A registered agent uses its OWN key; other identities the shared one."""
            key = AGENT_KEYS.get(actor)
            return client if key is None else MCCClient(base, api_key=key, operator_key="op-key",
                                                        timeout=10.0)

        print("MCC-Core Python SDK quickstart\n" + "=" * 40)

        # 2/3/4/5/6. Evaluate — the four verdicts.
        cases = [
            ("agent/payments-bot", "send_payment", {"amount": 1000}),      # ALLOW
            ("agent/ops-bot", "delete_database", {}),                       # DENY
            ("agent/nobody", "send_payment", {"amount": 100}),             # ESCALATE
            ("agent/payments-bot", "send_payment", {"amount": 99000}),     # CONSTRAIN
        ]
        decisions = {}
        for actor, action, payload in cases:
            d = client_for(actor).evaluate(actor_id=actor, action=action, payload=payload)
            decisions[d.verdict] = d
            extra = ""
            if d.verdict == Verdict.CONSTRAIN:
                extra = f"  authoritative(constrained) payload={d.authorized_payload}"
            print(f"[{d.verdict.value:9}] {actor} {action} {payload}{extra}")

        # DENY: execution is refused by the SDK before any call.
        deny = decisions.get(Verdict.DENY)
        if deny is not None:
            try:
                client.execute(deny, MandateAuthorization(mandate={"unused": True}))
                print("  ! DENY unexpectedly executed")
            except MCCDeniedError as exc:
                print(f"  DENY cannot execute (SDK refused): {exc.reason[:50]}")

        # ESCALATE: no execution until approval; then explicit governed execution.
        esc = decisions.get(Verdict.ESCALATE)
        if esc is not None:
            client = client_for(esc.actor_id)      # the escalating agent itself
            try:
                client.execute(esc, MandateAuthorization(mandate={"unused": True}))
            except MCCApprovalRequiredError:
                print("  ESCALATE requires approval (SDK refused to execute)")
            approval = client.request_approval(esc)
            granted = client.approve(approval)          # operator action (mints a mandate)
            try:
                result = client.execute_after_approval(esc, granted)
                print(f"  ESCALATE -> approved -> governed execution: status={result.status}")
            except MCCError as exc:
                print(f"  ESCALATE -> approved -> governed path returned: {type(exc).__name__}")

        # 8. No direct executor / external-target access exists.
        assert not any(hasattr(client, n) for n in ("send", "call_external", "http", "request"))
        print("\nNo direct executor or external-target access — execution is only ever")
        print("through the governed gateway path. Proposal is not permission.")
        return 0
    finally:
        for s in servers:
            s.stop()


if __name__ == "__main__":
    sys.exit(main())
