# examples/agent_runtime_mcc.py

"""
MCC Agent Runtime Demonstration (Ed25519 decision tokens)

Shows:
- WITHOUT MCC -> actions execute on raw intent
- WITH MCC    -> actions execute only behind a verified decision token
  (fail-closed gate, replay protection, scope binding)

Self-contained demo: policy thresholds follow the rego canon
(ALLOW <= 5000, ESCALATE <= 10000, DENY > 10000). The in-memory nonce
client below is a demo-only stand-in for Redis.

Run:  python examples/agent_runtime_mcc.py
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcc_core import (
    DecisionEngine,
    ExecutionGate,
    NonceRegistry,
    SigningKey,
    TokenNotIssuable,
    Verdict,
)


# =========================
# TOOLS (real actions)
# =========================

def delete_user(intent):
    return f"EXECUTED: deleted user {intent.get('user_id')}"


def send_payment(intent):
    return f"EXECUTED: sent ${intent.get('amount')}"


tools = {
    "delete_user": delete_user,
    "send_payment": send_payment,
}


# =========================
# UNCONTROLLED EXECUTION
# =========================

def unsafe_execute(intent):
    action = intent.get("action")
    if action in tools:
        return tools[action](intent)
    return "UNKNOWN ACTION"


# =========================
# POLICY (rego canon thresholds)
# =========================

def decide(intent) -> Verdict:
    action = intent.get("action")
    if action == "send_payment":
        amount = float(intent.get("amount", 0))
        if amount <= 5000:
            return Verdict.ALLOW
        if amount <= 10000:
            return Verdict.ESCALATE
        return Verdict.DENY
    return Verdict.DENY  # deny-by-default, incl. delete_user


# =========================
# DEMO-ONLY NONCE BACKEND
# =========================

class InMemoryNonceClient:
    """Stand-in for redis.asyncio with SET NX EX semantics. Demo only."""

    def __init__(self):
        self._store = {}

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self._store:
            return None
        self._store[key] = value
        return True


# =========================
# MCC-BOUND RUNTIME
# =========================

class BoundRuntime:
    def __init__(self, tools):
        self.tools = tools
        self.signing_key = SigningKey.generate("demo-key-1")
        self.engine = DecisionEngine(
            signing_key=self.signing_key,
            issuer="mcc/demo",
            audience="demo-gate",
            policy_id="demo-policy",
            policy_hash="sha256:demo",
        )
        self.gate = ExecutionGate(
            trusted_keys={self.signing_key.kid: self.signing_key.public_key()},
            audience="demo-gate",
            nonce_registry=NonceRegistry(InMemoryNonceClient()),
            policy_hash="sha256:demo",
        )

    def run(self, intent):
        return asyncio.run(self._run(intent))

    async def _run(self, intent):
        action = intent.get("action")
        verdict = decide(intent)

        try:
            token = self.engine.issue_token(
                verdict=verdict,
                subject="agent/demo",
                action=action,
                payload=intent,
            )
        except TokenNotIssuable:
            return f"BLOCKED: {verdict.value} carries no execution authority"

        result = await self.gate.verify(token, action=action, payload=intent)
        if not result.allowed:
            return f"BLOCKED: {result.reason}"

        if action not in self.tools:
            return "UNKNOWN ACTION"
        return self.tools[action](intent)


# =========================
# DEMO
# =========================

if __name__ == "__main__":
    runtime = BoundRuntime(tools)

    cases = [
        {"action": "delete_user", "user_id": 1},
        {"action": "send_payment", "amount": 50000},
        {"action": "send_payment", "amount": 100},
    ]

    for case in cases:
        print("\n==============================")
        print("INPUT:", case)
        print("\nWITHOUT MCC:")
        print(unsafe_execute(case))
        print("\nWITH MCC:")
        print(runtime.run(case))
