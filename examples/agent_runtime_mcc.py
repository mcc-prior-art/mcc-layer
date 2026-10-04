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

Authority principal separation: the agent and the MCC authority are
genuinely separate OS PROCESSES (via ``multiprocessing``), not just
separate objects sharing one process. ``AgentRuntimeClient`` -- what the
"WITH MCC" demo code below actually holds -- never imports or constructs
``SigningKey`` / ``DecisionEngine`` / ``ExecutionGate``; it only sends an
intent across a pipe to a separate process and receives back a result
string. Even a fully compromised agent process has no access to the
signing key, the decision engine, or the gate: none of them are ever
created in that process's memory. Only ``_authority_process`` -- which
runs as its own forked process -- constructs them, once, inside its own
function body.

Run:  python examples/agent_runtime_mcc.py
"""

import multiprocessing as mp
import sys
from pathlib import Path
from typing import Any, Dict

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


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

def decide(intent):
    # Imported lazily inside the authority process too (see below); also
    # used here as a pure function with no MCC-Core objects involved, so
    # it is safe to keep at module level (shared by both processes via
    # fork, but it holds no credential or secret state).
    from mcc_core import Verdict

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
# THE AUTHORITY -- runs in its OWN, separate OS process.
# =========================

def _authority_process(conn) -> None:
    """Entry point for the authority's OWN process (started via
    ``multiprocessing.Process``). Constructs the signing key, decision
    engine, and execution gate HERE -- after the fork, inside this
    function's local scope -- so they exist ONLY in this process's
    memory. The agent process that spawned this one never calls any of
    these constructors itself and holds no reference to the resulting
    objects: it only has ``conn``'s peer end, over which it can send a
    plain-dict intent and receive back a plain-string result.
    """
    import asyncio

    from mcc_core import DecisionEngine, ExecutionGate, NonceRegistry, SigningKey, TokenNotIssuable

    signing_key = SigningKey.generate("demo-key-1")
    engine = DecisionEngine(
        signing_key=signing_key,
        issuer="mcc/demo",
        audience="demo-gate",
        policy_id="demo-policy",
        policy_hash="sha256:demo",
    )
    gate = ExecutionGate(
        trusted_keys={signing_key.kid: signing_key.public_key()},
        audience="demo-gate",
        nonce_registry=NonceRegistry(InMemoryNonceClient()),
        policy_hash="sha256:demo",
    )

    async def handle(intent: Dict[str, Any]) -> str:
        action = intent.get("action")
        verdict = decide(intent)

        try:
            token = engine.issue_token(
                verdict=verdict,
                subject="agent/demo",
                action=action,
                payload=intent,
                # Optional, explicit replay-protection nonce: if the caller
                # supplies one (unused by the three cases in __main__
                # below, which never set it), reusing it a second time is
                # rejected by the gate's nonce registry -- demonstrating
                # that replay protection holds across the process
                # boundary too, not just within one process.
                nonce=intent.get("nonce"),
            )
        except TokenNotIssuable:
            return f"BLOCKED: {verdict.value} carries no execution authority"

        result = await gate.verify(token, action=action, payload=intent)
        if not result.allowed:
            return f"BLOCKED: {result.reason}"

        if action not in tools:
            return "UNKNOWN ACTION"
        return tools[action](intent)

    while True:
        intent = conn.recv()
        if intent is None:  # shutdown signal
            break
        conn.send(asyncio.run(handle(intent)))
    conn.close()


class AgentRuntimeClient:
    """What the AGENT side holds. No SigningKey, DecisionEngine, or
    ExecutionGate -- only a pipe to a separate authority process it
    spawns. This class cannot complete its own authorization path: it has
    no method that issues or verifies a token, because it never has
    access to the objects that do."""

    def __init__(self) -> None:
        self._parent_conn, child_conn = mp.Pipe()
        self._proc = mp.Process(target=_authority_process, args=(child_conn,), daemon=True)
        self._proc.start()

    def run(self, intent: Dict[str, Any]) -> str:
        self._parent_conn.send(intent)
        return self._parent_conn.recv()

    def close(self) -> None:
        try:
            self._parent_conn.send(None)
        except (BrokenPipeError, OSError):
            pass
        self._proc.join(timeout=2)


# =========================
# DEMO
# =========================

if __name__ == "__main__":
    client = AgentRuntimeClient()
    try:
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
            print("\nWITH MCC (separate authority process):")
            print(client.run(case))
    finally:
        client.close()
