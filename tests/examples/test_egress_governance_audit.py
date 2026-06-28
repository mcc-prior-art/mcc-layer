"""Governance invariants for the egress executor: audit-before-execution, the
extended-but-verifiable audit chain, and payload-hash binding.

Uses the consensus-mode harness (HTTP test upstream) so the full governed path
runs; the HTTPS hardening is covered separately in test_egress_https.py.
"""

import json
from pathlib import Path

from mcc_core import AuditLog
from tests._egress_harness import EgressHarness


def _allow(hz, *, txn="t1", idem="i1", amount=1000):
    url = hz.url("/charge")
    r1 = hz.post(method="POST", url=url, body={"amount": amount}, actor="agent/egress",
                 transaction_id=txn, idempotency_key=idem).json()
    action = hz.canonical(method="POST", url=url, body={"amount": amount})
    return hz.post(method="POST", url=url, body={"amount": amount}, actor="agent/egress",
                   transaction_id=txn, idempotency_key=idem, challenge_id=r1["challenge_id"],
                   votes=hz.votes(action, actor="agent/egress", nonce=r1["nonce"])).json()


def _entries(path):
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def test_audit_chain_extended_with_egress_metadata_and_verifiable():
    hz = EgressHarness()
    r = _allow(hz)
    assert r["outcome"] == "ALLOW" and r["executed"]
    path = hz.settings.audit_log_path
    assert AuditLog.verify_chain(path)  # extension preserves the hash chain
    entries = _entries(path)
    egress = [e for e in entries if e.get("kind") == "egress_execution"]
    assert egress, "no egress_execution audit entry"
    e = egress[-1]
    # Safe metadata present...
    for field in ("method", "host", "port", "selected_ip", "peer_ip", "tls_validated",
                  "status", "final_destination", "authorized_action_hash"):
        assert field in e, f"missing audit field {field}"
    assert e["status"] == 200 and e["selected_ip"] == "127.0.0.1" and e["peer_ip"] == "127.0.0.1"
    # ...and no secret-bearing fields are logged.
    blob = json.dumps(e).lower()
    for forbidden in ("authorization", "cookie", "x-api-key", "votes", "private", "secret"):
        assert forbidden not in blob


def test_pre_actuation_audit_precedes_egress_metadata():
    hz = EgressHarness()
    _allow(hz)
    kinds = [e.get("kind") for e in _entries(hz.settings.audit_log_path)]
    # The durable pre-actuation record is written before the egress call metadata,
    # which is written before the actuation result.
    assert "pre_actuation" in kinds and "egress_execution" in kinds and "actuation_result" in kinds
    assert kinds.index("pre_actuation") < kinds.index("egress_execution") < kinds.index("actuation_result")


def test_no_execution_when_durable_audit_fails():
    hz = EgressHarness()
    # Break the durable audit so pre-actuation cannot be confirmed.
    def boom(*a, **k):
        raise OSError("audit unavailable")
    hz.app.state.egress_service.rt.client.audit.append = boom
    r = _allow(hz, txn="ta", idem="ia")
    assert not r["executed"]
    assert hz.executor.count() == 0 and hz.seen == []


def test_executed_payload_matches_governed_hash():
    hz = EgressHarness()
    _allow(hz, txn="tm", idem="im")
    entries = _entries(hz.settings.audit_log_path)
    pre = [e for e in entries if e.get("kind") == "pre_actuation"][-1]
    egress = [e for e in entries if e.get("kind") == "egress_execution"][-1]
    # The executor acted on exactly the governed (gate-verified) payload hash.
    assert egress["authorized_action_hash"] == pre["payload_hash"]
    assert hz.executor.last().authorized_action_hash == pre["payload_hash"]
