"""V10 - Log tampering: can an agent hide or alter its audit trail."""
import hashlib
import json

from _harness import *
from mcc_core import AuditLog
from mcc_core.signing import canonical_bytes


def _run_three(s):
    m = s.mandate()
    for i in range(3):
        run(s.execute(m, idempotency_key=f"k-{i}", context=payment(amount=100 + i)))
    return [l for l in open(s.audit_path).read().splitlines() if l.strip()]


@attack(vector=10, severity="high", title="In-place edit of a recorded entry")
def test_edit_entry_detected():
    s = Stack()
    lines = _run_three(s)
    e = json.loads(lines[1]); e["action"] = "read_balance"
    lines[1] = json.dumps(e, sort_keys=True)
    open(s.audit_path, "w").write("\n".join(lines) + "\n")
    assert not AuditLog.verify_chain(s.audit_path)


@attack(vector=10, severity="high", title="Delete / reorder an entry in the middle of the chain")
def test_delete_middle_entry_detected():
    s = Stack()
    lines = _run_three(s)
    open(s.audit_path, "w").write("\n".join(lines[:2] + lines[3:]) + "\n")
    assert not AuditLog.verify_chain(s.audit_path)


@attack(vector=10, severity="high", kind="known-limitation",
        title="Tail truncation (drop the newest records) passes AuditLog.verify_chain")
def test_tail_truncation_detected_by_verify_chain():
    s = Stack()
    lines = _run_three(s)
    kept = lines[:-2]                               # hide the last execution (pre_actuation + result)
    open(s.audit_path, "w").write("\n".join(kept) + "\n")
    assert not AuditLog.verify_chain(s.audit_path), \
        f"chain verifies after dropping the last 2 of {len(lines)} records (no external anchor in verify_chain)"


@attack(vector=10, severity="high", kind="known-limitation",
        title="Self-consistent full rewrite (Scenario G) passes AuditLog.verify_chain")
def test_full_rewrite_detected_by_verify_chain():
    s = Stack()
    lines = _run_three(s)
    prev, out = "GENESIS", []
    for raw in lines:
        e = json.loads(raw)
        if e.get("kind") in ("pre_actuation", "actuation_result") and e.get("idempotency_key") == "k-1":
            continue                                 # erase one whole operation
        body = {k: v for k, v in e.items() if k not in ("hash", "prev_hash")}
        body["prev_hash"] = prev
        h = hashlib.sha256(prev.encode() + canonical_bytes(body)).hexdigest()
        out.append(json.dumps({**body, "hash": h}, sort_keys=True))
        prev = h
    open(s.audit_path, "w").write("\n".join(out) + "\n")
    assert not AuditLog.verify_chain(s.audit_path), \
        "rewritten chain with one operation erased verifies (entries are hash-linked, not signed/anchored)"


@attack(vector=10, severity="medium", title="Blocked attempts are recorded, not just successes")
def test_denied_attempts_are_audited():
    s = Stack()
    toks = spy_tokens(s)
    run(s.execute(s.mandate(), idempotency_key="k"))

    async def ex():
        s.executed.append(("REPLAY", {}))
    run(s.coordinator.enforce(token=toks[0], action=ACTION, payload=payment(), executor=ex))
    kinds = [json.loads(l).get("kind") for l in open(s.audit_path) if l.strip()]
    assert "actuation_rejected" in kinds, kinds


@attack(vector=10, severity="medium", kind="hardening",
        title="Requests rejected before token issuance leave no audit record")
def test_pre_token_denials_are_audited():
    s = Stack()
    run(s.execute(s.mandate(), idempotency_key="k", action="wire_swift"))          # out of scope
    run(s.execute(s.mandate(subject="agent/x"), idempotency_key="k2"))             # wrong subject
    try:
        n = len([l for l in open(s.audit_path) if l.strip()])
    except FileNotFoundError:
        n = 0
    assert n >= 2, f"{n} audit records for 2 denied execution attempts (probing is invisible in the chain)"
