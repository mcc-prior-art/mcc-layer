"""V09 - Fail-open: timeout, crash, malformed input."""
import os
import tempfile

import pytest
from _harness import *
from mcc_core.trusted_time import TimeTrustError, TrustedTimeSource


def _attempt(s, **kw):
    try:
        return run(s.execute(s.mandate(), idempotency_key="k", **kw))
    except Exception as exc:          # an unhandled exception is still "not executed"
        return exc


@attack(vector=9, severity="critical", title="Nonce registry down")
def test_nonce_backend_down():
    s = Stack(nonce_registry=Boom())
    _attempt(s)
    assert s.executed == []


@attack(vector=9, severity="critical", title="Idempotency registry down")
def test_idempotency_backend_down():
    s = Stack(idempotency=Boom())
    _attempt(s)
    assert s.executed == []


@attack(vector=9, severity="critical", title="Velocity registry down")
def test_velocity_backend_down():
    s = Stack(velocity_limits_for=pilot_limits_for())
    s.coordinator.velocity = Boom()
    _attempt(s)
    assert s.executed == []


@attack(vector=9, severity="critical", title="Revocation registry down at actuation")
def test_revocation_backend_down():
    s = Stack()
    s.coordinator.revocation_registry = Boom()
    try:
        run(s.execute(s.mandate(revocation_required=True), idempotency_key="k"))
    except Exception:
        pass
    assert s.executed == []


@attack(vector=9, severity="critical", title="Audit log unwritable (audit-before-actuation)")
def test_audit_unwritable():
    d = tempfile.mkdtemp(prefix="mcc-redteam-")
    s = Stack(audit_path=os.path.join(d, "audit.jsonl"))
    os.mkdir(s.audit_path)             # path is now a directory: every append fails
    _attempt(s)
    assert s.executed == []


@attack(vector=9, severity="critical", title="Trusted time source unavailable")
def test_time_source_down():
    class Dead(TrustedTimeSource):
        async def now(self):
            raise TimeTrustError("TIME_UNAVAILABLE", "ntp down")
    s = Stack()
    s.service.time_source = Dead()
    s.coordinator.time_source = Dead()
    s.gate.time_source = Dead()
    _attempt(s)
    assert s.executed == []


MALFORMED_MANDATES = [None, "", "ALLOW", [], {}, 0, True, {"kid": ["x"]}, {"kid": "issuer-1"},
                      {"kid": "issuer-1", "sig": "AAAA"}, {"kid": {"a": 1}, "sig": 1}]


@attack(vector=9, severity="critical", title="Malformed mandate objects")
@pytest.mark.parametrize("mandate", MALFORMED_MANDATES, ids=range(len(MALFORMED_MANDATES)))
def test_malformed_mandate(mandate):
    s = Stack()
    try:
        run(s.execute(mandate, idempotency_key="k"))
    except Exception:
        pass
    assert s.executed == []


MALFORMED_CTX = [{"amount": [1]}, {"amount": {"$gt": 0}}, {"amount": None}, {"amount": ""},
                 {"amount": "five"}]


@attack(vector=9, severity="high", title="Malformed payload field types")
@pytest.mark.parametrize("override", MALFORMED_CTX, ids=range(len(MALFORMED_CTX)))
def test_malformed_payload(override):
    s = Stack()
    _attempt(s, context=payment(**override))
    bad = [p for _, p in s.executed if not isinstance(p.get("amount"), (int, float))
           or not isinstance(p.get("currency"), str) or p.get("currency") in ("NONE", "")]
    assert bad == [], f"executed malformed payload {bad}"


@attack(vector=9, severity="low", kind="hardening",
        title="PaymentProfile coerces a null/non-string currency to text instead of rejecting it")
def test_null_currency_rejected():
    s = Stack()
    _attempt(s, context=payment(currency=None))
    assert s.executed == [], f"currency=None executed as {s.executed[0][1]['currency']!r}"


@attack(vector=9, severity="high", title="Missing idempotency key / tenant")
@pytest.mark.parametrize("kw", [dict(idempotency_key=None), dict(idempotency_key="  "),
                                dict(idempotency_key="k", tenant_id=None),
                                dict(idempotency_key="k", tenant_id="")], ids=range(4))
def test_missing_operation_identity(kw):
    s = Stack()
    key = kw.pop("idempotency_key")
    try:
        run(s.execute(s.mandate(), idempotency_key=key, **kw))
    except Exception:
        pass
    assert s.executed == []


@attack(vector=9, severity="high", title="Executor crash leaves the operation non-retryable")
def test_executor_crash_is_not_silently_retried():
    s = Stack(upstream_raises=True)
    m = s.mandate()
    run(s.execute(m, idempotency_key="k"))
    s.upstream_raises = False
    out = run(s.execute(m, idempotency_key="k"))
    assert len(s.executed) == 1, f"indeterminate operation re-dispatched ({out.reason})"
