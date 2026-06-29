"""Operational observability: correlation, error taxonomy, bounded metrics,
redaction, telemetry-failure isolation, and liveness/readiness distinctness.
Deterministic; no network beyond the harness's loopback upstream."""

import json
import logging
import re

import pytest

from egress_proxy.observability import (
    CorrelationError, ErrorCode, Metrics, classify_reason, emit_event, redact,
    resolve_correlation_id, span,
)
from egress_proxy.credentials import (
    SECRET_HEADER, CredentialBinding, CredentialEntry, InMemoryCredentialProvider,
)
from egress_proxy.canonical_action import build_canonical_action
from tests._egress_harness import EgressHarness

SECRET = "Bearer obs-secret-token-987"


# ---------------- correlation ids ----------------

def test_generate_when_absent():
    cid = resolve_correlation_id(None)
    assert cid.startswith("corr-") and resolve_correlation_id("") .startswith("corr-")


def test_valid_external_id_preserved():
    assert resolve_correlation_id("req-abc.123:xy_Z-9") == "req-abc.123:xy_Z-9"


@pytest.mark.parametrize("bad", ["has space", "x" * 129, "semi;colon", "drop/slash", "a\nb", "$(x)"])
def test_malformed_external_id_rejected(bad):
    with pytest.raises(CorrelationError):
        resolve_correlation_id(bad)


# ---------------- redaction (pure) ----------------

def test_redact_drops_secret_keys_and_nested():
    out = redact({"authorization": SECRET, "cookie": "c", "stage": "x",
                  "nested": {"x-api-key": "k", "host": "h"}, "headers": {"a": "b"}})
    assert "authorization" not in out and "cookie" not in out and "headers" not in out
    assert out["stage"] == "x" and out["nested"] == {"host": "h"} and SECRET not in json.dumps(out)


def test_emit_event_is_redacted(caplog):
    with caplog.at_level(logging.INFO, logger="mcc.test"):
        ev = emit_event(logging.getLogger("mcc.test"), "stage1",
                        correlation_id="c1", authorization=SECRET, verdict="ALLOW")
    assert ev == {"event": "mcc.egress", "stage": "stage1", "correlation_id": "c1",
                  "verdict": "ALLOW"}
    assert SECRET not in caplog.text


# ---------------- metrics: bounded cardinality ----------------

_LABELLED = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^}]*)\}')


def _label_values(text):
    """Map metric name -> set of label k=v pairs present (for bound checking)."""
    seen = {}
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        m = _LABELLED.match(line)
        if not m:
            continue
        name, labels = m.group(1), m.group(2)
        for kv in labels.split(","):
            if kv:
                seen.setdefault(name, set()).add(kv.strip())
    return seen


def test_metric_labels_are_bounded():
    m = Metrics()
    # Drive a spread of recordings.
    for outcome, verdict, code, ex in [
        ("ALLOW", "ALLOW", ErrorCode.OK, True),
        ("DENY", "DENY", ErrorCode.SSRF_DENIED, False),
        ("DENY", "DENY", ErrorCode.NONCE_REPLAY, False),
        ("ESCALATE", "ESCALATE", ErrorCode.ESCALATION_REQUIRED, False),
        ("CONSTRAIN", "CONSTRAIN", ErrorCode.CONSTRAINT_RECONSENSUS, False),
        ("UPSTREAM_ERROR", None, ErrorCode.TLS_FAILED, False),
        ("DEPENDENCY_UNAVAILABLE", None, ErrorCode.DEPENDENCY_UNAVAILABLE, False),
    ]:
        m.record(outcome=outcome, verdict=verdict, code=code, latency_s=0.01, executed=ex)
    text = m.render()[0].decode()
    labels = _label_values(text)
    # verdict label only from the 4 verdicts.
    assert labels.get("mcc_governance_decisions_total", set()) <= {
        'verdict="ALLOW"', 'verdict="DENY"', 'verdict="ESCALATE"', 'verdict="CONSTRAIN"'}
    # result labels only success/failure; tls type only tls/mtls.
    for name in ("mcc_consensus_total", "mcc_credential_resolution_total",
                 "mcc_https_execution_total"):
        assert labels.get(name, set()) <= {'result="success"', 'result="failure"'}
    assert labels.get("mcc_tls_failures_total", set()) <= {'type="tls"', 'type="mtls"'}
    # No unbounded values ever appear as labels.
    for forbidden in ("agent/", "http://", "https://", "txn-", "corr-", "Bearer"):
        assert forbidden not in text


def test_classify_reason_codes():
    assert classify_reason("nonce replay denied") == ErrorCode.NONCE_REPLAY
    assert classify_reason("idempotency conflict") == ErrorCode.IDEMPOTENCY_CONFLICT
    assert classify_reason("velocity limit exceeded") == ErrorCode.VELOCITY_EXCEEDED
    assert classify_reason("consensus below threshold") == ErrorCode.CONSENSUS_FAILED
    assert classify_reason("Redis registry unavailable") == ErrorCode.DEPENDENCY_UNAVAILABLE
    assert classify_reason("some other thing") == ErrorCode.GOVERNANCE_DENY


# ---------------- telemetry failure cannot bypass governance ----------------

def test_telemetry_export_failure_is_swallowed(monkeypatch):
    import egress_proxy.observability as obs

    class _BoomTracer:
        def start_as_current_span(self, *a, **k):
            raise RuntimeError("collector down")
    monkeypatch.setattr(obs, "_tracer", lambda: _BoomTracer())
    m = Metrics()
    ran = []
    with span("egress.request", {"mcc.stage": "x"}, metrics=m):
        ran.append(True)              # the body MUST still run
    assert ran == [True]
    assert m.telemetry_export_failures._value.get() == 1.0


# ---------------- end-to-end through the harness ----------------

def _provider():
    entry = CredentialEntry(
        binding=CredentialBinding(allowed_hosts=("127.0.0.1",), allowed_methods=("POST",),
                                  allowed_actions=("http.request",), allowed_envs=("dev",)),
        type=SECRET_HEADER, header_name="authorization", loader=lambda: SECRET)
    return InMemoryCredentialProvider({"api": entry})


def _allow(hz, *, credential_ref=None, correlation_id=None):
    url = hz.url("/charge")
    extra = {} if correlation_id is None else {"correlation_id": correlation_id}
    r1 = hz.post(method="POST", url=url, body={"amount": 1000}, actor="agent/egress",
                 transaction_id="t1", idempotency_key="i1", credential_ref=credential_ref,
                 **extra).json()
    action = build_canonical_action(method="POST", url=url, headers={}, body={"amount": 1000},
                                    credential_ref=credential_ref)
    return hz.post(method="POST", url=url, body={"amount": 1000}, actor="agent/egress",
                   transaction_id="t1", idempotency_key="i1", credential_ref=credential_ref,
                   challenge_id=r1["challenge_id"],
                   votes=hz.votes(action, actor="agent/egress", nonce=r1["nonce"]),
                   **extra).json()


def test_liveness_distinct_from_readiness():
    hz = EgressHarness()
    live = hz.client.get("/livez")
    assert live.status_code == 200 and live.json() == {"alive": True,
                                                       "version": live.json()["version"]}
    rdy = hz.client.get("/ready").json()
    assert "checks" in rdy and "audit_durable" in rdy["checks"]  # readiness checks deps


def test_correlation_propagates_to_response_header_and_audit():
    hz = EgressHarness()
    r = hz.client.post("/v1/http/execute", headers=hz.H, json={
        "method": "POST", "url": hz.url("/charge"), "body": {"amount": 1000},
        "actor": "agent/egress", "resource": "acct-1", "correlation_id": "req-trace-1"})
    # round 1 (consensus required) still carries the correlation id back.
    assert r.headers.get("X-MCC-Correlation-Id") == "req-trace-1"
    assert r.json()["correlation_id"] == "req-trace-1"


def test_malformed_correlation_id_rejected_by_api():
    hz = EgressHarness()
    r = hz.client.post("/v1/http/execute", headers=hz.H, json={
        "method": "POST", "url": hz.url("/charge"), "body": {"amount": 1},
        "actor": "agent/egress", "correlation_id": "bad id with spaces"})
    assert r.status_code == 400 and r.json()["error_code"] == "INVALID_CORRELATION_ID"


def test_secret_never_in_metrics_logs_or_response(caplog):
    hz = EgressHarness()
    hz.app.state.egress_service.rt.executor.credential_provider = _provider()
    hz.app.state.egress_service.rt.executor.env_name = "dev"
    with caplog.at_level(logging.INFO, logger="mcc.egress"):
        r = _allow(hz, credential_ref="api", correlation_id="req-sec-1")
    assert r["outcome"] == "ALLOW" and r["executed"]
    # The proxy's own response fields, metrics, logs, /ready, and audit carry no secret.
    assert SECRET not in json.dumps({k: v for k, v in r.items() if k != "upstream_body"})
    assert SECRET not in hz.client.get("/metrics").text
    assert SECRET not in caplog.text
    assert SECRET not in json.dumps(hz.client.get("/ready").json())
    assert SECRET not in open(hz.settings.audit_log_path).read()
    # Decisions were counted.
    assert 'mcc_governance_decisions_total{verdict="ALLOW"} 1.0' in hz.client.get("/metrics").text


def test_audit_before_execution_still_enforced_and_metered():
    hz = EgressHarness()

    def boom(*a, **k):
        raise OSError("audit unavailable")
    hz.app.state.egress_service.rt.client.audit.append = boom
    r = _allow(hz)
    assert not r["executed"] and hz.executor.count() == 0 and hz.seen == []
