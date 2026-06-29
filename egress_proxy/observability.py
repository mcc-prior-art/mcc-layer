"""Operational observability for the governed egress path.

This is instrumentation only — it never decides, authorizes, or alters governance.
It provides:

* **correlation IDs** — validate an externally-supplied id (safe charset) or
  generate one; propagated through the proposal, the runtime, the executor, and
  the audit chain. Never used as authorization input.
* **a stable error taxonomy** (:class:`ErrorCode`) with safe external messages —
  no raw exception text or stack traces leave the process.
* **redacted structured events** — machine-readable lifecycle records with only
  safe fields; never secrets/headers/bodies.
* **bounded-cardinality Prometheus metrics** — labels are drawn only from small,
  fixed sets (verdict, result, tls type, outcome, error code); never actor ids,
  URLs, transaction ids, credential refs, or arbitrary error text.
* **optional OpenTelemetry tracing hooks** — no-op when the package or a collector
  is absent; export failures are swallowed and can never affect a decision.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from contextlib import contextmanager
from enum import Enum
from typing import Any, Dict, Optional, Tuple

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

LOGGER = logging.getLogger("mcc.egress")

# --------------------------------------------------------------------------
# Correlation IDs
# --------------------------------------------------------------------------

# Conservative safe charset; bounded length. An externally-supplied id outside
# this is rejected (never sanitized-and-trusted).
CORRELATION_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")


class CorrelationError(ValueError):
    """An externally-supplied correlation id is malformed (rejected, fail-closed)."""


def resolve_correlation_id(raw: Optional[str]) -> str:
    """Return a valid correlation id: generate one when absent, validate when
    supplied. Raises :class:`CorrelationError` for a malformed external id.

    The correlation id is an observability handle only — it is never consulted in
    any authorization decision."""
    if raw is None or raw == "":
        return f"corr-{uuid.uuid4().hex}"
    if not CORRELATION_RE.match(raw):
        raise CorrelationError("malformed correlation id")
    return raw


# --------------------------------------------------------------------------
# Stable error taxonomy
# --------------------------------------------------------------------------

class ErrorCode(str, Enum):
    OK = "OK"
    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_CORRELATION_ID = "INVALID_CORRELATION_ID"
    GOVERNANCE_DENY = "GOVERNANCE_DENY"
    ESCALATION_REQUIRED = "ESCALATION_REQUIRED"
    CONSENSUS_REQUIRED = "CONSENSUS_REQUIRED"
    CONSENSUS_FAILED = "CONSENSUS_FAILED"
    CONSTRAINT_RECONSENSUS = "CONSTRAINT_RECONSENSUS"
    APPROVAL_INVALID = "APPROVAL_INVALID"
    MANDATE_INVALID = "MANDATE_INVALID"
    NONCE_REPLAY = "NONCE_REPLAY"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    VELOCITY_EXCEEDED = "VELOCITY_EXCEEDED"
    SSRF_DENIED = "SSRF_DENIED"
    REDIRECT_DENIED = "REDIRECT_DENIED"
    TLS_FAILED = "TLS_FAILED"
    MTLS_FAILED = "MTLS_FAILED"
    CREDENTIAL_DENIED = "CREDENTIAL_DENIED"
    CREDENTIAL_UNAVAILABLE = "CREDENTIAL_UNAVAILABLE"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    AUDIT_WRITE_FAILED = "AUDIT_WRITE_FAILED"
    UPSTREAM_TIMEOUT = "UPSTREAM_TIMEOUT"
    UPSTREAM_ERROR = "UPSTREAM_ERROR"
    RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"
    TELEMETRY_EXPORT_FAILED = "TELEMETRY_EXPORT_FAILED"
    READINESS_FAILED = "READINESS_FAILED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# Safe, fixed external messages — never raw exception text or stack traces.
SAFE_MESSAGE: Dict[ErrorCode, str] = {
    ErrorCode.INVALID_REQUEST: "request could not be canonicalized",
    ErrorCode.INVALID_CORRELATION_ID: "malformed correlation id",
    ErrorCode.GOVERNANCE_DENY: "governance denied the action",
    ErrorCode.ESCALATION_REQUIRED: "human approval required",
    ErrorCode.CONSENSUS_REQUIRED: "consensus evidence required",
    ErrorCode.CONSENSUS_FAILED: "consensus verification failed",
    ErrorCode.CONSTRAINT_RECONSENSUS: "action constrained; fresh authorization required",
    ErrorCode.APPROVAL_INVALID: "approval missing, expired, or invalid",
    ErrorCode.MANDATE_INVALID: "mandate validation failed",
    ErrorCode.NONCE_REPLAY: "request replay denied",
    ErrorCode.IDEMPOTENCY_CONFLICT: "idempotency conflict",
    ErrorCode.VELOCITY_EXCEEDED: "velocity limit exceeded",
    ErrorCode.SSRF_DENIED: "destination rejected",
    ErrorCode.REDIRECT_DENIED: "redirect rejected",
    ErrorCode.TLS_FAILED: "TLS verification failed",
    ErrorCode.MTLS_FAILED: "client identity / CA material invalid",
    ErrorCode.CREDENTIAL_DENIED: "credential not authorized",
    ErrorCode.CREDENTIAL_UNAVAILABLE: "credential unavailable",
    ErrorCode.DEPENDENCY_UNAVAILABLE: "a required dependency is unavailable",
    ErrorCode.AUDIT_WRITE_FAILED: "audit could not be durably written",
    ErrorCode.UPSTREAM_TIMEOUT: "upstream timed out",
    ErrorCode.UPSTREAM_ERROR: "upstream transport error",
    ErrorCode.RESPONSE_TOO_LARGE: "response too large",
    ErrorCode.TELEMETRY_EXPORT_FAILED: "telemetry export failed",
    ErrorCode.READINESS_FAILED: "not ready",
    ErrorCode.INTERNAL_ERROR: "internal error",
}


def safe_message(code: ErrorCode) -> str:
    return SAFE_MESSAGE.get(code, "error")


# Keyword -> error code mapping for governance-layer denials whose category is
# only available as a (safe, internal) reason string. Used for metrics/codes
# only — never for any authorization decision.
def classify_reason(reason: Optional[str]) -> ErrorCode:
    r = (reason or "").lower()
    if "replay" in r or "nonce" in r or "already consumed" in r:
        return ErrorCode.NONCE_REPLAY
    if "idempot" in r:
        return ErrorCode.IDEMPOTENCY_CONFLICT
    if "velocity" in r:
        return ErrorCode.VELOCITY_EXCEEDED
    if "consensus" in r:
        return ErrorCode.CONSENSUS_FAILED
    if "approval" in r:
        return ErrorCode.APPROVAL_INVALID
    if "mandate" in r:
        return ErrorCode.MANDATE_INVALID
    if "audit-before-actuation" in r or "audit" in r and "fail" in r:
        return ErrorCode.AUDIT_WRITE_FAILED
    if "redis" in r or "registry unavailable" in r or "could not reserve" in r:
        return ErrorCode.DEPENDENCY_UNAVAILABLE
    return ErrorCode.GOVERNANCE_DENY


# Executor error categories (set on egress_proxy.executor pop_error) -> codes.
EXECUTOR_CATEGORY_TO_CODE: Dict[str, ErrorCode] = {
    "SSRF_DENIED": ErrorCode.SSRF_DENIED,
    "SCHEME_DENIED": ErrorCode.SSRF_DENIED,
    "REDIRECT_DENIED": ErrorCode.REDIRECT_DENIED,
    "CREDENTIAL_DENIED": ErrorCode.CREDENTIAL_DENIED,
    "TLS_FAILED": ErrorCode.TLS_FAILED,
    "MTLS_FAILED": ErrorCode.MTLS_FAILED,
    "UPSTREAM_TIMEOUT": ErrorCode.UPSTREAM_TIMEOUT,
    "UPSTREAM_ERROR": ErrorCode.UPSTREAM_ERROR,
    "DENY": ErrorCode.SSRF_DENIED,
}


# --------------------------------------------------------------------------
# Redacted structured events
# --------------------------------------------------------------------------

# Never emit these keys; and scrub any value that looks secret-bearing.
_FORBIDDEN_KEYS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key",
    "x-operator-key", "api-key", "headers", "body", "upstream_body", "votes",
    "credential", "secret", "token", "password", "private_key", "cert_pem",
    "key_pem", "ca_pem", "value",
})


def _safe_value(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: _safe_value(val) for k, val in v.items() if k.lower() not in _FORBIDDEN_KEYS}
    if isinstance(v, (list, tuple)):
        return [_safe_value(x) for x in v][:32]
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return str(type(v).__name__)


def redact(fields: Dict[str, Any]) -> Dict[str, Any]:
    """Drop forbidden keys and reduce values to safe primitives."""
    return {k: _safe_value(val) for k, val in fields.items() if k.lower() not in _FORBIDDEN_KEYS}


def emit_event(logger: logging.Logger, stage: str, *, level: int = logging.INFO,
               **fields: Any) -> Dict[str, Any]:
    """Emit one machine-readable, redacted lifecycle event (JSON). Returns the
    (redacted) event dict so callers/tests can inspect it. Operational logs do not
    replace the durable audit chain."""
    event = redact({"event": "mcc.egress", "stage": stage, **fields})
    try:
        logger.log(level, json.dumps(event, sort_keys=True, default=str))
    except Exception:  # noqa: BLE001 — logging must never break the request path
        pass
    return event


# --------------------------------------------------------------------------
# Bounded-cardinality metrics
# --------------------------------------------------------------------------

_VERDICTS = ("ALLOW", "DENY", "ESCALATE", "CONSTRAIN")
_LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10)


class Metrics:
    """All metrics bound to a private registry (isolated per app / test)."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        r = self.registry
        self.decisions = Counter("mcc_governance_decisions_total",
                                 "Governance decisions by verdict.", ["verdict"], registry=r)
        self.decision_latency = Histogram("mcc_governance_decision_latency_seconds",
                                          "Governance+execution latency.", buckets=_LATENCY_BUCKETS,
                                          registry=r)
        self.requests = Counter("mcc_egress_requests_total",
                                "Egress requests by terminal outcome.", ["outcome"], registry=r)
        self.consensus = Counter("mcc_consensus_total", "Consensus results.",
                                 ["result"], registry=r)
        self.approval_latency = Histogram("mcc_approval_latency_seconds",
                                          "Approval round-trip latency.", buckets=_LATENCY_BUCKETS,
                                          registry=r)
        self.approvals_expired = Counter("mcc_approvals_expired_total",
                                         "Approvals that expired.", registry=r)
        self.mandate_failures = Counter("mcc_mandate_validation_failures_total",
                                        "Mandate validation failures.", registry=r)
        self.nonce_replays = Counter("mcc_nonce_replay_denials_total",
                                     "Nonce replay denials.", registry=r)
        self.idempotency_conflicts = Counter("mcc_idempotency_conflicts_total",
                                             "Idempotency conflicts.", registry=r)
        self.velocity_violations = Counter("mcc_velocity_violations_total",
                                           "Velocity-limit violations.", registry=r)
        self.redis_failures = Counter("mcc_redis_failures_total",
                                      "Redis/registry failures observed.", registry=r)
        self.redis_up = Gauge("mcc_redis_up", "1 if Redis is reachable at last check.",
                              registry=r)
        self.credential_resolution = Counter("mcc_credential_resolution_total",
                                             "Credential resolution outcomes.", ["result"],
                                             registry=r)
        self.https_execution = Counter("mcc_https_execution_total",
                                       "HTTPS execution outcomes.", ["result"], registry=r)
        self.tls_failures = Counter("mcc_tls_failures_total", "TLS/mTLS failures.",
                                    ["type"], registry=r)
        self.redirect_denials = Counter("mcc_redirect_denials_total",
                                        "Redirect denials.", registry=r)
        self.ssrf_denials = Counter("mcc_ssrf_denials_total",
                                    "SSRF/DNS validation denials.", registry=r)
        self.audit_write_failures = Counter("mcc_audit_write_failures_total",
                                            "Durable audit write failures.", registry=r)
        self.failclosed_dependency = Counter("mcc_failclosed_dependency_total",
                                             "Fail-closed denials caused by a dependency failure.",
                                             registry=r)
        self.correlation_rejected = Counter("mcc_correlation_rejected_total",
                                            "Malformed correlation ids rejected.", registry=r)
        self.telemetry_export_failures = Counter("mcc_telemetry_export_failures_total",
                                                 "Telemetry export failures.", registry=r)
        self.readiness = Gauge("mcc_readiness_ready", "1 if the last readiness probe passed.",
                               registry=r)
        # Pre-initialize bounded label series so they appear at 0.
        for v in _VERDICTS:
            self.decisions.labels(verdict=v)
        for res in ("success", "failure"):
            self.consensus.labels(result=res)
            self.credential_resolution.labels(result=res)
            self.https_execution.labels(result=res)
        for t in ("tls", "mtls"):
            self.tls_failures.labels(type=t)

    # ---- the single recording entry point ----

    def record(self, *, outcome: str, verdict: Optional[str], code: ErrorCode,
               latency_s: float, executed: bool) -> None:
        """Record one terminal request. ``outcome`` and ``verdict`` are bounded;
        ``code`` is the stable taxonomy; no unbounded labels are used."""
        self.requests.labels(outcome=str(outcome)).inc()
        self.decision_latency.observe(max(0.0, latency_s))
        if verdict in _VERDICTS:
            self.decisions.labels(verdict=verdict).inc()
        if executed:
            self.https_execution.labels(result="success").inc()
            self.consensus.labels(result="success").inc() if verdict in ("ALLOW", "CONSTRAIN") else None
            self.credential_resolution.labels(result="success").inc() if code == ErrorCode.OK else None
        _CODE_HOOK = {
            ErrorCode.SSRF_DENIED: self.ssrf_denials.inc,
            ErrorCode.REDIRECT_DENIED: self.redirect_denials.inc,
            ErrorCode.NONCE_REPLAY: self.nonce_replays.inc,
            ErrorCode.IDEMPOTENCY_CONFLICT: self.idempotency_conflicts.inc,
            ErrorCode.VELOCITY_EXCEEDED: self.velocity_violations.inc,
            ErrorCode.MANDATE_INVALID: self.mandate_failures.inc,
            ErrorCode.AUDIT_WRITE_FAILED: self.audit_write_failures.inc,
            ErrorCode.CONSENSUS_FAILED: lambda: self.consensus.labels(result="failure").inc(),
            ErrorCode.CREDENTIAL_DENIED: lambda: self.credential_resolution.labels(result="failure").inc(),
            ErrorCode.CREDENTIAL_UNAVAILABLE: lambda: self.credential_resolution.labels(result="failure").inc(),
            ErrorCode.TLS_FAILED: lambda: (self.tls_failures.labels(type="tls").inc(),
                                           self.https_execution.labels(result="failure").inc()),
            ErrorCode.MTLS_FAILED: lambda: (self.tls_failures.labels(type="mtls").inc(),
                                            self.https_execution.labels(result="failure").inc()),
            ErrorCode.UPSTREAM_TIMEOUT: lambda: self.https_execution.labels(result="failure").inc(),
            ErrorCode.UPSTREAM_ERROR: lambda: self.https_execution.labels(result="failure").inc(),
        }
        hook = _CODE_HOOK.get(code)
        if hook:
            hook()
        if code == ErrorCode.DEPENDENCY_UNAVAILABLE:
            self.redis_failures.inc()
            self.failclosed_dependency.inc()

    def render(self) -> Tuple[bytes, str]:
        return generate_latest(self.registry), CONTENT_TYPE_LATEST


# --------------------------------------------------------------------------
# Optional OpenTelemetry tracing (no-op without the package / a collector)
# --------------------------------------------------------------------------

_SAFE_SPAN_ATTRS = frozenset({"mcc.stage", "mcc.outcome", "mcc.verdict", "mcc.error_code",
                              "mcc.correlation_id", "http.method", "mcc.host", "mcc.status"})


def _tracer():
    try:
        from opentelemetry import trace  # type: ignore
        return trace.get_tracer("mcc.egress")
    except Exception:  # noqa: BLE001 — OTel is optional
        return None


def _note_export_failure(metrics: Optional[Metrics]) -> None:
    if metrics is not None:
        try:
            metrics.telemetry_export_failures.inc()
        except Exception:  # noqa: BLE001
            pass


@contextmanager
def span(name: str, attributes: Optional[Dict[str, Any]] = None, *,
         metrics: Optional[Metrics] = None):
    """A tracing span that is a no-op when OpenTelemetry (or a collector) is
    absent. Span creation/attribute/finish failures are swallowed and counted —
    telemetry can never authorize execution, bypass governance, retry, or change a
    decision. The wrapped body always runs (exactly one yield)."""
    tracer = _tracer()
    cm = None
    sp = None
    if tracer is not None:
        safe = {k: v for k, v in (attributes or {}).items() if k in _SAFE_SPAN_ATTRS}
        try:  # pragma: no cover - exercised only with OTel installed
            cm = tracer.start_as_current_span(str(name))
            sp = cm.__enter__()
            for k, v in safe.items():
                sp.set_attribute(k, v)
        except Exception:  # noqa: BLE001 — never break the path
            cm = None
            sp = None
            _note_export_failure(metrics)
    try:
        yield sp
    finally:
        if cm is not None:  # pragma: no cover - needs OTel
            try:
                cm.__exit__(None, None, None)
            except Exception:  # noqa: BLE001
                _note_export_failure(metrics)
