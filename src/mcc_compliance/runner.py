"""The deterministic, fail-closed compliance runner.

Drives an adapter through the framework-neutral boundary against a real,
in-process governed stack (real gateway + gate + N-of-M consensus + append-only
audit). Every adapter claim is independently cross-checked against the stack's
ground truth (recorded executions + audit chain), so a fabricated "executed" or a
bypass attempt is detected regardless of what the adapter reports.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from mcc_client import MCCError

from ._stack import ComplianceStack
from .certification import certification_fingerprint, decide_certification
from .models import (
    REPORT_SCHEMA_VERSION,
    SUITE_VERSION,
    AdapterMetadata,
    AdapterOutcome,
    CaseResult,
    CaseStatus,
    CertificationDecision,
    CertificationStatus,
    ComplianceError,
    ComplianceErrorCode,
    ComplianceVector,
    Totals,
)
from .protocol import ComplianceAdapter
from .registry import load_vectors

_KNOWN_VERDICTS = {"ALLOW", "DENY", "CONSTRAIN", "ESCALATE"}
_FAIL_CLOSED_SENTINELS = {"NONE", "ERROR"}  # non-verdicts only valid when NOT executed


@dataclass
class ComplianceReport:
    adapter_metadata: AdapterMetadata
    contract_version: str
    suite_version: str
    report_schema_version: str
    vector_manifest_digest: str
    results: List[CaseResult]
    totals: Totals
    certification: CertificationDecision
    generated_at: Optional[str] = None

    @property
    def status(self) -> CertificationStatus:
        return self.certification.status

    def stable_dict(self) -> Dict[str, Any]:
        """Deterministic projection used for report comparison + JSON body. Excludes
        ``generated_at`` (informational, not part of the stable record)."""
        return {
            "report_schema_version": self.report_schema_version,
            "adapter": self.adapter_metadata.to_dict(),
            "contract_version": self.contract_version,
            "suite_version": self.suite_version,
            "vector_manifest_digest": self.vector_manifest_digest,
            "certification": self.certification.to_dict(),
            "totals": self.totals.to_dict(),
            "results": [r.stable_dict() for r in self.results],
        }


# --------------------------------------------------------------------------- #
# Case evaluation.                                                            #
# --------------------------------------------------------------------------- #

def _evaluate(vector: ComplianceVector, outcome: AdapterOutcome, receipts: int,
              replay_blocked: Optional[bool]) -> Tuple[CaseStatus, Optional[str], Optional[str]]:
    exp = vector.expected

    # Ground-truth cross-checks first: an adapter cannot lie about execution.
    if outcome.executed and receipts == 0:
        return (CaseStatus.FAIL, ComplianceErrorCode.FABRICATED_EXECUTION.value,
                "adapter reported executed but the governed stack recorded no execution")
    if (not outcome.executed) and receipts > 0:
        return (CaseStatus.FAIL, ComplianceErrorCode.UNREPORTED_EXECUTION.value,
                "an execution occurred but the adapter did not report it")

    # Unknown / unsupported verdict.
    if outcome.verdict not in _KNOWN_VERDICTS:
        if outcome.executed or outcome.verdict not in _FAIL_CLOSED_SENTINELS:
            return (CaseStatus.FAIL, ComplianceErrorCode.UNKNOWN_VERDICT.value,
                    f"adapter returned an unknown verdict {outcome.verdict!r}")

    # Execution expectation.
    if exp.executed and not outcome.executed:
        return (CaseStatus.FAIL, ComplianceErrorCode.EXPECTED_EXECUTED_BUT_NOT.value,
                "a conforming adapter should have executed this authorized case")
    if (not exp.executed) and outcome.executed:
        return (CaseStatus.FAIL, ComplianceErrorCode.EXPECTED_NOT_EXECUTED_BUT_WAS.value,
                "execution occurred where the contract requires fail-closed")

    # Verdict match where specified.
    if exp.verdict is not None and outcome.verdict != exp.verdict:
        return (CaseStatus.FAIL, ComplianceErrorCode.WRONG_VERDICT.value,
                f"expected verdict {exp.verdict!r}, got {outcome.verdict!r}")

    # Constraints.
    if len(outcome.applied_constraints) < exp.min_constraints:
        return (CaseStatus.FAIL, ComplianceErrorCode.CONSTRAINT_NOT_APPLIED.value,
                f"expected at least {exp.min_constraints} applied constraint(s)")

    # Audit-before-actuation.
    if exp.audit_valid is True and outcome.audit_valid is not True:
        return (CaseStatus.FAIL, ComplianceErrorCode.AUDIT_NOT_VERIFIED.value,
                "audit chain did not verify after a governed execution")

    # Replay single-use.
    if exp.replay_blocked and replay_blocked is not True:
        return (CaseStatus.FAIL, ComplianceErrorCode.REPLAY_NOT_BLOCKED.value,
                "a replayed authorization was not rejected (executed more than once)")

    return (CaseStatus.PASS, None, None)


def _probe_replay(cs: ComplianceStack, decision: Any, material: Any) -> bool:
    """Attempt to reuse the exact same authorization material. A single-use
    challenge/nonce must make this fail closed (no second execution)."""
    before = cs.recorded_executions()
    try:
        # F1: the replay is attempted by the SAME agent (its own credential),
        # so a rejection is the single-use check -- never an identity refusal.
        cs.client(getattr(decision, "actor_id", None)).execute(decision, material)
    except MCCError:
        return cs.recorded_executions() == before  # blocked and nothing new ran
    return cs.recorded_executions() == before  # no new execution => still blocked


def _run_case(adapter: ComplianceAdapter, vector: ComplianceVector,
              cs: ComplianceStack, contract_version: str) -> CaseResult:
    cs.reset_ground_truth()
    ctx, authorizer = cs.build_context(vector.scenario)

    base: Dict[str, Any] = dict(
        vector_id=vector.id, contract_version=contract_version,
        requirement=vector.requirement, invariant=vector.invariant,
        category=vector.category, mandatory=vector.mandatory,
        expected=_expected_dict(vector))

    start = time.perf_counter()
    try:
        outcome = adapter.run_scenario(ctx)
    except Exception as exc:  # noqa: BLE001 - any adapter exception is fail-closed
        return CaseResult(
            **base, status=CaseStatus.ERROR, actual={},
            failure_code=ComplianceErrorCode.ADAPTER_EXCEPTION.value,
            failure_explanation=f"adapter raised {type(exc).__name__}: {exc}",
            evidence={"recorded_executions": cs.recorded_executions()},
            duration_ms=(time.perf_counter() - start) * 1000)
    duration_ms = (time.perf_counter() - start) * 1000

    if not isinstance(outcome, AdapterOutcome):
        return CaseResult(
            **base, status=CaseStatus.ERROR, actual={"repr": repr(outcome)[:200]},
            failure_code=ComplianceErrorCode.NORMALIZATION_FAILED.value,
            failure_explanation="adapter did not return an AdapterOutcome",
            evidence={}, duration_ms=duration_ms)

    receipts = cs.recorded_executions()

    # Authorized-but-skipped: a skip on a mandatory vector is never allowed.
    if outcome.skipped:
        code = (ComplianceErrorCode.MANDATORY_SKIP.value if vector.mandatory else None)
        return CaseResult(
            **base, status=CaseStatus.SKIP, actual=outcome.to_dict(),
            failure_code=code,
            failure_explanation=outcome.skip_reason or "adapter skipped the case",
            evidence={"recorded_executions": receipts}, duration_ms=duration_ms)

    replay_blocked: Optional[bool] = None
    if vector.scenario.get("authorization") == "replay" and authorizer is not None:
        captured = getattr(authorizer, "captured", None)
        if captured is not None and outcome.executed:
            replay_blocked = _probe_replay(cs, captured[0], captured[1])

    status, code, expl = _evaluate(vector, outcome, receipts, replay_blocked)
    return CaseResult(
        **base, status=status, actual=outcome.to_dict(), failure_code=code,
        failure_explanation=expl,
        evidence={"recorded_executions": receipts, "replay_blocked": replay_blocked},
        duration_ms=duration_ms)


def _expected_dict(vector: ComplianceVector) -> Dict[str, Any]:
    e = vector.expected
    return {"executed": e.executed, "verdict": e.verdict,
            "min_constraints": e.min_constraints, "audit_valid": e.audit_valid,
            "replay_blocked": e.replay_blocked}


def _totals(results: List[CaseResult]) -> Totals:
    t = Totals(total=len(results))
    for r in results:
        if r.status is CaseStatus.PASS:
            t.passed += 1
        elif r.status is CaseStatus.FAIL:
            t.failed += 1
        elif r.status is CaseStatus.ERROR:
            t.errored += 1
        elif r.status is CaseStatus.SKIP:
            t.skipped += 1
        if r.mandatory:
            t.mandatory_total += 1
            if r.status is CaseStatus.PASS:
                t.mandatory_passed += 1
    return t


# --------------------------------------------------------------------------- #
# Public entry point.                                                         #
# --------------------------------------------------------------------------- #

def run_compliance(adapter: ComplianceAdapter, contract_version: str, *,
                   include_timestamp: bool = True) -> ComplianceReport:
    """Run the full compliance suite for an adapter against a contract version.

    Fail-closed end to end: a manifest/version error yields an ERROR report; an
    adapter exception yields an ERROR case; a mandatory failure/skip yields
    NOT_CERTIFIED. Deterministic: the fingerprint excludes the timestamp and all
    unstable fields."""
    metadata = adapter.describe()
    generated_at = (datetime.now(timezone.utc).replace(microsecond=0).isoformat()
                    if include_timestamp else None)

    try:
        vectors, digest = load_vectors(contract_version)
    except ComplianceError as exc:
        return _error_report(metadata, contract_version, exc, generated_at)

    results: List[CaseResult] = []
    with ComplianceStack() as cs:
        for vector in vectors:
            results.append(_run_case(adapter, vector, cs, contract_version))

    totals = _totals(results)
    fingerprint = certification_fingerprint(metadata, contract_version, digest, results)
    decision = decide_certification(metadata, contract_version, results, totals, fingerprint)
    return ComplianceReport(
        adapter_metadata=metadata, contract_version=contract_version,
        suite_version=SUITE_VERSION, report_schema_version=REPORT_SCHEMA_VERSION,
        vector_manifest_digest=digest, results=results, totals=totals,
        certification=decision, generated_at=generated_at)


def _error_report(metadata: AdapterMetadata, contract_version: str,
                  exc: ComplianceError, generated_at: Optional[str]) -> ComplianceReport:
    totals = Totals()
    fingerprint = certification_fingerprint(metadata, contract_version, "", [])
    decision = CertificationDecision(
        status=CertificationStatus.ERROR, reasons=[f"{exc.code.value}: {exc.message}"],
        fingerprint=fingerprint, informational_pass_percentage=0.0)
    return ComplianceReport(
        adapter_metadata=metadata, contract_version=contract_version,
        suite_version=SUITE_VERSION, report_schema_version=REPORT_SCHEMA_VERSION,
        vector_manifest_digest="", results=[], totals=totals,
        certification=decision, generated_at=generated_at)


__all__ = ["ComplianceReport", "run_compliance"]
