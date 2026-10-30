"""Workstream J -- Mutation Testing (PR #71; extended by PR-5; extended by
Round 17).

A thin wrapper, like ``test_formal_model.py``: this does not touch the
live SUT (no ``sut`` fixture). It runs the real mutation harness
(``mutation.harness.run_all_mutants``) against all 44 targeted defects and
asserts 100% detection, so ``python -m assurance run`` surfaces the
mutation score in the same evidence bundle as every other workstream.

P2-A3 added 2 more: ``audit-integrity-dispatch-gate-disabled`` and
``audit-integrity-issuance-gate-disabled``, targeting the two independent
fail-closed enforcement boundaries added by that work -- see
``docs/AUDIT_INTEGRITY_ENFORCEMENT.md``.

The P2-A3 hardening round (independent review follow-up) added 2 more:
``audit-integrity-bootstrap-latch-disabled`` (the P1 fix -- a journal
deleted/truncated AFTER legitimate initialization must never be
re-accepted as a fresh trusted bootstrap) and
``audit-integrity-cross-worker-identity-check-disabled`` (a worker must
never inherit another worker's HEALTHY result for a DIFFERENT underlying
audit log) -- see ``docs/AUDIT_INTEGRITY_ENFORCEMENT.md``'s "Hardening
round" section.

The P2-A3 SECOND hardening round (independent review follow-up to the
follow-up) added 1 more: ``audit-integrity-write-path-identity-veto-disabled``
-- a content fingerprint alone (the prior defect above) cannot distinguish
two genuinely DIFFERENT physical audit logs cloned from the same initial
record; this defect targets the write-path physical-identity veto that is
the actual primary fix -- see ``docs/AUDIT_INTEGRITY_ENFORCEMENT.md``'s
"Second hardening round" section.

Round 17 added one more: ``idempotency-unsafe-release-after-dispatch``,
reintroducing the exact Round 16/17 defect Astra identified (releasing,
instead of marking UNKNOWN, the logical operation after a post-dispatch
executor exception) -- see ``docs/DURABLE_OPERATION_SAFETY.md``.

The original 26 = 13 hand-picked security defects + a later addition: an
exhaustive sweep of all 14 ``GateResult(False, ...)`` fail-open sites in
``src/mcc_core/gate.py`` (13 new + the pre-existing ``gate-fail-open``,
which already covered one of the 14 -- see ``mutation/defects.py``). That
addition closed a gap a direct-verification mutation-testing addendum
found: 2 of the 14 gate fail-open sites were not caught by a reasonable
hand-selected test oracle. Both are now permanently, individually asserted
here, not just informally re-checked once.

PR-5 added 12 more, closing the SAME kind of gap for the PR-1->4
attestation-to-execution chain (which the original 26 entirely predate):
attester trust/signature/action/payload/scope/expiry/replay checks, the
PR-3 TOCTOU fix, evidence_digest token binding and Gate enforcement, and
the Independent Attester Service's own schema-strictness and auth
ordering. See ``docs/ATTESTATION_INDEPENDENT_ASSURANCE.md`` §6 for the
full per-mutant table and the one candidate mutation class assessed and
deliberately not added (a physical statement-reordering mutation the
harness's exact-substring-replace mechanism cannot express as a single
well-formed edit).

Each mutant boots its own isolated repo copy and runs real pytest
subprocesses (see ``mutation/harness.py``), so this is slower than the
rest of the suite (~60-90s for all 39, several of the new PR-5 mutants'
detector tests being real multi-process assurance E2E tests) --
deliberately not folded into a tighter loop, since a mutation result
silently downgraded to "good enough" would defeat the entire point of
Workstream J.
"""

from __future__ import annotations

from mutation.harness import run_all_mutants


def test_j1_every_targeted_defect_is_detected():
    report = run_all_mutants(timeout=120.0)

    survived_detail = "\n".join(
        f"  - {r.defect_id}: {r.description}" for r in report.survived
    )
    assert not report.survived, (
        f"{len(report.survived)}/{report.total} targeted mutations SURVIVED "
        f"(not caught by their detector tests):\n{survived_detail}"
    )
    assert report.mutation_score == 1.0
    assert report.total == 44
