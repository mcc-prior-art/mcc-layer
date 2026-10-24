"""Live demonstration scenarios, each driving the REAL MCC-Core gateway.

Every scenario in ``SCENARIOS`` below is a thin sequence of calls through
``pilot.client.MCCGatewayClient`` (the repository's existing, supported,
transport-only HTTP client) against the real running ``gateway.app``
process started by :mod:`runtime`. No scenario computes, predicts,
hard-codes, or overrides a decision, a token, a gate verdict, or an audit
result -- every field shown to the browser is copied verbatim from the
gateway's own HTTP responses.

The four authority verdicts (ALLOW/DENY/ESCALATE/CONSTRAIN) are produced by
``POST /evaluate`` against the real, unmodified ``gateway/pilot_policy.py``.
Governed execution (Stage 4/5) always runs the ONE existing coordinator
path via ``POST /consensus/execute`` -- the same mandatory N-of-M
consensus + gateway-issued challenge + fail-closed gate + audit-before-
actuation sequence proven, over real HTTP, by
``tests/test_consensus_enforcement_http.py`` and
``tests/test_challenge_http.py``. The four required attack scenarios
(replay / tamper / expired / bad signature) reuse those exact, already-
tested mechanisms -- nothing new is invented, and nothing is simulated in
the frontend.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

_HERE = Path(__file__).resolve()
ROOT = _HERE.parents[3]
for _p in (str(ROOT),):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from mcc_core import issue_vote  # noqa: E402 -- public "evaluator" primitive, not governance logic

from pilot.client import Decision, ExecutionOutcome, MCCGatewayClient, ProposalResult  # noqa: E402

from .runtime import DemoRuntime

FAR_FUTURE = 4_000_000_000


def unique_idem(prefix: str) -> str:
    """A fresh idempotency key per call, so repeated demo runs of the same
    scenario are each treated as a NEW operation rather than tripping the
    real idempotency guard (which correctly, and deliberately, refuses to
    re-execute an operation it has already seen)."""
    import uuid
    return f"{prefix}-{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"


@dataclass
class StageResult:
    name: str
    label: str
    ok: bool
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "label": self.label, "ok": self.ok, "detail": self.detail}


@dataclass
class ScenarioResult:
    scenario_id: str
    title: str
    expected: str
    stages: List[StageResult]
    summary: str
    passed: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id, "title": self.title, "expected": self.expected,
            "summary": self.summary, "passed": self.passed,
            "stages": [s.to_dict() for s in self.stages],
        }


# ---- helpers (transport + display only -- no decision logic) --------------

def client_for(rt: DemoRuntime) -> MCCGatewayClient:
    return MCCGatewayClient(rt.gateway_url, api_key=rt.api_key, operator_key=rt.operator_key)


def token_view(token: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Safe-for-browser view of a real decision token. Every field is copied
    verbatim from the gateway's response; nothing is computed here. There is
    no private key material in a decision token (only the public ``kid`` and
    the Ed25519 signature), so nothing is redacted -- this is display
    formatting only."""
    if token is None:
        return {"issued": False}
    return {
        "issued": True,
        "decision": token.get("decision"),
        "subject": token.get("sub"),
        "action": token.get("action"),
        "action_hash": token.get("action_hash"),
        "payload_hash": token.get("payload_hash"),
        "policy_id": token.get("policy_id"),
        "policy_hash": token.get("policy_hash"),
        "nonce": token.get("nonce"),
        "audience": token.get("aud"),
        "issuer": token.get("iss"),
        "issued_at": token.get("iat"),
        "not_before": token.get("nbf"),
        "expires_at": token.get("exp"),
        "constraints": token.get("constraints"),
        "actor_id": token.get("actor_id"),
        "resource_id": token.get("resource_id"),
        "transaction_id": token.get("transaction_id"),
        "idempotency_key": token.get("idempotency_key"),
        "mandate_id": token.get("mandate_id"),
        "signing_key_id": token.get("kid"),
        "signature": token.get("sig"),
        "signature_verification": (
            "Not re-verified client-side by design (the Control Room does not "
            "duplicate token-verification logic). The real Execution Gate "
            "performs the authoritative Ed25519 verification at actuation -- "
            "see the Gate Verification & Actuation stage below."
        ),
    }


def exec_view(outcome: ExecutionOutcome) -> Dict[str, Any]:
    return {
        "status": outcome.status,
        "executed": outcome.executed,
        "reason": outcome.reason,
        "decision": outcome.decision,
        "audit_ref": outcome.audit_ref,
        "execution": outcome.execution,
    }


def audit_entries_by_trace(client: MCCGatewayClient, trace_id: str) -> List[Dict[str, Any]]:
    data = json.loads(client.export_audit(fmt="json"))
    return [e for e in data.get("entries", []) if e.get("trace_id") == trace_id]


def audit_entries_count(client: MCCGatewayClient) -> int:
    data = json.loads(client.export_audit(fmt="json"))
    return len(data.get("entries", []))


def audit_new_entries(client: MCCGatewayClient, count_before: int) -> List[Dict[str, Any]]:
    data = json.loads(client.export_audit(fmt="json"))
    entries = data.get("entries", [])
    return entries[count_before:]


def sign_votes(rt: DemoRuntime, *, action: str, payload: Dict[str, Any], actor: str,
                policy_hash: str, nonce: str, resource: Optional[str] = None,
                verdicts: tuple = ("ALLOW", "ALLOW", "ALLOW")) -> List[Dict[str, Any]]:
    """Sign N independent evaluator votes -- the same operation
    ``deploy/pilot/pilot_driver.py`` performs to play the evaluator role for
    a demo. Private evaluator keys never leave this backend process."""
    return [
        issue_vote(rt.evaluator_keys[i], evaluator_id=rt.evaluator_keys[i].kid, verdict=verdicts[i],
                   action=action, payload=payload, actor=actor, not_before=0, not_after=FAR_FUTURE,
                   resource=resource, policy_hash=policy_hash, nonce=nonce)
        for i in range(len(verdicts))
    ]


def audit_record_stage(entries: List[Dict[str, Any]], chain: Dict[str, Any]) -> StageResult:
    ok = bool(entries) and chain.get("valid") is True
    return StageResult(
        "audit_record", "Audit Record", ok,
        {
            "matched_entries": [
                {
                    "event_id": e.get("hash"),
                    "previous_hash": e.get("prev_hash"),
                    "timestamp": e.get("ts"),
                    "decision": e.get("decision"),
                    "reason": e.get("reason"),
                    "policy_hash": e.get("policy_hash"),
                    "trace_id": e.get("trace_id"),
                    "kind": e.get("kind"),
                }
                for e in entries
            ],
            "chain_verification": {
                "valid": chain.get("valid"),
                "entries": chain.get("entries"),
                "head_hash": chain.get("head_hash"),
                "signing_kid": chain.get("signing_kid"),
                "public_key_b64": chain.get("public_key_b64"),
            },
        },
    )


# ---- the four authority verdicts (POST /evaluate) --------------------------

def _decision_scenario(rt: DemoRuntime, *, scenario_id: str, title: str, expected: Decision,
                        identity: str, action: str, context: Dict[str, Any]) -> ScenarioResult:
    client = client_for(rt)
    stages = [StageResult("proposed_action", "Proposed Action", True,
                          {"identity": identity, "action": action, "context": context})]

    result: ProposalResult = client.propose(identity=identity, action=action, context=context)
    stages.append(StageResult(
        "mcc_decision", "MCC Decision", result.decision == expected,
        {"decision": result.decision.value, "reason": result.reason,
         "constraints": result.constraints, "forward_context": result.forward_context,
         "applied_constraints": result.applied_constraints,
         "authority_required": result.authority_required, "policy_ref": result.policy_ref},
    ))
    stages.append(StageResult("decision_token", "Decision Token", True, token_view(result.decision_token)))

    entries = audit_entries_by_trace(client, result.raw.get("trace_id", ""))
    chain = client.verify_chain()
    stages.append(audit_record_stage(entries, chain))

    passed = result.decision == expected
    return ScenarioResult(scenario_id, title, expected.value, stages,
                          f"Real MCC-Core decision: {result.decision.value} ({result.reason})", passed)


PAYMENT_SOURCE = "acct-control-room-demo"
PAYMENT_BENEFICIARY = "beneficiary-control-room-demo"


def canonical_payment(context: Dict[str, Any]) -> Dict[str, Any]:
    """Pre-normalize a payment context exactly the way
    ``mcc_core.profiles.PaymentProfile.canonical_payload`` does (amount as
    float, currency upper-cased), so evaluator votes are signed over the
    IDENTICAL bytes the gateway itself hashes when it re-derives the
    canonical payload -- otherwise a merely-cosmetic difference (e.g. "usd"
    vs "USD", ``1000`` vs ``1000.0``) would make genuinely-valid votes look
    like a payload mismatch. This is display/demo plumbing, not a second
    implementation of the profile's authorization semantics."""
    payload = dict(context)
    if "amount" in payload:
        payload["amount"] = float(payload["amount"])
    if "currency" in payload:
        payload["currency"] = str(payload["currency"]).upper()
    return payload


def scenario_allow(rt: DemoRuntime) -> ScenarioResult:
    context = canonical_payment({"amount": 1000, "currency": "usd", "source": PAYMENT_SOURCE,
                                 "beneficiary_id": PAYMENT_BENEFICIARY})
    r = _decision_scenario(rt, scenario_id="allow", title="ALLOW — payment within mandate",
                           expected=Decision.ALLOW, identity="agent/payments-bot",
                           action="send_payment", context=context)
    exec_stage, actuation_stage = run_execution(
        rt, actor="agent/payments-bot", action="send_payment", context=context,
        idem=unique_idem("control-room-allow"))
    r.stages += [exec_stage, actuation_stage]
    r.passed = r.passed and exec_stage.ok
    return r


def scenario_deny(rt: DemoRuntime) -> ScenarioResult:
    return _decision_scenario(rt, scenario_id="deny", title="DENY — irreversible action, no mandate can authorize it",
                              expected=Decision.DENY, identity="agent/ops-bot",
                              action="delete_database", context={})


def scenario_escalate(rt: DemoRuntime) -> ScenarioResult:
    return _decision_scenario(rt, scenario_id="escalate", title="ESCALATE — no standing mandate",
                              expected=Decision.ESCALATE, identity="agent/nobody",
                              action="send_payment", context={"amount": 100})


def scenario_constrain(rt: DemoRuntime) -> ScenarioResult:
    client = client_for(rt)
    identity, action = "agent/payments-bot", "send_payment"
    context = canonical_payment({"amount": 99000, "currency": "usd", "source": PAYMENT_SOURCE,
                                 "beneficiary_id": PAYMENT_BENEFICIARY})
    r = _decision_scenario(rt, scenario_id="constrain", title="CONSTRAIN — over the mandate cap, clamped",
                           expected=Decision.CONSTRAIN, identity=identity, action=action, context=context)
    proposal = client.propose(identity=identity, action=action, context=context)
    # The clamped forward_context (not the original) is what may actually be
    # authorized and executed -- a fresh consensus challenge/vote is required
    # to bind evidence to the NEW (clamped) payload hash. See
    # deploy/pilot/RUNBOOK.md §5d ("CONSTRAIN with re-consensus").
    clamped_context = canonical_payment(proposal.forward_context)
    exec_stage, actuation_stage = run_execution(
        rt, actor=identity, action=action, context=clamped_context,
        idem=unique_idem("control-room-constrain"))
    r.stages += [exec_stage, actuation_stage]
    r.passed = r.passed and exec_stage.ok
    return r


def scenario_escalate_then_approve(rt: DemoRuntime) -> ScenarioResult:
    """The full ESCALATE loop: agent opens a request, an operator (held only
    on this backend, never in the browser) approves it, then the SAME
    coordinator path executes it -- exactly `examples/governance_http_demo.py`."""
    client = client_for(rt)
    identity, action, resource = "agent/nobody", "send_payment", "acct-demo"
    context = canonical_payment({"amount": 250, "currency": "usd", "source": PAYMENT_SOURCE,
                                 "beneficiary_id": PAYMENT_BENEFICIARY})
    stages = [StageResult("proposed_action", "Proposed Action", True,
                          {"identity": identity, "action": action, "resource": resource, "context": context})]

    proposal = client.propose(identity=identity, action=action, context=context)
    stages.append(StageResult("mcc_decision", "MCC Decision", proposal.decision == Decision.ESCALATE,
                              {"decision": proposal.decision.value, "reason": proposal.reason}))

    transaction_id = unique_idem("control-room-escalate")
    policy_hash = client.health()["policy_hash"]
    req = client.request_approval(actor=identity, action=action, resource=resource,
                                  transaction_id=transaction_id, policy_hash=policy_hash,
                                  payload=context)
    stages.append(StageResult("approval_requested", "Approval Requested (ESCALATE loop)", True, req))

    approved = client.approve(req["request_id"])
    stages.append(StageResult("operator_approval", "Operator Approval (mints single-use mandate)",
                              approved.get("mandate") is not None,
                              {"state": approved.get("state"), "mandate_present": approved.get("mandate") is not None}))

    outcome = client.execute_with_approval(
        req["request_id"], mandate=approved["mandate"], actor=identity, action=action,
        resource=resource, context=context, transaction_id=transaction_id,
        idempotency_key=unique_idem("control-room-escalate-exec"))
    stages.append(StageResult("gate_and_actuation", "Gate Verification & Actuation", outcome.executed, exec_view(outcome)))
    stages.append(StageResult("actuation_result", "Actuation Result", outcome.executed,
                              {"upstream_calls": len(rt.upstream_seen)}))

    entries = audit_entries_by_trace(client, proposal.raw.get("trace_id", ""))
    stages.append(audit_record_stage(entries, client.verify_chain()))

    passed = proposal.decision == Decision.ESCALATE and outcome.executed
    return ScenarioResult("escalate_then_approve", "ESCALATE → operator approval → EXECUTED", "EXECUTED",
                          stages, f"ESCALATE, then a real operator approval, then real EXECUTED "
                          f"({outcome.status}).", passed)


def run_execution(rt: DemoRuntime, *, actor: str, action: str, context: Dict[str, Any],
                    idem: str, resource: Optional[str] = None) -> tuple:
    client = client_for(rt)
    policy_hash = client.health()["policy_hash"]
    challenge = client.issue_challenge(actor=actor, action=action, resource=resource, context=context)
    votes = sign_votes(rt, action=action, payload=context, actor=actor, policy_hash=policy_hash,
                       nonce=challenge["nonce"], resource=resource)
    outcome = client.execute_with_consensus(
        votes=votes, actor=actor, action=action, resource=resource, context=context,
        nonce=challenge["nonce"], challenge_id=challenge["challenge_id"], idempotency_key=idem)
    gate_stage = StageResult("gate_and_actuation", "Gate Verification & Actuation (real N-of-M consensus + gate)",
                             outcome.executed, {**exec_view(outcome), "votes_submitted": len(votes),
                                                "challenge": challenge})
    actuation_stage = StageResult("actuation_result", "Actuation Result", outcome.executed,
                                  {"upstream_calls_total": len(rt.upstream_seen),
                                   "last_upstream_call": rt.upstream_seen[-1] if rt.upstream_seen else None})
    return gate_stage, actuation_stage


# ---- required attack / failure-mode scenarios (all real, none simulated) ---

ATTACK_ACTION = "demo_notify_customer"
ATTACK_ACTOR = "agent/control-room-demo"


def scenario_execution_replay(rt: DemoRuntime) -> ScenarioResult:
    client = client_for(rt)
    context = {"message": "Your order has shipped."}
    policy_hash = client.health()["policy_hash"]
    challenge = client.issue_challenge(actor=ATTACK_ACTOR, action=ATTACK_ACTION, context=context)
    votes = sign_votes(rt, action=ATTACK_ACTION, payload=context, actor=ATTACK_ACTOR,
                       policy_hash=policy_hash, nonce=challenge["nonce"])
    before = audit_entries_count(client)

    first = client.execute_with_consensus(votes=votes, actor=ATTACK_ACTOR, action=ATTACK_ACTION,
                                          context=context, nonce=challenge["nonce"],
                                          challenge_id=challenge["challenge_id"], idempotency_key="cr-replay-1")
    stages = [
        StageResult("proposed_action", "Proposed Action", True, {"actor": ATTACK_ACTOR, "action": ATTACK_ACTION, "context": context}),
        StageResult("first_execution", "First Execution (real, valid evidence)", first.executed, exec_view(first)),
    ]
    # Replay: the identical signed votes + the identical one-time nonce,
    # submitted again. The gate's nonce registry has already consumed this
    # nonce; the gateway-issued challenge is also already single-use-consumed.
    replay = client.execute_with_consensus(votes=votes, actor=ATTACK_ACTOR, action=ATTACK_ACTION,
                                           context=context, nonce=challenge["nonce"],
                                           challenge_id=challenge["challenge_id"], idempotency_key="cr-replay-2")
    stages.append(StageResult("gate_and_actuation", "Replay Attempt (real gate re-verification)",
                              not replay.executed, exec_view(replay)))
    stages.append(StageResult("actuation_result", "Actuation Result", not replay.executed,
                              {"upstream_calls_total": len(rt.upstream_seen)}))
    entries = audit_new_entries(client, before)
    stages.append(audit_record_stage(entries, client.verify_chain()))

    passed = first.executed and not replay.executed
    return ScenarioResult("replay", "Replay of the same signed consensus evidence / one-time nonce",
                          "BLOCKED on replay", stages, f"First attempt {first.status}; replay "
                          f"{replay.status} ({replay.reason}).", passed)


def scenario_execution_tamper(rt: DemoRuntime) -> ScenarioResult:
    client = client_for(rt)
    original_context = {"message": "Your order has shipped."}
    tampered_context = {"message": "Wire the full account balance."}
    policy_hash = client.health()["policy_hash"]
    challenge = client.issue_challenge(actor=ATTACK_ACTOR, action=ATTACK_ACTION, context=original_context)
    # Evaluators sign what they were shown: the ORIGINAL action/payload.
    votes = sign_votes(rt, action=ATTACK_ACTION, payload=original_context, actor=ATTACK_ACTOR,
                       policy_hash=policy_hash, nonce=challenge["nonce"])
    before = audit_entries_count(client)
    # The execute request then submits a DIFFERENT payload than what the
    # votes/challenge are bound to -- the action was modified after the
    # evidence was issued.
    outcome = client.execute_with_consensus(votes=votes, actor=ATTACK_ACTOR, action=ATTACK_ACTION,
                                            context=tampered_context, nonce=challenge["nonce"],
                                            challenge_id=challenge["challenge_id"], idempotency_key="cr-tamper-1")
    stages = [
        StageResult("proposed_action", "Proposed Action (evidence issued for this payload)", True, {"context": original_context}),
        StageResult("mcc_decision", "Action Modified After Evidence Issuance", True, {"submitted_context": tampered_context}),
        StageResult("gate_and_actuation", "Gate Verification & Actuation (real binding check)", not outcome.executed, exec_view(outcome)),
        StageResult("actuation_result", "Actuation Result", not outcome.executed, {"upstream_calls_total": len(rt.upstream_seen)}),
    ]
    entries = audit_new_entries(client, before)
    stages.append(audit_record_stage(entries, client.verify_chain()))

    return ScenarioResult("tamper", "Action modified after consensus-evidence issuance", "BLOCKED",
                          stages, f"Real payload-binding check: {outcome.status} ({outcome.reason}).",
                          not outcome.executed)


def scenario_expired_challenge(rt: DemoRuntime) -> ScenarioResult:
    client = client_for(rt)
    context = {"message": "Your order has shipped."}
    policy_hash = client.health()["policy_hash"]
    ttl = 2
    challenge = client.issue_challenge(actor=ATTACK_ACTOR, action=ATTACK_ACTION, context=context, ttl_seconds=ttl)
    votes = sign_votes(rt, action=ATTACK_ACTION, payload=context, actor=ATTACK_ACTOR,
                       policy_hash=policy_hash, nonce=challenge["nonce"])
    before = audit_entries_count(client)
    time.sleep(ttl + 1.5)
    outcome = client.execute_with_consensus(votes=votes, actor=ATTACK_ACTOR, action=ATTACK_ACTION,
                                            context=context, nonce=challenge["nonce"],
                                            challenge_id=challenge["challenge_id"], idempotency_key="cr-expired-1")
    stages = [
        StageResult("proposed_action", "Proposed Action", True, {"context": context}),
        StageResult("mcc_decision", "Gateway-Issued Challenge (2s validity window, for a fast demo)", True,
                   {"issued": challenge, "waited_seconds": ttl + 1.5}),
        StageResult("gate_and_actuation", "Gate Verification & Actuation (real expiry check)", not outcome.executed, exec_view(outcome)),
        StageResult("actuation_result", "Actuation Result", not outcome.executed, {"upstream_calls_total": len(rt.upstream_seen)}),
    ]
    entries = audit_new_entries(client, before)
    stages.append(audit_record_stage(entries, client.verify_chain()))

    return ScenarioResult("expired", "Expired consensus-challenge validity window", "BLOCKED",
                          stages, f"Real expiry enforcement: {outcome.status} ({outcome.reason}).",
                          not outcome.executed)


def scenario_bad_signature(rt: DemoRuntime) -> ScenarioResult:
    client = client_for(rt)
    context = {"message": "Your order has shipped."}
    policy_hash = client.health()["policy_hash"]
    challenge = client.issue_challenge(actor=ATTACK_ACTOR, action=ATTACK_ACTION, context=context)
    votes = sign_votes(rt, action=ATTACK_ACTION, payload=context, actor=ATTACK_ACTOR,
                       policy_hash=policy_hash, nonce=challenge["nonce"])
    # Tamper with a signed vote's claims AFTER signing -- the Ed25519
    # signature no longer matches the claims, exactly like
    # tests/test_consensus_enforcement_http.py::test_bad_signature_denied.
    votes[-1] = {**votes[-1], "verdict": "DENY"}
    before = audit_entries_count(client)
    outcome = client.execute_with_consensus(votes=votes, actor=ATTACK_ACTOR, action=ATTACK_ACTION,
                                            context=context, nonce=challenge["nonce"],
                                            challenge_id=challenge["challenge_id"], idempotency_key="cr-badsig-1")
    stages = [
        StageResult("proposed_action", "Proposed Action", True, {"context": context}),
        StageResult("mcc_decision", "One Evaluator Vote Tampered After Signing", True,
                   {"tampered_field": "verdict", "evaluator": votes[-1].get("evaluator_id")}),
        StageResult("gate_and_actuation", "Gate Verification & Actuation (real Ed25519 signature check)",
                   not outcome.executed, exec_view(outcome)),
        StageResult("actuation_result", "Actuation Result", not outcome.executed, {"upstream_calls_total": len(rt.upstream_seen)}),
    ]
    entries = audit_new_entries(client, before)
    stages.append(audit_record_stage(entries, client.verify_chain()))

    return ScenarioResult("bad_signature", "Invalid / tampered evaluator signature", "BLOCKED",
                          stages, f"Real signature verification: {outcome.status} ({outcome.reason}).",
                          not outcome.executed)


SCENARIOS: Dict[str, Callable[[DemoRuntime], ScenarioResult]] = {
    "allow": scenario_allow,
    "deny": scenario_deny,
    "escalate": scenario_escalate,
    "constrain": scenario_constrain,
    "escalate_then_approve": scenario_escalate_then_approve,
    "replay": scenario_execution_replay,
    "tamper": scenario_execution_tamper,
    "expired": scenario_expired_challenge,
    "bad_signature": scenario_bad_signature,
}

SCENARIO_METADATA = [
    {"id": "allow", "title": "ALLOW", "description": "A compliant payment within the agent's mandate cap — decided, signed, executed."},
    {"id": "deny", "title": "DENY", "description": "An irreversible action no mandate can authorize."},
    {"id": "escalate", "title": "ESCALATE", "description": "An action above the agent's standing authority — requires a human."},
    {"id": "constrain", "title": "CONSTRAIN", "description": "A payment over the cap — clamped to the authorized amount, then executed."},
    {"id": "escalate_then_approve", "title": "ESCALATE → Approve → EXECUTED",
     "description": "The full human-in-the-loop path: escalate, a real operator approval, then real execution."},
    {"id": "replay", "title": "Consensus-evidence replay rejected",
     "description": "The identical signed evaluator votes and one-time gateway-issued nonce, submitted twice — "
                    "demonstrates the gate's one-time nonce consumption. Not a resubmitted Decision Token: MCC-Core "
                    "has no endpoint that accepts a client-supplied Decision Token for re-verification (no second "
                    "execution path); see the note in tools/control-room/README.md."},
    {"id": "tamper", "title": "Action-binding tamper rejected",
     "description": "The action is submitted with a different payload than the one the consensus evidence was "
                    "issued for — demonstrates the same action/payload-hash binding check a Decision Token is "
                    "itself bound by."},
    {"id": "expired", "title": "Expired consensus-challenge rejected",
     "description": "A gateway-issued challenge used after its validity window has passed — demonstrates the same "
                    "time-bounded-validity invariant a Decision Token's own expiry (`exp`) enforces."},
    {"id": "bad_signature", "title": "Invalid evaluator signature rejected",
     "description": "One evaluator vote is altered after being signed — demonstrates real Ed25519 signature "
                    "verification failing closed, the same primitive that verifies a Decision Token's own signature."},
]
