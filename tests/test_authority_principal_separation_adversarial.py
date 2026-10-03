"""Adversarial runtime proof that the agent (proposer) and the operator
(authority) are genuinely separate principals for the egress-proxy-based
governed-agent pilot (``docker-compose.pilot.yml`` / ``deploy/pilot/docker-
compose.yml``), against the REAL ``egress_proxy.app`` (via
``tests/_egress_harness.py``) -- not a mock.

This exercises the same two credential sets the refactored compose services
hold: an "agent" header set (``x-api-key`` only, matching ``mcc-agent`` /
``reference-egress-agent`` after the credential-separation fixes) and an
"operator" header set (``x-operator-key`` only, matching the new
``mcc-operator`` sidecar / the operator side of the pilot). No test here
ever constructs a header set holding both, because no refactored service
does either.

Security property under proof: COMPROMISE(AGENT) != COMPROMISE(AUTHORITY).
Holding the agent's credentials must never be sufficient to grant an
approval; holding the operator's credentials must never be sufficient to
execute an arbitrary action the operator did not itself propose.
"""

from __future__ import annotations

from tests._egress_harness import EgressHarness


def _escalate(hz: EgressHarness, *, idem: str) -> dict:
    out = hz.post(
        method="POST", url=hz.url("/charge"), body={"amount": 10},
        actor="agent/intern", transaction_id=idem, idempotency_key=idem,
    ).json()
    assert out["outcome"] == "ESCALATE", out
    assert out.get("executed") is not True
    return out


class TestCaseA_CompromisedAgentCannotSelfApprove:
    """A: even a fully compromised agent process -- one that tries every
    credential/header it holds -- cannot grant its own approval, and zero
    upstream actuation occurs."""

    def test_agent_key_rejected_by_approve_endpoint(self):
        hz = EgressHarness(require_consensus=False)
        out = _escalate(hz, idem="case-a-1")
        rid = out["approval_request_id"]

        # The agent tries to approve using its OWN key (the only credential
        # it holds after the fix) instead of an operator key.
        r = hz.client.post(f"/v1/approvals/{rid}/approve", headers=hz.H)
        assert r.status_code == 403, r.text

        # ... and with no credential at all.
        r2 = hz.client.post(f"/v1/approvals/{rid}/approve", headers={})
        assert r2.status_code in (401, 403), r2.text

        # Resubmitting with the (never-granted) approval_id still does not
        # execute.
        out2 = hz.post(method="POST", url=hz.url("/charge"), body={"amount": 10},
                       actor="agent/intern", transaction_id="case-a-1",
                       idempotency_key="case-a-1", approval_id=rid).json()
        assert out2.get("executed") is not True
        assert len(hz.seen) == 0, f"actuator count must be 0, saw: {hz.seen}"


class TestCaseB_SeparatedAuthoritySucceedsExactlyOnce:
    """B: the legitimate, separated operator (holding ONLY the operator key,
    as mcc-operator does) can grant the approval, and the agent's own
    resubmission (holding ONLY the agent key) then executes -- exactly
    once, even if the agent polls/retries after success."""

    def test_operator_approval_then_single_execution(self):
        hz = EgressHarness(require_consensus=False)
        out = _escalate(hz, idem="case-b-1")
        rid = out["approval_request_id"]

        r = hz.approve(rid)
        assert r.status_code == 200, r.text

        out2 = hz.post(method="POST", url=hz.url("/charge"), body={"amount": 10},
                       actor="agent/intern", transaction_id="case-b-1",
                       idempotency_key="case-b-1", approval_id=rid).json()
        assert out2.get("executed") is True, out2
        assert len(hz.seen) == 1, f"expected exactly one upstream call, saw: {hz.seen}"

        # A second resubmission (agent polling again after it already saw
        # success, or retrying blindly) must not cause a second actuation.
        out3 = hz.post(method="POST", url=hz.url("/charge"), body={"amount": 10},
                       actor="agent/intern", transaction_id="case-b-1",
                       idempotency_key="case-b-1", approval_id=rid).json()
        assert len(hz.seen) == 1, f"idempotency must prevent a second actuation, saw: {hz.seen}"


class TestCaseC_StolenOrWrongCredentialRejected:
    """C: a wrong/forged operator credential is rejected; zero actuation."""

    def test_wrong_operator_key_rejected(self):
        hz = EgressHarness(require_consensus=False)
        out = _escalate(hz, idem="case-c-1")
        rid = out["approval_request_id"]

        r = hz.client.post(f"/v1/approvals/{rid}/approve",
                           headers={"x-operator-key": "stolen-or-guessed-key"})
        assert r.status_code == 403, r.text

        out2 = hz.post(method="POST", url=hz.url("/charge"), body={"amount": 10},
                       actor="agent/intern", transaction_id="case-c-1",
                       idempotency_key="case-c-1", approval_id=rid).json()
        assert out2.get("executed") is not True
        assert len(hz.seen) == 0


class TestCaseD_WrongBindingRejected:
    """D: a valid approval for ONE proposed action does not authorize a
    DIFFERENT action (different payload/actor/resource) -- the gate must
    bind the approval to the exact original proposal, not just its id."""

    def test_approval_does_not_cover_a_substituted_payload(self):
        hz = EgressHarness(require_consensus=False)
        out = _escalate(hz, idem="case-d-1")
        rid = out["approval_request_id"]
        r = hz.approve(rid)
        assert r.status_code == 200, r.text

        # Same approval_id, transaction_id, and idempotency_key, but a
        # substituted higher amount -- the binding check must reject this,
        # not silently widen the approval's scope to a different payload.
        out2 = hz.post(method="POST", url=hz.url("/charge"), body={"amount": 5_000_000},
                       actor="agent/intern", transaction_id="case-d-1",
                       idempotency_key="case-d-1", approval_id=rid).json()
        assert out2.get("executed") is not True, out2
        assert len(hz.seen) == 0, f"substituted payload must not actuate, saw: {hz.seen}"


class TestCaseE_AuthorityUnavailableFailsClosed:
    """E: if the separated authority (operator process) never runs at all --
    simulating it being down/unreachable -- the agent's own bounded
    polling/retry loop never executes anything. No actuation happens
    without an independently-granted approval, no matter how many times
    the agent (holding only its own key) retries."""

    def test_no_approval_ever_granted_means_zero_actuation_after_retries(self):
        hz = EgressHarness(require_consensus=False)
        out = _escalate(hz, idem="case-e-1")
        rid = out["approval_request_id"]

        for _ in range(5):
            out2 = hz.post(method="POST", url=hz.url("/charge"), body={"amount": 10},
                           actor="agent/intern", transaction_id="case-e-1",
                           idempotency_key="case-e-1", approval_id=rid).json()
            assert out2.get("executed") is not True
            assert out2.get("error_code") == "APPROVAL_INVALID", out2

        assert len(hz.seen) == 0, f"authority never ran -- actuator count must be 0, saw: {hz.seen}"
