"""Workstream G -- Audit Survivability (PR #71).

Proves the append-only hash-chain audit log is not merely present but
genuinely tamper-EVIDENT, observed entirely through the Gateway's real
``GET /verify`` HTTP endpoint (recomputes and checks the chain -- never
trusted as a bare "yes" from the application). ``corrupt_gateway_audit_chain``
is the one deliberate exception to "HTTP only": it writes directly to the
Gateway's on-disk audit file, simulating a DIFFERENT threat model than a
network attacker -- a compromised/tampered storage layer. That is a stated
scope note, not a silent one; see ``ASSUMPTIONS_AND_LIMITS.md``.

An audit log with zero entries reports ``valid: false`` (there is nothing
to anchor trust to yet), not an implicit "trivially valid" -- so every test
here writes real entries first, then reasons about validity.
"""

from __future__ import annotations

import uuid

ACTOR = "agent/notify-bot"
ACTION = "send_notification"
RESOURCE = "notifications"


def _payload(**overrides):
    base = {"recipient": "customer-123", "message": "assurance-g-probe", "priority": 2,
            "channel": "email", "correlation_id": str(uuid.uuid4())}
    base.update(overrides)
    return base


def _authorized_execute(sut) -> None:
    import httpx

    payload = _payload()
    ch = httpx.post(
        f"{sut.gateway_url}/consensus/challenge", headers={"x-api-key": sut.agent_key(ACTOR)},
        json={"actor": ACTOR, "action": ACTION, "resource": RESOURCE, "context": payload}, timeout=10.0,
    ).json()
    votes = sut.gateway_consensus_votes(
        action=ACTION, payload=payload, actor=ACTOR, resource=RESOURCE,
        nonce=ch["nonce"], policy_hash=ch.get("policy_hash"),
    )
    r = httpx.post(
        f"{sut.gateway_url}/consensus/execute", headers={"x-api-key": sut.agent_key(ACTOR)},
        json={"votes": votes, "actor": ACTOR, "action": ACTION, "resource": RESOURCE, "context": payload,
              "challenge_id": ch["challenge_id"], "nonce": ch["nonce"],
              "idempotency_key": f"g-authorized-{uuid.uuid4()}"}, timeout=10.0,
    ).json()
    assert r["status"] == "EXECUTED"


def _rejected_attempt(sut) -> None:
    """A below-threshold, doomed-to-fail consensus attempt -- must not
    corrupt or otherwise disturb the chain's own internal consistency."""
    import httpx

    payload = _payload()
    ch = httpx.post(
        f"{sut.gateway_url}/consensus/challenge", headers={"x-api-key": sut.agent_key(ACTOR)},
        json={"actor": ACTOR, "action": ACTION, "resource": RESOURCE, "context": payload}, timeout=10.0,
    ).json()
    votes = sut.gateway_consensus_votes(
        action=ACTION, payload=payload, actor=ACTOR, resource=RESOURCE,
        nonce=ch["nonce"], policy_hash=ch.get("policy_hash"),
    )[:1]
    r = httpx.post(
        f"{sut.gateway_url}/consensus/execute", headers={"x-api-key": sut.agent_key(ACTOR)},
        json={"votes": votes, "actor": ACTOR, "action": ACTION, "resource": RESOURCE, "context": payload,
              "challenge_id": ch["challenge_id"], "nonce": ch["nonce"]}, timeout=10.0,
    ).json()
    assert r["status"] != "EXECUTED"


def test_g1_chain_is_valid_after_a_genuine_authorized_execution(sut):
    _authorized_execute(sut)
    assert sut.gateway_audit_chain_valid() is True


def test_g2_chain_stays_valid_across_a_mix_of_successes_and_rejections(sut):
    """Real audit-chain traffic is not just happy-path -- a working
    tamper-evident chain must stay internally consistent whether the
    operations it records succeeded or were blocked."""
    _authorized_execute(sut)
    _rejected_attempt(sut)
    _authorized_execute(sut)
    _rejected_attempt(sut)
    _rejected_attempt(sut)
    _authorized_execute(sut)

    assert sut.gateway_audit_chain_valid() is True


def test_g3_direct_storage_tamper_is_detected():
    """The chain must be tamper-EVIDENT, not merely tamper-resistant in
    theory: after at least one real entry exists, directly corrupting the
    on-disk file must flip /verify to invalid.

    Uses its OWN, throwaway SystemUnderTest (not the shared session-scoped
    ``sut`` fixture) so this deliberately destructive tamper never leaves
    the chain OTHER workstream test modules observe permanently corrupted
    for the rest of the pytest session."""
    from assurance.sut.harness import build_system_under_test

    with build_system_under_test() as isolated_sut:
        _authorized_execute(isolated_sut)
        assert isolated_sut.gateway_audit_chain_valid() is True

        isolated_sut.corrupt_gateway_audit_chain()

        assert isolated_sut.gateway_audit_chain_valid() is False
