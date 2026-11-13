"""Official Integration Contract — remaining scenario coverage (PR #43).

The framework-neutral reference governed agent + the ``mcc_client`` SDK are the
canonical integration path. The existing suite
(``tests/test_reference_governed_agent.py``) already covers ALLOW / DENY /
CONSTRAIN / ESCALATE, forged/expired/mismatched approval, altered-payload,
receipt verification, Redis outage, audit verify and the no-direct-execution
guard. This file completes the contract's scenario matrix with the gaps:

  * invalid signature            -> fail closed, no execution
  * expired authorization        -> fail closed, no execution
  * replay attempt               -> executed at most once
  * invalid policy hash          -> fail closed, no execution
  * gateway unavailable          -> fail closed, no execution
  * audit evidence generation    -> portable bundle, offline-verifiable (PR #42)
  * framework-neutral public API -> no framework-specific names leak

Every governed-path test drives the REAL gateway over real HTTP via the SDK
(``NotifyPilotHarness``) with the receipt-verifying executor pointed at a real
loopback service. Deterministic and offline: no external API key, no network
egress, no LLM. No governance code is stubbed or bypassed.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sdk" / "python" / "src"))

from mcc_client import MCCClient  # noqa: E402
from mcc_client.exceptions import MCCError, MCCTransportError  # noqa: E402
from mcc_client.models import ConsensusAuthorization  # noqa: E402

from mcc_core import issue_vote  # noqa: E402
from mcc_core.signing import SIGNATURE_FIELD  # noqa: E402

from examples.reference_governed_agent import (  # noqa: E402
    DeterministicProvider,
    export_agent_evidence,
)
from examples.reference_governed_agent.authorizers import FAR_FUTURE  # noqa: E402
from mcc_evidence import EvidenceStatus, verify_bundle  # noqa: E402

from pilot_notify import recorded_receipts, reset_receipts  # noqa: E402

from tests._notify_harness import (  # noqa: E402
    API_KEY,
    OPERATOR_KEY,
    TENANT_ID,
    NotifyPilotHarness,
    agent_key,
)

REQUEST = "Notify customer-123 that the appointment is confirmed"


@pytest.fixture()
def hz():
    h = NotifyPilotHarness()
    try:
        yield h
    finally:
        h.close()


@pytest.fixture(autouse=True)
def _reset():
    reset_receipts()
    yield


def _client(h: NotifyPilotHarness, actor: str = "agent/notify-bot") -> MCCClient:
    # F1: the agent presents its OWN credential on /evaluate and /consensus/*,
    # so every negative below reaches its intended check (signature, expiry,
    # replay, policy hash) rather than an identity refusal.
    return MCCClient(h.base_url, api_key=agent_key(actor), operator_key=OPERATOR_KEY, timeout=15.0)


def _allow_decision(h: NotifyPilotHarness, client: MCCClient):
    prop = DeterministicProvider(actor_id="agent/notify-bot", priority="normal",
                                 channel="email").propose(REQUEST)
    d = client.evaluate(actor_id=prop.actor_id, action=prop.action,
                        resource=prop.resource, payload=prop.payload,
                        idempotency_key=prop.idempotency_key)
    assert d.verdict.value == "ALLOW"
    return d


def _votes(h, decision, nonce, *, policy_hash=None, not_after=FAR_FUTURE):
    """N-of-M evaluator votes over the decision's authoritative payload."""
    canonical = h.profiles.for_action(decision.action).canonical_payload(
        dict(decision.authorized_payload))
    return [
        issue_vote(h.evaluators[i], evaluator_id=h.evaluators[i].kid, verdict="ALLOW",
                   action=decision.action, payload=canonical, actor=decision.actor_id,
                   not_before=0, not_after=not_after, resource=decision.resource_id,
                   policy_hash=policy_hash if policy_hash is not None else h.policy_hash,
                   nonce=nonce, tenant_id=TENANT_ID)
        for i in range(len(h.evaluators))
    ]


def _consensus(client, decision, *, policy_hash=None, not_after=FAR_FUTURE, corrupt_sig=False, h=None):
    ch = client.issue_challenge(decision)
    votes = _votes(h, decision, ch["nonce"], policy_hash=policy_hash, not_after=not_after)
    if corrupt_sig:
        for v in votes:
            raw = base64.b64decode(v[SIGNATURE_FIELD])
            flipped = bytes([raw[0] ^ 0xFF]) + raw[1:]
            v[SIGNATURE_FIELD] = base64.b64encode(flipped).decode()
    return ConsensusAuthorization(votes=votes, challenge_id=ch["challenge_id"], nonce=ch["nonce"])


def _assert_fails_closed(client, decision, material):
    """A governed execute with invalid material must fail closed: it raises a typed
    MCCError (never a silent success) and the external service is never called."""
    with pytest.raises(MCCError):
        result = client.execute(decision, material)
        # If the SDK ever returned instead of raising, it must still be non-executed.
        assert not result.executed  # pragma: no cover
    assert recorded_receipts() == [], "the external service was called despite a blocked verdict"


# --------------------------------------------------------------------------- #
# 1. Invalid signature -> fail closed.                                        #
# --------------------------------------------------------------------------- #

def test_invalid_signature_fails_closed(hz):
    c = _client(hz)
    d = _allow_decision(hz, c)
    _assert_fails_closed(c, d, _consensus(c, d, corrupt_sig=True, h=hz))


# --------------------------------------------------------------------------- #
# 2. Expired authorization -> fail closed.                                    #
# --------------------------------------------------------------------------- #

def test_expired_authorization_fails_closed(hz):
    c = _client(hz)
    d = _allow_decision(hz, c)
    _assert_fails_closed(c, d, _consensus(c, d, not_after=1, h=hz))  # not_after in the past


# --------------------------------------------------------------------------- #
# 3. Replay attempt -> executed at most once.                                 #
# --------------------------------------------------------------------------- #

def test_replay_attempt_executes_at_most_once(hz):
    c = _client(hz)
    d = _allow_decision(hz, c)
    material = _consensus(c, d, h=hz)
    first = c.execute(d, material)
    assert first.executed and len(recorded_receipts()) == 1
    # Replaying the SAME challenge/nonce + votes must not execute again — the SDK
    # raises (replay/blocked), never a silent second success.
    with pytest.raises(MCCError):
        c.execute(d, material)
    assert len(recorded_receipts()) == 1, "replay produced a second execution"


# --------------------------------------------------------------------------- #
# 4. Invalid policy hash -> fail closed.                                      #
# --------------------------------------------------------------------------- #

def test_invalid_policy_hash_fails_closed(hz):
    c = _client(hz)
    d = _allow_decision(hz, c)
    _assert_fails_closed(c, d, _consensus(c, d, policy_hash="sha256:not-the-policy", h=hz))


# --------------------------------------------------------------------------- #
# 5. Gateway unavailable -> fail closed (no execution).                       #
# --------------------------------------------------------------------------- #

def test_gateway_unavailable_fails_closed(hz):
    c = _client(hz)
    _allow_decision(hz, c)  # prove the gateway was reachable first
    hz.close()  # gateway goes away
    with pytest.raises(MCCError):  # transport/ambiguous error — never a silent success
        c.evaluate(actor_id="agent/notify-bot", action="send_notification",
                   resource="notifications", payload={"message": "x"})
    assert recorded_receipts() == []


def test_gateway_unreachable_from_start_fails_closed():
    # A client pointed at a dead endpoint can never manufacture authorization.
    c = MCCClient("http://127.0.0.1:9", api_key=API_KEY, timeout=2.0)
    with pytest.raises(MCCTransportError):
        c.evaluate(actor_id="agent/x", action="send_notification", payload={"m": "x"})


# --------------------------------------------------------------------------- #
# 6. Audit evidence generation -> portable, offline-verifiable (PR #42).      #
# --------------------------------------------------------------------------- #

def test_audit_evidence_generation_and_offline_verify(hz, tmp_path):
    c = _client(hz)
    d = _allow_decision(hz, c)
    result = c.execute(d, _consensus(c, d, h=hz))
    assert result.executed

    bundle = export_agent_evidence(d, result, tmp_path / "bundle")
    gk = hz.gateway.signing_key
    trusted = {gk.kid: gk.public_key_b64()}

    ok = verify_bundle(bundle, trusted_keys=trusted)
    assert ok.overall_status is EvidenceStatus.VERIFIED
    assert ok.trusted and ok.authority_evidence_verified and ok.integrity_valid

    # Without the trusted key it is intact but not trusted evidence.
    untrusted = verify_bundle(bundle)
    assert untrusted.overall_status is EvidenceStatus.INTACT_UNTRUSTED_SIGNER
    assert not untrusted.trusted

    # Tampering the signed token is detected.
    import json
    tok_path = bundle / "decision/token.json"
    tok = json.loads(tok_path.read_text())
    tok["decision"] = "DENY"
    tok_path.write_text(json.dumps(tok))
    assert verify_bundle(bundle, trusted_keys=trusted).overall_status is EvidenceStatus.INVALID


def test_deny_evidence_has_no_fabricated_receipt(hz, tmp_path):
    c = _client(hz)
    prop = DeterministicProvider(actor_id="agent/notify-bot", priority="normal",
                                 channel="pager").propose(REQUEST)  # pager -> DENY
    from mcc_client.exceptions import MCCDeniedError
    with pytest.raises(MCCDeniedError):
        # A DENY surfaces as a denied error at evaluate/guard; nothing executes.
        d = c.evaluate(actor_id=prop.actor_id, action=prop.action,
                       resource=prop.resource, payload=prop.payload)
        c.execute(d, _consensus(c, d, h=hz))
    assert recorded_receipts() == []


# --------------------------------------------------------------------------- #
# 7. The public integration surface is framework-neutral.                     #
# --------------------------------------------------------------------------- #

def test_public_integration_api_is_framework_neutral():
    import examples.reference_governed_agent as agent_pkg
    import mcc_client

    frameworks = ("voltagent", "langgraph", "crewai", "openai", "autogen",
                  "semantic_kernel", "semantickernel", "adk")
    for mod in (agent_pkg, mcc_client):
        for name in getattr(mod, "__all__", dir(mod)):
            low = name.lower()
            assert not any(fw in low for fw in frameworks), \
                f"framework-specific name {name!r} leaked into {mod.__name__} public API"


# --------------------------------------------------------------------------- #
# 8. Documentation validation (deterministic, offline).                       #
# --------------------------------------------------------------------------- #

def test_integration_contract_doc_is_present_and_complete():
    doc = (ROOT / "docs" / "INTEGRATION_CONTRACT.md").read_text(encoding="utf-8")
    assert "```mermaid" in doc and "sequenceDiagram" in doc, "missing sequence diagram"
    for stage in ("Proposal", "Decision", "Verification", "Execution", "Audit"):
        assert stage in doc, f"contract doc missing the {stage} stage"
    for section in ("Trust boundaries", "Failure modes", "Security guarantees",
                    "Integration steps"):
        assert section in doc, f"contract doc missing the {section!r} section"
    # It must point at the canonical implementation, not reinvent one.
    assert "mcc_client" in doc and "reference_governed_agent" in doc
