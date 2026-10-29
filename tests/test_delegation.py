"""Verifiable Delegation & Intent Binding -- unit-level tests of
``mcc_core.delegation`` in isolation: ``issue_delegation``,
``DelegationVerifier``, ``DelegationAuthority``, and the atomic
cumulative-budget helpers (which reuse ``velocity.py`` directly).

Covers, per the task's required adversarial matrix, the subset that does
NOT require a full governed stack (see
``tests/test_delegation_governance_service.py`` for the end-to-end,
actuator-instrumented coverage): forgery, scope escalation (action /
resource / recipient / currency / amount / purpose), expired / not-yet-
valid delegation, revocation (revoked / unavailable / required-but-
unconfigured), malformed delegation, subject mismatch (transfer
prevention), tenant mismatch (cross-tenant), policy-binding mismatch, and
issuance-time fail-closed validation.
"""

from __future__ import annotations

import asyncio

import pytest

from mcc_core.core import Verdict
from mcc_core.delegation import (
    DelegationAuthority,
    DelegationResult,
    DelegationVerifier,
    delegation_velocity_descriptor,
    delegation_velocity_limit,
    issue_delegation,
)
from mcc_core.mandate import InMemoryRevocationRegistry, RevocationStatus
from mcc_core.signing import SigningKey
from mcc_core.trusted_time import TimeTrustError, TrustedTimeSource
from mcc_core.velocity import InMemoryVelocityRegistry

run = asyncio.run

ACTION = "send_payment"
RESOURCE = "acct-1"
RECIPIENT = "vendor-42"
TENANT = "tenant-1"
PURPOSE = "vendor_payment"
NOW = 1_000_000


def _owner_key() -> SigningKey:
    return SigningKey.generate("owner-1")


def _delegation(owner_key, **overrides):
    kw = dict(
        owner_id="owner/alex", subject="agent/payments-bot", tenant_id=TENANT,
        purpose=PURPOSE, action_scope=[ACTION], resource_scope=[RESOURCE],
        recipient_scope=["vendor-*"], currency="EUR", max_amount=500.0,
        not_before=NOW - 10, not_after=NOW + 3600, issued_at=NOW - 10,
        consent_ref="sha256:consent-abc",
    )
    kw.update(overrides)
    return issue_delegation(owner_key, **kw)


def _verifier(owner_key, *, revocation_registry=None):
    return DelegationVerifier(
        trusted_owner_keys={owner_key.kid: owner_key.public_key()},
        revocation_registry=revocation_registry or InMemoryRevocationRegistry(),
    )


def _authorize(authority, delegation, **overrides):
    kw = dict(
        subject="agent/payments-bot", tenant_id=TENANT, action=ACTION, resource=RESOURCE,
        recipient=RECIPIENT, currency="EUR", amount=100.0, purpose=PURPOSE, now=NOW,
    )
    kw.update(overrides)
    return run(authority.authorize(delegation, **kw))


# --------------------------------------------------------------------------
# 1. Non-vacuity baseline: a well-formed delegation, proposed exactly as
# delegated, ALLOWs.
# --------------------------------------------------------------------------

def test_valid_delegation_allows():
    owner_key = _owner_key()
    deleg = _delegation(owner_key)
    authority = DelegationAuthority(_verifier(owner_key))
    decision = _authorize(authority, deleg)
    assert decision.verdict == Verdict.ALLOW
    assert decision.delegation_id == deleg["delegation_id"]
    assert decision.delegation_exp == deleg["exp"]


# --------------------------------------------------------------------------
# 2. Forgery: a delegation signed by ANY key outside the dedicated owner
# trust root -- including a key the agent itself could plausibly hold --
# must never verify. This is the structural proof that an agent cannot
# mint its own authority (module doctrine point 2).
# --------------------------------------------------------------------------

def test_forged_delegation_from_untrusted_key_denied():
    owner_key = _owner_key()
    agent_key = SigningKey.generate("agent-own-key")  # the agent's OWN key
    forged = _delegation(agent_key, max_amount=999999.0)  # tries to self-grant a huge budget
    authority = DelegationAuthority(_verifier(owner_key))  # trusts ONLY owner_key
    decision = _authorize(authority, forged)
    assert decision.verdict == Verdict.DENY
    assert "UNTRUSTED_ISSUER" in decision.reason


def test_tampered_signed_delegation_denied():
    """A delegation whose signed claims were mutated after signing (e.g. an
    attacker raising max_amount in transit) fails signature verification --
    the Ed25519 signature covers every claim."""
    owner_key = _owner_key()
    deleg = dict(_delegation(owner_key))
    deleg["max_amount"] = 999999.0  # tamper post-signature
    authority = DelegationAuthority(_verifier(owner_key))
    decision = _authorize(authority, deleg, amount=999999.0)
    assert decision.verdict == Verdict.DENY
    assert "INVALID_DELEGATION_SIGNATURE" in decision.reason


def test_malformed_delegation_missing_field_denied():
    owner_key = _owner_key()
    deleg = dict(_delegation(owner_key))
    del deleg["max_amount"]
    # Re-signing would fix the signature but the point is a RAW malformed
    # dict (e.g. truncated in transit) is rejected before any field logic.
    authority = DelegationAuthority(_verifier(owner_key))
    decision = _authorize(authority, deleg)
    assert decision.verdict == Verdict.DENY


def test_non_dict_delegation_denied():
    owner_key = _owner_key()
    authority = DelegationAuthority(_verifier(owner_key))
    decision = _authorize(authority, "not-a-delegation")
    assert decision.verdict == Verdict.DENY
    assert "NO_DELEGATION" in decision.reason


# --------------------------------------------------------------------------
# 3. Scope escalation: every authorization-bearing dimension is checked
# independently, and a mismatch on ANY of them denies -- the proposal can
# never talk its way into a wider grant than what the owner actually
# signed.
# --------------------------------------------------------------------------

def test_action_outside_scope_denied():
    owner_key = _owner_key()
    deleg = _delegation(owner_key)
    authority = DelegationAuthority(_verifier(owner_key))
    decision = _authorize(authority, deleg, action="send_payment_bulk")
    assert decision.verdict == Verdict.DENY
    assert "ACTION_SCOPE_MISMATCH" in decision.reason


def test_resource_outside_scope_denied():
    owner_key = _owner_key()
    deleg = _delegation(owner_key)
    authority = DelegationAuthority(_verifier(owner_key))
    decision = _authorize(authority, deleg, resource="acct-OTHER")
    assert decision.verdict == Verdict.DENY
    assert "RESOURCE_SCOPE_MISMATCH" in decision.reason


def test_recipient_outside_scope_denied():
    owner_key = _owner_key()
    deleg = _delegation(owner_key)
    authority = DelegationAuthority(_verifier(owner_key))
    decision = _authorize(authority, deleg, recipient="attacker-999")
    assert decision.verdict == Verdict.DENY
    assert "RECIPIENT_SCOPE_MISMATCH" in decision.reason


def test_currency_mismatch_denied_never_silently_converted():
    owner_key = _owner_key()
    deleg = _delegation(owner_key, currency="EUR")
    authority = DelegationAuthority(_verifier(owner_key))
    decision = _authorize(authority, deleg, currency="USD")
    assert decision.verdict == Verdict.DENY
    assert "CURRENCY_MISMATCH" in decision.reason


def test_amount_exceeding_per_operation_ceiling_denied_not_clamped():
    """Unlike MandateAuthority's CONSTRAIN, a delegation never silently
    clamps an over-ceiling amount down -- it denies outright."""
    owner_key = _owner_key()
    deleg = _delegation(owner_key, max_amount=500.0)
    authority = DelegationAuthority(_verifier(owner_key))
    decision = _authorize(authority, deleg, amount=500.01)
    assert decision.verdict == Verdict.DENY
    assert "AMOUNT_EXCEEDS_DELEGATION" in decision.reason


def test_zero_or_negative_amount_denied():
    owner_key = _owner_key()
    deleg = _delegation(owner_key)
    authority = DelegationAuthority(_verifier(owner_key))
    for bad_amount in (0.0, -50.0):
        decision = _authorize(authority, deleg, amount=bad_amount)
        assert decision.verdict == Verdict.DENY


def test_non_numeric_amount_denied():
    owner_key = _owner_key()
    deleg = _delegation(owner_key)
    authority = DelegationAuthority(_verifier(owner_key))
    decision = _authorize(authority, deleg, amount="100")  # string, not a number
    assert decision.verdict == Verdict.DENY
    assert "INVALID_AMOUNT" in decision.reason


def test_purpose_mismatch_denied():
    owner_key = _owner_key()
    deleg = _delegation(owner_key, purpose="vendor_payment")
    authority = DelegationAuthority(_verifier(owner_key))
    decision = _authorize(authority, deleg, purpose="payroll")
    assert decision.verdict == Verdict.DENY
    assert "PURPOSE_MISMATCH" in decision.reason


def test_amount_exactly_at_ceiling_allowed():
    """Non-vacuity / boundary sanity: the ceiling itself is inclusive."""
    owner_key = _owner_key()
    deleg = _delegation(owner_key, max_amount=500.0)
    authority = DelegationAuthority(_verifier(owner_key))
    decision = _authorize(authority, deleg, amount=500.0)
    assert decision.verdict == Verdict.ALLOW


# --------------------------------------------------------------------------
# 4. Transfer prevention (subject mismatch) and cross-tenant attacks.
# --------------------------------------------------------------------------

def test_subject_mismatch_prevents_transfer_to_another_agent():
    owner_key = _owner_key()
    deleg = _delegation(owner_key, subject="agent/payments-bot")
    authority = DelegationAuthority(_verifier(owner_key))
    decision = _authorize(authority, deleg, subject="agent/OTHER-bot")
    assert decision.verdict == Verdict.DENY
    assert "SUBJECT_MISMATCH" in decision.reason


def test_cross_tenant_attack_denied():
    owner_key = _owner_key()
    deleg = _delegation(owner_key, tenant_id="tenant-1")
    authority = DelegationAuthority(_verifier(owner_key))
    decision = _authorize(authority, deleg, tenant_id="tenant-2-ATTACKER")
    assert decision.verdict == Verdict.DENY
    assert "TENANT_MISMATCH" in decision.reason


def test_policy_hash_binding_mismatch_denied():
    owner_key = _owner_key()
    deleg = _delegation(owner_key, policy_hash="sha256:" + "a" * 64)
    authority = DelegationAuthority(_verifier(owner_key))
    decision = _authorize(authority, deleg, policy_hash="sha256:" + "b" * 64)
    assert decision.verdict == Verdict.DENY
    assert "POLICY_BINDING_MISMATCH" in decision.reason


# --------------------------------------------------------------------------
# 5. Expiry / validity window.
# --------------------------------------------------------------------------

def test_expired_delegation_denied():
    owner_key = _owner_key()
    deleg = _delegation(owner_key, not_before=NOW - 100, not_after=NOW - 1, issued_at=NOW - 100)
    authority = DelegationAuthority(_verifier(owner_key))
    decision = _authorize(authority, deleg, now=NOW)
    assert decision.verdict == Verdict.DENY
    assert "DELEGATION_EXPIRED" in decision.reason


def test_not_yet_valid_delegation_denied():
    owner_key = _owner_key()
    deleg = _delegation(owner_key, not_before=NOW + 100, not_after=NOW + 3600, issued_at=NOW)
    authority = DelegationAuthority(_verifier(owner_key))
    decision = _authorize(authority, deleg, now=NOW)
    assert decision.verdict == Verdict.DENY
    assert "DELEGATION_NOT_YET_VALID" in decision.reason


# --------------------------------------------------------------------------
# 6. Revocation.
# --------------------------------------------------------------------------

def test_revoked_delegation_denied():
    owner_key = _owner_key()
    deleg = _delegation(owner_key, revocation_required=True)
    registry = InMemoryRevocationRegistry()
    run(registry.revoke(deleg["delegation_id"]))
    authority = DelegationAuthority(_verifier(owner_key, revocation_registry=registry))
    decision = _authorize(authority, deleg)
    assert decision.verdict == Verdict.DENY
    assert "DELEGATION_REVOKED" in decision.reason


def test_revocation_required_but_no_registry_configured_fails_closed():
    owner_key = _owner_key()
    deleg = _delegation(owner_key, revocation_required=True)
    verifier = DelegationVerifier(
        trusted_owner_keys={owner_key.kid: owner_key.public_key()}, revocation_registry=None,
    )
    authority = DelegationAuthority(verifier)
    decision = _authorize(authority, deleg)
    assert decision.verdict == Verdict.DENY
    assert "REVOCATION_REQUIRED" in decision.reason


def test_revocation_backend_unavailable_fails_closed():
    owner_key = _owner_key()
    deleg = _delegation(owner_key, revocation_required=True)

    class _RaisingRevocationRegistry:
        async def check(self, delegation_id):
            raise ConnectionError("simulated backend outage")

        async def revoke(self, delegation_id):
            raise ConnectionError("simulated backend outage")

    verifier = DelegationVerifier(
        trusted_owner_keys={owner_key.kid: owner_key.public_key()},
        revocation_registry=_RaisingRevocationRegistry(),
    )
    authority = DelegationAuthority(verifier)
    decision = _authorize(authority, deleg)
    # DelegationVerifier.verify() wraps _verify() in a bare except -> fail closed
    assert decision.verdict == Verdict.DENY


def test_revocation_unavailable_status_fails_closed():
    owner_key = _owner_key()
    deleg = _delegation(owner_key, revocation_required=True)

    class _UnavailableRegistry:
        async def check(self, delegation_id):
            return RevocationStatus.UNAVAILABLE

    verifier = DelegationVerifier(
        trusted_owner_keys={owner_key.kid: owner_key.public_key()},
        revocation_registry=_UnavailableRegistry(),
    )
    authority = DelegationAuthority(verifier)
    decision = _authorize(authority, deleg)
    assert decision.verdict == Verdict.DENY
    assert "REVOCATION_UNAVAILABLE" in decision.reason


# --------------------------------------------------------------------------
# 7. Issuance-time fail-closed validation: a malformed delegation can
# never be signed in the first place (see delegation.py's module docstring
# on why this matters -- an empty scope dimension would otherwise let
# DelegationAuthority silently skip that check later).
# --------------------------------------------------------------------------

@pytest.mark.parametrize("field,bad_value", [
    ("consent_ref", ""),
    ("consent_ref", None),
    ("purpose", ""),
    ("action_scope", []),
    ("resource_scope", []),
    ("recipient_scope", []),
    ("currency", ""),
    ("max_amount", 0.0),
    ("max_amount", -5.0),
    ("max_amount", "100"),
])
def test_issue_delegation_rejects_malformed_input(field, bad_value):
    owner_key = _owner_key()
    kw = dict(
        owner_id="owner/alex", subject="agent/payments-bot", tenant_id=TENANT,
        purpose=PURPOSE, action_scope=[ACTION], resource_scope=[RESOURCE],
        recipient_scope=["vendor-*"], currency="EUR", max_amount=500.0,
        not_before=NOW - 10, not_after=NOW + 3600, issued_at=NOW - 10,
        consent_ref="sha256:consent-abc",
    )
    kw[field] = bad_value
    with pytest.raises(ValueError):
        issue_delegation(owner_key, **kw)


def test_issue_delegation_rejects_non_positive_duration():
    owner_key = _owner_key()
    with pytest.raises(ValueError):
        issue_delegation(
            owner_key, owner_id="owner/alex", subject="agent/payments-bot", tenant_id=TENANT,
            purpose=PURPOSE, action_scope=[ACTION], resource_scope=[RESOURCE],
            recipient_scope=["vendor-*"], currency="EUR", max_amount=500.0,
            not_before=NOW, not_after=NOW, issued_at=NOW,  # exp == nbf
            consent_ref="sha256:consent-abc",
        )


# --------------------------------------------------------------------------
# 8. Clock-trust fail-closed (reuses the same TrustedTimeSource contract
# every other PR #122 component already uses).
# --------------------------------------------------------------------------

def test_untrusted_time_source_fails_closed():
    owner_key = _owner_key()
    deleg = _delegation(owner_key)

    class _AlwaysUntrusted(TrustedTimeSource):
        async def now(self):
            raise TimeTrustError("CLOCK_UNTRUSTED", "simulated: time source down")

    verifier = DelegationVerifier(
        trusted_owner_keys={owner_key.kid: owner_key.public_key()},
        revocation_registry=InMemoryRevocationRegistry(),
        time_source=_AlwaysUntrusted(),
    )
    result = run(verifier.verify(
        deleg, subject="agent/payments-bot", tenant_id=TENANT, action=ACTION, resource=RESOURCE,
        now=None,  # force internal resolution via the untrusted time source
    ))
    assert not result.ok
    assert "CLOCK_UNTRUSTED" in result.reason


# --------------------------------------------------------------------------
# 9. Atomic cumulative budget helpers (direct velocity.py reuse) --
# concurrent spending / transaction splitting, single process.
# ``tests/test_delegation_governance_service.py`` additionally covers this
# over REAL Redis across simulated concurrent gateway instances.
# --------------------------------------------------------------------------

def test_cumulative_budget_enforced_atomically_across_split_operations():
    owner_key = _owner_key()
    deleg = _delegation(owner_key, max_amount=500.0)
    vel = InMemoryVelocityRegistry()
    limit = delegation_velocity_limit(deleg)

    async def _go():
        amounts = [200.0, 200.0, 200.0]  # 600 total > 500 ceiling
        admitted = 0
        for amt in amounts:
            desc = delegation_velocity_descriptor(deleg, amount=amt, currency="EUR", recipient=RECIPIENT)
            outcome = await vel.reserve(limit, desc)
            if outcome.ok:
                admitted += 1
        return admitted

    admitted = run(_go())
    assert admitted == 2, "a split into 3x200 against a 500 ceiling must admit exactly 2, never all 3"


def test_cumulative_budget_is_scoped_per_delegation_not_shared():
    """Two DIFFERENT delegations (even for the same agent/tenant) must have
    INDEPENDENT cumulative ceilings -- confirms the velocity scope key is
    keyed by delegation_id, not some shared/coarser dimension."""
    owner_key = _owner_key()
    deleg_a = _delegation(owner_key, max_amount=100.0, delegation_id="deleg-a")
    deleg_b = _delegation(owner_key, max_amount=100.0, delegation_id="deleg-b")
    vel = InMemoryVelocityRegistry()

    async def _go():
        limit_a = delegation_velocity_limit(deleg_a)
        limit_b = delegation_velocity_limit(deleg_b)
        desc_a = delegation_velocity_descriptor(deleg_a, amount=90.0, currency="EUR", recipient=RECIPIENT)
        desc_b = delegation_velocity_descriptor(deleg_b, amount=90.0, currency="EUR", recipient=RECIPIENT)
        out_a = await vel.reserve(limit_a, desc_a)
        out_b = await vel.reserve(limit_b, desc_b)
        return out_a.ok, out_b.ok

    ok_a, ok_b = run(_go())
    assert ok_a and ok_b, "independent delegations must not share one cumulative ceiling"
