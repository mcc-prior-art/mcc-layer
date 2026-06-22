"""Authority model: mandates and the action -> authority -> verdict map.

This is the missing half of the formula. The decision engine signs a
verdict; the gate enforces a signed token; the audit chain records. But a
verdict has to come from *somewhere*, and in MCC-Core it does not come from
a free-floating condition like ``amount <= 5000``. It comes from authority:

    An identity presents an action.
    MCC-Core checks whether that identity holds a *verified mandate*
    for the authority the action requires.
    The verdict follows from the answer.

Intent is not authority. A request to act is not a right to act. The only
thing that converts intent into an executable verdict is a mandate that was
granted ahead of time and is still valid.

The configuration is deliberately declarative and tiny — a registry of
mandates plus a list of action policies. It is not a DSL. On a pilot these
are hardcoded for a single client (see ``gateway/pilot_policy.py``).
"""

from __future__ import annotations

import fnmatch
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .core import Verdict


@dataclass(frozen=True)
class Mandate:
    """A verified grant of authority to one identity.

    A mandate is the unit of "who is allowed to do what". It binds a
    ``holder`` (identity) to an ``authority`` scope, optionally narrowed by
    ``constraints`` (e.g. ``{"max_amount": 5000}``) and bounded in time by
    ``expires_at``. Absence of a matching, unexpired mandate is, by default,
    absence of authority — and therefore not an ALLOW.
    """

    holder: str
    authority: str
    constraints: Dict[str, Any] = field(default_factory=dict)
    expires_at: Optional[int] = None  # unix seconds; None = no expiry
    granted_by: str = "axlogiq/pilot"

    def is_valid(self, now: int) -> bool:
        return self.expires_at is None or now < self.expires_at


class MandateRegistry:
    """The set of mandates MCC-Core currently trusts.

    On a pilot the registry is loaded from hardcoded config. In production it
    would be backed by a verifiable store (each mandate itself signed); the
    lookup contract is identical, so nothing downstream changes.
    """

    def __init__(self, mandates: List[Mandate]) -> None:
        self._by_holder: Dict[str, List[Mandate]] = {}
        for mandate in mandates:
            self._by_holder.setdefault(mandate.holder, []).append(mandate)

    def find(self, identity: str, authority: str, *, now: int) -> Optional[Mandate]:
        """Return the holder's valid mandate for ``authority``, or None."""
        for mandate in self._by_holder.get(identity, []):
            if mandate.authority == authority and mandate.is_valid(now):
                return mandate
        return None

    @classmethod
    def from_config(cls, config: Dict[str, List[Dict[str, Any]]]) -> "MandateRegistry":
        """Build from ``{identity: [{"authority": ..., "constraints": ...}, ...]}``."""
        mandates: List[Mandate] = []
        for holder, grants in config.items():
            for grant in grants:
                mandates.append(
                    Mandate(
                        holder=holder,
                        authority=grant["authority"],
                        constraints=dict(grant.get("constraints", {})),
                        expires_at=grant.get("expires_at"),
                        granted_by=grant.get("granted_by", "axlogiq/pilot"),
                    )
                )
        return cls(mandates)


@dataclass(frozen=True)
class ActionPolicy:
    """Maps an action pattern to the authority it requires and the resulting
    verdicts.

    ``action`` is an ``fnmatch`` glob (e.g. ``"send_payment"``,
    ``"POST api.stripe.com/*"``). The first policy whose pattern matches an
    action wins, so order policies most-specific first.

    Verdict slots, each one of the four canonical verdicts:

    * ``on_mandate``     — holder presents a valid mandate and the context
                           satisfies its constraints. Default ``ALLOW``.
    * ``on_violation``   — holder presents a valid mandate but the context
                           breaches a constraint (e.g. amount over the cap).
                           Default ``CONSTRAIN``: execution may proceed only
                           within the mandate's bounds.
    * ``without_mandate``— no valid mandate for the required authority.
                           Default ``ESCALATE``: a human must grant authority.

    ``requires=None`` marks an action for which no mandate can ever suffice
    (e.g. an irreversibly destructive action); it always resolves to
    ``without_mandate`` — set that to ``DENY`` for a hard block.
    """

    action: str
    requires: Optional[str]
    on_mandate: Verdict = Verdict.ALLOW
    on_violation: Verdict = Verdict.CONSTRAIN
    without_mandate: Verdict = Verdict.ESCALATE

    @classmethod
    def from_config(cls, item: Dict[str, Any]) -> "ActionPolicy":
        def verdict(key: str, default: Verdict) -> Verdict:
            raw = item.get(key)
            return Verdict(raw) if raw is not None else default

        return cls(
            action=item["action"],
            requires=item.get("requires"),
            on_mandate=verdict("on_mandate", Verdict.ALLOW),
            on_violation=verdict("on_violation", Verdict.CONSTRAIN),
            without_mandate=verdict("without_mandate", Verdict.ESCALATE),
        )


@dataclass(frozen=True)
class AuthorityDecision:
    """The verdict the authority model produced, with everything needed to
    audit *why*: which policy matched, which mandate (if any) was relied on,
    and the constraints that bind execution."""

    verdict: Verdict
    reason: str
    constraints: Dict[str, Any]
    matched_action: Optional[str]
    authority_required: Optional[str]
    mandate_holder: Optional[str]


def _constraint_violations(
    constraints: Dict[str, Any], context: Dict[str, Any]
) -> List[str]:
    """Check context against a mandate's constraints.

    A tiny, fixed convention — not a DSL:

    * ``max_<field>``     -> ``context[field] <= value``
    * ``min_<field>``     -> ``context[field] >= value``
    * ``allowed_<field>`` -> ``context[field] in value``

    A field referenced by a constraint but missing from the context counts as
    a violation: the mandate's bound cannot be shown to hold, so it does not.
    """
    violations: List[str] = []
    for key, bound in constraints.items():
        if key.startswith("max_"):
            field_name = key[4:]
            value = context.get(field_name)
            if not isinstance(value, (int, float)) or value > bound:
                violations.append(f"{field_name}={value!r} exceeds max {bound!r}")
        elif key.startswith("min_"):
            field_name = key[4:]
            value = context.get(field_name)
            if not isinstance(value, (int, float)) or value < bound:
                violations.append(f"{field_name}={value!r} below min {bound!r}")
        elif key.startswith("allowed_"):
            field_name = key[8:]
            value = context.get(field_name)
            if value not in bound:
                violations.append(f"{field_name}={value!r} not in allowed set")
    return violations


class AuthorityModel:
    """Resolves ``(identity, action, context)`` into a verdict from mandates.

    Fail-closed by construction: if no action policy matches, the default is
    ``DENY``. No policy means no granted authority means no execution.
    """

    def __init__(
        self,
        *,
        registry: MandateRegistry,
        policies: List[ActionPolicy],
        default: Verdict = Verdict.DENY,
    ) -> None:
        self.registry = registry
        self.policies = list(policies)
        self.default = default

    @classmethod
    def from_config(cls, config: Dict[str, Any]) -> "AuthorityModel":
        registry = MandateRegistry.from_config(config.get("mandates", {}))
        policies = [ActionPolicy.from_config(item) for item in config.get("policies", [])]
        default_raw = config.get("default")
        default = Verdict(default_raw) if default_raw is not None else Verdict.DENY
        return cls(registry=registry, policies=policies, default=default)

    def _match(self, action: str) -> Optional[ActionPolicy]:
        for policy in self.policies:
            if fnmatch.fnmatchcase(action, policy.action):
                return policy
        return None

    def evaluate(
        self,
        *,
        identity: str,
        action: str,
        context: Optional[Dict[str, Any]] = None,
        now: Optional[int] = None,
    ) -> AuthorityDecision:
        context = context or {}
        now = int(now if now is not None else time.time())

        policy = self._match(action)
        if policy is None:
            return AuthorityDecision(
                verdict=self.default,
                reason=f"no policy governs action '{action}'; deny-by-default",
                constraints={},
                matched_action=None,
                authority_required=None,
                mandate_holder=None,
            )

        # An action with no satisfiable authority (requires=None) never gets a
        # mandate path: it resolves straight to its without_mandate verdict.
        if policy.requires is None:
            return AuthorityDecision(
                verdict=policy.without_mandate,
                reason=f"action '{action}' admits no mandate (requires=none)",
                constraints={},
                matched_action=policy.action,
                authority_required=None,
                mandate_holder=None,
            )

        mandate = self.registry.find(identity, policy.requires, now=now)
        if mandate is None:
            return AuthorityDecision(
                verdict=policy.without_mandate,
                reason=(
                    f"identity '{identity}' holds no verified mandate for "
                    f"authority '{policy.requires}'"
                ),
                constraints={},
                matched_action=policy.action,
                authority_required=policy.requires,
                mandate_holder=None,
            )

        violations = _constraint_violations(mandate.constraints, context)
        if violations:
            return AuthorityDecision(
                verdict=policy.on_violation,
                reason=(
                    f"mandate '{policy.requires}' held, but context breaches its "
                    f"bounds: {'; '.join(violations)}"
                ),
                constraints=dict(mandate.constraints),
                matched_action=policy.action,
                authority_required=policy.requires,
                mandate_holder=mandate.holder,
            )

        return AuthorityDecision(
            verdict=policy.on_mandate,
            reason=(
                f"verified mandate '{policy.requires}' held by '{identity}'"
            ),
            constraints=dict(mandate.constraints),
            matched_action=policy.action,
            authority_required=policy.requires,
            mandate_holder=mandate.holder,
        )
