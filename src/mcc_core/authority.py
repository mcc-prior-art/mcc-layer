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
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

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
            # R3: refuse to load a policy whose constraints cannot be
            # enforced as written (fail-closed startup, never a silent skip).
            try:
                validate_constraints(mandate.constraints)
            except ConstraintError as exc:
                raise ConstraintError(
                    f"mandate {mandate.authority!r} for {mandate.holder!r}: {exc}"
                ) from None
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
    the constraints that bind execution, and — crucially for CONSTRAIN — the
    ``forward_context`` that has actually been rewritten to fit those bounds.

    ``forward_context`` is the context an executable verdict authorizes: the
    original context for ALLOW, the rewritten (clamped) context for CONSTRAIN.
    The decision token is signed over exactly this, so the gate's payload-hash
    check binds to the body that will really be forwarded. ``applied_changes``
    is a human-readable list of the rewrites performed (empty for ALLOW)."""

    verdict: Verdict
    reason: str
    constraints: Dict[str, Any]
    matched_action: Optional[str]
    authority_required: Optional[str]
    mandate_holder: Optional[str]
    forward_context: Dict[str, Any] = field(default_factory=dict)
    applied_changes: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Constraint contract (R3 remediation)
# --------------------------------------------------------------------------
#
# The ONE supported constraint convention, shared by every execution route
# (MandateAuthority for signed / approval-minted mandates, AuthorityModel for
# config policy: gateway /evaluate, egress proxy, governed agent):
#
#   max_<field>      context[field] <= bound      bound: finite number
#   min_<field>      context[field] >= bound      bound: finite number
#   allowed_<field>  context[field] in bound      bound: list of JSON scalars
#
# Operators are exact and case-sensitive. ``<field>`` is a non-empty path of
# segments ``[A-Za-z0-9_-]+`` joined by ``.`` (e.g. ``amount``,
# ``body.amount`` -- the egress proxy's flat canonical keys), matched
# literally against the context key. The convention is domain-neutral: any
# profile may constrain any of its own fields this way (the documented
# extension mechanism -- new fields, never new operators).
#
# Anything else -- an unknown key, a misspelled / wrongly-cased / suffix-form
# operator (``max-amount``, ``amount_max``, ``MAX_amount``, ``maxAmount``), an
# unsupported operator (``denied_<field>``), a bare field (``currency``), a
# malformed path, a wrong-typed bound, or an unsatisfiable min > max -- is an
# INVALID constraint set. Before R3 such keys were silently skipped, so the
# restriction they were meant to express simply did not exist (fail-open).
# Now an invalid constraint set is never evaluated, never clamped, never
# corrected and never discarded: it is a denial everywhere.

CONSTRAINT_OPERATORS = ("max_", "min_", "allowed_")
_FIELD_PATH = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*")


class ConstraintError(ValueError):
    """A constraint set that is not expressible in the supported contract.
    Raised at issuance / load time; at evaluation time it is a DENY."""


def _parse_constraint_key(key: Any):
    """Return ``(operator, field)`` for a supported key, else ``None``."""
    if not isinstance(key, str):
        return None
    for op in CONSTRAINT_OPERATORS:
        if key.startswith(op):
            field_path = key[len(op):]
            if _FIELD_PATH.fullmatch(field_path):
                return op, field_path
            return None
    return None


def _json_scalar(value: Any) -> bool:
    if value is None or isinstance(value, (str, bool)):
        return True
    return isinstance(value, (int, float)) and math.isfinite(value)


def constraint_errors(constraints: Any) -> List[str]:
    """Validate a constraint set against the supported contract. Returns a
    list of human-readable problems; empty means the set is valid. Pure and
    total: never raises, whatever it is given."""
    if constraints is None:
        return []
    if not isinstance(constraints, Mapping):
        return [f"constraints must be an object, got {type(constraints).__name__}"]
    errors: List[str] = []
    numeric: Dict[str, Dict[str, Any]] = {}
    for key, bound in constraints.items():
        parsed = _parse_constraint_key(key)
        if parsed is None:
            errors.append(
                f"unsupported constraint key {key!r} (supported: "
                f"max_<field>, min_<field>, allowed_<field>; operators are exact "
                f"and lowercase, <field> is a dotted path of [A-Za-z0-9_-] segments)"
            )
            continue
        op, field_path = parsed
        if op in ("max_", "min_"):
            if not _finite_number(bound):
                errors.append(f"{key!r} bound {bound!r} must be a finite number")
                continue
            numeric.setdefault(field_path, {})[op] = bound
        else:  # allowed_
            if isinstance(bound, (str, bytes)) or not isinstance(bound, (list, tuple, set, frozenset)):
                # A string bound used to degrade to substring matching.
                errors.append(f"{key!r} bound must be a list of allowed values, got {type(bound).__name__}")
            elif not all(_json_scalar(v) for v in bound):
                errors.append(f"{key!r} allowed values must be JSON scalars")
    for field_path, ops in numeric.items():
        if "min_" in ops and "max_" in ops and ops["min_"] > ops["max_"]:
            errors.append(
                f"min_{field_path}={ops['min_']!r} exceeds max_{field_path}={ops['max_']!r} (unsatisfiable)"
            )
    return errors


def validate_constraints(constraints: Any) -> None:
    """Raise :class:`ConstraintError` if ``constraints`` is invalid (issuance /
    load-time check). Evaluation-time callers use :func:`constraint_errors`."""
    errors = constraint_errors(constraints)
    if errors:
        raise ConstraintError("invalid constraints: " + "; ".join(errors))


def _finite_number(value: Any) -> bool:
    """R2: a usable bound/value -- a real ``int``/``float`` (not a bool) that is finite.
    NaN, +inf and -inf are never usable: every ordered comparison with NaN is
    False (so ``nan > bound`` would read as "within the cap"), and an infinite
    value can never be the exact authorized quantity."""
    # bool is an int subclass: ``True`` would otherwise be checked as ``1``
    # while the actuator receives the boolean itself (type confusion).
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


def _implicit_zero_floor(constraints: Dict[str, Any], field_name: str, bound: Any) -> bool:
    """R2: a ``max_<field>`` cap with NO explicit ``min_<field>`` bounds a
    non-negative quantity (an amount, a percentage, a count, a force...), so
    values below zero are outside the mandate. An explicit ``min_<field>``
    defines the lower bound itself (and may legitimately be negative), and a
    negative cap obviously describes a negative-valued field -- neither gets
    the implicit floor."""
    return f"min_{field_name}" not in constraints and bound >= 0


def _constraint_violations(
    constraints: Dict[str, Any], context: Dict[str, Any]
) -> List[str]:
    """Check context against a mandate's constraints.

    A tiny, fixed convention — not a DSL:

    * ``max_<field>``     -> ``context[field] <= value`` (and ``>= 0`` when no
      ``min_<field>`` is given -- see ``_implicit_zero_floor``)
    * ``min_<field>``     -> ``context[field] >= value``
    * ``allowed_<field>`` -> ``context[field] in value``

    A field referenced by a constraint but missing from the context counts as
    a violation: the mandate's bound cannot be shown to hold, so it does not.
    So does a non-finite (NaN / +-inf) value or bound (R2): fail-closed.
    """
    errors = constraint_errors(constraints)
    if errors:
        # R3: an invalid set is never partially evaluated (that is exactly how
        # an unknown key used to be skipped): every problem is a violation.
        return [f"INVALID_CONSTRAINT: {e}" for e in errors]
    violations: List[str] = []
    for key, bound in constraints.items():
        if key.startswith("max_"):
            field_name = key[4:]
            value = context.get(field_name)
            if not _finite_number(bound):
                violations.append(f"max_{field_name} bound {bound!r} is not a finite number")
            elif not _finite_number(value):
                violations.append(f"{field_name}={value!r} is not a finite number (max {bound!r})")
            elif value > bound:
                violations.append(f"{field_name}={value!r} exceeds max {bound!r}")
            elif value < 0 and _implicit_zero_floor(constraints, field_name, bound):
                violations.append(f"{field_name}={value!r} is negative (max {bound!r})")
        elif key.startswith("min_"):
            field_name = key[4:]
            value = context.get(field_name)
            if not _finite_number(bound):
                violations.append(f"min_{field_name} bound {bound!r} is not a finite number")
            elif not _finite_number(value):
                violations.append(f"{field_name}={value!r} is not a finite number (min {bound!r})")
            elif value < bound:
                violations.append(f"{field_name}={value!r} below min {bound!r}")
        elif key.startswith("allowed_"):
            field_name = key[8:]
            value = context.get(field_name)
            if value not in bound:
                violations.append(f"{field_name}={value!r} not in allowed set")
    return violations


def apply_constraints(
    constraints: Dict[str, Any], context: Dict[str, Any]
) -> Tuple[Dict[str, Any], List[str]]:
    """Rewrite ``context`` to fit the mandate's numeric bounds.

    This is what makes CONSTRAIN real rather than advisory: a value above a
    ``max_`` cap is clamped down to the cap, a value below a ``min_`` floor is
    raised to the floor. Returns ``(new_context, changes)``.

    Only ``max_``/``min_`` on present numeric fields are clampable — clamping
    is well-defined there. ``allowed_`` violations and missing/non-numeric
    fields are *not* rewritten here; there is no safe value to invent, so the
    caller treats a residual violation as DENY (it cannot be brought into
    compliance) rather than silently forwarding a non-conforming request.
    """
    new_context = dict(context)
    changes: List[str] = []
    if constraint_errors(constraints):
        # R3: never clamp under an invalid constraint set -- nothing is
        # "brought into compliance" with bounds that are not well-defined.
        return new_context, changes
    for key, bound in constraints.items():
        if key.startswith(("max_", "min_")):
            field_name = key[4:]
            value = new_context.get(field_name)
            if not _finite_number(value) or not _finite_number(bound):
                # Nothing safe to clamp (missing / non-numeric / NaN / +-inf
                # value, or an unusable bound): it stays a violation -> DENY.
                # A negative value under an implicit zero floor is likewise
                # never "clamped up": it is not raised into compliance below.
                continue
            if key.startswith("max_") and value > bound:
                new_context[field_name] = bound
                changes.append(f"{field_name}: {value} -> {bound} (max)")
            elif key.startswith("min_") and value < bound:
                new_context[field_name] = bound
                changes.append(f"{field_name}: {value} -> {bound} (min)")
    return new_context, changes


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

        constraints = dict(mandate.constraints)
        invalid = constraint_errors(constraints)
        if invalid:
            # R3: always DENY -- never the policy's on_violation verdict (an
            # ESCALATE would route an unenforceable bound to a human approval
            # that could then mint authority under it).
            return AuthorityDecision(
                verdict=Verdict.DENY,
                reason=f"INVALID_CONSTRAINTS on mandate '{policy.requires}': {'; '.join(invalid)}",
                constraints={},
                matched_action=policy.action,
                authority_required=policy.requires,
                mandate_holder=mandate.holder,
            )
        violations = _constraint_violations(constraints, context)
        if not violations:
            # Within the mandate's bounds: ALLOW, context unchanged.
            return AuthorityDecision(
                verdict=policy.on_mandate,
                reason=f"verified mandate '{policy.requires}' held by '{identity}'",
                constraints=constraints,
                matched_action=policy.action,
                authority_required=policy.requires,
                mandate_holder=mandate.holder,
                forward_context=dict(context),
            )

        # Bounds breached. If the policy chose to constrain, try to rewrite the
        # context into compliance. Anything left over after clamping cannot be
        # brought into compliance, so it fails closed to DENY.
        if policy.on_violation == Verdict.CONSTRAIN:
            constrained, changes = apply_constraints(constraints, context)
            residual = _constraint_violations(constraints, constrained)
            if residual:
                return AuthorityDecision(
                    verdict=Verdict.DENY,
                    reason=(
                        f"mandate '{policy.requires}' held, but request cannot be "
                        f"constrained into compliance: {'; '.join(residual)}"
                    ),
                    constraints=constraints,
                    matched_action=policy.action,
                    authority_required=policy.requires,
                    mandate_holder=mandate.holder,
                )
            return AuthorityDecision(
                verdict=Verdict.CONSTRAIN,
                reason=(
                    f"mandate '{policy.requires}' bounds applied: "
                    f"{'; '.join(changes)}"
                ),
                constraints=constraints,
                matched_action=policy.action,
                authority_required=policy.requires,
                mandate_holder=mandate.holder,
                forward_context=constrained,
                applied_changes=changes,
            )

        # Policy escalates or denies on violation rather than constraining.
        return AuthorityDecision(
            verdict=policy.on_violation,
            reason=(
                f"mandate '{policy.requires}' held, but context breaches its "
                f"bounds: {'; '.join(violations)}"
            ),
            constraints=constraints,
            matched_action=policy.action,
            authority_required=policy.requires,
            mandate_holder=mandate.holder,
        )
