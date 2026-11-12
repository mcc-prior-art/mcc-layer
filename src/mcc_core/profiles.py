"""Action-specific authorization profiles.

MCC-Core stays domain-neutral: the decision token model knows nothing about
payments. What *an action means* — which payload fields are authorization-
bearing, and how it aggregates for velocity — lives in a profile, selected per
action. Non-payment actions use the generic ``ActionProfile`` and carry no
payment fields at all. The payment vocabulary (source, beneficiary, amount,
currency) is introduced only by ``PaymentProfile`` and only ever travels inside
the canonical payload (covered by ``payload_hash``) and the opaque
``auth_claims`` map (covered by the Ed25519 signature).
"""

from __future__ import annotations

import fnmatch
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .authority import _representable_finite


@dataclass(frozen=True)
class VelocityDescriptor:
    """The aggregation dimensions and quantities an action contributes to
    velocity/aggregate limits. Domain-neutral: ``amount`` and ``destination``
    are simply optional — non-numeric, single-shot actions leave them unset."""

    dimensions: Dict[str, Any] = field(default_factory=dict)
    amount: Optional[float] = None
    currency: Optional[str] = None
    destination: Optional[str] = None


class ActionProfile:
    """Generic profile: the canonical payload is the context as given, there are
    no action-specific authorization claims, and velocity aggregates by actor,
    resource, and action only. This is what every non-payment action uses."""

    name = "generic"

    def canonical_payload(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return dict(context)

    def auth_claims(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return {}

    def velocity_descriptor(
        self,
        *,
        actor_id: Optional[str],
        resource_id: Optional[str],
        action: str,
        policy_scope: Optional[str],
        context: Dict[str, Any],
    ) -> VelocityDescriptor:
        return VelocityDescriptor(
            dimensions={
                "actor": actor_id,
                "resource": resource_id,
                "action": action,
                "policy_scope": policy_scope,
            }
        )


class PaymentProfile(ActionProfile):
    """Payment-like actions: source account/resource, beneficiary, amount, and
    currency are authorization-bearing.

    They are placed into the canonical payload (so ``payload_hash`` covers them)
    and surfaced as explicit ``auth_claims`` on the token (so they are first-
    class, signature-covered authorization facts). The velocity descriptor
    aggregates by actor and source, counts the beneficiary as a destination, and
    contributes the amount to cumulative ceilings.
    """

    name = "payment"
    required_fields: Tuple[str, ...] = ("source", "beneficiary_id", "amount", "currency")

    def canonical_payload(self, context: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(context)
        missing = [f for f in self.required_fields if f not in payload]
        if missing:
            raise ProfileError(
                f"payment profile requires fields {self.required_fields}; missing {missing}"
            )
        # Normalise amount so the canonical hash is stable across int/float input.
        raw_amount = payload["amount"]
        # R2: a bool is not an amount (float(True) == 1.0 would silently turn
        # ``true`` into a 1.0 payment, sidestepping delegation's own bool
        # rejection), and an unparseable value must be a clean ProfileError
        # (DENY), never an unhandled exception. Parseable numeric strings stay
        # accepted, exactly as before.
        if isinstance(raw_amount, bool) or not isinstance(raw_amount, (int, float, str)):
            raise ProfileError(
                f"payment amount must be a number; got {type(raw_amount).__name__}"
            )
        try:
            payload["amount"] = float(raw_amount)
        except OverflowError:
            # An int beyond the double range (e.g. a 10**400 JSON literal) is
            # an unsupported amount: a clean ProfileError, never an exception.
            raise ProfileError("payment amount is outside the supported numeric range")
        except (TypeError, ValueError):
            raise ProfileError(f"payment amount {raw_amount!r} is not a parseable number")
        # R2: a payment amount is a finite, non-negative quantity. float() turns
        # "nan" / "inf" / "-1e9" strings into exactly the values that slip past
        # ordered comparisons downstream, so reject them here, on every route
        # that canonicalizes a payment (mandate, approval, consensus, delegation).
        if not math.isfinite(payload["amount"]) or payload["amount"] < 0:
            raise ProfileError(
                f"payment amount must be a finite, non-negative number; got {context['amount']!r}"
            )
        payload["currency"] = str(payload["currency"]).upper()
        return payload

    def auth_claims(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "source": context.get("source"),
            "beneficiary_id": context.get("beneficiary_id"),
            "amount": float(context["amount"]) if "amount" in context else None,
            "currency": str(context["currency"]).upper() if "currency" in context else None,
        }

    def velocity_descriptor(
        self,
        *,
        actor_id: Optional[str],
        resource_id: Optional[str],
        action: str,
        policy_scope: Optional[str],
        context: Dict[str, Any],
    ) -> VelocityDescriptor:
        source = context.get("source", resource_id)
        return VelocityDescriptor(
            dimensions={
                "actor": actor_id,
                "source": source,
                "action": action,
                "policy_scope": policy_scope,
            },
            amount=float(context["amount"]) if "amount" in context else None,
            currency=str(context["currency"]).upper() if "currency" in context else None,
            destination=context.get("beneficiary_id"),
        )


class InfraProfile(ActionProfile):
    """Infrastructure operations (restart_service, change_firewall_rule,
    deploy_release, scale_cluster, rotate_secret, ...).

    The authorization-bearing fields are the **target** (the resource being
    operated on) and the **environment** (e.g. ``prod``/``staging``); both go
    into the canonical payload (covered by ``payload_hash``) and into signed
    ``auth_claims``. Profile-specific limits ride on the *universal* constraint
    convention — ``allowed_environment`` (an allow-list), ``max_replicas``, etc.
    — so the core gains no infrastructure vocabulary. Velocity aggregates by
    actor + target + environment.

    This is the demonstration of domain neutrality: a completely different
    domain, expressed entirely through a profile, with the universal token,
    gate, authority, audit, and replay semantics unchanged.
    """

    name = "infrastructure"
    required_fields: Tuple[str, ...] = ("target", "environment")

    def canonical_payload(self, context: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(context)
        missing = [f for f in self.required_fields if f not in payload]
        if missing:
            raise ProfileError(
                f"infrastructure profile requires fields {self.required_fields}; missing {missing}"
            )
        payload["environment"] = str(payload["environment"]).lower()
        _reject_oversized_int(payload, "replicas", self.name)
        return payload

    def auth_claims(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "target": context.get("target"),
            "environment": str(context["environment"]).lower() if "environment" in context else None,
            "change_ref": context.get("change_ref"),
        }

    def velocity_descriptor(
        self, *, actor_id, resource_id, action, policy_scope, context,
    ) -> VelocityDescriptor:
        replicas = context.get("replicas")
        return VelocityDescriptor(
            dimensions={
                "actor": actor_id,
                "target": context.get("target", resource_id),
                "environment": context.get("environment"),
                "action": action,
                "policy_scope": policy_scope,
            },
            amount=float(replicas) if isinstance(replicas, (int, float)) else None,
            destination=context.get("target"),
        )


class RoboticsProfile(ActionProfile):
    """Robotics actuation (move_to_zone, pick_object, release_object,
    enter_restricted_area, exceed_force_limit, ...).

    The authorization-bearing fields are the **robot** (the resource actuating)
    and the **zone** (where), plus optional ``object_id`` and ``force``; all go
    into the canonical payload (covered by ``payload_hash``) and into signed
    ``auth_claims``. Profile-specific safety limits ride the *universal*
    constraint convention — ``allowed_zone`` (an allow-list; a restricted zone
    is simply one not on it) and ``max_force`` (a ceiling). Velocity aggregates
    by actor + robot + zone.

    A second non-payment domain expressed entirely through a profile: the
    universal token, gate, authority, audit, and replay semantics are unchanged
    and gain no robotics vocabulary.
    """

    name = "robotics"
    required_fields: Tuple[str, ...] = ("robot", "zone")

    def canonical_payload(self, context: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(context)
        missing = [f for f in self.required_fields if f not in payload]
        if missing:
            raise ProfileError(
                f"robotics profile requires fields {self.required_fields}; missing {missing}"
            )
        payload["zone"] = str(payload["zone"]).lower()
        _reject_oversized_int(payload, "force", self.name)
        if "force" in payload and isinstance(payload["force"], (int, float)):
            payload["force"] = float(payload["force"])
        return payload

    def auth_claims(self, context: Dict[str, Any]) -> Dict[str, Any]:
        force = context.get("force")
        return {
            "robot": context.get("robot"),
            "zone": str(context["zone"]).lower() if "zone" in context else None,
            "object_id": context.get("object_id"),
            "force": float(force) if isinstance(force, (int, float)) else None,
        }

    def velocity_descriptor(
        self, *, actor_id, resource_id, action, policy_scope, context,
    ) -> VelocityDescriptor:
        force = context.get("force")
        return VelocityDescriptor(
            dimensions={
                "actor": actor_id,
                "robot": context.get("robot", resource_id),
                "zone": context.get("zone"),
                "action": action,
                "policy_scope": policy_scope,
            },
            amount=float(force) if isinstance(force, (int, float)) else None,
            destination=context.get("zone"),
        )


class ProfileError(Exception):
    """Raised when a context does not satisfy its action profile."""


def _reject_oversized_int(payload: Dict[str, Any], field_name: str, profile: str) -> None:
    """An int beyond the double range (e.g. a ``10**400`` JSON literal) in a
    numeric field this profile converts with ``float()`` is unsupported: a
    clean :class:`ProfileError` (DENY) here, at canonicalization, instead of an
    ``OverflowError`` from ``float()`` later (HTTP 500)."""
    value = payload.get(field_name)
    if isinstance(value, int) and not isinstance(value, bool) and not _representable_finite(value):
        raise ProfileError(f"{profile} field {field_name!r} is outside the supported numeric range")


class ProfileRegistry:
    """Maps action patterns to profiles; the default is the generic profile."""

    def __init__(
        self,
        mapping: Optional[List[Tuple[str, ActionProfile]]] = None,
        *,
        default: Optional[ActionProfile] = None,
    ) -> None:
        self._mapping = mapping or []
        self._default = default or ActionProfile()

    def for_action(self, action: str) -> ActionProfile:
        for pattern, profile in self._mapping:
            if fnmatch.fnmatchcase(action, pattern):
                return profile
        return self._default

    @classmethod
    def default_pilot(cls) -> "ProfileRegistry":
        """Pilot wiring: payments -> PaymentProfile, infrastructure ->
        InfraProfile, robotics -> RoboticsProfile, everything else generic."""
        infra = InfraProfile()
        robotics = RoboticsProfile()
        return cls(
            [
                ("send_payment", PaymentProfile()),
                ("pay_*", PaymentProfile()),
                ("restart_service", infra),
                ("change_firewall_rule", infra),
                ("deploy_release", infra),
                ("scale_cluster", infra),
                ("rotate_secret", infra),
                ("move_to_zone", robotics),
                ("pick_object", robotics),
                ("release_object", robotics),
                ("enter_restricted_area", robotics),
                ("exceed_force_limit", robotics),
            ]
        )
