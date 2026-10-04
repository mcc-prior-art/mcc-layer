"""Independent authority-side policy — the authority plane's own decision.

Closes the "unattended operator auto-approves whatever it is shown" gap: an
ESCALATE verdict means no mandate was found for the actor/action, so a human
(or, for an unattended demo, an independently configured authority policy)
must separately decide ALLOW/DENY for the EXACT operation before any approval
mandate is minted.

This module is deliberately a SEPARATE decision surface from
``mcc_core.authority.AuthorityModel`` (the main mandate-driven policy that
produced the ESCALATE verdict in the first place). It is:

* configured independently of the agent (loaded from a file path supplied at
  gateway/runtime startup — never from a request body, never writable by a
  proposer-facing process);
* evaluated against the operation's SERVER-STORED, authoritative fields
  (``ApprovalRecord``'s own actor/action/resource/payload/policy_hash/tenant),
  never against caller-supplied fields at approve-time;
* fail-closed on every ambiguity: a missing policy, a malformed policy file, a
  rule that cannot be evaluated, a missing logical_operation_id, a payload
  missing a bound field, or simply no matching rule all resolve to DENY.

``PROPOSAL != PERMISSION``: a compromised proposer can create arbitrarily many
forged or legitimate-looking pending requests, but none of them is approved
unless it falls EXACTLY within a rule this policy's owner configured in
advance — the proposer never supplies the decision, only facts describing its
request.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, Mapping, Optional, Tuple


class AuthorityPolicyError(Exception):
    """Raised when the authority policy itself is missing or malformed.

    Callers MUST treat this as "no usable authority policy" and fail closed
    (DENY) — never catch this and silently proceed as if no policy were
    configured when one was expected."""


_VALID_BOUND_OPS = {"in", "max", "min", "eq"}


class _Missing:
    def __repr__(self) -> str:
        return "<missing>"


_MISSING = _Missing()


@dataclass(frozen=True)
class AuthorityPolicyDecision:
    verdict: str  # "ALLOW" or "DENY" — no other value is ever produced.
    reason: str


@dataclass(frozen=True)
class AuthorityRule:
    """One independently-authored, exact ALLOW rule.

    Every binding field is REQUIRED and matched exactly (or via fnmatch for
    ``resource_pattern``) — there is no implicit wildcard for tenant or actor,
    because an ambiguous rule ("any tenant", "any actor") is exactly the kind
    of policy ambiguity this module must fail closed on, not silently permit.
    """

    action: str
    tenant: str
    actors: FrozenSet[str]
    resource_pattern: str
    payload_bounds: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    valid_from: Optional[int] = None
    valid_until: Optional[int] = None

    def __post_init__(self) -> None:
        if not self.action or not isinstance(self.action, str):
            raise AuthorityPolicyError("AuthorityRule.action must be a non-empty string")
        if not self.tenant or not isinstance(self.tenant, str):
            raise AuthorityPolicyError("AuthorityRule.tenant must be a non-empty string")
        if not self.actors:
            raise AuthorityPolicyError(
                "AuthorityRule.actors must be a non-empty set (no implicit 'any actor')"
            )
        if not self.resource_pattern or not isinstance(self.resource_pattern, str):
            raise AuthorityPolicyError(
                "AuthorityRule.resource_pattern must be a non-empty string "
                "('*' is a valid explicit wildcard, but must be stated)"
            )
        for field_name, bound in self.payload_bounds.items():
            if not isinstance(bound, Mapping) or len(bound) != 1:
                raise AuthorityPolicyError(
                    f"payload_bounds[{field_name!r}] must be a single-key mapping"
                )
            (op,) = bound.keys()
            if op not in _VALID_BOUND_OPS:
                raise AuthorityPolicyError(
                    f"payload_bounds[{field_name!r}] uses unknown operator {op!r}; "
                    f"expected one of {sorted(_VALID_BOUND_OPS)}"
                )

    def _action_matches(self, action: str) -> bool:
        if any(ch in self.action for ch in "*?["):
            return fnmatch.fnmatchcase(action, self.action)
        return action == self.action

    def _resource_matches(self, resource: Optional[str]) -> bool:
        candidate = resource if resource is not None else ""
        return fnmatch.fnmatchcase(candidate, self.resource_pattern)

    def _window_ok(self, now: int) -> bool:
        if self.valid_from is not None and now < self.valid_from:
            return False
        if self.valid_until is not None and now > self.valid_until:
            return False
        return True

    @staticmethod
    def _resolve(payload: Mapping[str, Any], dotted_key: str) -> Any:
        """Resolve ``dotted_key`` against ``payload``.

        Tries the LITERAL key first -- e.g. the egress canonical action
        (``egress_proxy.canonical_action.build_canonical_action``) encodes a
        JSON body as flat literal keys like ``"body.amount"``, not a nested
        ``{"body": {"amount": ...}}`` dict -- and only falls back to
        descending nested dicts segment-by-segment (e.g.
        ``{"body": {"amount": ...}}``) if no literal key matches. Returns a
        private sentinel distinct from any real value (including ``None``)
        when neither form is present, so a genuinely missing field is never
        confused with a present ``None``."""
        if dotted_key in payload:
            return payload[dotted_key]
        node: Any = payload
        for part in dotted_key.split("."):
            if not isinstance(node, Mapping) or part not in node:
                return _MISSING
            node = node[part]
        return node

    def _payload_satisfies(self, payload: Mapping[str, Any]) -> bool:
        for field_name, bound in self.payload_bounds.items():
            value = self._resolve(payload, field_name)
            if value is _MISSING:
                # Missing binding data for a field this rule cares about -> this
                # rule does not match (never silently skip the bound).
                return False
            (op, operand) = next(iter(bound.items()))
            try:
                if op == "in" and value not in operand:
                    return False
                if op == "eq" and value != operand:
                    return False
                if op == "max" and not (isinstance(value, (int, float)) and value <= operand):
                    return False
                if op == "min" and not (isinstance(value, (int, float)) and value >= operand):
                    return False
            except TypeError:
                return False
        return True

    def matches(self, *, tenant_id: str, actor: str, action: str, resource: Optional[str],
                payload: Mapping[str, Any], now: int) -> bool:
        return (
            self.tenant == tenant_id
            and actor in self.actors
            and self._action_matches(action)
            and self._resource_matches(resource)
            and self._window_ok(now)
            and self._payload_satisfies(payload)
        )


class AuthorityPolicy:
    """The independent authority-plane decision for ESCALATE auto-approval.

    Deny-by-default: the ONLY way to get ALLOW is an exact, fully-specified
    rule match. Everything else — malformed input, missing binding data, no
    match — is DENY.
    """

    def __init__(self, rules: Tuple[AuthorityRule, ...], *,
                 policy_hash_binding: Optional[str] = None) -> None:
        self._rules = tuple(rules)
        self._policy_hash_binding = policy_hash_binding

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> "AuthorityPolicy":
        if not isinstance(config, Mapping):
            raise AuthorityPolicyError("authority policy config must be a JSON object")
        unknown = set(config) - {"rules", "policy_hash_binding"}
        if unknown:
            raise AuthorityPolicyError(f"unknown authority policy keys: {sorted(unknown)}")
        raw_rules = config.get("rules")
        if not isinstance(raw_rules, list) or not raw_rules:
            raise AuthorityPolicyError(
                "authority policy must declare a non-empty 'rules' list "
                "(an empty/missing policy is ambiguous and must not be treated "
                "as 'no restriction')"
            )
        rules = []
        for i, raw in enumerate(raw_rules):
            if not isinstance(raw, Mapping):
                raise AuthorityPolicyError(f"rules[{i}] must be a JSON object")
            allowed_keys = {"action", "tenant", "actors", "resource_pattern",
                            "payload_bounds", "valid_from", "valid_until"}
            unknown_rule_keys = set(raw) - allowed_keys
            if unknown_rule_keys:
                raise AuthorityPolicyError(f"rules[{i}] has unknown keys: {sorted(unknown_rule_keys)}")
            try:
                rules.append(AuthorityRule(
                    action=raw["action"],
                    tenant=raw["tenant"],
                    actors=frozenset(raw["actors"]),
                    resource_pattern=raw["resource_pattern"],
                    payload_bounds=raw.get("payload_bounds", {}),
                    valid_from=raw.get("valid_from"),
                    valid_until=raw.get("valid_until"),
                ))
            except KeyError as exc:
                raise AuthorityPolicyError(f"rules[{i}] missing required key: {exc}") from exc
        policy_hash_binding = config.get("policy_hash_binding")
        return cls(tuple(rules), policy_hash_binding=policy_hash_binding)

    @classmethod
    def from_file(cls, path: str) -> "AuthorityPolicy":
        try:
            raw = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise AuthorityPolicyError(f"authority policy file unavailable: {path!r} ({exc})") from exc
        try:
            config = json.loads(raw)
        except ValueError as exc:
            raise AuthorityPolicyError(f"authority policy file is not valid JSON: {path!r} ({exc})") from exc
        return cls.from_config(config)

    def decide(
        self, *, tenant_id: Optional[str], actor: Optional[str], action: Optional[str],
        resource: Optional[str], payload: Optional[Mapping[str, Any]],
        payload_hash: Optional[str], policy_hash: Optional[str],
        logical_operation_id: Optional[str], now: Optional[int] = None,
    ) -> AuthorityPolicyDecision:
        import time

        now = int(now if now is not None else time.time())

        if not actor or not isinstance(actor, str):
            return AuthorityPolicyDecision("DENY", "MISSING_BINDING_DATA: actor is required")
        if not action or not isinstance(action, str):
            return AuthorityPolicyDecision("DENY", "MISSING_BINDING_DATA: action is required")
        if not tenant_id or not isinstance(tenant_id, str):
            return AuthorityPolicyDecision("DENY", "MISSING_TENANT_IDENTITY")
        if not logical_operation_id or not isinstance(logical_operation_id, str):
            return AuthorityPolicyDecision("DENY", "MISSING_LOGICAL_OPERATION_ID")
        if self._policy_hash_binding is not None and policy_hash != self._policy_hash_binding:
            return AuthorityPolicyDecision("DENY", "POLICY_HASH_MISMATCH: stale or foreign policy version")

        candidate_payload: Mapping[str, Any] = payload if isinstance(payload, Mapping) else {}
        for i, rule in enumerate(self._rules):
            if rule.matches(tenant_id=tenant_id, actor=actor, action=action,
                            resource=resource, payload=candidate_payload, now=now):
                return AuthorityPolicyDecision("ALLOW", f"matched independent authority rule #{i}")
        return AuthorityPolicyDecision(
            "DENY",
            "NO_AUTHORITY_RULE_MATCHES: this exact operation was not pre-authorized "
            "by the independently configured authority policy",
        )


def authority_policy_from_env(
    env: Optional[Mapping[str, str]] = None,
    var_name: str = "MCC_AUTHORITY_POLICY_CONFIG",
) -> Optional[AuthorityPolicy]:
    """None when unset (no unattended auto-approval is configured at all — the
    deployment relies purely on explicit, authenticated human approval).

    Fail-closed when SET but unusable: raises ``AuthorityPolicyError`` rather
    than silently returning ``None``, so a deployer who intended an unattended
    authority policy never ends up, by a typo or a bad deploy, with no policy
    and (if a caller mistakenly treated that as "no restriction") effectively
    an unattended-auto-approve-everything regression."""
    import os

    env = os.environ if env is None else env
    path = env.get(var_name, "").strip()
    if not path:
        return None
    return AuthorityPolicy.from_file(path)
