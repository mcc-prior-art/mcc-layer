"""Hardcoded authority configuration for the first pilot client.

Deliberately not a YAML/DSL file and not a database — on a pilot the policy
is small, reviewed, and shipped as code so it can be read in one screen and
versioned with the runtime. When the second client arrives, this is the file
that forks; the engine, gateway, and interceptor do not.

Shape consumed by ``mcc_core.AuthorityModel.from_config``:

    mandates:  identity -> list of granted authorities (+ optional constraints)
    policies:  ordered list of action patterns -> required authority -> verdicts
    default:   verdict when no policy matches (fail-closed: DENY)
"""

from __future__ import annotations

from typing import Any, Dict

PILOT_POLICY: Dict[str, Any] = {
    # ---- Who holds what authority -------------------------------------
    "mandates": {
        # The payments agent may move money, but only up to a ceiling.
        "agent/payments-bot": [
            {"authority": "payments.send", "constraints": {"max_amount": 5000}},
        ],
        # The ops agent may read infrastructure state. It holds no mandate to
        # destroy anything — so destructive actions will not find authority.
        "agent/ops-bot": [
            {"authority": "infra.read"},
        ],
    },
    # ---- What each action requires, and the verdict that follows ------
    #
    # Order matters: first matching pattern wins. Most-specific first.
    "policies": [
        {
            # Within mandate + within the amount cap -> ALLOW.
            # Mandate held but amount over the cap     -> CONSTRAIN (cap binds).
            # No payments.send mandate                 -> ESCALATE (ask a human).
            "action": "send_payment",
            "requires": "payments.send",
            "on_mandate": "ALLOW",
            "on_violation": "CONSTRAIN",
            "without_mandate": "ESCALATE",
        },
        {
            # Reading infra is allowed for a holder of infra.read, else escalate.
            "action": "read_*",
            "requires": "infra.read",
            "on_mandate": "ALLOW",
            "without_mandate": "ESCALATE",
        },
        {
            # Irreversible destruction: no mandate can authorize it on the
            # pilot. requires=None routes straight to without_mandate=DENY.
            "action": "delete_*",
            "requires": None,
            "without_mandate": "DENY",
        },
    ],
    # No policy matched -> no authority -> DENY.
    "default": "DENY",
}


# Velocity / aggregate ceilings enforced at actuation time (the coordinator),
# distinct from the per-decision authority above. Action pattern -> list of
# limits. Hardcoded for the pilot, like the authority policy.
PILOT_VELOCITY: Dict[str, Any] = {
    "send_payment": [
        # No more than 3 payments per actor per minute.
        {"name": "payment_count", "window_seconds": 60, "max_count": 3,
         "aggregate_by": ["actor"], "on_exceed": "DENY"},
        # No more than 10,000 cumulative per actor per minute — this is the
        # ceiling that four split payments cannot bypass.
        {"name": "payment_amount", "window_seconds": 60, "max_amount": 10000,
         "aggregate_by": ["actor"], "on_exceed": "DENY"},
        # No more than 2 new beneficiaries per actor per minute.
        {"name": "payment_new_beneficiaries", "window_seconds": 60,
         "max_new_destinations": 2, "aggregate_by": ["actor"], "on_exceed": "ESCALATE"},
    ],
}
