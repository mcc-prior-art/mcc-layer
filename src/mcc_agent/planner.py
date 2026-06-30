"""Deterministic planner: a user goal -> a structured :class:`ActionProposal`.

This is the "model proposes" half of the formula. It is deliberately a small,
deterministic rule set so the full pilot and test suite run with **no external
LLM credentials** and are reproducible. An optional LLM planner may be added
later, but it must never make the default pilot depend on external credentials.

A plan is a *proposal*, never a permission. Whether the proposed action may
execute is decided entirely by MCC-Core, downstream of this planner.
"""

from __future__ import annotations

import re
import uuid
from typing import Optional

from .client import TRUSTED_ACTOR
from .errors import UnsupportedGoalError
from .models import ActionProposal

_AMOUNT = re.compile(r"(\d+(?:\.\d+)?)")


def _amount(goal: str, default: float = 0.0) -> float:
    m = _AMOUNT.search(goal.replace(",", ""))
    return float(m.group(1)) if m else default


def _ids(idempotency_key: Optional[str], transaction_id: Optional[str]):
    return (idempotency_key or f"idem-{uuid.uuid4().hex}",
            transaction_id or f"txn-{uuid.uuid4().hex}")


class DeterministicPlanner:
    """Maps a small set of realistic enterprise pilot goals to proposals."""

    def __init__(self, *, pilot_api_base: str, campaign_id: str = "camp-42") -> None:
        self.base = pilot_api_base.rstrip("/")
        self.campaign_id = campaign_id

    def plan(
        self,
        goal: str,
        *,
        actor: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        transaction_id: Optional[str] = None,
        destination_url: Optional[str] = None,
    ) -> ActionProposal:
        """Return a structured proposal for ``goal``.

        ``destination_url`` overrides the action's target URL (used to exercise
        SSRF / malformed-destination rejection). ``actor``/``idempotency_key``/
        ``transaction_id`` may be pinned (used to demonstrate replay)."""
        g = goal.lower()
        actor = actor or TRUSTED_ACTOR
        idem, txn = _ids(idempotency_key, transaction_id)

        def proposal(action_type, method, path, body, resource):
            return ActionProposal(
                goal=goal, actor=actor, action_type=action_type, method=method,
                url=destination_url or f"{self.base}{path}", body=body, resource=resource,
                transaction_id=txn, idempotency_key=idem,
                amount=body.get("amount") if isinstance(body, dict) else None)

        # --- prohibited / data exfiltration -> hard DENY ---
        if "prohibited" in g or "export customer data" in g or "exfiltrat" in g:
            return proposal("export_customer_data", "POST", "/webhooks",
                            {"event": "customer_data_export", "target": "prohibited"},
                            "crm:customer-data")

        # --- campaign budget: increase (escalates) vs set (clamps) ---
        if "budget" in g and ("increase" in g or "raise" in g):
            amt = _amount(g, 5000)
            return proposal("increase_campaign_budget", "POST",
                            f"/campaigns/{self.campaign_id}/budget",
                            {"amount": amt, "currency": "EUR"},
                            f"crm:campaign:{self.campaign_id}")
        if "budget" in g and ("set" in g or "update" in g):
            amt = _amount(g, 1000)
            return proposal("set_campaign_budget", "POST",
                            f"/campaigns/{self.campaign_id}/budget",
                            {"amount": amt, "currency": "EUR"},
                            f"crm:campaign:{self.campaign_id}")

        # --- create CRM lead ---
        if "lead" in g:
            name = _lead_name(goal)
            budget = _amount(g, 0)
            return proposal("create_lead", "POST", "/leads",
                            {"name": name, "email": f"{name.lower()}@example.com",
                             "campaign_budget_eur": budget},
                            f"crm:lead:{name.lower()}")

        # --- customer notification ---
        if "notif" in g or "notify" in g:
            return proposal("send_notification", "POST", "/notifications",
                            {"customer_id": "cust-1", "message": goal},
                            "crm:customer:cust-1")

        # --- customer task ---
        if "task" in g:
            return proposal("create_task", "POST", "/tasks",
                            {"title": goal, "assignee": "agent/crm"}, "crm:task")

        # --- webhook ---
        if "webhook" in g or "trigger" in g:
            return proposal("trigger_webhook", "POST", "/webhooks",
                            {"event": "pilot.event", "target": "crm"}, "crm:webhook")

        raise UnsupportedGoalError(
            f"deterministic planner has no plan for goal: {goal!r}")


def _lead_name(goal: str) -> str:
    m = re.search(r"lead for ([A-Za-z][A-Za-z0-9_-]*)", goal)
    return m.group(1) if m else "Lead"
