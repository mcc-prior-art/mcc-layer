"""Action-name contract (R4 remediation).

An action name is an **identifier**. Authorities match it (``fnmatch`` over a
mandate's ``action_scope``), the decision token signs it, and the shipped
governed upstreams place it into an outbound URL as a single path segment
(``{base}/{action}``):

* ``gateway.governance_api._httpx_upstream``
* ``pilot_notify.governed_upstream.receipt_verifying_upstream``
* ``pilot.outbound_executor.OutboundHTTPExecutor``

Before R4 nothing constrained that string. A wildcard scope such as
``pay_*`` matched ``pay_x/../../admin/wipe``. The token signed exactly that
string, and the client then normalized it to ``POST /admin/wipe``, escaping
the endpoint. ``pay_x?admin=1`` injected a query, and ``pay_x#frag``
executed ``/pay_x``, a different action identity than the one signed.
Percent-encoding is not a defense: a Starlette receiver decodes ``%2F`` back
into ``/`` before routing.

**The contract.** An action name is one or more segments of ASCII
``[A-Za-z0-9_-]``, joined by single dots. It starts with a letter or digit
and is at most 128 characters long. Examples: ``send_payment``,
``appointment_book``, ``http.egress``, ``github.create_issue``. That covers
every action used in this repository's code, docs, pilots and integrations.

So no slash or backslash, ``?``, ``#``, ``%``, ``;``, ``:``, ``@``, whitespace,
control characters or non-ASCII. No empty name, no ``.`` / ``..`` segment and
no leading, trailing or doubled dot. A conforming name is therefore always
exactly one literal path segment: it cannot change the configured origin,
leave the endpoint path, add a query or fragment, or be decoded into anything
else downstream.

A non-conforming name is **rejected**, never sanitized into a different
action: the signed action is always the executed action.
"""
from __future__ import annotations

import re
from typing import Any, Optional

ACTION_NAME_MAX_LENGTH = 128

_ACTION_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*")


class ActionNameError(ValueError):
    """An action name does not satisfy the action-name contract."""


def _show(value: Any) -> str:
    text = repr(value) if isinstance(value, str) else f"<{type(value).__name__}>"
    return text if len(text) <= 80 else text[:80] + "..."


def action_name_error(action: Any) -> Optional[str]:
    """Return why ``action`` violates the contract, or ``None`` if it is valid.
    Pure and total: never raises."""
    if not isinstance(action, str):
        return f"action must be a string, got {type(action).__name__}"
    if not action:
        return "action must be non-empty"
    if len(action) > ACTION_NAME_MAX_LENGTH:
        return f"action exceeds {ACTION_NAME_MAX_LENGTH} characters"
    # re.fullmatch with explicit ASCII classes: no Unicode letters/digits, and
    # no trailing-newline leniency (``$`` would accept "x\n"; fullmatch does not).
    if _ACTION_NAME.fullmatch(action) is None:
        return (f"unsupported action name {_show(action)} (allowed: dot-separated "
                f"segments of ASCII [A-Za-z0-9_-], starting with a letter or digit)")
    return None


def validate_action_name(action: Any) -> str:
    """Return ``action`` unchanged if valid; raise :class:`ActionNameError`
    otherwise."""
    error = action_name_error(action)
    if error is not None:
        raise ActionNameError(error)
    return action


def action_endpoint_url(base: str, action: Any) -> str:
    """``{base}/{action}`` for a contract-conforming action, otherwise
    :class:`ActionNameError`. This is raised before any network I/O, so a
    rejected name never produces an outbound request. The action is never
    stripped, encoded or rewritten."""
    validate_action_name(action)
    return f"{base.rstrip('/')}/{action}"
