"""Typed request/response models for the egress proxy API (strict schemas).

The caller *proposes* an outbound HTTP action and may carry governance material
(challenge votes / approval id) for a continuation. It can never assert a verdict:
there is no field by which a caller supplies ALLOW/DENY/ESCALATE/CONSTRAIN.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HTTPExecuteRequest(_Strict):
    # The proposed outbound HTTP action.
    method: str = Field(min_length=1)
    url: str = Field(min_length=1)
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Any = None

    # Operation binding (the caller proposes; MCC binds + decides).
    actor: str = Field(min_length=1)
    resource: Optional[str] = None
    transaction_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    correlation_id: Optional[str] = None

    # Continuation / governance material (optional).
    challenge_id: Optional[str] = None
    votes: Optional[List[Dict[str, Any]]] = None
    approval_id: Optional[str] = None
    # True when resubmitting the authority-constrained action for fresh consensus.
    constrained: bool = False


class Outcome(str, Enum):
    ALLOW = "ALLOW"                       # executed through the governed path
    DENY = "DENY"                         # governance refused; no upstream call
    ESCALATE = "ESCALATE"                 # human approval required before execution
    CONSTRAIN = "CONSTRAIN"               # authority clamped; fresh authorization required
    CONSENSUS_REQUIRED = "CONSENSUS_REQUIRED"  # supply N-of-M votes for this challenge
    INVALID_REQUEST = "INVALID_REQUEST"   # malformed/SSRF-rejected action (no governance)
    GOVERNANCE_UNAVAILABLE = "GOVERNANCE_UNAVAILABLE"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"  # Redis/registry fail-closed
    UPSTREAM_TIMEOUT = "UPSTREAM_TIMEOUT"
    UPSTREAM_ERROR = "UPSTREAM_ERROR"
    RESPONSE_TOO_LARGE = "RESPONSE_TOO_LARGE"


class HTTPExecuteResponse(_Strict):
    outcome: Outcome
    executed: bool = False
    reason: str = ""
    action_hash: Optional[str] = None
    audit_ref: Optional[str] = None
    correlation_id: Optional[str] = None

    # ESCALATE / CONSENSUS_REQUIRED continuation material.
    challenge_id: Optional[str] = None
    nonce: Optional[str] = None
    approval_request_id: Optional[str] = None

    # CONSTRAIN: the authority-clamped action the caller must re-authorize.
    constrained_action: Optional[Dict[str, Any]] = None
    applied_constraints: List[str] = Field(default_factory=list)

    # ALLOW: the sanitized upstream response.
    upstream_status: Optional[int] = None
    upstream_headers: Optional[Dict[str, str]] = None
    upstream_body: Any = None
    truncated: Optional[bool] = None
