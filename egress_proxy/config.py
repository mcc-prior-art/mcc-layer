"""Egress proxy configuration (trusted deployment config; never caller input).

Destination restrictions and the egress authority come from here / MCC policy —
never an implicit permissive default. Secrets are file paths or references, never
inline values.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic_settings import BaseSettings


def _csv(value: str) -> List[str]:
    return [v.strip().lower() for v in value.split(",") if v.strip()]


class EgressSettings(BaseSettings):
    # Deployment posture.
    mcc_env: str = "dev"                      # "pilot" tightens fail-closed startup
    api_key: str = "egress-demo-key"          # caller X-API-Key
    operator_api_key: str = ""                # X-Operator-Key; empty disables approvals

    # Egress authority (the MCC policy the embedded runtime evaluates).
    egress_actor_mandate: str = "agent/egress"   # who holds the http.egress mandate
    allowed_hosts: str = ""                   # CSV; empty = none (deny-by-default)
    allowed_methods: str = "get,post,put,patch,delete"
    max_amount: Optional[int] = None          # CONSTRAIN cap on body.amount (if any)

    # Destination safety (SSRF). Loopback/private allowed ONLY by explicit config
    # (test/dev); production keeps them off and relies on network policy.
    allow_loopback: bool = False
    allow_private: bool = False
    allow_link_local: bool = False

    # Mandatory Multi-Context Consensus (reuses the runtime's verifier/challenge).
    require_consensus: bool = False
    consensus_threshold: int = 3
    consensus_trust_config: str = ""          # path to evaluator public-key trust set

    # Signing (decision-token key). Empty -> ephemeral dev key (reported in /ready).
    signing_key_path: str = ""
    signing_key_id: str = "mcc-egress-signer"
    policy_id: str = "mcc.egress/v1"
    audience: str = "mcc-egress-gate"
    audit_log_path: str = "egress-audit.jsonl"

    # Transport limits.
    connect_timeout_seconds: float = 2.0
    read_timeout_seconds: float = 5.0
    total_timeout_seconds: float = 8.0
    max_response_bytes: int = 1048576

    class Config:
        env_prefix = "MCC_EGRESS_"

    def allowed_hosts_list(self) -> List[str]:
        return _csv(self.allowed_hosts)

    def allowed_methods_list(self) -> List[str]:
        return [m.upper() for m in _csv(self.allowed_methods)]
