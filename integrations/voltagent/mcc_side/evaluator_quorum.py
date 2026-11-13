"""Independent N-of-M evaluator quorum for the VoltAgent governed integration.

The consensus execution path requires N independent evaluator votes bound to a
gateway-issued challenge. In a real deployment those evaluators are separate
services holding their own keys; this quorum plays that role for the integration.

Crucially, the quorum is **independent of VoltAgent**:

* it holds the evaluator Ed25519 signing keys — the VoltAgent process never does;
* on a vote request it does NOT sign whatever it is handed. It independently asks
  the gateway to evaluate the proposal (``POST /evaluate``), and only signs votes
  for an **executable** decision (ALLOW / CONSTRAIN), over the gateway's own
  authoritative payload (the clamped body for CONSTRAIN), bound to the gateway
  policy hash + the one-time challenge nonce + actor/action/resource;
* for DENY / ESCALATE it refuses to vote (returns zero votes).

Therefore votes cannot be obtained for a denied action, the votes bind the
authoritative payload (not a client-supplied one), and the gateway still verifies
every vote (signature, trust, threshold, veto, binding) before the governed
executor runs. Selecting the VoltAgent tool cannot, by itself, cause execution.

F1 (agent identity): the quorum votes only for the agent that asked. A vote
request must present a registered per-agent credential (strict mode, the
default); its ``actor`` must be that credential's principal (403 otherwise),
and the quorum forwards THAT credential to the gateway's ``/evaluate`` -- so
the gateway itself authenticates the principal the votes are for. Every vote
is signed for the authenticated tenant (``tenant_id``). The quorum's own
shared key is accepted only in explicit ``MCC_AGENT_IDENTITY_MODE=
legacy-shared-key`` (no impersonation protection). Before F1 any tenant key
could obtain votes for any actor (verified on PR #135 head 2761f4f).

This re-uses the existing ``mcc_core.issue_vote`` signing primitive; it does not
re-implement any governance or consensus logic.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from mcc_core import SigningKey, issue_vote

FAR_FUTURE = 4_000_000_000
EXECUTABLE = {"ALLOW", "CONSTRAIN"}


class VoteRequest(BaseModel):
    actor: str = Field(min_length=1)
    action: str = Field(min_length=1)
    nonce: str = Field(min_length=1)
    resource: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)


class VoteResponse(BaseModel):
    verdict: str
    authorized_context: Dict[str, Any]
    policy_hash: str
    votes: List[Dict[str, Any]]
    reason: str = ""


class QuorumSettings:
    """Trusted configuration for the quorum (never from the request body)."""

    def __init__(self, env: Optional[Mapping[str, str]] = None) -> None:
        env = os.environ if env is None else env
        self.gateway_url = env.get("MCC_QUORUM_GATEWAY_URL", "http://mcc-gateway:8001").rstrip("/")
        self.api_key = env.get("MCC_GATEWAY_API_KEY", "demo-key")
        self.quorum_api_key = env.get("MCC_QUORUM_API_KEY", self.api_key)
        self.keys_dir = env.get("MCC_EVALUATOR_KEYS_DIR", "").strip()
        self.timeout = float(env.get("MCC_QUORUM_TIMEOUT", "10"))
        # V05 (part 2): a caller may also authenticate with its OWN registered
        # per-agent credential (the gateway's registry file; hashes only). This
        # is tenant-level client auth for vote requests -- the quorum still
        # votes only over the gateway's authoritative payload. A malformed
        # registry refuses to start (fail-closed).
        self.tenant_id = env.get("MCC_GATEWAY_TENANT_ID", "").strip() or "pilot"
        creds_path = env.get("MCC_AGENT_CREDENTIALS_CONFIG", "").strip()
        self.agent_credentials = None
        if creds_path:
            from gateway.agent_identity import AgentCredentialRegistry
            self.agent_credentials = AgentCredentialRegistry.from_file(creds_path)
        # F1: strict (default) | legacy-shared-key; anything else refuses to start.
        from gateway.agent_identity import agent_identity_mode_from_env
        self.identity_mode = agent_identity_mode_from_env(env)


def load_evaluator_keys(keys_dir: str) -> List[SigningKey]:
    pems = sorted(Path(keys_dir).glob("evaluator_*.pem"))
    if not pems:
        raise FileNotFoundError(f"no evaluator_*.pem in {keys_dir}")
    return [SigningKey.from_pem_file(str(p), p.stem) for p in pems]


def build_quorum_app(
    evaluator_keys: List[SigningKey],
    settings: QuorumSettings,
    *,
    client: Optional[httpx.Client] = None,
) -> FastAPI:
    """Assemble the quorum service around a fixed pool of evaluator keys."""
    if not evaluator_keys:
        raise ValueError("evaluator quorum requires at least one evaluator key")

    app = FastAPI(title="MCC Evaluator Quorum")
    http = client or httpx.Client(timeout=settings.timeout)
    app.state.http = http

    def require_key(x_api_key: str = Header(...)):
        """F1: ``(agent, forwarded_key)``. A registered, active per-agent
        credential of this tenant -> its AuthenticatedAgent, and that same
        credential is forwarded to the gateway. The quorum's shared key ->
        ``(None, gateway service key)`` ONLY in explicit legacy mode."""
        registry = settings.agent_credentials
        if registry is not None:
            res = registry.resolve(x_api_key, tenant_id=settings.tenant_id)
            if res.agent is not None:
                return res.agent, x_api_key
            if res.error in ("AGENT_CREDENTIAL_REVOKED", "AGENT_CREDENTIAL_WRONG_TENANT"):
                raise HTTPException(status_code=403, detail=res.error)
        if secrets.compare_digest(x_api_key.encode(), settings.quorum_api_key.encode()):
            from gateway.agent_identity import AGENT_IDENTITY_LEGACY
            if settings.identity_mode == AGENT_IDENTITY_LEGACY:
                return None, settings.api_key
            raise HTTPException(status_code=403, detail=(
                "AGENT_IDENTITY_REQUIRED: votes are issued only to an individually "
                "authenticated agent; use your own per-agent credential"))
        raise HTTPException(status_code=401, detail="INVALID_API_KEY")

    def gateway_policy_hash() -> str:
        resp = http.get(f"{settings.gateway_url}/health")
        resp.raise_for_status()
        ph = resp.json().get("policy_hash")
        if not ph:
            raise HTTPException(status_code=502, detail="gateway did not report a policy hash")
        return str(ph)

    @app.get("/health")
    def health() -> Dict[str, Any]:
        return {"status": "ok", "evaluators": [k.kid for k in evaluator_keys]}

    @app.get("/ready")
    def ready() -> Dict[str, Any]:
        try:
            gateway_policy_hash()
            return {"ready": True, "evaluators": len(evaluator_keys)}
        except Exception as exc:  # noqa: BLE001 - readiness must fail closed, not crash
            raise HTTPException(status_code=503, detail=f"gateway unreachable: {type(exc).__name__}")

    @app.post("/vote", response_model=VoteResponse)
    def vote(req: VoteRequest, caller=Depends(require_key)) -> VoteResponse:
        agent, forwarded_key = caller
        # 0. F1: vote only for the agent that asked -- never for another actor.
        if agent is not None and req.actor != agent.principal_id:
            raise HTTPException(status_code=403, detail=(
                "AGENT_PRINCIPAL_MISMATCH: the quorum votes only for the authenticated "
                "agent's own principal"))
        vote_tenant = agent.tenant_id if agent is not None else settings.tenant_id
        # 1. Independently evaluate the proposal against the gateway. The quorum
        #    does NOT trust the caller's claim about the verdict or payload. The
        #    caller's own credential is forwarded, so the GATEWAY authenticates
        #    the principal (it refuses an agent evaluating as anyone else).
        body: Dict[str, Any] = {
            "identity": req.actor, "actor_id": req.actor,
            "action": req.action, "context": dict(req.context),
        }
        if req.resource is not None:
            body["resource_id"] = req.resource
        try:
            resp = http.post(f"{settings.gateway_url}/evaluate", json=body,
                             headers={"x-api-key": forwarded_key})
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=f"gateway evaluate failed: {exc}")
        if resp.status_code == 401:
            raise HTTPException(status_code=502, detail="quorum not authorized to the gateway")
        if resp.status_code == 403:
            raise HTTPException(status_code=403, detail=f"gateway refused: {resp.json().get('detail')}")
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"gateway evaluate status {resp.status_code}")
        decision = resp.json()
        verdict = str(decision.get("decision", ""))
        authorized = dict(decision.get("forward_context") or {})

        # 2. Refuse to vote for anything that is not executable. No votes for a
        #    DENY or an ESCALATE — those never reach the governed executor here.
        if verdict not in EXECUTABLE:
            return VoteResponse(verdict=verdict, authorized_context=authorized,
                                policy_hash="", votes=[],
                                reason=f"not executable ({verdict}); quorum will not vote")

        # 3. Sign N ALLOW votes over the gateway's OWN authoritative payload,
        #    bound to the gateway policy hash + the one-time challenge nonce.
        policy_hash = gateway_policy_hash()
        votes = [
            issue_vote(k, evaluator_id=k.kid, verdict="ALLOW", action=req.action,
                       payload=authorized, actor=req.actor, not_before=0, not_after=FAR_FUTURE,
                       resource=req.resource, policy_hash=policy_hash, nonce=req.nonce,
                       tenant_id=vote_tenant)
            for k in evaluator_keys
        ]
        return VoteResponse(verdict=verdict, authorized_context=authorized,
                            policy_hash=policy_hash, votes=votes)

    return app


def build_app_from_env(env: Optional[Dict[str, str]] = None) -> FastAPI:
    settings = QuorumSettings(env)
    if not settings.keys_dir:
        raise RuntimeError("MCC_EVALUATOR_KEYS_DIR is required (evaluator private keys); "
                           "refusing to start a quorum with no keys")
    keys = load_evaluator_keys(settings.keys_dir)
    return build_quorum_app(keys, settings)


# Uvicorn entrypoint: `uvicorn integrations.voltagent.mcc_side.evaluator_quorum:app`
try:  # pragma: no cover - only when MCC_EVALUATOR_KEYS_DIR is configured (container)
    if os.environ.get("MCC_EVALUATOR_KEYS_DIR"):
        app = build_app_from_env()
except Exception:  # noqa: BLE001 - import must not crash tooling; container logs the failure
    app = None  # type: ignore[assignment]
