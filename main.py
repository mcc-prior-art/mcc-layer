#!/usr/bin/env python3
"""
MCC-Core — Execution Governance Runtime with OPA/Rego Policy Adapter

Reference implementation:
- Real OPA/Rego policy evaluation via /v1/data/mcc/decision
- Fail-closed behavior when OPA is unavailable or returns invalid output
- Explicit outcomes: ALLOW / DENY / ESCALATE / CONSTRAIN
- Ed25519-signed decision tokens for ALLOW and CONSTRAIN only
- Append-only hash-chain audit log (fsync on every write)
- Idempotency cache
- Prometheus metrics
- Optional Redis connection placeholder

Intent is not authority.
Execution requires a verified decision.
No verified decision — no execution.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import sys
import time
import uuid
from pathlib import Path
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx
import redis.asyncio as redis
from fastapi import Depends, FastAPI, Header, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import Counter, Histogram, generate_latest
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from mcc_core import (
    ActuationStatus,
    AuditLog,
    ChallengeService,
    ConsensusPolicy,
    ConsensusVerifier,
    DecisionEngine,
    EnforcementCoordinator,
    ExecutionGate,
    InMemoryChallengeRegistry,
    InMemoryIdempotencyRegistry,
    InMemoryNonceRegistry,
    InMemoryVelocityRegistry,
    PolicyBundle,
    ProfileRegistry,
    RUNTIME_VERSION,
    SigningKey,
    hash_payload,
    public_key_from_b64,
)


# ---------- Settings ----------

class Settings(BaseSettings):
    redis_url: str = "redis://redis:6379"

    signing_key_path: str = ""
    signing_key_id: str = "mcc-core-dev-key-1"
    token_issuer: str = "mcc/core"
    token_audience: str = "execution-gate-1"
    token_ttl_seconds: int = 60

    audit_log_path: str = "audit.jsonl"
    policy_bundle_path: str = "policies/mcc.rego"
    policy_id: str = "mcc.rego/v1"

    api_key: str = "demo-key"

    use_opa: bool = True
    opa_url: str = "http://opa:8181"
    opa_data_path: str = "mcc/decision"
    opa_timeout_seconds: float = 1.5

    # --- Multi-Context Consensus + gateway challenge (governance layer) ---
    # Path to the evaluator trust config (same JSON shape as the gateway trust
    # set: issuers -> keys -> {kid, public_key_b64}). When set AND a policy
    # bundle is loaded, the full governance pipeline is ACTIVE on /evaluate:
    # challenge issuance -> policy decision -> N-of-M quorum -> ExecutionGate
    # (+ nonce consume) -> challenge consume -> hash-chain audit. Unset = the
    # base policy-decision runtime (governance reported as disabled in /health).
    consensus_trust_config: str = ""
    consensus_threshold: int = 3
    challenge_ttl_seconds: int = 120
    # When true, refuse to start without a usable governance configuration —
    # no fail-open: a deployment that asked for governance must not silently
    # run in base mode.
    require_governance: bool = False

    class Config:
        env_prefix = "MCC_"


settings = Settings()


# Canonical runtime release version comes from mcc_core.version (single source
# of truth: the repo-root VERSION file). Imported above as RUNTIME_VERSION.


# ---------- Logging ----------

logging.basicConfig(level="INFO")
logger = logging.getLogger("mcc")


# ---------- Metrics ----------

DECISIONS = Counter("mcc_decisions_total", "MCC decisions", ["decision"])
OPA_ERRORS = Counter("mcc_opa_errors_total", "OPA evaluation errors", ["reason"])
LATENCY = Histogram("mcc_latency_seconds", "MCC evaluation latency")

# Governance-layer metrics (Phase 1 wiring).
QUORUM = Counter("mcc_quorum_total", "N-of-M quorum verification outcomes", ["result"])
CHALLENGE = Counter("mcc_challenge_total", "Consensus challenge outcomes", ["result"])
NONCE_REPLAY = Counter("mcc_nonce_replay_total", "Replayed / unusable nonce at the gate")
EVALUATOR_REJECTED = Counter(
    "mcc_evaluator_rejected_total", "Evaluator votes rejected during quorum", ["reason"]
)


# ---------- Redis ----------

redis_client: Optional[redis.Redis] = None


async def get_redis() -> redis.Redis:
    global redis_client
    if redis_client is None:
        redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    return redis_client


# ---------- Models ----------

class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ESCALATE = "ESCALATE"
    CONSTRAIN = "CONSTRAIN"


class EvaluateRequest(BaseModel):
    session_id: str = Field(..., min_length=1)
    intent: str = Field(..., min_length=1)
    args: Dict[str, Any] = Field(default_factory=dict)
    idempotency_key: Optional[str] = None
    # --- governance (Phase B) ---
    resource: Optional[str] = None
    # The challenge issued by POST /evaluate/challenge for this exact operation.
    challenge_id: Optional[str] = None
    # Cryptographically signed evaluator votes (each a signed token), bound to
    # the challenge nonce. Quorum is N-of-M over DISTINCT TRUSTED evaluator
    # identities. (Verified votes are NOT a guarantee of evaluator independence.)
    votes: Optional[List[Dict[str, Any]]] = None


class EvaluateResponse(BaseModel):
    decision: Decision
    trace_id: str
    reason: str
    constraints: Dict[str, Any] = Field(default_factory=dict)
    policy_engine: str = "opa"
    policy_ref: Optional[str] = None
    decision_token: Optional[Dict[str, Any]] = None
    # Governance evidence echoed back when the full pipeline ran.
    quorum: Optional[Dict[str, Any]] = None


class ChallengeRequest(BaseModel):
    session_id: str = Field(..., min_length=1)
    intent: str = Field(..., min_length=1)
    args: Dict[str, Any] = Field(default_factory=dict)
    resource: Optional[str] = None


class ChallengeResponse(BaseModel):
    challenge_id: str
    nonce: str
    action: str
    actor: str
    resource: Optional[str] = None
    payload_hash: str
    policy_hash: Optional[str] = None
    issued_at: int
    expires_at: int


class PolicyDecision(BaseModel):
    decision: Decision
    reason: str
    constraints: Dict[str, Any] = Field(default_factory=dict)
    policy_ref: Optional[str] = None


# ---------- Auth ----------

def get_tenant(x_api_key: str = Header(...)) -> Dict[str, str]:
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="INVALID_API_KEY")
    return {"tenant": "demo"}


# ---------- OPA Adapter ----------

class OPAAdapter:
    """
    Real OPA/Rego adapter.

    Calls:
        POST {OPA_URL}/v1/data/{OPA_DATA_PATH}

    Expected OPA response:
        {
          "result": {
            "decision": "ALLOW|DENY|ESCALATE|CONSTRAIN",
            "reason": "...",
            "constraints": {...},
            "policy_ref": "optional"
          }
        }

    Fail-closed rule:
        Any timeout, connection error, invalid JSON, missing result,
        or invalid decision resolves to DENY.
    """

    def __init__(self, base_url: str, data_path: str, timeout_seconds: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.data_path = data_path.strip("/")
        self.timeout_seconds = timeout_seconds

    async def evaluate(
        self,
        *,
        tenant: str,
        trace_id: str,
        req: EvaluateRequest,
    ) -> PolicyDecision:
        url = f"{self.base_url}/v1/data/{self.data_path}"
        payload = {
            "input": {
                "tenant": tenant,
                "trace_id": trace_id,
                "session_id": req.session_id,
                "intent": req.intent,
                "args": req.args,
                "ts_unix": int(time.time()),
            }
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
        except httpx.TimeoutException:
            OPA_ERRORS.labels(reason="timeout").inc()
            logger.warning("OPA timeout; fail closed | trace=%s", trace_id)
            return self._deny("OPA timeout; fail closed")
        except httpx.HTTPError as exc:
            OPA_ERRORS.labels(reason="http_error").inc()
            logger.warning("OPA HTTP error; fail closed | trace=%s | error=%s", trace_id, exc)
            return self._deny("OPA HTTP error; fail closed")
        except json.JSONDecodeError:
            OPA_ERRORS.labels(reason="invalid_json").inc()
            logger.warning("OPA invalid JSON; fail closed | trace=%s", trace_id)
            return self._deny("OPA invalid JSON; fail closed")

        result = data.get("result")
        if not isinstance(result, dict):
            OPA_ERRORS.labels(reason="missing_result").inc()
            logger.warning("OPA missing result; fail closed | trace=%s", trace_id)
            return self._deny("OPA missing result; fail closed")

        try:
            return PolicyDecision(
                decision=Decision(result.get("decision")),
                reason=str(result.get("reason") or "OPA decision"),
                constraints=result.get("constraints") if isinstance(result.get("constraints"), dict) else {},
                policy_ref=result.get("policy_ref"),
            )
        except Exception:
            OPA_ERRORS.labels(reason="invalid_decision").inc()
            logger.warning("OPA invalid decision object; fail closed | trace=%s | result=%s", trace_id, result)
            return self._deny("OPA invalid decision; fail closed")

    @staticmethod
    def _deny(reason: str) -> PolicyDecision:
        return PolicyDecision(
            decision=Decision.DENY,
            reason=reason,
            constraints={},
            policy_ref="fail-closed",
        )


# ---------- Local Fallback Policy ----------

class LocalFallbackPolicy:
    """
    Explicit non-production fallback.

    Used only when MCC_USE_OPA=false.
    Default operational posture should use OPA.
    """

    async def evaluate(self, *, req: EvaluateRequest) -> PolicyDecision:
        decision = Decision.DENY
        reason = "deny-by-default"
        constraints: Dict[str, Any] = {}

        if req.intent == "send_payment":
            amount = float(req.args.get("amount", 0))
            if amount <= 5000:
                decision = Decision.ALLOW
                reason = "local fallback: within safe limit"
            elif amount <= 10000:
                decision = Decision.ESCALATE
                reason = "local fallback: requires human approval"
            else:
                decision = Decision.DENY
                reason = "local fallback: amount exceeds policy limit"

        elif req.intent == "delete_user":
            decision = Decision.ESCALATE
            reason = "local fallback: high-risk action requires approval"

        elif req.intent == "delete_database":
            decision = Decision.DENY
            reason = "local fallback: destructive infrastructure action denied"

        return PolicyDecision(
            decision=decision,
            reason=reason,
            constraints=constraints,
            policy_ref="local-fallback",
        )


# ---------- Governance pipeline (Multi-Context Consensus + challenge) ----------

def _load_evaluator_keys(path: str) -> Dict[str, Any]:
    """Load ``{kid: Ed25519PublicKey}`` from an evaluator trust config (same JSON
    shape as the gateway trust set: ``issuers -> keys -> {kid, public_key_b64,
    not_after}``). Disabled issuers and expired keys are skipped. Returns ``{}``
    when no path / unreadable — governance simply stays disabled (fail-closed:
    no trusted evaluators means no quorum can ever be reached, so no ALLOW)."""
    path = (path or "").strip()
    if not path:
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        logger.error("evaluator trust config unreadable at %s; governance disabled", path)
        return {}
    now = int(time.time())
    keys: Dict[str, Any] = {}
    for issuer in data.get("issuers", []):
        if not issuer.get("enabled", True):
            continue
        for k in issuer.get("keys", []):
            na = k.get("not_after")
            if na is not None and now >= int(na):
                continue
            try:
                keys[k["kid"]] = public_key_from_b64(k["public_key_b64"])
            except Exception:
                continue
    return keys


def _quorum_reason(low: str) -> str:
    for key in ("veto", "expired", "duplicate", "untrusted", "forged",
                "mismatch", "below", "malformed", "no_consensus", "no consensus"):
        if key in low:
            return key.replace(" ", "_")
    return "rejected"


class GovernancePipeline:
    """Wires the in-tree governance modules into the public ``/evaluate``
    entrypoint: gateway-issued **challenge** → N-of-M **quorum**
    (``ConsensusVerifier``) → **ExecutionGate** (signature + binding + one-time
    **nonce** consume) → **challenge** single-use consume → hash-chain
    **audit**, all orchestrated by the ``EnforcementCoordinator``. Fail-closed
    at every boundary.

    NIW honesty constraint — the runtime cryptographically verifies evaluator
    votes from **distinct trusted evaluator identities**: signatures, evaluator
    **identity uniqueness**, **trust membership**, **quorum (N-of-M)**, action
    **bindings**, token **expiry**, and **veto**. It does **NOT** guarantee
    organizational, operational, or model-level **independence** of those
    evaluators — that is a deployment/governance property outside the software's
    control.
    """

    def __init__(self, *, signing_key: SigningKey, engine: DecisionEngine, audit: AuditLog,
                 trusted_evaluators: Dict[str, Any], threshold: int, audience: str,
                 challenge_ttl: int) -> None:
        self.engine = engine
        self.policy_hash = engine.policy_hash
        self.threshold = threshold
        self.evaluator_count = len(trusted_evaluators)
        self.verifier = ConsensusVerifier(
            trusted_keys=trusted_evaluators, policy=ConsensusPolicy(threshold=threshold))
        # REPLAY-PROTECTION SCOPE (important): the nonce, challenge, idempotency,
        # and velocity registries below are IN-MEMORY and therefore
        # **process-local / single-instance**. Replay protection (one-time nonce,
        # single-use challenge) holds within ONE running process only — it is NOT
        # shared across processes or hosts. For a multi-instance deployment these
        # must be swapped for the Redis-backed registries already in the tree
        # (RedisNonceRegistry / RedisChallengeRegistry / RedisIdempotencyRegistry
        # / RedisVelocityRegistry). This build makes NO multi-instance guarantee;
        # /health reports `governance.replay_scope = "process-local"`.
        self.replay_scope = "process-local"
        self.nonce_registry = InMemoryNonceRegistry()
        self.gate = ExecutionGate(
            trusted_keys={signing_key.kid: signing_key.public_key()}, audience=audience,
            nonce_registry=self.nonce_registry, policy_hash=engine.policy_hash)
        self.challenges = ChallengeService(
            InMemoryChallengeRegistry(), default_ttl_seconds=challenge_ttl)
        # require_consensus + require_challenge => no actuation without a valid
        # quorum bound to a gateway-issued, single-use challenge.
        self.coordinator = EnforcementCoordinator(
            gate=self.gate, idempotency=InMemoryIdempotencyRegistry(),
            velocity=InMemoryVelocityRegistry(), audit=audit, profiles=ProfileRegistry(),
            consensus_verifier=self.verifier, require_consensus=True,
            challenges=self.challenges, require_challenge=True)

    async def issue_challenge(self, *, actor: str, action: str, resource: Optional[str],
                              args: Dict[str, Any]):
        rec = await self.challenges.issue(
            action=action, actor=actor, resource=resource,
            payload_hash=hash_payload(args), policy_hash=self.policy_hash)
        CHALLENGE.labels(result="issued").inc()
        return rec

    async def decide(self, *, actor: str, action: str, resource: Optional[str],
                     args: Dict[str, Any], verdict: str, constraints: Dict[str, Any],
                     challenge_id: Optional[str], votes: Optional[List[Dict[str, Any]]],
                     audit_ref: Optional[str]):
        """Run the full pipeline for an ALLOW/CONSTRAIN policy verdict.
        Returns ``(ok, token_or_None, reason, evidence_or_None)``. Any missing or
        invalid challenge/quorum/gate/nonce condition fails closed → ``ok=False``."""
        if not challenge_id or not votes:
            QUORUM.labels(result="fail").inc()
            EVALUATOR_REJECTED.labels(reason="no_evidence").inc()
            return False, None, "no challenge / quorum evidence supplied; fail-closed", None
        # Resolve + re-bind the challenge before issuing any token.
        rec = await self.challenges.get(challenge_id)
        if rec is None:
            CHALLENGE.labels(result="unknown").inc()
            return False, None, "challenge unknown or expired; fail-closed", None
        if rec.state != "ISSUED":
            CHALLENGE.labels(result="not_open").inc()
            return False, None, f"challenge not open (state {rec.state}); fail-closed", None
        if (rec.action != action or rec.actor != actor or rec.resource != resource
                or rec.payload_hash != hash_payload(args) or rec.policy_hash != self.policy_hash):
            CHALLENGE.labels(result="mismatch").inc()
            return False, None, "challenge binding mismatch; fail-closed", None

        token = self.engine.issue_token(
            verdict=verdict, subject=actor, action=action, payload=args,
            constraints=constraints, nonce=rec.nonce, actor_id=actor, resource_id=resource,
            auth_claims={"challenge_id": challenge_id}, audit_ref=audit_ref)

        async def grant():
            return "authorized"

        result = await self.coordinator.enforce(
            token=token, action=action, payload=args, executor=grant,
            request_binding={"actor_id": actor, "resource_id": resource},
            consensus_votes=votes)

        if result.status == ActuationStatus.EXECUTED:
            QUORUM.labels(result="pass").inc()
            CHALLENGE.labels(result="consumed").inc()
            evidence = {
                "threshold": self.threshold,
                "evaluator_pool": self.evaluator_count,
                "verified": True,
                "claim": ("cryptographically verified evaluator votes from distinct "
                          "trusted evaluator identities; NOT a guarantee of evaluator "
                          "independence"),
            }
            return True, token, "governance verified", evidence

        reason = result.reason or "governance denied"
        low = reason.lower()
        if "nonce" in low or "replay" in low:
            NONCE_REPLAY.inc()
        if any(t in low for t in ("consensus", "quorum", "evaluator", "veto", "no_consensus")):
            QUORUM.labels(result="fail").inc()
            EVALUATOR_REJECTED.labels(reason=_quorum_reason(low)).inc()
        if "challenge" in low:
            CHALLENGE.labels(result="reject").inc()
        return False, None, reason, None


# ---------- MCC Core ----------

IDEM_CACHE_MAX_ENTRIES = 10_000


class MCC:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        # key -> (expires_at_unix, response); entries live no longer than a token
        self._idem_cache: Dict[str, tuple] = {}
        self.opa = OPAAdapter(
            base_url=settings.opa_url,
            data_path=settings.opa_data_path,
            timeout_seconds=settings.opa_timeout_seconds,
        )
        self.local_fallback = LocalFallbackPolicy()

        if settings.signing_key_path:
            self.signing_key = SigningKey.from_pem_file(
                settings.signing_key_path, settings.signing_key_id
            )
        else:
            self.signing_key = SigningKey.generate(settings.signing_key_id)
            logger.warning(
                "MCC_SIGNING_KEY_PATH not set; using ephemeral Ed25519 dev key "
                "(not a production posture)"
            )

        self.audit = AuditLog(settings.audit_log_path)

        # No trusted policy bundle -> no decision engine -> no tokens (fail-closed).
        self.engine: Optional[DecisionEngine] = None
        try:
            self.policy_bundle: Optional[PolicyBundle] = PolicyBundle.from_file(
                settings.policy_bundle_path, settings.policy_id
            )
            self.engine = DecisionEngine(
                signing_key=self.signing_key,
                issuer=settings.token_issuer,
                audience=settings.token_audience,
                policy_id=self.policy_bundle.policy_id,
                policy_hash=self.policy_bundle.policy_hash,
                token_ttl_seconds=settings.token_ttl_seconds,
            )
        except Exception:
            self.policy_bundle = None
            logger.warning(
                "policy bundle unavailable at %s; decision tokens will not be "
                "issued (fail-closed)",
                settings.policy_bundle_path,
            )

        # --- governance pipeline (Multi-Context Consensus + challenge) ---
        # Active only when a usable evaluator trust set AND a policy bundle (for
        # the policy_hash binding) are present. Otherwise the runtime serves the
        # base policy-decision layer and reports governance as disabled.
        self.governance: Optional[GovernancePipeline] = None
        trusted = _load_evaluator_keys(settings.consensus_trust_config)
        if trusted and self.engine is not None:
            self.governance = GovernancePipeline(
                signing_key=self.signing_key, engine=self.engine, audit=self.audit,
                trusted_evaluators=trusted, threshold=settings.consensus_threshold,
                audience=settings.token_audience, challenge_ttl=settings.challenge_ttl_seconds,
            )
            logger.info(
                "governance ACTIVE | evaluators=%d | threshold=%d",
                len(trusted), settings.consensus_threshold,
            )
        elif settings.require_governance:
            raise RuntimeError(
                "MCC_REQUIRE_GOVERNANCE is set but no usable governance config "
                "(MCC_CONSENSUS_TRUST_CONFIG + a loadable policy bundle); refusing "
                "fail-open startup"
            )
        else:
            logger.warning(
                "governance layer disabled (no evaluator trust set / policy bundle); "
                "/evaluate runs base policy-decision mode"
            )

    def _trace(self, session_id: str) -> str:
        return hashlib.sha256((session_id + str(uuid.uuid4())).encode()).hexdigest()[:12]

    def _idem_get(self, key: str) -> Optional[EvaluateResponse]:
        entry = self._idem_cache.get(key)
        if entry is None:
            return None
        expires_at, cached = entry
        if time.time() >= expires_at:
            self._idem_cache.pop(key, None)
            return None
        return cached

    def _idem_put(self, key: str, result: EvaluateResponse) -> None:
        if len(self._idem_cache) >= IDEM_CACHE_MAX_ENTRIES:
            now = time.time()
            for stale in [k for k, (exp, _) in self._idem_cache.items() if exp <= now]:
                self._idem_cache.pop(stale, None)
            while len(self._idem_cache) >= IDEM_CACHE_MAX_ENTRIES:
                self._idem_cache.pop(next(iter(self._idem_cache)))
        self._idem_cache[key] = (time.time() + settings.token_ttl_seconds, result)

    async def evaluate(self, tenant: str, req: EvaluateRequest) -> EvaluateResponse:
        trace_id = self._trace(req.session_id)

        if req.idempotency_key:
            cached = self._idem_get(f"{tenant}:{req.idempotency_key}")
            if cached is not None:
                return cached

        if settings.use_opa:
            policy_decision = await self.opa.evaluate(
                tenant=tenant,
                trace_id=trace_id,
                req=req,
            )
            policy_engine = "opa"
        else:
            policy_decision = await self.local_fallback.evaluate(req=req)
            policy_engine = "local-fallback"

        # Audit before any authority is released: no audit record, no token.
        try:
            async with self._lock:
                audit_entry = self.audit.append(
                    {
                        "tenant": tenant,
                        "session_id": req.session_id,
                        "intent": req.intent,
                        "args_hash": hash_payload(req.args),
                        "decision": policy_decision.decision.value,
                        "reason": policy_decision.reason,
                        "trace_id": trace_id,
                        "policy_engine": policy_engine,
                        "policy_ref": policy_decision.policy_ref,
                    }
                )
        except Exception:
            logger.error("audit write failed; fail closed | trace=%s", trace_id)
            policy_decision = PolicyDecision(
                decision=Decision.DENY,
                reason="audit unavailable; fail closed",
                constraints={},
                policy_ref="fail-closed",
            )
            audit_entry = None

        decision_token: Optional[Dict[str, Any]] = None
        quorum_evidence: Optional[Dict[str, Any]] = None
        if policy_decision.decision in (Decision.ALLOW, Decision.CONSTRAIN):
            if self.governance is not None:
                # FULL pipeline: a policy ALLOW/CONSTRAIN is only authority if it
                # also passes challenge + N-of-M quorum + gate (nonce) + audit.
                # Any failure fails closed -> DENY (no verified decision, no
                # execution).
                ok, token, gov_reason, quorum_evidence = await self.governance.decide(
                    actor=f"agent/{req.session_id}",
                    action=req.intent,
                    resource=req.resource,
                    args=req.args,
                    verdict=policy_decision.decision.value,
                    constraints=policy_decision.constraints,
                    challenge_id=req.challenge_id,
                    votes=req.votes,
                    audit_ref=audit_entry["hash"] if audit_entry else None,
                )
                if ok:
                    decision_token = token
                else:
                    decision_token = None
                    policy_decision = PolicyDecision(
                        decision=Decision.DENY,
                        reason=gov_reason,
                        constraints={},
                        policy_ref="fail-closed",
                    )
                    try:
                        async with self._lock:
                            self.audit.append(
                                {
                                    "tenant": tenant,
                                    "intent": req.intent,
                                    "decision": Decision.DENY.value,
                                    "reason": f"governance denied: {gov_reason}",
                                    "trace_id": trace_id,
                                }
                            )
                    except Exception:
                        logger.error("audit write failed on governance downgrade | trace=%s", trace_id)
            else:
                # Base mode (governance not configured): policy decision + token.
                try:
                    if self.engine is None:
                        raise RuntimeError("decision engine unavailable")
                    decision_token = self.engine.issue_token(
                        verdict=policy_decision.decision.value,
                        subject=f"agent/{req.session_id}",
                        action=req.intent,
                        payload=req.args,
                        constraints=policy_decision.constraints,
                        audit_ref=audit_entry["hash"] if audit_entry else None,
                    )
                except Exception:
                    logger.error(
                        "decision token issuance failed; fail closed | trace=%s", trace_id
                    )
                    decision_token = None
                    policy_decision = PolicyDecision(
                        decision=Decision.DENY,
                        reason="decision token unavailable; fail closed",
                        constraints={},
                        policy_ref="fail-closed",
                    )
                    try:
                        async with self._lock:
                            self.audit.append(
                                {
                                    "tenant": tenant,
                                    "intent": req.intent,
                                    "decision": Decision.DENY.value,
                                    "reason": "token issuance failed; downgraded to DENY",
                                    "trace_id": trace_id,
                                }
                            )
                    except Exception:
                        logger.error("audit write failed on downgrade | trace=%s", trace_id)

        result = EvaluateResponse(
            decision=policy_decision.decision,
            trace_id=trace_id,
            reason=policy_decision.reason,
            constraints=policy_decision.constraints,
            policy_engine=policy_engine,
            policy_ref=policy_decision.policy_ref,
            decision_token=decision_token,
            quorum=quorum_evidence,
        )

        if req.idempotency_key:
            self._idem_put(f"{tenant}:{req.idempotency_key}", result)

        DECISIONS.labels(decision=result.decision.value).inc()

        logger.info(
            "%s | intent=%s | trace=%s | engine=%s | reason=%s",
            result.decision.value,
            req.intent,
            trace_id,
            policy_engine,
            result.reason,
        )

        return result

    async def issue_challenge(self, tenant: str, req: ChallengeRequest) -> ChallengeResponse:
        if self.governance is None:
            raise HTTPException(
                status_code=409,
                detail="governance layer not configured; challenge unavailable",
            )
        rec = await self.governance.issue_challenge(
            actor=f"agent/{req.session_id}", action=req.intent,
            resource=req.resource, args=req.args,
        )
        view = rec.public_view()
        logger.info("challenge issued | id=%s | intent=%s", view["challenge_id"], req.intent)
        return ChallengeResponse(**view)


mcc = MCC()


# ---------- FastAPI ----------

app = FastAPI(
    title="MCC-Core Execution Governance Runtime",
    version=RUNTIME_VERSION,
    description=(
        "MCC-Core runtime with real OPA/Rego policy adapter, fail-closed "
        "evaluation, Ed25519-signed decision tokens, and the full governance "
        "pipeline (challenge -> N-of-M quorum -> gate -> nonce -> audit) on "
        "/evaluate when an evaluator trust set is configured."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- API ----------
#
# Authority is carried by the Ed25519-signed decision token inside the
# response body (ALLOW / CONSTRAIN only). There is no transport-level
# symmetric signature: verification happens at the execution gate.

@app.post("/evaluate/challenge", response_model=ChallengeResponse)
async def evaluate_challenge(req: ChallengeRequest, tenant_ctx: Dict[str, str] = Depends(get_tenant)):
    # Phase A — Propose / Challenge: the gateway issues the one-time, nonce-bound
    # challenge for this exact (actor, action, resource, payload, policy). The
    # client gathers evaluator votes bound to it, then calls POST /evaluate.
    return await mcc.issue_challenge(tenant_ctx["tenant"], req)


@app.post("/evaluate", response_model=EvaluateResponse)
async def evaluate(req: EvaluateRequest, tenant_ctx: Dict[str, str] = Depends(get_tenant)):
    # Phase B — Verify / Decide: policy decision AND (when governance is active)
    # N-of-M quorum over cryptographically verified evaluator votes from distinct
    # trusted evaluator identities -> ExecutionGate -> nonce consume -> challenge
    # consume -> hash-chain audit. Fail-closed throughout.
    with LATENCY.time():
        return await mcc.evaluate(tenant_ctx["tenant"], req)


@app.get("/health")
async def health():
    opa_status = "disabled"
    if settings.use_opa:
        try:
            async with httpx.AsyncClient(timeout=0.75) as client:
                r = await client.get(f"{settings.opa_url.rstrip('/')}/health")
                opa_status = "ok" if r.status_code == 200 else f"error:{r.status_code}"
        except Exception:
            opa_status = "unreachable"

    return {
        "status": "ok",
        "version": RUNTIME_VERSION,
        "policy_engine": "opa" if settings.use_opa else "local-fallback",
        "opa_status": opa_status,
        "fail_closed": True,
        "signing": {
            "algorithm": "Ed25519",
            "kid": mcc.signing_key.kid,
            "public_key_b64": mcc.signing_key.public_key_b64(),
            "ephemeral_key": not bool(settings.signing_key_path),
        },
        "policy_bundle": (
            {
                "policy_id": mcc.policy_bundle.policy_id,
                "policy_hash": mcc.policy_bundle.policy_hash,
            }
            if mcc.policy_bundle
            else "unavailable (tokens not issued; fail-closed)"
        ),
        "governance": (
            {
                "active": True,
                "evaluator_pool": mcc.governance.evaluator_count,
                "threshold": mcc.governance.threshold,
                "pipeline": "challenge -> quorum -> gate -> nonce -> audit",
                "replay_scope": mcc.governance.replay_scope,
                "replay_scope_note": "in-memory nonce/challenge/idempotency/velocity "
                                     "registries: replay protection is single-instance, "
                                     "not shared across processes/hosts (use the "
                                     "Redis-backed registries for multi-instance)",
                "claim": "cryptographically verified evaluator votes from distinct "
                         "trusted evaluator identities; not a guarantee of evaluator "
                         "independence",
            }
            if mcc.governance is not None
            else {"active": False, "mode": "base policy-decision (no evaluator trust set)"}
        ),
    }


@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type="text/plain")


# ---------- Run ----------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
