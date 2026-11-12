"""Private demo harness: a self-contained, real governed stack for the CLI
and test suite.

Mirrors ``examples/reference_governed_agent/_localstack.py`` exactly in
spirit: this is NOT the Astra adapter, and NOT MCC-Core. It assembles the
real environment the demo runs against — a real Attester service, a real
Gateway decision engine + Control + Gate + coordinator, and a mock GitHub
service the real (disabled-by-default) actuator would call — on loopback,
so ``python -m examples.gpt6_astra_reference.cli positive`` works with zero
external setup.

The Independent Attester Service runs in-process here (not as a separate
OS subprocess) for demo speed; its genuine process-isolation property is
already proven independently by
``tests/test_attester_service_process_isolation.py`` (PR-4) and is not
re-demonstrated by this reference integration. What IS demonstrated here,
faithfully, is that the Astra adapter process (conceptually: wherever
``AstraProvider.propose`` runs) never touches the Attester's signing key,
the Gateway's signing key, the trust store, or the Gate — see
``tests/test_gpt6_astra_reference_architecture_guards.py``.
"""

from __future__ import annotations

import socket
import tempfile
import time
from typing import Any, Dict

from mcc_attester_service import AssessmentResult, AttesterService, AttesterServiceConfig, DeterministicTestProvider
from mcc_core import AuditLog, EnforcementCoordinator, ExecutionGate, ProfileRegistry, SigningKey, issue_mandate
from mcc_core import (
    InMemoryApprovalRegistry, InMemoryNonceRegistry,
    InMemoryRevocationRegistry, InMemoryVelocityRegistry, ApprovalService,
    idempotency_registry_from_env,
)

from gateway.governance_service import GovernanceService
from gateway.pre_execution_control import AttestationRequirement, AttestationRequirementRegistry, PreExecutionControl
from gateway.trust import TrustSet

from examples._demo_server import DemoServer

from .mock_github_service import app as mock_github_app, reset_issues

ACTION = "create_github_issue"
ACTOR = "agent/astra-demo"
# PR #105: this demo's fixed, trusted tenant/security-domain identity.
# Exposed as ``self.tenant_id`` on the stack for tests to pass into any
# direct ``stack.coordinator.idempotency.<method>(..., tenant_id=...)`` call.
TENANT_ID = "astra-demo-tenant"
ISSUER = "axlogiq/astra-demo"
ATTESTER_ID = "attester.astra-demo.v1"
SCOPE_TEMPLATE = "github:{resource}"
EVIDENCE_TYPE = "task_assessment"
AUTH_SECRET = "astra-demo-attester-auth-secret-0123456789"
POLICY_HASH = "sha256:" + "a" * 64


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


class LocalAstraDemoStack:
    """A loopback Gateway (Control + Gate + coordinator) + a real in-process
    Attester + a mock GitHub service, wired for exactly one action:
    ``create_github_issue`` on ``self.demo_repo``."""

    def __init__(self, *, demo_repo: str = "owner/mcc-astra-demo-sandbox",
                 assessment_table: Dict[str, AssessmentResult] | None = None,
                 mandate_action_scope=(ACTION,), mandate_resource_scope=None,
                 token_ttl_seconds: int = 60) -> None:
        # 0. Round 18: select the idempotency backend through the SAME
        #    enforcement-aware factory production code uses -- never a bare
        #    ``InMemoryIdempotencyRegistry()`` construction here. By default
        #    (``MCC_DEPLOYMENT_MODE`` unset/``reference``) this still resolves
        #    to in-memory, exactly as before, for local demo/test runs that
        #    never invoke a real actuator. The moment an operator configures
        #    ``MCC_DEPLOYMENT_MODE=enforcement`` -- required before this stack
        #    could ever be pointed at a real external actuator -- construction
        #    fails closed (``IdempotencyConfigError``) unless a real, shared,
        #    durable backend (``MCC_IDEMPOTENCY_BACKEND=redis`` +
        #    ``MCC_REDIS_URL``) is configured. Selected FIRST, before any
        #    server/thread is started, so a fail-closed refusal here never
        #    leaks a running mock-service port. See
        #    ``docs/DURABLE_OPERATION_SAFETY.md``.
        idempotency_backend = idempotency_registry_from_env()

        reset_issues()
        self.demo_repo = demo_repo
        self.profiles = ProfileRegistry.default_pilot()
        self.tenant_id = TENANT_ID

        # 1. Mock external GitHub service (loopback).
        self.github_port = _free_port()
        self.github_base_url = f"http://127.0.0.1:{self.github_port}"
        self._server = DemoServer(mock_github_app, self.github_port)
        self._server.start()

        # 2. Real, in-process Independent Attester (its own signing key --
        #    never shared with anything else this stack builds).
        self.attester_key = SigningKey.generate(f"{ATTESTER_ID}-key-01")
        attester_config = AttesterServiceConfig(
            attester_id=ATTESTER_ID, signing_key=self.attester_key, auth_secret=AUTH_SECRET,
            scope_template=SCOPE_TEMPLATE, validity_seconds=900,
        )
        table = assessment_table or {
            ACTION: AssessmentResult(evidence_type=EVIDENCE_TYPE, claims={},
                                     provenance={"assessed_by": "astra-demo-reference-attester"}),
        }
        self.attester = AttesterService(config=attester_config, provider=DeterministicTestProvider(table))

        # 3. Gateway decision engine + Ed25519 signing key (this demo's own,
        #    never the Attester's).
        self.signing_key = SigningKey.generate("astra-demo-gw-signing-1")
        from mcc_core import DecisionEngine

        self.engine = DecisionEngine(
            signing_key=self.signing_key, issuer="mcc/astra-demo", audience="astra-demo",
            policy_id="astra-demo/v1", policy_hash=POLICY_HASH, token_ttl_seconds=token_ttl_seconds,
        )
        self.nonce_registry = InMemoryNonceRegistry()
        self.gate = ExecutionGate(
            trusted_keys={self.signing_key.kid: self.signing_key.public_key()}, audience="astra-demo",
            nonce_registry=self.nonce_registry, policy_hash=POLICY_HASH,
        )
        self._audit_path = tempfile.mkdtemp(prefix="astra-demo-audit-") + "/audit.jsonl"
        self.audit = AuditLog(self._audit_path)
        self.coordinator = EnforcementCoordinator(
            gate=self.gate, idempotency=idempotency_backend,
            velocity=InMemoryVelocityRegistry(), audit=self.audit,
            profiles=self.profiles, revocation_registry=InMemoryRevocationRegistry(),
        )

        # 4. PR-2 Control: requires a VERIFIED, correctly-bound attestation
        #    for create_github_issue, from THIS demo's trusted Attester only.
        from mcc_attestation import AttesterTrustAnchor, AttesterTrustStore

        self.pre_execution_control = PreExecutionControl(
            requirements=AttestationRequirementRegistry([AttestationRequirement(
                action_pattern=ACTION, evidence_type=EVIDENCE_TYPE,
                scope_template=SCOPE_TEMPLATE, require_payload_binding=True,
            )]),
            trust_store=AttesterTrustStore([
                AttesterTrustAnchor(ATTESTER_ID, self.attester_key.kid, self.attester_key.public_key(),
                                    frozenset({EVIDENCE_TYPE})),
            ]),
            nonce_registry=self.nonce_registry,
        )

        # 5. Mandate trust (the operator-issued authority Astra can never mint).
        self.mandate_key = SigningKey.generate("astra-demo-issuer-1")
        self.trust_set = TrustSet()
        self.trust_set.add_runtime_issuer(ISSUER, self.mandate_key.kid, self.mandate_key.public_key())
        approver_key = SigningKey.generate("astra-demo-approver-1")
        self.trust_set.add_runtime_issuer("mcc/approvals", approver_key.kid, approver_key.public_key())
        self.approvals = ApprovalService(InMemoryApprovalRegistry(), approver_key)

        self.mandate = issue_mandate(
            self.mandate_key, issuer=ISSUER, subject=ACTOR,
            action_scope=list(mandate_action_scope),
            resource_scope=list(mandate_resource_scope) if mandate_resource_scope else [demo_repo],
            constraints={}, not_before=int(time.time()) - 10, not_after=int(time.time()) + 3600,
            issued_at=int(time.time()),
            # V05: bound to this demo's fixed, trusted tenant (strict tenant mode).
            tenant_id=TENANT_ID,
        )

        # 6. The upstream: the real (disabled-by-default) actuator is wired
        #    in by the CLI/test, not here -- this harness only stands up the
        #    environment. Default to a no-op so constructing the stack alone
        #    never has a side effect.
        self.upstream = None

        self.service = GovernanceService(
            engine=self.engine, coordinator=self.coordinator, trust_set=self.trust_set,
            revocation_registry=self.coordinator.revocation_registry, approvals=self.approvals,
            profiles=self.profiles, upstream=self._dispatch, policy_hash=POLICY_HASH,
            pre_execution_control=self.pre_execution_control,
        )

    async def _dispatch(self, action: str, payload: Dict[str, Any]) -> Any:
        if self.upstream is None:
            raise RuntimeError("no upstream configured for this demo stack")
        return await self.upstream(action, payload)

    def close(self) -> None:
        self._server.stop()

    def __enter__(self) -> "LocalAstraDemoStack":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


__all__ = ["LocalAstraDemoStack", "ACTION", "ACTOR", "ISSUER"]
