"""Governed credential ordering through the full runtime (consensus harness):
credentials are resolved only AFTER governance authorization + durable audit,
and the raw secret never appears in the API response or audit.
"""

import json

from egress_proxy.canonical_action import build_canonical_action
from egress_proxy.credentials import (
    SECRET_HEADER, CredentialBinding, CredentialEntry, CredentialProvider,
    InMemoryCredentialProvider,
)
from tests._egress_harness import EgressHarness

SECRET = "Bearer governed-secret-xyz"


class SpyProvider(CredentialProvider):
    def __init__(self, inner):
        self.inner = inner
        self.calls = 0

    async def resolve(self, ref, *, scope, expected_type):
        self.calls += 1
        return await self.inner.resolve(ref, scope=scope, expected_type=expected_type)


def _provider():
    entry = CredentialEntry(
        binding=CredentialBinding(allowed_hosts=("127.0.0.1",), allowed_methods=("POST",),
                                  allowed_actions=("http.request",), allowed_envs=("dev",)),
        type=SECRET_HEADER, header_name="authorization", loader=lambda: SECRET)
    return SpyProvider(InMemoryCredentialProvider({"api": entry}))


def _harness_with_provider():
    hz = EgressHarness()
    spy = _provider()
    hz.app.state.egress_service.rt.executor.credential_provider = spy
    hz.app.state.egress_service.rt.executor.env_name = "dev"
    return hz, spy


def _allow_with_cred(hz, *, method="POST", txn="t1", idem="i1", credential_ref="api"):
    url = hz.url("/charge")
    r1 = hz.post(method=method, url=url, body={"amount": 1000}, actor="agent/egress",
                 transaction_id=txn, idempotency_key=idem, credential_ref=credential_ref).json()
    action = build_canonical_action(method=method, url=url, headers={}, body={"amount": 1000},
                                    credential_ref=credential_ref)
    return hz.post(method=method, url=url, body={"amount": 1000}, actor="agent/egress",
                   transaction_id=txn, idempotency_key=idem, credential_ref=credential_ref,
                   challenge_id=r1["challenge_id"],
                   votes=hz.votes(action, actor="agent/egress", nonce=r1["nonce"])).json()


def test_credential_not_resolved_on_authority_deny():
    hz, spy = _harness_with_provider()
    # DELETE is outside the authority's allowed methods -> DENY before the executor.
    r = _allow_with_cred(hz, method="DELETE", txn="td", idem="idd")
    assert r["outcome"] == "DENY" and not r["executed"]
    assert spy.calls == 0 and hz.executor.count() == 0  # no resolution before authorization


def test_credential_resolved_only_after_authorization():
    hz, spy = _harness_with_provider()
    r = _allow_with_cred(hz)
    assert r["outcome"] == "ALLOW" and r["executed"]
    assert spy.calls == 1                                  # resolved exactly once, after ALLOW
    assert r["credential_ref"] == "api" and r["credential_resolved"] is True
    received = json.loads(r["upstream_body"])["headers"]
    assert received["authorization"] == SECRET             # injected inside the executor


def test_credential_not_resolved_before_durable_audit():
    hz, spy = _harness_with_provider()

    def boom(*a, **k):
        raise OSError("audit unavailable")
    hz.app.state.egress_service.rt.client.audit.append = boom
    r = _allow_with_cred(hz, txn="ta", idem="ia")
    assert not r["executed"]
    assert spy.calls == 0 and hz.executor.count() == 0 and hz.seen == []


def test_raw_secret_absent_from_response_and_audit():
    hz, spy = _harness_with_provider()
    r = _allow_with_cred(hz)
    assert SECRET not in json.dumps({k: v for k, v in r.items() if k != "upstream_body"})
    # The audit chain records the reference + safe flags, never the secret.
    blob = open(hz.settings.audit_log_path).read()
    assert "credential_ref" in blob and SECRET not in blob
