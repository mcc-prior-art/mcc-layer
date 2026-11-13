"""V05 (part 2) -- per-agent credential ISOLATION in real containers.

Runs the actual deployable stack (docker-compose.pilot-voltagent.yml) with two
agent principals in two separate containers in the same tenant:

    A = agent/unknown     (voltagent-agent-unknown)
    B = agent/notify-bot  (voltagent-agent)

and verifies, against the real gateway's HTTP authentication, that a fully
controlled container B obtains nothing that lets it act as A:

* isolation: B's process environment, readable filesystem and mounts contain
  no A credential, no provisioning map, no shared tenant key and no operator
  key; no agent image contains build-context or runtime secrets;
* impersonation: with its own credential and A's copied approval mandate
  (readable from the shared state volume), B is refused on
  /approvals/{id}/execute and /mandates/execute (actor=A and actor=B), cannot
  create an approval in A's name, and gains nothing from spoofed
  actor/tenant/identity headers or body fields; every rejection issues no
  decision token (no audit record), consumes no approval, reserves no
  idempotency key and causes no actuation (external receipts unchanged);
* positive controls: B's key authenticates (read-only routes), the leaked
  shared tenant key is refused as an agent identity, A then executes its own
  approval using the SAME idempotency key B tried, A's replay is refused
  (single-use), and B executes its own authorized operation.

Docker is required. Locally without Docker the module is SKIPPED (stated in
the skip reason); CI sets MCC_REQUIRE_CONTAINER_TESTS=1, which turns a missing
Docker or any skip into a hard failure.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "docker-compose.pilot-voltagent.yml"
A_SVC, B_SVC = "voltagent-agent-unknown", "voltagent-agent"
A, B = "agent/unknown", "agent/notify-bot"
REQUIRED = os.environ.get("MCC_REQUIRE_CONTAINER_TESTS") == "1"


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


if not (os.environ.get("MCC_RUN_CONTAINER_TESTS") == "1" or REQUIRED):
    pytest.skip("container isolation tests run only with MCC_RUN_CONTAINER_TESTS=1 "
                "(mandatory CI job: agent-credential-isolation)", allow_module_level=True)
if not _docker_ok():
    if REQUIRED:
        pytest.fail("MCC_REQUIRE_CONTAINER_TESTS=1 but Docker is unavailable (fail-closed)",
                    pytrace=False)
    pytest.skip("Docker is unavailable in this environment", allow_module_level=True)


class Compose:
    def __init__(self, project: str, env_file: Path):
        self.base = ["docker", "compose", "-p", project, "-f", str(COMPOSE_FILE)]
        override = os.environ.get("MCC_E2E_OVERRIDE")       # local prebuilt images only
        if override:
            self.base += ["-f", override]
        self.base += ["--env-file", str(env_file)]
        self.env = dict(os.environ, MCC_PILOT_ENV_FILE=str(env_file))

    def run(self, *args, input: Optional[str] = None, check: bool = True, timeout: int = 900):
        p = subprocess.run(self.base + list(args), input=input, capture_output=True, text=True,
                           cwd=ROOT, env=self.env, timeout=timeout)
        if check and p.returncode != 0:
            raise AssertionError(f"{' '.join(args)} failed rc={p.returncode}\n{p.stdout[-3000:]}\n{p.stderr[-3000:]}")
        return p

    def exec(self, svc: str, *cmd, input: Optional[str] = None, check: bool = True):
        return self.run("exec", "-T", svc, *cmd, input=input, check=check)

    def cid(self, svc: str) -> str:
        return self.run("ps", "-q", svc).stdout.strip()


# Executed INSIDE an agent container (node), reading only that container's own
# credential + the shared state volume. Prints one JSON document.
ATTACK_JS = r"""
const fs = require("fs");
const own = JSON.parse(fs.readFileSync("/run/mcc-agent/credential.json", "utf8"));
const leakedShared = fs.readFileSync(0, "utf8").trim();   // harness-supplied (stdin)
const esc = JSON.parse(fs.readFileSync("/pilot-state/escalation.json", "utf8"));
const appr = JSON.parse(fs.readFileSync("/pilot-state/approval.json", "utf8"));
const GW = "http://mcc-gateway:8001";
const A = esc.actor;
esc.action = esc.action || "send_notification";
async function call(name, method, path, body, headers) {
  const h = Object.assign({"content-type": "application/json"}, headers || {});
  const r = await fetch(GW + path, {method, headers: h, body: body === undefined ? undefined : JSON.stringify(body)});
  let j = null; try { j = await r.json(); } catch (e) {}
  return {name, http: r.status, status: j && j.status, reason: j && (j.reason || (typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail)))};
}
const execBody = (actor, extra) => Object.assign({mandate: appr.mandate, actor, action: esc.action,
  resource: esc.resource, context: esc.context, idempotency_key: esc.correlationId}, extra || {});
const own_h = {"x-api-key": own.api_key};
(async () => {
  const out = {own_principal: own.principal_id, target_actor: A, attacks: [], controls: []};
  out.attacks.push(await call("approval_execute_as_A", "POST", `/approvals/${esc.requestId}/execute`, execBody(A), own_h));
  out.attacks.push(await call("approval_execute_as_self", "POST", `/approvals/${esc.requestId}/execute`, execBody(own.principal_id), own_h));
  out.attacks.push(await call("mandate_execute_as_A", "POST", "/mandates/execute", execBody(A), own_h));
  out.attacks.push(await call("mandate_execute_as_self", "POST", "/mandates/execute", execBody(own.principal_id), own_h));
  out.attacks.push(await call("create_approval_for_A", "POST", "/approvals",
    {actor: A, action: esc.action, resource: esc.resource, payload: esc.context}, own_h));
  out.attacks.push(await call("spoofed_identity_headers", "POST", `/approvals/${esc.requestId}/execute`, execBody(A),
    Object.assign({"x-mcc-identity": A, "x-agent-principal": A, "x-principal-id": A, "x-actor": A,
                   "x-mcc-tenant": "pilot", "x-tenant-id": "pilot", "x-forwarded-user": A}, own_h)));
  out.attacks.push(await call("spoofed_body_identity", "POST", `/approvals/${esc.requestId}/execute`,
    execBody(A, {principal_id: A, tenant_id: "pilot", credential_id: "x"}), own_h));
  out.attacks.push(await call("no_credential", "POST", `/approvals/${esc.requestId}/execute`, execBody(A), {}));
  out.attacks.push(await call("leaked_shared_tenant_key", "POST", `/approvals/${esc.requestId}/execute`, execBody(A),
    {"x-api-key": leakedShared}));
  out.controls.push(await call("own_key_authenticates_readonly", "GET", `/approvals/${esc.requestId}`, undefined, own_h));
  out.approval_state_after = (await (await fetch(GW + `/approvals/${esc.requestId}`, {headers: own_h})).json()).state;
  console.log(JSON.stringify(out));
})().catch((e) => { console.log(JSON.stringify({error: String(e)})); process.exit(1); });
"""

REPLAY_JS = r"""
const fs = require("fs");
const own = JSON.parse(fs.readFileSync("/run/mcc-agent/credential.json", "utf8"));
const [rid, corr, mandate, ctx, action, resource] = JSON.parse(fs.readFileSync(0, "utf8"));
(async () => {
  const res = [];
  for (const idem of [corr, corr + "-replay"]) {
    const r = await fetch(`http://mcc-gateway:8001/approvals/${rid}/execute`, {method: "POST",
      headers: {"content-type": "application/json", "x-api-key": own.api_key},
      body: JSON.stringify({mandate, actor: own.principal_id, action, resource, context: ctx, idempotency_key: idem})});
    const j = await r.json();
    res.push({http: r.status, status: j.status, reason: j.reason});
  }
  console.log(JSON.stringify(res));
})();
"""


def _secrets_from_env_file(path: Path) -> Dict[str, str]:
    out = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("iso")
    tag = secrets.token_hex(6)
    canary = {
        "shared": f"CANARY-SHARED-{tag}-{secrets.token_hex(8)}",
        "operator": f"CANARY-OPERATOR-{tag}-{secrets.token_hex(8)}",
        "ctx_env": f"CANARY-CTX-ENV-{tag}-{secrets.token_hex(8)}",
        "ctx_file": f"CANARY-CTX-FILE-{tag}-{secrets.token_hex(8)}",
    }
    env_file = tmp / "env.pilot"
    text = (ROOT / ".env.pilot.example").read_text()
    text = "\n".join(
        f"MCC_GATEWAY_API_KEY={canary['shared']}" if l.startswith("MCC_GATEWAY_API_KEY=") else
        f"MCC_GATEWAY_OPERATOR_API_KEY={canary['operator']}" if l.startswith("MCC_GATEWAY_OPERATOR_API_KEY=") else l
        for l in text.splitlines()) + "\n"
    env_file.write_text(text)
    # Build-context canaries: real-looking secret files in the repository
    # root that .dockerignore must keep out of every image.
    ctx_env = ROOT / f".env.isolation-canary-{tag}"
    ctx_dir = ROOT / "secrets" / f"isolation-canary-{tag}"
    ctx_env.write_text(f"MCC_GATEWAY_OPERATOR_API_KEY={canary['ctx_env']}\n")
    ctx_dir.mkdir(parents=True)
    (ctx_dir / "agent.key").write_text(canary["ctx_file"] + "\n")

    dc = Compose(f"mcciso{tag}", env_file)
    facts: Dict = {"canary": canary}
    try:
        if os.environ.get("MCC_E2E_NO_BUILD") != "1":
            dc.run("build", timeout=2400)
        dc.run("up", "-d", "--no-build", timeout=900)
        deadline = time.time() + 600
        for svc in ("mcc-gateway", "evaluator-quorum", B_SVC, A_SVC):
            while True:
                st = subprocess.run(["docker", "inspect", "-f", "{{.State.Health.Status}}", dc.cid(svc)],
                                    capture_output=True, text=True).stdout.strip()
                if st == "healthy":
                    break
                assert time.time() < deadline and st != "unhealthy", f"{svc} not healthy ({st})"
                time.sleep(3)
        facts.update(_collect(dc, canary))
        yield facts
    finally:
        try:
            if os.environ.get("MCC_ISOLATION_KEEP") != "1":
                dc.run("down", "-v", "--remove-orphans", check=False, timeout=300)
        finally:
            ctx_env.unlink(missing_ok=True)
            shutil.rmtree(ctx_dir.parent / f"isolation-canary-{tag}", ignore_errors=True)
            try:
                (ROOT / "secrets").rmdir()               # only if we created it and it is now empty
            except OSError:
                pass


def _read_cred(dc: Compose, svc: str) -> Dict[str, str]:
    raw = dc.exec(svc, "cat", "/run/mcc-agent/credential.json").stdout
    return json.loads(raw)


def _scan_container(dc: Compose, svc: str, needles: List[str]) -> Dict:
    """Search the agent container's main-process environment and its whole
    readable filesystem for each needle (needles passed on stdin, never on a
    command line where they would appear in /proc)."""
    script = (
        'grep -vx "" > /tmp/.needles; '
        'echo "ENV:$(tr "\\0" "\\n" < /proc/1/environ | grep -cFf /tmp/.needles)"; '
        'echo "VARS:$(tr "\\0" "\\n" < /proc/1/environ | cut -d= -f1 | tr "\\n" ",")"; '
        'grep -rIlFf /tmp/.needles / --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev '
        '2>/dev/null | grep -v "^/tmp/.needles$" | sed "s/^/FILE:/"; '
        'rm -f /tmp/.needles; true')
    out = dc.exec(svc, "sh", "-c", script, input="\n".join(needles) + "\n").stdout
    env_hits = int(next(l for l in out.splitlines() if l.startswith("ENV:"))[4:] or 0)
    var_names = next(l for l in out.splitlines() if l.startswith("VARS:"))[5:].split(",")
    files = [l[5:] for l in out.splitlines() if l.startswith("FILE:")]
    mounts = json.loads(subprocess.run(["docker", "inspect", "-f", "{{json .Mounts}}", dc.cid(svc)],
                                       capture_output=True, text=True, check=True).stdout)
    return {"env_hits": env_hits, "var_names": var_names, "files": files,
            "mounts": [(m.get("Name"), m["Destination"], m["RW"]) for m in mounts]}


def _scan_image(image: str, needles: List[str]) -> Dict:
    p = subprocess.run(["docker", "run", "--rm", "-i", "--network", "none", "--entrypoint", "sh", image, "-c",
                        'grep -vx "" > /tmp/.n; grep -rIlFf /tmp/.n / --exclude-dir=proc --exclude-dir=sys '
                        '--exclude-dir=dev 2>/dev/null | grep -v "^/tmp/.n$"; true'],
                       input="\n".join(needles) + "\n", capture_output=True, text=True, timeout=900)
    hist = subprocess.run(["docker", "history", "--no-trunc", "--format", "{{.CreatedBy}}", image],
                          capture_output=True, text=True, check=True).stdout
    return {"files": [l for l in p.stdout.splitlines() if l.strip()],
            "history_hits": [n for n in needles if n in hist]}


def _receipts(dc: Compose) -> int:
    out = dc.exec("mcc-gateway", "python", "-c",
                  "import json,urllib.request;print(len(json.load(urllib.request.urlopen("
                  "'http://external-service:9200/receipts')).get('receipts',[])))").stdout
    return int(out.strip())


def _audit_lines(dc: Compose) -> List[dict]:
    raw = dc.exec("mcc-gateway", "sh", "-c", "cat /data/audit.jsonl 2>/dev/null; true").stdout
    return [json.loads(l) for l in raw.splitlines() if l.strip()]


def _collect(dc: Compose, canary: Dict[str, str]) -> Dict:
    f: Dict = {}
    cred_a, cred_b = _read_cred(dc, A_SVC), _read_cred(dc, B_SVC)
    f["cred_a_principal"], f["cred_b_principal"] = cred_a["principal_id"], cred_b["principal_id"]
    f["keys_distinct"] = cred_a["api_key"] != cred_b["api_key"]
    runtime_secrets = [canary["shared"], canary["operator"], canary["ctx_env"], canary["ctx_file"]]
    f["scan_b"] = _scan_container(dc, B_SVC, [cred_a["api_key"]] + runtime_secrets)
    f["scan_a"] = _scan_container(dc, A_SVC, [cred_b["api_key"]] + runtime_secrets)
    images = {}
    for svc in (A_SVC, B_SVC, "mcc-gateway"):
        img = subprocess.run(["docker", "inspect", "-f", "{{.Image}}", dc.cid(svc)],
                             capture_output=True, text=True, check=True).stdout.strip()
        needles = [canary["ctx_env"], canary["ctx_file"]]
        if svc != "mcc-gateway":
            needles += [canary["shared"], canary["operator"]]
        images[svc] = _scan_image(img, needles)
    f["images"] = images

    # ---- A escalates; the operator (operator key only) approves. ----
    f["a_escalate_rc"] = dc.exec(A_SVC, "npx", "tsx", "src/pilot-cli.ts", "escalate", check=False).returncode
    f["operator_rc"] = dc.exec("mcc-gateway", "python", "-m", "integrations.voltagent.mcc_side.operator_cli",
                               check=False).returncode
    esc = json.loads(dc.exec(A_SVC, "cat", "/pilot-state/escalation.json").stdout)
    appr = json.loads(dc.exec(A_SVC, "cat", "/pilot-state/approval.json").stdout)
    f["escalation_actor"] = esc["actor"]

    # ---- B (own credential + A's copied mandate) attacks. ----
    receipts0, audit0 = _receipts(dc), _audit_lines(dc)
    p = dc.exec(B_SVC, "node", "-e", ATTACK_JS, input=canary["shared"] + "\n", check=False)
    f["attack"] = json.loads(p.stdout.strip().splitlines()[-1])
    f["receipts_after_attack_delta"] = _receipts(dc) - receipts0
    audit1 = _audit_lines(dc)
    f["audit_after_attack_new"] = audit1[len(audit0):]

    # ---- Positive controls. ----
    f["a_execute_rc"] = dc.exec(A_SVC, "npx", "tsx", "src/pilot-cli.ts", "execute-approved", check=False).returncode
    f["receipts_after_a_execute_delta"] = _receipts(dc) - receipts0
    audit2 = _audit_lines(dc)
    f["a_execute_audit_events"] = [e.get("event") or e.get("type") for e in audit2[len(audit1):]]
    p = dc.exec(A_SVC, "node", "-e", REPLAY_JS, input=json.dumps(
        [esc["requestId"], esc["correlationId"], appr["mandate"], esc["context"],
         esc.get("action", "send_notification"), esc["resource"]]),
        check=False)
    f["a_replay"] = json.loads(p.stdout.strip().splitlines()[-1])
    f["receipts_after_replay_delta"] = _receipts(dc) - receipts0
    f["b_allow_rc"] = dc.exec(B_SVC, "npx", "tsx", "src/pilot-cli.ts", "allow", check=False).returncode
    f["receipts_after_b_allow_delta"] = _receipts(dc) - receipts0
    f["audit_chain_valid"] = dc.exec("mcc-gateway", "python", "-c",
                                     "from mcc_core import AuditLog;print(AuditLog.verify_chain('/data/audit.jsonl'))"
                                     ).stdout.strip()
    return f


# ------------------------------------------------------------------ isolation

def test_each_container_is_provisioned_as_exactly_its_own_principal(stack):
    assert stack["cred_a_principal"] == A
    assert stack["cred_b_principal"] == B
    assert stack["keys_distinct"]


@pytest.mark.parametrize("scan", ["scan_b", "scan_a"])
def test_agent_container_exposes_no_foreign_or_provisioning_secret(stack, scan):
    s = stack[scan]
    assert s["env_hits"] == 0, s
    assert s["files"] == [], s
    for forbidden in ("MCC_AGENT_API_KEYS", "MCC_GATEWAY_API_KEY", "MCC_GATEWAY_OPERATOR_API_KEY"):
        assert forbidden not in s["var_names"], (forbidden, s["var_names"])
    assert "MCC_AGENT_CREDENTIAL_FILE" in s["var_names"]


def test_agent_mounts_only_its_own_credential_volume_read_only(stack):
    for scan, own, other in (("scan_b", "agent-cred-notify-bot", "agent-cred-unknown"),
                             ("scan_a", "agent-cred-unknown", "agent-cred-notify-bot")):
        mounts = stack[scan]["mounts"]
        cred = [m for m in mounts if m[1] == "/run/mcc-agent"]
        assert len(cred) == 1 and cred[0][0].endswith(own) and cred[0][2] is False, mounts
        assert not any((m[0] or "").endswith(other) for m in mounts), mounts
        assert not any("config" in (m[0] or "") for m in mounts), mounts   # no registry/keys volume


@pytest.mark.parametrize("svc", [A_SVC, B_SVC, "mcc-gateway"])
def test_images_contain_no_provisioning_or_build_context_secret(stack, svc):
    img = stack["images"][svc]
    assert img["files"] == [], img
    assert img["history_hits"] == [], img


# -------------------------------------------------------------- impersonation

def test_preconditions_for_the_attack_were_met(stack):
    # Non-vacuity: A really escalated, the operator really approved, and B
    # really held A's copied mandate.
    assert stack["a_escalate_rc"] == 0 and stack["operator_rc"] == 0
    assert stack["escalation_actor"] == A
    assert stack["attack"]["own_principal"] == B and stack["attack"]["target_actor"] == A


def _attack(stack, name):
    return next(a for a in stack["attack"]["attacks"] if a["name"] == name)


def test_b_cannot_execute_a_copied_approval_on_either_route(stack):
    for name in ("approval_execute_as_A", "mandate_execute_as_A"):
        a = _attack(stack, name)
        assert a["status"] == "BLOCKED" and "AGENT_PRINCIPAL_MISMATCH" in (a["reason"] or ""), a
    for name in ("approval_execute_as_self", "mandate_execute_as_self"):
        a = _attack(stack, name)
        assert a["status"] == "BLOCKED" and "SUBJECT_MISMATCH" in (a["reason"] or ""), a


def test_b_cannot_create_an_approval_in_a_name(stack):
    a = _attack(stack, "create_approval_for_A")
    assert a["http"] == 403 and "AGENT_PRINCIPAL_MISMATCH" in (a["reason"] or ""), a


def test_spoofed_identity_headers_and_body_fields_grant_nothing(stack):
    a = _attack(stack, "spoofed_identity_headers")
    assert a["status"] == "BLOCKED" and "AGENT_PRINCIPAL_MISMATCH" in (a["reason"] or ""), a
    assert _attack(stack, "spoofed_body_identity")["http"] == 422


def test_missing_or_shared_credentials_are_refused(stack):
    assert _attack(stack, "no_credential")["http"] in (401, 422)
    shared = _attack(stack, "leaked_shared_tenant_key")
    assert shared["http"] == 403 and "AGENT_IDENTITY_REQUIRED" in (shared["reason"] or ""), shared


def test_rejected_attempts_left_no_trace_in_execution_state(stack):
    assert stack["receipts_after_attack_delta"] == 0
    # No decision token reached the coordinator: not a single audit record.
    assert stack["audit_after_attack_new"] == [], stack["audit_after_attack_new"]
    assert stack["attack"]["approval_state_after"] == "APPROVED"          # not consumed


# ------------------------------------------------------------ positive controls

def test_b_own_key_authenticates(stack):
    ctrl = stack["attack"]["controls"][0]
    assert ctrl["http"] == 200, ctrl


def test_a_executes_its_own_approval_with_the_key_b_tried(stack):
    # A uses the SAME idempotency key (correlationId) every B attempt used:
    # a rejected attempt reserved nothing.
    assert stack["a_execute_rc"] == 0
    assert stack["receipts_after_a_execute_delta"] == 1


def test_approval_is_single_use_after_execution(stack):
    same_key, fresh_key = stack["a_replay"]
    assert same_key["status"] != "EXECUTED" and fresh_key["status"] != "EXECUTED", stack["a_replay"]
    assert stack["receipts_after_replay_delta"] == 1


def test_b_executes_its_own_authorized_operation(stack):
    assert stack["b_allow_rc"] == 0
    assert stack["receipts_after_b_allow_delta"] == 2


def test_audit_chain_still_verifies(stack):
    assert stack["audit_chain_valid"] == "True"
