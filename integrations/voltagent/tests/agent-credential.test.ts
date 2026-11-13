// V05 (part 2): one agent process = one provisioned credential, and the
// escalating agent (not the operator) executes its own approved operation.
// Offline: no gateway is contacted (a recording fake client stands in).
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AgentCredentialError,
  loadAgentCredential,
  parseAgentCredential,
  resolveAgentIdentity,
} from "../src/agent-credential.js";
import { agentEnv } from "../src/agent.js";
import {
  APPROVAL_FILE,
  ESCALATION_FILE,
  executeApprovedFromState,
  loadApprovedEscalation,
} from "../src/approved-continuation.js";
import type { MccClient } from "../src/mcc-client.js";

const CRED = {
  tenant_id: "pilot",
  principal_id: "agent/a",
  credential_id: "a-1",
  api_key: "canary-key-a",
};

function credFile(doc: unknown): string {
  const dir = mkdtempSync(join(tmpdir(), "mcc-cred-"));
  const p = join(dir, "credential.json");
  writeFileSync(p, typeof doc === "string" ? doc : JSON.stringify(doc));
  return p;
}

describe("per-agent credential file (fail-closed)", () => {
  it("loads exactly one principal + key; the actor IS the provisioned principal", () => {
    const env = { MCC_AGENT_CREDENTIAL_FILE: credFile(CRED) };
    expect(loadAgentCredential(env)?.principalId).toBe("agent/a");
    const cfg = agentEnv(env);
    expect(cfg.identity.actor).toBe("agent/a");
    expect(cfg.apiKey).toBe("canary-key-a");
  });

  it("refuses a provisioning map in the agent environment, even alongside a valid file", () => {
    const env = {
      MCC_AGENT_CREDENTIAL_FILE: credFile(CRED),
      MCC_AGENT_API_KEYS: JSON.stringify({ "agent/a": "k", "agent/b": "k2" }),
    };
    expect(() => loadAgentCredential(env)).toThrow(AgentCredentialError);
    expect(() => agentEnv(env)).toThrow(/never be given to an agent/);
  });

  it("refuses an actor setting that differs from the provisioned principal", () => {
    const env = { MCC_AGENT_CREDENTIAL_FILE: credFile(CRED), MCC_VOLTAGENT_ACTOR: "agent/b" };
    expect(() => agentEnv(env)).toThrow(/not this agent's provisioned principal/);
    expect(() =>
      resolveAgentIdentity({ MCC_AGENT_CREDENTIAL_FILE: credFile(CRED) }, "agent/a", "x"),
    ).not.toThrow();
  });

  it.each([
    ["missing file", undefined],
    ["not JSON", "not-json"],
    ["array", "[]"],
    ["missing field", { tenant_id: "pilot", principal_id: "agent/a", api_key: "k" }],
    ["extra field", { ...CRED, other_agents: { "agent/b": "k" } }],
    ["empty key", { ...CRED, api_key: "" }],
    ["padded principal", { ...CRED, principal_id: " agent/a" }],
    ["non-string", { ...CRED, api_key: 7 }],
  ])("refuses %s", (_label, doc) => {
    const path = doc === undefined ? "/nonexistent/credential.json" : credFile(doc);
    expect(() => loadAgentCredential({ MCC_AGENT_CREDENTIAL_FILE: path })).toThrow(
      AgentCredentialError,
    );
  });

  it("parse never accepts a value it cannot attribute to one principal", () => {
    expect(() => parseAgentCredential(JSON.stringify({ ...CRED, principal_id: "" }))).toThrow();
  });

  it("without a credential file (local dev only) it falls back to the shared tenant key", () => {
    const out = resolveAgentIdentity({ MCC_GATEWAY_API_KEY: "shared" }, undefined, "agent/x");
    expect(out).toEqual({ actor: "agent/x", apiKey: "shared", provisioned: false });
  });
});

// ---- ESCALATE continuation: the agent executes its OWN approval ----------- //

function stateDir(esc: Record<string, unknown> | undefined, appr?: Record<string, unknown>) {
  const dir = mkdtempSync(join(tmpdir(), "mcc-state-"));
  if (esc) writeFileSync(join(dir, ESCALATION_FILE), JSON.stringify(esc));
  if (appr) writeFileSync(join(dir, APPROVAL_FILE), JSON.stringify(appr));
  return dir;
}

const ESC = {
  requestId: "req-1",
  correlationId: "corr-preserve-me",
  actor: "agent/a",
  resource: "crm",
  action: "send_notification",
  context: { recipient: "c-1", message: "hi" },
};
const APPR = {
  requestId: "req-1",
  correlationId: "corr-preserve-me",
  state: "APPROVED",
  mandate: { m: 1 },
};

function recordingClient(status = "EXECUTED") {
  const calls: Array<{ requestId: string; idem?: string; actor: string }> = [];
  const client = {
    async executeApprovedNotification(
      proposal: { actor: string },
      requestId: string,
      _mandate: unknown,
      _corr: string,
      opts: { idempotencyKey?: string },
    ) {
      calls.push({ requestId, idem: opts.idempotencyKey, actor: proposal.actor });
      return {
        verdict: "ESCALATE",
        status,
        executed: status === "EXECUTED",
        reason: "",
        correlationId: "corr-preserve-me",
        appliedConstraints: [],
        receipt: status === "EXECUTED" ? { receiptVerified: true } : undefined,
      };
    },
    async verifyAudit() {
      return { valid: true, raw: {} };
    },
  } as unknown as MccClient;
  return { client, calls };
}

describe("approved continuation (Round 26/27 invariants at the new execution point)", () => {
  it("executes with the SAME logical-operation id the proposal recorded (correlationId)", async () => {
    const { client, calls } = recordingClient();
    const res = await executeApprovedFromState({
      stateDir: stateDir(ESC, APPR),
      client,
      principal: "agent/a",
    });
    expect(res.code).toBe(0);
    expect(calls).toEqual([{ requestId: "req-1", idem: "corr-preserve-me", actor: "agent/a" }]);
  });

  it.each([
    ["missing", undefined],
    ["empty", ""],
    ["blank", "   "],
    ["null", null],
    ["non-string", 12345],
  ])(
    "a %s correlationId fails closed before any gateway call (never the request id)",
    async (_l, bad) => {
      const { client, calls } = recordingClient();
      const { correlationId: _omit, ...rest } = ESC;
      const esc: Record<string, unknown> =
        bad === undefined ? rest : { ...rest, correlationId: bad };
      const res = await executeApprovedFromState({
        stateDir: stateDir(esc, APPR),
        client,
        principal: "agent/a",
      });
      expect(res.code).toBe(1);
      expect(calls).toEqual([]);
    },
  );

  it("another principal's escalation is refused before any gateway call", async () => {
    const { client, calls } = recordingClient();
    const res = await executeApprovedFromState({
      stateDir: stateDir(ESC, APPR),
      client,
      principal: "agent/b",
    });
    expect(res.code).toBe(1);
    expect(calls).toEqual([]);
  });

  it.each([
    ["no approval yet", undefined],
    ["approval for another request", { ...APPR, requestId: "req-other" }],
    ["approval for another operation id", { ...APPR, correlationId: "corr-other" }],
    ["approval not granted", { ...APPR, state: "DENIED", mandate: null }],
  ])("refuses: %s", async (_l, appr) => {
    expect(loadApprovedEscalation(stateDir(ESC, appr), "agent/a").ok).toBe(false);
    const { client, calls } = recordingClient();
    const res = await executeApprovedFromState({
      stateDir: stateDir(ESC, appr),
      client,
      principal: "agent/a",
    });
    expect(res.code).toBe(1);
    expect(calls).toEqual([]);
  });

  it("a gateway BLOCKED outcome is reported as failure, never success", async () => {
    const { client } = recordingClient("BLOCKED");
    const res = await executeApprovedFromState({
      stateDir: stateDir(ESC, APPR),
      client,
      principal: "agent/a",
    });
    expect(res.code).toBe(1);
  });
});
