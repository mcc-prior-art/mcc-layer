import { describe, expect, it } from "vitest";
import { createGovernedAgent } from "../src/agent.js";
import { MccClient } from "../src/mcc-client.js";
import { createDeterministicModel } from "../src/model.js";
import { type ProposalIdentity, buildProposal } from "../src/schemas.js";
import { createGovernedNotificationTool } from "../src/tools/governed-notification.js";
import {
  API_KEY,
  GATEWAY_URL,
  OPERATOR_KEY,
  QUORUM_URL,
  SKIP_INTEGRATION,
  agentKey,
} from "./_config.js";

const IDENTITY: ProposalIdentity = { actor: "agent/notify-bot", resource: "crm" };

// V05 (part 2) + F1: an agent acting as `actor` presents its OWN credential on
// every governed route -- /evaluate, /consensus/*, the quorum's /vote and the
// identity routes. The shared tenant key grants no agent identity.
function agentClient(actor: string = IDENTITY.actor): MccClient {
  return new MccClient({ gatewayUrl: GATEWAY_URL, quorumUrl: QUORUM_URL, apiKey: agentKey(actor) });
}
function operatorClient(actor?: string): MccClient {
  return new MccClient({
    gatewayUrl: GATEWAY_URL,
    quorumUrl: QUORUM_URL,
    apiKey: actor ? agentKey(actor) : API_KEY,
    operatorKey: OPERATOR_KEY,
  });
}
function propose(
  over: Partial<{
    recipient: string;
    message: string;
    priority: "low" | "normal" | "high" | "urgent";
    channel: "email" | "sms" | "pager";
    correlationId: string;
  }>,
  identity = IDENTITY,
) {
  return buildProposal(
    {
      recipient: over.recipient ?? "customer-123",
      message: over.message ?? "your order is approved",
      priority: over.priority ?? "normal",
      channel: over.channel ?? "email",
      correlationId: over.correlationId,
    },
    identity,
  );
}

describe.skipIf(SKIP_INTEGRATION)("VoltAgent governed integration (real MCC gateway)", () => {
  it("A. ALLOW -> genuine EXECUTED with a verified external receipt + valid audit", async () => {
    const out = await agentClient().governNotification(
      propose({ correlationId: "corr-it-allow" }),
      "corr-it-allow",
    );
    expect(out.verdict).toBe("ALLOW");
    expect(out.status).toBe("EXECUTED");
    expect(out.executed).toBe(true);
    expect(out.receipt?.receiptVerified).toBe(true);
    expect(out.receipt?.correlationId).toBe("corr-it-allow");
    expect((await agentClient().verifyAudit("corr-it-audit")).valid).toBe(true);
  });

  it("B. DENY -> not executed, external service never called", async () => {
    const out = await agentClient().governNotification(
      propose({ channel: "pager" }),
      "corr-it-deny",
    );
    expect(out.verdict).toBe("DENY");
    expect(out.executed).toBe(false);
    expect(out.status).toBe("BLOCKED");
    expect(out.receipt).toBeUndefined();
  });

  it("D. CONSTRAIN -> only the clamped payload is executed and bound to the receipt", async () => {
    const out = await agentClient().governNotification(
      propose({ priority: "urgent" }),
      "corr-it-con",
    );
    expect(out.verdict).toBe("CONSTRAIN");
    expect(out.executed).toBe(true);
    expect(out.appliedConstraints.length).toBeGreaterThan(0);
    expect(out.finalPayload?.priority).toBe(3); // clamped, not the original 9
    expect(out.receipt?.received).toBe(true);
  });

  it("C. ESCALATE -> PENDING_APPROVAL before approval; EXECUTED only after a valid operator approval", async () => {
    const proposal = propose(
      { correlationId: "corr-it-esc" },
      { actor: "agent/unknown", resource: "crm" },
    );
    const pending = await agentClient("agent/unknown").governNotification(proposal, "corr-it-esc");
    expect(pending.verdict).toBe("ESCALATE");
    expect(pending.executed).toBe(false);
    expect(pending.status).toBe("PENDING_APPROVAL");
    expect(pending.approvalRequestId).toBeTruthy();

    // Operator (separate authority, holds the operator key) approves; the
    // approved execution is presented with agent/unknown's own credential
    // (V05 part 2: the shared tenant key cannot execute as an agent).
    const op = operatorClient("agent/unknown");
    const granted = await op.approveAsOperator(pending.approvalRequestId as string, "corr-it-esc");
    const done = await op.executeApprovedNotification(
      proposal,
      pending.approvalRequestId as string,
      granted.mandate,
      "corr-it-esc",
    );
    expect(done.status).toBe("EXECUTED");
    expect(done.receipt?.receiptVerified).toBe(true);
  });

  it("F1. another agent's credential cannot obtain consensus or execute as notify-bot", async () => {
    // agent/unknown presents its OWN credential but proposes as agent/notify-bot:
    // the gateway (/evaluate, /consensus/*) and the quorum (/vote) refuse.
    const proposal = propose({ correlationId: "corr-it-f1" });
    const refused = await agentClient("agent/unknown").governNotification(proposal, "corr-it-f1");
    expect(refused.executed).toBe(false);
    expect(refused.status).toBe("ERROR");
    expect(refused.error).toMatch(/AGENT_PRINCIPAL_MISMATCH/);
    expect(refused.receipt).toBeUndefined();
    // Positive control: notify-bot executes the very same proposal.
    const ok = await agentClient().governNotification(proposal, "corr-it-f1");
    expect(ok.status).toBe("EXECUTED");
    expect(ok.receipt?.receiptVerified).toBe(true);
  });

  it("F. duplicate execution (same idempotency key) does not run twice", async () => {
    const p = propose({ correlationId: "corr-it-dupe" });
    const first = await agentClient().governNotification(p, "corr-it-dupe", {
      idempotencyKey: "idem-1",
    });
    expect(first.executed).toBe(true);
    const second = await agentClient().governNotification(p, "corr-it-dupe", {
      idempotencyKey: "idem-1",
    });
    expect(second.executed).toBe(false); // deduped by MCC-Core, not re-executed
  });

  it("propagates the correlation id through to the governed outcome", async () => {
    const out = await agentClient().governNotification(
      propose({ correlationId: "corr-trace-9" }),
      "corr-trace-9",
    );
    expect(out.correlationId).toBe("corr-trace-9");
  });

  it("the governed tool maps args -> contract -> governed execution", async () => {
    const tool = createGovernedNotificationTool({ client: agentClient(), identity: IDENTITY });
    // Call the tool's execute directly (as VoltAgent would after tool selection).
    const out = (await (
      tool.execute as (a: unknown, o?: unknown) => Promise<{ status: string; executed: boolean }>
    )({ recipient: "customer-55", message: "hi", priority: "normal", channel: "email" }, {})) as {
      status: string;
      executed: boolean;
    };
    expect(out.status).toBe("EXECUTED");
    expect(out.executed).toBe(true);
  });

  it("the real VoltAgent agent selects the governed tool and gets a governed result", async () => {
    let captured: { status: string; executed: boolean } | undefined;
    const agent = createGovernedAgent({
      client: agentClient(),
      identity: IDENTITY,
      model: createDeterministicModel(),
      onOutcome: (o) => {
        captured = o as unknown as { status: string; executed: boolean };
      },
    });
    await agent.generateText("Send a confirmation to customer-123 that their order was approved");
    expect(captured?.status).toBe("EXECUTED");
    expect(captured?.executed).toBe(true);
  });
});
