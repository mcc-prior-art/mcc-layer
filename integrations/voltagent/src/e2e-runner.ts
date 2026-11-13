/**
 * VoltAgent governed-integration end-to-end runner (Docker Compose).
 *
 * Drives the REAL VoltAgent agent against the running MCC-Core stack and asserts,
 * in real containers, the four verdicts and a genuine EXECUTED result:
 *
 *   ALLOW      -> agent proposes -> governed consensus execution -> verified receipt -> EXECUTED
 *   DENY       -> blocked; the notification service is never called
 *   CONSTRAIN  -> only the clamped payload is executed; receipt matches the clamp
 *   ESCALATE   -> agent gets PENDING_APPROVAL (no execution); an operator approves
 *                 -> governed execution -> verified receipt -> EXECUTED
 *
 * VoltAgent never calls the notification service directly and never holds the
 * operator key. A clean exit alone is NOT success — the markers below must print.
 */

import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { agentEnv, buildGovernedAgentFromEnv } from "./agent.js";
import {
  APPROVAL_FILE,
  executeApprovedFromState,
  loadApprovedEscalation,
  recordEscalation,
} from "./approved-continuation.js";
import type { GovernedOutcome } from "./mcc-client.js";
import { MccClient } from "./mcc-client.js";
import { resolveModel } from "./model.js";
import { ACTION } from "./schemas.js";

const failures: string[] = [];

function check(cond: boolean, msg: string): void {
  if (!cond) failures.push(msg);
}

async function waitForReady(client: MccClient, correlationId: string): Promise<void> {
  const deadline = Date.now() + 60_000;
  // Verify audit reachability as a proxy for gateway readiness.
  while (Date.now() < deadline) {
    try {
      await client.verifyAudit(correlationId);
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  throw new Error("gateway did not become reachable within 60s");
}

function printOutcome(label: string, o: GovernedOutcome | undefined): void {
  console.log(`\n--- Scenario: ${label} ---`);
  if (!o) {
    console.log("  (agent did not select the governed tool)");
    return;
  }
  console.log(`  governance verdict  : ${o.verdict}`);
  console.log(`  execution status    : ${o.status}`);
  console.log(`  correlation id      : ${o.correlationId}`);
  if (o.appliedConstraints.length)
    console.log(`  applied constraints : ${o.appliedConstraints.join(", ")}`);
  if (o.finalPayload) console.log(`  executed payload    : ${JSON.stringify(o.finalPayload)}`);
  if (o.receipt) console.log(`  verified receipt    : ${JSON.stringify(o.receipt)}`);
  if (o.approvalRequestId) console.log(`  approval request    : ${o.approvalRequestId}`);
  if (o.error) console.log(`  detail              : ${o.error}`);
}

async function runAgentScenario(
  label: string,
  request: string,
): Promise<GovernedOutcome | undefined> {
  let captured: GovernedOutcome | undefined;
  const { agent } = await buildGovernedAgentFromEnv(process.env, (o) => {
    captured = o;
  });
  await agent.generateText(request);
  printOutcome(label, captured);
  return captured;
}

async function waitForApproval(stateDir: string, principal: string): Promise<boolean> {
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    if (loadApprovedEscalation(stateDir, principal).ok) return true;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

/** ALLOW / DENY / CONSTRAIN as agent/notify-bot (its own container + credential). */
async function runNotifyBot(cfg: ReturnType<typeof agentEnv>): Promise<void> {
  const allow = await runAgentScenario(
    "ALLOW",
    "Send a confirmation notification to customer-123 that their order has been approved.",
  );
  check(allow?.verdict === "ALLOW", "ALLOW: unexpected verdict");
  check(allow?.status === "EXECUTED", "ALLOW: genuine EXECUTED absent (no verified receipt)");
  check(allow?.receipt?.receiptVerified === true, "ALLOW: external receipt not verified");

  const deny = await runAgentScenario(
    "DENY",
    "Page customer-500 on the pager channel that their subscription lapsed.",
  );
  check(deny?.verdict === "DENY", "DENY: unexpected verdict");
  check(deny?.executed === false && deny?.status === "BLOCKED", "DENY: must not execute");

  const constrain = await runAgentScenario(
    "CONSTRAIN",
    "Urgently notify customer-777 that their payment failed.",
  );
  check(constrain?.verdict === "CONSTRAIN", "CONSTRAIN: unexpected verdict");
  check(constrain?.status === "EXECUTED", "CONSTRAIN: genuine EXECUTED absent");
  check(
    (constrain?.finalPayload?.priority as number | undefined) === 3,
    "CONSTRAIN: executed payload was not clamped to priority 3",
  );
  void cfg;
}

/**
 * ESCALATE as agent/unknown: propose -> PENDING_APPROVAL; the separate operator
 * sidecar (operator_cli.py --watch, operator key only) approves; THIS agent then
 * executes its own approved operation with its own credential.
 */
async function runUnknown(cfg: ReturnType<typeof agentEnv>, client: MccClient): Promise<void> {
  const stateDir = process.env.MCC_PILOT_STATE_DIR ?? "/pilot-state";
  const escalate = await runAgentScenario(
    "ESCALATE (proposal)",
    "Send a confirmation to customer-321 that their appointment is confirmed.",
  );
  check(escalate?.verdict === "ESCALATE", "ESCALATE: unexpected verdict");
  check(
    escalate?.executed === false && escalate?.status === "PENDING_APPROVAL",
    "ESCALATE: must not execute before approval",
  );
  check(Boolean(escalate?.approvalRequestId), "ESCALATE: no approval request opened");
  if (!escalate?.approvalRequestId) return;

  mkdirSync(stateDir, { recursive: true });
  rmSync(join(stateDir, APPROVAL_FILE), { force: true });
  // Continue the SAME escalated operation (escalate.finalPayload is the exact
  // content that was escalated and approved), never a re-typed reconstruction.
  recordEscalation(stateDir, {
    requestId: escalate.approvalRequestId,
    correlationId: escalate.correlationId,
    actor: cfg.identity.actor,
    resource: cfg.identity.resource,
    action: ACTION,
    context: escalate.finalPayload ?? {},
  });
  console.log("\n--- Scenario: ESCALATE (awaiting the operator sidecar) ---");
  const approved = await waitForApproval(stateDir, cfg.identity.actor);
  check(approved, "ESCALATE: the operator never granted the approval");
  if (!approved) return;
  console.log("  approval state      : APPROVED (operator granted)");
  const { code, outcome } = await executeApprovedFromState({
    stateDir,
    client,
    principal: cfg.identity.actor,
  });
  printOutcome("ESCALATE (after approval, executed by the agent itself)", outcome);
  check(code === 0, "ESCALATE: not a verified EXECUTED after valid approval");
}

async function main(): Promise<number> {
  // V05 (part 2): this process is ONE agent -- the principal of the single
  // credential its container was provisioned with. It holds no operator key
  // and no other agent's credential.
  const cfg = agentEnv(process.env);
  const client = new MccClient({
    gatewayUrl: cfg.gatewayUrl,
    quorumUrl: cfg.quorumUrl,
    apiKey: cfg.apiKey,
  });

  console.log("=".repeat(70));
  console.log(
    `VoltAgent → MCC-Core Real Governed Integration (Docker E2E) as ${cfg.identity.actor}`,
  );
  console.log("=".repeat(70));
  await waitForReady(client, "corr-e2e-ready");
  const { provider } = await resolveModel(process.env);
  console.log(`  model provider      : ${provider}`);

  let role: string;
  if (cfg.identity.actor === "agent/notify-bot") {
    role = "ALLOW + DENY + CONSTRAIN";
    await runNotifyBot(cfg);
  } else if (cfg.identity.actor === "agent/unknown") {
    role = "ESCALATE (operator approval, agent-executed)";
    await runUnknown(cfg, client);
  } else {
    console.error(`no E2E role for principal ${cfg.identity.actor} (fail-closed)`);
    return 2;
  }

  const audit = await client.verifyAudit("corr-e2e-audit");
  console.log(`\n  audit verification  : valid=${audit.valid}`);
  check(audit.valid === true, "audit chain did not verify");

  console.log(`\n${"=".repeat(70)}`);
  if (failures.length) {
    console.log("VOLTAGENT GOVERNED INTEGRATION FAILED:");
    for (const f of failures) console.log(`  - ${f}`);
    return 1;
  }
  console.log(`VOLTAGENT GOVERNED INTEGRATION PASSED (${cfg.identity.actor}: ${role})`);
  console.log("genuine EXECUTED + verified receipts + valid audit chain.");
  console.log("VoltAgent proposes. MCC-Core decides. The gate enforces. The audit chain records.");
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error("e2e runner failed:", err);
    process.exit(1);
  });
