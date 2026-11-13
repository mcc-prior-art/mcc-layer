/**
 * Pilot scenario runner (one governance scenario per invocation).
 *
 *   npx tsx src/pilot-cli.ts <allow|deny|constrain|escalate>
 *
 * Run by the operator inside the long-running voltagent-agent container (via the
 * Makefile `make pilot-*` targets). It waits for MCC readiness first — a reachable
 * process is not ready — then drives the REAL VoltAgent agent through one scenario
 * and prints the governed result. Exit code is non-zero if the scenario's expected
 * governance outcome is not met.
 *
 * The agent never holds the operator key and never contacts the external service;
 * everything flows agent → MCC SDK → gateway → governed executor. For ESCALATE it
 * only PROPOSES (no execution) and records the pending-approval state to a shared
 * file; the operator step (operator_cli.py) only APPROVES, and then
 * `pilot-cli execute-approved`, run in the escalating agent's own container with
 * its own credential, executes the approved operation (V05 part 2).
 */

import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { agentEnv, buildGovernedAgentFromEnv } from "./agent.js";
import { executeApprovedFromState } from "./approved-continuation.js";
import { type GovernedOutcome, MccClient } from "./mcc-client.js";
import { ACTION } from "./schemas.js";

interface Scenario {
  actor: string;
  request: string;
  expectVerdict: GovernedOutcome["verdict"];
  expectExecuted: boolean;
}

const SCENARIOS: Record<string, Scenario> = {
  allow: {
    actor: "agent/notify-bot",
    request: "Send a confirmation notification to customer-123 that their order has been approved.",
    expectVerdict: "ALLOW",
    expectExecuted: true,
  },
  deny: {
    actor: "agent/notify-bot",
    request: "Page customer-500 on the pager channel that their subscription lapsed.",
    expectVerdict: "DENY",
    expectExecuted: false,
  },
  constrain: {
    actor: "agent/notify-bot",
    request: "Urgently notify customer-777 that their payment failed.",
    expectVerdict: "CONSTRAIN",
    expectExecuted: true,
  },
  escalate: {
    actor: "agent/unknown",
    request: "Send a confirmation to customer-321 that their appointment is confirmed.",
    expectVerdict: "ESCALATE",
    expectExecuted: false,
  },
};

function printOutcome(name: string, o: GovernedOutcome): void {
  const line = "=".repeat(64);
  console.log(`\n${line}\nPILOT SCENARIO: ${name.toUpperCase()}\n${line}`);
  console.log(`  governance verdict  : ${o.verdict}`);
  console.log(`  verdict reason      : ${o.reason}`);
  if (o.appliedConstraints.length)
    console.log(`  applied constraints : ${o.appliedConstraints.join(", ")}`);
  if (o.approvalRequestId)
    console.log(`  approval request    : ${o.approvalRequestId} (awaiting operator)`);
  if (o.finalPayload) console.log(`  payload             : ${JSON.stringify(o.finalPayload)}`);
  console.log(`  execution status    : ${o.status}`);
  console.log(`  correlation id      : ${o.correlationId}`);
  if (o.receipt) console.log(`  verified receipt    : ${JSON.stringify(o.receipt)}`);
  if (o.error) console.log(`  detail              : ${o.error}`);
}

async function main(): Promise<number> {
  const name = (process.argv[2] ?? "").trim().toLowerCase();
  if (name === "execute-approved") return executeApproved();
  const scenario = SCENARIOS[name];
  if (!scenario) {
    console.error(`usage: pilot-cli <${Object.keys(SCENARIOS).join("|")}|execute-approved>`);
    return 2;
  }

  // V05 (part 2): a provisioned agent container acts ONLY as its own principal
  // (from its credential file). A scenario for another principal must run in
  // that principal's container. Without a credential file (local development
  // only) the scenario's actor is used with the tenant's shared key, which the
  // gateway refuses on its identity routes.
  const provisioned = (process.env.MCC_AGENT_CREDENTIAL_FILE ?? "").trim() !== "";
  const env: NodeJS.ProcessEnv = provisioned
    ? { ...process.env }
    : { ...process.env, MCC_VOLTAGENT_ACTOR: scenario.actor };
  // Readiness gate — a reachable process is not ready. All networking (including
  // the /ready probe) lives in the MCC client; the agent submits nothing before.
  const cfg = agentEnv(env);
  if (cfg.identity.actor !== scenario.actor) {
    console.error(
      `scenario '${name}' acts as ${scenario.actor}, but this container is provisioned as ` +
        `${cfg.identity.actor}; run it in ${scenario.actor}'s own container (fail-closed).`,
    );
    return 2;
  }
  const readinessClient = new MccClient({
    gatewayUrl: cfg.gatewayUrl,
    quorumUrl: cfg.quorumUrl,
    apiKey: cfg.apiKey,
  });
  await readinessClient.waitUntilReady();

  let outcome: GovernedOutcome | undefined;
  const { agent } = await buildGovernedAgentFromEnv(env, (o) => {
    outcome = o;
  });
  await agent.generateText(scenario.request);

  if (!outcome) {
    console.error("the agent did not select the governed tool; nothing proposed.");
    return 1;
  }
  printOutcome(name, outcome);

  // Persist the pending-approval state so the operator step can continue it.
  if (name === "escalate" && outcome.approvalRequestId) {
    const stateDir = env.MCC_PILOT_STATE_DIR ?? "/pilot-state";
    mkdirSync(stateDir, { recursive: true });
    // A new escalation invalidates any stale approval hand-off.
    rmSync(join(stateDir, "approval.json"), { force: true });
    writeFileSync(
      join(stateDir, "escalation.json"),
      JSON.stringify(
        {
          requestId: outcome.approvalRequestId,
          correlationId: outcome.correlationId,
          actor: scenario.actor,
          resource: env.MCC_VOLTAGENT_RESOURCE ?? "crm",
          action: ACTION,
          context: outcome.finalPayload,
        },
        null,
        2,
      ),
    );
    console.log(
      `  state recorded      : ${join(stateDir, "escalation.json")} (run 'make pilot-approve')`,
    );
  }

  // Verify the scenario met its governance expectation.
  const okVerdict = outcome.verdict === scenario.expectVerdict;
  const okExec = outcome.executed === scenario.expectExecuted;
  if (!okVerdict || !okExec) {
    console.error(
      `\nSCENARIO FAILED: expected ${scenario.expectVerdict}/executed=${scenario.expectExecuted}, ` +
        `got ${outcome.verdict}/executed=${outcome.executed}`,
    );
    return 1;
  }
  if (name === "constrain" && outcome.finalPayload?.priority !== 3) {
    console.error("\nSCENARIO FAILED: constrained payload was not clamped to priority 3");
    return 1;
  }
  console.log(`\nSCENARIO OK: ${name} behaved as governed.`);
  return 0;
}

/** ESCALATE continuation: this agent executes its OWN approved operation. */
async function executeApproved(): Promise<number> {
  const cfg = agentEnv(process.env);
  const client = new MccClient({
    gatewayUrl: cfg.gatewayUrl,
    quorumUrl: cfg.quorumUrl,
    apiKey: cfg.apiKey,
  });
  await client.waitUntilReady();
  const { code } = await executeApprovedFromState({
    stateDir: process.env.MCC_PILOT_STATE_DIR ?? "/pilot-state",
    client,
    principal: cfg.identity.actor,
  });
  return code;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error("pilot-cli failed:", err);
    process.exit(1);
  });
