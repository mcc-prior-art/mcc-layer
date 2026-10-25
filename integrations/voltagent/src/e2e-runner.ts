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

import { agentEnv, buildGovernedAgentFromEnv } from "./agent.js";
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
  actor: string,
): Promise<GovernedOutcome | undefined> {
  const env = { ...process.env, MCC_VOLTAGENT_ACTOR: actor };
  let captured: GovernedOutcome | undefined;
  const { agent } = await buildGovernedAgentFromEnv(env, (o) => {
    captured = o;
  });
  await agent.generateText(request);
  printOutcome(label, captured);
  return captured;
}

async function main(): Promise<number> {
  const cfg = agentEnv(process.env);
  const operatorKey = process.env.MCC_GATEWAY_OPERATOR_API_KEY ?? "op-key";
  // Operator client: holds the operator key. This is NOT the agent — the agent's
  // client never has it. Used only to grant the ESCALATE approval.
  const operator = new MccClient({
    gatewayUrl: cfg.gatewayUrl,
    quorumUrl: cfg.quorumUrl,
    apiKey: cfg.apiKey,
    operatorKey,
  });

  console.log("=".repeat(70));
  console.log("VoltAgent → MCC-Core Real Governed Integration (Docker E2E)");
  console.log("=".repeat(70));
  await waitForReady(operator, "corr-e2e-ready");
  const { provider } = await resolveModel(process.env);
  console.log(`  model provider      : ${provider}`);

  // A. ALLOW -> genuine EXECUTED.
  const allow = await runAgentScenario(
    "ALLOW",
    "Send a confirmation notification to customer-123 that their order has been approved.",
    cfg.identity.actor,
  );
  check(allow?.verdict === "ALLOW", "ALLOW: unexpected verdict");
  check(allow?.status === "EXECUTED", "ALLOW: genuine EXECUTED absent (no verified receipt)");
  check(allow?.receipt?.receiptVerified === true, "ALLOW: external receipt not verified");

  // B. DENY -> blocked, service never called.
  const deny = await runAgentScenario(
    "DENY",
    "Page customer-500 on the pager channel that their subscription lapsed.",
    cfg.identity.actor,
  );
  check(deny?.verdict === "DENY", "DENY: unexpected verdict");
  check(deny?.executed === false && deny?.status === "BLOCKED", "DENY: must not execute");

  // C. CONSTRAIN -> only the clamped payload executed.
  const constrain = await runAgentScenario(
    "CONSTRAIN",
    "Urgently notify customer-777 that their payment failed.",
    cfg.identity.actor,
  );
  check(constrain?.verdict === "CONSTRAIN", "CONSTRAIN: unexpected verdict");
  check(constrain?.status === "EXECUTED", "CONSTRAIN: genuine EXECUTED absent");
  check(
    (constrain?.finalPayload?.priority as number | undefined) === 3,
    "CONSTRAIN: executed payload was not clamped to priority 3",
  );

  // D. ESCALATE -> agent gets PENDING_APPROVAL; operator approves -> EXECUTED.
  const escRequest = "Send a confirmation to customer-321 that their appointment is confirmed.";
  const escalate = await runAgentScenario("ESCALATE (proposal)", escRequest, "agent/unknown");
  check(escalate?.verdict === "ESCALATE", "ESCALATE: unexpected verdict");
  check(
    escalate?.executed === false && escalate?.status === "PENDING_APPROVAL",
    "ESCALATE: must not execute before approval",
  );
  check(Boolean(escalate?.approvalRequestId), "ESCALATE: no approval request opened");

  if (escalate?.approvalRequestId) {
    // Operator (separate authority) approves and the governed execution
    // continues the SAME escalated operation -- reusing escalate.finalPayload
    // (the exact content that was escalated and approved) rather than
    // hand-typing a new message here. The gateway now binds the approval to
    // the exact server-stored payload (see src/mcc_core/approvals.py), so
    // even a cosmetically-different re-typed payload for "the same" action
    // is correctly rejected as a substitution -- this demo continues the
    // real approved operation, not a reconstruction of it.
    const proposal = {
      actor: "agent/unknown",
      action: ACTION,
      resource: cfg.identity.resource,
      context: escalate.finalPayload ?? {},
    };
    const granted = await operator.approveAsOperator(
      escalate.approvalRequestId,
      escalate.correlationId,
    );
    console.log(`\n--- Scenario: ESCALATE (operator ${granted.state}) ---`);
    const done = await operator.executeApprovedNotification(
      proposal,
      escalate.approvalRequestId,
      granted.mandate,
      escalate.correlationId,
    );
    printOutcome("ESCALATE (after approval)", done);
    check(done.status === "EXECUTED", "ESCALATE: not EXECUTED after valid approval");
    check(done.receipt?.receiptVerified === true, "ESCALATE: receipt not verified after approval");
  }

  // Audit chain must verify.
  const audit = await operator.verifyAudit("corr-e2e-audit");
  console.log(`\n  audit verification  : valid=${audit.valid}`);
  check(audit.valid === true, "audit chain did not verify");

  console.log(`\n${"=".repeat(70)}`);
  if (failures.length) {
    console.log("VOLTAGENT GOVERNED INTEGRATION FAILED:");
    for (const f of failures) console.log(`  - ${f}`);
    return 1;
  }
  console.log("VOLTAGENT GOVERNED INTEGRATION PASSED: four verdicts + genuine EXECUTED");
  console.log("(consensus + operator approval) + verified receipts + valid audit chain.");
  console.log("VoltAgent proposes. MCC-Core decides. The gate enforces. The audit chain records.");
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error("e2e runner failed:", err);
    process.exit(1);
  });
