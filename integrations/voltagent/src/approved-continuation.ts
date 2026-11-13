/**
 * V05 (part 2): the escalating AGENT executes its own approved operation.
 *
 * ESCALATE flow across trust boundaries:
 *   1. the agent proposes -> PENDING_APPROVAL, records `escalation.json`;
 *   2. the operator (operator_cli.py, gateway side, operator key only) approves
 *      and records the granted single-use mandate in `approval.json`;
 *   3. THIS module, running in the escalating agent's own container with its
 *      own provisioned credential, executes the ORIGINAL operation.
 *
 * The operator never holds or presents an agent credential; the shared state
 * directory carries no credential (the mandate is signed for this agent, this
 * exact operation and tenant, and is useless to any other principal).
 *
 * Fail-closed before any gateway call: missing/malformed state, a missing
 * original logical-operation id (correlationId -- Round 26/27: reused verbatim
 * as the idempotency key, never replaced by the approval request id), an
 * approval that is not for this exact escalation, or an escalation that
 * belongs to another principal.
 */

import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { GovernedOutcome, MccClient } from "./mcc-client.js";

export const ESCALATION_FILE = "escalation.json";
export const APPROVAL_FILE = "approval.json";

export interface EscalationRecord {
  requestId: string;
  correlationId: string;
  actor: string;
  resource: string;
  action: string;
  context: Record<string, unknown>;
}

function readJson(path: string): Record<string, unknown> | undefined {
  try {
    const doc = JSON.parse(readFileSync(path, "utf8"));
    return doc !== null && typeof doc === "object" && !Array.isArray(doc) ? doc : undefined;
  } catch {
    return undefined;
  }
}

const nonEmpty = (v: unknown): v is string => typeof v === "string" && v.trim() !== "";

export function recordEscalation(stateDir: string, rec: EscalationRecord): string {
  const path = join(stateDir, ESCALATION_FILE);
  writeFileSync(path, JSON.stringify(rec, null, 2));
  return path;
}

/** Validate the pending escalation + its granted approval for `principal`. */
export function loadApprovedEscalation(
  stateDir: string,
  principal: string,
):
  | { ok: true; esc: EscalationRecord; mandate: Record<string, unknown> }
  | { ok: false; error: string } {
  const esc = readJson(join(stateDir, ESCALATION_FILE));
  if (!esc) return { ok: false, error: `no readable ${ESCALATION_FILE} in ${stateDir}` };
  if (!nonEmpty(esc.correlationId)) {
    return {
      ok: false,
      error:
        "escalation is missing its original logical_operation_id (correlationId); " +
        "the approval request id is never substituted for it",
    };
  }
  if (!nonEmpty(esc.requestId) || !nonEmpty(esc.actor) || !nonEmpty(esc.resource)) {
    return { ok: false, error: "escalation state is malformed" };
  }
  const ctx = esc.context;
  if (ctx === null || typeof ctx !== "object" || Array.isArray(ctx)) {
    return { ok: false, error: "escalation state has no proposed payload" };
  }
  if (esc.actor !== principal) {
    return {
      ok: false,
      error: `this escalation belongs to '${String(esc.actor)}', not to this agent ('${principal}'); it can only be executed from that agent's own container with its own credential`,
    };
  }
  const appr = readJson(join(stateDir, APPROVAL_FILE));
  if (!appr) return { ok: false, error: `no granted approval (${APPROVAL_FILE}) yet` };
  if (appr.requestId !== esc.requestId || appr.correlationId !== esc.correlationId) {
    return { ok: false, error: "the recorded approval is not for this escalation" };
  }
  const mandate = appr.mandate;
  if (
    appr.state !== "APPROVED" ||
    mandate === null ||
    typeof mandate !== "object" ||
    Array.isArray(mandate)
  ) {
    return { ok: false, error: "the approval was not granted (no mandate)" };
  }
  return {
    ok: true,
    esc: {
      requestId: esc.requestId,
      correlationId: esc.correlationId,
      actor: esc.actor,
      resource: esc.resource,
      action: nonEmpty(esc.action) ? esc.action : "send_notification",
      context: ctx as Record<string, unknown>,
    },
    mandate: mandate as Record<string, unknown>,
  };
}

/** Execute the approved escalation; returns a process exit code. */
export async function executeApprovedFromState(opts: {
  stateDir: string;
  client: MccClient;
  principal: string;
}): Promise<{ code: number; outcome?: GovernedOutcome }> {
  const loaded = loadApprovedEscalation(opts.stateDir, opts.principal);
  if (!loaded.ok) {
    console.error(`\nFAILED: ${loaded.error}; refusing to execute (fail-closed).`);
    return { code: 1 };
  }
  const { esc, mandate } = loaded;
  console.log("=".repeat(64));
  console.log(`AGENT EXECUTES APPROVED ESCALATION ${esc.requestId}`);
  console.log("=".repeat(64));
  console.log(`  actor / resource    : ${esc.actor} / ${esc.resource}`);
  console.log(`  correlation id      : ${esc.correlationId}`);
  const outcome = await opts.client.executeApprovedNotification(
    { actor: esc.actor, action: esc.action, resource: esc.resource, context: esc.context },
    esc.requestId,
    mandate,
    esc.correlationId,
    // Round 26: the SAME logical-operation identity the proposal recorded.
    { idempotencyKey: esc.correlationId },
  );
  console.log(`  execution status    : ${outcome.status}`);
  if (outcome.receipt) console.log(`  external receipt    : ${JSON.stringify(outcome.receipt)}`);
  if (outcome.error) console.log(`  detail              : ${outcome.error}`);
  const audit = await opts.client.verifyAudit(esc.correlationId);
  console.log(`  audit verification  : valid=${audit.valid}`);
  if (outcome.status !== "EXECUTED" || outcome.receipt?.receiptVerified !== true || !audit.valid) {
    console.error("\nFAILED: escalation did not reach a verified EXECUTED after approval.");
    return { code: 1, outcome };
  }
  // Consume the state so it cannot be replayed (the approval is single-use at
  // the gateway regardless).
  for (const f of [ESCALATION_FILE, APPROVAL_FILE]) {
    const p = join(opts.stateDir, f);
    if (existsSync(p)) rmSync(p);
  }
  console.log(
    "\nSCENARIO OK: ESCALATE approved -> governed execution -> verified receipt -> EXECUTED.",
  );
  return { code: 0, outcome };
}
