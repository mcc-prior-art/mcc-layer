/**
 * The AXFlow clinic agent: the business agent wired to the governed clinic tool.
 *
 * AXFlow is the business/domain agent (revenue + booking). VoltAgent is the
 * framework integration layer. MCC-Core is the execution governance authority.
 * The agent classifies patient intent and proposes structured clinic actions; it
 * holds no operator key and no route to the clinic service, and everything flows
 * agent -> MCC SDK -> gateway -> governed executor -> mock clinic service.
 */

import { Agent } from "@voltagent/core";
import { resolveAgentIdentity } from "./agent-credential.js";
import { createClinicModel } from "./clinic-model.js";
import type { ClinicIdentity } from "./clinic-schemas.js";
import type { GovernedOutcome } from "./mcc-client.js";
import { MccClient } from "./mcc-client.js";
import { resolveModel } from "./model.js";
import { createGovernedClinicTool } from "./tools/clinic-action.js";

const INSTRUCTIONS =
  "You are AXFlow, a clinic revenue and booking assistant. Interpret the patient's " +
  "request and call propose_clinic_action with exactly ONE structured clinic action " +
  "— it is your only capability. You cannot book, message, discount, change " +
  "priority, refund, or take any action except through that tool, and MCC-Core " +
  "governs every action. NEVER give medical advice, diagnosis, or prescriptions: " +
  "for such requests propose action_type=medical_advice_request so MCC-Core can deny " +
  "it. Report the governed outcome honestly (ALLOW / DENY / CONSTRAIN / ESCALATE); " +
  "you cannot override MCC-Core or reach the clinic service any other way.";

export interface ClinicAgentConfig {
  client: MccClient;
  identity: ClinicIdentity;
  model: unknown;
  name?: string;
  onOutcome?: (outcome: GovernedOutcome) => void;
}

export function createClinicAgent(config: ClinicAgentConfig): Agent {
  const tool = createGovernedClinicTool({
    client: config.client,
    identity: config.identity,
    onOutcome: config.onOutcome,
  });
  return new Agent({
    name: config.name ?? "axflow-clinic-agent",
    purpose: "Convert patient leads and propose clinic actions, only ever through MCC-Core.",
    instructions: INSTRUCTIONS,
    model: config.model as never,
    tools: [tool],
  });
}

export interface ClinicAgentEnv {
  gatewayUrl: string;
  quorumUrl: string;
  apiKey: string;
  identity: ClinicIdentity;
}

export function clinicAgentEnv(env: NodeJS.ProcessEnv = process.env): ClinicAgentEnv {
  // V05 (part 2): the clinic agent's OWN provisioned credential (agent-credential.ts).
  const { actor, apiKey } = resolveAgentIdentity(env, env.MCC_CLINIC_ACTOR, "agent/axflow-clinic");
  return {
    gatewayUrl: env.MCC_GATEWAY_URL ?? "http://mcc-gateway:8001",
    quorumUrl: env.MCC_QUORUM_URL ?? "http://evaluator-quorum:8080",
    apiKey,
    identity: {
      actor,
      clinicId: env.MCC_CLINIC_ID ?? "clinic-1",
    },
  };
}

/**
 * Build a ready-to-run clinic agent + its (operator-less) client from the
 * environment. Uses the deterministic offline clinic classifier unless a real
 * model provider is configured (governance is independent of the model).
 */
export async function buildClinicAgentFromEnv(
  env: NodeJS.ProcessEnv = process.env,
  onOutcome?: (outcome: GovernedOutcome) => void,
): Promise<{ agent: Agent; client: MccClient; identity: ClinicIdentity; provider: string }> {
  const cfg = clinicAgentEnv(env);
  const client = new MccClient({
    gatewayUrl: cfg.gatewayUrl,
    quorumUrl: cfg.quorumUrl,
    apiKey: cfg.apiKey,
    // NOTE: no operatorKey — the agent process is never an approver.
  });
  const providerName = (env.MCC_VOLTAGENT_MODEL_PROVIDER ?? "deterministic").trim().toLowerCase();
  let model: unknown;
  let provider: string;
  if (providerName === "deterministic") {
    model = createClinicModel();
    provider = "deterministic";
  } else {
    ({ model, provider } = await resolveModel(env));
  }
  const agent = createClinicAgent({ client, identity: cfg.identity, model, onOutcome });
  return { agent, client, identity: cfg.identity, provider };
}
