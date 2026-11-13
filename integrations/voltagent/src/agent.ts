/**
 * The VoltAgent agent wired to the governed notification tool.
 *
 * VoltAgent owns reasoning, instruction-following, and tool selection. It is
 * given exactly one tool — the governed notification tool — and no direct
 * execution capability. Its client is constructed WITHOUT an operator key, so the
 * agent can never approve its own escalations.
 *
 *   VoltAgent proposes. MCC-Core decides. The gate enforces. The governed
 *   executor acts. The external receipt proves execution. The audit chain records.
 */

import { Agent } from "@voltagent/core";
import { MccClient } from "./mcc-client.js";
import type { GovernedOutcome } from "./mcc-client.js";
import { resolveModel } from "./model.js";
import type { ProposalIdentity } from "./schemas.js";
import { createGovernedNotificationTool } from "./tools/governed-notification.js";

const INSTRUCTIONS =
  "You help users send customer notifications. To send anything you MUST call the " +
  "propose_governed_notification tool — it is your only capability. Never claim a " +
  "notification was delivered unless the tool result's status is EXECUTED. If the " +
  "result is DENY, BLOCKED, or PENDING_APPROVAL, report that honestly; you cannot " +
  "override MCC-Core, retry around it, or send by any other means.";

export interface GovernedAgentConfig {
  client: MccClient;
  identity: ProposalIdentity;
  model: unknown;
  name?: string;
  onOutcome?: (outcome: GovernedOutcome) => void;
}

export function createGovernedAgent(config: GovernedAgentConfig): Agent {
  const tool = createGovernedNotificationTool({
    client: config.client,
    identity: config.identity,
    onOutcome: config.onOutcome,
  });
  return new Agent({
    name: config.name ?? "voltagent-governed-notifier",
    purpose: "Send customer notifications, but only ever through MCC-Core governance.",
    instructions: INSTRUCTIONS,
    // The concrete model type comes from the AI SDK provider (or the deterministic
    // mock); VoltAgent accepts any AI SDK LanguageModel here.
    model: config.model as never,
    tools: [tool],
  });
}

export interface AgentIdentityEnv {
  gatewayUrl: string;
  quorumUrl: string;
  apiKey: string;
  identity: ProposalIdentity;
}

/**
 * V05 (part 2): the credential the agent acting as `actor` presents. When
 * MCC_AGENT_API_KEYS (JSON {principal: key}) is set, each principal uses its
 * OWN registered key and a missing/malformed entry fails closed here. Unset:
 * the shared MCC_GATEWAY_API_KEY, which the gateway refuses on its identity
 * routes (/approvals, /approvals/{id}/execute, /mandates/execute) in strict mode.
 */
export function agentApiKey(env: NodeJS.ProcessEnv, actor: string): string {
  const raw = env.MCC_AGENT_API_KEYS;
  if (raw === undefined || raw.trim() === "") return env.MCC_GATEWAY_API_KEY ?? "demo-key";
  let keys: unknown;
  try {
    keys = JSON.parse(raw);
  } catch {
    throw new Error("MCC_AGENT_API_KEYS is not valid JSON (fail-closed)");
  }
  const key =
    keys !== null && typeof keys === "object"
      ? (keys as Record<string, unknown>)[actor]
      : undefined;
  if (typeof key !== "string" || key === "") {
    throw new Error(`no per-agent credential for ${actor} in MCC_AGENT_API_KEYS (fail-closed)`);
  }
  return key;
}

/** Read the agent's (non-operator) MCC configuration from the environment. */
export function agentEnv(env: NodeJS.ProcessEnv = process.env): AgentIdentityEnv {
  const actor = env.MCC_VOLTAGENT_ACTOR ?? "agent/notify-bot";
  return {
    gatewayUrl: env.MCC_GATEWAY_URL ?? "http://mcc-gateway:8001",
    quorumUrl: env.MCC_QUORUM_URL ?? "http://mcc-evaluator-quorum:8080",
    apiKey: agentApiKey(env, actor),
    identity: {
      actor,
      resource: env.MCC_VOLTAGENT_RESOURCE ?? "crm",
    },
  };
}

/**
 * Build a ready-to-run agent + its (operator-less) client from the environment.
 * The returned client deliberately has no operator key — the agent cannot approve.
 */
export async function buildGovernedAgentFromEnv(
  env: NodeJS.ProcessEnv = process.env,
  onOutcome?: (outcome: GovernedOutcome) => void,
): Promise<{ agent: Agent; client: MccClient; identity: ProposalIdentity; provider: string }> {
  const cfg = agentEnv(env);
  const client = new MccClient({
    gatewayUrl: cfg.gatewayUrl,
    quorumUrl: cfg.quorumUrl,
    apiKey: cfg.apiKey,
    // NOTE: no operatorKey — the agent process is never an approver.
  });
  const { model, provider } = await resolveModel(env);
  const agent = createGovernedAgent({ client, identity: cfg.identity, model, onOutcome });
  return { agent, client, identity: cfg.identity, provider };
}
