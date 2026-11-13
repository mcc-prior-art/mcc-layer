/**
 * V05 (part 2): the ONE per-agent credential this agent process was given.
 *
 * Provisioning (gateway/agent_provisioning.py, run only in the trusted
 * provisioning boundary) writes each agent's credential into that agent's own
 * file -- in the Docker pilots a named volume mounted read-only into that
 * agent's container and no other. This module only READS it.
 *
 * Fail-closed rules:
 *  - a provisioning MAP (MCC_AGENT_API_KEYS) in the agent's environment is
 *    refused outright: an agent must never be handed other principals'
 *    credentials, even to filter them;
 *  - a missing/unreadable/malformed file, unknown or missing fields, or an
 *    empty/padded value is refused;
 *  - the agent's principal comes from the file; a separately configured actor
 *    that differs from it is refused (ambiguous identity).
 *
 * Without MCC_AGENT_CREDENTIAL_FILE the agent uses the tenant's shared key
 * (local development against the in-process test server only). The gateway
 * refuses that key on every identity route (/mandates/execute, /approvals,
 * /approvals/{id}/execute) in its default strict mode.
 */

import { readFileSync } from "node:fs";

export interface AgentCredential {
  tenantId: string;
  principalId: string;
  credentialId: string;
  apiKey: string;
}

const FIELDS = ["api_key", "credential_id", "principal_id", "tenant_id"] as const;

export class AgentCredentialError extends Error {}

export function parseAgentCredential(raw: string): AgentCredential {
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch {
    throw new AgentCredentialError("agent credential file is not valid JSON (fail-closed)");
  }
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
    throw new AgentCredentialError("agent credential file must be a JSON object (fail-closed)");
  }
  const rec = doc as Record<string, unknown>;
  const keys = Object.keys(rec).sort();
  if (keys.length !== FIELDS.length || keys.some((k, i) => k !== FIELDS[i])) {
    throw new AgentCredentialError(
      `agent credential file must contain exactly ${FIELDS.join(", ")} (fail-closed)`,
    );
  }
  for (const f of FIELDS) {
    const v = rec[f];
    if (typeof v !== "string" || v === "" || v !== v.trim()) {
      throw new AgentCredentialError(
        `agent credential field '${f}' is empty or malformed (fail-closed)`,
      );
    }
  }
  return {
    tenantId: rec.tenant_id as string,
    principalId: rec.principal_id as string,
    credentialId: rec.credential_id as string,
    apiKey: rec.api_key as string,
  };
}

/** The provisioned credential, or undefined when none is configured. */
export function loadAgentCredential(env: NodeJS.ProcessEnv): AgentCredential | undefined {
  if ((env.MCC_AGENT_API_KEYS ?? "").trim() !== "") {
    throw new AgentCredentialError(
      "MCC_AGENT_API_KEYS must never be given to an agent; provision one credential file " +
        "per agent (MCC_AGENT_CREDENTIAL_FILE) (fail-closed)",
    );
  }
  const path = (env.MCC_AGENT_CREDENTIAL_FILE ?? "").trim();
  if (path === "") return undefined;
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    throw new AgentCredentialError("cannot read MCC_AGENT_CREDENTIAL_FILE (fail-closed)");
  }
  return parseAgentCredential(raw);
}

/**
 * Resolve (actor, apiKey) for this process. With a provisioned credential the
 * actor IS its principal; a configured actor that differs is refused.
 */
export function resolveAgentIdentity(
  env: NodeJS.ProcessEnv,
  configuredActor: string | undefined,
  defaultActor: string,
): { actor: string; apiKey: string; provisioned: boolean } {
  const cred = loadAgentCredential(env);
  if (cred) {
    if (configuredActor !== undefined && configuredActor !== cred.principalId) {
      throw new AgentCredentialError(
        `configured actor '${configuredActor}' is not this agent's provisioned principal ` +
          `'${cred.principalId}' (fail-closed)`,
      );
    }
    return { actor: cred.principalId, apiKey: cred.apiKey, provisioned: true };
  }
  return {
    actor: configuredActor ?? defaultActor,
    apiKey: env.MCC_GATEWAY_API_KEY ?? "demo-key",
    provisioned: false,
  };
}
