/** Shared configuration for the integration tests. */

export const SKIP_INTEGRATION = process.env.MCC_SKIP_INTEGRATION === "1";

// Fixed loopback ports for the in-process MCC test stack (started by globalSetup).
export const GATEWAY_PORT = Number(process.env.MCC_TEST_GATEWAY_PORT ?? 8911);
export const QUORUM_PORT = Number(process.env.MCC_TEST_QUORUM_PORT ?? 8912);
export const NOTIFY_PORT = Number(process.env.MCC_TEST_NOTIFY_PORT ?? 8913);

export const GATEWAY_URL = `http://127.0.0.1:${GATEWAY_PORT}`;
export const QUORUM_URL = `http://127.0.0.1:${QUORUM_PORT}`;
export const API_KEY = "demo-key";
export const OPERATOR_KEY = "op-key";
/**
 * V05 (part 2): the per-agent credential `principal` presents on the gateway's
 * identity routes (POST /approvals, /approvals/{id}/execute, /mandates/execute).
 * API_KEY is the tenant's shared key and grants no agent identity there.
 * Mirrors agent_key() in mcc_side/testserver.py.
 */
export function agentKey(principal: string): string {
  return `${API_KEY}::agent::${principal}`;
}
export const REPO_ROOT = new URL("../../../", import.meta.url).pathname;
