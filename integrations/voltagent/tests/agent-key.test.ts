// V05 (part 2): the agent presents its OWN per-agent credential; a missing or
// malformed MCC_AGENT_API_KEYS entry fails closed (no shared-key fallback).
import { describe, expect, it } from "vitest";
import { agentApiKey, agentEnv } from "../src/agent.js";

describe("per-agent credential selection (offline)", () => {
  it("uses the acting principal's own key from MCC_AGENT_API_KEYS", () => {
    const env = {
      MCC_GATEWAY_API_KEY: "shared",
      MCC_AGENT_API_KEYS: JSON.stringify({ "agent/a": "key-a", "agent/b": "key-b" }),
    };
    expect(agentApiKey(env, "agent/a")).toBe("key-a");
    expect(agentApiKey(env, "agent/b")).toBe("key-b");
    expect(agentEnv({ ...env, MCC_VOLTAGENT_ACTOR: "agent/b" }).apiKey).toBe("key-b");
  });

  it("fails closed for a principal without a key (never the shared key)", () => {
    const env = { MCC_GATEWAY_API_KEY: "shared", MCC_AGENT_API_KEYS: '{"agent/a": "key-a"}' };
    expect(() => agentApiKey(env, "agent/b")).toThrow(/fail-closed/);
    expect(() => agentApiKey({ ...env, MCC_AGENT_API_KEYS: '{"agent/b": ""}' }, "agent/b")).toThrow(
      /fail-closed/,
    );
  });

  it("fails closed on malformed MCC_AGENT_API_KEYS", () => {
    expect(() => agentApiKey({ MCC_AGENT_API_KEYS: "not-json" }, "agent/a")).toThrow(/fail-closed/);
    expect(() => agentApiKey({ MCC_AGENT_API_KEYS: "null" }, "agent/a")).toThrow(/fail-closed/);
  });

  it("without MCC_AGENT_API_KEYS falls back to MCC_GATEWAY_API_KEY (gateway refuses it on identity routes)", () => {
    expect(agentApiKey({ MCC_GATEWAY_API_KEY: "shared" }, "agent/a")).toBe("shared");
  });
});
