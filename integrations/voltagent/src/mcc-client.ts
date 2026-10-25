/**
 * The MCC-Core client for the VoltAgent integration.
 *
 * This is the ONLY outward channel the integration has, and it speaks exactly the
 * framework-neutral gateway HTTP contract introduced by PR #35:
 *
 *   evaluate            POST /evaluate                 -> verdict + authoritative body
 *   consensus challenge POST /consensus/challenge      -> gateway-issued one-time nonce
 *   consensus votes     POST {quorum}/vote             -> N independent evaluator votes
 *   consensus execute   POST /consensus/execute        -> governed execution
 *   approvals           POST /approvals[/id/(approve|execute)]
 *   audit               GET  /verify
 *
 * It holds URLs for the gateway and the independent evaluator quorum ONLY. It has
 * NO client for, and no URL of, the external notification service — the governed
 * executor inside the gateway is the only thing that ever calls it. There is no
 * `send()` / `notify()` / direct-execute method here by construction.
 *
 * Fail-closed: a transport failure during a POST that may already have executed
 * is surfaced as an ambiguous-execution error and NEVER treated as success; a
 * non-executed status is never downgraded to EXECUTED.
 */

export type Verdict = "ALLOW" | "DENY" | "ESCALATE" | "CONSTRAIN";

export interface Decision {
  verdict: Verdict;
  reason: string;
  auditId: string;
  actor: string;
  action: string;
  resource: string;
  /** The body the verdict authorizes: original for ALLOW, clamped for CONSTRAIN. */
  forwardContext: Record<string, unknown>;
  appliedConstraints: string[];
  correlationId: string;
  raw: Record<string, unknown>;
}

export interface ReceiptSummary {
  receiptVerified: unknown;
  upstreamStatus: unknown;
  received: unknown;
  correlationId: unknown;
  payloadSha256: unknown;
}

export type ExecutionStatus = "EXECUTED" | "BLOCKED" | "PENDING_APPROVAL" | "ERROR";

export interface GovernedOutcome {
  verdict: Verdict | "NONE";
  status: ExecutionStatus;
  executed: boolean;
  reason: string;
  correlationId: string;
  appliedConstraints: string[];
  finalPayload?: Record<string, unknown>;
  receipt?: ReceiptSummary;
  auditRef?: string;
  approvalRequestId?: string;
  approvalStatus?: string;
  error?: string;
}

export class MccError extends Error {}
export class MccTransportError extends MccError {}
export class MccDeniedError extends MccError {}
export class MccExecutionError extends MccError {}
/** A POST may or may not have executed; the outcome is unknown — never success. */
export class MccAmbiguousExecutionError extends MccError {}

export interface MccClientOptions {
  gatewayUrl: string;
  quorumUrl: string;
  apiKey: string;
  /** Operator key. Only an OPERATOR holds this — never the agent's tool client. */
  operatorKey?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

const CORRELATION_HEADER = "X-MCC-Correlation-Id";
const REPLAY_MARKERS = ["replay", "already consumed", "already used", "nonce", "consumed"];

interface ExecOutcome {
  status: string;
  reason: string;
  execution?: Record<string, unknown>;
  auditRef?: string;
  raw: Record<string, unknown>;
}

export class MccClient {
  private readonly gatewayUrl: string;
  private readonly quorumUrl: string;
  private readonly apiKey: string;
  private readonly operatorKey?: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: MccClientOptions) {
    this.gatewayUrl = opts.gatewayUrl.replace(/\/$/, "");
    this.quorumUrl = opts.quorumUrl.replace(/\/$/, "");
    this.apiKey = opts.apiKey;
    this.operatorKey = opts.operatorKey;
    this.timeoutMs = opts.timeoutMs ?? 15000;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  // ---- low-level HTTP (correlation id propagated on every request) --------- //

  private headers(correlationId: string, operator: boolean): Record<string, string> {
    const h: Record<string, string> = {
      "content-type": "application/json",
      "x-api-key": this.apiKey,
      [CORRELATION_HEADER]: correlationId,
    };
    if (operator) {
      if (!this.operatorKey) {
        throw new MccError(
          "operator action requires an operator key; none configured (fail-closed)",
        );
      }
      h["x-operator-key"] = this.operatorKey;
    }
    return h;
  }

  private async request(
    url: string,
    method: "GET" | "POST",
    correlationId: string,
    body?: unknown,
    operator = false,
  ): Promise<Record<string, unknown>> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let resp: Response;
    try {
      resp = await this.fetchImpl(url, {
        method,
        headers: this.headers(correlationId, operator),
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (err) {
      throw new MccTransportError(`transport failure calling ${method} ${url}: ${String(err)}`);
    } finally {
      clearTimeout(timer);
    }
    if (resp.status === 401) {
      throw new MccError(`unauthorized calling ${method} ${url}`);
    }
    let data: Record<string, unknown>;
    try {
      data = (await resp.json()) as Record<string, unknown>;
    } catch {
      throw new MccTransportError(`non-JSON response (HTTP ${resp.status}) from ${url}`);
    }
    if (resp.status >= 500) {
      throw new MccTransportError(`server error (HTTP ${resp.status}) from ${url}`);
    }
    return data;
  }

  // ---- 1. evaluate --------------------------------------------------------- //

  async evaluate(
    proposal: { actor: string; action: string; resource: string; context: Record<string, unknown> },
    correlationId: string,
  ): Promise<Decision> {
    const data = await this.request(`${this.gatewayUrl}/evaluate`, "POST", correlationId, {
      identity: proposal.actor,
      actor_id: proposal.actor,
      action: proposal.action,
      resource_id: proposal.resource,
      context: proposal.context,
    });
    return {
      verdict: String(data.decision) as Verdict,
      reason: String(data.reason ?? ""),
      auditId: String(data.audit_id ?? ""),
      actor: String(data.actor_id ?? proposal.actor),
      action: proposal.action,
      resource: String(data.resource_id ?? proposal.resource),
      forwardContext: (data.forward_context as Record<string, unknown>) ?? {},
      appliedConstraints: (data.applied_constraints as string[]) ?? [],
      correlationId,
      raw: data,
    };
  }

  // ---- 2. consensus material (challenge + independent quorum votes) --------- //

  private async issueChallenge(
    decision: Decision,
    correlationId: string,
  ): Promise<{ challengeId: string; nonce: string }> {
    const data = await this.request(
      `${this.gatewayUrl}/consensus/challenge`,
      "POST",
      correlationId,
      {
        actor: decision.actor,
        action: decision.action,
        resource: decision.resource,
        context: decision.forwardContext,
      },
    );
    return { challengeId: String(data.challenge_id), nonce: String(data.nonce) };
  }

  private async collectVotes(
    decision: Decision,
    nonce: string,
    correlationId: string,
  ): Promise<unknown[]> {
    // The quorum independently re-evaluates against the gateway and signs votes
    // over the gateway's authoritative payload. We pass the ORIGINAL proposal
    // context (from the raw evaluate) so the quorum derives the same authoritative
    // (clamped) body the coordinator will.
    const originalContext =
      (decision.raw.context as Record<string, unknown>) ?? decision.forwardContext;
    const data = await this.request(`${this.quorumUrl}/vote`, "POST", correlationId, {
      actor: decision.actor,
      action: decision.action,
      resource: decision.resource,
      context: originalContext,
      nonce,
    });
    return (data.votes as unknown[]) ?? [];
  }

  // ---- 3. governed execution (the only side effect) ------------------------ //

  private toOutcome(data: Record<string, unknown>): ExecOutcome {
    const status = data.status;
    if (typeof status !== "string" || status.length === 0) {
      throw new MccAmbiguousExecutionError(
        "governed execution response has no status; outcome unknown",
      );
    }
    return {
      status,
      reason: String(data.reason ?? ""),
      execution: data.execution as Record<string, unknown> | undefined,
      auditRef: data.audit_ref as string | undefined,
      raw: data,
    };
  }

  private async postExecute(
    path: string,
    body: Record<string, unknown>,
    correlationId: string,
    operator = false,
  ): Promise<ExecOutcome> {
    let data: Record<string, unknown>;
    try {
      data = await this.request(`${this.gatewayUrl}${path}`, "POST", correlationId, body, operator);
    } catch (err) {
      if (err instanceof MccTransportError) {
        // A POST that may already have executed: outcome is unknown, never success.
        throw new MccAmbiguousExecutionError(
          `governed execution outcome unknown (${String(err)}); do not assume success`,
        );
      }
      throw err;
    }
    return this.toOutcome(data);
  }

  private async consensusExecute(
    decision: Decision,
    correlationId: string,
    idempotencyKey?: string,
  ): Promise<ExecOutcome> {
    const challenge = await this.issueChallenge(decision, correlationId);
    const votes = await this.collectVotes(decision, challenge.nonce, correlationId);
    const body: Record<string, unknown> = {
      votes,
      actor: decision.actor,
      action: decision.action,
      resource: decision.resource,
      context: decision.forwardContext,
      nonce: challenge.nonce,
      challenge_id: challenge.challengeId,
    };
    if (idempotencyKey) body.idempotency_key = idempotencyKey;
    return this.postExecute("/consensus/execute", body, correlationId);
  }

  // ---- 4. approvals (ESCALATE) --------------------------------------------- //

  async requestApproval(
    decision: Decision,
    correlationId: string,
    payload: Record<string, unknown>,
  ): Promise<{ requestId: string; state: string }> {
    // ``payload`` must be the ORIGINAL proposed content (the caller's own
    // ``proposal.context``), never ``decision.forwardContext`` -- for an
    // ESCALATE verdict no authority has rewritten/authorized a forward
    // context yet, so the gateway's /evaluate response leaves it `{}` (see
    // src/mcc_core/authority.py: only ALLOW/CONSTRAIN populate it). The
    // gateway now always derives its payload binding from this field
    // server-side (never from a caller-supplied hash), so sending `{}` here
    // would bind the approval to an empty payload and fail-closed reject
    // the real, non-empty operation at execute() time.
    // See src/mcc_core/approvals.py.
    const data = await this.request(`${this.gatewayUrl}/approvals`, "POST", correlationId, {
      actor: decision.actor,
      action: decision.action,
      resource: decision.resource,
      payload,
    });
    return { requestId: String(data.request_id), state: String(data.state ?? "") };
  }

  /** OPERATOR action (requires the operator key). Never called by the agent tool. */
  async approveAsOperator(
    requestId: string,
    correlationId: string,
  ): Promise<{ requestId: string; state: string; mandate: Record<string, unknown> }> {
    const data = await this.request(
      `${this.gatewayUrl}/approvals/${requestId}/approve`,
      "POST",
      correlationId,
      {},
      true,
    );
    return {
      requestId: String(data.request_id ?? requestId),
      state: String(data.state ?? ""),
      mandate: (data.mandate as Record<string, unknown>) ?? {},
    };
  }

  private async executeWithApproval(
    decision: Decision,
    requestId: string,
    mandate: Record<string, unknown>,
    correlationId: string,
    idempotencyKey?: string,
  ): Promise<ExecOutcome> {
    const body: Record<string, unknown> = {
      mandate,
      actor: decision.actor,
      action: decision.action,
      resource: decision.resource,
      context: decision.forwardContext,
    };
    if (idempotencyKey) body.idempotency_key = idempotencyKey;
    return this.postExecute(`/approvals/${requestId}/execute`, body, correlationId);
  }

  // ---- readiness (a reachable process is not ready) ------------------------ //

  /** True only when BOTH the gateway and the quorum report ready (HTTP 200). */
  async ready(): Promise<boolean> {
    for (const base of [this.gatewayUrl, this.quorumUrl]) {
      try {
        const r = await this.fetchImpl(`${base}/ready`, { method: "GET" });
        if (!r.ok) return false;
      } catch {
        return false;
      }
    }
    return true;
  }

  /** Poll until ready or throw after timeout. The agent must not submit before. */
  async waitUntilReady(timeoutMs = 90_000, intervalMs = 1500): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (await this.ready()) return;
      await new Promise((r) => setTimeout(r, intervalMs));
    }
    throw new MccError("MCC dependencies (gateway + quorum) did not become ready in time");
  }

  // ---- 5. audit ------------------------------------------------------------ //

  async verifyAudit(
    correlationId: string,
  ): Promise<{ valid: boolean; raw: Record<string, unknown> }> {
    const data = await this.request(`${this.gatewayUrl}/verify`, "GET", correlationId);
    return { valid: data.valid === true, raw: data };
  }

  // ---- Universal Proposal Service (Phase 1) — additive, non-actuating ------ //
  //
  // Pure translation onto POST /v1/proposals and GET /v1/operations/{id}
  // (gateway/proposal_api.py). Neither method here computes a binding,
  // evaluates policy, infers status, or executes anything -- that is all
  // MCCProposalService, reached identically by every other adapter. A
  // proposal here is never permission: it never touches /evaluate,
  // /consensus/execute, or /approvals/*.

  async submitProposal(
    proposal: {
      logicalOperationId: string;
      actor: string;
      action: string;
      resource?: string | null;
      payload?: Record<string, unknown>;
    },
    correlationId: string,
  ): Promise<Record<string, unknown>> {
    return this.request(`${this.gatewayUrl}/v1/proposals`, "POST", correlationId, {
      logical_operation_id: proposal.logicalOperationId,
      actor: proposal.actor,
      action: proposal.action,
      resource: proposal.resource ?? null,
      payload: proposal.payload ?? {},
    });
  }

  async getOperationStatus(
    logicalOperationId: string,
    correlationId: string,
  ): Promise<Record<string, unknown>> {
    return this.request(
      `${this.gatewayUrl}/v1/operations/${encodeURIComponent(logicalOperationId)}`,
      "GET",
      correlationId,
    );
  }

  // ---- orchestration returned to the governed tool ------------------------- //

  /**
   * Governed execution for any action domain (e.g. the AXFlow clinic actions).
   * The governed path is action-agnostic — the action comes from
   * ``proposal.action`` — so this is a thin, readable alias of
   * :meth:`governNotification` for non-notification business actions.
   */
  async governAction(
    proposal: { actor: string; action: string; resource: string; context: Record<string, unknown> },
    correlationId: string,
    opts: { idempotencyKey?: string } = {},
  ): Promise<GovernedOutcome> {
    return this.governNotification(proposal, correlationId, opts);
  }

  /**
   * Submit a proposal and drive the governed path to a terminal outcome:
   *  - DENY      -> BLOCKED (no execution, service never called);
   *  - ALLOW     -> governed consensus execution -> EXECUTED iff receipt verified;
   *  - CONSTRAIN -> governed execution of the CLAMPED payload only -> EXECUTED;
   *  - ESCALATE  -> PENDING_APPROVAL (no execution before a valid operator approval).
   */
  async governNotification(
    proposal: { actor: string; action: string; resource: string; context: Record<string, unknown> },
    correlationId: string,
    opts: { idempotencyKey?: string } = {},
  ): Promise<GovernedOutcome> {
    let decision: Decision;
    try {
      decision = await this.evaluate(proposal, correlationId);
    } catch (err) {
      return this.errorOutcome(correlationId, `governance evaluation failed: ${String(err)}`);
    }

    if (decision.verdict === "DENY") {
      return {
        verdict: "DENY",
        status: "BLOCKED",
        executed: false,
        reason: decision.reason || "governance denied the action",
        correlationId,
        appliedConstraints: decision.appliedConstraints,
      };
    }

    if (decision.verdict === "ESCALATE") {
      let approval: { requestId: string; state: string };
      try {
        approval = await this.requestApproval(decision, correlationId, proposal.context);
      } catch (err) {
        return this.errorOutcome(correlationId, `could not open approval request: ${String(err)}`);
      }
      return {
        verdict: "ESCALATE",
        status: "PENDING_APPROVAL",
        executed: false,
        reason: decision.reason || "human approval required before execution",
        correlationId,
        appliedConstraints: decision.appliedConstraints,
        // Surface the ORIGINAL proposed payload so an operator can continue the
        // exact same action after approval (nothing is mutated in between).
        finalPayload: { ...proposal.context },
        approvalRequestId: approval.requestId,
      };
    }

    // ALLOW / CONSTRAIN -> governed consensus execution. Anything else (an
    // unexpected/unknown verdict) fails closed: we never attempt execution for a
    // verdict we do not explicitly recognise as executable.
    if (decision.verdict === "ALLOW" || decision.verdict === "CONSTRAIN") {
      // Round 25: EnforcementCoordinator now fails closed without a stable
      // logical-operation identity. Default to the operation's own
      // correlationId (already unique per proposal) when a caller doesn't
      // supply its own -- never synthesized at the gateway/coordinator.
      const idempotencyKey = opts.idempotencyKey ?? correlationId;
      return this.finishExecution(
        decision,
        () => this.consensusExecute(decision, correlationId, idempotencyKey),
        correlationId,
      );
    }
    return {
      verdict: decision.verdict,
      status: "BLOCKED",
      executed: false,
      reason: decision.reason || `unrecognised verdict '${decision.verdict}'; refusing to execute`,
      correlationId,
      appliedConstraints: decision.appliedConstraints,
      error: "fail-closed: unknown verdict",
    };
  }

  /**
   * Continue an ESCALATE after an operator has granted the approval mandate.
   * Submits the ORIGINAL proposed payload; the gateway re-evaluates it under the
   * single-use mandate (clamping server-side if needed). The agent's tool never
   * calls this — only a holder of the granted mandate can.
   */
  async executeApprovedNotification(
    proposal: { actor: string; action: string; resource: string; context: Record<string, unknown> },
    requestId: string,
    mandate: Record<string, unknown>,
    correlationId: string,
    opts: { idempotencyKey?: string } = {},
  ): Promise<GovernedOutcome> {
    const decision: Decision = {
      verdict: "ESCALATE",
      reason: "",
      auditId: "",
      actor: proposal.actor,
      action: proposal.action,
      resource: proposal.resource,
      forwardContext: proposal.context,
      appliedConstraints: [],
      correlationId,
      raw: { context: proposal.context },
    };
    // Round 25: default the logical-operation identity to correlationId when
    // the caller doesn't supply its own (never synthesized at the gateway).
    const idempotencyKey = opts.idempotencyKey ?? correlationId;
    return this.finishExecution(
      decision,
      () => this.executeWithApproval(decision, requestId, mandate, correlationId, idempotencyKey),
      correlationId,
      "APPROVED",
    );
  }

  private async finishExecution(
    decision: Decision,
    run: () => Promise<ExecOutcome>,
    correlationId: string,
    approvalStatus?: string,
  ): Promise<GovernedOutcome> {
    let outcome: ExecOutcome;
    try {
      outcome = await run();
    } catch (err) {
      const msg = String(err);
      const status: ExecutionStatus =
        err instanceof MccAmbiguousExecutionError ? "ERROR" : "BLOCKED";
      return {
        verdict: decision.verdict,
        status,
        executed: false,
        reason: decision.reason,
        correlationId,
        appliedConstraints: decision.appliedConstraints,
        finalPayload: decision.forwardContext,
        error: msg,
        approvalStatus,
      };
    }

    if (outcome.status !== "EXECUTED") {
      const reasonL = outcome.reason.toLowerCase();
      const replay = REPLAY_MARKERS.some((m) => reasonL.includes(m));
      return {
        verdict: decision.verdict,
        status: "BLOCKED",
        executed: false,
        reason: outcome.reason || `execution not completed (${outcome.status})`,
        correlationId,
        appliedConstraints: decision.appliedConstraints,
        finalPayload: decision.forwardContext,
        auditRef: outcome.auditRef,
        approvalStatus,
        error: replay ? "replay/duplicate rejected" : undefined,
      };
    }

    let auditValid: boolean | undefined;
    try {
      auditValid = (await this.verifyAudit(correlationId)).valid;
    } catch {
      auditValid = undefined;
    }
    return {
      verdict: decision.verdict,
      status: "EXECUTED",
      executed: true,
      reason: decision.reason || "authorized",
      correlationId,
      appliedConstraints: decision.appliedConstraints,
      finalPayload: decision.forwardContext,
      receipt: receiptSummary(outcome.execution),
      auditRef: outcome.auditRef ?? (auditValid ? "audit-verified" : undefined),
      approvalStatus,
    };
  }

  private errorOutcome(correlationId: string, message: string): GovernedOutcome {
    return {
      verdict: "NONE",
      status: "ERROR",
      executed: false,
      reason: "governance unavailable",
      correlationId,
      appliedConstraints: [],
      error: message,
    };
  }
}

/** A safe, non-sensitive summary of the governed executor's receipt. */
export function receiptSummary(
  execution: Record<string, unknown> | undefined,
): ReceiptSummary | undefined {
  if (!execution || typeof execution !== "object") return undefined;
  const body = (execution.body as Record<string, unknown>) ?? execution;
  return {
    receiptVerified: execution.receipt_verified,
    upstreamStatus: execution.upstream_status,
    received: body.received,
    correlationId: body.correlation_id,
    payloadSha256: body.payload_sha256,
  };
}
