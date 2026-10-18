/**
 * The REMORA execution client.
 *
 * This module is the only place that holds a credential for the execution
 * API, and it exposes exactly three operations: propose, look up, execute.
 * There is deliberately no method here that performs a side effect without
 * first going through assess, because a bypass that exists is a bypass that
 * will eventually be used.
 */

export type Decision = "accept" | "verify" | "abstain" | "escalate";

/** The request a call arrived in (remora/execution/request_ref.py). REMORA
 *  binds its digest into the ACCEPT grant, so the grant redeems only with the
 *  same reference, and an outside capture of the request can be matched to
 *  the exported record by id and body digest rather than by call content. */
export interface RequestRef {
  transport: "mcp-streamable-http";
  /** The JSON-RPC id's JSON text, so 7 and "7" stay distinct. */
  jsonrpc_id: string;
  /** Lowercase hex SHA-256 of the HTTP body bytes as received. */
  body_sha256: string;
}

export interface ToolCall {
  tool_name: string;
  arguments: Record<string, unknown>;
  target_environment: string;
  intent_ref?: string;
  request_ref?: RequestRef;
}

export interface AssessResult {
  decision: Decision;
  reasons: string[];
  review_item_id?: string;
  proposal_id?: string;
  tool_call_hash?: string;
  execution_token?: Record<string, unknown>;
  semantic?: Record<string, unknown>;
}

export interface ExecuteResult {
  outcome: string;
  tool_execution?: Record<string, unknown>;
  /** Error body from a non-200; carried only on the failure path. */
  detail?: unknown;
}

export class RemoraClient {
  constructor(
    private readonly fetcher: (req: Request) => Promise<Response>,
    private readonly token: string,
    private readonly base = "http://remora",
  ) {}

  private async call<T>(path: string, body: unknown): Promise<{ status: number; body: T }> {
    const res = await this.fetcher(
      new Request(`${this.base}${path}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.token}`,
        },
        body: JSON.stringify(body),
      }),
    );
    const text = await res.text();
    let parsed: unknown = {};
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { raw: text.slice(0, 400) };
      }
    }
    return { status: res.status, body: parsed as T };
  }

  /** Propose a call. Never performs the side effect. */
  assess(call: ToolCall) {
    return this.call<AssessResult>("/v1/execution/assess", call);
  }

  /**
   * Execute a call that has already been approved.
   *
   * The full payload is re-presented rather than referenced, so REMORA
   * re-verifies that what runs is what was approved. This is why the gateway
   * stores the original arguments instead of letting the agent supply them
   * again at execution time.
   */
  execute(itemId: string, call: ToolCall) {
    return this.call<ExecuteResult>("/v1/execution/execute", {
      item_id: itemId,
      tool_call: call,
    });
  }

  /** Redeem an ACCEPT token. The token was bound to the exact call at assess
   *  time, so no review item exists or is needed. */
  executeAccepted(token: Record<string, unknown>, call: ToolCall) {
    return this.call<ExecuteResult>("/v1/execution/execute-accepted", {
      execution_token: token,
      tool_call: call,
    });
  }
}
