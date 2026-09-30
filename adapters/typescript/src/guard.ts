import { shouldDispatch, type Approver, type ProvioClient } from "./client.js";
import { ProvioBlockedError, ProvioError } from "./errors.js";
import { fromRedacted, outputText } from "./output.js";
import type { CallerIdentity, ServerIdentity, ToolCallInput, TrustVerdict } from "./protocol.js";

export interface GuardOptions<A extends unknown[]> {
  client: ProvioClient;
  /** Tool name as provio policies see it, e.g. `bash`, `fs.read`, `postgres.query`. */
  tool: string;
  /**
   * Build the policy-visible `args` from the call's parameters. Default: the
   * first parameter when it is a plain object, else `{ args: [...params] }`.
   * Never include credentials.
   */
  args?: (...params: A) => Record<string, unknown>;
  /** Stable id for this call (default: provio generates one). */
  callId?: (...params: A) => string | undefined;
  /** Default: the client's session id. */
  sessionId?: string;
  caller?: CallerIdentity;
  server?: ServerIdentity | null;
  trust?: TrustVerdict | null;
  /** Decides deferred asks (client with `ask: "defer"`). Default: reject. */
  approver?: Approver;
  approvalTimeoutMs?: number;
}

function defaultArgs(params: unknown[]): Record<string, unknown> {
  const first = params[0];
  if (params.length === 1 && typeof first === "object" && first !== null && !Array.isArray(first)) {
    return { ...(first as Record<string, unknown>) };
  }
  return { args: params };
}

/**
 * Wrap a tool function so every invocation is decided by provio first and its
 * execution recorded afterwards.
 *
 * - deny, rejected or unresolved ask: throws `ProvioBlockedError`; `fn` never runs.
 * - any gateway failure before dispatch: throws `ProvioError`; `fn` never runs.
 * - redact: returns provio's redacted output instead of the raw result.
 * - `complete` failure after `fn` ran: throws `ProvioError` (the result is withheld).
 */
export function guard<A extends unknown[], R>(
  fn: (...params: A) => R | Promise<R>,
  options: GuardOptions<A>,
): (...params: A) => Promise<Awaited<R>> {
  const { client, tool } = options;
  return async (...params: A): Promise<Awaited<R>> => {
    const call: ToolCallInput = {
      session_id: options.sessionId ?? client.sessionId,
      tool,
      args: options.args ? options.args(...params) : defaultArgs(params),
    };
    const callId = options.callId?.(...params);
    if (callId !== undefined) call.call_id = callId;
    if (options.caller !== undefined) call.caller = options.caller;
    if (options.server !== undefined) call.server = options.server;
    if (options.trust !== undefined) call.trust = options.trust;

    const authorizeOptions = {
      ...(options.approver !== undefined ? { approver: options.approver } : {}),
      ...(options.approvalTimeoutMs !== undefined ? { approvalTimeoutMs: options.approvalTimeoutMs } : {}),
    };
    const decision = await client.authorize(call, authorizeOptions);
    if (!shouldDispatch(decision)) throw new ProvioBlockedError(decision, tool);
    const ref = decision.ref;
    if (ref === undefined) throw new ProvioError("protocol", "dispatching decision is missing ref");

    let result: Awaited<R>;
    try {
      result = await fn(...params);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      await client.complete(ref, { ok: false, output: message }).catch(() => undefined);
      throw err;
    }

    const text = outputText(result);
    const recorded = await client.complete(ref, text === undefined ? { ok: true } : { ok: true, output: text });
    if (decision.decision === "redact") {
      if (text === undefined) return result;
      if (recorded.output === undefined) {
        throw new ProvioError("redaction_missing", `provio: redact verdict for '${tool}' but no redacted output was returned; result withheld`);
      }
      return fromRedacted(recorded.output, result) as Awaited<R>;
    }
    return result;
  };
}

/** A `{ description, parameters, execute }` tool object (Vercel AI SDK and similar). */
export interface ExecutableTool {
  execute?: (...params: never[]) => unknown;
  [key: string]: unknown;
}

export interface GuardToolsOptions {
  client: ProvioClient;
  /** Map a tool key to the provio tool name (default: the key itself). */
  toolName?: (key: string) => string;
  /** Build policy-visible args from the tool's first parameter (default: the parameter itself). */
  args?: (key: string, input: unknown) => Record<string, unknown>;
  sessionId?: string;
  caller?: CallerIdentity;
  approver?: Approver;
  approvalTimeoutMs?: number;
}

/**
 * Wrap the `execute` of every tool in a record of tool objects (for example
 * Vercel AI SDK `tools`). Tools without `execute` are returned unchanged.
 * Extra `execute` parameters (e.g. the AI SDK's `{ toolCallId }`) are passed
 * through, and `toolCallId` becomes provio's `call_id` when present.
 */
export function guardTools<T extends Record<string, ExecutableTool>>(tools: T, options: GuardToolsOptions): T {
  const out: Record<string, ExecutableTool> = {};
  for (const [key, tool] of Object.entries(tools)) {
    const execute = tool.execute as ((...params: unknown[]) => unknown) | undefined;
    if (typeof execute !== "function") {
      out[key] = tool;
      continue;
    }
    const wrapped = guard((...params: unknown[]) => execute.apply(tool, params), {
      client: options.client,
      tool: options.toolName ? options.toolName(key) : key,
      args: (...params: unknown[]) => {
        const input = params[0];
        if (options.args) return options.args(key, input);
        return typeof input === "object" && input !== null && !Array.isArray(input)
          ? { ...(input as Record<string, unknown>) }
          : { input };
      },
      callId: (...params: unknown[]) => {
        const ctx = params[1];
        if (typeof ctx === "object" && ctx !== null && typeof (ctx as { toolCallId?: unknown }).toolCallId === "string") {
          return (ctx as { toolCallId: string }).toolCallId;
        }
        return undefined;
      },
      ...(options.sessionId !== undefined ? { sessionId: options.sessionId } : {}),
      ...(options.caller !== undefined ? { caller: options.caller } : {}),
      ...(options.approver !== undefined ? { approver: options.approver } : {}),
      ...(options.approvalTimeoutMs !== undefined ? { approvalTimeoutMs: options.approvalTimeoutMs } : {}),
    });
    out[key] = { ...tool, execute: wrapped };
  }
  return out as T;
}
