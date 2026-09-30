/**
 * Wire types for the provio hook gateway (`provio check --stdio`), protocol v1.
 * Source of truth: docs/INTERFACES.md, Contract 6 (and Contract 1 for the
 * `call` envelope). Additive-only: unknown response fields are ignored.
 */

export const PROTOCOL_VERSION = 1 as const;

/** Who is making the call (Contract 1 `CallerIdentity`). */
export interface CallerIdentity {
  agent: string;
  agent_version?: string | null;
  user?: string | null;
  non_human_id?: string | null;
}

/** Identity of the (MCP) server a call targets (Contract 1 `ServerIdentity`). */
export interface ServerIdentity {
  name: string;
  /** "stdio" | "sse" | "http", or another transport label. */
  transport: string;
  version?: string | null;
}

/** External scanner verdict (Contract 1 `TrustVerdict`). */
export type TrustVerdict = "verified" | "unverified" | "malicious";

/**
 * The `call` object of a `decide` request. provio sets `mode = SdkHook` and
 * `captured_at` itself. Credentials must never appear in `args`.
 */
export interface ToolCallInput {
  /** Optional; provio generates one when omitted. */
  call_id?: string;
  session_id: string;
  tool: string;
  args: Record<string, unknown>;
  /** Defaults to the client's `caller`, then `{ agent: "unknown" }`. */
  caller?: CallerIdentity;
  server?: ServerIdentity | null;
  trust?: TrustVerdict | null;
}

export type DecisionKind = "allow" | "deny" | "ask" | "redact";

/** A validated `decide` or `resolve` response. */
export interface Decision {
  decision: DecisionKind;
  /** True only for allow / redact / approved ask. */
  dispatch: boolean;
  /** Opaque handle to pass back to `resolve` / `complete`. */
  ref?: string;
  rule_id?: string;
  reason?: string;
  location?: string;
  /** "required" when `--ask defer` deferred the ask to the adapter. */
  approval?: "required";
  irreversible?: boolean;
  timeout_ms?: number;
  /** Redaction patterns (provio applies them on `complete`). */
  patterns?: string[];
}

/** A validated `complete` response. */
export interface CompleteResult {
  recorded: true;
  /** Redacted output; present only for a redact verdict. */
  output?: string;
}

export interface CompleteInput {
  ok: boolean;
  exit?: number;
  /** Tool result as text. Hashed into the ledger, never stored. */
  output?: string;
}
