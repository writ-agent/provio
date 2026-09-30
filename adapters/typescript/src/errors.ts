import type { Decision } from "./protocol.js";

/**
 * Base class for every provio failure. Any `ProvioError` means the tool call must
 * not run (fail closed).
 */
export class ProvioError extends Error {
  /** Machine-readable code, e.g. `unavailable`, `timeout`, `protocol`, or a gateway `error.code`. */
  readonly code: string;

  constructor(code: string, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ProvioError";
    this.code = code;
  }
}

/** The provio binary could not be found or started. */
export class ProvioUnavailableError extends ProvioError {
  constructor(message: string, options?: { cause?: unknown }) {
    super("unavailable", message, options);
    this.name = "ProvioUnavailableError";
  }
}

/** The gateway did not answer within the per-request timeout. */
export class ProvioTimeoutError extends ProvioError {
  constructor(message: string) {
    super("timeout", message);
    this.name = "ProvioTimeoutError";
  }
}

/** The gateway wrote something that is not a valid protocol v1 response, or exited. */
export class ProvioProtocolError extends ProvioError {
  constructor(message: string, options?: { cause?: unknown }) {
    super("protocol", message, options);
    this.name = "ProvioProtocolError";
  }
}

/** provio decided the call must not run (deny, rejected or unresolved ask). */
export class ProvioBlockedError extends ProvioError {
  readonly decision: Decision;

  constructor(decision: Decision, tool: string) {
    super("blocked", describeBlock(decision, tool));
    this.name = "ProvioBlockedError";
    this.decision = decision;
  }
}

/** Human-readable reason for a non-dispatching decision, naming the rule. */
export function describeBlock(decision: Decision, tool: string): string {
  const rule = decision.rule_id ? `rule '${decision.rule_id}'` : "policy default";
  const where = decision.location ? ` (${decision.location})` : "";
  const why = decision.reason ? `: ${decision.reason}` : "";
  const verb = decision.decision === "ask" ? "needs approval and was not approved" : "was blocked";
  return `provio: '${tool}' ${verb} by ${rule}${where}${why}`;
}
