/**
 * provio integration for the Claude Agent SDK (`@anthropic-ai/claude-agent-sdk`).
 *
 * Plugs into `query({ options: { hooks, canUseTool } })`:
 * - `PreToolUse` asks provio for a verdict and returns the SDK's
 *   `permissionDecision` (`allow` / `deny` / `ask`).
 * - `PostToolUse` / `PostToolUseFailure` record the execution (`complete`)
 *   and, for a redact verdict, replace the tool output via `updatedToolOutput`.
 * - `canUseTool` resolves provio asks that were routed to the SDK's own
 *   permission flow.
 *
 * Only SDK *types* are imported; this module has no runtime dependency on the SDK.
 */
import type {
  CanUseTool,
  HookCallback,
  HookCallbackMatcher,
  HookEvent,
  HookInput,
  PermissionResult,
  PostToolUseFailureHookInput,
  PostToolUseHookInput,
  PreToolUseHookInput,
  SyncHookJSONOutput,
} from "@anthropic-ai/claude-agent-sdk";

import { shouldDispatch, type Approver, type ProvioClient } from "./client.js";
import { describeBlock, ProvioError } from "./errors.js";
import { fromRedacted, outputText, WITHHELD_OUTPUT } from "./output.js";
import type { CallerIdentity, Decision, ServerIdentity, ToolCallInput } from "./protocol.js";

/** A Claude tool use normalized to provio's vocabulary. */
export interface MappedToolCall {
  tool: string;
  args: Record<string, unknown>;
  server?: ServerIdentity | null;
}

/** MCP server provenance as the SDK reports it (`mcp_server` / `mcpServer`). */
export interface McpProvenance {
  name: string;
  source: string;
}

const SHELL_TOOLS = new Set(["Bash", "PowerShell"]);
const READ_TOOLS = new Set(["Read", "Glob", "Grep", "LS", "NotebookRead"]);
const WRITE_TOOLS = new Set(["Write", "Edit", "MultiEdit", "NotebookEdit"]);

function asRecord(input: unknown): Record<string, unknown> {
  return typeof input === "object" && input !== null && !Array.isArray(input)
    ? { ...(input as Record<string, unknown>) }
    : { input };
}

function firstString(args: Record<string, unknown>, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = args[k];
    if (typeof v === "string") return v;
  }
  return undefined;
}

/**
 * Map a Claude tool name + input to provio's policy vocabulary. Kept identical
 * to `provio check --format claude-code` (crates/provio-cli/src/hook.rs):
 * - `Bash` / `PowerShell` → `bash` (with `command`)
 * - `Read` / `Glob` / `Grep` / `LS` / `NotebookRead` → `fs.read`; `Write` / `Edit` / `MultiEdit` / `NotebookEdit` → `fs.write` (with `path`)
 * - `WebFetch` → `http` (with `url`); `WebSearch` → `web.search` (with `query`)
 * - `mcp__<server>__<tool>` → tool `<tool>` with `server: { name: <server> }`
 * - anything else keeps its SDK name.
 * The original input fields are kept; normalized keys are added alongside.
 */
export function mapClaudeTool(toolName: string, input: unknown, mcpServer?: McpProvenance): MappedToolCall {
  const args = asRecord(input);
  if (SHELL_TOOLS.has(toolName)) {
    const command = firstString(args, ["command"]);
    return { tool: "bash", args: command === undefined ? args : { ...args, command } };
  }
  if (READ_TOOLS.has(toolName) || WRITE_TOOLS.has(toolName)) {
    // An explicit string `path` wins; otherwise the tool's native key.
    const path = firstString(args, ["path", "file_path", "notebook_path"]);
    const tool = WRITE_TOOLS.has(toolName) ? "fs.write" : "fs.read";
    return { tool, args: path === undefined ? args : { ...args, path } };
  }
  if (toolName === "WebFetch") return { tool: "http", args };
  if (toolName === "WebSearch") return { tool: "web.search", args };
  if (toolName.startsWith("mcp__")) {
    const rest = toolName.slice("mcp__".length);
    const sep = rest.indexOf("__");
    if (sep > 0 && sep < rest.length - 2) {
      const serverName = mcpServer?.name ?? rest.slice(0, sep);
      return {
        tool: rest.slice(sep + 2),
        args,
        server: { name: serverName, transport: "unknown" },
      };
    }
  }
  return { tool: toolName, args };
}

export interface ProvioClaudeOptions {
  client: ProvioClient;
  /**
   * Decides deferred asks inline, inside the PreToolUse hook (client must use
   * `ask: "defer"`). Takes precedence over `canUseTool`.
   */
  approver?: Approver;
  /**
   * Your own SDK permission callback. With `ask: "defer"` and no `approver`,
   * provio asks are handed to the SDK's permission flow (`permissionDecision:
   * "ask"`) and this callback decides them; its answer is sent to provio as
   * `resolve`. It is also consulted for SDK permission prompts that provio did
   * not raise. Without it, those are denied.
   */
  canUseTool?: CanUseTool;
  /** Default `{ agent: "claude-agent-sdk" }`. */
  caller?: CallerIdentity;
  /** Override the tool mapping (default `mapClaudeTool`). */
  mapTool?: (toolName: string, input: unknown, mcpServer?: McpProvenance) => MappedToolCall;
  /** Hook matcher (tool name regex); default: every tool. */
  matcher?: string;
  /** SDK hook timeout in seconds (covers inline approvals). */
  hookTimeoutSec?: number;
  approvalTimeoutMs?: number;
  /**
   * What an allow / redact verdict returns to the SDK: `"allow"` (default, as
   * `provio check --format claude-code`) skips the SDK's own permission prompt;
   * `"passthrough"` returns no decision, so the SDK's permission rules still
   * apply on top of provio.
   */
  onAllow?: "allow" | "passthrough";
}

interface Tracked {
  ref: string;
  decision: Decision;
}

const MAX_TRACKED = 10_000;

/** The pieces to spread into the SDK's `query({ options })`. */
export interface ProvioClaudeIntegration {
  hooks: Partial<Record<HookEvent, HookCallbackMatcher[]>>;
  canUseTool: CanUseTool;
  preToolUse: HookCallback;
  postToolUse: HookCallback;
  postToolUseFailure: HookCallback;
}

function preOutput(permissionDecision: "allow" | "deny" | "ask", reason: string): SyncHookJSONOutput {
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision,
      permissionDecisionReason: reason,
    },
  };
}

function allowReason(d: Decision): string {
  const rule = d.rule_id ? `rule '${d.rule_id}'` : "policy default";
  return d.decision === "redact" ? `provio: allowed with redaction by ${rule}` : `provio: allowed by ${rule}`;
}

function askReason(d: Decision, tool: string): string {
  const rule = d.rule_id ? `rule '${d.rule_id}'` : "policy default";
  const where = d.location ? ` (${d.location})` : "";
  const why = d.reason ? `: ${d.reason}` : "";
  return `provio: '${tool}' needs approval by ${rule}${where}${why}`;
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function sameJson(a: unknown, b: unknown): boolean {
  try {
    return JSON.stringify(a) === JSON.stringify(b);
  } catch {
    return false;
  }
}

/**
 * Build provio hooks and a `canUseTool` callback for the Claude Agent SDK.
 * Every failure path denies the tool (fail closed): a hook never throws.
 */
export function createProvioIntegration(options: ProvioClaudeOptions): ProvioClaudeIntegration {
  const { client } = options;
  const caller = options.caller ?? client.caller ?? { agent: "claude-agent-sdk" };
  const mapTool = options.mapTool ?? mapClaudeTool;
  const onAllow = options.onAllow ?? "allow";
  const dispatched = new Map<string, Tracked>();
  const pendingAsks = new Map<string, Tracked>();

  const track = (map: Map<string, Tracked>, key: string, value: Tracked): void => {
    if (map.size >= MAX_TRACKED) {
      const oldest = map.keys().next();
      if (oldest.done !== true) map.delete(oldest.value);
    }
    map.set(key, value);
  };

  const buildCall = (input: PreToolUseHookInput, toolUseID: string | undefined): ToolCallInput => {
    const mapped = mapTool(input.tool_name, input.tool_input, input.mcp_server);
    const call: ToolCallInput = {
      session_id: input.session_id || client.sessionId,
      tool: mapped.tool,
      args: mapped.args,
      // Subagent tool calls carry the subagent id as the non-human identity.
      caller: input.agent_id ? { ...caller, non_human_id: input.agent_id } : caller,
    };
    const id = input.tool_use_id || toolUseID;
    if (id) call.call_id = id;
    if (mapped.server !== undefined) call.server = mapped.server;
    return call;
  };

  const preToolUse: HookCallback = async (input: HookInput, toolUseID, { signal }) => {
    if (input.hook_event_name !== "PreToolUse") return {};
    const key = input.tool_use_id || toolUseID || "";
    try {
      if (signal.aborted) return preOutput("deny", "provio: aborted before a decision (fail closed)");
      const call = buildCall(input, toolUseID);
      let decision: Decision;
      if (options.approver !== undefined) {
        decision = await client.authorize(call, {
          approver: options.approver,
          ...(options.approvalTimeoutMs !== undefined ? { approvalTimeoutMs: options.approvalTimeoutMs } : {}),
        });
      } else {
        decision = await client.decide(call);
        if (decision.decision === "ask" && decision.approval === "required") {
          if (decision.ref === undefined) throw new ProvioError("protocol", "deferred ask is missing ref");
          if (options.canUseTool !== undefined && key !== "") {
            track(pendingAsks, key, { ref: decision.ref, decision });
            return preOutput("ask", askReason(decision, input.tool_name));
          }
          decision = await client.resolve(decision.ref, false, "adapter:no-approver");
        }
      }
      if (!shouldDispatch(decision) || decision.ref === undefined) {
        return preOutput("deny", describeBlock(decision, input.tool_name));
      }
      if (key === "" && decision.decision === "redact") {
        return preOutput("deny", `provio: redact verdict for '${input.tool_name}' needs a tool_use_id to apply (fail closed)`);
      }
      if (key !== "") track(dispatched, key, { ref: decision.ref, decision });
      return onAllow === "passthrough" ? {} : preOutput("allow", allowReason(decision));
    } catch (err) {
      return preOutput("deny", `provio: cannot authorize '${input.tool_name}' (fail closed): ${errorText(err)}`);
    }
  };

  const postToolUse: HookCallback = async (input: HookInput, toolUseID) => {
    if (input.hook_event_name !== "PostToolUse") return {};
    const post = input as PostToolUseHookInput;
    const key = post.tool_use_id || toolUseID || "";
    const tracked = dispatched.get(key);
    if (tracked === undefined) {
      const unresolved = pendingAsks.get(key);
      if (unresolved !== undefined) {
        // The tool ran although its provio ask was never resolved: record the
        // rejection and keep the output away from the model.
        pendingAsks.delete(key);
        await client.resolve(unresolved.ref, false, "adapter:unresolved-ask").catch(() => undefined);
        return {
          systemMessage: `provio: '${post.tool_name}' ran without a resolved provio approval; output withheld`,
          hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: WITHHELD_OUTPUT },
        };
      }
      return {};
    }
    dispatched.delete(key);
    const text = outputText(post.tool_response);
    const redact = tracked.decision.decision === "redact";
    try {
      const recorded = await client.complete(tracked.ref, text === undefined ? { ok: true } : { ok: true, output: text });
      if (!redact || text === undefined) return {};
      if (recorded.output === undefined) {
        return {
          systemMessage: "provio: redact verdict but no redacted output was returned; output withheld",
          hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: WITHHELD_OUTPUT },
        };
      }
      return {
        hookSpecificOutput: {
          hookEventName: "PostToolUse",
          updatedToolOutput: fromRedacted(recorded.output, post.tool_response),
        },
      };
    } catch (err) {
      const message = `provio: could not record '${post.tool_name}' execution: ${errorText(err)}`;
      if (!redact) return { systemMessage: message };
      return {
        systemMessage: `${message}; output withheld`,
        hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: WITHHELD_OUTPUT },
      };
    }
  };

  const postToolUseFailure: HookCallback = async (input: HookInput, toolUseID) => {
    if (input.hook_event_name !== "PostToolUseFailure") return {};
    const failed = input as PostToolUseFailureHookInput;
    const key = failed.tool_use_id || toolUseID || "";
    const tracked = dispatched.get(key);
    if (tracked === undefined) return {};
    dispatched.delete(key);
    await client.complete(tracked.ref, { ok: false, output: failed.error }).catch(() => undefined);
    return {};
  };

  const canUseTool: CanUseTool = async (toolName, input, opts): Promise<PermissionResult> => {
    const pending = pendingAsks.get(opts.toolUseID);
    if (pending === undefined) {
      if (options.canUseTool !== undefined) {
        try {
          const res = await options.canUseTool(toolName, input, opts);
          return res ?? { behavior: "deny", message: "provio: permission callback returned no result (fail closed)" };
        } catch (err) {
          return { behavior: "deny", message: `provio: permission callback failed (fail closed): ${errorText(err)}` };
        }
      }
      return { behavior: "deny", message: `provio: no approver for '${toolName}' (fail closed)` };
    }
    pendingAsks.delete(opts.toolUseID);
    let approved = false;
    try {
      const res = options.canUseTool !== undefined && !opts.signal.aborted ? await options.canUseTool(toolName, input, opts) : null;
      // provio decided on the original input; an edited input is not what was approved.
      approved = res?.behavior === "allow" && (res.updatedInput === undefined || sameJson(res.updatedInput, input));
    } catch {
      approved = false;
    }
    try {
      const decision = await client.resolve(pending.ref, approved, "sdk:canUseTool");
      if (!shouldDispatch(decision)) {
        return { behavior: "deny", message: describeBlock({ ...pending.decision, ...decision }, toolName) };
      }
      track(dispatched, opts.toolUseID, { ref: decision.ref ?? pending.ref, decision });
      // No updatedPermissions: a persistent SDK allow rule would bypass future provio asks.
      return { behavior: "allow", updatedInput: input };
    } catch (err) {
      return { behavior: "deny", message: `provio: cannot resolve approval for '${toolName}' (fail closed): ${errorText(err)}` };
    }
  };

  const matcher = (hook: HookCallback): HookCallbackMatcher => {
    const m: HookCallbackMatcher = { hooks: [hook] };
    if (options.matcher !== undefined) m.matcher = options.matcher;
    if (options.hookTimeoutSec !== undefined) m.timeout = options.hookTimeoutSec;
    return m;
  };

  return {
    hooks: {
      PreToolUse: [matcher(preToolUse)],
      PostToolUse: [matcher(postToolUse)],
      PostToolUseFailure: [matcher(postToolUseFailure)],
    },
    canUseTool,
    preToolUse,
    postToolUse,
    postToolUseFailure,
  };
}

/** Just the `hooks` option. Deferred asks need `approver` (or use `createProvioIntegration` for `canUseTool`). */
export function provioHooks(options: ProvioClaudeOptions): Partial<Record<HookEvent, HookCallbackMatcher[]>> {
  return createProvioIntegration(options).hooks;
}

/**
 * Merge provio's hooks with your own `hooks` option. provio's matchers come first
 * for each event; yours are kept.
 */
export function mergeHooks(
  ...sets: Array<Partial<Record<HookEvent, HookCallbackMatcher[]>> | undefined>
): Partial<Record<HookEvent, HookCallbackMatcher[]>> {
  const out: Partial<Record<HookEvent, HookCallbackMatcher[]>> = {};
  for (const set of sets) {
    if (set === undefined) continue;
    for (const [event, matchers] of Object.entries(set) as Array<[HookEvent, HookCallbackMatcher[] | undefined]>) {
      if (matchers === undefined) continue;
      out[event] = [...(out[event] ?? []), ...matchers];
    }
  }
  return out;
}
