// Calls the hook functions directly with SDK-typed inputs. No Claude session
// is started, no network, no API key.
import * as assert from "node:assert/strict";
import { join } from "node:path";
import { describe, it } from "node:test";

import type {
  CanUseTool,
  HookJSONOutput,
  Options,
  PermissionResult,
  PostToolUseFailureHookInput,
  PostToolUseHookInput,
  PreToolUseHookInput,
  SyncHookJSONOutput,
} from "@anthropic-ai/claude-agent-sdk";

import { createProvioIntegration, mapClaudeTool, mergeHooks, provioHooks } from "../src/claude-agent-sdk.js";
import { ProvioClient } from "../src/index.js";
import { fakeClient, tempDir } from "./helpers.js";

const base = { session_id: "sess-1", transcript_path: "/tmp/t.jsonl", cwd: "/work" };
const signal = () => ({ signal: new AbortController().signal });

function pre(tool_name: string, tool_input: unknown, tool_use_id = "toolu_1"): PreToolUseHookInput {
  return { ...base, hook_event_name: "PreToolUse", tool_name, tool_input, tool_use_id };
}
function post(tool_name: string, tool_input: unknown, tool_response: unknown, tool_use_id = "toolu_1"): PostToolUseHookInput {
  return { ...base, hook_event_name: "PostToolUse", tool_name, tool_input, tool_response, tool_use_id };
}
function failure(tool_name: string, error: string, tool_use_id = "toolu_1"): PostToolUseFailureHookInput {
  return { ...base, hook_event_name: "PostToolUseFailure", tool_name, tool_input: {}, error, tool_use_id };
}
function permission(out: HookJSONOutput): { decision?: string; reason?: string } {
  const specific = (out as SyncHookJSONOutput).hookSpecificOutput;
  if (specific === undefined || specific.hookEventName !== "PreToolUse") return {};
  const r: { decision?: string; reason?: string } = {};
  if (specific.permissionDecision !== undefined) r.decision = specific.permissionDecision;
  if (specific.permissionDecisionReason !== undefined) r.reason = specific.permissionDecisionReason;
  return r;
}
function updatedOutput(out: HookJSONOutput): unknown {
  const specific = (out as SyncHookJSONOutput).hookSpecificOutput;
  return specific?.hookEventName === "PostToolUse" ? specific.updatedToolOutput : undefined;
}
const canUseOpts = (toolUseID: string) => ({ signal: new AbortController().signal, toolUseID, requestId: "req-1" });

describe("mapClaudeTool", () => {
  it("maps Claude Code tools to provio's vocabulary", () => {
    assert.deepEqual(mapClaudeTool("Bash", { command: "ls -la", description: "list" }), {
      tool: "bash",
      args: { command: "ls -la", description: "list" },
    });
    assert.deepEqual(mapClaudeTool("Read", { file_path: "/a/.env" }), { tool: "fs.read", args: { file_path: "/a/.env", path: "/a/.env" } });
    for (const t of ["Write", "Edit", "MultiEdit"]) {
      assert.equal(mapClaudeTool(t, { file_path: "x.ts" }).tool, "fs.write");
      assert.equal(mapClaudeTool(t, { file_path: "x.ts" }).args.path, "x.ts");
    }
    assert.equal(mapClaudeTool("NotebookEdit", { notebook_path: "n.ipynb", new_source: "" }).args.path, "n.ipynb");
    assert.deepEqual(mapClaudeTool("WebFetch", { url: "https://api.github.com/x", prompt: "p" }), {
      tool: "http",
      args: { url: "https://api.github.com/x", prompt: "p" },
    });
    assert.deepEqual(mapClaudeTool("mcp__postgres__query", { sql: "select 1" }), {
      tool: "query",
      args: { sql: "select 1" },
      server: { name: "postgres", transport: "unknown" },
    });
    assert.deepEqual(mapClaudeTool("mcp__my_srv__do__thing", {}, { name: "my_srv", source: "sdk" }).server, { name: "my_srv", transport: "unknown" });
    assert.deepEqual(mapClaudeTool("Grep", { pattern: "x", path: "/src" }), { tool: "fs.read", args: { pattern: "x", path: "/src" } });
    assert.equal(mapClaudeTool("LS", { path: "/src" }).tool, "fs.read");
    assert.equal(mapClaudeTool("mcp__my_srv__do__thing", {}).tool, "do__thing");
    assert.equal(mapClaudeTool("TodoWrite", { todos: [] }).tool, "TodoWrite");
  });
});

describe("Claude Agent SDK hooks", () => {
  it("fits the SDK's Options type", async () => {
    const h = fakeClient();
    const integ = createProvioIntegration({ client: h.client });
    const options: Options = { hooks: mergeHooks(integ.hooks, { Stop: [{ hooks: [async () => ({})] }] }), canUseTool: integ.canUseTool };
    assert.equal(options.hooks?.PreToolUse?.length, 1);
    assert.equal(options.hooks?.Stop?.length, 1);
    assert.equal(provioHooks({ client: h.client, matcher: "Bash", hookTimeoutSec: 30 }).PreToolUse?.[0]?.matcher, "Bash");
    await h.client.close();
  });

  it("PreToolUse allow -> permissionDecision allow; PostToolUse records", async () => {
    const h = fakeClient();
    const integ = createProvioIntegration({ client: h.client });
    try {
      const out = await integ.preToolUse(pre("Bash", { command: "ls" }), "toolu_1", signal());
      assert.deepEqual(permission(out), { decision: "allow", reason: "provio: allowed by rule 'allow-all'" });
      const after = await integ.postToolUse(post("Bash", { command: "ls" }, { stdout: "a", stderr: "" }), "toolu_1", signal());
      assert.deepEqual(after, {});
    } finally {
      await h.client.close();
    }
    const call = h.requests("decide")[0]?.call as Record<string, unknown>;
    assert.equal(call.tool, "bash");
    assert.equal(call.call_id, "toolu_1");
    assert.equal(call.session_id, "sess-1");
    assert.deepEqual(call.caller, { agent: "claude-agent-sdk" });
  });

  it("subagent calls carry agent_id as non_human_id", async () => {
    const h = fakeClient();
    const integ = createProvioIntegration({ client: h.client, caller: { agent: "my-app", agent_version: "2" } });
    try {
      await integ.preToolUse({ ...pre("Read", { file_path: "a" }), agent_id: "sub-1" }, "toolu_1", signal());
    } finally {
      await h.client.close();
    }
    const call = h.requests("decide")[0]?.call as Record<string, unknown>;
    assert.deepEqual(call.caller, { agent: "my-app", agent_version: "2", non_human_id: "sub-1" });
  });

  it("PostToolUse output is the JSON of the SDK tool_response", async () => {
    const h = fakeClient();
    const integ = createProvioIntegration({ client: h.client });
    try {
      await integ.preToolUse(pre("Bash", { command: "ls" }), "toolu_1", signal());
      await integ.postToolUse(post("Bash", { command: "ls" }, { stdout: "a", stderr: "" }), "toolu_1", signal());
    } finally {
      await h.client.close();
    }
    assert.equal(h.requests("complete")[0]?.output, JSON.stringify({ stdout: "a", stderr: "" }));
  });

  it("onAllow: passthrough leaves the SDK's own permission flow in charge", async () => {
    const h = fakeClient();
    const integ = createProvioIntegration({ client: h.client, onAllow: "passthrough" });
    try {
      assert.deepEqual(await integ.preToolUse(pre("Bash", { command: "ls" }), "toolu_1", signal()), {});
    } finally {
      await h.client.close();
    }
  });

  it("PreToolUse deny -> permissionDecision deny naming rule and location", async () => {
    const h = fakeClient();
    const integ = createProvioIntegration({ client: h.client, mapTool: () => ({ tool: "deny", args: {} }) });
    try {
      const out = permission(await integ.preToolUse(pre("Bash", { command: "rm -rf /" }), "toolu_1", signal()));
      assert.equal(out.decision, "deny");
      assert.match(out.reason ?? "", /rule 'no-rm' \(provio\.yaml:7\): Destructive command\./);
    } finally {
      await h.client.close();
    }
  });

  it("ask with an inline approver -> allow after resolve(approved)", async () => {
    const h = fakeClient({ ask: "defer" });
    const integ = createProvioIntegration({ client: h.client, approver: () => true, mapTool: () => ({ tool: "ask", args: {} }) });
    try {
      assert.equal(permission(await integ.preToolUse(pre("Bash", { command: "deploy" }), "toolu_1", signal())).decision, "allow");
    } finally {
      await h.client.close();
    }
    assert.equal(h.requests("resolve")[0]?.approved, true);
  });

  it("ask with no approver and no canUseTool -> deny, and resolve(false) is recorded", async () => {
    const h = fakeClient({ ask: "defer" });
    const integ = createProvioIntegration({ client: h.client, mapTool: () => ({ tool: "ask", args: {} }) });
    try {
      assert.equal(permission(await integ.preToolUse(pre("Bash", {}), "toolu_1", signal())).decision, "deny");
    } finally {
      await h.client.close();
    }
    assert.equal(h.requests("resolve")[0]?.approved, false);
  });

  it("ask under --ask deny -> deny", async () => {
    const h = fakeClient();
    const integ = createProvioIntegration({ client: h.client, approver: () => true, mapTool: () => ({ tool: "ask", args: {} }) });
    try {
      assert.equal(permission(await integ.preToolUse(pre("Bash", {}), "toolu_1", signal())).decision, "deny");
    } finally {
      await h.client.close();
    }
  });

  it("ask routed to the SDK: PreToolUse returns ask, canUseTool resolves provio", async () => {
    const h = fakeClient({ ask: "defer" });
    const seen: string[] = [];
    const userCanUseTool: CanUseTool = async (toolName, input): Promise<PermissionResult> => {
      seen.push(toolName);
      return { behavior: "allow", updatedInput: input, updatedPermissions: [] };
    };
    const integ = createProvioIntegration({ client: h.client, canUseTool: userCanUseTool, mapTool: () => ({ tool: "ask", args: {} }) });
    try {
      const out = permission(await integ.preToolUse(pre("Bash", { command: "deploy" }, "toolu_7"), "toolu_7", signal()));
      assert.equal(out.decision, "ask");
      assert.match(out.reason ?? "", /needs approval by rule 'prod'/);
      const res = await integ.canUseTool("Bash", { command: "deploy" }, canUseOpts("toolu_7"));
      assert.deepEqual(res, { behavior: "allow", updatedInput: { command: "deploy" } });
      assert.deepEqual(seen, ["Bash"]);
      await integ.postToolUse(post("Bash", { command: "deploy" }, "done", "toolu_7"), "toolu_7", signal());
    } finally {
      await h.client.close();
    }
    assert.equal(h.requests("resolve")[0]?.approved, true);
    assert.equal(h.requests("complete").length, 1);
  });

  it("ask routed to the SDK: user denies -> deny", async () => {
    const h = fakeClient({ ask: "defer" });
    const integ = createProvioIntegration({
      client: h.client,
      canUseTool: async () => ({ behavior: "deny", message: "no" }),
      mapTool: () => ({ tool: "ask", args: {} }),
    });
    try {
      await integ.preToolUse(pre("Bash", {}, "toolu_8"), "toolu_8", signal());
      const res = await integ.canUseTool("Bash", {}, canUseOpts("toolu_8"));
      assert.equal(res?.behavior, "deny");
    } finally {
      await h.client.close();
    }
    assert.equal(h.requests("resolve")[0]?.approved, false);
  });

  it("ask routed to the SDK: approval with edited input is rejected", async () => {
    const h = fakeClient({ ask: "defer" });
    const integ = createProvioIntegration({
      client: h.client,
      canUseTool: async () => ({ behavior: "allow", updatedInput: { command: "something else" } }),
      mapTool: () => ({ tool: "ask", args: {} }),
    });
    try {
      await integ.preToolUse(pre("Bash", { command: "deploy" }, "toolu_9"), "toolu_9", signal());
      const res = await integ.canUseTool("Bash", { command: "deploy" }, canUseOpts("toolu_9"));
      assert.equal(res?.behavior, "deny");
    } finally {
      await h.client.close();
    }
    assert.equal(h.requests("resolve")[0]?.approved, false);
  });

  it("canUseTool for a call provio did not defer -> deny without a delegate", async () => {
    const h = fakeClient();
    const integ = createProvioIntegration({ client: h.client });
    try {
      assert.equal((await integ.canUseTool("Bash", {}, canUseOpts("toolu_x")))?.behavior, "deny");
    } finally {
      await h.client.close();
    }
  });

  it("a deferred ask that runs anyway gets its output withheld", async () => {
    const h = fakeClient({ ask: "defer" });
    const integ = createProvioIntegration({ client: h.client, canUseTool: async () => ({ behavior: "allow" }), mapTool: () => ({ tool: "ask", args: {} }) });
    try {
      await integ.preToolUse(pre("Bash", {}, "toolu_10"), "toolu_10", signal());
      const out = await integ.postToolUse(post("Bash", {}, "leaked", "toolu_10"), "toolu_10", signal());
      assert.match(String(updatedOutput(out)), /withheld/);
    } finally {
      await h.client.close();
    }
    assert.equal(h.requests("resolve")[0]?.approved, false);
  });

  it("redact: PostToolUse replaces the tool output via updatedToolOutput", async () => {
    const h = fakeClient();
    const integ = createProvioIntegration({ client: h.client, mapTool: () => ({ tool: "redact", args: {} }) });
    try {
      assert.equal(permission(await integ.preToolUse(pre("mcp__db__query", { sql: "select" }), "toolu_1", signal())).decision, "allow");
      const out = await integ.postToolUse(post("mcp__db__query", {}, { rows: [{ email: "a@b.io" }] }), "toolu_1", signal());
      assert.deepEqual(updatedOutput(out), { rows: [{ email: "[REDACTED]" }] });
    } finally {
      await h.client.close();
    }
  });

  it("redact: if complete fails the output is withheld", async () => {
    const h = fakeClient();
    let n = 0;
    // First decide is redact; then the gateway goes away before complete.
    const integ = createProvioIntegration({ client: h.client, mapTool: () => ({ tool: n++ === 0 ? "redact" : "x", args: {} }) });
    try {
      await integ.preToolUse(pre("Read", { file_path: "a" }), "toolu_1", signal());
      await h.client.close();
      const out = await integ.postToolUse(post("Read", {}, "a@b.io"), "toolu_1", signal());
      assert.equal(updatedOutput(out), "[provio: tool output withheld because redaction could not be applied]");
    } finally {
      await h.client.close();
    }
  });

  it("PostToolUseFailure records ok:false", async () => {
    const h = fakeClient();
    const integ = createProvioIntegration({ client: h.client });
    try {
      await integ.preToolUse(pre("Bash", { command: "false" }), "toolu_1", signal());
      assert.deepEqual(await integ.postToolUseFailure(failure("Bash", "exit 1"), "toolu_1", signal()), {});
    } finally {
      await h.client.close();
    }
    const [complete] = h.requests("complete");
    assert.equal(complete?.ok, false);
    assert.equal(complete?.output, "exit 1");
  });

  for (const tool of ["malformed", "crash", "error", "hang"]) {
    it(`gateway ${tool} -> deny (fail closed)`, async () => {
      const h = fakeClient({ timeoutMs: 150 });
      const integ = createProvioIntegration({ client: h.client, mapTool: () => ({ tool, args: {} }) });
      try {
        const out = permission(await integ.preToolUse(pre("Bash", {}), "toolu_1", signal()));
        assert.equal(out.decision, "deny");
        assert.match(out.reason ?? "", /fail closed/);
      } finally {
        await h.client.close();
      }
    });
  }

  it("missing provio binary -> deny (fail closed)", async () => {
    const client = new ProvioClient({ bin: join(tempDir(), "provio.exe") });
    const integ = createProvioIntegration({ client });
    const out = permission(await integ.preToolUse(pre("Read", { file_path: "a" }), "toolu_1", signal()));
    assert.equal(out.decision, "deny");
    assert.match(out.reason ?? "", /not found/);
    await client.close();
  });

  it("aborted signal -> deny without asking provio", async () => {
    const h = fakeClient();
    const integ = createProvioIntegration({ client: h.client });
    const ac = new AbortController();
    ac.abort();
    try {
      assert.equal(permission(await integ.preToolUse(pre("Bash", {}), "toolu_1", { signal: ac.signal })).decision, "deny");
    } finally {
      await h.client.close();
    }
    assert.equal(h.requests("decide").length, 0);
  });

  it("ignores events it is not registered for", async () => {
    const h = fakeClient();
    const integ = createProvioIntegration({ client: h.client });
    assert.deepEqual(await integ.preToolUse(post("Bash", {}, ""), "toolu_1", signal()), {});
    assert.deepEqual(await integ.postToolUse(post("Bash", {}, "", "unknown"), "unknown", signal()), {});
    await h.client.close();
  });
});
