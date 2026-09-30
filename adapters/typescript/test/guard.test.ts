import * as assert from "node:assert/strict";
import { join } from "node:path";
import { describe, it } from "node:test";

import { ProvioBlockedError, ProvioClient, ProvioError, guard, guardTools } from "../src/index.js";
import { fakeClient, tempDir } from "./helpers.js";

function counter<A extends unknown[], R>(impl: (...a: A) => R) {
  const calls: A[] = [];
  const fn = (...a: A): R => {
    calls.push(a);
    return impl(...a);
  };
  return { fn, calls };
}

describe("guard()", () => {
  it("allow: runs the tool, records it, returns its result", async () => {
    const h = fakeClient();
    const t = counter((input: { command: string }) => `ran ${input.command}`);
    try {
      const run = guard(t.fn, { client: h.client, tool: "bash", callId: () => "c-1" });
      assert.equal(await run({ command: "ls" }), "ran ls");
      assert.equal(t.calls.length, 1);
    } finally {
      await h.client.close();
    }
    const decide = h.requests("decide")[0]?.call as Record<string, unknown>;
    assert.deepEqual(decide.args, { command: "ls" });
    assert.equal(decide.call_id, "c-1");
    assert.equal(h.requests("complete")[0]?.output, "ran ls");
    assert.equal(h.requests("complete")[0]?.ok, true);
  });

  it("deny: throws ProvioBlockedError naming the rule; the tool never runs", async () => {
    const h = fakeClient();
    const t = counter(() => "should not run");
    try {
      const run = guard(t.fn, { client: h.client, tool: "deny" });
      await assert.rejects(run(), (e: unknown) => {
        assert.ok(e instanceof ProvioBlockedError);
        assert.equal(e.decision.rule_id, "no-rm");
        assert.match(e.message, /no-rm.*provio\.yaml:7.*Destructive command/);
        return true;
      });
      assert.equal(t.calls.length, 0);
    } finally {
      await h.client.close();
    }
    assert.equal(h.requests("complete").length, 0);
  });

  it("ask deferred and approved: runs", async () => {
    const h = fakeClient({ ask: "defer" });
    const t = counter(() => 42);
    try {
      const run = guard(t.fn, { client: h.client, tool: "ask", approver: () => true });
      assert.equal(await run(), 42);
      assert.equal(t.calls.length, 1);
    } finally {
      await h.client.close();
    }
    assert.equal(h.requests("resolve")[0]?.approved, true);
    assert.equal(h.requests("complete").length, 1);
  });

  it("ask deferred without an approver (default deny): blocked, never runs", async () => {
    const h = fakeClient({ ask: "defer" });
    const t = counter(() => 42);
    try {
      const run = guard(t.fn, { client: h.client, tool: "ask" });
      await assert.rejects(run(), ProvioBlockedError);
      assert.equal(t.calls.length, 0);
    } finally {
      await h.client.close();
    }
  });

  it("ask deferred and rejected: blocked, never runs", async () => {
    const h = fakeClient({ ask: "defer" });
    const t = counter(() => 42);
    try {
      const run = guard(t.fn, { client: h.client, tool: "ask", approver: async () => ({ approved: false, approver: "human:bob" }) });
      await assert.rejects(run(), ProvioBlockedError);
      assert.equal(t.calls.length, 0);
    } finally {
      await h.client.close();
    }
    assert.equal(h.requests("resolve")[0]?.approver, "human:bob");
  });

  it("redact: returns provio's redacted text for string results", async () => {
    const h = fakeClient();
    try {
      const run = guard(async () => "contact: alice@example.com", { client: h.client, tool: "redact" });
      assert.equal(await run(), "contact: [REDACTED]");
    } finally {
      await h.client.close();
    }
  });

  it("redact: keeps the shape of structured results", async () => {
    const h = fakeClient();
    try {
      const run = guard(() => ({ rows: [{ email: "bob@example.org", id: 7 }] }), { client: h.client, tool: "redact" });
      assert.deepEqual(await run(), { rows: [{ email: "[REDACTED]", id: 7 }] });
    } finally {
      await h.client.close();
    }
  });

  for (const tool of ["malformed", "crash", "error", "wrongid", "contradict"]) {
    it(`${tool}: fails closed with ProvioError and never runs`, async () => {
      const h = fakeClient();
      const t = counter(() => "no");
      try {
        await assert.rejects(guard(t.fn, { client: h.client, tool })(), ProvioError);
        assert.equal(t.calls.length, 0);
      } finally {
        await h.client.close();
      }
    });
  }

  it("timeout: fails closed and never runs", async () => {
    const h = fakeClient({ timeoutMs: 150 });
    const t = counter(() => "no");
    try {
      await assert.rejects(guard(t.fn, { client: h.client, tool: "hang" })(), ProvioError);
      assert.equal(t.calls.length, 0);
    } finally {
      await h.client.close();
    }
  });

  it("missing binary: fails closed and never runs", async () => {
    const client = new ProvioClient({ bin: join(tempDir(), "provio.exe") });
    const t = counter(() => "no");
    await assert.rejects(guard(t.fn, { client, tool: "bash" })(), ProvioError);
    assert.equal(t.calls.length, 0);
    await client.close();
  });

  it("gateway dies before complete: result is withheld (throws)", async () => {
    const h = fakeClient();
    const t = counter(() => "secret-ish output");
    try {
      await assert.rejects(guard(t.fn, { client: h.client, tool: "crash-on-complete" })(), ProvioError);
      assert.equal(t.calls.length, 1);
    } finally {
      await h.client.close();
    }
  });

  it("tool throws: records ok:false and rethrows the tool's error", async () => {
    const h = fakeClient();
    try {
      const run = guard(() => {
        throw new Error("disk full");
      }, { client: h.client, tool: "bash" });
      await assert.rejects(run(), /disk full/);
    } finally {
      await h.client.close();
    }
    const [complete] = h.requests("complete");
    assert.equal(complete?.ok, false);
    assert.equal(complete?.output, "disk full");
  });
});

describe("guardTools()", () => {
  it("wraps execute of { description, parameters, execute } tools", async () => {
    const h = fakeClient();
    const noExec = { description: "no execute" };
    const tools = {
      weather: {
        description: "Get the weather",
        parameters: { type: "object" },
        execute: async (input: { city: string }, _ctx?: { toolCallId: string }) => `sunny in ${input.city}`,
      },
      deny: { description: "blocked", parameters: {}, execute: async () => "never" },
      noExec,
    };
    try {
      const wrapped = guardTools(tools, { client: h.client, toolName: (k) => (k === "weather" ? "http" : k) });
      assert.equal(wrapped.noExec, noExec);
      assert.equal(wrapped.weather.description, "Get the weather");
      assert.equal(await wrapped.weather.execute({ city: "Oslo" }, { toolCallId: "call_9" }), "sunny in Oslo");
      await assert.rejects(wrapped.deny.execute(), ProvioBlockedError);
    } finally {
      await h.client.close();
    }
    const decide = h.requests("decide")[0]?.call as Record<string, unknown>;
    assert.equal(decide.tool, "http");
    assert.equal(decide.call_id, "call_9");
    assert.deepEqual(decide.args, { city: "Oslo" });
  });
});
