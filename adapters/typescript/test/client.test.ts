import * as assert from "node:assert/strict";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  ProvioClient,
  ProvioError,
  ProvioProtocolError,
  ProvioTimeoutError,
  ProvioUnavailableError,
  findOnPath,
  locateProvio,
  shouldDispatch,
} from "../src/index.js";
import { FAKE_PROVIO, call, fakeClient, tempDir } from "./helpers.js";

describe("ProvioClient against the fake gateway", () => {
  it("allow: decides, dispatches and records", async () => {
    const h = fakeClient({ policy: "p.yaml", ledger: "l.jsonl" });
    try {
      const d = await h.client.decide({ ...call("bash", { command: "ls" }), call_id: "toolu_1" });
      assert.equal(d.decision, "allow");
      assert.equal(shouldDispatch(d), true);
      assert.equal(d.rule_id, "allow-all");
      assert.ok(d.ref);
      const done = await h.client.complete(d.ref as string, { ok: true, exit: 0, output: "a\nb" });
      assert.deepEqual(done, { recorded: true });
    } finally {
      await h.client.close();
    }
    const argv = h.log()[0]?.argv as string[];
    assert.deepEqual(argv, ["--policy", "p.yaml", "--ledger", "l.jsonl", "check", "--stdio", "--ask", "deny"]);
    const [decide] = h.requests("decide");
    const sent = decide?.call as Record<string, unknown>;
    assert.equal(decide?.v, 1);
    assert.equal(sent.call_id, "toolu_1");
    assert.deepEqual(sent.caller, { agent: "unknown" });
    assert.equal(sent.server, null);
    const [complete] = h.requests("complete");
    assert.equal(complete?.output, "a\nb");
    assert.equal(complete?.exit, 0);
  });

  it("deny: carries rule, reason and location; no dispatch", async () => {
    const h = fakeClient();
    try {
      const d = await h.client.decide(call("deny", { command: "rm -rf /" }));
      assert.equal(d.decision, "deny");
      assert.equal(shouldDispatch(d), false);
      assert.equal(d.rule_id, "no-rm");
      assert.equal(d.location, "provio.yaml:7");
      assert.equal(d.reason, "Destructive command.");
    } finally {
      await h.client.close();
    }
  });

  it("ask under --ask deny never dispatches, even with an approver", async () => {
    const h = fakeClient();
    let asked = false;
    try {
      const d = await h.client.authorize(call("ask"), { approver: () => ((asked = true), true) });
      assert.equal(d.decision, "deny");
      assert.equal(shouldDispatch(d), false);
      assert.equal(asked, false);
    } finally {
      await h.client.close();
    }
    assert.equal(h.requests("resolve").length, 0);
  });

  it("ask --ask defer: approver approves -> resolve(approved) -> dispatch", async () => {
    const h = fakeClient({ ask: "defer" });
    try {
      const d = await h.client.authorize(call("ask"), {
        approver: ({ decision }) => {
          assert.equal(decision.approval, "required");
          assert.equal(decision.irreversible, true);
          return { approved: true, approver: "human:alice" };
        },
      });
      assert.equal(shouldDispatch(d), true);
      assert.ok(d.ref);
      await h.client.complete(d.ref as string, { ok: true });
    } finally {
      await h.client.close();
    }
    const [resolve] = h.requests("resolve");
    assert.equal(resolve?.approved, true);
    assert.equal(resolve?.approver, "human:alice");
    assert.equal(h.log()[0]?.argv instanceof Array && (h.log()[0]?.argv as string[]).includes("defer"), true);
  });

  for (const [name, approver] of [
    ["rejects", () => false],
    ["throws", () => {
      throw new Error("ui crashed");
    }],
    ["answers non-boolean", () => "yes" as unknown as boolean],
    ["is missing", undefined],
  ] as const) {
    it(`ask --ask defer: approver ${name} -> resolve(false) -> no dispatch`, async () => {
      const h = fakeClient({ ask: "defer" });
      try {
        const d = await h.client.authorize(call("ask"), approver ? { approver } : {});
        assert.equal(shouldDispatch(d), false);
        assert.equal(d.decision, "deny");
      } finally {
        await h.client.close();
      }
      assert.equal(h.requests("resolve")[0]?.approved, false);
    });
  }

  it("ask --ask defer: approver slower than timeout_ms -> denied", async () => {
    const h = fakeClient({ ask: "defer" });
    try {
      let aborted = false;
      const d = await h.client.authorize(call("ask", { timeout_ms: 50 }), {
        approver: ({ signal }) =>
          new Promise<boolean>((done) => {
            signal.addEventListener("abort", () => (aborted = true));
            setTimeout(() => done(true), 500);
          }),
      });
      assert.equal(shouldDispatch(d), false);
      assert.equal(aborted, true);
    } finally {
      await h.client.close();
    }
    assert.equal(h.requests("resolve")[0]?.approved, false);
  });

  it("redact: complete returns the redacted output", async () => {
    const h = fakeClient();
    try {
      const d = await h.client.decide(call("redact", { query: "select email from users" }));
      assert.equal(d.decision, "redact");
      assert.equal(shouldDispatch(d), true);
      assert.deepEqual(d.patterns?.length, 1);
      const res = await h.client.complete(d.ref as string, { ok: true, output: "alice@example.com, bob@example.org" });
      assert.equal(res.output, "[REDACTED], [REDACTED]");
    } finally {
      await h.client.close();
    }
  });

  it("malformed line fails closed, then a fresh gateway is started", async () => {
    const h = fakeClient();
    try {
      await assert.rejects(h.client.decide(call("malformed")), ProvioProtocolError);
      const d = await h.client.decide(call("bash", { command: "ls" }));
      assert.equal(d.decision, "allow");
    } finally {
      await h.client.close();
    }
    assert.equal(h.log().filter((e) => "argv" in e).length, 2);
  });

  it("timeout fails closed", async () => {
    const h = fakeClient({ timeoutMs: 200 });
    try {
      await assert.rejects(h.client.decide(call("hang")), ProvioTimeoutError);
    } finally {
      await h.client.close();
    }
  });

  it("crash fails every in-flight request closed", async () => {
    const h = fakeClient();
    try {
      const a = h.client.decide(call("hang"));
      const b = h.client.decide(call("crash"));
      await assert.rejects(a, (e: unknown) => e instanceof ProvioProtocolError && /exited \(code 3\)/.test(e.message));
      await assert.rejects(b, ProvioProtocolError);
    } finally {
      await h.client.close();
    }
  });

  it("crash at startup fails closed and includes stderr", async () => {
    const h = fakeClient({}, { FAKE_PROVIO_STARTUP_CRASH: "1" });
    try {
      await assert.rejects(h.client.decide(call("bash")), (e: unknown) => e instanceof ProvioError && /startup failure/.test(e.message));
    } finally {
      await h.client.close();
    }
  });

  it("respawn: false keeps a broken client broken", async () => {
    const h = fakeClient({ respawn: false });
    try {
      await assert.rejects(h.client.decide(call("malformed")), ProvioProtocolError);
      await assert.rejects(h.client.decide(call("bash")), ProvioProtocolError);
    } finally {
      await h.client.close();
    }
  });

  it("error response rejects with the gateway code", async () => {
    const h = fakeClient();
    try {
      await assert.rejects(h.client.decide(call("error")), (e: unknown) => e instanceof ProvioError && e.code === "policy_error");
    } finally {
      await h.client.close();
    }
  });

  it("response with the wrong id fails closed", async () => {
    const h = fakeClient();
    try {
      await assert.rejects(h.client.decide(call("wrongid")), ProvioProtocolError);
    } finally {
      await h.client.close();
    }
  });

  it("self-contradicting or ref-less dispatch fails closed", async () => {
    const h = fakeClient();
    try {
      await assert.rejects(h.client.decide(call("contradict")), ProvioProtocolError);
      await assert.rejects(h.client.decide(call("noref")), ProvioProtocolError);
    } finally {
      await h.client.close();
    }
  });

  it("parallel requests are matched in order", async () => {
    const h = fakeClient();
    try {
      const results = await Promise.all([
        h.client.decide(call("bash", { command: "ls" })),
        h.client.decide(call("deny")),
        h.client.decide(call("redact")),
        h.client.decide(call("fs.read", { path: "a" })),
      ]);
      assert.deepEqual(
        results.map((r) => r.decision),
        ["allow", "deny", "redact", "allow"],
      );
    } finally {
      await h.client.close();
    }
  });

  it("close() and Symbol.asyncDispose reject later requests", async () => {
    const h = fakeClient();
    await h.client.decide(call("bash"));
    await h.client[Symbol.asyncDispose]();
    await assert.rejects(h.client.decide(call("bash")), (e: unknown) => e instanceof ProvioError && e.code === "closed");
  });

  it("an idle client does not keep the process alive", async () => {
    // node:test would hang on an unref'd-but-open child only if refs leaked;
    // this just exercises the ref/unref path around a request.
    const h = fakeClient();
    await h.client.decide(call("bash"));
    await h.client.close();
  });
});

describe("locating provio", () => {
  it("missing explicit binary -> ProvioUnavailableError", async () => {
    const client = new ProvioClient({ bin: join(tempDir(), "nope", "provio.exe") });
    await assert.rejects(client.decide(call("bash")), ProvioUnavailableError);
    await client.close();
  });

  it("PROVIO_BIN pointing nowhere -> ProvioUnavailableError", async () => {
    const client = new ProvioClient({ env: { ...process.env, PROVIO_BIN: join(tempDir(), "missing") } });
    await assert.rejects(client.decide(call("bash")), ProvioUnavailableError);
    await client.close();
  });

  it("no PROVIO_BIN and nothing on PATH -> ProvioUnavailableError", async () => {
    const env: NodeJS.ProcessEnv = { PATH: tempDir() };
    assert.throws(() => locateProvio(undefined, env), ProvioUnavailableError);
    const client = new ProvioClient({ env });
    await assert.rejects(client.decide(call("bash")), ProvioUnavailableError);
    await client.close();
  });

  it("explicit command that does not exist -> ProvioUnavailableError", async () => {
    const client = new ProvioClient({ command: join(tempDir(), "definitely-not-provio") });
    await assert.rejects(client.decide(call("bash")), ProvioUnavailableError);
    await client.close();
  });

  it("PROVIO_BIN may point at a .mjs gateway, which runs under node", async () => {
    const launch = locateProvio(undefined, { PROVIO_BIN: FAKE_PROVIO });
    assert.equal(launch.command, process.execPath);
    assert.deepEqual(launch.args, [FAKE_PROVIO]);
    const client = new ProvioClient({ env: { ...process.env, PROVIO_BIN: FAKE_PROVIO } });
    try {
      assert.equal((await client.decide(call("bash"))).decision, "allow");
    } finally {
      await client.close();
    }
  });

  it("finds provio.exe on a Windows PATH and ignores provio.cmd", async () => {
    const { writeFileSync } = await import("node:fs");
    const dir = tempDir();
    writeFileSync(join(dir, "provio.cmd"), "");
    assert.equal(findOnPath("provio", { PATH: dir }, "win32"), undefined);
    writeFileSync(join(dir, "provio.exe"), "");
    assert.equal(findOnPath("provio", { Path: `"${dir}"` }, "win32"), join(dir, "provio.exe"));
  });

  it("rejects an invalid ask mode", () => {
    assert.throws(() => new ProvioClient({ ask: "allow" as "deny" }), ProvioError);
  });
});
