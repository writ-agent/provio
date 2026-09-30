// End-to-end against the real `provio` binary. Skipped unless PROVIO_E2E=1.
// Uses PROVIO_BIN (or `provio` on PATH).
import * as assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";

import { ProvioBlockedError, ProvioClient, guard, locateProvio } from "../src/index.js";
import { tempDir } from "./helpers.js";

const enabled = process.env.PROVIO_E2E === "1";

const POLICY = `version: 1
default: ask

rules:
  - id: allow-ls
    when: tool == "bash" and command matches "^ls"
    verdict: allow

  - id: no-rm
    when: tool == "bash" and command matches "rm -rf"
    verdict: deny
    reason: "Destructive command."

  - id: prod-deploy
    when: tool == "bash" and command matches "^deploy"
    verdict: ask
    reason: "Production deploy."

  - id: mask-email
    when: tool == "db.query"
    verdict: redact
    patterns:
      - "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\\\.[A-Za-z]{2,}"
`;

describe("e2e: real provio check --stdio", { skip: enabled ? false : "set PROVIO_E2E=1 (and PROVIO_BIN) to run" }, () => {
  it("allow / deny / redact / default-ask, then provio verify", async () => {
    const dir = tempDir("provio-e2e-");
    const policy = join(dir, "provio.yaml");
    const ledger = join(dir, "ledger.jsonl");
    writeFileSync(policy, POLICY);

    const client = new ProvioClient({ policy, ledger, cwd: dir, caller: { agent: "provio-sdk-e2e" } });
    try {
      const bash = guard((input: { command: string }) => `ran: ${input.command}`, { client, tool: "bash" });
      assert.equal(await bash({ command: "ls -la" }), "ran: ls -la");

      await assert.rejects(bash({ command: "rm -rf /" }), (e: unknown) => {
        assert.ok(e instanceof ProvioBlockedError);
        assert.equal(e.decision.rule_id, "no-rm");
        assert.match(e.decision.location ?? "", /provio\.yaml:\d+/);
        return true;
      });

      const query = guard(() => "alice@example.com,42", { client, tool: "db.query" });
      const redacted = await query();
      assert.equal(typeof redacted, "string");
      assert.doesNotMatch(redacted, /alice@example\.com/);
      assert.match(redacted, /42/);

      // Unmatched -> policy default ask -> `--ask deny` -> blocked.
      await assert.rejects(guard((_input: { path: string }) => "never", { client, tool: "fs.write" })({ path: "x" }), ProvioBlockedError);
    } finally {
      await client.close();
    }

    // Deferred asks: approve one, reject one; completes use the resolve's ref.
    const deferred = new ProvioClient({ policy, ledger, cwd: dir, ask: "defer" });
    try {
      const deploy = (approved: boolean) =>
        guard((input: { command: string }) => `deployed: ${input.command}`, {
          client: deferred,
          tool: "bash",
          approver: () => ({ approved, approver: "human:e2e" }),
        });
      assert.equal(await deploy(true)({ command: "deploy web" }), "deployed: deploy web");
      await assert.rejects(deploy(false)({ command: "deploy db" }), ProvioBlockedError);
    } finally {
      await deferred.close();
    }

    const launch = locateProvio();
    const verify = spawnSync(launch.command, [...launch.args, "--ledger", ledger, "verify"], { cwd: dir, encoding: "utf8" });
    assert.equal(verify.status, 0, `provio verify failed:\n${verify.stdout}\n${verify.stderr}`);
  });
});
