// Node smoke test for the COMMITTED playground build (site/assets/playground):
// loads the exact .wasm + glue the website serves and runs a few decisions.
//
//   node --test crates/provio-wasm/tests/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const dir = new URL("../../../site/assets/playground/", import.meta.url);
const wasm = await import(new URL("provio_wasm.js", dir));
wasm.initSync({ module: readFileSync(fileURLToPath(new URL("provio_wasm_bg.wasm", dir))) });
const { POLICY_PRESETS, CALL_PRESETS, SESSIONS } = await import(new URL("presets.js", dir));

const NOW = Date.UTC(2026, 8, 21, 20, 8, 35);
const policy = POLICY_PRESETS.find((p) => p.id === "examples/provio.yaml").source;
const preset = (id) => CALL_PRESETS.find((c) => c.id === id);
const run = (id, src = policy) =>
  JSON.parse(wasm.evaluate(src, JSON.stringify(preset(id).call), NOW));

test("every baked policy preset compiles", () => {
  for (const p of POLICY_PRESETS) {
    const src = p.kind === "pack" ? wasm.pack_to_policy(p.source) : p.source;
    const out = JSON.parse(wasm.compile_policy(src));
    assert.equal(out.ok, true, `${p.id}: ${JSON.stringify(out.errors)}`);
    assert.ok(out.rules.length > 0, p.id);
  }
});

test("Claude Code Bash rm -rf is denied with rule, reason and line", () => {
  const out = run("cc-bash-rm");
  assert.equal(out.kind, "deny");
  assert.equal(out.verdict.rule_id, "block-destructive-shell");
  assert.match(out.verdict.location, /^provio\.yaml:\d+$/);
  assert.equal(out.call.tool, "bash");
  assert.equal(out.ctx.command, "rm -rf build");
});

test("verdicts for the headline presets", () => {
  assert.equal(run("cc-write-env").verdict.rule_id, "never-read-secrets");
  assert.equal(run("cc-webfetch-evil").verdict.rule_id, "egress-allowlist");
  assert.equal(run("mcp-postgres-drop").kind, "ask");
  assert.equal(run("mcp-postgres-drop").verdict.irreversible, true);
  const r = run("mcp-postgres-select");
  assert.equal(r.kind, "redact");
  const m = JSON.parse(wasm.mask_output(JSON.stringify(r.verdict.patterns), preset("mcp-postgres-select").output));
  assert.equal(m.ok, true);
  assert.ok(!m.masked.includes("ada@example.com"));
  assert.ok(m.masked.includes("[redacted-by-provio]"));
});

test("compile errors carry provio.yaml line numbers", () => {
  const out = JSON.parse(wasm.compile_policy("version: 1\ndefault: ask\nrules:\n  - id: x\n    when: tool ==== 1\n    verdict: deny\n"));
  assert.equal(out.ok, false);
  assert.equal(out.errors[0].line, 4);
});

test("ledger: append, verify, tamper, verify again", () => {
  const lines = [];
  for (const id of ["cc-bash-test", "cc-bash-rm", "mcp-postgres-select"]) {
    const ev = run(id);
    const d = JSON.parse(wasm.ledger_record_decision(lines.at(-1) ?? "", JSON.stringify(ev.call), JSON.stringify(ev.verdict), "", NOW));
    assert.equal(d.ok, true, d.error);
    lines.push(JSON.stringify(d.record));
  }
  const ok = JSON.parse(wasm.ledger_verify(lines.join("\n")));
  assert.equal(ok.intact, true);
  assert.equal(ok.message, "chain intact · 3 records · no gaps");
  const t = JSON.parse(wasm.ledger_tamper(lines.join("\n"), 1, "edit"));
  const bad = JSON.parse(wasm.ledger_verify(t.jsonl));
  assert.equal(bad.intact, false);
  assert.equal(bad.broken_at, 1);
  assert.equal(bad.message, "chain BROKEN at record 1 · 1 records verified before the break");
});

test("replay flags previously-allowed calls the candidate would block", () => {
  const s = SESSIONS.find((x) => x.id === "friday-refactor");
  const lines = [];
  s.calls.forEach((id, i) => {
    const call = { ...preset(id).call, session_id: s.session_id, call_id: `c${i}` };
    const ev = JSON.parse(wasm.evaluate(s.recorded_under, JSON.stringify(call), NOW + i));
    const d = JSON.parse(wasm.ledger_record_decision(lines.at(-1) ?? "", JSON.stringify(ev.call), JSON.stringify(ev.verdict), "", NOW + i));
    lines.push(JSON.stringify(d.record));
  });
  const out = JSON.parse(wasm.replay(lines.join("\n"), s.session_id, policy));
  assert.equal(out.ok, true, out.error);
  assert.ok(out.rows.some((r) => r.newly_blocked && r.now_rule === "block-destructive-shell"));
  assert.match(out.summary, /previously-allowed call\(s\) would now be blocked/);
});
