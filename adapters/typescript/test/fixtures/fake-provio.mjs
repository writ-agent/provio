#!/usr/bin/env node
// A fake `provio check --stdio` implementing INTERFACES.md Contract 6 (v1) for
// tests. Behaviour is chosen by the call's `tool`:
//   deny | ask | redact | malformed | hang | crash | error | wrongid | noref |
//   contradict | crash-on-complete | anything else => allow.
// FAKE_PROVIO_LOG=<file> appends {argv} and every request as JSON lines.
// FAKE_PROVIO_STARTUP_CRASH=1 exits immediately.
import { appendFileSync } from "node:fs";

const argv = process.argv.slice(2);
const log = (obj) => {
  if (process.env.FAKE_PROVIO_LOG) appendFileSync(process.env.FAKE_PROVIO_LOG, JSON.stringify(obj) + "\n");
};
log({ argv });

if (process.env.FAKE_PROVIO_STARTUP_CRASH === "1") {
  process.stderr.write("fake provio: startup failure\n");
  process.exit(1);
}
const checkAt = argv.indexOf("check");
if (checkAt < 0 || !argv.includes("--stdio")) {
  process.stderr.write("fake provio: expected `check --stdio`\n");
  process.exit(1);
}
const askAt = argv.indexOf("--ask");
const askMode = askAt >= 0 ? argv[askAt + 1] : "deny";

const refs = new Map(); // ref -> { tool, decision, patterns, state }
let n = 0;
const send = (obj) => process.stdout.write(JSON.stringify({ v: 1, ...obj }) + "\n");

function decide(id, call) {
  const tool = call?.tool;
  const ref = `ref-${++n}`;
  switch (tool) {
    case "deny":
      refs.set(ref, { tool, state: "denied" });
      return send({ id, decision: "deny", dispatch: false, rule_id: "no-rm", reason: "Destructive command.", location: "provio.yaml:7", ref });
    case "ask": {
      const timeout_ms = typeof call.args?.timeout_ms === "number" ? call.args.timeout_ms : 60000;
      if (askMode === "defer") {
        refs.set(ref, { tool, state: "deferred" });
        return send({ id, decision: "ask", dispatch: false, approval: "required", rule_id: "prod", reason: "diff: DROP TABLE users", irreversible: true, timeout_ms, ref });
      }
      // As the real gateway: --ask deny answers deny, tagged with the original verdict.
      refs.set(ref, { tool, state: "denied" });
      return send({ id, decision: "deny", verdict: "ask", dispatch: false, rule_id: "prod", reason: "requires human approval; --ask deny has no approver", location: "provio.yaml:12", ref });
    }
    case "redact":
      refs.set(ref, { tool, state: "dispatched", redact: true });
      return send({ id, decision: "redact", dispatch: true, rule_id: "pii", patterns: ["[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"], ref });
    case "malformed":
      return process.stdout.write("this is not json\n");
    case "hang":
      return;
    case "crash":
      process.stderr.write("fake provio: boom\n");
      return process.exit(3);
    case "error":
      return send({ id, error: { code: "policy_error", message: "policy failed to load" } });
    case "wrongid":
      return send({ id: "not-" + id, decision: "allow", dispatch: true, ref });
    case "noref":
      return send({ id, decision: "allow", dispatch: true, rule_id: "x" });
    case "contradict":
      return send({ id, decision: "deny", dispatch: true, rule_id: "x", ref });
    default:
      refs.set(ref, { tool, state: "dispatched", crashOnComplete: tool === "crash-on-complete" });
      return send({ id, decision: "allow", dispatch: true, rule_id: "allow-all", ref });
  }
}

function handle(req) {
  const { id, op } = req;
  if (req.v !== 1) return send({ id, error: { code: "bad_request", message: "unsupported protocol version" } });
  if (op === "decide") return decide(id, req.call);
  const entry = refs.get(req.ref);
  if (op === "resolve") {
    if (!entry || entry.state !== "deferred") return send({ id, error: { code: "bad_request", message: "resolve without a deferred ask" } });
    if (req.approved === true) {
      // As the real gateway: an approval yields a new ref; only that one completes.
      entry.state = "resolved";
      const approvedRef = `${req.ref}-approved`;
      refs.set(approvedRef, { tool: entry.tool, state: "dispatched" });
      return send({ id, decision: "allow", dispatch: true, rule_id: "prod", ref: approvedRef });
    }
    entry.state = "denied";
    return send({ id, decision: "deny", dispatch: false, rule_id: "prod", reason: "approval rejected", ref: req.ref });
  }
  if (op === "complete") {
    if (!entry || entry.state !== "dispatched") return send({ id, error: { code: "bad_request", message: "complete without a dispatched decision" } });
    if (entry.crashOnComplete) return process.exit(4);
    entry.state = "completed";
    if (entry.redact && typeof req.output === "string") {
      return send({ id, recorded: true, output: req.output.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "[REDACTED]") });
    }
    return send({ id, recorded: true });
  }
  return send({ id, error: { code: "bad_request", message: `unknown op ${String(op)}` } });
}

let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buf += chunk;
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    let req;
    try {
      req = JSON.parse(line);
    } catch {
      send({ id: null, error: { code: "bad_request", message: "malformed request" } });
      continue;
    }
    log(req);
    handle(req);
  }
});
process.stdin.on("end", () => process.exit(0));
