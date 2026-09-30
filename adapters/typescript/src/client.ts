import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";

import { ProvioError, ProvioProtocolError, ProvioTimeoutError, ProvioUnavailableError } from "./errors.js";
import { launchFor, locateProvio, type Launch } from "./locate.js";
import {
  PROTOCOL_VERSION,
  type CallerIdentity,
  type CompleteInput,
  type CompleteResult,
  type Decision,
  type DecisionKind,
  type ToolCallInput,
} from "./protocol.js";

/** What `provio check` does with an `ask` verdict. */
export type AskMode = "deny" | "defer" | "ui";

export interface ProvioClientOptions {
  /** Path to the provio binary. Default: `PROVIO_BIN`, then `provio` on PATH. A `.js`/`.mjs`/`.cjs` path runs under Node. */
  bin?: string;
  /**
   * Explicit program to spawn instead of locating provio (e.g. `process.execPath`
   * for a test gateway). `args` are placed before provio's own arguments.
   */
  command?: string;
  args?: string[];
  /** `--policy` (default: provio's own default, `./provio.yaml`). */
  policy?: string;
  /** `--ledger` (default: provio's own default, `.provio/ledger.jsonl`). */
  ledger?: string;
  /**
   * `--ask deny` (default, fail closed); `--ask defer`, which hands the
   * decision to an `approver` callback or the agent's own UI; or `--ask ui`,
   * where `decide` waits for a human on the `provio ui` Approvals screen (no
   * console, a denial or a timeout all deny).
   */
  ask?: AskMode;
  /**
   * Per-request timeout in ms (default 30000; 180000 with `ask: "ui"`, where a
   * `decide` waits for the console). A timeout kills the gateway and fails closed.
   */
  timeoutMs?: number;
  /** Default caller identity for calls that do not set one. */
  caller?: CallerIdentity;
  /** Default session id for calls that do not set one (default: a random UUID per client). */
  sessionId?: string;
  /** Working directory for the gateway process. */
  cwd?: string;
  /** Environment for the gateway process (default: `process.env`). */
  env?: NodeJS.ProcessEnv;
  /** Start a fresh gateway after a crash or timeout (default true). In-flight requests still fail closed. */
  respawn?: boolean;
  /** Receives the gateway's stderr (diagnostics). */
  onStderr?: (text: string) => void;
  /** Longest accepted response line in bytes (default 16 MiB). */
  maxLineBytes?: number;
}

/** Input to an `approver` callback for a deferred ask. */
export interface ApprovalRequest {
  call: ToolCallInput;
  decision: Decision;
  /** Aborted when the ask's `timeout_ms` elapses. */
  signal: AbortSignal;
}

export type ApprovalAnswer = boolean | { approved: boolean; approver?: string };

/** Obtains a human decision for a deferred ask. Anything but an explicit approval is a denial. */
export type Approver = (request: ApprovalRequest) => ApprovalAnswer | Promise<ApprovalAnswer>;

export interface AuthorizeOptions {
  /** Called for a deferred ask (`--ask defer`). Without one, deferred asks are rejected. */
  approver?: Approver;
  /** Upper bound on waiting for the approver when the ask carries no `timeout_ms` (default 5 min). */
  approvalTimeoutMs?: number;
}

type Json = Record<string, unknown>;

interface Pending {
  id: string;
  op: string;
  resolve: (value: Json) => void;
  reject: (error: ProvioError) => void;
  timer: NodeJS.Timeout;
}

const DECISIONS: ReadonlySet<string> = new Set(["allow", "deny", "ask", "redact"]);
const DEFAULT_APPROVAL_TIMEOUT_MS = 5 * 60 * 1000;

/** True only when a decision says the tool may run. */
export function shouldDispatch(decision: Decision): boolean {
  return decision.dispatch === true && decision.decision !== "deny";
}

/**
 * A long-lived `provio check --stdio` child process speaking protocol v1.
 * Every failure (missing binary, crash, timeout, malformed line, `error`
 * response) rejects with a `ProvioError`; callers must then not run the tool.
 */
export class ProvioClient implements AsyncDisposable {
  readonly askMode: AskMode;
  readonly sessionId: string;
  readonly caller: CallerIdentity | undefined;

  private readonly options: ProvioClientOptions;
  private readonly timeoutMs: number;
  private readonly maxLineBytes: number;
  private proc: ChildProcess | undefined;
  private queue: Pending[] = [];
  private buffer = "";
  private seq = 0;
  private closed = false;
  private broken: ProvioError | undefined;
  private stderrTail = "";

  constructor(options: ProvioClientOptions = {}) {
    this.options = options;
    this.askMode = options.ask ?? "deny";
    if (this.askMode !== "deny" && this.askMode !== "defer" && this.askMode !== "ui") {
      throw new ProvioError("bad_option", `ask must be "deny", "defer" or "ui", got ${String(options.ask)}`);
    }
    this.timeoutMs = options.timeoutMs ?? (this.askMode === "ui" ? 180_000 : 30_000);
    this.maxLineBytes = options.maxLineBytes ?? 16 * 1024 * 1024;
    this.sessionId = options.sessionId ?? randomUUID();
    this.caller = options.caller;
  }

  /** The argv (after the program) passed to provio. */
  gatewayArgs(): string[] {
    const args: string[] = [];
    if (this.options.policy !== undefined) args.push("--policy", this.options.policy);
    if (this.options.ledger !== undefined) args.push("--ledger", this.options.ledger);
    args.push("check", "--stdio", "--ask", this.askMode);
    return args;
  }

  /** Ask provio for a verdict. Rejects on any gateway failure. */
  async decide(call: ToolCallInput): Promise<Decision> {
    const body: Json = {
      op: "decide",
      call: {
        ...call,
        session_id: call.session_id || this.sessionId,
        caller: call.caller ?? this.caller ?? { agent: "unknown" },
        server: call.server ?? null,
        trust: call.trust ?? null,
      },
    };
    return parseDecision(await this.request(body), "decide");
  }

  /** Resolve a deferred ask. The response is a final decision. */
  async resolve(ref: string, approved: boolean, approver?: string): Promise<Decision> {
    const body: Json = { op: "resolve", ref, approved };
    if (approver !== undefined) body.approver = approver;
    const decision = parseDecision(await this.request(body), "resolve");
    if (!approved && shouldDispatch(decision)) {
      throw new ProvioProtocolError("gateway returned dispatch:true for a rejected ask");
    }
    return decision;
  }

  /** Record the execution of a dispatched call. For redact, `output` in the result is the redacted text. */
  async complete(ref: string, input: CompleteInput): Promise<CompleteResult> {
    const body: Json = { op: "complete", ref, ok: input.ok };
    if (input.exit !== undefined) body.exit = input.exit;
    if (input.output !== undefined) body.output = input.output;
    const res = await this.request(body);
    if (res.recorded !== true) {
      throw new ProvioProtocolError("complete response is missing recorded:true");
    }
    if (res.output !== undefined && typeof res.output !== "string") {
      throw new ProvioProtocolError("complete response output is not a string");
    }
    return typeof res.output === "string" ? { recorded: true, output: res.output } : { recorded: true };
  }

  /**
   * decide, and for a deferred ask obtain an answer from `approver` and
   * `resolve` it. Returns the final decision; check `shouldDispatch`.
   * A missing, throwing, late or non-approving approver is a denial.
   */
  async authorize(call: ToolCallInput, options: AuthorizeOptions = {}): Promise<Decision> {
    const decision = await this.decide(call);
    if (decision.decision !== "ask" || decision.approval !== "required") return decision;
    if (decision.ref === undefined) throw new ProvioProtocolError("deferred ask is missing ref");
    const { approved, approver } = await runApprover(call, decision, options);
    return this.resolve(decision.ref, approved, approver);
  }

  /** Close stdin, wait briefly for provio to exit, then kill it. Idempotent. */
  async close(): Promise<void> {
    this.closed = true;
    const proc = this.proc;
    if (proc === undefined) return;
    await new Promise<void>((done) => {
      if (proc.exitCode !== null || proc.signalCode !== null) return done();
      const timer = setTimeout(() => {
        proc.kill();
        done();
      }, 2000);
      proc.once("exit", () => {
        clearTimeout(timer);
        done();
      });
      proc.stdin?.end();
    });
    this.failAll(new ProvioError("closed", "provio client closed"));
    this.proc = undefined;
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  // --- transport -----------------------------------------------------------

  private request(body: Json): Promise<Json> {
    if (this.closed) return Promise.reject(new ProvioError("closed", "provio client is closed"));
    if (this.broken !== undefined && this.options.respawn === false) return Promise.reject(this.broken);
    let proc: ChildProcess;
    try {
      proc = this.ensureProcess();
    } catch (err) {
      return Promise.reject(toProvioError(err));
    }
    const id = `r${++this.seq}`;
    const op = String(body.op);
    const line = JSON.stringify({ v: PROTOCOL_VERSION, id, ...body }) + "\n";
    return new Promise<Json>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.poison(new ProvioTimeoutError(`provio check did not answer ${op} ${id} within ${this.timeoutMs} ms`));
      }, this.timeoutMs);
      this.queue.push({ id, op, resolve, reject, timer });
      this.setRef(true);
      const stdin = proc.stdin;
      if (stdin === null || !stdin.writable) {
        this.poison(new ProvioProtocolError("provio check stdin is not writable"));
        return;
      }
      stdin.write(line);
    });
  }

  private ensureProcess(): ChildProcess {
    if (this.proc !== undefined) return this.proc;
    const launch = this.resolveLaunch();
    const args = [...launch.args, ...this.gatewayArgs()];
    const proc = spawn(launch.command, args, {
      cwd: this.options.cwd,
      env: this.options.env ?? process.env,
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
      windowsHide: true,
    });
    this.proc = proc;
    this.broken = undefined;
    this.buffer = "";
    this.stderrTail = "";
    proc.stdout?.setEncoding("utf8");
    proc.stderr?.setEncoding("utf8");
    proc.stdout?.on("data", (chunk: string) => {
      if (this.proc === proc) this.onData(chunk);
    });
    proc.stderr?.on("data", (chunk: string) => {
      this.stderrTail = (this.stderrTail + chunk).slice(-4096);
      this.options.onStderr?.(chunk);
    });
    proc.stdin?.on("error", (err) => {
      if (this.proc === proc) this.poison(new ProvioProtocolError(`provio check stdin failed: ${err.message}`, { cause: err }));
    });
    proc.on("error", (err) => {
      if (this.proc !== proc) return;
      const code = (err as NodeJS.ErrnoException).code;
      this.poison(
        code === "ENOENT" || code === "EACCES"
          ? new ProvioUnavailableError(`cannot start provio (${launch.command}): ${err.message}`, { cause: err })
          : new ProvioProtocolError(`provio check failed: ${err.message}`, { cause: err }),
      );
    });
    // "close" fires after stdout/stderr are drained, so the stderr tail is complete.
    proc.on("close", (code, signal) => {
      if (this.proc !== proc) return;
      const how = signal !== null ? `signal ${signal}` : `code ${String(code)}`;
      const tail = this.stderrTail.trim();
      this.poison(new ProvioProtocolError(`provio check exited (${how})${tail ? `: ${tail}` : ""}`));
    });
    return proc;
  }

  private resolveLaunch(): Launch {
    if (this.options.command !== undefined) {
      return { command: this.options.command, args: [...(this.options.args ?? [])] };
    }
    const launch = this.options.bin !== undefined ? launchFor(this.options.bin) : locateProvio(undefined, this.options.env ?? process.env);
    return { command: launch.command, args: [...launch.args, ...(this.options.args ?? [])] };
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    let nl: number;
    while ((nl = this.buffer.indexOf("\n")) >= 0) {
      const raw = this.buffer.slice(0, nl).replace(/\r$/, "");
      this.buffer = this.buffer.slice(nl + 1);
      if (raw.trim() === "") continue;
      this.onLine(raw);
      if (this.proc === undefined) return;
    }
    if (Buffer.byteLength(this.buffer, "utf8") > this.maxLineBytes) {
      this.poison(new ProvioProtocolError(`provio check response line exceeds ${this.maxLineBytes} bytes`));
    }
  }

  private onLine(raw: string): void {
    let msg: unknown;
    try {
      msg = JSON.parse(raw);
    } catch {
      this.poison(new ProvioProtocolError(`malformed line from provio check: ${truncate(raw)}`));
      return;
    }
    const head = this.queue[0];
    if (head === undefined) {
      this.poison(new ProvioProtocolError(`unsolicited line from provio check: ${truncate(raw)}`));
      return;
    }
    if (!isObject(msg) || msg.v !== PROTOCOL_VERSION || msg.id !== head.id) {
      this.poison(new ProvioProtocolError(`unexpected response (wanted v:1 id:${head.id}): ${truncate(raw)}`));
      return;
    }
    this.queue.shift();
    clearTimeout(head.timer);
    if (this.queue.length === 0) this.setRef(false);
    if (msg.error !== undefined) {
      const e = isObject(msg.error) ? msg.error : {};
      const code = typeof e.code === "string" ? e.code : "error";
      const message = typeof e.message === "string" ? e.message : "provio check returned an error";
      head.reject(new ProvioError(code, `provio ${head.op} failed (${code}): ${message}`));
      return;
    }
    head.resolve(msg);
  }

  /** Fail every in-flight request and drop the process (fail closed). */
  private poison(error: ProvioError): void {
    const proc = this.proc;
    this.proc = undefined;
    this.broken = error;
    this.buffer = "";
    if (proc !== undefined && proc.exitCode === null && proc.signalCode === null) {
      proc.kill();
    }
    this.failAll(error);
  }

  private failAll(error: ProvioError): void {
    const pending = this.queue;
    this.queue = [];
    for (const p of pending) {
      clearTimeout(p.timer);
      p.reject(error);
    }
  }

  /** Keep the event loop alive only while requests are in flight. */
  private setRef(on: boolean): void {
    const proc = this.proc;
    if (proc === undefined) return;
    const method = on ? "ref" : "unref";
    proc[method]();
    for (const s of [proc.stdin, proc.stdout, proc.stderr]) {
      const handle = s as unknown as { ref?: () => void; unref?: () => void } | null;
      handle?.[method]?.();
    }
  }
}

// --- helpers ---------------------------------------------------------------

async function runApprover(
  call: ToolCallInput,
  decision: Decision,
  options: AuthorizeOptions,
): Promise<{ approved: boolean; approver: string }> {
  const approver = options.approver;
  if (approver === undefined) return { approved: false, approver: "adapter:no-approver" };
  const limit = decision.timeout_ms ?? options.approvalTimeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS;
  const controller = new AbortController();
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<"timeout">((done) => {
    timer = setTimeout(() => {
      controller.abort();
      done("timeout");
    }, limit);
  });
  try {
    const answer = await Promise.race([
      Promise.resolve().then(() => approver({ call, decision, signal: controller.signal })),
      timeout,
    ]);
    if (answer === "timeout") return { approved: false, approver: "adapter:approval-timeout" };
    if (answer === true) return { approved: true, approver: "adapter:approver" };
    if (isObject(answer) && answer.approved === true) {
      return { approved: true, approver: typeof answer.approver === "string" ? answer.approver : "adapter:approver" };
    }
    const who = isObject(answer) && typeof answer.approver === "string" ? answer.approver : "adapter:approver";
    return { approved: false, approver: who };
  } catch {
    return { approved: false, approver: "adapter:approver-error" };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function parseDecision(msg: Json, op: "decide" | "resolve"): Decision {
  const kind = msg.decision;
  if (typeof kind !== "string" || !DECISIONS.has(kind)) {
    throw new ProvioProtocolError(`${op} response has no valid decision`);
  }
  if (typeof msg.dispatch !== "boolean") {
    throw new ProvioProtocolError(`${op} response has no boolean dispatch`);
  }
  const decision: Decision = { decision: kind as DecisionKind, dispatch: msg.dispatch };
  // A decision that contradicts itself is not trusted.
  if (kind === "deny" && msg.dispatch) throw new ProvioProtocolError(`${op}: deny with dispatch:true`);
  if (op === "decide" && kind === "ask" && msg.dispatch) throw new ProvioProtocolError("decide: ask with dispatch:true");
  if (op === "decide" && (kind === "allow" || kind === "redact") && !msg.dispatch) {
    throw new ProvioProtocolError(`decide: ${kind} with dispatch:false`);
  }
  if (typeof msg.ref === "string") decision.ref = msg.ref;
  if (typeof msg.rule_id === "string") decision.rule_id = msg.rule_id;
  if (typeof msg.reason === "string") decision.reason = msg.reason;
  if (typeof msg.location === "string") decision.location = msg.location;
  if (msg.approval === "required") decision.approval = "required";
  if (typeof msg.irreversible === "boolean") decision.irreversible = msg.irreversible;
  if (typeof msg.timeout_ms === "number") decision.timeout_ms = msg.timeout_ms;
  if (Array.isArray(msg.patterns)) decision.patterns = msg.patterns.filter((p): p is string => typeof p === "string");
  if (decision.dispatch && decision.ref === undefined) {
    throw new ProvioProtocolError(`${op}: dispatching decision is missing ref`);
  }
  return decision;
}

function isObject(v: unknown): v is Json {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function truncate(s: string): string {
  return s.length > 200 ? `${s.slice(0, 200)}...` : s;
}

function toProvioError(err: unknown): ProvioError {
  if (err instanceof ProvioError) return err;
  const message = err instanceof Error ? err.message : String(err);
  return new ProvioUnavailableError(`cannot start provio: ${message}`, { cause: err });
}
