# INTERFACES.md — Frozen Contracts (Wave 0)

**Status: FROZEN.** Changes require an ADR in `docs/DECISIONS.md` and A0 sign-off.
The source of truth is code in `crates/writ-core`; this document is the map.

## Contract 1 — `ToolCall` envelope (`writ_core::call`)

Every interceptor (MCP proxy / process wrap / SDK hook) normalizes to `ToolCall`:
`call_id, session_id, caller: CallerIdentity, mode: InterceptMode, tool, args: Value, server: Option<ServerIdentity>, trust: Option<TrustVerdict>, captured_at`.

- Credentials NEVER appear in `args` — writ-mcp injects them at dispatch, after the ledger write.
- `ToolCallContext::from_call(&ToolCall)` produces the policy-evaluation vocabulary: `tool`, `command`, `path`, `url_host`, `query`, `server`, `trust`, `mode`, `agent`. DSL identifiers map: `url.host` → `url_host`, `server.trust` → `trust`.

## Contract 2 — `PolicyEngine` + `Verdict` IR (`writ_core::policy`, `writ_core::verdict`)

```rust
trait PolicyEngine { name(); evaluate(&ToolCallContext) -> Verdict; reload(&mut self, &str) -> Result<()>; rule_count(); }
```

`Verdict = Allow{rule_id?} | Deny{rule_id, reason, location?} | Ask{rule_id, diff, timeout_ms?, irreversible, location?} | Redact{rule_id, patterns}`.

- Engines always return a verdict; unmatched calls hit the policy's `default` (spec §7: `ask`, fail-closed; `--yolo` flips to `allow` at the CLI layer).
- `reload` is atomic: parse failure keeps the last-good policy.
- All engines (native, Rego, Cedar) must agree on `crates/writ-policy/fixtures/`.
- Denials MUST carry `rule_id`, human `reason`, and `location` (`writ.yaml:LINE`) — never "denied by policy" (spec §12).

## Contract 3 — `LedgerRecord` schema v1 (`writ_core::ledger`)

Frozen. Additive-only changes under bumped `schema_version`. `writ verify` validates every historical version forever.

- Two-phase records: exactly one `Decision` record per intercepted call (even if execution never starts); one linked `Execution` record per dispatched call (`decision_index` links back). Records are never mutated.
- `record_hash` = SHA-256 over the canonical payload (all fields except `record_hash`, serde_json struct order). `prev_hash` chains records; genesis = 64 zero hex chars.
- `LedgerStore`: `append / tip / get / len / iter`. `append` must reject a non-sequential index, a wrong `prev_hash`, or a `record_hash` that is not the record's own.
- Stores: `FileLedgerStore` (JSONL, default, everywhere; many concurrent writer processes via a `<ledger>.lock` file lock), `SqliteLedgerStore` (WAL, `sqlite` feature) and `PostgresLedgerStore` (`postgres` feature; `postgres://` / `postgresql://` locations; many hosts append one chain under a row lock; see [ledger-postgres.md](ledger-postgres.md)). All pass the same generic test suite and `verify_chain`. Every row holds the exact JSONL line, so records and hashes are store-independent. Locations are shown with `display_ledger`, which redacts a Postgres password; the CLI refuses to write a password into agent hook configuration or a `writ run` hook command line.
- Store selection: `writ_ledger::open_store(path)` / `detect_store_kind(path)` — content first (SQLite header), then extension (`.db`, `.sqlite`, `.sqlite3`), failing closed on a mismatch or when the `sqlite` feature is off. `verify(path)`, `sessions(path)` and `find_by_call_id(path)` use it; `verify_sqlite(path)` checks a database too damaged to open as a store.
- No content capture beyond call args by default; zero product telemetry.

## Contract 4 — `SandboxBackend` (`writ_core::sandbox`)

`name() / available() / prepare(SandboxSpec) -> SandboxId / exec(id, ExecRequest) -> ExecOutput / collect(id) -> Artifacts / teardown(id)`.
Backends: `local-os` (default), `docker`, `microsandbox`, `firecracker`/`e2b`, `k8s`. Optional and detected, never required (spec §12).

## Contract 5 — `Approver` (`writ_core::approver`)

`request(&ToolCall, &AskView) -> ApprovalOutcome`. Implementations: TUI (workstation), out-of-band (CI), RBAC (cluster). Timeout → `Deny` (fail closed). `ApprovalDecision = AllowOnce | AlwaysAllowRule | Deny | EditArgs(Value)`. `FailClosedApprover` ships in core for headless use.

## Contract 6 — Hook gateway (`writ check`)

The one integration primitive for agents that expose a pre-tool hook (SDK
adapters, Claude Code hooks, any future agent). No daemon: writ runs either
once per call or as a long-lived child process of the agent. Protocol
version `v: 1`; changes are additive only.

**Transport.**
- One-shot: `writ check [--format writ|claude-code]` reads one request from
  stdin, writes one response to stdout, exits. Exit code: `0` = dispatch,
  `2` = do not dispatch, `1` = writ error (callers treat 1 as do-not-dispatch).
- Long-lived: `writ check --stdio` reads newline-delimited JSON requests and
  writes one newline-delimited JSON response per request, in order, until
  stdin closes. stdout carries only protocol lines; diagnostics go to stderr.
- `--policy`/`--ledger` resolve as for every command. Many `writ check`
  processes may share one ledger concurrently (parallel tool calls); the
  ledger store serializes appends across processes.

**Decision** (additive, 0.1.3). The recorded verdict is the engine's verdict
for the call, made stricter by the commands hidden behind it (lines of a
script it runs or writes, heredocs by consumer, `package.json` scripts,
shell strings in code; [inspection.md](inspection.md)). Only an explicit
deny/ask rule of a hidden command counts, and only when stricter; its
`rule_id` and `location` are that rule's, and its `reason`/`diff` is
prefixed with where the command was found. Command-line rules evaluate the
command with heredoc bodies removed. The ledger records the call as sent.

**Requests** (`--format writ`, the adapter format):

```json
{"v":1,"id":"r1","op":"decide","call":{
  "call_id":"toolu_01","session_id":"thread-42","tool":"bash",
  "args":{"command":"ls"},
  "caller":{"agent":"langgraph","agent_version":"0.3","user":"alice"},
  "server":null,"trust":null}}
{"v":1,"id":"r2","op":"resolve","ref":"<ref from decide>","approved":true,"approver":"human:alice"}
{"v":1,"id":"r3","op":"complete","ref":"<ref>","ok":true,"exit":0,"output":"<tool result as text, optional>"}
```

- `call` fields mirror `ToolCall`; writ sets `mode = SdkHook` and
  `captured_at`. `call_id` is optional (writ generates one); `caller` defaults
  to `{"agent":"unknown"}`; `server`/`trust` use `ToolCall`'s JSON shapes.
  Adapters must never put credentials in `args`.
- `resolve` is only valid after a `decide` that returned `approval:"required"`.
- `complete` records the execution. `output` is hashed into the execution
  record and never stored; for a `redact` verdict writ returns the redacted
  text, which is what the adapter must hand back to the model.

**Responses:**

```json
{"v":1,"id":"r1","decision":"allow","dispatch":true,"rule_id":"read-only","ref":"..."}
{"v":1,"id":"r1","decision":"deny","dispatch":false,"rule_id":"no-rm","reason":"...","location":"writ.yaml:12","ref":"..."}
{"v":1,"id":"r1","decision":"ask","dispatch":false,"approval":"required","rule_id":"prod","reason":"<diff>","irreversible":true,"timeout_ms":60000,"ref":"..."}
{"v":1,"id":"r1","decision":"deny","dispatch":false,"verdict":"ask","rule_id":"prod","reason":"rule \"prod\" requires human approval; ...","location":"writ.yaml:20","ref":"..."}
{"v":1,"id":"r1","decision":"redact","dispatch":true,"rule_id":"pii","patterns":["\d{3}-\d{2}-\d{4}"],"ref":"..."}
{"v":1,"id":"r3","recorded":true,"output":"<redacted output, only for redact>"}
{"v":1,"id":"r1","error":{"code":"bad_request","message":"..."}}
```

- `ref` is opaque; pass it back unchanged. The `ref` in a `resolve`
  response supersedes the decide-time ref: `complete` for an approved ask
  must use the resolve-time ref (the decide-time ref of an ask is refused).
- The third example is `--ask defer`; the fourth is the same ask under the
  default `--ask deny`: `decision:"deny"` plus `verdict:"ask"`.
- `ask` handling is `--ask deny|defer` (default `deny`, fail-closed, since
  `writ check` has no terminal). With `defer`, `ask` comes back with
  `approval:"required"`; the adapter obtains a human decision through the
  agent's own UI and sends `resolve`, whose response is a final decision
  (`dispatch` true or false). An unresolved deferred ask never dispatches.
- Any `error`, malformed line, timeout, or missing writ binary is
  fail-closed in every adapter: the tool does not run.
- Ledger semantics are unchanged (Contract 3): exactly one Decision record
  per intercepted call, one Execution record per `complete`.

**Clarifications (additive, from the Wave 2 implementation in
`crates/writ-cli/src/hook.rs`).**
- *Deferred asks in the ledger.* The Decision record (engine verdict `ask`,
  `approver: null`) is written at `decide` time, so an ask that is never
  resolved is still on the record: an `ask` decision with no linked
  Execution record = never dispatched. `resolve` writes no record. An
  approval is evidenced by the Execution record written at `complete`,
  whose `approver` field carries the resolving approver (schema v1
  unchanged; `approver` is already a field of every record). A rejection
  writes nothing further. Under `--ask deny` the Decision record carries
  the fail-closed approver's identity, as `handle_call` does, and a
  `resolve` of it is `invalid_state`.
- *Resolve.* The response is final: `decision:"allow"`, `dispatch:true`
  (approved) or `decision:"deny"`, `dispatch:false` (rejected or timed
  out), never `"ask"`. `timeout_ms` counts from decide time (the Decision
  record's `recorded_at`, which has one-second precision, so a timeout can
  fire up to 1s early — never late). `approver` is optional:
  `"human:<id>"` is recorded as kind `tui`, `"rbac:<id>"` as `rbac`,
  anything else as `out_of_band` with the whole string as id; a missing
  approver is recorded as `out_of_band`/`"unattributed"`. Resolving an
  already-resolved ref, or a call that already completed, is `invalid_state`.
- *Complete.* Requires `ok` and/or `exit` (`exit_status` = `exit`, else 0
  for `ok:true`, 1 for `ok:false`). `output` is text (adapters
  JSON-stringify structured results); its SHA-256 is recorded, the text is
  not. For a `redact` verdict, `output` is always returned when `output`
  was sent — also for `ok:false` (failure text is masked too); masking
  replaces each regex match with the token `[redacted-by-writ]` (as the MCP
  proxy does); an invalid pattern is an `error`, never unmasked output. A second `complete` for the same decision, or a `complete` for a
  `deny` or an unapproved `ask`, is `invalid_state`.
- *Refs* are self-contained (`w1.<decision index>.<decision record_hash>`,
  plus the approver after an approval): they stay valid across processes
  and gateway restarts (an adapter may resolve/complete with a ref from a
  crashed `--stdio` child), and are validated against the ledger on every
  use: the record must exist, be a Decision, and carry that hash, else
  `bad_ref`.
- *Repeated `call_id`.* A second `decide` with a `call_id` already used in
  the session is a new intercepted call: it gets its own Decision record
  and a fresh ref (a retry is a real attempt), never a reuse of the earlier
  decision. Each ref completes at most once.
- *`--stdio`* is stateless between requests: one process keeps accepting
  requests while an earlier deferred ask waits for its `resolve`
  (adapters may pipeline). Blank lines get no response.
- *`id`* is echoed whenever the request parsed as JSON (`null` if absent);
  a malformed line is answered with `id: null`.
- *Error codes:* `bad_request`, `unknown_op`, `bad_ref`, `invalid_state`,
  `policy_error` (missing/invalid policy or redact pattern), `ledger_error`,
  `internal`.
- *Concurrency:* `FileLedgerStore` serializes appends with an exclusive
  lock on `<ledger>.lock` and checks each append against the tip on disk;
  writers retry lost races (`writ_ledger::retry_append`).

**`--format claude-code`.** stdin is a Claude Code hook payload
(`PreToolUse` → decide, `PostToolUse` → complete, keyed by `tool_use_id`
within `session_id`); stdout is Claude Code's hook JSON. A writ `ask` maps to
Claude Code's own permission prompt (`permissionDecision: "ask"`), `deny` to
`"deny"` with the rule's reason, `allow`/`redact` to `"allow"`.
`writ integrate claude-code` writes the hook entries into
`.claude/settings.json` (project) without disturbing existing settings.

Claude Code specifics (verified against https://code.claude.com/docs/en/hooks):
- Exit codes: the "`1` = writ error" rule above is for `--format writ`
  only. Claude Code treats any exit code other than 2 without a valid
  decision as a *non-blocking* error and runs the tool, so in this format
  every writ-side failure (malformed payload, missing or unparseable
  policy, ledger error, panic, ...) prints `permissionDecision:"deny"` when
  it can and always exits **2** with the reason on stderr; `deny` also
  exits 2; `allow`/`redact`/`ask` exit 0. Nothing in this format exits 1.
  On `PostToolUse`/`PostToolUseFailure` (the tool already ran) a failure to
  correlate or record exits 2 with stderr, which Claude Code shows to
  Claude. (A missing binary or a hook timeout is outside writ's control and
  does not block in Claude Code.)
- `PostToolUseFailure` is also handled (execution record with the
  `Exit code N` from `error`, else 1). `call_id = tool_use_id`; the
  `PostToolUse` is correlated to its decision through the ledger. An `ask`
  approved in Claude Code's prompt is evidenced by an Execution record with
  approver `{kind: tui, id: "claude-code-prompt"}`.
- `redact` returns `hookSpecificOutput.updatedToolOutput`: the
  `tool_response` with every string leaf masked (shape preserved). If the
  decision cannot be found or masking fails, every string leaf is masked and
  the hook exits 2. Failure (`PostToolUseFailure`) text cannot be replaced
  by a hook and is not masked.
- Tool mapping (same table as the Python/TypeScript adapters): `Bash`,
  `PowerShell` → `bash`; `Read`/`Glob`/`Grep`/`LS`/`NotebookRead` →
  `fs.read`; `Write`/`Edit`/`MultiEdit`/`NotebookEdit` → `fs.write` (a
  `path` arg is added from `file_path`/`notebook_path`); `WebFetch` → `http`;
  `WebSearch` → `web.search`; `mcp__<server>__<tool>` → `<tool>` with
  `server.name = <server>`; anything else keeps its name.
- The hook entries use exec form (`command` = absolute writ path, `args` =
  `--policy P --ledger L check --format claude-code --ask defer`) for
  `PreToolUse`, `PostToolUse` and `PostToolUseFailure`, matcher `*`.

**`--format codex|gemini|cursor|windsurf`** (`crates/writ-cli/src/hook/agents.rs`;
per-agent detail in [integrations/](integrations/)). Same ledger semantics as
claude-code: one Decision per pre event, one Execution per post event. Post
events correlate by the agent's tool-call id (Codex, Cursor `tool_use_id`),
otherwise by (session, tool, server, args), newest decision without an
execution (Gemini, Cursor MCP, Windsurf). When one call names several paths or
URLs, each is evaluated and the strictest verdict is recorded (the choice as
`path`/`url`, the full list as `paths`/`urls`). Every writ-side error returns
that agent's blocking answer; nothing exits 1.

- Codex (PreToolUse/PostToolUse): always exit 0; deny = `hookSpecificOutput.permissionDecision:"deny"` + stderr; allow prints nothing; `ask` fails closed (Codex has none); redact and every post error use `{"decision":"block","reason":…}`.
- Gemini (BeforeTool/AfterTool): deny = `{"decision":"deny"}` + exit 2; `--ask defer` → `{"decision":"ask"}` (approver `tui/gemini-cli-prompt`); redact via AfterTool `decision:"deny"` with the masked content as the reason.
- Cursor (preToolUse, beforeMCPExecution, postToolUse, postToolUseFailure; `failClosed:true`): deny = `permission:"deny"` + exit 0; MCP calls decided at beforeMCPExecution, where `ask` → `permission:"ask"` (approver `tui/cursor-prompt`); redact only for MCP (`updated_mcp_tool_output`), denied at pre for other tools.
- Windsurf (pre_/post_ run_command, read_code, write_code, mcp_tool_use): deny = exit 2 + stderr; ask and redact are denied.
- Outside writ's control: a missing binary or a hook timeout lets the tool run in Codex, Gemini and Windsurf (Cursor blocks via `failClosed`).
- `writ integrate codex|gemini|cursor|windsurf` writes `.codex/config.toml` (toml_edit, comments kept), `.gemini/settings.json`, `.cursor/hooks.json`, `.devin/hooks.json` (or legacy `.windsurf/hooks.json`) with the same guarantees as claude-code.

**`--ask ui`** (detail: [ui.md](ui.md#writ-check---ask-ui)). An `ask` waits for a
human on the `writ ui` Approvals screen: the Decision record is written first
(no approver), a pending request is queued, and the gateway polls for the
console's answer until the rule's `timeout` (default 120 s; capped at 55 s
for claude-code and Cursor, whose hook timeouts would otherwise not block).
Approval returns a final `allow` and the Execution record names
`{tui, "web-console:<user>"}`; a denial, timeout, no live console, or a
Postgres ledger (no local queue) is a `deny`. Console state lives in a
per-user directory outside every `writ run` writable path, so a confined agent
cannot approve its own asks. Supported by `--format writ`, claude-code, gemini
and cursor (MCP); the other formats deny. The Python and TypeScript SDKs take
`ask="ui"` and wait up to 180 s per `decide`.

## Contract 7 — Receipts (`writ_receipts`)

Specified in full in [receipts.md](receipts.md#contract-7--receipts-writ_receipts). A receipt (`writ.receipt/v1`) is an Ed25519ph signature over a canonical, domain-separated text rendering of a ledger checkpoint: ledger id (record 0's hash), record count, tip index and hash, an RFC 6962 Merkle root over record hashes, optional session scope, and `created_at`. `writ receipt verify` fails if any record at or before the checkpoint was edited, removed or rewritten, or the ledger was truncated; records appended later are allowed. Inclusion proofs (`writ.inclusion-proof/v1`) prove one call's records against a signed root without the ledger. Anchors sit outside the signature and carry their own proof: Sigstore Rekor `hashedrekord` entries (verified offline against a pinned log key) or an append-only file line.

## Pipeline (`writ_core::pipeline`)

`handle_call(call, policy, ledger, approver) -> DecisionOutcome` — evaluate → resolve ask via approver → write decision record → return. Dispatch (sandbox exec / MCP forwarding) happens in the caller AFTER `handle_call` returns and only when `outcome.should_dispatch()`. Execution completion → `record_execution(ledger, &decision_record, backend, exit, output)`.

## CLI surface (`writ-cli`)

`writ init [--agent A,B] [--strict] [--global] [--dry-run]` · `writ scan [--days N] [--agent claude-code,codex,gemini] [--packs A,B] [--dir PATH] [--format text|json|markdown]` · `writ test [--tool T --path P --url U --query Q --content C --server S | --call JSON] [--packs A,B] [--json] [<command>…]` (exit 0 allow/redact, 2 deny, 3 ask, 1 error) · `writ run [--yolo] [--policy PATH] [--net open|none] [--allow-write PATH]… [--unconfined] [--no-hooks] -- <agent cmd>` · `writ check [--stdio] [--format writ|claude-code|codex|gemini|cursor|windsurf] [--ask deny|defer|ui]` · `writ integrate <claude-code|codex|gemini|cursor|windsurf>` · `writ ui [--port N] [--no-open]` · `writ receipt keygen|create|verify|prove|anchor` · `writ proxy --mcp [--transport stdio|http --listen ADDR --upstream URL]` · `writ log` · `writ show <call-id>` · `writ verify [--ledger PATH]` · `writ replay <run-id>` · `writ policy test` · `writ policy add <pack>` · `writ doctor` · `writ report`. Ledger default path: `.writ/ledger.jsonl` (displayed as `ledger.db` once SQLite is enabled).
