//! `writ check`: the hook gateway (INTERFACES.md Contract 6).
//!
//! One integration primitive for every agent that exposes a pre-tool hook:
//! SDK adapters speak `--format writ` (one-shot or `--stdio` JSON lines),
//! Claude Code's command hooks speak `--format claude-code`. There is no
//! daemon; every piece of state that must survive between two `writ check`
//! processes lives in the ledger.
//!
//! # Fail closed, everywhere
//!
//! Every error path answers "do not dispatch": `--format writ` returns an
//! `error` response and exits `1` (one-shot); `--format claude-code` prints a
//! `permissionDecision: "deny"` and exits `2`, because Claude Code treats
//! every exit code other than 2 without a valid decision as a *non-blocking*
//! error and would run the tool. Nothing is dispatched before its decision
//! record is durable.
//!
//! # Ledger semantics
//!
//! - `decide` writes exactly one `Decision` record, carrying the engine's
//!   verdict (as `handle_call` does). With `--ask deny` an `ask` is recorded
//!   with the fail-closed approver's identity and answered `deny`.
//! - **Deferred asks** (`--ask defer`): the `Decision` record (verdict `Ask`,
//!   no approver) is written at `decide` time, so an ask that is never
//!   resolved — the adapter crashed, the human walked away — is still on
//!   the record. `resolve` writes nothing: it re-validates the ref against
//!   the ledger, enforces the rule's `timeout_ms` (measured from the
//!   decision's `recorded_at`; late approvals are denials, Contract 5), and
//!   returns the final decision. An approval returns a *new* ref that also
//!   carries the approver identity; the `complete` for that ref writes the
//!   `Execution` record with `approver` set, which is the ledger's evidence
//!   of who authorised the dispatch. A rejection dispatches nothing, so the
//!   ledger shows the ask with no linked execution. This keeps "exactly one
//!   Decision record per call" and the frozen v1 record schema intact.
//!   `complete` on a ref for an ask that was not approved is an error.
//! - `complete` writes exactly one `Execution` record (`decision_index`
//!   linking back). The output is hashed (`output_hash`), never stored. For
//!   a `redact` verdict the output is masked with the same rule as the MCP
//!   proxy (every regex match becomes `[redacted-by-writ]`) after the hash
//!   of the original is recorded; an invalid pattern is an error, never an
//!   unmasked pass-through. A second `complete` for the same decision is an
//!   error.
//! - Appends go through `writ_ledger::retry_append`, which rebuilds a record
//!   on the new tip when another process won the race for it (many
//!   `writ check` processes share one ledger; the store serializes them).
//!
//! # Refs
//!
//! One-shot mode spans processes, so a ref is self-contained:
//! `w1.<decision index>.<decision record_hash>` plus, after an approval,
//! `.<tui|oob|rbac>.<hex approver id>`. It is never trusted on its own: the
//! record at that index must exist, be a `Decision`, and carry exactly that
//! hash. Anything else is `bad_ref`.
//!
//! # `--format claude-code`
//!
//! Protocol as documented at <https://code.claude.com/docs/en/hooks>
//! (formerly docs.claude.com/en/docs/claude-code/hooks):
//!
//! - `PreToolUse` → decide. Output is
//!   `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":…,"permissionDecisionReason":…}}`.
//!   `allow`/`redact` → `"allow"` (exit 0); `ask` → `"ask"` (Claude Code's
//!   own permission prompt, exit 0) with `--ask defer`, `"deny"` with
//!   `--ask deny`; `deny` and every error → `"deny"` + exit 2 (exit 2 blocks
//!   even if the JSON were lost).
//! - `PostToolUse` / `PostToolUseFailure` → complete, correlated to the
//!   `PreToolUse` decision by `(session_id, tool_use_id)` through the ledger
//!   (`call_id = tool_use_id`). Execution `exit_status` is 0 for
//!   `PostToolUse`, the `Exit code N` of the `error` text (else 1) for
//!   `PostToolUseFailure`; the output hash covers the JSON `tool_response`
//!   (or the `error` text). A `redact` verdict returns
//!   `hookSpecificOutput.updatedToolOutput`: the `tool_response` with every
//!   string leaf masked (shape preserved, as Claude Code requires). If the
//!   decision cannot be found or masking fails, every string leaf is masked
//!   (fail closed) and the hook exits 2. `PostToolUseFailure` output cannot
//!   be replaced by a hook, so a redacted tool's *error* text is not masked.
//! - An `ask` that Claude Code's prompt approved shows up only as the
//!   `PostToolUse` for that call; its execution record carries approver
//!   `{kind: tui, id: "claude-code-prompt"}`.
//!
//! Tool mapping (identical to `adapters/python/src/writ_agent/toolmap.py`
//! and the TypeScript adapter's `mapClaudeTool`). The original `tool_input`
//! is kept; a normalized `path` is added when the native key differs.
//!
//! | Claude Code tool                          | writ `tool`  | policy fields from args            |
//! |-------------------------------------------|--------------|------------------------------------|
//! | `Bash`, `PowerShell`                      | `bash`       | `command`                          |
//! | `Read`, `Glob`, `Grep`, `LS`, `NotebookRead` | `fs.read` | `path` (from `file_path`/`path`)   |
//! | `Write`, `Edit`, `MultiEdit`, `NotebookEdit` | `fs.write` | `path` (from `file_path`/`notebook_path`) |
//! | `WebFetch`                                | `http`       | `url` → `url.host`                 |
//! | `WebSearch`                               | `web.search` | `query`                            |
//! | `mcp__<server>__<tool>`                   | `<tool>`     | `server = <server>` (`mcp_server.name` if sent) |
//! | anything else                             | unchanged    | unchanged (policy default applies) |
//!
//! Caller: `agent = "claude-code"`, `user` from `USER`/`USERNAME`,
//! `non_human_id` = the payload's `agent_id` (subagents).

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use regex::Regex;
use serde_json::{json, Map, Value};
use writ_core::approver::{ApproverIdentity, ApproverKind, AskView, FailClosedApprover};
use writ_core::call::{CallerIdentity, InterceptMode, ServerIdentity, ToolCall, TrustVerdict};
use writ_core::ledger::{LedgerRecord, LedgerStore, LedgerWriter, RecordKind, SCHEMA_VERSION};
use writ_core::verdict::Verdict;
use writ_core::{Approver, Timestamp};
use writ_ledger::retry_append;
use writ_policy::NativePolicyEngine;

use crate::cmds::{emit_span, load_engine};

/// Wire format of `writ check`'s stdin/stdout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// writ's own JSON protocol (SDK adapters).
    Writ,
    /// Claude Code hook payloads (PreToolUse / PostToolUse).
    ClaudeCode,
    /// OpenAI Codex CLI hooks (PreToolUse / PostToolUse).
    Codex,
    /// Gemini CLI hooks (BeforeTool / AfterTool).
    Gemini,
    /// Cursor hooks (preToolUse / beforeMCPExecution / postToolUse /
    /// postToolUseFailure).
    Cursor,
    /// Windsurf Cascade hooks (pre_/post_ run_command, read_code,
    /// write_code, mcp_tool_use).
    Windsurf,
}

/// The other coding agents' hook formats (`hook/agents.rs`).
mod agents;
pub(crate) use agents::native_calls;

/// What an `ask` verdict does when `writ check` has no terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum AskMode {
    /// Fail closed: the call does not dispatch.
    Deny,
    /// Return `approval: "required"`; the agent's own UI asks the human.
    Defer,
    /// Wait for a human decision on the `writ ui` Approvals screen; fail
    /// closed on timeout, when no console is running, or on any error
    /// (see `ui::approvals`).
    Ui,
}

/// Protocol version this gateway speaks.
const PROTOCOL_V: u64 = 1;
/// Same replacement text as the MCP proxy's redaction transform.
const REDACTION_MARK: &str = "[redacted-by-writ]";
/// Ref prefix (ref format version 1).
const REF_PREFIX: &str = "w1";
/// Approver recorded when Claude Code's own permission prompt let an `ask` run.
const CLAUDE_PROMPT_APPROVER: &str = "claude-code-prompt";

/// Exit codes (Contract 6).
const EXIT_DISPATCH: i32 = 0;
const EXIT_ERROR: i32 = 1;
const EXIT_NO_DISPATCH: i32 = 2;

pub fn check(
    policy: &Path,
    ledger: &Path,
    yolo: bool,
    stdio: bool,
    format: Format,
    ask: AskMode,
) -> Result<()> {
    install_fail_closed_panic_hook(format);
    let mut gw = Gateway::new(policy, ledger, yolo, ask, format);
    let code = match (format, stdio) {
        (Format::Writ, true) => serve_stdio(&mut gw),
        (Format::Writ, false) => {
            let input = read_stdin();
            let (resp, code) = match input {
                Ok(s) if s.trim().is_empty() => (
                    error_response(Value::Null, &GwError::bad_request("empty request on stdin")),
                    EXIT_ERROR,
                ),
                Ok(s) => gw.handle_line(s.trim()),
                Err(e) => (
                    error_response(Value::Null, &GwError::bad_request(e)),
                    EXIT_ERROR,
                ),
            };
            emit_line(&resp);
            code
        }
        (Format::ClaudeCode, stdio) => {
            let out = if stdio {
                ClaudeOut::pre_error("--stdio is not supported with --format claude-code")
            } else {
                match read_stdin() {
                    Ok(s) => gw.claude_code(&s),
                    Err(e) => ClaudeOut::pre_error(&e),
                }
            };
            if !out.stderr.is_empty() {
                eprintln!("{}", out.stderr);
            }
            emit_line(&out.stdout);
            out.code
        }
        (Format::Codex | Format::Gemini | Format::Cursor | Format::Windsurf, stdio) => {
            agents::run(&mut gw, format, stdio)
        }
    };
    let _ = std::io::stdout().flush();
    std::process::exit(code);
}

/// A panic must never surface as Rust's default exit code 101: Claude Code
/// would treat that as a non-blocking hook error and run the tool. In
/// claude-code format a panic prints a deny decision and exits 2; in writ
/// format it exits 1 (the contract's error code).
fn install_fail_closed_panic_hook(format: Format) {
    std::panic::set_hook(Box::new(move |info| {
        let msg = format!("writ check panicked: {info}");
        match format {
            Format::ClaudeCode => {
                let out = ClaudeOut::pre_error(&msg);
                eprintln!("{}", out.stderr);
                emit_line(&out.stdout);
                std::process::exit(EXIT_NO_DISPATCH);
            }
            Format::Writ => {
                eprintln!("{msg}");
                std::process::exit(EXIT_ERROR);
            }
            // Each agent's own blocking answer (see `hook/agents.rs`).
            Format::Codex | Format::Gemini | Format::Cursor | Format::Windsurf => {
                let code = agents::emit(&agents::pre_error(format, &msg));
                std::process::exit(code);
            }
        }
    }));
}

fn read_stdin() -> std::result::Result<String, String> {
    let mut s = String::new();
    std::io::stdin()
        .read_to_string(&mut s)
        .map_err(|e| format!("cannot read stdin: {e}"))?;
    Ok(s)
}

fn emit_line(v: &Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

/// `--stdio`: one response line per request line, in order, until EOF.
/// Blank lines are not requests and get no response.
fn serve_stdio(gw: &mut Gateway) -> i32 {
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => return EXIT_DISPATCH,
            Ok(_) => {}
            Err(e) => {
                eprintln!("writ check: stdin read failed: {e}");
                return EXIT_ERROR;
            }
        }
        let resp = match std::str::from_utf8(&buf) {
            Ok(line) if line.trim().is_empty() => continue,
            Ok(line) => gw.handle_line(line.trim()).0,
            Err(_) => error_response(
                Value::Null,
                &GwError::bad_request("request line is not UTF-8"),
            ),
        };
        emit_line(&resp);
    }
}

// ---------------------------------------------------------------------------
// Errors

#[derive(Debug)]
struct GwError {
    code: &'static str,
    message: String,
}

impl GwError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        GwError {
            code,
            message: message.into(),
        }
    }
    fn bad_request(m: impl Into<String>) -> Self {
        Self::new("bad_request", m)
    }
    fn bad_ref(m: impl Into<String>) -> Self {
        Self::new("bad_ref", m)
    }
    fn ledger(e: impl std::fmt::Display) -> Self {
        Self::new("ledger_error", format!("{e}"))
    }
    fn state(m: impl Into<String>) -> Self {
        Self::new("invalid_state", m)
    }
}

fn error_response(id: Value, e: &GwError) -> Value {
    json!({"v": PROTOCOL_V, "id": id, "error": {"code": e.code, "message": e.message}})
}

// ---------------------------------------------------------------------------
// Gateway core (shared by both formats)

struct Gateway {
    engine: std::result::Result<NativePolicyEngine, String>,
    store: Option<Box<dyn LedgerStore>>,
    ledger_path: PathBuf,
    ask: AskMode,
    backend: &'static str,
}

/// The outcome of one `decide`.
struct Decided {
    call: ToolCall,
    /// Engine verdict (what the ledger recorded).
    verdict: Verdict,
    record: LedgerRecord,
}

/// A decision record located through a ref or a Claude Code correlation key.
struct Located {
    record: LedgerRecord,
    /// An `Execution` record already links this decision.
    executed: bool,
}

impl Gateway {
    fn new(policy: &Path, ledger: &Path, yolo: bool, ask: AskMode, format: Format) -> Self {
        Gateway {
            engine: load_engine(policy, yolo).map_err(|e| e.to_string()),
            store: None,
            ledger_path: ledger.to_path_buf(),
            ask,
            backend: match format {
                Format::Writ => "sdk-hook",
                Format::ClaudeCode => "claude-code",
                Format::Codex => "codex",
                Format::Gemini => "gemini-cli",
                Format::Cursor => "cursor",
                Format::Windsurf => "windsurf",
            },
        }
    }

    fn engine(&self) -> std::result::Result<&NativePolicyEngine, GwError> {
        self.engine
            .as_ref()
            .map_err(|e| GwError::new("policy_error", e.clone()))
    }

    /// Opened on first use; a failed open is retried on the next request.
    fn store(&mut self) -> std::result::Result<&mut dyn LedgerStore, GwError> {
        if self.store.is_none() {
            let s = writ_ledger::open_store(&self.ledger_path).map_err(GwError::ledger)?;
            self.store = Some(s);
        }
        Ok(self.store.as_deref_mut().expect("opened above"))
    }

    /// Evaluate, record exactly one decision record, return the outcome.
    fn decide_call(&mut self, call: ToolCall) -> std::result::Result<Decided, GwError> {
        // The call's own verdict, made stricter by the lines of any script
        // it runs or writes (see `inspect`).
        let verdict = crate::inspect::evaluate(self.engine()?, &call);
        // `--ask deny`: the headless fail-closed approver answers, and its
        // identity is recorded with the ask (as `handle_call` does).
        let approver = match (&verdict, self.ask) {
            // `--ask ui` records the ask with no approver (like `defer`):
            // the console's approval is evidenced by the execution record.
            (Verdict::Ask { .. }, AskMode::Deny) => {
                let view = AskView::from_verdict(&verdict).expect("ask verdict");
                let outcome = FailClosedApprover
                    .request(&call, &view)
                    .map_err(|e| GwError::new("internal", e.to_string()))?;
                Some(outcome.approver)
            }
            _ => None,
        };
        let store = self.store()?;
        let record = retry_append(|| {
            LedgerWriter::new(&mut *store).record_decision(&call, &verdict, approver.clone())
        })
        .map_err(GwError::ledger)?;
        emit_span(&self.ledger_path, &call, &verdict);
        Ok(Decided {
            call,
            verdict,
            record,
        })
    }

    /// Scan the ledger for the last decision matching `pred`, noting whether
    /// an execution record already links it.
    fn locate(
        &mut self,
        pred: impl Fn(&LedgerRecord) -> bool,
    ) -> std::result::Result<Option<Located>, GwError> {
        let store = self.store()?;
        let mut found: Option<Located> = None;
        for item in store.iter() {
            let rec = item.map_err(GwError::ledger)?;
            match rec.kind {
                RecordKind::Decision if pred(&rec) => {
                    found = Some(Located {
                        record: rec,
                        executed: false,
                    })
                }
                RecordKind::Execution => {
                    if let Some(f) = found.as_mut() {
                        if rec.decision_index == Some(f.record.index) {
                            f.executed = true;
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(found)
    }

    /// Resolve a ref to its decision record, validated against the ledger.
    fn locate_ref(&mut self, r: &ParsedRef) -> std::result::Result<Located, GwError> {
        let (index, hash) = (r.index, r.hash.clone());
        let found = self.locate(|rec| rec.index == index)?;
        match found {
            Some(l) if l.record.record_hash == hash => Ok(l),
            _ => Err(GwError::bad_ref(
                "ref does not name a decision record in this ledger",
            )),
        }
    }

    /// Write the one execution record for `decision`.
    fn record_execution(
        &mut self,
        decision: &LedgerRecord,
        approver: Option<ApproverIdentity>,
        exit_status: i32,
        output: &[u8],
    ) -> std::result::Result<LedgerRecord, GwError> {
        let backend = self.backend;
        let store = self.store()?;
        retry_append(|| match &approver {
            None => LedgerWriter::new(&mut *store).record_execution(
                decision,
                backend,
                exit_status,
                output,
            ),
            // `LedgerWriter::record_execution` never sets `approver`; this is
            // the same record with the approval evidence filled in.
            Some(a) => {
                let (index, prev_hash) = match store.tip()? {
                    Some(t) => (t.index + 1, t.record_hash),
                    None => (0, writ_core::ledger::GENESIS_HASH.to_string()),
                };
                let mut rec = LedgerRecord {
                    schema_version: SCHEMA_VERSION,
                    kind: RecordKind::Execution,
                    index,
                    call_id: decision.call_id.clone(),
                    session_id: decision.session_id.clone(),
                    call: None,
                    verdict: None,
                    rule_id: decision.rule_id.clone(),
                    approver: Some(a.clone()),
                    decision_index: Some(decision.index),
                    backend: Some(backend.to_string()),
                    exit_status: Some(exit_status),
                    input_hash: decision.input_hash.clone(),
                    output_hash: Some(LedgerRecord::hash_bytes(output)),
                    recorded_at: Timestamp::now(),
                    prev_hash,
                    record_hash: String::new(),
                };
                rec.record_hash = rec.compute_hash()?;
                store.append(&rec)?;
                Ok(rec)
            }
        })
        .map_err(GwError::ledger)
    }

    // -----------------------------------------------------------------------
    // --format writ

    fn handle_line(&mut self, line: &str) -> (Value, i32) {
        let req: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                return (
                    error_response(
                        Value::Null,
                        &GwError::bad_request(format!("malformed JSON: {e}")),
                    ),
                    EXIT_ERROR,
                )
            }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        match self.handle_request(&req) {
            Ok((mut body, code)) => {
                body.insert("v".into(), json!(PROTOCOL_V));
                body.insert("id".into(), id);
                (Value::Object(body), code)
            }
            Err(e) => (error_response(id, &e), EXIT_ERROR),
        }
    }

    fn handle_request(
        &mut self,
        req: &Value,
    ) -> std::result::Result<(Map<String, Value>, i32), GwError> {
        let obj = req
            .as_object()
            .ok_or_else(|| GwError::bad_request("request must be a JSON object"))?;
        match obj.get("v").and_then(Value::as_u64) {
            Some(PROTOCOL_V) => {}
            Some(v) => {
                return Err(GwError::bad_request(format!(
                    "unsupported protocol version {v} (this writ speaks v{PROTOCOL_V})"
                )))
            }
            None => return Err(GwError::bad_request("missing protocol version \"v\"")),
        }
        match obj.get("op").and_then(Value::as_str) {
            Some("decide") => self.op_decide(obj),
            Some("resolve") => self.op_resolve(obj),
            Some("complete") => self.op_complete(obj),
            Some(other) => Err(GwError::new(
                "unknown_op",
                format!("unknown op {other:?} (expected decide, resolve or complete)"),
            )),
            None => Err(GwError::bad_request("missing \"op\"")),
        }
    }

    fn op_decide(
        &mut self,
        obj: &Map<String, Value>,
    ) -> std::result::Result<(Map<String, Value>, i32), GwError> {
        let call = parse_call(obj.get("call"))?;
        let d = self.decide_call(call)?;
        let mut r = make_ref(&d.record, None);
        let mut body = Map::new();
        body.insert("call_id".into(), json!(d.call.call_id));
        let dispatch = match &d.verdict {
            Verdict::Allow { rule_id } => {
                body.insert("decision".into(), json!("allow"));
                body.insert("rule_id".into(), json!(rule_id));
                true
            }
            Verdict::Redact { rule_id, patterns } => {
                body.insert("decision".into(), json!("redact"));
                body.insert("rule_id".into(), json!(rule_id));
                body.insert("patterns".into(), json!(patterns));
                true
            }
            Verdict::Deny {
                rule_id,
                reason,
                location,
            } => {
                insert_deny(&mut body, rule_id, reason, location.as_deref());
                false
            }
            Verdict::Ask {
                rule_id,
                diff,
                timeout_ms,
                irreversible,
                location,
            } => match self.ask {
                AskMode::Ui => {
                    match crate::ui::approvals::await_decision(
                        &self.ledger_path,
                        &d.record,
                        "writ",
                        None,
                    ) {
                        crate::ui::approvals::UiDecision::Approved(who) => {
                            body.insert("decision".into(), json!("allow"));
                            body.insert("rule_id".into(), json!(rule_id));
                            body.insert("approver".into(), json!(who.id));
                            // Like a resolve-time ref: `complete` records
                            // the approver on the execution record.
                            r = make_ref(&d.record, Some(&who));
                            true
                        }
                        crate::ui::approvals::UiDecision::Denied(reason) => {
                            insert_deny(&mut body, rule_id, &reason, location.as_deref());
                            body.insert("verdict".into(), json!("ask"));
                            false
                        }
                    }
                }
                AskMode::Deny => {
                    let reason = format!(
                        "rule \"{rule_id}\" requires human approval; `writ check --ask deny` has no approver (fail closed)"
                    );
                    insert_deny(&mut body, rule_id, &reason, location.as_deref());
                    body.insert("verdict".into(), json!("ask"));
                    false
                }
                AskMode::Defer => {
                    body.insert("decision".into(), json!("ask"));
                    body.insert("approval".into(), json!("required"));
                    body.insert("rule_id".into(), json!(rule_id));
                    body.insert("reason".into(), json!(diff));
                    body.insert("irreversible".into(), json!(irreversible));
                    if let Some(t) = timeout_ms {
                        body.insert("timeout_ms".into(), json!(t));
                    }
                    if let Some(l) = location {
                        body.insert("location".into(), json!(l));
                    }
                    false
                }
            },
        };
        body.insert("dispatch".into(), json!(dispatch));
        body.insert("ref".into(), json!(r));
        Ok((
            body,
            if dispatch {
                EXIT_DISPATCH
            } else {
                EXIT_NO_DISPATCH
            },
        ))
    }

    fn op_resolve(
        &mut self,
        obj: &Map<String, Value>,
    ) -> std::result::Result<(Map<String, Value>, i32), GwError> {
        let r = parse_ref(obj.get("ref"))?;
        if self.ask == AskMode::Ui {
            // Under `--ask ui` only the console decides; decide never
            // returns approval "required".
            return Err(GwError::state(
                "`--ask ui` takes approvals from the writ ui console only; resolve is not accepted",
            ));
        }
        if r.approver.is_some() {
            return Err(GwError::state("this ref is already resolved"));
        }
        let approved = obj
            .get("approved")
            .and_then(Value::as_bool)
            .ok_or_else(|| GwError::bad_request("resolve needs a boolean \"approved\""))?;
        let approver = match obj.get("approver") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if !s.trim().is_empty() => Some(parse_approver(s.trim())),
            Some(_) => {
                return Err(GwError::bad_request(
                    "\"approver\" must be a non-empty string",
                ))
            }
        };
        let located = self.locate_ref(&r)?;
        let rec = located.record;
        let Some(Verdict::Ask {
            rule_id,
            timeout_ms,
            location,
            ..
        }) = rec.verdict.clone()
        else {
            return Err(GwError::state(
                "resolve is only valid for a decide that returned approval \"required\"",
            ));
        };
        if rec.approver.is_some() {
            // Recorded with --ask deny: the fail-closed approver already answered.
            return Err(GwError::state(
                "this ask was already denied by the fail-closed approver (--ask deny)",
            ));
        }
        if located.executed {
            return Err(GwError::state("this call has already completed"));
        }
        let mut body = Map::new();
        body.insert("call_id".into(), json!(rec.call_id));
        let elapsed = Timestamp::now().epoch_ms() - rec.recorded_at.epoch_ms();
        let timed_out = timeout_ms.is_some_and(|t| elapsed > i64::try_from(t).unwrap_or(i64::MAX));
        let dispatch = if timed_out {
            let reason = format!(
                "approval for rule \"{rule_id}\" arrived after its {}ms timeout (fail closed)",
                timeout_ms.unwrap_or(0)
            );
            insert_deny(&mut body, &rule_id, &reason, location.as_deref());
            body.insert("ref".into(), json!(make_ref(&rec, None)));
            false
        } else if approved {
            let who = approver.unwrap_or(ApproverIdentity {
                kind: ApproverKind::OutOfBand,
                id: "unattributed".into(),
            });
            body.insert("decision".into(), json!("allow"));
            body.insert("rule_id".into(), json!(rule_id));
            body.insert("ref".into(), json!(make_ref(&rec, Some(&who))));
            true
        } else {
            let who = approver
                .map(|a| a.id)
                .unwrap_or_else(|| "unattributed".into());
            let reason = format!("denied by approver {who}");
            insert_deny(&mut body, &rule_id, &reason, location.as_deref());
            body.insert("ref".into(), json!(make_ref(&rec, None)));
            false
        };
        body.insert("dispatch".into(), json!(dispatch));
        Ok((
            body,
            if dispatch {
                EXIT_DISPATCH
            } else {
                EXIT_NO_DISPATCH
            },
        ))
    }

    fn op_complete(
        &mut self,
        obj: &Map<String, Value>,
    ) -> std::result::Result<(Map<String, Value>, i32), GwError> {
        let r = parse_ref(obj.get("ref"))?;
        let ok = match obj.get("ok") {
            None | Some(Value::Null) => None,
            Some(Value::Bool(b)) => Some(*b),
            Some(_) => return Err(GwError::bad_request("\"ok\" must be a boolean")),
        };
        let exit = match obj.get("exit") {
            None | Some(Value::Null) => None,
            Some(v) => Some(
                v.as_i64()
                    .and_then(|n| i32::try_from(n).ok())
                    .ok_or_else(|| GwError::bad_request("\"exit\" must be a 32-bit integer"))?,
            ),
        };
        let exit_status = match (exit, ok) {
            (Some(e), _) => e,
            (None, Some(true)) => 0,
            (None, Some(false)) => 1,
            (None, None) => {
                return Err(GwError::bad_request(
                    "complete needs \"ok\" and/or \"exit\"",
                ))
            }
        };
        let output = match obj.get("output") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.as_str()),
            Some(_) => return Err(GwError::bad_request("\"output\" must be a string")),
        };
        let located = self.locate_ref(&r)?;
        if located.executed {
            return Err(GwError::state("this call has already completed"));
        }
        let rec = located.record;
        let patterns = match (&rec.verdict, &r.approver) {
            (Some(Verdict::Allow { .. }), None) => None,
            (Some(Verdict::Redact { patterns, .. }), None) => Some(patterns.clone()),
            (Some(Verdict::Ask { .. }), Some(_)) if rec.approver.is_none() => None,
            (Some(Verdict::Ask { .. }), _) => return Err(GwError::state(
                "complete for an ask that was not approved (send resolve first and use its ref)",
            )),
            (Some(Verdict::Deny { .. }), _) => {
                return Err(GwError::state("complete for a denied call"))
            }
            _ => {
                return Err(GwError::bad_ref(
                    "ref does not name a dispatchable decision",
                ))
            }
        };
        // Evidence first: the hash of the original output is recorded
        // before any masking is attempted.
        self.record_execution(
            &rec,
            r.approver.clone(),
            exit_status,
            output.unwrap_or("").as_bytes(),
        )?;
        let mut body = Map::new();
        body.insert("recorded".into(), json!(true));
        if let (Some(patterns), Some(out)) = (patterns, output) {
            let res = compile_patterns(&patterns)?;
            body.insert("output".into(), json!(mask_text(out, &res)));
        }
        Ok((body, EXIT_DISPATCH))
    }

    // -----------------------------------------------------------------------
    // --format claude-code

    fn claude_code(&mut self, input: &str) -> ClaudeOut {
        let payload: Value = match serde_json::from_str(input.trim()) {
            Ok(v @ Value::Object(_)) => v,
            Ok(_) => return ClaudeOut::pre_error("hook payload is not a JSON object"),
            Err(e) => return ClaudeOut::pre_error(&format!("malformed hook payload: {e}")),
        };
        // Cursor also runs the hooks in `.claude/settings.json` (its
        // "third-party hooks"), with Cursor payloads. Still fail closed,
        // but say what to do.
        if payload.get("cursor_version").is_some() {
            return ClaudeOut::pre_error(
                "this is a Cursor hook payload (Cursor also runs the Claude Code hooks in .claude/settings.json): run `writ integrate cursor` and turn off Cursor's third-party hook import, or remove writ's hooks from .claude/settings.json",
            );
        }
        let event = payload
            .get("hook_event_name")
            .and_then(Value::as_str)
            .unwrap_or("");
        match event {
            "PreToolUse" => self.cc_pre(&payload),
            "PostToolUse" | "PostToolUseFailure" => self.cc_post(&payload, event),
            other => ClaudeOut::pre_error(&format!(
                "unsupported hook_event_name {other:?} (writ handles PreToolUse, PostToolUse, PostToolUseFailure)"
            )),
        }
    }

    fn cc_pre(&mut self, p: &Value) -> ClaudeOut {
        let call = match cc_call(p) {
            Ok(c) => c,
            Err(e) => return ClaudeOut::pre_error(&e),
        };
        let d = match self.decide_call(call) {
            Ok(d) => d,
            Err(e) => return ClaudeOut::pre_error(&format!("{}: {}", e.code, e.message)),
        };
        match &d.verdict {
            Verdict::Allow { rule_id } => ClaudeOut::pre(
                "allow",
                &format!(
                    "writ: allowed by {}",
                    rule_id
                        .as_deref()
                        .map(|r| format!("rule \"{r}\""))
                        .unwrap_or_else(|| "the policy default".into())
                ),
                EXIT_DISPATCH,
            ),
            Verdict::Redact { rule_id, .. } => ClaudeOut::pre(
                "allow",
                &format!("writ: allowed by rule \"{rule_id}\"; matched output is redacted"),
                EXIT_DISPATCH,
            ),
            Verdict::Deny {
                rule_id,
                reason,
                location,
            } => ClaudeOut::pre(
                "deny",
                &format!(
                    "writ denied this: rule \"{rule_id}\" — {reason} ({})",
                    location.as_deref().unwrap_or("policy default")
                ),
                EXIT_NO_DISPATCH,
            ),
            Verdict::Ask {
                rule_id,
                diff,
                location,
                ..
            } => match self.ask {
                AskMode::Defer => ClaudeOut::pre(
                    "ask",
                    &format!(
                        "writ: rule \"{rule_id}\" ({}) needs your approval: {diff}",
                        location.as_deref().unwrap_or("policy default")
                    ),
                    EXIT_DISPATCH,
                ),
                // Bounded below Claude Code's own hook timeout: a hook that
                // times out there does not block the tool.
                AskMode::Ui => match crate::ui::approvals::await_decision(
                    &self.ledger_path,
                    &d.record,
                    "claude-code",
                    Some(crate::ui::approvals::CLAUDE_CODE_CAP_MS),
                ) {
                    crate::ui::approvals::UiDecision::Approved(who) => ClaudeOut::pre(
                        "allow",
                        &format!(
                            "writ: rule \"{rule_id}\" approved in the writ ui web console by {}",
                            who.id
                        ),
                        EXIT_DISPATCH,
                    ),
                    crate::ui::approvals::UiDecision::Denied(reason) => ClaudeOut::pre(
                        "deny",
                        &format!("writ denied this: {reason}"),
                        EXIT_NO_DISPATCH,
                    ),
                },
                AskMode::Deny => ClaudeOut::pre(
                    "deny",
                    &format!(
                        "writ denied this: rule \"{rule_id}\" requires human approval and none is available here (fail closed)"
                    ),
                    EXIT_NO_DISPATCH,
                ),
            },
        }
    }

    fn cc_post(&mut self, p: &Value, event: &str) -> ClaudeOut {
        let failure = event == "PostToolUseFailure";
        let response = p.get("tool_response").cloned().unwrap_or(Value::Null);
        // Unless we positively know the call was not redacted, a failure
        // here masks the whole tool output (fail closed).
        let fail = |msg: String, known_plain: bool| {
            let mut out = ClaudeOut::post_error(event, &msg);
            if !known_plain && !failure {
                out.stdout = post_json(event, Some(mask_all(&response)));
            }
            out
        };
        let (session, tool_use_id) = match (
            p.get("session_id").and_then(Value::as_str),
            p.get("tool_use_id").and_then(Value::as_str),
        ) {
            (Some(s), Some(t)) if !s.is_empty() && !t.is_empty() => (s.to_string(), t.to_string()),
            _ => {
                return fail(
                    "hook payload lacks session_id/tool_use_id; cannot correlate".into(),
                    false,
                )
            }
        };
        let located = match self.locate(|r| r.session_id == session && r.call_id == tool_use_id) {
            Ok(Some(l)) => l,
            Ok(None) => {
                let msg = format!("no writ decision recorded for {tool_use_id} in {session}");
                return fail(msg, false);
            }
            Err(e) => return fail(format!("{}: {}", e.code, e.message), false),
        };
        let rec = located.record;
        let patterns = match &rec.verdict {
            Some(Verdict::Redact { patterns, .. }) => Some(patterns.clone()),
            _ => None,
        };
        let plain = patterns.is_none();
        let approver = match &rec.verdict {
            Some(Verdict::Allow { .. }) | Some(Verdict::Redact { .. }) => None,
            // `--ask ui`: approved in the console, which says by whom.
            Some(Verdict::Ask { .. }) if rec.approver.is_none() && self.ask == AskMode::Ui => {
                match crate::ui::approvals::console_approval(&self.ledger_path, &rec) {
                    Some(who) => Some(who),
                    None => {
                        return fail(
                            format!(
                                "tool {tool_use_id} ran although the writ ui console did not approve it (rule {}); recorded nothing",
                                rec.rule_id.as_deref().unwrap_or("?")
                            ),
                            plain,
                        )
                    }
                }
            }
            // Deferred to Claude Code's prompt, and the tool ran: approved there.
            Some(Verdict::Ask { .. }) if rec.approver.is_none() => Some(ApproverIdentity {
                kind: ApproverKind::Tui,
                id: CLAUDE_PROMPT_APPROVER.into(),
            }),
            _ => {
                return fail(
                    format!(
                        "tool {tool_use_id} ran although writ did not allow it (rule {}); recorded nothing",
                        rec.rule_id.as_deref().unwrap_or("?")
                    ),
                    plain,
                )
            }
        };
        if located.executed {
            return fail(format!("tool {tool_use_id} was already completed"), plain);
        }
        let (exit, output) = if failure {
            let err = p.get("error").and_then(Value::as_str).unwrap_or("");
            (parse_exit_code(err), err.as_bytes().to_vec())
        } else {
            (0, serde_json::to_vec(&response).unwrap_or_default())
        };
        if let Err(e) = self.record_execution(&rec, approver, exit, &output) {
            return fail(format!("{}: {}", e.code, e.message), plain);
        }
        // The input that ran must be the input writ decided on (another
        // hook's `updatedInput` could have changed it).
        let mismatch = match (cc_call(p), &rec.call) {
            (Ok(now), Some(then)) => now.tool != then.tool || now.args != then.args,
            _ => false,
        };
        let updated = match (&patterns, failure) {
            (Some(pats), false) => match compile_patterns(pats) {
                Ok(res) => Some(mask_value(&response, &res)),
                Err(e) => return fail(e.message, false),
            },
            _ => None,
        };
        let mut out = ClaudeOut {
            stdout: post_json(event, updated),
            stderr: String::new(),
            code: EXIT_DISPATCH,
        };
        if mismatch {
            out.stderr = format!(
                "writ: tool {tool_use_id} ran with input that differs from the input writ decided on; the ledger records the decided input"
            );
            out.code = EXIT_NO_DISPATCH;
        }
        out
    }
}

fn insert_deny(body: &mut Map<String, Value>, rule_id: &str, reason: &str, location: Option<&str>) {
    body.insert("decision".into(), json!("deny"));
    body.insert("rule_id".into(), json!(rule_id));
    body.insert("reason".into(), json!(reason));
    if let Some(l) = location {
        body.insert("location".into(), json!(l));
    }
}

// ---------------------------------------------------------------------------
// Request parsing

static CALL_SEQ: AtomicU64 = AtomicU64::new(0);

fn generated_call_id() -> String {
    format!(
        "wc-{}-{}-{}",
        std::process::id(),
        Timestamp::now().epoch_ms(),
        CALL_SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

fn non_empty_str(v: Option<&Value>, field: &str) -> std::result::Result<Option<String>, GwError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if !s.is_empty() => Ok(Some(s.clone())),
        Some(_) => Err(GwError::bad_request(format!(
            "call.{field} must be a non-empty string"
        ))),
    }
}

/// Contract 6 `call` → `ToolCall` (`mode = SdkHook`, `captured_at` = now).
fn parse_call(v: Option<&Value>) -> std::result::Result<ToolCall, GwError> {
    let c = v
        .and_then(Value::as_object)
        .ok_or_else(|| GwError::bad_request("decide needs a \"call\" object"))?;
    let session_id = non_empty_str(c.get("session_id"), "session_id")?
        .ok_or_else(|| GwError::bad_request("call.session_id is required"))?;
    let tool = non_empty_str(c.get("tool"), "tool")?
        .ok_or_else(|| GwError::bad_request("call.tool is required"))?;
    let call_id = non_empty_str(c.get("call_id"), "call_id")?.unwrap_or_else(generated_call_id);
    let args = match c.get("args") {
        None | Some(Value::Null) => json!({}),
        Some(a) => a.clone(),
    };
    let caller = match c.get("caller") {
        None | Some(Value::Null) => CallerIdentity {
            agent: "unknown".into(),
            agent_version: None,
            user: None,
            non_human_id: None,
        },
        Some(v) => serde_json::from_value(v.clone())
            .map_err(|e| GwError::bad_request(format!("call.caller: {e}")))?,
    };
    let server: Option<ServerIdentity> = match c.get("server") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            serde_json::from_value(v.clone())
                .map_err(|e| GwError::bad_request(format!("call.server: {e}")))?,
        ),
    };
    let trust: Option<TrustVerdict> = match c.get("trust") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            serde_json::from_value(v.clone())
                .map_err(|e| GwError::bad_request(format!("call.trust: {e}")))?,
        ),
    };
    Ok(ToolCall {
        call_id,
        session_id,
        caller,
        mode: InterceptMode::SdkHook,
        tool,
        args,
        server,
        trust,
        captured_at: Timestamp::now(),
    })
}

/// A validated-syntax ref (ledger validation happens in `locate_ref`).
struct ParsedRef {
    index: u64,
    hash: String,
    approver: Option<ApproverIdentity>,
}

fn make_ref(rec: &LedgerRecord, approver: Option<&ApproverIdentity>) -> String {
    let mut r = format!("{REF_PREFIX}.{}.{}", rec.index, rec.record_hash);
    if let Some(a) = approver {
        let kind = match a.kind {
            ApproverKind::Tui => "tui",
            ApproverKind::OutOfBand => "oob",
            ApproverKind::Rbac => "rbac",
        };
        r.push_str(&format!(".{kind}.{}", hex_encode(a.id.as_bytes())));
    }
    r
}

fn parse_ref(v: Option<&Value>) -> std::result::Result<ParsedRef, GwError> {
    let s = v
        .and_then(Value::as_str)
        .ok_or_else(|| GwError::bad_request("missing \"ref\""))?;
    let bad = || GwError::bad_ref("malformed ref (pass back the ref writ returned, unchanged)");
    let parts: Vec<&str> = s.split('.').collect();
    if !(parts.len() == 3 || parts.len() == 5) || parts[0] != REF_PREFIX {
        return Err(bad());
    }
    let index: u64 = parts[1].parse().map_err(|_| bad())?;
    let hash = parts[2];
    if hash.len() != 64 || !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(bad());
    }
    let approver = if parts.len() == 5 {
        let kind = match parts[3] {
            "tui" => ApproverKind::Tui,
            "oob" => ApproverKind::OutOfBand,
            "rbac" => ApproverKind::Rbac,
            _ => return Err(bad()),
        };
        let id = hex_decode(parts[4])
            .and_then(|b| String::from_utf8(b).ok())
            .filter(|s| !s.is_empty())
            .ok_or_else(bad)?;
        Some(ApproverIdentity { kind, id })
    } else {
        None
    };
    Ok(ParsedRef {
        index,
        hash: hash.to_string(),
        approver,
    })
}

/// `"human:alice"` → TUI (a human at the agent's UI), `"rbac:…"` → RBAC,
/// anything else (`"oob:…"`, `"ci:…"`, `"sdk:canUseTool"`) → out-of-band
/// with the full string as id.
fn parse_approver(s: &str) -> ApproverIdentity {
    if let Some(id) = s.strip_prefix("human:").filter(|i| !i.is_empty()) {
        ApproverIdentity {
            kind: ApproverKind::Tui,
            id: id.to_string(),
        }
    } else if let Some(id) = s.strip_prefix("rbac:").filter(|i| !i.is_empty()) {
        ApproverIdentity {
            kind: ApproverKind::Rbac,
            id: id.to_string(),
        }
    } else {
        ApproverIdentity {
            kind: ApproverKind::OutOfBand,
            id: s.to_string(),
        }
    }
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Redaction (same replacement as the MCP proxy)

fn compile_patterns(patterns: &[String]) -> std::result::Result<Vec<Regex>, GwError> {
    patterns
        .iter()
        .map(|p| {
            Regex::new(p).map_err(|e| {
                GwError::new(
                    "policy_error",
                    format!("redact pattern {p:?} does not compile ({e}); output withheld (fail closed)"),
                )
            })
        })
        .collect()
}

fn mask_text(text: &str, res: &[Regex]) -> String {
    let mut out = text.to_string();
    for re in res {
        out = re.replace_all(&out, REDACTION_MARK).into_owned();
    }
    out
}

/// Mask every string leaf; keys and structure stay as they are.
fn mask_value(v: &Value, res: &[Regex]) -> Value {
    map_strings(v, &|s| mask_text(s, res))
}

/// Fail-closed mask: every string leaf is replaced.
fn mask_all(v: &Value) -> Value {
    if v.is_null() {
        return json!(REDACTION_MARK);
    }
    map_strings(v, &|_| REDACTION_MARK.to_string())
}

fn map_strings(v: &Value, f: &dyn Fn(&str) -> String) -> Value {
    match v {
        Value::String(s) => Value::String(f(s)),
        Value::Array(a) => Value::Array(a.iter().map(|x| map_strings(x, f)).collect()),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| (k.clone(), map_strings(x, f)))
                .collect(),
        ),
        other => other.clone(),
    }
}

// ---------------------------------------------------------------------------
// Claude Code mapping

struct ClaudeOut {
    stdout: Value,
    stderr: String,
    code: i32,
}

impl ClaudeOut {
    fn pre(decision: &str, reason: &str, code: i32) -> Self {
        ClaudeOut {
            stdout: json!({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }}),
            // Exit 2 blocks on stderr alone, should the JSON be lost.
            stderr: if code == EXIT_NO_DISPATCH {
                reason.to_string()
            } else {
                String::new()
            },
            code,
        }
    }

    /// Any failure before or while deciding: deny + exit 2 (blocks).
    fn pre_error(msg: &str) -> Self {
        Self::pre(
            "deny",
            &format!("writ error (fail closed, tool not run): {msg}"),
            EXIT_NO_DISPATCH,
        )
    }

    /// PostToolUse cannot un-run the tool; exit 2 shows stderr to Claude.
    fn post_error(event: &str, msg: &str) -> Self {
        ClaudeOut {
            stdout: post_json(event, None),
            stderr: format!("writ error: {msg}"),
            code: EXIT_NO_DISPATCH,
        }
    }
}

fn post_json(event: &str, updated: Option<Value>) -> Value {
    let mut hso = Map::new();
    hso.insert("hookEventName".into(), json!(event));
    if let Some(u) = updated {
        hso.insert("updatedToolOutput".into(), u);
    }
    json!({ "hookSpecificOutput": hso })
}

/// `"Exit code N"` on the first line of a PostToolUseFailure `error`, else 1.
fn parse_exit_code(err: &str) -> i32 {
    err.lines()
        .next()
        .and_then(|l| l.trim().strip_prefix("Exit code "))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(1)
}

/// Claude Code hook payload → `ToolCall` (see the mapping table above).
fn cc_call(p: &Value) -> std::result::Result<ToolCall, String> {
    let s = |k: &str| {
        p.get(k)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    let session_id = s("session_id").ok_or("hook payload lacks session_id")?;
    let tool_use_id = s("tool_use_id").ok_or("hook payload lacks tool_use_id")?;
    let tool_name = s("tool_name").ok_or("hook payload lacks tool_name")?;
    let input = match p.get("tool_input") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(_) => return Err("tool_input is not a JSON object".into()),
    };
    let mcp_server_name = p
        .get("mcp_server")
        .and_then(|m| m.get("name"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let (tool, args, server) = map_claude_tool(&tool_name, input, mcp_server_name);
    Ok(ToolCall {
        call_id: tool_use_id,
        session_id,
        caller: CallerIdentity {
            agent: "claude-code".into(),
            agent_version: None,
            user: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .ok(),
            non_human_id: s("agent_id"),
        },
        mode: InterceptMode::SdkHook,
        tool,
        args: Value::Object(args),
        server,
        trust: None,
        captured_at: Timestamp::now(),
    })
}

const FS_READ: &[&str] = &["Read", "Glob", "Grep", "LS", "NotebookRead"];
const FS_WRITE: &[&str] = &["Write", "Edit", "MultiEdit", "NotebookEdit"];

fn map_claude_tool(
    name: &str,
    mut args: Map<String, Value>,
    mcp_server_name: Option<String>,
) -> (String, Map<String, Value>, Option<ServerIdentity>) {
    if name == "Bash" || name == "PowerShell" {
        return ("bash".into(), args, None);
    }
    let is_read = FS_READ.contains(&name);
    if is_read || FS_WRITE.contains(&name) {
        if !args.get("path").is_some_and(Value::is_string) {
            let native = ["file_path", "notebook_path"]
                .iter()
                .find_map(|k| args.get(*k).and_then(Value::as_str).map(str::to_string));
            if let Some(p) = native {
                args.insert("path".into(), json!(p));
            }
        }
        let tool = if is_read { "fs.read" } else { "fs.write" };
        return (tool.into(), args, None);
    }
    match name {
        "WebFetch" => return ("http".into(), args, None),
        "WebSearch" => return ("web.search".into(), args, None),
        _ => {}
    }
    if let Some(rest) = name.strip_prefix("mcp__") {
        if let Some((server, tool)) = rest.split_once("__") {
            if !server.is_empty() && !tool.is_empty() {
                let server = ServerIdentity {
                    name: mcp_server_name.unwrap_or_else(|| server.to_string()),
                    transport: "unknown".into(),
                    version: None,
                };
                return (tool.to_string(), args, Some(server));
            }
        }
    }
    (name.to_string(), args, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(index: u64) -> LedgerRecord {
        LedgerRecord {
            schema_version: 1,
            kind: RecordKind::Decision,
            index,
            call_id: "c".into(),
            session_id: "s".into(),
            call: None,
            verdict: None,
            rule_id: None,
            approver: None,
            decision_index: None,
            backend: None,
            exit_status: None,
            input_hash: String::new(),
            output_hash: None,
            recorded_at: Timestamp::now(),
            prev_hash: String::new(),
            record_hash: "ab".repeat(32),
        }
    }

    #[test]
    fn refs_round_trip_and_reject_garbage() {
        let r = make_ref(&rec(7), None);
        let p = parse_ref(Some(&json!(r))).unwrap();
        assert_eq!(p.index, 7);
        assert!(p.approver.is_none());

        let who = ApproverIdentity {
            kind: ApproverKind::Tui,
            id: "alice.o'neil".into(),
        };
        let r = make_ref(&rec(3), Some(&who));
        let p = parse_ref(Some(&json!(r))).unwrap();
        assert_eq!(p.approver.unwrap(), who);

        for bad in [
            "",
            "w1",
            "w1.x.abc",
            "w2.1.abababababababababababababababababababababababababababababababab",
            "w1.1.ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB",
            "w1.1.abababababababababababababababababababababababababababababababab.god.00",
            "w1.1.abababababababababababababababababababababababababababababababab.tui.zz",
            "w1.1.abababababababababababababababababababababababababababababababab.tui.",
        ] {
            let e = parse_ref(Some(&json!(bad))).err().unwrap();
            assert_eq!(e.code, "bad_ref", "{bad}");
        }
    }

    #[test]
    fn approver_strings() {
        assert_eq!(parse_approver("human:alice").kind, ApproverKind::Tui);
        assert_eq!(parse_approver("human:alice").id, "alice");
        assert_eq!(parse_approver("rbac:ops").kind, ApproverKind::Rbac);
        let o = parse_approver("sdk:canUseTool");
        assert_eq!(
            (o.kind, o.id.as_str()),
            (ApproverKind::OutOfBand, "sdk:canUseTool")
        );
    }

    #[test]
    fn claude_tool_mapping() {
        let m = |name: &str, input: Value| {
            map_claude_tool(name, input.as_object().unwrap().clone(), None)
        };
        let (t, a, _) = m("Bash", json!({"command": "ls"}));
        assert_eq!((t.as_str(), a["command"].as_str()), ("bash", Some("ls")));
        let (t, _, _) = m("PowerShell", json!({"command": "dir"}));
        assert_eq!(t, "bash");
        let (t, a, _) = m("Read", json!({"file_path": "/x/.env"}));
        assert_eq!(
            (t.as_str(), a["path"].as_str()),
            ("fs.read", Some("/x/.env"))
        );
        assert_eq!(a["file_path"], "/x/.env", "original input kept");
        let (t, a, _) = m("NotebookEdit", json!({"notebook_path": "/n.ipynb"}));
        assert_eq!(
            (t.as_str(), a["path"].as_str()),
            ("fs.write", Some("/n.ipynb"))
        );
        let (t, a, _) = m("Grep", json!({"pattern": "x", "path": "/src"}));
        assert_eq!((t.as_str(), a["path"].as_str()), ("fs.read", Some("/src")));
        let (t, _, _) = m("WebFetch", json!({"url": "https://evil.example/x"}));
        assert_eq!(t, "http");
        let (t, _, _) = m("WebSearch", json!({"query": "q"}));
        assert_eq!(t, "web.search");
        let (t, _, s) = m("mcp__postgres__query", json!({"sql": "select 1"}));
        assert_eq!(
            (t.as_str(), s.unwrap().name.as_str()),
            ("query", "postgres")
        );
        let (t, _, s) = m("mcp__plugin_x_db__run__fast", json!({}));
        assert_eq!(
            (t.as_str(), s.unwrap().name.as_str()),
            ("run__fast", "plugin_x_db")
        );
        let (t, _, s) = m("mcp__broken", json!({}));
        assert_eq!((t.as_str(), s.is_none()), ("mcp__broken", true));
        let (t, _, _) = m("TodoWrite", json!({}));
        assert_eq!(t, "TodoWrite");
    }

    #[test]
    fn masking_preserves_shape() {
        let res = compile_patterns(&["\\d{3}-\\d{2}-\\d{4}".into()]).unwrap();
        let v = json!({"stdout": "ssn 123-45-6789", "n": 3, "list": ["123-45-6789"]});
        let m = mask_value(&v, &res);
        assert_eq!(m["stdout"], "ssn [redacted-by-writ]");
        assert_eq!(m["n"], 3);
        assert_eq!(m["list"][0], "[redacted-by-writ]");
        assert_eq!(mask_all(&v)["stdout"], "[redacted-by-writ]");
        assert!(compile_patterns(&["(".into()]).is_err());
    }

    #[test]
    fn exit_code_from_failure_text() {
        assert_eq!(parse_exit_code("Exit code 3\nboom"), 3);
        assert_eq!(parse_exit_code("could not start shell"), 1);
    }
}
