//! `writ check --format codex|gemini|cursor|windsurf`: the hook gateway
//! (INTERFACES.md Contract 6) for the other coding agents with a
//! documented, blocking pre-tool hook.
//!
//! Every format keeps the Claude Code guarantees:
//!
//! - **Fail closed.** Every writ-side error (malformed payload, missing or
//!   unparseable policy, ledger error, panic) answers with the output the
//!   agent treats as *blocking*, and each agent's non-blocking failure
//!   modes are avoided:
//!   - Codex runs the tool on any exit code other than 0 (with valid
//!     JSON) or 2 (with a non-empty stderr), and PowerShell 5.1 turns a
//!     native exit code 2 into 1. So this format *always exits 0* with
//!     `permissionDecision: "deny"` JSON (and the reason on stderr).
//!   - Gemini CLI parses stdout JSON whatever the exit code, and exit 2
//!     blocks: a deny is `{"decision":"deny"}` + exit 2.
//!   - Cursor: `permission: "deny"` blocks, a lost or invalid answer from
//!     a permission hook blocks, and writ's hook entries set `failClosed`,
//!     so a crash, timeout or non-zero exit blocks too; a deny is
//!     `permission: "deny"` + exit 0 (exit codes do not survive every
//!     shell, JSON does).
//!   - Windsurf (Cascade): only exit 2 blocks; a deny is exit 2 + stderr.
//! - **One Decision + one Execution record per call.** Pre events decide;
//!   post events complete, correlated to the decision by the agent's
//!   tool-call id where the payload has one (Codex `tool_use_id`, Cursor
//!   `tool_use_id`), else by `(session, tool, args)`: the newest decision
//!   of that session for the same mapped call that has no execution yet
//!   (Gemini CLI, Cursor MCP, Windsurf).
//! - **ask** maps to the agent's own confirmation where one exists (Gemini
//!   CLI `decision: "ask"`, Cursor `beforeMCPExecution` `permission:
//!   "ask"`) with `--ask defer`; everywhere else it fails closed.
//! - **redact** replaces what the model sees where the agent lets a hook
//!   do that (Codex `PostToolUse` `decision: "block"` + reason, Gemini
//!   `AfterTool` `decision: "deny"` + reason, Cursor `postToolUse`
//!   `updated_mcp_tool_output` for MCP tools). Where it cannot (Cursor
//!   non-MCP tools, Windsurf), a `redact` verdict is denied up front:
//!   writ never lets output it promised to mask reach the model.
//! - A call that consists of several paths or URLs (a Codex `apply_patch`
//!   touching several files, a Gemini `read_many_files`, a `web_fetch`
//!   prompt with several URLs) is evaluated once per candidate and the
//!   strictest verdict is recorded, with the candidate that produced it as
//!   the call's `path`/`url` and the full list as `paths`/`urls`.

use std::path::Path;

use regex::Regex;
use serde_json::{json, Map, Value};
use writ_core::approver::{ApproverIdentity, ApproverKind};
use writ_core::call::{CallerIdentity, InterceptMode, ServerIdentity, ToolCall, ToolCallContext};
use writ_core::ledger::{LedgerRecord, RecordKind};
use writ_core::verdict::Verdict;
use writ_core::{PolicyEngine, Timestamp};

use super::{
    compile_patterns, generated_call_id, map_claude_tool, mask_all, mask_value, AskMode, Decided,
    Format, Gateway, GwError, EXIT_DISPATCH, EXIT_NO_DISPATCH,
};

/// What one hook invocation prints and exits with.
pub(super) struct HookOut {
    /// One JSON line on stdout (nothing when `None`).
    pub stdout: Option<Value>,
    pub stderr: String,
    pub code: i32,
}

/// Approver ids recorded when the agent's own prompt let an `ask` run.
const GEMINI_PROMPT_APPROVER: &str = "gemini-cli-prompt";
const CURSOR_PROMPT_APPROVER: &str = "cursor-prompt";

/// Keys writ may add to a call's args (normalized fields); ignored when a
/// post event's input is compared with the decided input.
const ADDED_KEYS: &[&str] = &["path", "url", "paths", "urls"];

/// Entry point from `hook::check` for the formats of this module.
pub(super) fn run(gw: &mut Gateway, format: Format, stdio: bool) -> i32 {
    let out = if stdio {
        pre_error(
            format,
            &format!(
                "--stdio is not supported with --format {}",
                format_name(format)
            ),
        )
    } else {
        match super::read_stdin() {
            Ok(s) => handle(gw, format, &s),
            Err(e) => pre_error(format, &e),
        }
    };
    emit(&out)
}

/// Print `out` (stderr first, then at most one ASCII-only JSON line) and
/// return its exit code.
pub(super) fn emit(out: &HookOut) -> i32 {
    if !out.stderr.is_empty() {
        eprintln!("{}", out.stderr);
    }
    if let Some(v) = &out.stdout {
        use std::io::Write;
        let mut o = std::io::stdout().lock();
        let _ = writeln!(o, "{}", ascii_json(v));
        let _ = o.flush();
    }
    out.code
}

/// JSON with every non-ASCII character escaped (`\uXXXX`): shells that
/// re-encode a native command's output (Windows PowerShell 5.1 decodes it
/// with the OEM code page) cannot corrupt it.
fn ascii_json(v: &Value) -> String {
    let s = v.to_string();
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut buf = [0u16; 2];
            for u in c.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{u:04x}"));
            }
        }
    }
    out
}

fn format_name(format: Format) -> &'static str {
    match format {
        Format::Codex => "codex",
        Format::Gemini => "gemini",
        Format::Cursor => "cursor",
        Format::Windsurf => "windsurf",
        Format::Writ => "writ",
        Format::ClaudeCode => "claude-code",
    }
}

/// Any failure before or while deciding: the agent's blocking answer.
pub(super) fn pre_error(format: Format, msg: &str) -> HookOut {
    deny(
        format,
        &format!("writ error (fail closed, tool not run): {msg}"),
    )
}

/// The blocking pre-tool answer of each agent.
fn deny(format: Format, reason: &str) -> HookOut {
    let reason = reason.to_string();
    match format {
        // Always exit 0: Codex honours the JSON under every shell, while a
        // non-zero exit could arrive as 1 (PowerShell 5.1) and not block.
        Format::Codex => HookOut {
            stdout: Some(json!({"hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }})),
            stderr: reason,
            code: EXIT_DISPATCH,
        },
        Format::Gemini => HookOut {
            stdout: Some(json!({"decision": "deny", "reason": reason})),
            stderr: reason,
            code: EXIT_NO_DISPATCH,
        },
        // Exit 0: Cursor honours `permission: "deny"` from any shell, and
        // for its permission hooks a lost or invalid JSON answer blocks
        // too; a non-zero code could arrive as 1 (PowerShell 5.1), which
        // blocks only because writ's entries set `failClosed`.
        Format::Cursor => HookOut {
            stdout: Some(json!({
                "permission": "deny",
                "user_message": reason,
                "agent_message": reason,
            })),
            stderr: reason,
            code: EXIT_DISPATCH,
        },
        // Windsurf reads only the exit code and stderr.
        _ => HookOut {
            stdout: None,
            stderr: reason,
            code: EXIT_NO_DISPATCH,
        },
    }
}

fn handle(gw: &mut Gateway, format: Format, input: &str) -> HookOut {
    let payload: Value = match serde_json::from_str(input.trim()) {
        Ok(v @ Value::Object(_)) => v,
        Ok(_) => return pre_error(format, "hook payload is not a JSON object"),
        Err(e) => return pre_error(format, &format!("malformed hook payload: {e}")),
    };
    match format {
        Format::Codex => codex(gw, &payload),
        Format::Gemini => gemini(gw, &payload),
        Format::Cursor => cursor(gw, &payload),
        Format::Windsurf => windsurf(gw, &payload),
        _ => pre_error(format, "internal: not an agent hook format"),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers

fn str_field(p: &Value, k: &str) -> Option<String> {
    p.get(k)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// A tool input as an args object: objects as they are, JSON-encoded
/// strings (Cursor MCP) parsed, anything else wrapped as `{"input": v}`.
fn input_object(v: Option<&Value>, parse_strings: bool) -> Map<String, Value> {
    match v {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(Value::String(s)) if parse_strings => match serde_json::from_str::<Value>(s) {
            Ok(Value::Object(m)) => m,
            Ok(Value::Null) => Map::new(),
            _ => Map::from_iter([("input".to_string(), json!(s))]),
        },
        Some(other) => Map::from_iter([("input".to_string(), other.clone())]),
    }
}

fn caller(agent: &str, non_human_id: Option<String>) -> CallerIdentity {
    CallerIdentity {
        agent: agent.into(),
        agent_version: None,
        user: std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .ok(),
        non_human_id,
    }
}

/// Several values for one normalized key (`path`, `url`).
type Candidates = (&'static str, Vec<String>);

/// A mapped tool call before candidate selection.
struct Mapped {
    tool: String,
    args: Map<String, Value>,
    server: Option<ServerIdentity>,
    /// Several values for one normalized key: the strictest one is decided.
    candidates: Option<Candidates>,
}

impl Mapped {
    fn plain(tool: impl Into<String>, args: Map<String, Value>) -> Self {
        Mapped {
            tool: tool.into(),
            args,
            server: None,
            candidates: None,
        }
    }

    fn into_call(
        self,
        session_id: String,
        call_id: String,
        caller: CallerIdentity,
    ) -> (ToolCall, Option<Candidates>) {
        let mut args = self.args;
        let candidates = match self.candidates {
            Some((key, mut vals)) => {
                let mut seen = std::collections::HashSet::new();
                vals.retain(|v| seen.insert(v.clone()));
                match vals.len() {
                    0 => None,
                    1 => {
                        args.insert(key.into(), json!(vals[0]));
                        None
                    }
                    _ => {
                        let plural = format!("{key}s");
                        if !args.contains_key(&plural) {
                            args.insert(plural, json!(vals));
                        }
                        Some((key, vals))
                    }
                }
            }
            None => None,
        };
        (
            ToolCall {
                call_id,
                session_id,
                caller,
                mode: InterceptMode::SdkHook,
                tool: self.tool,
                args: Value::Object(args),
                server: self.server,
                trust: None,
                captured_at: Timestamp::now(),
            },
            candidates,
        )
    }
}

/// One writ tool call mapped from an agent's native tool call.
pub(crate) type NativeCall = (String, Map<String, Value>, Option<ServerIdentity>);

/// Map a tool call read back from an agent's transcript (`writ scan`) the
/// way that agent's hook would: one writ call per candidate value of a
/// multi-valued key. `agent` is `claude-code`, `codex` or `gemini-cli`;
/// `mcp` is Gemini's `mcp_context`, when the transcript has one.
pub(crate) fn native_calls(
    agent: &str,
    name: &str,
    input: Map<String, Value>,
    cwd: Option<&str>,
    mcp: Option<&Value>,
) -> Vec<NativeCall> {
    let mapped = match agent {
        "codex" => codex_map(name, input, cwd),
        "gemini-cli" => gemini_map(name, input, mcp),
        _ => {
            let (tool, args, server) = map_claude_tool(name, input, None);
            Mapped {
                tool,
                args,
                server,
                candidates: None,
            }
        }
    };
    match mapped.candidates {
        Some((key, vals)) if vals.len() > 1 => vals
            .into_iter()
            .map(|v| {
                let mut args = mapped.args.clone();
                args.insert(key.into(), json!(v));
                (mapped.tool.clone(), args, mapped.server.clone())
            })
            .collect(),
        Some((key, vals)) => {
            let mut args = mapped.args;
            if let Some(v) = vals.into_iter().next() {
                args.insert(key.into(), json!(v));
            }
            vec![(mapped.tool, args, mapped.server)]
        }
        None => vec![(mapped.tool, mapped.args, mapped.server)],
    }
}

fn server(name: &str, transport: &str) -> ServerIdentity {
    ServerIdentity {
        name: name.to_string(),
        transport: transport.to_string(),
        version: None,
    }
}

fn severity(v: &Verdict) -> u8 {
    match v {
        Verdict::Allow { .. } => 0,
        Verdict::Redact { .. } => 1,
        Verdict::Ask { .. } => 2,
        Verdict::Deny { .. } => 3,
    }
}

/// Does the decided call `rec` describe the same call as `now` (tool,
/// server and args, ignoring the keys writ adds)?
fn same_call(rec: &LedgerRecord, now: &ToolCall) -> bool {
    let Some(then) = &rec.call else {
        return false;
    };
    let strip = |v: &Value| -> Map<String, Value> {
        let mut m = v.as_object().cloned().unwrap_or_default();
        for k in ADDED_KEYS {
            m.remove(*k);
        }
        m
    };
    then.tool == now.tool
        && then.server.as_ref().map(|s| &s.name) == now.server.as_ref().map(|s| &s.name)
        && strip(&then.args) == strip(&now.args)
}

/// A string for the model: strings as they are, anything else as JSON.
fn text_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Pick a user-facing reason for a verdict that does not dispatch.
fn deny_reason(v: &Verdict) -> Option<String> {
    match v {
        Verdict::Deny {
            rule_id,
            reason,
            location,
        } => Some(format!(
            "writ denied this: rule \"{rule_id}\" — {reason} ({})",
            location.as_deref().unwrap_or("policy default")
        )),
        _ => None,
    }
}

fn ask_reason(rule_id: &str, diff: &str, location: Option<&str>) -> String {
    format!(
        "writ: rule \"{rule_id}\" ({}) needs your approval: {diff}",
        location.unwrap_or("policy default")
    )
}

fn ask_fail_closed(rule_id: &str, why: &str) -> String {
    format!("writ denied this: rule \"{rule_id}\" requires human approval and {why} (fail closed)")
}

impl Gateway {
    /// Decide `call`, evaluating each candidate value of the
    /// multi-valued key and recording the strictest (Contract 6: one
    /// Decision record per intercepted call).
    fn decide_candidates(
        &mut self,
        call: ToolCall,
        candidates: Option<Candidates>,
    ) -> std::result::Result<Decided, GwError> {
        let Some((key, vals)) = candidates else {
            return self.decide_call(call);
        };
        let engine = self.engine()?;
        let mut best: Option<(u8, ToolCall)> = None;
        for v in vals {
            let mut c = call.clone();
            if let Some(args) = c.args.as_object_mut() {
                args.insert(key.into(), json!(v));
            }
            let sev = severity(&engine.evaluate(&ToolCallContext::from_call(&c)));
            if best.as_ref().is_none_or(|(s, _)| sev > *s) {
                best = Some((sev, c));
            }
        }
        let chosen = best.map(|(_, c)| c).unwrap_or(call);
        self.decide_call(chosen)
    }

    /// The newest decision of `session` matching `pred` that has no
    /// execution record yet.
    fn locate_open(
        &mut self,
        session: &str,
        pred: impl Fn(&LedgerRecord) -> bool,
    ) -> std::result::Result<Option<LedgerRecord>, GwError> {
        let store = self.store()?;
        let mut open: Vec<LedgerRecord> = Vec::new();
        for item in store.iter() {
            let rec = item.map_err(GwError::ledger)?;
            match rec.kind {
                RecordKind::Decision if rec.session_id == session && pred(&rec) => open.push(rec),
                RecordKind::Execution => {
                    if let Some(i) = rec.decision_index {
                        open.retain(|d| d.index != i);
                    }
                }
                _ => {}
            }
        }
        Ok(open.pop())
    }

    /// Who authorised the dispatch of `rec` (None = the policy allowed
    /// it); an error when writ never allowed it. `prompt` names the
    /// agent's own confirmation, when `--ask defer` delegated to it.
    fn dispatch_approver(
        &self,
        rec: &LedgerRecord,
        prompt: Option<&str>,
    ) -> std::result::Result<Option<ApproverIdentity>, String> {
        match &rec.verdict {
            Some(Verdict::Allow { .. }) | Some(Verdict::Redact { .. }) => Ok(None),
            // `--ask ui`: approved in the console, which says by whom.
            Some(Verdict::Ask { .. }) if rec.approver.is_none() && self.ask == AskMode::Ui => {
                crate::ui::approvals::console_approval(&self.ledger_path, rec)
                    .map(Some)
                    .ok_or_else(|| {
                        format!(
                            "tool {} ran although the writ ui console did not approve it (rule {}); recorded nothing",
                            rec.call_id,
                            rec.rule_id.as_deref().unwrap_or("?")
                        )
                    })
            }
            Some(Verdict::Ask { .. }) if rec.approver.is_none() && self.ask == AskMode::Defer => {
                match prompt {
                    Some(id) => Ok(Some(ApproverIdentity {
                        kind: ApproverKind::Tui,
                        id: id.into(),
                    })),
                    None => Err(self.not_allowed(rec)),
                }
            }
            _ => Err(self.not_allowed(rec)),
        }
    }

    fn not_allowed(&self, rec: &LedgerRecord) -> String {
        format!(
            "tool {} ran although writ did not allow it (rule {}); recorded nothing",
            rec.call_id,
            rec.rule_id.as_deref().unwrap_or("?")
        )
    }

    /// Record the execution of `rec`; the redaction patterns to apply to
    /// the output, if its verdict is `redact`.
    fn complete_located(
        &mut self,
        rec: &LedgerRecord,
        prompt: Option<&str>,
        exit: i32,
        output: &[u8],
    ) -> std::result::Result<Option<Vec<Regex>>, String> {
        let approver = self.dispatch_approver(rec, prompt)?;
        self.record_execution(rec, approver, exit, output)
            .map_err(|e| format!("{}: {}", e.code, e.message))?;
        match &rec.verdict {
            Some(Verdict::Redact { patterns, .. }) => {
                compile_patterns(patterns).map(Some).map_err(|e| e.message)
            }
            _ => Ok(None),
        }
    }
}

fn is_redact(rec: &LedgerRecord) -> bool {
    matches!(rec.verdict, Some(Verdict::Redact { .. }))
}

// ---------------------------------------------------------------------------
// OpenAI Codex CLI
//
// Protocol: https://learn.chatgpt.com/docs/hooks (developers.openai.com/codex/hooks)
// and codex-rs/hooks (engine/output_parser.rs, events/pre_tool_use.rs).

fn codex(gw: &mut Gateway, p: &Value) -> HookOut {
    match p
        .get("hook_event_name")
        .and_then(Value::as_str)
        .unwrap_or("")
    {
        "PreToolUse" => codex_pre(gw, p),
        "PostToolUse" => codex_post(gw, p),
        other => pre_error(
            Format::Codex,
            &format!(
                "unsupported hook_event_name {other:?} (writ handles PreToolUse, PostToolUse)"
            ),
        ),
    }
}

/// Paths an `apply_patch` envelope touches (`*** Add|Update|Delete File:`
/// and `*** Move to:`), resolved against `cwd`.
fn patch_paths(patch: &str, cwd: Option<&str>) -> Vec<String> {
    const HEADERS: &[&str] = &[
        "*** Add File:",
        "*** Update File:",
        "*** Delete File:",
        "*** Move to:",
    ];
    patch
        .lines()
        .filter_map(|l| {
            let l = l.trim_start();
            HEADERS
                .iter()
                .find_map(|h| l.strip_prefix(h))
                .map(|rest| rest.trim().to_string())
        })
        .filter(|p| !p.is_empty())
        .map(|p| match cwd {
            Some(c) if !Path::new(&p).is_absolute() => Path::new(c).join(&p).display().to_string(),
            _ => p,
        })
        .collect()
}

fn codex_map(name: &str, mut input: Map<String, Value>, cwd: Option<&str>) -> Mapped {
    match name {
        // Shell and unified exec both report as `Bash` with a string
        // `command`; older shell payloads carry an argv array.
        "Bash" | "shell" | "local_shell" | "exec_command" => {
            if let Some(Value::Array(argv)) = input.get("command") {
                let joined: Vec<String> = argv.iter().map(text_of).collect();
                input.insert("command".into(), json!(joined.join(" ")));
            }
            Mapped::plain("bash", input)
        }
        "apply_patch" => {
            let paths = input
                .get("command")
                .and_then(Value::as_str)
                .map(|c| patch_paths(c, cwd))
                .unwrap_or_default();
            let mut m = Mapped::plain("fs.write", input);
            if !m.args.get("path").is_some_and(Value::is_string) {
                m.candidates = Some(("path", paths));
            }
            m
        }
        "view_image" => Mapped::plain("fs.read", input),
        _ => {
            let (tool, args, server) = map_claude_tool(name, input, None);
            Mapped {
                tool,
                args,
                server,
                candidates: None,
            }
        }
    }
}

fn codex_call(p: &Value) -> std::result::Result<(ToolCall, Option<Candidates>), String> {
    let session = str_field(p, "session_id").ok_or("hook payload lacks session_id")?;
    let tool_use_id = str_field(p, "tool_use_id").ok_or("hook payload lacks tool_use_id")?;
    let name = str_field(p, "tool_name").ok_or("hook payload lacks tool_name")?;
    let input = input_object(p.get("tool_input"), false);
    let cwd = p.get("cwd").and_then(Value::as_str);
    let mapped = codex_map(&name, input, cwd);
    Ok(mapped.into_call(
        session,
        tool_use_id,
        caller("codex", str_field(p, "agent_id")),
    ))
}

fn codex_pre(gw: &mut Gateway, p: &Value) -> HookOut {
    let (call, cands) = match codex_call(p) {
        Ok(c) => c,
        Err(e) => return pre_error(Format::Codex, &e),
    };
    let d = match gw.decide_candidates(call, cands) {
        Ok(d) => d,
        Err(e) => return pre_error(Format::Codex, &format!("{}: {}", e.code, e.message)),
    };
    match &d.verdict {
        // `permissionDecision: "allow"` without `updatedInput` is reported
        // as a failed hook by Codex; no output means "continue".
        Verdict::Allow { .. } | Verdict::Redact { .. } => HookOut {
            stdout: None,
            stderr: String::new(),
            code: EXIT_DISPATCH,
        },
        Verdict::Deny { .. } => deny(Format::Codex, &deny_reason(&d.verdict).unwrap_or_default()),
        Verdict::Ask { rule_id, .. } => deny(
            Format::Codex,
            &ask_fail_closed(rule_id, "Codex hooks cannot raise an approval prompt"),
        ),
    }
}

/// A Codex `PostToolUse` answer that replaces the tool result the model
/// sees with `reason`.
fn codex_block(reason: String, stderr: String) -> HookOut {
    HookOut {
        stdout: Some(json!({"decision": "block", "reason": reason})),
        stderr,
        code: EXIT_DISPATCH,
    }
}

fn exit_from_response(v: &Value) -> i32 {
    ["exit_code", "exitCode"]
        .iter()
        .find_map(|k| v.get(*k).and_then(Value::as_i64))
        .or_else(|| {
            v.get("metadata")
                .and_then(|m| m.get("exit_code"))
                .and_then(Value::as_i64)
        })
        .and_then(|n| i32::try_from(n).ok())
        .unwrap_or(0)
}

fn codex_post(gw: &mut Gateway, p: &Value) -> HookOut {
    // The tool already ran: every failure withholds its output from the
    // model (fail closed) and says why.
    let fail = |msg: String| {
        codex_block(
            format!("writ error: {msg}; the tool output is withheld"),
            format!("writ error: {msg}"),
        )
    };
    let response = p.get("tool_response").cloned().unwrap_or(Value::Null);
    let (now, _) = match codex_call(p) {
        Ok(c) => c,
        Err(e) => return fail(format!("{e}; cannot correlate")),
    };
    let located = match gw.locate(|r| r.session_id == now.session_id && r.call_id == now.call_id) {
        Ok(Some(l)) => l,
        Ok(None) => {
            return fail(format!(
                "no writ decision recorded for {} in {}",
                now.call_id, now.session_id
            ))
        }
        Err(e) => return fail(format!("{}: {}", e.code, e.message)),
    };
    if located.executed {
        return fail(format!("tool {} was already completed", now.call_id));
    }
    let rec = located.record;
    let output = serde_json::to_vec(&response).unwrap_or_default();
    let patterns = match gw.complete_located(&rec, None, exit_from_response(&response), &output) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    // The input that ran must be the input writ decided on (another hook's
    // `updatedInput` could have changed it).
    if let Some(then) = &rec.call {
        let cmd = |c: &ToolCall| c.args.get("command").cloned();
        if then.tool != now.tool || cmd(then) != cmd(&now) {
            return fail(format!(
                "tool {} ran with input that differs from the input writ decided on",
                now.call_id
            ));
        }
    }
    match patterns {
        Some(res) => codex_block(text_of(&mask_value(&response, &res)), String::new()),
        None => HookOut {
            stdout: None,
            stderr: String::new(),
            code: EXIT_DISPATCH,
        },
    }
}

// ---------------------------------------------------------------------------
// Gemini CLI
//
// Protocol: https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md
// and packages/core/src/hooks (hookRunner.ts, hookAggregator.ts),
// packages/core/src/scheduler (hook-utils.ts: `decision: "ask"`).

fn gemini(gw: &mut Gateway, p: &Value) -> HookOut {
    match p
        .get("hook_event_name")
        .and_then(Value::as_str)
        .unwrap_or("")
    {
        "BeforeTool" => gemini_pre(gw, p),
        "AfterTool" => gemini_post(gw, p),
        other => pre_error(
            Format::Gemini,
            &format!("unsupported hook_event_name {other:?} (writ handles BeforeTool, AfterTool)"),
        ),
    }
}

const GEMINI_READ: &[&str] = &[
    "read_file",
    "read_many_files",
    "list_directory",
    "glob",
    "grep_search",
    "search_file_content",
];
const GEMINI_WRITE: &[&str] = &["write_file", "replace", "edit"];

fn url_regex() -> Regex {
    Regex::new(r#"https?://[^\s"'<>)\]]+"#).expect("static regex")
}

fn gemini_map(name: &str, mut input: Map<String, Value>, mcp: Option<&Value>) -> Mapped {
    // MCP tools are `mcp_<server>_<tool>`; the server/tool split is only
    // unambiguous from `mcp_context`.
    if let Some(ctx) = mcp {
        if let (Some(srv), Some(tool)) = (
            ctx.get("server_name").and_then(Value::as_str),
            ctx.get("tool_name").and_then(Value::as_str),
        ) {
            let transport = if ctx.get("url").is_some_and(|u| !u.is_null()) {
                "http"
            } else if ctx.get("command").is_some_and(|c| !c.is_null()) {
                "stdio"
            } else {
                "unknown"
            };
            let mut m = Mapped::plain(tool, input);
            m.server = Some(server(srv, transport));
            return m;
        }
    }
    let path_of = |m: &Map<String, Value>| {
        ["file_path", "dir_path", "absolute_path", "path"]
            .iter()
            .find_map(|k| m.get(*k).and_then(Value::as_str).map(str::to_string))
    };
    if name == "run_shell_command" {
        return Mapped::plain("bash", input);
    }
    let is_read = GEMINI_READ.contains(&name);
    if is_read || GEMINI_WRITE.contains(&name) {
        let mut cands: Vec<String> = Vec::new();
        if !input.get("path").is_some_and(Value::is_string) {
            if let Some(p) = path_of(&input) {
                input.insert("path".into(), json!(p));
            } else {
                for k in ["include", "paths"] {
                    if let Some(Value::Array(a)) = input.get(k) {
                        cands.extend(a.iter().filter_map(Value::as_str).map(str::to_string));
                    }
                }
            }
        }
        let mut m = Mapped::plain(if is_read { "fs.read" } else { "fs.write" }, input);
        if !cands.is_empty() {
            m.candidates = Some(("path", cands));
        }
        return m;
    }
    match name {
        "web_fetch" => {
            let urls: Vec<String> = if input.get("url").is_some_and(Value::is_string) {
                Vec::new()
            } else {
                let prompt = input.get("prompt").and_then(Value::as_str).unwrap_or("");
                url_regex()
                    .find_iter(prompt)
                    .map(|m| {
                        m.as_str()
                            .trim_end_matches(['.', ',', ';', ':'])
                            .to_string()
                    })
                    .collect()
            };
            let mut m = Mapped::plain("http", input);
            if !urls.is_empty() {
                m.candidates = Some(("url", urls));
            }
            m
        }
        "google_web_search" => Mapped::plain("web.search", input),
        _ => Mapped::plain(name, input),
    }
}

fn gemini_call(
    p: &Value,
    call_id: String,
) -> std::result::Result<(ToolCall, Option<Candidates>), String> {
    let session = str_field(p, "session_id").ok_or("hook payload lacks session_id")?;
    let name = str_field(p, "tool_name").ok_or("hook payload lacks tool_name")?;
    let input = input_object(p.get("tool_input"), false);
    let mapped = gemini_map(&name, input, p.get("mcp_context"));
    Ok(mapped.into_call(session, call_id, caller("gemini-cli", None)))
}

fn gemini_pre(gw: &mut Gateway, p: &Value) -> HookOut {
    let (call, cands) = match gemini_call(p, generated_call_id()) {
        Ok(c) => c,
        Err(e) => return pre_error(Format::Gemini, &e),
    };
    let d = match gw.decide_candidates(call, cands) {
        Ok(d) => d,
        Err(e) => return pre_error(Format::Gemini, &format!("{}: {}", e.code, e.message)),
    };
    let allow = |reason: String| HookOut {
        stdout: Some(json!({"decision": "allow", "reason": reason})),
        stderr: String::new(),
        code: EXIT_DISPATCH,
    };
    match &d.verdict {
        Verdict::Allow { rule_id } => allow(match rule_id {
            Some(r) => format!("writ: allowed by rule \"{r}\""),
            None => "writ: allowed by the policy default".into(),
        }),
        Verdict::Redact { rule_id, .. } => allow(format!(
            "writ: allowed by rule \"{rule_id}\"; matched output is redacted"
        )),
        Verdict::Deny { .. } => deny(Format::Gemini, &deny_reason(&d.verdict).unwrap_or_default()),
        Verdict::Ask {
            rule_id,
            diff,
            location,
            ..
        } => match gw.ask {
            // Gemini CLI's scheduler turns `decision: "ask"` into its own
            // confirmation prompt (ASK_USER), also in YOLO mode.
            AskMode::Defer => {
                let msg = ask_reason(rule_id, diff, location.as_deref());
                HookOut {
                    stdout: Some(json!({"decision": "ask", "reason": msg, "systemMessage": msg})),
                    stderr: String::new(),
                    code: EXIT_DISPATCH,
                }
            }
            AskMode::Ui => match crate::ui::approvals::await_decision(
                &gw.ledger_path,
                &d.record,
                "gemini",
                None,
            ) {
                crate::ui::approvals::UiDecision::Approved(who) => allow(format!(
                    "writ: rule \"{rule_id}\" approved in the writ ui web console by {}",
                    who.id
                )),
                crate::ui::approvals::UiDecision::Denied(reason) => {
                    deny(Format::Gemini, &format!("writ denied this: {reason}"))
                }
            },
            AskMode::Deny => deny(
                Format::Gemini,
                &ask_fail_closed(rule_id, "none is available here"),
            ),
        },
    }
}

fn gemini_post(gw: &mut Gateway, p: &Value) -> HookOut {
    // `decision: "deny"` on AfterTool replaces the tool result with
    // `reason`; every failure withholds the output (fail closed).
    let fail = |msg: String| HookOut {
        stdout: Some(json!({
            "decision": "deny",
            "reason": format!("writ error: {msg}; the tool output is withheld"),
        })),
        stderr: format!("writ error: {msg}"),
        code: EXIT_NO_DISPATCH,
    };
    let response = p.get("tool_response").cloned().unwrap_or(Value::Null);
    let (now, _) = match gemini_call(p, String::new()) {
        Ok(c) => c,
        Err(e) => return fail(format!("{e}; cannot correlate")),
    };
    let rec = match gw.locate_open(&now.session_id, |r| same_call(r, &now)) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return fail(format!(
                "no open writ decision for this {} call in {}",
                now.tool, now.session_id
            ))
        }
        Err(e) => return fail(format!("{}: {}", e.code, e.message)),
    };
    let exit = if response.get("error").is_some_and(|e| !e.is_null()) {
        1
    } else {
        0
    };
    let output = serde_json::to_vec(&response).unwrap_or_default();
    match gw.complete_located(&rec, Some(GEMINI_PROMPT_APPROVER), exit, &output) {
        Ok(Some(res)) => {
            let content = response.get("llmContent").unwrap_or(&response);
            HookOut {
                stdout: Some(json!({
                    "decision": "deny",
                    "reason": text_of(&mask_value(content, &res)),
                })),
                stderr: String::new(),
                code: EXIT_DISPATCH,
            }
        }
        Ok(None) => HookOut {
            stdout: Some(json!({})),
            stderr: String::new(),
            code: EXIT_DISPATCH,
        },
        Err(e) => fail(e),
    }
}

// ---------------------------------------------------------------------------
// Cursor
//
// Protocol: https://cursor.com/docs/hooks (preToolUse, postToolUse,
// postToolUseFailure, beforeMCPExecution; `failClosed`; exit code 2).

fn cursor(gw: &mut Gateway, p: &Value) -> HookOut {
    match p.get("hook_event_name").and_then(Value::as_str).unwrap_or("") {
        "preToolUse" => cursor_pre(gw, p),
        "beforeMCPExecution" => cursor_mcp_pre(gw, p),
        "postToolUse" => cursor_post(gw, p, false),
        "postToolUseFailure" => cursor_post(gw, p, true),
        other => pre_error(
            Format::Cursor,
            &format!(
                "unsupported hook_event_name {other:?} (writ handles preToolUse, beforeMCPExecution, postToolUse, postToolUseFailure)"
            ),
        ),
    }
}

/// Cursor's generic tool hooks name MCP tools `MCP:<tool>` and carry no
/// server identity; those calls are decided at `beforeMCPExecution`.
fn cursor_mcp_tool(name: &str) -> Option<&str> {
    name.strip_prefix("MCP:")
}

fn cursor_session(p: &Value) -> std::result::Result<String, String> {
    str_field(p, "conversation_id")
        .or_else(|| str_field(p, "session_id"))
        .ok_or_else(|| "hook payload lacks conversation_id".to_string())
}

fn cursor_map(name: &str, mut input: Map<String, Value>) -> Mapped {
    const PATH_KEYS: &[&str] = &[
        "file_path",
        "target_file",
        "notebook_path",
        "relative_workspace_path",
        "target_directory",
    ];
    let add_path = |m: &mut Map<String, Value>| {
        if !m.get("path").is_some_and(Value::is_string) {
            if let Some(p) = PATH_KEYS
                .iter()
                .find_map(|k| m.get(*k).and_then(Value::as_str).map(str::to_string))
            {
                m.insert("path".into(), json!(p));
            }
        }
    };
    match name {
        "Shell" => Mapped::plain("bash", input),
        "Delete" => {
            add_path(&mut input);
            Mapped::plain("fs.write", input)
        }
        _ => {
            if ["Read", "Write", "Edit", "Grep", "Glob", "LS"].contains(&name) {
                add_path(&mut input);
            }
            let (tool, args, server) = map_claude_tool(name, input, None);
            Mapped {
                tool,
                args,
                server,
                candidates: None,
            }
        }
    }
}

fn cursor_call(p: &Value) -> std::result::Result<(ToolCall, Option<Candidates>), String> {
    let session = cursor_session(p)?;
    let tool_use_id = str_field(p, "tool_use_id").ok_or("hook payload lacks tool_use_id")?;
    let name = str_field(p, "tool_name").ok_or("hook payload lacks tool_name")?;
    let input = input_object(p.get("tool_input"), true);
    Ok(cursor_map(&name, input).into_call(session, tool_use_id, caller("cursor", None)))
}

fn cursor_allow(reason: String) -> HookOut {
    HookOut {
        stdout: Some(json!({"permission": "allow", "agent_message": reason})),
        stderr: String::new(),
        code: EXIT_DISPATCH,
    }
}

fn cursor_pre(gw: &mut Gateway, p: &Value) -> HookOut {
    if let Some(name) = p.get("tool_name").and_then(Value::as_str) {
        if cursor_mcp_tool(name).is_some() {
            // Decided (with its server) at beforeMCPExecution.
            return cursor_allow("writ: MCP calls are decided at beforeMCPExecution".into());
        }
    }
    let (call, cands) = match cursor_call(p) {
        Ok(c) => c,
        Err(e) => return pre_error(Format::Cursor, &e),
    };
    let d = match gw.decide_candidates(call, cands) {
        Ok(d) => d,
        Err(e) => return pre_error(Format::Cursor, &format!("{}: {}", e.code, e.message)),
    };
    match &d.verdict {
        Verdict::Allow { rule_id } => cursor_allow(match rule_id {
            Some(r) => format!("writ: allowed by rule \"{r}\""),
            None => "writ: allowed by the policy default".into(),
        }),
        // Only MCP output can be replaced by a Cursor hook: a redact rule
        // on any other tool cannot be honoured, so the call is refused.
        Verdict::Redact { rule_id, .. } if d.call.server.is_none() => deny(
            Format::Cursor,
            &format!(
                "writ denied this: rule \"{rule_id}\" redacts this tool's output, and Cursor lets a hook replace only MCP tool output (fail closed)"
            ),
        ),
        Verdict::Redact { rule_id, .. } => cursor_allow(format!(
            "writ: allowed by rule \"{rule_id}\"; matched output is redacted"
        )),
        Verdict::Deny { .. } => deny(Format::Cursor, &deny_reason(&d.verdict).unwrap_or_default()),
        // `permission: "ask"` is accepted but not enforced for preToolUse.
        Verdict::Ask { rule_id, .. } => deny(
            Format::Cursor,
            &ask_fail_closed(rule_id, "Cursor's preToolUse cannot ask (only MCP calls can)"),
        ),
    }
}

fn cursor_mcp_call(p: &Value, call_id: String) -> std::result::Result<ToolCall, String> {
    let session = cursor_session(p)?;
    let tool = str_field(p, "tool_name").ok_or("hook payload lacks tool_name")?;
    // Cursor: "a hook that allows anything it does not recognize should
    // treat a missing mcp_server_name as a deny".
    let srv = str_field(p, "mcp_server_name").ok_or("hook payload lacks mcp_server_name")?;
    let transport = if str_field(p, "mcp_server_url")
        .or_else(|| str_field(p, "url"))
        .is_some()
    {
        "http"
    } else if str_field(p, "command").is_some() {
        "stdio"
    } else {
        "unknown"
    };
    let mut m = Mapped::plain(tool, input_object(p.get("tool_input"), true));
    m.server = Some(server(&srv, transport));
    Ok(m.into_call(session, call_id, caller("cursor", None)).0)
}

fn cursor_mcp_pre(gw: &mut Gateway, p: &Value) -> HookOut {
    let call = match cursor_mcp_call(p, generated_call_id()) {
        Ok(c) => c,
        Err(e) => return pre_error(Format::Cursor, &e),
    };
    let d = match gw.decide_call(call) {
        Ok(d) => d,
        Err(e) => return pre_error(Format::Cursor, &format!("{}: {}", e.code, e.message)),
    };
    match &d.verdict {
        Verdict::Allow { .. } => cursor_allow("writ: allowed".into()),
        Verdict::Redact { rule_id, .. } => cursor_allow(format!(
            "writ: allowed by rule \"{rule_id}\"; matched output is redacted"
        )),
        Verdict::Deny { .. } => deny(Format::Cursor, &deny_reason(&d.verdict).unwrap_or_default()),
        Verdict::Ask {
            rule_id,
            diff,
            location,
            ..
        } => match gw.ask {
            AskMode::Defer => {
                let msg = ask_reason(rule_id, diff, location.as_deref());
                HookOut {
                    stdout: Some(json!({
                        "permission": "ask",
                        "user_message": msg,
                        "agent_message": msg,
                    })),
                    stderr: String::new(),
                    code: EXIT_DISPATCH,
                }
            }
            AskMode::Ui => match crate::ui::approvals::await_decision(
                &gw.ledger_path,
                &d.record,
                "cursor",
                Some(crate::ui::approvals::CLAUDE_CODE_CAP_MS),
            ) {
                crate::ui::approvals::UiDecision::Approved(who) => cursor_allow(format!(
                    "writ: rule \"{rule_id}\" approved in the writ ui web console by {}",
                    who.id
                )),
                crate::ui::approvals::UiDecision::Denied(reason) => {
                    deny(Format::Cursor, &format!("writ denied this: {reason}"))
                }
            },
            AskMode::Deny => deny(
                Format::Cursor,
                &ask_fail_closed(rule_id, "none is available here"),
            ),
        },
    }
}

fn cursor_post(gw: &mut Gateway, p: &Value, failure: bool) -> HookOut {
    let name = p.get("tool_name").and_then(Value::as_str).unwrap_or("");
    let mcp_tool = cursor_mcp_tool(name).map(str::to_string);
    let raw_output = p.get("tool_output").cloned().unwrap_or(Value::Null);
    let parsed_output = match &raw_output {
        Value::String(s) => serde_json::from_str::<Value>(s).unwrap_or(raw_output.clone()),
        other => other.clone(),
    };
    // postToolUse cannot un-run the tool: a failure is reported to the
    // agent, and an MCP result that may need masking is fully masked.
    let fail = |msg: String, known_plain: bool| {
        let mut out = json!({
            "additional_context": format!("writ error: {msg}"),
        });
        if mcp_tool.is_some() && !known_plain && !failure {
            out["updated_mcp_tool_output"] = match mask_all(&parsed_output) {
                v @ Value::Object(_) => v,
                v => json!({ "content": [{"type": "text", "text": text_of(&v)}] }),
            };
        }
        HookOut {
            stdout: Some(out),
            stderr: format!("writ error: {msg}"),
            code: EXIT_DISPATCH,
        }
    };
    let session = match cursor_session(p) {
        Ok(s) => s,
        Err(e) => return fail(format!("{e}; cannot correlate"), false),
    };
    let rec = if let Some(tool) = &mcp_tool {
        let input = input_object(p.get("tool_input"), true);
        let tool = tool.clone();
        let found = gw.locate_open(&session, |r| {
            r.call.as_ref().is_some_and(|c| {
                c.server.is_some()
                    && (c.tool == tool || tool.ends_with(&format!("-{}", c.tool)))
                    && c.args.as_object() == Some(&input)
            })
        });
        match found {
            Ok(Some(r)) => r,
            Ok(None) => {
                return fail(
                    format!("no open writ decision for MCP tool {tool} in {session}"),
                    false,
                )
            }
            Err(e) => return fail(format!("{}: {}", e.code, e.message), false),
        }
    } else {
        let Some(id) = str_field(p, "tool_use_id") else {
            return fail(
                "hook payload lacks tool_use_id; cannot correlate".into(),
                false,
            );
        };
        match gw.locate(|r| r.session_id == session && r.call_id == id) {
            Ok(Some(l)) if l.executed => {
                return fail(
                    format!("tool {id} was already completed"),
                    !is_redact(&l.record),
                )
            }
            Ok(Some(l)) => l.record,
            Ok(None) => {
                return fail(
                    format!("no writ decision recorded for {id} in {session}"),
                    false,
                )
            }
            Err(e) => return fail(format!("{}: {}", e.code, e.message), false),
        }
    };
    let (exit, output) = if failure {
        let err = p.get("error_message").and_then(Value::as_str).unwrap_or("");
        (1, err.as_bytes().to_vec())
    } else {
        let exit = parsed_output
            .get("exitCode")
            .and_then(Value::as_i64)
            .and_then(|n| i32::try_from(n).ok())
            .unwrap_or(0);
        let bytes = match &raw_output {
            Value::String(s) => s.as_bytes().to_vec(),
            other => serde_json::to_vec(other).unwrap_or_default(),
        };
        (exit, bytes)
    };
    let plain = !is_redact(&rec);
    match gw.complete_located(&rec, Some(CURSOR_PROMPT_APPROVER), exit, &output) {
        Ok(Some(res)) if mcp_tool.is_some() && !failure => HookOut {
            stdout: Some(json!({"updated_mcp_tool_output": mask_value(&parsed_output, &res)})),
            stderr: String::new(),
            code: EXIT_DISPATCH,
        },
        Ok(_) => HookOut {
            stdout: Some(json!({})),
            stderr: String::new(),
            code: EXIT_DISPATCH,
        },
        Err(e) => fail(e, plain),
    }
}

// ---------------------------------------------------------------------------
// Windsurf (Cascade hooks)
//
// Protocol: https://docs.windsurf.com/windsurf/cascade/hooks (now
// https://docs.devin.ai/desktop/cascade/hooks): pre-hooks block only with
// exit code 2; any other exit code lets the action proceed.

fn windsurf(gw: &mut Gateway, p: &Value) -> HookOut {
    let event = p
        .get("agent_action_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let (phase, action) = match event.split_once('_') {
        Some((ph @ ("pre" | "post"), a)) => (ph, a),
        _ => ("", ""),
    };
    if !matches!(
        action,
        "run_command" | "read_code" | "write_code" | "mcp_tool_use"
    ) {
        return pre_error(
            Format::Windsurf,
            &format!(
                "unsupported agent_action_name {event:?} (writ handles pre_/post_ run_command, read_code, write_code, mcp_tool_use)"
            ),
        );
    }
    if phase == "pre" {
        windsurf_pre(gw, p, action)
    } else {
        windsurf_post(gw, p, action)
    }
}

fn windsurf_call(
    p: &Value,
    action: &str,
    call_id: String,
) -> std::result::Result<ToolCall, String> {
    let session = str_field(p, "trajectory_id").ok_or("hook payload lacks trajectory_id")?;
    let info = p
        .get("tool_info")
        .and_then(Value::as_object)
        .ok_or("hook payload lacks a tool_info object")?;
    let s = |k: &str| info.get(k).cloned().unwrap_or(Value::Null);
    let mut args = Map::new();
    let mapped = match action {
        "run_command" => {
            args.insert("command".into(), s("command_line"));
            args.insert("cwd".into(), s("cwd"));
            Mapped::plain("bash", args)
        }
        "read_code" => {
            args.insert("path".into(), s("file_path"));
            Mapped::plain("fs.read", args)
        }
        "write_code" => {
            args.insert("path".into(), s("file_path"));
            Mapped::plain("fs.write", args)
        }
        _ => {
            let tool = info
                .get("mcp_tool_name")
                .and_then(Value::as_str)
                .filter(|t| !t.is_empty())
                .ok_or("tool_info lacks mcp_tool_name")?;
            let srv = info
                .get("mcp_server_name")
                .and_then(Value::as_str)
                .filter(|t| !t.is_empty())
                .ok_or("tool_info lacks mcp_server_name")?;
            let mut m = Mapped::plain(tool, input_object(info.get("mcp_tool_arguments"), true));
            m.server = Some(server(srv, "unknown"));
            m
        }
    };
    if mapped.tool != "bash" && mapped.server.is_none() && !mapped.args["path"].is_string() {
        return Err("tool_info lacks file_path".into());
    }
    if mapped.tool == "bash" && !mapped.args["command"].is_string() {
        return Err("tool_info lacks command_line".into());
    }
    Ok(mapped
        .into_call(session, call_id, caller("windsurf", None))
        .0)
}

fn windsurf_pre(gw: &mut Gateway, p: &Value, action: &str) -> HookOut {
    let call = match windsurf_call(p, action, generated_call_id()) {
        Ok(c) => c,
        Err(e) => return pre_error(Format::Windsurf, &e),
    };
    let d = match gw.decide_call(call) {
        Ok(d) => d,
        Err(e) => return pre_error(Format::Windsurf, &format!("{}: {}", e.code, e.message)),
    };
    match &d.verdict {
        Verdict::Allow { .. } => HookOut {
            stdout: None,
            stderr: String::new(),
            code: EXIT_DISPATCH,
        },
        // A Cascade hook cannot replace what the model sees.
        Verdict::Redact { rule_id, .. } => deny(
            Format::Windsurf,
            &format!(
                "writ denied this: rule \"{rule_id}\" redacts this tool's output, and Windsurf hooks cannot replace tool output (fail closed)"
            ),
        ),
        Verdict::Deny { .. } => deny(
            Format::Windsurf,
            &deny_reason(&d.verdict).unwrap_or_default(),
        ),
        Verdict::Ask { rule_id, .. } => deny(
            Format::Windsurf,
            &ask_fail_closed(rule_id, "Windsurf hooks cannot raise an approval prompt"),
        ),
    }
}

fn windsurf_post(gw: &mut Gateway, p: &Value, action: &str) -> HookOut {
    // Post-hooks cannot block; exit 2 shows stderr to Cascade.
    let fail = |msg: String| HookOut {
        stdout: None,
        stderr: format!("writ error: {msg}"),
        code: EXIT_NO_DISPATCH,
    };
    let now = match windsurf_call(p, action, String::new()) {
        Ok(c) => c,
        Err(e) => return fail(format!("{e}; cannot correlate")),
    };
    let rec = match gw.locate_open(&now.session_id, |r| same_call(r, &now)) {
        Ok(Some(r)) => r,
        Ok(None) => {
            return fail(format!(
                "no open writ decision for this {} call in {}",
                now.tool, now.session_id
            ))
        }
        Err(e) => return fail(format!("{}: {}", e.code, e.message)),
    };
    let output = p
        .get("tool_info")
        .and_then(|i| i.get("mcp_result"))
        .map(text_of)
        .unwrap_or_default();
    match gw.complete_located(&rec, None, 0, output.as_bytes()) {
        Ok(_) => HookOut {
            stdout: None,
            stderr: String::new(),
            code: EXIT_DISPATCH,
        },
        Err(e) => fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_json_escapes_non_ascii() {
        let v = json!({"reason": "déjà — 🚫"});
        let s = ascii_json(&v);
        assert!(s.is_ascii(), "{s}");
        let back: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn patch_paths_cover_every_header() {
        let patch = "*** Begin Patch\n*** Add File: a.txt\n+x\n*** Update File: src/b.rs\n*** Move to: src/c.rs\n@@\n-y\n+z\n*** Delete File: /abs/.env\n*** End Patch";
        let got = patch_paths(patch, Some("/w"));
        let w = |p: &str| Path::new("/w").join(p).display().to_string();
        assert_eq!(
            got,
            vec![w("a.txt"), w("src/b.rs"), w("src/c.rs"), "/abs/.env".into()]
        );
    }

    #[test]
    fn codex_mapping() {
        let m =
            |name: &str, input: Value| codex_map(name, input.as_object().unwrap().clone(), None);
        assert_eq!(m("Bash", json!({"command": "ls"})).tool, "bash");
        let b = m("shell", json!({"command": ["git", "status"]}));
        assert_eq!(b.args["command"], "git status");
        let p = m(
            "apply_patch",
            json!({"command": "*** Add File: /x/.env\n+k"}),
        );
        assert_eq!(p.tool, "fs.write");
        assert_eq!(p.candidates.unwrap().1, vec!["/x/.env".to_string()]);
        let q = m("mcp__db__query", json!({"sql": "x"}));
        assert_eq!(
            (q.tool.as_str(), q.server.unwrap().name.as_str()),
            ("query", "db")
        );
        assert_eq!(m("view_image", json!({"path": "/i.png"})).tool, "fs.read");
        assert_eq!(m("update_plan", json!({})).tool, "update_plan");
    }

    #[test]
    fn gemini_mapping() {
        let m = |name: &str, input: Value, ctx: Option<Value>| {
            gemini_map(name, input.as_object().unwrap().clone(), ctx.as_ref())
        };
        assert_eq!(
            m("run_shell_command", json!({"command": "ls"}), None).tool,
            "bash"
        );
        let r = m("read_file", json!({"file_path": "/p/.env"}), None);
        assert_eq!(
            (r.tool.as_str(), r.args["path"].as_str()),
            ("fs.read", Some("/p/.env"))
        );
        let l = m("list_directory", json!({"dir_path": "/p"}), None);
        assert_eq!(l.args["path"], "/p");
        let w = m("replace", json!({"file_path": "/p/a.rs"}), None);
        assert_eq!(w.tool, "fs.write");
        let many = m(
            "read_many_files",
            json!({"include": ["a.rs", ".env"]}),
            None,
        );
        assert_eq!(many.candidates.unwrap().1.len(), 2);
        let f = m(
            "web_fetch",
            json!({"prompt": "summarize https://a.example/x and https://b.example/y."}),
            None,
        );
        assert_eq!(f.tool, "http");
        assert_eq!(
            f.candidates.unwrap().1,
            vec![
                "https://a.example/x".to_string(),
                "https://b.example/y".to_string()
            ]
        );
        assert_eq!(
            m("google_web_search", json!({"query": "q"}), None).tool,
            "web.search"
        );
        let mcp = m(
            "mcp_my_db_query",
            json!({"sql": "x"}),
            Some(json!({"server_name": "my_db", "tool_name": "query", "command": "npx"})),
        );
        assert_eq!(mcp.tool, "query");
        let s = mcp.server.unwrap();
        assert_eq!((s.name.as_str(), s.transport.as_str()), ("my_db", "stdio"));
        assert_eq!(m("save_memory", json!({}), None).tool, "save_memory");
    }

    #[test]
    fn cursor_mapping() {
        let m = |name: &str, input: Value| cursor_map(name, input.as_object().unwrap().clone());
        assert_eq!(m("Shell", json!({"command": "ls"})).tool, "bash");
        let r = m("Read", json!({"target_file": "/p/.env"}));
        assert_eq!(
            (r.tool.as_str(), r.args["path"].as_str()),
            ("fs.read", Some("/p/.env"))
        );
        let d = m("Delete", json!({"file_path": "/p/x"}));
        assert_eq!(
            (d.tool.as_str(), d.args["path"].as_str()),
            ("fs.write", Some("/p/x"))
        );
        assert_eq!(m("Write", json!({"file_path": "/p/y"})).tool, "fs.write");
        assert_eq!(m("WebFetch", json!({"url": "https://x"})).tool, "http");
        assert_eq!(m("Task", json!({})).tool, "Task");
        assert_eq!(cursor_mcp_tool("MCP:create_issue"), Some("create_issue"));
    }

    #[test]
    fn input_objects() {
        assert_eq!(input_object(Some(&json!("{\"a\":1}")), true)["a"], 1);
        assert_eq!(
            input_object(Some(&json!("not json")), true)["input"],
            "not json"
        );
        assert_eq!(
            input_object(Some(&json!("{\"a\":1}")), false)["input"],
            "{\"a\":1}"
        );
        assert!(input_object(None, true).is_empty());
    }
}
