//! provio-wasm — the provio policy engine and ledger record format, compiled to
//! WebAssembly for the browser playground (`site/playground.html`).
//!
//! Nothing here re-implements the engine. Every verdict comes from
//! [`provio_policy::NativePolicyEngine`], every call is normalised by
//! [`provio_core::ToolCallContext::from_call`], every record hash is
//! [`provio_core::LedgerRecord::compute_hash`], every chain check is
//! [`provio_core::verify_chain`], and policy replay is
//! [`provio_replay::policy_replay`]. This crate only adds the thin layer the
//! browser needs:
//!
//! - a JSON-string API (`#[wasm_bindgen]` functions that take and return
//!   JSON text, so the JS glue stays tiny and the functions are ordinary
//!   Rust functions natively — the test suite calls them directly);
//! - injected timestamps: `std::time::SystemTime::now()` panics on
//!   `wasm32-unknown-unknown`, so every function that stamps a record or a
//!   call takes `now_ms` from JS (`Date.now()`) instead of calling
//!   `Timestamp::now()` / `LedgerWriter`;
//! - the agent-side tool mapping (`claude-code` names → provio tools), which
//!   mirrors `provio check --format claude-code` (provio-cli `hook.rs`,
//!   `map_claude_tool`) because that function is private to the CLI binary;
//! - the redact mask (`[redacted-by-provio]`), which mirrors provio-cli's
//!   `mask_text` / `mask_value` for the same reason.
//!
//! Errors never panic across the boundary: every function answers
//! `{"ok": false, "error": "..."}`.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use provio_core::approver::{ApproverIdentity, ApproverKind};
use provio_core::call::{
    CallerIdentity, InterceptMode, ServerIdentity, ToolCall, ToolCallContext, TrustVerdict,
};
use provio_core::ledger::{LedgerRecord, RecordKind, GENESIS_HASH, SCHEMA_VERSION};
use provio_core::verdict::Verdict;
use provio_core::{verify_chain, PolicyEngine, Timestamp};
use provio_policy::policy_file::{compile, RuleVerdict};
use provio_policy::NativePolicyEngine;
use provio_replay::RecordedStep;
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use wasm_bindgen::prelude::wasm_bindgen;

/// The replacement string for every redacted match (same as provio-cli and
/// the MCP proxy).
pub const REDACTION_MARK: &str = "[redacted-by-provio]";

fn err(msg: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": msg.to_string() }).to_string()
}

fn ts(now_ms: f64) -> Timestamp {
    // Seconds precision on the wire (Timestamp serialises RFC 3339 seconds).
    Timestamp::from_epoch_ms(if now_ms.is_finite() { now_ms as i64 } else { 0 })
}

/// Crate version, shown in the playground footer.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ---------------------------------------------------------------------------
// Policy compile

/// Split a provio-policy error (`provio.yaml:LINE[:COL]: message`) into parts.
fn parse_error_location(msg: &str) -> Value {
    let re = Regex::new(r"^provio\.yaml:(\d+)(?::(\d+))?: ?(.*)$").expect("static regex");
    let flat = msg.strip_prefix("policy error: ").unwrap_or(msg);
    match re.captures(flat) {
        Some(c) => json!({
            "line": c[1].parse::<u64>().ok(),
            "column": c.get(2).and_then(|m| m.as_str().parse::<u64>().ok()),
            "message": c[3].to_string(),
            "raw": flat,
        }),
        None => json!({
            "line": Value::Null,
            "column": Value::Null,
            "message": flat.strip_prefix("provio.yaml: ").unwrap_or(flat),
            "raw": flat,
        }),
    }
}

fn verdict_word(v: RuleVerdict) -> &'static str {
    match v {
        RuleVerdict::Allow => "allow",
        RuleVerdict::Deny => "deny",
        RuleVerdict::Ask => "ask",
        RuleVerdict::Redact => "redact",
    }
}

/// Compile a provio.yaml source with the native engine's compiler.
///
/// `{"ok": true, "version", "default", "rules": [{id, verdict, line, reason,
/// irreversible, timeout_ms, patterns}], "errors": []}` or
/// `{"ok": false, "rules": [], "errors": [{line, column, message, raw}]}`.
#[wasm_bindgen]
pub fn compile_policy(src: &str) -> String {
    match compile(src) {
        Ok(p) => {
            let rules: Vec<Value> = p
                .rules
                .iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "verdict": verdict_word(r.verdict),
                        "line": r.line,
                        "reason": r.reason,
                        "irreversible": r.irreversible,
                        "timeout_ms": r.timeout_ms,
                        "patterns": r.patterns,
                    })
                })
                .collect();
            json!({
                "ok": true,
                "version": p.version,
                "default": p.default,
                "rules": rules,
                "errors": [],
            })
            .to_string()
        }
        Err(e) => json!({
            "ok": false,
            "rules": [],
            "errors": [parse_error_location(&e)],
        })
        .to_string(),
    }
}

// ---------------------------------------------------------------------------
// Calls

/// What the playground's agent simulator sends: a tool call as a given
/// agent would emit it, before provio normalises it.
#[derive(Debug, Clone, Deserialize)]
pub struct SimCall {
    /// "claude-code" | "mcp" | "langgraph" | "openai-agents" | anything
    /// (unknown agents pass the tool through unchanged).
    #[serde(default = "default_agent")]
    pub agent: String,
    /// The agent-side tool name (e.g. `Bash`, `mcp__github__create_issue`).
    pub tool: String,
    #[serde(default = "empty_object")]
    pub args: Value,
    /// MCP server name (for `mcp` or to override the `mcp__` prefix).
    #[serde(default)]
    pub server: Option<String>,
    /// "verified" | "unverified" | "malicious"
    #[serde(default)]
    pub trust: Option<String>,
    /// Override the interception mode ("mcp" | "processwrap" | "sdkhook");
    /// by default it follows the agent (MCP proxy for `mcp`, SDK hook
    /// otherwise).
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub call_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
}

fn default_agent() -> String {
    "claude-code".into()
}

fn empty_object() -> Value {
    Value::Object(Map::new())
}

const FS_READ: &[&str] = &["Read", "Glob", "Grep", "LS", "NotebookRead"];
const FS_WRITE: &[&str] = &["Write", "Edit", "MultiEdit", "NotebookEdit"];

/// Claude Code tool name → provio tool (mirror of provio-cli `map_claude_tool`,
/// the table in `crates/provio-cli/src/hook.rs`).
pub fn map_claude_tool(
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

fn parse_trust(t: Option<&str>) -> Result<Option<TrustVerdict>, String> {
    match t.map(str::trim) {
        None | Some("") => Ok(None),
        Some("verified") => Ok(Some(TrustVerdict::Verified)),
        Some("unverified") => Ok(Some(TrustVerdict::Unverified)),
        Some("malicious") => Ok(Some(TrustVerdict::Malicious)),
        Some(other) => Err(format!(
            "unknown trust {other:?} (expected verified, unverified, malicious)"
        )),
    }
}

/// Normalise a simulated call into the `ToolCall` envelope provio records,
/// exactly as the interceptor for that agent would.
pub fn build_call(sim: &SimCall, now_ms: f64) -> Result<ToolCall, String> {
    let args = match &sim.args {
        Value::Object(m) => m.clone(),
        Value::Null => Map::new(),
        _ => return Err("args must be a JSON object".into()),
    };
    if sim.tool.trim().is_empty() {
        return Err("tool must not be empty".into());
    }
    let server_name = sim
        .server
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let (mode, tool, args, server) = match sim.agent.as_str() {
        "claude-code" => {
            let (t, a, s) = map_claude_tool(&sim.tool, args, server_name);
            (InterceptMode::SdkHook, t, a, s)
        }
        "mcp" => {
            let server = server_name.map(|name| ServerIdentity {
                name,
                transport: "stdio".into(),
                version: None,
            });
            (InterceptMode::Mcp, sim.tool.clone(), args, server)
        }
        _ => {
            let server = server_name.map(|name| ServerIdentity {
                name,
                transport: "unknown".into(),
                version: None,
            });
            (InterceptMode::SdkHook, sim.tool.clone(), args, server)
        }
    };
    let mode = match sim.mode.as_deref().map(str::trim) {
        None | Some("") => mode,
        Some("mcp") => InterceptMode::Mcp,
        Some("processwrap") => InterceptMode::ProcessWrap,
        Some("sdkhook") => InterceptMode::SdkHook,
        Some(other) => {
            return Err(format!(
                "unknown mode {other:?} (expected mcp, processwrap, sdkhook)"
            ))
        }
    };
    let n = now_ms.max(0.0) as u64;
    Ok(ToolCall {
        call_id: sim.call_id.clone().unwrap_or_else(|| format!("call-{n:x}")),
        session_id: sim
            .session_id
            .clone()
            .unwrap_or_else(|| "playground".to_string()),
        caller: CallerIdentity {
            agent: sim.agent.clone(),
            agent_version: None,
            user: Some("playground".into()),
            non_human_id: None,
        },
        mode,
        tool,
        args: Value::Object(args),
        server,
        trust: parse_trust(sim.trust.as_deref())?,
        captured_at: ts(now_ms),
    })
}

fn verdict_kind(v: &Verdict) -> &'static str {
    match v {
        Verdict::Allow { .. } => "allow",
        Verdict::Deny { .. } => "deny",
        Verdict::Ask { .. } => "ask",
        Verdict::Redact { .. } => "redact",
    }
}

/// Evaluate one simulated call against a policy source.
///
/// Returns `{"ok": true, "kind", "verdict", "call", "ctx"}` — `verdict` is
/// the `provio_core::Verdict` JSON, `call` the normalised `ToolCall` (feed it
/// to [`ledger_record_decision`]), `ctx` the flattened policy view.
#[wasm_bindgen]
pub fn evaluate(src: &str, call_json: &str, now_ms: f64) -> String {
    let engine = match NativePolicyEngine::from_source(src) {
        Ok(e) => e,
        Err(e) => return err(e),
    };
    let sim: SimCall = match serde_json::from_str(call_json) {
        Ok(s) => s,
        Err(e) => return err(format!("call JSON: {e}")),
    };
    let call = match build_call(&sim, now_ms) {
        Ok(c) => c,
        Err(e) => return err(e),
    };
    let ctx = ToolCallContext::from_call(&call);
    let verdict = engine.evaluate(&ctx);
    json!({
        "ok": true,
        "kind": verdict_kind(&verdict),
        "verdict": verdict,
        "call": call,
        "ctx": ctx,
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Redact

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

/// Mask a tool result with a redact verdict's patterns, the way provio does
/// before the result re-enters the model's context. JSON objects/arrays
/// keep their shape (every string leaf is masked); anything else is masked
/// as text. The `output_hash` is of the ORIGINAL, as in the real ledger.
///
/// `{"ok": true, "masked", "matches", "output_hash"}`; an invalid pattern
/// is an error (fail closed, never an unmasked pass-through).
#[wasm_bindgen]
pub fn mask_output(patterns_json: &str, output: &str) -> String {
    let patterns: Vec<String> = match serde_json::from_str(patterns_json) {
        Ok(p) => p,
        Err(e) => return err(format!("patterns JSON: {e}")),
    };
    let mut res = Vec::with_capacity(patterns.len());
    for p in &patterns {
        match Regex::new(p) {
            Ok(r) => res.push(r),
            Err(e) => {
                return err(format!(
                    "redact pattern {p:?} does not compile ({e}); output withheld (fail closed)"
                ))
            }
        }
    }
    let count = std::cell::Cell::new(0usize);
    let mask_text = |text: &str| -> String {
        let mut out = text.to_string();
        for re in &res {
            count.set(count.get() + re.find_iter(&out).count());
            out = re.replace_all(&out, REDACTION_MARK).into_owned();
        }
        out
    };
    let masked = match serde_json::from_str::<Value>(output) {
        Ok(v @ (Value::Object(_) | Value::Array(_))) => {
            serde_json::to_string_pretty(&map_strings(&v, &mask_text)).unwrap_or_default()
        }
        _ => mask_text(output),
    };
    json!({
        "ok": true,
        "masked": masked,
        "matches": count.get(),
        "output_hash": LedgerRecord::hash_bytes(output.as_bytes()),
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Ledger

fn parse_prev(prev_json: &str) -> Result<(u64, String), String> {
    if prev_json.trim().is_empty() || prev_json.trim() == "null" {
        return Ok((0, GENESIS_HASH.to_string()));
    }
    let prev: LedgerRecord =
        serde_json::from_str(prev_json).map_err(|e| format!("previous record: {e}"))?;
    Ok((prev.index + 1, prev.record_hash))
}

fn parse_approver(approver_json: &str) -> Result<Option<ApproverIdentity>, String> {
    let t = approver_json.trim();
    if t.is_empty() || t == "null" {
        return Ok(None);
    }
    serde_json::from_str(t).map_err(|e| format!("approver: {e}"))
}

/// Build a `Decision` record — field for field what
/// `provio_core::LedgerWriter::record_decision` writes — chained onto `prev`
/// (a record JSON, or empty for the genesis record). The verdict stored is
/// the ENGINE's verdict; an approval is carried by `approver`
/// (`{"kind":"tui","id":"..."}`), exactly as `provio_core::handle_call` does.
pub fn decision_record(
    prev_json: &str,
    call: &ToolCall,
    verdict: &Verdict,
    approver: Option<ApproverIdentity>,
    now_ms: f64,
) -> Result<LedgerRecord, String> {
    let (index, prev_hash) = parse_prev(prev_json)?;
    let mut rec = LedgerRecord {
        schema_version: SCHEMA_VERSION,
        kind: RecordKind::Decision,
        index,
        call_id: call.call_id.clone(),
        session_id: call.session_id.clone(),
        call: Some(call.clone()),
        verdict: Some(verdict.clone()),
        rule_id: verdict.rule_id().map(|s| s.to_string()),
        approver,
        decision_index: None,
        backend: None,
        exit_status: None,
        input_hash: LedgerRecord::hash_call(call).map_err(|e| e.to_string())?,
        output_hash: None,
        recorded_at: ts(now_ms),
        prev_hash,
        record_hash: String::new(),
    };
    rec.record_hash = rec.compute_hash().map_err(|e| e.to_string())?;
    Ok(rec)
}

/// Build an `Execution` record linked to `decision` — field for field what
/// `provio_core::LedgerWriter::record_execution` writes.
pub fn execution_record(
    prev_json: &str,
    decision: &LedgerRecord,
    backend: &str,
    exit_status: i32,
    output: &[u8],
    now_ms: f64,
) -> Result<LedgerRecord, String> {
    if decision.kind != RecordKind::Decision {
        return Err("record_execution requires a decision record".into());
    }
    let (index, prev_hash) = parse_prev(prev_json)?;
    let mut rec = LedgerRecord {
        schema_version: SCHEMA_VERSION,
        kind: RecordKind::Execution,
        index,
        call_id: decision.call_id.clone(),
        session_id: decision.session_id.clone(),
        call: None,
        verdict: None,
        rule_id: decision.rule_id.clone(),
        approver: None,
        decision_index: Some(decision.index),
        backend: Some(backend.to_string()),
        exit_status: Some(exit_status),
        input_hash: decision.input_hash.clone(),
        output_hash: Some(LedgerRecord::hash_bytes(output)),
        recorded_at: ts(now_ms),
        prev_hash,
        record_hash: String::new(),
    };
    rec.record_hash = rec.compute_hash().map_err(|e| e.to_string())?;
    Ok(rec)
}

/// JSON wrapper for [`decision_record`]: `{"ok": true, "record"}`.
#[wasm_bindgen]
pub fn ledger_record_decision(
    prev_json: &str,
    call_json: &str,
    verdict_json: &str,
    approver_json: &str,
    now_ms: f64,
) -> String {
    let call: ToolCall = match serde_json::from_str(call_json) {
        Ok(c) => c,
        Err(e) => return err(format!("call: {e}")),
    };
    let verdict: Verdict = match serde_json::from_str(verdict_json) {
        Ok(v) => v,
        Err(e) => return err(format!("verdict: {e}")),
    };
    let approver = match parse_approver(approver_json) {
        Ok(a) => a,
        Err(e) => return err(e),
    };
    match decision_record(prev_json, &call, &verdict, approver, now_ms) {
        Ok(r) => json!({ "ok": true, "record": r }).to_string(),
        Err(e) => err(e),
    }
}

/// JSON wrapper for [`execution_record`]: `{"ok": true, "record"}`.
#[wasm_bindgen]
pub fn ledger_record_execution(
    prev_json: &str,
    decision_json: &str,
    backend: &str,
    exit_status: i32,
    output: &str,
    now_ms: f64,
) -> String {
    let decision: LedgerRecord = match serde_json::from_str(decision_json) {
        Ok(d) => d,
        Err(e) => return err(format!("decision record: {e}")),
    };
    match execution_record(
        prev_json,
        &decision,
        backend,
        exit_status,
        output.as_bytes(),
        now_ms,
    ) {
        Ok(r) => json!({ "ok": true, "record": r }).to_string(),
        Err(e) => err(e),
    }
}

fn lines(jsonl: &str) -> impl Iterator<Item = &str> {
    jsonl.lines().filter(|l| !l.trim().is_empty())
}

/// `provio verify` over a JSONL ledger (one record per line): the same
/// `provio_core::verify_chain`, with an unparseable record reported as a break
/// at its position (as provio-ledger's `verify_records` does).
///
/// `{"ok": true, "records", "intact", "broken_at", "why", "message"}` where
/// `message` is the CLI's line and `why` says which check failed.
#[wasm_bindgen]
pub fn ledger_verify(jsonl: &str) -> String {
    let mut parsed: Vec<LedgerRecord> = Vec::new();
    let mut parse_break: Option<(u64, String)> = None;
    for (i, line) in lines(jsonl).enumerate() {
        match serde_json::from_str::<LedgerRecord>(line) {
            Ok(r) => parsed.push(r),
            Err(e) => {
                parse_break = Some((i as u64, format!("record is not a valid LedgerRecord: {e}")));
                break;
            }
        }
    }
    let report = match verify_chain(parsed.iter().cloned().map(Ok)) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let (records, intact, broken_at, why) = if !report.intact {
        let at = report.broken_at.unwrap_or(0);
        let pos = report.records as usize;
        let why = parsed.get(pos).map(|rec| {
            let prev = if pos == 0 {
                GENESIS_HASH.to_string()
            } else {
                parsed[pos - 1].record_hash.clone()
            };
            if rec.index != report.records {
                format!(
                    "index is {} but {} records precede it (a record was removed or reordered)",
                    rec.index, report.records
                )
            } else if rec.prev_hash != prev {
                "prev_hash does not match the hash of the record before it".to_string()
            } else {
                "record_hash does not match the record's contents (it was edited)".to_string()
            }
        });
        (report.records, false, Some(at), why)
    } else if let Some((i, why)) = parse_break {
        (i, false, Some(i), Some(why))
    } else {
        (report.records, true, None, None)
    };
    let message = if intact {
        format!("chain intact · {records} records · no gaps")
    } else {
        format!(
            "chain BROKEN at record {} · {records} records verified before the break",
            broken_at.unwrap_or(0)
        )
    };
    json!({
        "ok": true,
        "records": records,
        "intact": intact,
        "broken_at": broken_at,
        "why": why,
        "message": message,
    })
    .to_string()
}

/// Simulate an attacker editing the ledger file (the page's "tamper"
/// button). Returns the edited JSONL; hashes are NOT recomputed unless the
/// mode says so, which is what makes the edit visible to `ledger_verify`.
///
/// Modes: `"edit"` — rewrite the record's content (a deny/ask becomes an
/// allow, an allow's command is changed, an execution's exit status flips);
/// `"edit-rehash"` — the same edit, and the attacker also recomputes that
/// record's own hash (the break then shows at the next record's link);
/// `"delete"` — drop the record.
#[wasm_bindgen]
pub fn ledger_tamper(jsonl: &str, index: u32, mode: &str) -> String {
    let mut recs: Vec<String> = lines(jsonl).map(str::to_string).collect();
    let i = index as usize;
    if i >= recs.len() {
        return err(format!("no record at index {index}"));
    }
    if mode == "delete" {
        recs.remove(i);
        return json!({ "ok": true, "jsonl": recs.join("\n"), "what": format!("deleted record {index}") })
            .to_string();
    }
    let mut rec: LedgerRecord = match serde_json::from_str(&recs[i]) {
        Ok(r) => r,
        Err(e) => return err(format!("record {index}: {e}")),
    };
    let what = match (&rec.verdict, rec.kind) {
        (Some(Verdict::Allow { .. }), _) => {
            if let Some(call) = rec.call.as_mut() {
                if let Some(m) = call.args.as_object_mut() {
                    m.insert("note".into(), json!("edited after the fact"));
                }
            }
            format!("added an argument to the allowed call in record {index}")
        }
        (Some(v), _) => {
            let rule = v.rule_id().map(str::to_string);
            rec.verdict = Some(Verdict::Allow {
                rule_id: rule.clone(),
            });
            rec.rule_id = rule;
            format!("rewrote record {index}'s verdict to allow")
        }
        (None, RecordKind::Execution) => {
            rec.exit_status = Some(if rec.exit_status == Some(0) { 1 } else { 0 });
            format!("flipped the exit status in record {index}")
        }
        (None, RecordKind::Decision) => {
            rec.session_id.push_str("-edited");
            format!("edited the session id in record {index}")
        }
    };
    let what = if mode == "edit-rehash" {
        match rec.compute_hash() {
            Ok(h) => rec.record_hash = h,
            Err(e) => return err(e),
        }
        format!("{what} and recomputed its hash")
    } else {
        what
    };
    recs[i] = match serde_json::to_string(&rec) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    json!({ "ok": true, "jsonl": recs.join("\n"), "what": what }).to_string()
}

// ---------------------------------------------------------------------------
// Replay

/// Pair decisions with their executions for one session (or every session
/// when `session_id` is empty) — `provio_replay::load_trajectory` without the
/// filesystem.
pub fn trajectory(records: &[LedgerRecord], session_id: &str) -> Vec<RecordedStep> {
    let mut decisions: Vec<LedgerRecord> = Vec::new();
    let mut executions: HashMap<u64, LedgerRecord> = HashMap::new();
    for rec in records {
        if !session_id.is_empty() && rec.session_id != session_id {
            continue;
        }
        match rec.kind {
            RecordKind::Decision => decisions.push(rec.clone()),
            RecordKind::Execution => {
                if let Some(di) = rec.decision_index {
                    executions.insert(di, rec.clone());
                }
            }
        }
    }
    decisions
        .into_iter()
        .map(|d| {
            let e = executions.get(&d.index).cloned();
            RecordedStep {
                decision: d,
                execution: e,
            }
        })
        .collect()
}

/// `provio replay <session> --candidate <file>`: which recorded verdicts the
/// candidate policy would change. The change list and summary are
/// `provio_replay::policy_replay`'s; `steps` adds a per-call row for display.
#[wasm_bindgen]
pub fn replay(jsonl: &str, session_id: &str, candidate_src: &str) -> String {
    let mut records = Vec::new();
    for (i, line) in lines(jsonl).enumerate() {
        match serde_json::from_str::<LedgerRecord>(line) {
            Ok(r) => records.push(r),
            Err(e) => return err(format!("ledger line {}: {e}", i + 1)),
        }
    }
    let steps = trajectory(&records, session_id);
    if steps.is_empty() {
        return err(if session_id.is_empty() {
            "no recorded calls in this ledger".to_string()
        } else {
            format!("no recorded calls for session '{session_id}'")
        });
    }
    let report = match provio_replay::policy_replay(&steps, candidate_src) {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    // Display rows: same engine, same normalisation as policy_replay.
    let engine = match NativePolicyEngine::from_source(candidate_src) {
        Ok(e) => e,
        Err(e) => return err(e),
    };
    let rows: Vec<Value> = steps
        .iter()
        .filter_map(|s| {
            let call = s.decision.call.as_ref()?;
            let was = s.decision.verdict.as_ref()?;
            let now = engine.evaluate(&ToolCallContext::from_call(call));
            let (w, n) = (verdict_kind(was), verdict_kind(&now));
            Some(json!({
                "index": s.decision.index,
                "call_id": call.call_id,
                "tool": call.tool,
                "args": call.args,
                "was": w,
                "was_rule": was.rule_id(),
                "executed": s.execution.is_some(),
                "now": n,
                "now_rule": now.rule_id(),
                "now_verdict": now,
                "changed": w != n,
                "newly_blocked": w == "allow" && (n == "deny" || n == "ask"),
            }))
        })
        .collect();
    let changes: Vec<Value> = report
        .changes
        .iter()
        .map(|c| {
            json!({
                "call_id": c.call_id, "tool": c.tool, "was": c.was,
                "now": c.now, "now_rule": c.now_rule,
            })
        })
        .collect();
    json!({
        "ok": true,
        "summary": report.summary(),
        "steps": report.steps,
        "unchanged": report.unchanged,
        "changes": changes,
        "rows": rows,
    })
    .to_string()
}

/// Turn a community pack (`packs/<id>/pack.yaml`: `id`, `version`,
/// `description`, `rules`) into a standalone provio.yaml the engine loads:
/// the pack header becomes a comment and `version: 1` / `default: ask`
/// (fail closed) are prepended. Rule text is kept byte for byte, so the
/// editor shows the pack as written.
#[wasm_bindgen]
pub fn pack_to_policy(pack_yaml: &str) -> String {
    let mut header = Vec::new();
    let mut body = Vec::new();
    for line in pack_yaml.lines() {
        let top = !line.starts_with(|c: char| c.is_whitespace() || c == '-' || c == '#');
        let key = line.split(':').next().unwrap_or("").trim();
        if top && matches!(key, "id" | "version" | "description") {
            header.push(format!("# pack {line}"));
        } else {
            body.push(line.to_string());
        }
    }
    let nl = "\u{a}";
    let mut out = header.join(nl);
    out.push_str(nl);
    out.push_str("# Packs carry rules only; the playground adds the fail-closed header.");
    out.push_str(nl);
    out.push_str("version: 1");
    out.push_str(nl);
    out.push_str("default: ask");
    out.push_str(nl);
    out.push_str(nl);
    out.push_str(body.join(nl).trim_end());
    out.push_str(nl);
    out
}

/// The approver identity the playground records for an answered ask
/// (a TUI approver, like `provio run`'s prompt).
#[wasm_bindgen]
pub fn playground_approver() -> String {
    serde_json::to_string(&ApproverIdentity {
        kind: ApproverKind::Tui,
        id: "playground".into(),
    })
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_location_is_split() {
        let v = parse_error_location("provio.yaml:7: rule \"x\": invalid `when`: boom");
        assert_eq!(v["line"], 7);
        assert!(v["column"].is_null());
        let v = parse_error_location("provio.yaml:3:5: did not find expected key");
        assert_eq!(
            (v["line"].as_u64(), v["column"].as_u64()),
            (Some(3), Some(5))
        );
        let v = parse_error_location("provio.yaml: top-level key \"x\" must be a mapping");
        assert!(v["line"].is_null());
    }
}
