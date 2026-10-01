//! `provio mcp serve`: provio as an MCP server (stdio, newline-delimited
//! JSON-RPC 2.0). Read-only tools an agent can use to ask provio before it
//! acts, and to read back what was decided:
//!
//! - `check_tool_call`: what the policy would decide for a call (not run,
//!   not recorded);
//! - `recent_decisions`: the latest decisions in the ledger;
//! - `list_sessions`: sessions in the ledger, with denials and approvals;
//! - `verify_ledger`: is the hash chain intact;
//! - `policy_info`: which policy judges calls, and the bundled packs.
//!
//! It never dispatches a call and never writes the ledger. Governing calls is
//! the job of the hooks and of `provio proxy`.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use provio_core::ledger::RecordKind;
use provio_core::verdict::Verdict;
use serde_json::{json, Value};

const PROTOCOL: &str = "2025-06-18";
const SUPPORTED: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

pub fn serve(policy: &Path, ledger: &Path) -> Result<()> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(reply) = handle_line(policy, ledger, &line) {
            writeln!(out, "{reply}")?;
            out.flush()?;
        }
    }
    Ok(())
}

/// One JSON-RPC message in, at most one reply out (none for notifications).
pub(crate) fn handle_line(policy: &Path, ledger: &Path, line: &str) -> Option<Value> {
    let msg: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return Some(error(Value::Null, -32700, &format!("parse error: {e}"))),
    };
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or(json!({}));
    let Some(id) = id else {
        return None; // notification (initialized, cancelled, ...)
    };
    let result = match method {
        "initialize" => Ok(initialize(&params)),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => Ok(call_tool(policy, ledger, &params)),
        "resources/list" => Ok(json!({ "resources": [] })),
        "prompts/list" => Ok(json!({ "prompts": [] })),
        _ => Err((-32601, format!("method not found: {method}"))),
    };
    Some(match result {
        Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
        Err((code, m)) => error(id, code, &m),
    })
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn initialize(params: &Value) -> Value {
    let asked = params.get("protocolVersion").and_then(Value::as_str);
    let version = asked.filter(|v| SUPPORTED.contains(v)).unwrap_or(PROTOCOL);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": { "name": "provio", "title": "provio", "version": env!("CARGO_PKG_VERSION") },
        "instructions": "provio checks AI agent tool calls against a policy (provio.yaml) and records every decision in a tamper-evident ledger. Use check_tool_call before a risky shell command, file write or network call to see whether the policy allows, denies, asks about or redacts it; use recent_decisions and verify_ledger to review what was decided. These tools only read: they never run a call."
    })
}

fn read_only() -> Value {
    json!({ "readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false })
}

fn tools() -> Value {
    json!([
        {
            "name": "check_tool_call",
            "title": "Check a tool call against the policy",
            "description": "What provio's policy would decide for a tool call: allow, deny (with the rule and the reason), ask (a human must approve) or redact. Give a shell command, or a tool name with its arguments (fs.read / fs.write with path, http with url, an MCP tool with server). Scripts the command runs or writes are judged too. Nothing is run or recorded.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": { "type": "string", "description": "A shell command, as an agent would run it." },
                    "tool": { "type": "string", "description": "Another tool instead of a shell command: fs.read, fs.write, http, or an MCP tool name." },
                    "args": { "type": "object", "description": "The tool's arguments, e.g. {\"path\": \"~/.ssh/id_rsa\"} or {\"url\": \"https://...\"}." },
                    "server": { "type": "string", "description": "The MCP server the tool belongs to." },
                    "cwd": { "type": "string", "description": "Directory the call would run in (to read the scripts it runs). Defaults to the server's directory." }
                }
            },
            "annotations": read_only()
        },
        {
            "name": "recent_decisions",
            "title": "Recent decisions",
            "description": "The latest decisions recorded in the provio ledger, newest first: when, which session, the call, the verdict and the rule that decided it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 20 },
                    "session": { "type": "string", "description": "Only this session id." },
                    "verdict": { "type": "string", "enum": ["allow", "deny", "ask", "redact"], "description": "Only this verdict." }
                }
            },
            "annotations": read_only()
        },
        {
            "name": "list_sessions",
            "title": "Sessions in the ledger",
            "description": "Every agent session in the provio ledger with its record count, how many calls were denied, and whether a human approved anything.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": read_only()
        },
        {
            "name": "verify_ledger",
            "title": "Verify the ledger",
            "description": "Recompute the provio ledger's hash chain: intact, or the first record where it breaks (a record edited, removed or reordered).",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": read_only()
        },
        {
            "name": "policy_info",
            "title": "Policy in force",
            "description": "Which policy judges calls (the provio.yaml in use, or the starter packs when there is none), its text, and the bundled policy packs it can compose.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": read_only()
        }
    ])
}

fn call_tool(policy: &Path, ledger: &Path, params: &Value) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let out = match name {
        "check_tool_call" => check(policy, &args),
        "recent_decisions" => recent(ledger, &args),
        "list_sessions" => sessions(ledger),
        "verify_ledger" => verify(ledger),
        "policy_info" => policy_info(policy),
        _ => Err(anyhow::anyhow!("unknown tool: {name}")),
    };
    match out {
        Ok(v) => json!({
            "content": [{ "type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_default() }],
            "structuredContent": v,
            "isError": false
        }),
        Err(e) => json!({
            "content": [{ "type": "text", "text": e.to_string() }],
            "isError": true
        }),
    }
}

fn check(policy: &Path, args: &Value) -> Result<Value> {
    let s = |k: &str| args.get(k).and_then(Value::as_str).map(str::to_string);
    let call = match (s("command"), s("tool")) {
        (Some(c), None) => json!({ "tool": "bash", "args": { "command": c } }),
        (None, Some(t)) => json!({
            "tool": t,
            "args": args.get("args").cloned().unwrap_or(json!({})),
            "server": s("server"),
        }),
        (Some(_), Some(_)) => anyhow::bail!("give either command or tool, not both"),
        (None, None) => anyhow::bail!("give a shell command, or a tool with its args"),
    };
    let test = crate::onboard::TestArgs {
        command: vec![],
        tool: None,
        path: None,
        url: None,
        query: None,
        content: None,
        server: None,
        call: Some(call.to_string()),
        packs: vec![],
        json: true,
    };
    let call = crate::onboard::test_call(&test)?;
    let (engine, label) = crate::onboard::judging_policy(policy, &[])?;
    let cwd = s("cwd").map(PathBuf::from).filter(|p| p.is_dir());
    let verdict = match cwd {
        Some(dir) => crate::inspect::evaluate_in(&engine, &call, &dir),
        None => crate::inspect::evaluate(&engine, &call),
    };
    let (decision, rule, why, location) = match &verdict {
        Verdict::Allow { rule_id } => ("allow", rule_id.clone(), None, None),
        Verdict::Redact { rule_id, .. } => (
            "redact",
            Some(rule_id.clone()),
            Some("Runs; matching output is masked before the model sees it.".to_string()),
            None,
        ),
        Verdict::Deny {
            rule_id,
            reason,
            location,
        } => (
            "deny",
            Some(rule_id.clone()),
            Some(reason.clone()),
            location.clone(),
        ),
        Verdict::Ask {
            rule_id,
            diff,
            location,
            ..
        } => (
            "ask",
            Some(rule_id.clone()),
            Some(diff.clone()),
            location.clone(),
        ),
    };
    Ok(json!({
        "decision": decision,
        "rule": rule,
        "reason": why,
        "location": location,
        "policy": label,
        "call": { "tool": call.tool, "args": call.args },
        "verdict": verdict,
    }))
}

fn no_ledger(ledger: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "no ledger at {} yet: decisions are recorded once an agent runs under provio (`provio init`)",
        crate::cmds::show_ledger(ledger)
    )
}

fn verdict_name(v: &Verdict) -> &'static str {
    match v {
        Verdict::Allow { .. } => "allow",
        Verdict::Deny { .. } => "deny",
        Verdict::Ask { .. } => "ask",
        Verdict::Redact { .. } => "redact",
    }
}

fn summary(call: &provio_core::call::ToolCall) -> String {
    let text = match call.args.get("command").and_then(Value::as_str) {
        Some(c) => c.to_string(),
        None => format!("{} {}", call.tool, call.args),
    };
    if text.chars().count() > 200 {
        format!("{}…", text.chars().take(200).collect::<String>())
    } else {
        text
    }
}

fn recent(ledger: &Path, args: &Value) -> Result<Value> {
    if !crate::cmds::ledger_present(ledger) {
        return Err(no_ledger(ledger));
    }
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(20)
        .clamp(1, 200) as usize;
    let session = args.get("session").and_then(Value::as_str);
    let want = args.get("verdict").and_then(Value::as_str);
    let store = provio_ledger::open_store(ledger).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let mut ring: std::collections::VecDeque<Value> = std::collections::VecDeque::new();
    for item in store.iter() {
        let rec = item.map_err(|e| anyhow::anyhow!(e.to_string()))?;
        if rec.kind != RecordKind::Decision || session.is_some_and(|s| s != rec.session_id) {
            continue;
        }
        let (Some(call), Some(v)) = (&rec.call, &rec.verdict) else {
            continue;
        };
        if want.is_some_and(|w| w != verdict_name(v)) {
            continue;
        }
        ring.push_back(json!({
            "index": rec.index,
            "recorded_at": rec.recorded_at,
            "session": rec.session_id,
            "agent": call.caller.agent,
            "tool": call.tool,
            "call": summary(call),
            "verdict": verdict_name(v),
            "rule": rec.rule_id,
        }));
        if ring.len() > limit {
            ring.pop_front();
        }
    }
    let decisions: Vec<Value> = ring.into_iter().rev().collect();
    Ok(json!({ "ledger": crate::cmds::show_ledger(ledger), "decisions": decisions }))
}

fn sessions(ledger: &Path) -> Result<Value> {
    if !crate::cmds::ledger_present(ledger) {
        return Err(no_ledger(ledger));
    }
    let all = provio_ledger::sessions(ledger).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let list: Vec<Value> = all
        .iter()
        .map(|s| {
            json!({
                "session": s.session_id,
                "records": s.records,
                "denied": s.denied,
                "approved_by_human": s.approved_by_human,
            })
        })
        .collect();
    Ok(json!({ "ledger": crate::cmds::show_ledger(ledger), "sessions": list }))
}

fn verify(ledger: &Path) -> Result<Value> {
    if !crate::cmds::ledger_present(ledger) {
        return Err(no_ledger(ledger));
    }
    let r = provio_ledger::verify(ledger).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(json!({
        "ledger": crate::cmds::show_ledger(ledger),
        "intact": r.intact,
        "records": r.records,
        "broken_at": r.broken_at,
        "summary": if r.intact {
            format!("chain intact · {} records · no gaps", r.records)
        } else {
            format!("chain BROKEN at record {} · {} records verified before the break", r.broken_at.unwrap_or(0), r.records)
        },
    }))
}

fn policy_info(policy: &Path) -> Result<Value> {
    let (_, label) = crate::onboard::judging_policy(policy, &[])?;
    let text = std::fs::read_to_string(policy).ok();
    let packs: Vec<&str> = provio_policy::packs::BUNDLED
        .iter()
        .map(|(id, _)| *id)
        .collect();
    Ok(json!({
        "policy": label,
        "file": policy.exists().then(|| policy.display().to_string()),
        "text": text,
        "bundled_packs": packs,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rpc(policy: &Path, ledger: &Path, msg: Value) -> Value {
        handle_line(policy, ledger, &msg.to_string()).expect("a reply")
    }

    #[test]
    fn initialize_list_and_check() {
        let dir = std::env::temp_dir().join(format!("provio-mcp-serve-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (policy, ledger) = (dir.join("provio.yaml"), dir.join(".provio/ledger.jsonl"));
        let init = rpc(
            &policy,
            &ledger,
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}}),
        );
        assert_eq!(init["result"]["serverInfo"]["name"], "provio");
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        assert!(handle_line(
            &policy,
            &ledger,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
        )
        .is_none());
        let list = rpc(
            &policy,
            &ledger,
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        );
        let names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "check_tool_call",
                "recent_decisions",
                "list_sessions",
                "verify_ledger",
                "policy_info"
            ]
        );
        // No provio.yaml: judged by the starter packs.
        let c = rpc(
            &policy,
            &ledger,
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "check_tool_call", "arguments": {"command": "rm -rf ~"}}}),
        );
        assert_eq!(c["result"]["structuredContent"]["decision"], "deny", "{c}");
        assert_eq!(c["result"]["isError"], false);
        let c = rpc(
            &policy,
            &ledger,
            json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "check_tool_call", "arguments": {"tool": "fs.read", "args": {"path": "/home/a/.ssh/id_rsa"}}}}),
        );
        assert_eq!(c["result"]["structuredContent"]["decision"], "deny", "{c}");
        // No ledger yet: a tool error, not a protocol error.
        let v = rpc(
            &policy,
            &ledger,
            json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "verify_ledger", "arguments": {}}}),
        );
        assert_eq!(v["result"]["isError"], true);
        let e = rpc(
            &policy,
            &ledger,
            json!({"jsonrpc": "2.0", "id": 6, "method": "nope"}),
        );
        assert_eq!(e["error"]["code"], -32601);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
