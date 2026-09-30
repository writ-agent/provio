//! Policy screen: validate, "try a tool call" (no ledger write), save
//! (atomic, `.bak` kept), and the bundled packs.

use std::path::Path;

use provio_core::call::{
    CallerIdentity, InterceptMode, ServerIdentity, ToolCall, ToolCallContext, TrustVerdict,
};
use provio_core::verdict::Verdict;
use provio_core::{PolicyEngine, Timestamp};
use provio_ledger::StoreKind;
use provio_policy::policy_file::{compile, RuleVerdict};
use provio_policy::NativePolicyEngine;
use serde_json::{json, Value};

use super::approvals::write_atomic;
use super::http::Response;
use super::ledger::verdict_kind;

/// Packs shipped with provio, embedded at build time (see `build.rs`).
pub(crate) const PACKS: &[(&str, &str)] = crate::packs::BUNDLED;

/// Largest policy the editor accepts.
const MAX_POLICY: usize = 512 * 1024;

fn first_line_number(msg: &str) -> Option<usize> {
    let i = msg.find("provio.yaml:")? + "provio.yaml:".len();
    let digits: String = msg[i..].chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

fn rv(v: RuleVerdict) -> &'static str {
    match v {
        RuleVerdict::Allow => "allow",
        RuleVerdict::Deny => "deny",
        RuleVerdict::Ask => "ask",
        RuleVerdict::Redact => "redact",
    }
}

/// Compile `source`: `{ok, error?, line?, rules[], default}`.
pub(crate) fn validate(source: &str) -> Value {
    match compile(source) {
        Ok(p) => json!({
            "ok": true,
            "default": serde_json::to_value(p.default).unwrap_or(Value::Null),
            "rules": p.rules.iter().map(|r| json!({
                "id": r.id, "verdict": rv(r.verdict), "line": r.line,
                "reason": r.reason, "irreversible": r.irreversible, "timeout_ms": r.timeout_ms,
            })).collect::<Vec<_>>(),
        }),
        Err(e) => json!({"ok": false, "error": e, "line": first_line_number(&e)}),
    }
}

/// The source line of `rule_id` in `source`, if the rule exists.
pub(crate) fn rule_line(source: &str, rule_id: &str) -> Option<usize> {
    compile(source)
        .ok()?
        .rules
        .into_iter()
        .find(|r| r.id == rule_id)
        .and_then(|r| r.line)
}

/// Build the call the tester evaluates.
pub(crate) fn tester_call(body: &Value) -> Result<ToolCall, String> {
    let tool = body
        .get("tool")
        .and_then(Value::as_str)
        .filter(|t| !t.trim().is_empty())
        .ok_or("pick a tool")?
        .trim()
        .to_string();
    let args = match body.get("args") {
        None | Some(Value::Null) => json!({}),
        Some(v @ Value::Object(_)) => v.clone(),
        Some(_) => return Err("args must be a JSON object".into()),
    };
    let server = body
        .get("server")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(|s| ServerIdentity {
            name: s.trim().to_string(),
            transport: "stdio".into(),
            version: None,
        });
    let trust: Option<TrustVerdict> = match body.get("trust").and_then(Value::as_str) {
        None | Some("") => None,
        Some(t) => Some(
            serde_json::from_value(json!(t)).map_err(|_| format!("unknown trust value {t:?}"))?,
        ),
    };
    let mode = match body.get("mode").and_then(Value::as_str) {
        None | Some("") => {
            if server.is_some() {
                InterceptMode::Mcp
            } else {
                InterceptMode::SdkHook
            }
        }
        Some(m) => serde_json::from_value(json!(m)).map_err(|_| format!("unknown mode {m:?}"))?,
    };
    let agent = body
        .get("agent")
        .and_then(Value::as_str)
        .filter(|a| !a.is_empty())
        .unwrap_or("provio-ui-tester");
    Ok(ToolCall {
        call_id: "provio-ui-tester".into(),
        session_id: "provio-ui-tester".into(),
        caller: CallerIdentity {
            agent: agent.to_string(),
            agent_version: None,
            user: None,
            non_human_id: None,
        },
        mode,
        tool,
        args,
        server,
        trust,
        captured_at: Timestamp::now(),
    })
}

/// Evaluate a verdict for display: kind, rule, reason, line.
pub(crate) fn describe_verdict(v: &Verdict, source: &str) -> Value {
    let rule = v.rule_id().map(str::to_string);
    let line = match v {
        Verdict::Deny { location, .. } | Verdict::Ask { location, .. } => location
            .as_deref()
            .and_then(first_line_number)
            .or_else(|| rule.as_deref().and_then(|r| rule_line(source, r))),
        _ => rule.as_deref().and_then(|r| rule_line(source, r)),
    };
    let mut out = json!({
        "verdict": verdict_kind(v),
        "rule_id": rule,
        "line": line,
        "default": rule.as_deref().is_none_or(|r| r == "default") && line.is_none(),
        "raw": v,
    });
    match v {
        Verdict::Deny { reason, .. } => out["reason"] = json!(reason),
        Verdict::Ask {
            diff,
            timeout_ms,
            irreversible,
            ..
        } => {
            out["reason"] = json!(diff);
            out["timeout_ms"] = json!(timeout_ms);
            out["irreversible"] = json!(irreversible);
        }
        Verdict::Redact { patterns, .. } => out["patterns"] = json!(patterns),
        Verdict::Allow { .. } => {}
    }
    out
}

/// `--yolo` flips the default exactly as `load_engine` does.
pub(crate) fn engine_for(source: &str, yolo: bool) -> Result<NativePolicyEngine, String> {
    let src = if yolo {
        source.replacen("default: ask", "default: allow", 1)
    } else {
        source.to_string()
    };
    NativePolicyEngine::from_source(&src).map_err(|e| e.to_string())
}

/// The tester: evaluate one call against `source`; nothing is recorded.
pub(crate) fn test(body: &Value, source: &str, yolo: bool) -> Response {
    let engine = match engine_for(source, yolo) {
        Ok(e) => e,
        Err(e) => {
            return Response::ok(json!({"ok": false, "error": e, "line": first_line_number(&e)}))
        }
    };
    let call = match tester_call(body) {
        Ok(c) => c,
        Err(e) => return Response::error(400, "bad_request", &e),
    };
    let ctx = ToolCallContext::from_call(&call);
    let v = engine.evaluate(&ctx);
    Response::ok(json!({
        "ok": true,
        "result": describe_verdict(&v, source),
        "context": ctx,
        "recorded": false,
    }))
}

/// Save: only the configured policy file; the new source must compile; the
/// file on disk must still be the one the editor loaded (`base_sha256`).
pub(crate) fn save(path: &Path, body: &Value) -> Response {
    let Some(source) = body.get("source").and_then(Value::as_str) else {
        return Response::error(400, "bad_request", "save needs \"source\"");
    };
    if source.len() > MAX_POLICY {
        return Response::error(413, "too_large", "policy is larger than 512 KiB");
    }
    if let Err(e) = compile(source) {
        return Response::json(
            422,
            &json!({"error": {"code": "invalid_policy", "message": e,
                "line": first_line_number(&e)}}),
        );
    }
    let current = std::fs::read(path).ok();
    let current_sha = current
        .as_deref()
        .map(provio_core::ledger::LedgerRecord::hash_bytes);
    let base = body.get("base_sha256").and_then(Value::as_str);
    if current_sha.as_deref() != base {
        return Response::error(
            409,
            "conflict",
            "the policy file changed on disk since the editor loaded it; reload before saving",
        );
    }
    if let Some(old) = &current {
        let mut bak = path.as_os_str().to_owned();
        bak.push(".bak");
        if let Err(e) = write_atomic(Path::new(&bak), old) {
            return Response::error(500, "io", &format!("could not write the .bak copy: {e}"));
        }
    }
    if let Err(e) = write_atomic(path, source.as_bytes()) {
        return Response::error(500, "io", &format!("could not write the policy: {e}"));
    }
    Response::ok(json!({
        "saved": true,
        "path": path.display().to_string(),
        "sha256": provio_core::ledger::LedgerRecord::hash_bytes(source.as_bytes()),
        "backup": current.is_some(),
    }))
}

/// The packs, with their rules pre-indented for insertion under `rules:`.
pub(crate) fn packs() -> Value {
    let list: Vec<Value> = PACKS
        .iter()
        .map(|(name, src)| {
            let v: serde_yaml::Value = serde_yaml::from_str(src).unwrap_or_default();
            let desc = v
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();
            let rules = src
                .find("rules:")
                .map(|i| src[i + "rules:".len()..].trim_start_matches(['\r', '\n']))
                .unwrap_or("")
                .trim_end()
                .to_string();
            let count = v
                .get("rules")
                .and_then(|r| r.as_sequence())
                .map_or(0, Vec::len);
            json!({"name": name, "description": desc, "rules": rules, "rule_count": count,
                "sha256": provio_core::ledger::LedgerRecord::hash_bytes(src.as_bytes())})
        })
        .collect();
    json!({ "packs": list })
}

/// Whether the ledger kind at `path` can be read by this build.
pub(crate) fn ledger_kind(path: &Path) -> &'static str {
    match provio_ledger::detect_store_kind(path) {
        Ok(StoreKind::Jsonl) => "jsonl",
        Ok(StoreKind::Sqlite) => "sqlite",
        Ok(StoreKind::Postgres) => "postgres",
        Err(_) => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_embed_and_parse() {
        let p = packs();
        let list = p["packs"].as_array().unwrap();
        assert!(
            list.len() >= 9,
            "expected every pack in packs/, got {}",
            list.len()
        );
        assert!(list.iter().any(|x| x["name"] == "aws-safety"));
        for pk in list {
            assert!(pk["rule_count"].as_u64().unwrap() > 0);
            // What the editor inserts under `rules:` must compile as-is.
            let rules = pk["rules"].as_str().unwrap();
            let policy = format!("version: 1\ndefault: ask\nrules:\n{rules}\n");
            if let Err(e) = provio_policy::NativePolicyEngine::from_source(&policy) {
                panic!("pack {} snippet does not compile: {e}", pk["name"]);
            }
        }
    }

    #[test]
    fn validation_reports_the_line() {
        let bad =
            "version: 1\ndefault: ask\nrules:\n  - id: x\n    when: tool ==\n    verdict: deny\n";
        let v = validate(bad);
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("provio.yaml"));
        assert!(v["line"].as_u64().is_some(), "{v}");
    }
}
