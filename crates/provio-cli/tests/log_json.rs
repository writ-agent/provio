//! `provio log --json`: one JSON object per session, for scripts and CI.

mod check_common;

use check_common::*;
use serde_json::{json, Value};

fn pre(session: &str, id: &str, command: &str) -> Value {
    json!({
        "session_id": session,
        "turn_id": "turn-1",
        "transcript_path": null,
        "cwd": "/work/proj",
        "hook_event_name": "PreToolUse",
        "model": "gpt-5-codex",
        "permission_mode": "default",
        "tool_name": "Bash",
        "tool_input": { "command": command },
        "tool_use_id": id,
    })
}

fn stdout(out: &std::process::Output) -> String {
    assert!(
        out.status.success(),
        "provio failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn session<'a>(sessions: &'a [Value], needle: &str) -> &'a Value {
    sessions
        .iter()
        .find(|s| s["session_id"].as_str().unwrap().contains(needle))
        .unwrap_or_else(|| panic!("no session {needle} in {sessions:?}"))
}

#[test]
fn log_json_prints_one_object_per_session() {
    let p = Project::new();
    p.hook("codex", &[], &pre("thr-a", "c1", "ls"));
    p.hook("codex", &[], &pre("thr-a", "c2", "echo hi"));
    p.hook("codex", &[], &pre("thr-b", "c3", "rm -rf /"));

    let text = stdout(&p.provio(&["log", "--json"], ""));
    let sessions: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON: {l:?}: {e}")))
        .collect();
    assert_eq!(sessions.len(), 2, "{text}");

    // Every line is a full session summary and nothing else (no table header).
    for s in &sessions {
        let keys: Vec<&str> = s.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys.len(), 4, "unexpected fields in {s}: {keys:?}");
        assert!(s["session_id"].is_string() && s["records"].is_u64());
        assert!(s["denied"].is_u64() && s["approved_by_human"].is_boolean());
    }

    assert_eq!(session(&sessions, "thr-a")["denied"], 0);
    assert_eq!(session(&sessions, "thr-b")["denied"], 1);
    assert_eq!(session(&sessions, "thr-b")["approved_by_human"], false);

    // The per-session counts add up to the ledger.
    let total: u64 = sessions
        .iter()
        .map(|s| s["records"].as_u64().unwrap())
        .sum();
    assert_eq!(total as usize, p.records().len());
}

#[test]
fn log_without_json_keeps_the_table() {
    let p = Project::new();
    p.hook("codex", &[], &pre("thr-a", "c1", "ls"));
    let text = stdout(&p.provio(&["log"], ""));
    let mut lines = text.lines();
    assert!(lines.next().unwrap().contains("1 sessions"), "{text}");
    assert!(lines.next().unwrap().starts_with("session"), "{text}");
    assert!(serde_json::from_str::<Value>(text.lines().last().unwrap()).is_err());
}

#[test]
fn log_json_without_a_ledger_fails_like_the_table() {
    let p = Project::new();
    let out = p.provio(&["log", "--json"], "");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no ledger"));
    assert!(out.stdout.is_empty());
}
