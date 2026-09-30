//! `provio check --format cursor`, `provio integrate cursor`,
//! `provio run -- cursor-agent` driven exactly as Cursor drives them (payload
//! shapes from https://cursor.com/docs/hooks).

mod check_common;

use check_common::*;
use serde_json::{json, Value};

fn base(event: &str) -> Value {
    json!({
        "conversation_id": "conv-1",
        "generation_id": "gen-1",
        "model": "claude-opus",
        "hook_event_name": event,
        "cursor_version": "1.7.2",
        "workspace_roots": ["/work/proj"],
        "user_email": null,
        "transcript_path": null,
    })
}

fn pre(id: &str, tool: &str, input: Value) -> Value {
    let mut v = base("preToolUse");
    v["tool_name"] = json!(tool);
    v["tool_input"] = input;
    v["tool_use_id"] = json!(id);
    v["cwd"] = json!("/work/proj");
    v
}

fn post(id: &str, tool: &str, input: Value, output: &str) -> Value {
    let mut v = pre(id, tool, input);
    v["hook_event_name"] = json!("postToolUse");
    v["tool_output"] = json!(output);
    v["duration"] = json!(12);
    v
}

fn mcp(server: Option<&str>, tool: &str, input: Value) -> Value {
    let mut v = base("beforeMCPExecution");
    v["tool_name"] = json!(tool);
    v["tool_input"] = json!(input.to_string());
    if let Some(s) = server {
        v["mcp_server_name"] = json!(s);
    }
    v["command"] = json!("npx -y @modelcontextprotocol/server-github");
    v
}

/// Cursor blocks on `permission: "deny"`; provio exits 0 so no shell can
/// turn the answer into a non-blocking failure (and `failClosed` blocks
/// any failure of the hook itself).
fn assert_denies(h: &Hook, what: &str) {
    assert_eq!(h.code, 0, "{what}: exit 0 with a deny ({h:?})");
    assert!(h.json.is_some(), "{what}: no JSON ({h:?})");
    assert_eq!(h.j()["permission"], "deny", "{what}");
    assert!(
        !h.j()["user_message"].as_str().unwrap_or("").is_empty(),
        "{what}"
    );
    assert!(!h.stderr.trim().is_empty(), "{what}: reason on stderr");
}

fn assert_allows(h: &Hook, what: &str) {
    assert_eq!(h.code, 0, "{what}: {h:?}");
    assert_eq!(h.j()["permission"], "allow", "{what}");
}

#[test]
fn shell_round_trip_links_one_decision_and_one_execution() {
    let p = Project::new();
    let input = json!({"command": "ls -la", "working_directory": "/work/proj"});
    assert_allows(
        &p.hook("cursor", &[], &pre("tu_1", "Shell", input.clone())),
        "ls",
    );
    let out = r#"{"exitCode":0,"stdout":"a\nb"}"#;
    let h = p.hook("cursor", &[], &post("tu_1", "Shell", input, out));
    assert_eq!(h.code, 0, "{h:?}");
    assert_eq!(h.j(), &json!({}));
    let recs = p.records();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0]["call_id"], "tu_1");
    assert_eq!(recs[0]["session_id"], "conv-1");
    assert_eq!(recs[0]["call"]["tool"], "bash");
    assert_eq!(recs[0]["call"]["caller"]["agent"], "cursor");
    assert_eq!(recs[1]["backend"], "cursor");
    assert_eq!(recs[1]["output_hash"], sha256_hex(out.as_bytes()));
    assert!(p.verify().contains("chain intact · 2 records"));
}

#[test]
fn deny_ask_and_unmaskable_redact_block_at_pre_tool_use() {
    let p = Project::new();
    let h = p.hook(
        "cursor",
        &[],
        &pre("a", "Shell", json!({"command": "rm -rf /"})),
    );
    assert_denies(&h, "rm");
    assert!(h.j()["agent_message"].as_str().unwrap().contains("no-rm"));
    assert_denies(
        &p.hook(
            "cursor",
            &[],
            &pre("b", "Read", json!({"file_path": "/p/.env"})),
        ),
        "read .env",
    );
    assert_allows(
        &p.hook(
            "cursor",
            &[],
            &pre("c", "Read", json!({"file_path": "/p/src/a.rs"})),
        ),
        "read src",
    );
    assert_denies(
        &p.hook(
            "cursor",
            &[],
            &pre("d", "Delete", json!({"file_path": "/p/.env"})),
        ),
        "delete .env",
    );
    assert_denies(
        &p.hook(
            "cursor",
            &[],
            &pre("e", "WebFetch", json!({"url": "https://evil.example/x"})),
        ),
        "egress",
    );
    // preToolUse cannot ask (accepted, not enforced): fail closed.
    let h = p.hook(
        "cursor",
        &["--ask", "defer"],
        &pre("f", "Shell", json!({"command": "deploy prod"})),
    );
    assert_denies(&h, "ask on preToolUse");
    // A redact rule on a non-MCP tool cannot be honoured in Cursor.
    let h = p.hook(
        "cursor",
        &[],
        &pre("g", "Shell", json!({"command": "cat secrets.txt"})),
    );
    assert_denies(&h, "redact on Shell");
    assert!(h.stderr.contains("only MCP"), "{}", h.stderr);
}

#[test]
fn mcp_is_decided_at_before_mcp_execution_with_its_server() {
    let p = Project::new();
    // The generic hook passes MCP calls through without a decision…
    let h = p.hook(
        "cursor",
        &[],
        &pre("m1", "MCP:delete_repo", json!({"repo": "x"})),
    );
    assert_allows(&h, "MCP passthrough");
    assert!(p.records().is_empty());
    // …beforeMCPExecution decides with the server identity.
    let h = p.hook(
        "cursor",
        &[],
        &mcp(Some("github"), "delete_repo", json!({"repo": "x"})),
    );
    assert_denies(&h, "delete_repo");
    let rec = &p.records()[0];
    assert_eq!(rec["call"]["server"]["name"], "github");
    assert_eq!(rec["call"]["server"]["transport"], "stdio");
    assert_eq!(
        rec["call"]["args"]["repo"], "x",
        "JSON-string params parsed"
    );
    // No server name: deny (Cursor's own guidance).
    assert_denies(
        &p.hook("cursor", &[], &mcp(None, "list", json!({}))),
        "no mcp_server_name",
    );
    // ask → Cursor's own prompt (exit 0), then the approved call completes.
    let args = json!({"title": "bug", "body": "b"});
    let h = p.hook(
        "cursor",
        &["--ask", "defer"],
        &mcp(Some("github"), "create_issue", args.clone()),
    );
    assert_eq!(h.code, 0, "{h:?}");
    assert_eq!(h.j()["permission"], "ask");
    let h = p.hook(
        "cursor",
        &["--ask", "defer"],
        &post(
            "tu_mcp",
            "MCP:create_issue",
            args.clone(),
            r#"{"content":[{"type":"text","text":"issue 7"}]}"#,
        ),
    );
    assert_eq!(h.code, 0, "{h:?}");
    let recs = p.records();
    let exec = executions(&recs);
    assert_eq!(exec.len(), 1);
    assert_eq!(
        exec[0]["approver"],
        json!({"kind": "tui", "id": "cursor-prompt"})
    );
    // Without --ask defer the ask fails closed.
    assert_denies(
        &p.hook("cursor", &[], &mcp(Some("github"), "create_issue", args)),
        "ask without defer",
    );
}

#[test]
fn mcp_output_is_redacted_through_updated_mcp_tool_output() {
    let p = Project::new();
    let args = json!({"sql": "select ssn"});
    assert_allows(
        &p.hook("cursor", &[], &mcp(Some("db"), "query", args.clone())),
        "query",
    );
    let out = r#"{"content":[{"type":"text","text":"ssn=123-45-6789"}],"isError":false}"#;
    let h = p.hook("cursor", &[], &post("tu_q", "MCP:query", args, out));
    assert_eq!(h.code, 0, "{h:?}");
    let upd = &h.j()["updated_mcp_tool_output"];
    assert_eq!(upd["content"][0]["text"], "ssn=[redacted-by-provio]");
    assert_eq!(upd["isError"], false, "shape preserved");
    assert_eq!(p.records()[1]["output_hash"], sha256_hex(out.as_bytes()));
    // An MCP result with no open decision is fully masked.
    let h = p.hook(
        "cursor",
        &[],
        &post("tu_x", "MCP:query", json!({"sql": "other"}), out),
    );
    assert_eq!(
        h.j()["updated_mcp_tool_output"]["content"][0]["text"],
        "[redacted-by-provio]"
    );
    assert!(h.stderr.contains("no open provio decision"), "{}", h.stderr);
}

#[test]
fn failure_event_records_the_error() {
    let p = Project::new();
    let input = json!({"command": "echo boom"});
    p.hook("cursor", &[], &pre("tu_f", "Shell", input.clone()));
    let mut fail = pre("tu_f", "Shell", input);
    fail["hook_event_name"] = json!("postToolUseFailure");
    fail["error_message"] = json!("Command timed out after 30s");
    fail["failure_type"] = json!("timeout");
    let h = p.hook("cursor", &[], &fail);
    assert_eq!(h.code, 0, "{h:?}");
    let recs = p.records();
    assert_eq!(recs[1]["exit_status"], 1);
    assert_eq!(
        recs[1]["output_hash"],
        sha256_hex(b"Command timed out after 30s")
    );
    // Completing twice is refused (and reported to the agent).
    let h = p.hook(
        "cursor",
        &[],
        &post("tu_f", "Shell", json!({"command": "echo boom"}), "x"),
    );
    assert!(h.j()["additional_context"]
        .as_str()
        .unwrap()
        .contains("already completed"));
    assert_eq!(p.records().len(), 2);
}

#[test]
fn every_error_class_blocks() {
    let good = pre("t", "Shell", json!({"command": "ls"})).to_string();
    let p = Project::new();
    for (bad, what) in [
        ("", "empty stdin"),
        ("{\"hook_event_name\":", "truncated JSON"),
        ("1", "non-object"),
        (
            r#"{"hook_event_name":"preToolUse","tool_name":"Shell","tool_use_id":"t"}"#,
            "no conversation_id",
        ),
        (
            r#"{"hook_event_name":"preToolUse","conversation_id":"c","tool_name":"Shell"}"#,
            "no tool_use_id",
        ),
        (
            r#"{"hook_event_name":"beforeReadFile","conversation_id":"c"}"#,
            "unsupported event",
        ),
    ] {
        assert_denies(
            &Hook::from(p.provio(&["check", "--format", "cursor"], bad)),
            what,
        );
    }
    assert_denies(
        &Hook::from(p.provio(&["check", "--format", "cursor", "--stdio"], &good)),
        "--stdio",
    );
    let bare = Project::bare();
    assert_denies(
        &Hook::from(bare.provio(&["check", "--format", "cursor"], &good)),
        "missing policy",
    );
    std::fs::write(bare.path().join("provio.yaml"), "rules: [[[").unwrap();
    assert_denies(
        &Hook::from(bare.provio(&["check", "--format", "cursor"], &good)),
        "bad policy",
    );
    let p = Project::new();
    std::fs::create_dir_all(p.path().join("dir.jsonl")).unwrap();
    assert_denies(
        &Hook::from(p.provio(
            &["--ledger", "dir.jsonl", "check", "--format", "cursor"],
            &good,
        )),
        "ledger dir",
    );
    let p = Project::new();
    p.hook("cursor", &[], &pre("a", "Shell", json!({"command": "ls"})));
    p.hook("cursor", &[], &pre("b", "Shell", json!({"command": "ls"})));
    corrupt_ledger(&p);
    assert_denies(
        &Hook::from(p.provio(&["check", "--format", "cursor"], &good)),
        "corrupt ledger",
    );
}

// ---------------------------------------------------------------------------
// provio integrate cursor

fn hooks_json(p: &Project) -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(p.path().join(".cursor").join("hooks.json")).unwrap(),
    )
    .unwrap()
}

#[test]
fn integrate_preserves_hooks_is_idempotent_and_the_hook_works() {
    let p = Project::new();
    std::fs::create_dir_all(p.path().join(".cursor")).unwrap();
    let existing = json!({"version": 1, "hooks": {
        "afterFileEdit": [{"command": ".cursor/hooks/format.sh"}],
        "preToolUse": [{"command": "./audit.sh", "matcher": "Shell"}]
    }});
    std::fs::write(
        p.path().join(".cursor").join("hooks.json"),
        serde_json::to_string_pretty(&existing).unwrap(),
    )
    .unwrap();
    let printed = p.provio(&["integrate", "cursor", "--print"], "");
    assert!(
        printed.status.success(),
        "{}",
        String::from_utf8_lossy(&printed.stderr)
    );
    assert_eq!(hooks_json(&p), existing, "--print does not write");
    let out = p.provio(&["integrate", "cursor"], "");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let once = hooks_json(&p);
    assert_eq!(
        once,
        serde_json::from_slice::<Value>(&printed.stdout).unwrap()
    );
    assert_eq!(once["version"], 1);
    assert_eq!(
        once["hooks"]["afterFileEdit"],
        existing["hooks"]["afterFileEdit"]
    );
    let pre_hooks = once["hooks"]["preToolUse"].as_array().unwrap();
    assert_eq!(pre_hooks.len(), 2);
    assert_eq!(pre_hooks[0]["command"], "./audit.sh");
    for ev in [
        "preToolUse",
        "beforeMCPExecution",
        "postToolUse",
        "postToolUseFailure",
    ] {
        let h = once["hooks"][ev]
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        assert_eq!(h["failClosed"], true, "{ev}");
    }
    assert!(p.provio(&["integrate", "cursor"], "").status.success());
    assert_eq!(hooks_json(&p), once, "idempotent");

    let cmd = pre_hooks[1]["command"].as_str().unwrap().to_string();
    for sh in portable_shells() {
        assert_allows(
            &run_in_shell(
                sh,
                &cmd,
                &pre(&format!("i{sh:?}"), "Shell", json!({"command": "ls"})),
                &p,
            ),
            "shell allow",
        );
        assert_denies(
            &run_in_shell(
                sh,
                &cmd,
                &pre(&format!("r{sh:?}"), "Shell", json!({"command": "rm -rf /"})),
                &p,
            ),
            "shell deny",
        );
    }
}

#[test]
fn integrate_refuses_broken_files() {
    let p = Project::new();
    std::fs::create_dir_all(p.path().join(".cursor")).unwrap();
    for bad in [
        "{ nope",
        r#"{"hooks": []}"#,
        r#"{"hooks": {"preToolUse": {}}}"#,
    ] {
        std::fs::write(p.path().join(".cursor").join("hooks.json"), bad).unwrap();
        assert!(
            !p.provio(&["integrate", "cursor"], "").status.success(),
            "{bad}"
        );
        assert_eq!(
            std::fs::read_to_string(p.path().join(".cursor").join("hooks.json")).unwrap(),
            bad
        );
    }
}

#[test]
fn claude_code_format_names_the_cursor_mixup() {
    // Cursor also runs .claude/settings.json hooks, with Cursor payloads.
    let p = Project::new();
    let h = p.hook(
        "claude-code",
        &[],
        &pre("t", "Shell", json!({"command": "ls"})),
    );
    assert_eq!(h.code, 2, "claude-code format still exits 2");
    assert!(h.stderr.contains("provio integrate cursor"), "{}", h.stderr);
}

// ---------------------------------------------------------------------------
// provio run -- cursor-agent

#[test]
fn run_passes_hooks_as_a_local_plugin() {
    if !boundary_available() {
        return;
    }
    let p = Project::new();
    p.fake_agent(
        "cursor-agent",
        "cat \"$2/.cursor-plugin/plugin.json\"\necho\ncat \"$2/hooks/hooks.json\"",
        "type \"%2\\.cursor-plugin\\plugin.json\"\r\necho.\r\ntype \"%2\\hooks\\hooks.json\"",
    );
    let o = p.run_agent(&[], &["cursor-agent", "-p", "hello"], &[]);
    let stdout = String::from_utf8_lossy(&o.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(3), "stdout {stdout} stderr {stderr}");
    let argv = stdout
        .lines()
        .find_map(|l| l.strip_prefix("ARGV:"))
        .unwrap();
    let parts: Vec<&str> = argv.split_whitespace().collect();
    assert_eq!(parts[0], "--plugin-dir", "{argv}");
    assert!(parts[1].ends_with("provio-cursor-plugin"), "{argv}");
    assert_eq!(&parts[2..], ["-p", "hello"]);
    assert!(
        !std::path::Path::new(parts[1]).exists(),
        "removed after the run"
    );
    assert!(stdout.contains("\"name\": \"provio-hooks\""), "{stdout}");
    assert!(stdout.contains("check --format cursor"), "{stdout}");
    assert!(stdout.contains("\"failClosed\": true"), "{stdout}");
    assert!(stderr.contains("profile    : cursor"), "{stderr}");
    assert!(stderr.contains("--plugin-dir"), "{stderr}");
    assert!(
        stderr.contains("no tool call reached provio's hooks"),
        "{stderr}"
    );
    assert!(p.home().join(".cursor").is_dir());
}
