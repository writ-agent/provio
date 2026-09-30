//! `provio check --format windsurf` and `provio integrate windsurf`, driven
//! exactly as Windsurf's Cascade hooks drive them (payload shapes from
//! https://docs.windsurf.com/windsurf/cascade/hooks). Cascade is an IDE:
//! there is no per-invocation `provio run` injection.

mod check_common;

use check_common::*;
use serde_json::{json, Value};

fn ev(action: &str, info: Value) -> Value {
    json!({
        "agent_action_name": action,
        "trajectory_id": "traj-1",
        "execution_id": "exec-1",
        "timestamp": "2026-09-22T10:00:00Z",
        "model_name": "Claude Sonnet 4",
        "tool_info": info,
    })
}

fn cmd(action: &str, line: &str) -> Value {
    ev(action, json!({"command_line": line, "cwd": "/work/proj"}))
}

/// Cascade blocks a pre-hook only on exit code 2 (stderr is the reason).
fn assert_blocks(h: &Hook, what: &str) {
    assert_eq!(h.code, 2, "{what}: must exit 2 ({h:?})");
    assert!(!h.stderr.trim().is_empty(), "{what}: reason on stderr");
    assert!(h.json.is_none(), "{what}: nothing on stdout");
}

#[test]
fn command_round_trip_links_one_decision_and_one_execution() {
    let p = Project::new();
    let h = p.hook("windsurf", &[], &cmd("pre_run_command", "ls -la"));
    assert_eq!((h.code, h.json.is_none()), (0, true), "{h:?}");
    let h = p.hook("windsurf", &[], &cmd("post_run_command", "ls -la"));
    assert_eq!(h.code, 0, "{h:?}");
    let recs = p.records();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0]["session_id"], "traj-1");
    assert_eq!(recs[0]["call"]["tool"], "bash");
    assert_eq!(recs[0]["call"]["args"]["command"], "ls -la");
    assert_eq!(recs[0]["call"]["caller"]["agent"], "windsurf");
    assert_eq!(recs[1]["decision_index"], 0);
    assert_eq!(recs[1]["backend"], "windsurf");
    assert!(p.verify().contains("chain intact · 2 records"));
}

#[test]
fn deny_ask_and_redact_block() {
    let p = Project::new();
    let h = p.hook("windsurf", &[], &cmd("pre_run_command", "rm -rf /"));
    assert_blocks(&h, "rm");
    assert!(h.stderr.contains("no-rm"), "{}", h.stderr);
    assert_blocks(
        &p.hook(
            "windsurf",
            &[],
            &ev("pre_read_code", json!({"file_path": "/p/.env"})),
        ),
        "read .env",
    );
    let h = p.hook(
        "windsurf",
        &[],
        &ev("pre_read_code", json!({"file_path": "/p/src"})),
    );
    assert_eq!(h.code, 0, "{h:?}");
    assert_blocks(
        &p.hook(
            "windsurf",
            &[],
            &ev(
                "pre_write_code",
                json!({"file_path": "/p/.env", "edits": [{"old_string": "", "new_string": "K=1"}]}),
            ),
        ),
        "write .env",
    );
    // No prompt to defer to, no output to mask: fail closed.
    assert_blocks(
        &p.hook(
            "windsurf",
            &["--ask", "defer"],
            &cmd("pre_run_command", "deploy prod"),
        ),
        "ask",
    );
    let q = ev(
        "pre_mcp_tool_use",
        json!({"mcp_server_name": "db", "mcp_tool_name": "query", "mcp_tool_arguments": {"sql": "x"}}),
    );
    let h = p.hook("windsurf", &[], &q);
    assert_blocks(&h, "redact");
    assert!(h.stderr.contains("cannot replace"), "{}", h.stderr);
    assert_blocks(
        &p.hook(
            "windsurf",
            &[],
            &ev("pre_mcp_tool_use", json!({"mcp_server_name": "github", "mcp_tool_name": "delete_repo", "mcp_tool_arguments": {}})),
        ),
        "mcp deny",
    );
}

#[test]
fn mcp_round_trip_hashes_the_result() {
    let p = Project::new();
    let info = json!({"mcp_server_name": "github", "mcp_tool_name": "list_commits", "mcp_tool_arguments": {"repo": "r"}});
    let h = p.hook("windsurf", &[], &ev("pre_mcp_tool_use", info.clone()));
    assert_eq!(h.code, 0, "{h:?}");
    let mut done = info;
    done["mcp_result"] = json!("3 commits");
    assert_eq!(
        p.hook("windsurf", &[], &ev("post_mcp_tool_use", done)).code,
        0
    );
    let recs = p.records();
    assert_eq!(recs[0]["call"]["server"]["name"], "github");
    assert_eq!(recs[1]["output_hash"], sha256_hex(b"3 commits"));
}

#[test]
fn every_error_class_blocks_and_post_errors_are_loud() {
    let good = cmd("pre_run_command", "ls").to_string();
    let p = Project::new();
    for (bad, what) in [
        ("", "empty stdin"),
        ("{\"agent_action_name\":", "truncated JSON"),
        ("null", "non-object"),
        (
            r#"{"agent_action_name":"pre_run_command","tool_info":{"command_line":"ls"}}"#,
            "no trajectory_id",
        ),
        (
            r#"{"agent_action_name":"pre_run_command","trajectory_id":"t"}"#,
            "no tool_info",
        ),
        (
            r#"{"agent_action_name":"pre_run_command","trajectory_id":"t","tool_info":{}}"#,
            "no command_line",
        ),
        (
            r#"{"agent_action_name":"pre_user_prompt","trajectory_id":"t","tool_info":{}}"#,
            "unsupported event",
        ),
    ] {
        assert_blocks(
            &Hook::from(p.provio(&["check", "--format", "windsurf"], bad)),
            what,
        );
    }
    assert_blocks(
        &Hook::from(p.provio(&["check", "--format", "windsurf", "--stdio"], &good)),
        "--stdio",
    );
    let bare = Project::bare();
    assert_blocks(
        &Hook::from(bare.provio(&["check", "--format", "windsurf"], &good)),
        "missing policy",
    );
    std::fs::write(bare.path().join("provio.yaml"), "rules: [[[").unwrap();
    assert_blocks(
        &Hook::from(bare.provio(&["check", "--format", "windsurf"], &good)),
        "bad policy",
    );
    let p = Project::new();
    std::fs::create_dir_all(p.path().join("dir.jsonl")).unwrap();
    assert_blocks(
        &Hook::from(p.provio(
            &["--ledger", "dir.jsonl", "check", "--format", "windsurf"],
            &good,
        )),
        "ledger dir",
    );
    let p = Project::new();
    p.hook("windsurf", &[], &cmd("pre_run_command", "ls"));
    p.hook("windsurf", &[], &cmd("pre_run_command", "ls"));
    corrupt_ledger(&p);
    assert_blocks(
        &Hook::from(p.provio(&["check", "--format", "windsurf"], &good)),
        "corrupt ledger",
    );
    // A post event with no open decision: exit 2 (Cascade shows stderr).
    let p = Project::new();
    let h = p.hook("windsurf", &[], &cmd("post_run_command", "ls"));
    assert_eq!(h.code, 2);
    assert!(h.stderr.contains("no open provio decision"), "{}", h.stderr);
}

// ---------------------------------------------------------------------------
// provio integrate windsurf

#[test]
fn integrate_writes_devin_hooks_merges_legacy_and_the_hook_works() {
    let p = Project::new();
    let out = p.provio(&["integrate", "windsurf"], "");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let path = p.path().join(".devin").join("hooks.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    for ev in [
        "pre_run_command",
        "pre_read_code",
        "pre_write_code",
        "pre_mcp_tool_use",
        "post_run_command",
        "post_mcp_tool_use",
    ] {
        assert!(
            v["hooks"][ev][0]["command"]
                .as_str()
                .unwrap()
                .contains("--format windsurf"),
            "{ev}"
        );
        assert!(
            v["hooks"][ev][0]["powershell"]
                .as_str()
                .unwrap()
                .ends_with("exit $LASTEXITCODE"),
            "{ev}"
        );
    }
    let once = std::fs::read_to_string(&path).unwrap();
    assert!(p.provio(&["integrate", "windsurf"], "").status.success());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), once, "idempotent");

    // The hook runs through the shell Cascade uses and blocks via exit 2.
    let h0 = &v["hooks"]["pre_run_command"][0];
    let (shell, line) = if cfg!(windows) {
        (Shell::PowerShell, h0["powershell"].as_str().unwrap())
    } else {
        (Shell::Bash, h0["command"].as_str().unwrap())
    };
    let h = run_in_shell(shell, line, &cmd("pre_run_command", "ls"), &p);
    assert_eq!(h.code, 0, "{h:?}");
    let h = run_in_shell(shell, line, &cmd("pre_run_command", "rm -rf /"), &p);
    assert_eq!(h.code, 2, "exit 2 survives the shell: {h:?}");

    // An existing legacy .windsurf/hooks.json (and no .devin) is merged
    // into, not shadowed.
    let q = Project::new();
    std::fs::create_dir_all(q.path().join(".windsurf")).unwrap();
    let legacy =
        json!({"hooks": {"post_write_code": [{"command": "fmt.sh", "show_output": true}]}});
    std::fs::write(
        q.path().join(".windsurf").join("hooks.json"),
        legacy.to_string(),
    )
    .unwrap();
    assert!(q.provio(&["integrate", "windsurf"], "").status.success());
    assert!(!q.path().join(".devin").exists());
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string(q.path().join(".windsurf").join("hooks.json")).unwrap(),
    )
    .unwrap();
    let pw = v["hooks"]["post_write_code"].as_array().unwrap();
    assert_eq!(pw.len(), 2);
    assert_eq!(pw[0]["command"], "fmt.sh");
}

#[test]
fn integrate_refuses_broken_files_and_run_points_at_integrate() {
    let p = Project::new();
    std::fs::create_dir_all(p.path().join(".devin")).unwrap();
    std::fs::write(p.path().join(".devin").join("hooks.json"), "[1]").unwrap();
    assert!(!p.provio(&["integrate", "windsurf"], "").status.success());
    assert_eq!(
        std::fs::read_to_string(p.path().join(".devin").join("hooks.json")).unwrap(),
        "[1]"
    );
    if !boundary_available() {
        return;
    }
    p.fake_agent("windsurf", "", "");
    let o = p.run_agent(&[], &["windsurf"], &[]);
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(stderr.contains("provio integrate windsurf"), "{stderr}");
    assert!(stderr.contains("hooks      : none"), "{stderr}");
}
