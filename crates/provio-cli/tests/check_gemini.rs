//! `provio check --format gemini`, `provio integrate gemini`, `provio run -- gemini`
//! driven exactly as Gemini CLI drives them (payload shapes from
//! packages/core/src/hooks/hookEventHandler.ts and docs/hooks/reference.md).

mod check_common;

use check_common::*;
use serde_json::{json, Value};

fn before(session: &str, tool: &str, input: Value) -> Value {
    json!({
        "session_id": session,
        "transcript_path": "/home/u/.gemini/tmp/chat.json",
        "cwd": "/work/proj",
        "hook_event_name": "BeforeTool",
        "timestamp": "2026-09-22T10:00:00.000Z",
        "tool_name": tool,
        "tool_input": input,
    })
}

fn after(session: &str, tool: &str, input: Value, response: Value) -> Value {
    let mut v = before(session, tool, input);
    v["hook_event_name"] = json!("AfterTool");
    v["tool_response"] = response;
    v
}

fn mcp_ctx(server: &str, tool: &str) -> Value {
    json!({"server_name": server, "tool_name": tool, "command": "npx", "args": ["-y", "srv"]})
}

/// Gemini blocks on exit 2, and parses `decision: "deny"` from stdout
/// whatever the exit code.
fn assert_denies(h: &Hook, what: &str) {
    assert_eq!(h.code, 2, "{what}: must exit 2 ({h:?})");
    assert!(h.json.is_some(), "{what}: no JSON ({h:?})");
    assert_eq!(h.j()["decision"], "deny", "{what}");
    assert!(!h.j()["reason"].as_str().unwrap_or("").is_empty(), "{what}");
    assert!(!h.stderr.trim().is_empty(), "{what}: reason on stderr");
}

#[test]
fn allow_round_trip_links_one_decision_and_one_execution() {
    let p = Project::new();
    let input = json!({"command": "ls -la", "description": "list"});
    let h = p.hook(
        "gemini",
        &[],
        &before("g-1", "run_shell_command", input.clone()),
    );
    assert_eq!(h.code, 0, "{h:?}");
    assert_eq!(h.j()["decision"], "allow");
    let resp = json!({"llmContent": "a\nb", "returnDisplay": "a\nb"});
    let h = p.hook(
        "gemini",
        &[],
        &after("g-1", "run_shell_command", input, resp.clone()),
    );
    assert_eq!(h.code, 0, "{h:?}");
    assert_eq!(h.j(), &json!({}));
    let recs = p.records();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0]["session_id"], "g-1");
    assert_eq!(recs[0]["call"]["tool"], "bash");
    assert_eq!(recs[0]["call"]["caller"]["agent"], "gemini-cli");
    assert_eq!(recs[1]["decision_index"], 0);
    assert_eq!(recs[1]["call_id"], recs[0]["call_id"]);
    assert_eq!(recs[1]["backend"], "gemini-cli");
    assert_eq!(
        recs[1]["output_hash"],
        sha256_hex(&serde_json::to_vec(&resp).unwrap())
    );
    assert!(p.verify().contains("chain intact · 2 records"));
}

#[test]
fn deny_blocks_and_tool_mapping_reaches_the_policy() {
    let p = Project::new();
    let h = p.hook(
        "gemini",
        &[],
        &before("s", "run_shell_command", json!({"command": "rm -rf /"})),
    );
    assert_denies(&h, "rm");
    assert!(h.j()["reason"].as_str().unwrap().contains("no-rm"));
    assert_denies(
        &p.hook(
            "gemini",
            &[],
            &before("s", "read_file", json!({"file_path": "/p/.env"})),
        ),
        "read .env",
    );
    let h = p.hook(
        "gemini",
        &[],
        &before("s", "read_file", json!({"file_path": "/p/src/a.rs"})),
    );
    assert_eq!((h.code, h.j()["decision"].as_str()), (0, Some("allow")));
    assert_denies(
        &p.hook(
            "gemini",
            &[],
            &before(
                "s",
                "write_file",
                json!({"file_path": "/p/.env", "content": "x"}),
            ),
        ),
        "write .env",
    );
    // read_many_files: the strictest of its paths decides.
    let h = p.hook(
        "gemini",
        &[],
        &before(
            "s",
            "read_many_files",
            json!({"include": ["src/a.rs", "config/.env"]}),
        ),
    );
    assert_denies(&h, "read_many_files with .env");
    // web_fetch: URLs come from the prompt; one off-list host denies.
    let h = p.hook(
        "gemini",
        &[],
        &before(
            "s",
            "web_fetch",
            json!({"prompt": "compare https://api.github.com/x with https://evil.example/y"}),
        ),
    );
    assert_denies(&h, "web_fetch egress");
    assert!(h.j()["reason"].as_str().unwrap().contains("egress"));
    let rec = p.records().pop().unwrap();
    assert_eq!(rec["call"]["args"]["url"], "https://evil.example/y");
    assert_eq!(rec["call"]["args"]["urls"].as_array().unwrap().len(), 2);
    // MCP: server identity from mcp_context.
    assert_denies(
        &p.hook(
            "gemini",
            &[],
            &json!({
                "session_id": "s", "hook_event_name": "BeforeTool", "cwd": "/w",
                "tool_name": "mcp_github_delete_repo", "tool_input": {"repo": "x"},
                "mcp_context": mcp_ctx("github", "delete_repo")
            }),
        ),
        "mcp delete_repo",
    );
}

#[test]
fn ask_maps_to_gemini_confirmation_with_defer() {
    let p = Project::new();
    let input = json!({"command": "deploy prod"});
    let h = p.hook(
        "gemini",
        &["--ask", "defer"],
        &before("s", "run_shell_command", input.clone()),
    );
    assert_eq!(h.code, 0, "{h:?}");
    assert_eq!(h.j()["decision"], "ask");
    assert!(h.j()["systemMessage"].as_str().unwrap().contains("deploy"));
    // The user confirmed, the tool ran.
    let h = p.hook(
        "gemini",
        &["--ask", "defer"],
        &after("s", "run_shell_command", input, json!({"llmContent": "ok"})),
    );
    assert_eq!(h.code, 0, "{h:?}");
    let recs = p.records();
    assert_eq!(
        recs[1]["approver"],
        json!({"kind": "tui", "id": "gemini-cli-prompt"})
    );
    // Default --ask deny: fail closed.
    assert_denies(
        &p.hook(
            "gemini",
            &[],
            &before("s", "run_shell_command", json!({"command": "deploy x"})),
        ),
        "ask without defer",
    );
    // An AfterTool for a call provio refused is refused too (nothing recorded).
    let h = p.hook(
        "gemini",
        &[],
        &after(
            "s",
            "run_shell_command",
            json!({"command": "deploy x"}),
            json!({"llmContent": "x"}),
        ),
    );
    assert_eq!((h.code, h.j()["decision"].as_str()), (2, Some("deny")));
    assert_eq!(executions(&p.records()).len(), 1);
}

#[test]
fn redact_replaces_the_tool_result() {
    let p = Project::new();
    let input = json!({"sql": "select ssn"});
    let payload = |event: &str| {
        let mut v = json!({
            "session_id": "s", "hook_event_name": event, "cwd": "/w",
            "tool_name": "mcp_db_query", "tool_input": input,
            "mcp_context": mcp_ctx("db", "query"),
        });
        if event == "AfterTool" {
            v["tool_response"] =
                json!({"llmContent": [{"text": "ssn=123-45-6789"}], "returnDisplay": "x"});
        }
        v
    };
    let h = p.hook("gemini", &[], &payload("BeforeTool"));
    assert_eq!((h.code, h.j()["decision"].as_str()), (0, Some("allow")));
    let h = p.hook("gemini", &[], &payload("AfterTool"));
    assert_eq!(h.code, 0, "{h:?}");
    assert_eq!(h.j()["decision"], "deny", "deny replaces the result");
    let reason = h.j()["reason"].as_str().unwrap();
    assert!(reason.contains("ssn=[redacted-by-provio]"), "{reason}");
    assert!(!reason.contains("6789"));
    let recs = p.records();
    assert_eq!(recs[0]["call"]["server"]["name"], "db");
    assert_eq!(recs[0]["call"]["tool"], "query");
}

#[test]
fn identical_parallel_calls_each_complete_once() {
    let p = Project::new();
    let input = json!({"command": "echo same"});
    for _ in 0..2 {
        p.hook(
            "gemini",
            &[],
            &before("s", "run_shell_command", input.clone()),
        );
    }
    for _ in 0..2 {
        let h = p.hook(
            "gemini",
            &[],
            &after(
                "s",
                "run_shell_command",
                input.clone(),
                json!({"llmContent": "same"}),
            ),
        );
        assert_eq!(h.code, 0, "{h:?}");
    }
    let recs = p.records();
    let execs = executions(&recs);
    assert_eq!(execs.len(), 2);
    assert_ne!(execs[0]["decision_index"], execs[1]["decision_index"]);
    // A third AfterTool has no open decision: output withheld, exit 2.
    let h = p.hook(
        "gemini",
        &[],
        &after(
            "s",
            "run_shell_command",
            input,
            json!({"llmContent": "same"}),
        ),
    );
    assert_eq!((h.code, h.j()["decision"].as_str()), (2, Some("deny")));
    assert!(h.stderr.contains("no open provio decision"), "{}", h.stderr);
    // Another session does not see this session's decisions.
    assert_eq!(p.records().len(), 4);
}

#[test]
fn every_error_class_blocks() {
    let good = before("s", "run_shell_command", json!({"command": "ls"})).to_string();
    let p = Project::new();
    for (bad, what) in [
        ("", "empty stdin"),
        ("{\"hook_event_name\":", "truncated JSON"),
        ("\"x\"", "non-object"),
        (
            r#"{"hook_event_name":"BeforeTool","tool_name":"x"}"#,
            "no session_id",
        ),
        (
            r#"{"hook_event_name":"BeforeTool","session_id":"s"}"#,
            "no tool_name",
        ),
        (
            r#"{"hook_event_name":"BeforeModel","session_id":"s"}"#,
            "unsupported event",
        ),
    ] {
        assert_denies(
            &Hook::from(p.provio(&["check", "--format", "gemini"], bad)),
            what,
        );
    }
    assert_denies(
        &Hook::from(p.provio(&["check", "--format", "gemini", "--stdio"], &good)),
        "--stdio",
    );
    let bare = Project::bare();
    assert_denies(
        &Hook::from(bare.provio(&["check", "--format", "gemini"], &good)),
        "missing policy",
    );
    std::fs::write(bare.path().join("provio.yaml"), "rules: [[[").unwrap();
    assert_denies(
        &Hook::from(bare.provio(&["check", "--format", "gemini"], &good)),
        "bad policy",
    );
    let p = Project::new();
    std::fs::create_dir_all(p.path().join("dir.jsonl")).unwrap();
    assert_denies(
        &Hook::from(p.provio(
            &["--ledger", "dir.jsonl", "check", "--format", "gemini"],
            &good,
        )),
        "ledger dir",
    );
    let p = Project::new();
    p.hook(
        "gemini",
        &[],
        &before("s", "run_shell_command", json!({"command": "ls"})),
    );
    p.hook(
        "gemini",
        &[],
        &before("s", "run_shell_command", json!({"command": "ls"})),
    );
    corrupt_ledger(&p);
    assert_denies(
        &Hook::from(p.provio(&["check", "--format", "gemini"], &good)),
        "corrupt ledger",
    );
    let h = p.hook(
        "gemini",
        &[],
        &after(
            "s",
            "run_shell_command",
            json!({"command": "ls"}),
            json!({"llmContent": "secret"}),
        ),
    );
    assert_eq!((h.code, h.j()["decision"].as_str()), (2, Some("deny")));
    assert!(!h.j()["reason"].as_str().unwrap().contains("secret"));
}

// ---------------------------------------------------------------------------
// provio integrate gemini

fn settings(p: &Project) -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(p.path().join(".gemini").join("settings.json")).unwrap(),
    )
    .unwrap()
}

#[test]
fn integrate_preserves_settings_is_idempotent_and_the_hook_works() {
    let p = Project::new();
    std::fs::create_dir_all(p.path().join(".gemini")).unwrap();
    let existing = json!({
        "general": {"vimMode": true},
        "hooks": {"BeforeTool": [{"matcher": "write_file", "hooks": [{"type": "command", "command": "sec.sh"}]}]}
    });
    std::fs::write(
        p.path().join(".gemini").join("settings.json"),
        serde_json::to_string_pretty(&existing).unwrap(),
    )
    .unwrap();
    let printed = p.provio(&["integrate", "gemini", "--print"], "");
    assert!(
        printed.status.success(),
        "{}",
        String::from_utf8_lossy(&printed.stderr)
    );
    assert_eq!(settings(&p), existing, "--print does not write");
    let out = p.provio(&["integrate", "gemini"], "");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let once = settings(&p);
    assert_eq!(
        once,
        serde_json::from_slice::<Value>(&printed.stdout).unwrap()
    );
    assert_eq!(once["general"], existing["general"]);
    let bt = once["hooks"]["BeforeTool"].as_array().unwrap();
    assert_eq!(bt.len(), 2);
    assert_eq!(bt[0]["hooks"][0]["command"], "sec.sh");
    assert!(once["hooks"]["AfterTool"].is_array());
    assert!(p.provio(&["integrate", "gemini"], "").status.success());
    assert_eq!(settings(&p), once, "idempotent");

    let cmd = bt[1]["hooks"][0]["command"].as_str().unwrap().to_string();
    let shell = if cfg!(windows) {
        Shell::GeminiPowerShell
    } else {
        Shell::Bash
    };
    let h = run_in_shell(
        shell,
        &cmd,
        &before("sh", "run_shell_command", json!({"command": "ls"})),
        &p,
    );
    assert_eq!(
        (h.code, h.j()["decision"].as_str()),
        (0, Some("allow")),
        "{h:?}"
    );
    let h = run_in_shell(
        shell,
        &cmd,
        &before("sh", "run_shell_command", json!({"command": "rm -rf /"})),
        &p,
    );
    assert_denies(&h, "via the shell Gemini uses");
    let h = run_in_shell(
        shell,
        &cmd,
        &before("sh", "run_shell_command", json!({"command": "deploy"})),
        &p,
    );
    assert_eq!(
        h.j()["decision"],
        "ask",
        "integrate passes --ask defer: {h:?}"
    );
}

#[test]
fn integrate_refuses_broken_settings_and_warns_when_disabled() {
    let p = Project::new();
    std::fs::create_dir_all(p.path().join(".gemini")).unwrap();
    std::fs::write(p.path().join(".gemini").join("settings.json"), "{ nope").unwrap();
    assert!(!p.provio(&["integrate", "gemini"], "").status.success());
    assert_eq!(
        std::fs::read_to_string(p.path().join(".gemini").join("settings.json")).unwrap(),
        "{ nope"
    );
    std::fs::write(
        p.path().join(".gemini").join("settings.json"),
        r#"{"hooksConfig": {"enabled": false}}"#,
    )
    .unwrap();
    let out = p.provio(&["integrate", "gemini"], "");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("hooksConfig.enabled = false"));
    let bare = Project::bare();
    assert!(!bare.provio(&["integrate", "gemini"], "").status.success());
    assert!(!bare.path().join(".gemini").exists());
}

// ---------------------------------------------------------------------------
// provio run -- gemini

#[test]
fn run_points_gemini_at_provio_system_settings() {
    if !boundary_available() {
        return;
    }
    let p = Project::new();
    // An existing (enterprise) system settings file must survive.
    let sys = p.path().join("sys-settings.json");
    std::fs::write(
        &sys,
        r#"{"general": {"org": "acme"}, "hooksConfig": {"enabled": false}}"#,
    )
    .unwrap();
    p.fake_agent(
        "gemini",
        "echo \"SYS:$GEMINI_CLI_SYSTEM_SETTINGS_PATH\"\necho \"DEF:$GEMINI_CLI_SYSTEM_DEFAULTS_PATH\"\necho \"TRUST:$GEMINI_CLI_TRUST_WORKSPACE\"\ncat \"$GEMINI_CLI_SYSTEM_SETTINGS_PATH\"",
        "echo SYS:%GEMINI_CLI_SYSTEM_SETTINGS_PATH%\r\necho DEF:%GEMINI_CLI_SYSTEM_DEFAULTS_PATH%\r\necho TRUST:%GEMINI_CLI_TRUST_WORKSPACE%\r\ntype \"%GEMINI_CLI_SYSTEM_SETTINGS_PATH%\"",
    );
    let sys_s = sys.display().to_string();
    let o = p.run_agent(
        &[],
        &["gemini", "-p", "hi"],
        &[("GEMINI_CLI_SYSTEM_SETTINGS_PATH", &sys_s)],
    );
    let stdout = String::from_utf8_lossy(&o.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(o.status.code(), Some(3), "stdout {stdout} stderr {stderr}");
    assert!(stdout.contains("ARGV:-p hi"), "argv untouched: {stdout}");
    let line = |tag: &str| {
        stdout
            .lines()
            .find_map(|l| l.strip_prefix(tag))
            .unwrap_or_else(|| panic!("{tag} missing: {stdout}"))
            .trim()
            .to_string()
    };
    let file = line("SYS:");
    assert!(file.ends_with("gemini-system-settings.json"), "{file}");
    assert!(
        !std::path::Path::new(&file).exists(),
        "removed after the run"
    );
    assert_eq!(
        std::path::PathBuf::from(line("DEF:")),
        p.path().join("system-defaults.json"),
        "defaults path unchanged"
    );
    assert_eq!(line("TRUST:"), "true");
    let json_start = stdout.find('{').expect("settings printed");
    let settings: Value = serde_json::from_str(stdout[json_start..].trim()).unwrap();
    assert_eq!(settings["general"]["org"], "acme", "system settings kept");
    assert_eq!(settings["hooksConfig"]["enabled"], true, "pinned on");
    let hook = &settings["hooks"]["BeforeTool"][0]["hooks"][0];
    assert!(hook["command"]
        .as_str()
        .unwrap()
        .contains("check --format gemini"));
    assert!(hook["name"].as_str().unwrap().starts_with("provio-"));
    assert!(settings["hooks"]["AfterTool"].is_array());
    assert!(stderr.contains("profile    : gemini"), "{stderr}");
    assert!(
        stderr.contains("hooksConfig.enabled pinned true"),
        "{stderr}"
    );
    assert!(p.home().join(".gemini").is_dir());
}

#[test]
fn run_refuses_when_gemini_would_run_no_hooks() {
    let p = Project::new();
    p.fake_agent("gemini", "", "");
    for (k, v) in [
        ("GEMINI_RESTRICTED_MODE", "true"),
        ("GEMINI_CLI_TRUST_WORKSPACE", "false"),
    ] {
        let o = p.run_agent(&[], &["gemini"], &[(k, v)]);
        assert_ne!(o.status.code(), Some(3), "{k}");
        assert!(
            String::from_utf8_lossy(&o.stderr).contains("--no-hooks"),
            "{}",
            String::from_utf8_lossy(&o.stderr)
        );
    }
}
