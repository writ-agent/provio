//! `provio check --format codex`, `provio integrate codex`, `provio run -- codex`
//! driven exactly as OpenAI Codex CLI drives them (payload shapes from
//! codex-rs/hooks/schema/generated/*.command.input.schema.json and
//! https://learn.chatgpt.com/docs/hooks).

mod check_common;

use check_common::*;
use serde_json::{json, Value};

fn pre(session: &str, id: &str, tool: &str, input: Value) -> Value {
    json!({
        "session_id": session,
        "turn_id": "turn-1",
        "transcript_path": null,
        "cwd": "/work/proj",
        "hook_event_name": "PreToolUse",
        "model": "gpt-5-codex",
        "permission_mode": "default",
        "tool_name": tool,
        "tool_input": input,
        "tool_use_id": id,
    })
}

fn post(session: &str, id: &str, tool: &str, input: Value, response: Value) -> Value {
    let mut v = pre(session, id, tool, input);
    v["hook_event_name"] = json!("PostToolUse");
    v["tool_response"] = response;
    v
}

/// Codex blocks on `permissionDecision: "deny"` + a non-empty reason, and
/// provio always exits 0 so the JSON is honoured under every shell.
fn assert_denies(h: &Hook, what: &str) {
    assert_eq!(h.code, 0, "{what}: codex format always exits 0 ({h:?})");
    assert!(h.json.is_some(), "{what}: no JSON ({h:?})");
    let hso = &h.j()["hookSpecificOutput"];
    assert_eq!(hso["hookEventName"], "PreToolUse", "{what}");
    assert_eq!(hso["permissionDecision"], "deny", "{what}");
    assert!(
        !hso["permissionDecisionReason"]
            .as_str()
            .unwrap_or("")
            .trim()
            .is_empty(),
        "{what}: Codex needs a non-empty reason"
    );
    assert!(!h.stderr.trim().is_empty(), "{what}: reason on stderr");
}

fn assert_allows(h: &Hook, what: &str) {
    assert_eq!(h.code, 0, "{what}: {h:?}");
    // `permissionDecision: "allow"` without updatedInput is a failed hook
    // in Codex: allow means no output at all.
    assert!(h.json.is_none(), "{what}: allow prints nothing ({h:?})");
}

#[test]
fn allow_round_trip_links_one_decision_and_one_execution() {
    let p = Project::new();
    let input = json!({"command": "ls -la"});
    let h = p.hook("codex", &[], &pre("thr-1", "call_1", "Bash", input.clone()));
    assert_allows(&h, "ls");
    let resp = json!("a\nb\n");
    let h = p.hook(
        "codex",
        &[],
        &post("thr-1", "call_1", "Bash", input, resp.clone()),
    );
    assert_eq!(h.code, 0, "{h:?}");
    assert!(h.json.is_none(), "plain output is left alone: {h:?}");
    let recs = p.records();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0]["call_id"], "call_1");
    assert_eq!(recs[0]["session_id"], "thr-1");
    assert_eq!(recs[0]["call"]["tool"], "bash");
    assert_eq!(recs[0]["call"]["caller"]["agent"], "codex");
    assert_eq!(recs[1]["decision_index"], 0);
    assert_eq!(recs[1]["backend"], "codex");
    assert_eq!(recs[1]["exit_status"], 0);
    assert_eq!(
        recs[1]["output_hash"],
        sha256_hex(&serde_json::to_vec(&resp).unwrap())
    );
    assert!(p.verify().contains("chain intact · 2 records"));
}

#[test]
fn deny_and_ask_block_with_the_rule_and_reason() {
    let p = Project::new();
    let h = p.hook(
        "codex",
        &[],
        &pre("s", "c_rm", "Bash", json!({"command": "rm -rf /"})),
    );
    assert_denies(&h, "rm");
    let reason = h.j()["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        reason.contains("no-rm") && reason.contains("Destructive command."),
        "{reason}"
    );
    // Codex has no hook output that raises its approval prompt: an ask is
    // denied even with --ask defer.
    let h = p.hook(
        "codex",
        &["--ask", "defer"],
        &pre("s", "c_dep", "Bash", json!({"command": "deploy prod"})),
    );
    assert_denies(&h, "ask");
    assert!(h.stderr.contains("deploy"), "{}", h.stderr);
    let recs = p.records();
    assert_eq!(recs.len(), 2, "one decision per call, no execution");
    assert_eq!(recs[1]["rule_id"], "deploy");
    // A later PostToolUse for a denied call records nothing and hides the
    // output.
    let h = p.hook(
        "codex",
        &[],
        &post(
            "s",
            "c_rm",
            "Bash",
            json!({"command": "rm -rf /"}),
            json!("gone"),
        ),
    );
    assert_eq!(h.code, 0);
    assert_eq!(h.j()["decision"], "block");
    assert!(h.stderr.contains("did not allow"), "{}", h.stderr);
    assert_eq!(executions(&p.records()).len(), 0);
}

#[test]
fn apply_patch_is_decided_on_its_strictest_path() {
    let p = Project::new();
    let patch = "*** Begin Patch\n*** Update File: src/main.rs\n@@\n-a\n+b\n*** Add File: .env\n+KEY=1\n*** End Patch\n";
    let h = p.hook(
        "codex",
        &[],
        &pre("s", "c_patch", "apply_patch", json!({"command": patch})),
    );
    assert_denies(&h, "patch touching .env");
    let recs = p.records();
    let call = &recs[0]["call"];
    assert_eq!(call["tool"], "fs.write");
    assert!(call["args"]["path"].as_str().unwrap().ends_with(".env"));
    assert_eq!(call["args"]["paths"].as_array().unwrap().len(), 2);
    assert_eq!(call["args"]["command"], patch, "original input kept");

    let ok = "*** Begin Patch\n*** Update File: src/lib.rs\n@@\n-a\n+b\n*** End Patch\n";
    let h = p.hook(
        "codex",
        &[],
        &pre("s", "c_ok", "apply_patch", json!({"command": ok})),
    );
    assert_allows(&h, "src-only patch");
    assert!(p.records()[1]["call"]["args"]["path"]
        .as_str()
        .unwrap()
        .contains("src"));
}

#[test]
fn redact_replaces_the_result_the_model_sees() {
    let p = Project::new();
    let input = json!({"sql": "select ssn from people"});
    let h = p.hook(
        "codex",
        &[],
        &pre("s", "c_q", "mcp__db__query", input.clone()),
    );
    assert_allows(&h, "redact dispatches");
    assert_eq!(p.records()[0]["call"]["server"]["name"], "db");
    let resp = json!({"content": [{"type": "text", "text": "ssn=123-45-6789"}], "isError": false});
    let h = p.hook(
        "codex",
        &[],
        &post("s", "c_q", "mcp__db__query", input, resp.clone()),
    );
    assert_eq!(h.code, 0, "{h:?}");
    assert_eq!(h.j()["decision"], "block");
    let reason = h.j()["reason"].as_str().unwrap();
    assert!(reason.contains("ssn=[redacted-by-provio]"), "{reason}");
    assert!(!reason.contains("6789"), "{reason}");
    assert_eq!(
        p.records()[1]["output_hash"],
        sha256_hex(&serde_json::to_vec(&resp).unwrap()),
        "the original is hashed, never stored"
    );
    // Shell output too (Codex lets a PostToolUse hook replace any result).
    let cmd = json!({"command": "cat secrets.txt"});
    assert_allows(
        &p.hook("codex", &[], &pre("s", "c_cat", "Bash", cmd.clone())),
        "cat",
    );
    let h = p.hook(
        "codex",
        &[],
        &post("s", "c_cat", "Bash", cmd, json!("id 123-45-6789\n")),
    );
    assert_eq!(h.j()["reason"], "id [redacted-by-provio]\n");
}

#[test]
fn every_error_class_blocks() {
    let good = pre("s", "c1", "Bash", json!({"command": "ls"})).to_string();
    let p = Project::new();
    for (bad, what) in [
        ("", "empty stdin"),
        ("{\"hook_event_name\":", "truncated JSON"),
        ("[1]", "non-object"),
        (
            r#"{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Bash","tool_input":{}}"#,
            "no tool_use_id",
        ),
        (
            r#"{"hook_event_name":"PreToolUse","tool_use_id":"t","tool_name":"Bash"}"#,
            "no session_id",
        ),
        (
            r#"{"hook_event_name":"Stop","session_id":"s"}"#,
            "unsupported event",
        ),
    ] {
        assert_denies(
            &Hook::from(p.provio(&["check", "--format", "codex"], bad)),
            what,
        );
    }
    assert_denies(
        &Hook::from(p.provio(&["check", "--format", "codex", "--stdio"], &good)),
        "--stdio",
    );
    assert!(p.records().is_empty());

    let bare = Project::bare();
    assert_denies(
        &Hook::from(bare.provio(&["check", "--format", "codex"], &good)),
        "missing policy",
    );
    std::fs::write(bare.path().join("provio.yaml"), "version: 1\nrules: [[[").unwrap();
    assert_denies(
        &Hook::from(bare.provio(&["check", "--format", "codex"], &good)),
        "bad policy",
    );

    let p = Project::new();
    std::fs::create_dir_all(p.path().join("dir.jsonl")).unwrap();
    assert_denies(
        &Hook::from(p.provio(
            &["--ledger", "dir.jsonl", "check", "--format", "codex"],
            &good,
        )),
        "ledger is a directory",
    );
    let p = Project::new();
    p.hook(
        "codex",
        &[],
        &pre("s", "a", "Bash", json!({"command": "ls"})),
    );
    p.hook(
        "codex",
        &[],
        &pre("s", "b", "Bash", json!({"command": "ls"})),
    );
    // (A torn *last* line is recovered by the store; corrupt the first.)
    corrupt_ledger(&p);
    assert_denies(
        &Hook::from(p.provio(&["check", "--format", "codex"], &good)),
        "corrupt ledger",
    );
    // PostToolUse on an unreadable ledger: the output is withheld.
    let h = p.hook(
        "codex",
        &[],
        &post("s", "a", "Bash", json!({"command": "ls"}), json!("secret")),
    );
    assert_eq!((h.code, h.j()["decision"].as_str()), (0, Some("block")));
    assert!(!h.j()["reason"].as_str().unwrap().contains("secret"));
}

#[test]
fn post_without_a_decision_or_twice_is_withheld() {
    let p = Project::new();
    let input = json!({"command": "ls"});
    let h = p.hook(
        "codex",
        &[],
        &post("s", "ghost", "Bash", input.clone(), json!("x")),
    );
    assert_eq!(h.j()["decision"], "block");
    assert!(h.stderr.contains("no provio decision"), "{}", h.stderr);
    p.hook("codex", &[], &pre("s", "c", "Bash", input.clone()));
    assert!(p
        .hook(
            "codex",
            &[],
            &post("s", "c", "Bash", input.clone(), json!("x"))
        )
        .json
        .is_none());
    let h = p.hook("codex", &[], &post("s", "c", "Bash", input, json!("x")));
    assert_eq!(h.j()["decision"], "block");
    assert!(h.stderr.contains("already completed"), "{}", h.stderr);
    assert_eq!(p.records().len(), 2);
}

// ---------------------------------------------------------------------------
// provio integrate codex

fn codex_toml(p: &Project) -> String {
    std::fs::read_to_string(p.path().join(".codex").join("config.toml")).unwrap()
}

/// The `command` of provio's PreToolUse handler in `.codex/config.toml`.
fn provio_command(text: &str) -> String {
    let doc: toml_edit::DocumentMut = text.parse().unwrap();
    let groups = doc["hooks"]["PreToolUse"].as_array_of_tables().unwrap();
    let found = groups
        .iter()
        .flat_map(|g| g["hooks"].as_array_of_tables().unwrap().iter())
        .filter_map(|h| h["command"].as_str().map(str::to_string))
        .find(|c| c.contains("--format codex"));
    found.expect("provio's handler")
}

#[test]
fn integrate_preserves_comments_is_idempotent_and_the_hook_works() {
    let p = Project::new();
    std::fs::create_dir_all(p.path().join(".codex")).unwrap();
    let existing = "# team config\nmodel = \"gpt-5-codex\"  # keep\n\n[[hooks.PreToolUse]]\nmatcher = \"^Bash$\"\n\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"python3 lint.py\"\n";
    std::fs::write(p.path().join(".codex").join("config.toml"), existing).unwrap();

    let printed = p.provio(&["integrate", "codex", "--print"], "");
    assert!(
        printed.status.success(),
        "{}",
        String::from_utf8_lossy(&printed.stderr)
    );
    assert_eq!(codex_toml(&p), existing, "--print does not write");

    let out = p.provio(&["integrate", "codex"], "");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("/hooks"), "trust review is explained: {err}");
    let once = codex_toml(&p);
    assert_eq!(once, String::from_utf8_lossy(&printed.stdout));
    assert!(
        once.starts_with("# team config\nmodel = \"gpt-5-codex\"  # keep\n"),
        "{once}"
    );
    assert!(once.contains("python3 lint.py"));
    assert!(once.contains("[[hooks.PostToolUse]]"), "{once}");
    assert!(p.provio(&["integrate", "codex"], "").status.success());
    assert_eq!(codex_toml(&p), once, "second run changes nothing");

    // The hook command runs as Codex runs it: through the session's shell,
    // from an unrelated cwd.
    let cmd = provio_command(&once);
    let exe = env!("CARGO_BIN_EXE_provio").replace('\\', "/");
    assert!(
        cmd.replace('\'', "").starts_with(&exe) || cmd.starts_with(&exe),
        "{cmd}"
    );
    for (i, sh) in portable_shells().into_iter().enumerate() {
        let h = run_in_shell(
            sh,
            &cmd,
            &pre("s", &format!("ok{i}"), "Bash", json!({"command": "ls"})),
            &p,
        );
        assert_allows(&h, &format!("{sh:?} allow"));
        let h = run_in_shell(
            sh,
            &cmd,
            &pre(
                "s",
                &format!("rm{i}"),
                "Bash",
                json!({"command": "rm -rf /"}),
            ),
            &p,
        );
        assert_denies(&h, &format!("{sh:?} deny"));
    }
    assert!(p.verify().contains("chain intact"));
}

#[test]
fn integrate_refuses_invalid_config_or_missing_policy() {
    let p = Project::new();
    std::fs::create_dir_all(p.path().join(".codex")).unwrap();
    for bad in [
        "model = [unclosed",
        "hooks = 3\n",
        "[hooks]\nPreToolUse = \"x\"\n",
    ] {
        std::fs::write(p.path().join(".codex").join("config.toml"), bad).unwrap();
        let out = p.provio(&["integrate", "codex"], "");
        assert!(!out.status.success(), "{bad:?}");
        assert_eq!(codex_toml(&p), bad, "left untouched");
    }
    let bare = Project::bare();
    assert!(!bare.provio(&["integrate", "codex"], "").status.success());
    assert!(!bare.path().join(".codex").exists());
}

#[test]
fn integrate_warns_when_hooks_are_switched_off() {
    let p = Project::new();
    std::fs::create_dir_all(p.path().join(".codex")).unwrap();
    std::fs::write(
        p.path().join(".codex").join("config.toml"),
        "[features]\nhooks = false\n",
    )
    .unwrap();
    let out = p.provio(&["integrate", "codex"], "");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("hooks = false"));
}

// ---------------------------------------------------------------------------
// provio run -- codex

#[test]
fn run_injects_session_flag_hooks_and_bypasses_trust_review() {
    if !boundary_available() {
        return;
    }
    let p = Project::new();
    p.fake_agent("codex", "", "");
    let o = p.run_agent(&[], &["codex", "exec", "hello"], &[]);
    let stdout = String::from_utf8_lossy(&o.stdout);
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(3), "stdout {stdout} stderr {stderr}");
    let argv = stdout
        .lines()
        .find_map(|l| l.strip_prefix("ARGV:"))
        .unwrap_or_else(|| panic!("fake codex did not run: {stdout} {stderr}"));
    assert!(argv.starts_with("-c features.hooks=true -c "), "{argv}");
    assert!(argv.contains("hooks.PreToolUse="), "{argv}");
    assert!(argv.contains("hooks.PostToolUse="), "{argv}");
    assert!(argv.contains("check --format codex"), "{argv}");
    assert!(argv.contains("--dangerously-bypass-hook-trust"), "{argv}");
    assert!(
        argv.trim_end().ends_with("exec hello"),
        "user args last: {argv}"
    );
    assert!(stderr.contains("profile    : codex"), "{stderr}");
    assert!(stderr.contains("hooks      : on"), "{stderr}");
    assert!(stderr.contains("features.hooks pinned true"), "{stderr}");
    // The fake agent made no tool call: provio says the hooks never ran.
    assert!(
        stderr.contains("no tool call reached provio's hooks"),
        "{stderr}"
    );
    // State dir created in the fake home only.
    assert!(p.home().join(".codex").is_dir());
}

#[test]
fn run_refuses_conflicting_hook_overrides() {
    let p = Project::new();
    p.fake_agent("codex", "", "");
    for bad in [
        &["codex", "-c", "hooks.PreToolUse=[]"][..],
        &["codex", "--config", "features.hooks=false"][..],
        &["codex", "-cfeatures.hooks=false"][..],
    ] {
        let o = p.run_agent(&[], bad, &[]);
        assert_ne!(o.status.code(), Some(3), "{bad:?}");
        assert!(
            String::from_utf8_lossy(&o.stderr).contains("--no-hooks"),
            "{}",
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(!String::from_utf8_lossy(&o.stdout).contains("ARGV:"));
    }
    if !boundary_available() {
        return;
    }
    // Unrelated overrides pass through; --no-hooks adds nothing.
    let o = p.run_agent(&["--no-hooks"], &["codex", "-c", "hooks.x=1"], &[]);
    assert_eq!(o.status.code(), Some(3));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("ARGV:-c hooks.x=1"), "{out}");
    assert!(String::from_utf8_lossy(&o.stderr).contains("hooks      : off"));
    let o = p.run_agent(
        &[],
        &["codex", "-c", "model=o3", "--dangerously-bypass-hook-trust"],
        &[],
    );
    assert_eq!(
        o.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let out = String::from_utf8_lossy(&o.stdout);
    assert_eq!(
        out.matches("--dangerously-bypass-hook-trust").count(),
        1,
        "{out}"
    );
}
