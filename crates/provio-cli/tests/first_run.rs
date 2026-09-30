//! `provio scan`, `provio init`, `provio test` through the real binary.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Value};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn empty_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "provio-first-run-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn provio(dir: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_provio"))
        .args(args)
        .current_dir(dir)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME")
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

// Far-future timestamps are inside any --days window; the 2000 one is not.
const NOW: &str = "2099-01-01T00:00:00.000Z";
const OLD: &str = "2000-01-01T00:00:00.000Z";

fn claude_line(id: &str, when: &str, name: &str, input: Value) -> String {
    json!({
        "type": "assistant", "timestamp": when, "sessionId": "s1", "cwd": "/nowhere",
        "message": { "role": "assistant", "content": [
            { "type": "text", "text": "ok" },
            { "type": "tool_use", "id": id, "name": name, "input": input }
        ]}
    })
    .to_string()
}

fn write_transcripts(home: &Path) {
    let cc = home.join(".claude/projects/-repo");
    std::fs::create_dir_all(&cc).unwrap();
    let lines = [
        claude_line("t1", NOW, "Bash", json!({"command": "rm -rf \"$HOME\""})),
        claude_line("t2", NOW, "Bash", json!({"command": "cargo test"})),
        claude_line(
            "t3",
            NOW,
            "Read",
            json!({"file_path": "/home/u/.ssh/id_ed25519"}),
        ),
        claude_line("t4", NOW, "Bash", json!({"command": "terraform destroy"})),
        claude_line(
            "t5",
            OLD,
            "Bash",
            json!({"command": "git push --force origin main"}),
        ),
        // A resumed session repeats t1: counted once.
        claude_line("t1", NOW, "Bash", json!({"command": "rm -rf \"$HOME\""})),
        "not json".to_string(),
    ];
    std::fs::write(cc.join("s1.jsonl"), lines.join("\n") + "\n").unwrap();

    let cx = home.join(".codex/sessions/2099/01/01");
    std::fs::create_dir_all(&cx).unwrap();
    let codex = [
        json!({"timestamp": NOW, "type": "session_meta", "payload": {"id": "c1", "cwd": "/nowhere"}}),
        json!({"timestamp": NOW, "type": "response_item", "payload": {"type": "function_call", "name": "shell_command",
            "arguments": json!({"command": "git push -f origin master", "workdir": "/nowhere"}).to_string(), "call_id": "k1"}}),
        json!({"timestamp": NOW, "type": "response_item", "payload": {"type": "local_shell_call", "call_id": "k2",
            "action": {"type": "exec", "command": ["bash", "-lc", "ls -la"]}}}),
        json!({"timestamp": NOW, "type": "response_item", "payload": {"type": "custom_tool_call", "call_id": "k3", "name": "apply_patch",
            "input": "*** Begin Patch\n*** Add File: reset.sh\n+#!/bin/sh\n+git reset --hard origin/main\n*** End Patch\n"}}),
    ];
    std::fs::write(
        cx.join("rollout-2099-01-01T00-00-00-c1.jsonl"),
        codex
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n",
    )
    .unwrap();

    let gm = home.join(".gemini/tmp/abc123/chats");
    std::fs::create_dir_all(&gm).unwrap();
    std::fs::write(
        gm.join("session-1.json"),
        json!({"sessionId": "g1", "messages": [
            {"type": "user", "content": "hi"},
            {"type": "gemini", "toolCalls": [
                {"id": "g-1", "name": "run_shell_command", "args": {"command": "mkfs.ext4 /dev/sdb1"}, "timestamp": NOW},
                {"id": "g-2", "name": "read_file", "args": {"absolute_path": "/repo/README.md"}, "timestamp": NOW}
            ]}
        ]})
        .to_string(),
    )
    .unwrap();
}

#[test]
fn scan_reads_every_agent_and_judges_with_the_starter_packs() {
    let home = empty_dir("home");
    let work = empty_dir("work");
    write_transcripts(&home);
    let out = provio(&work, &home, &["scan", "--format", "json", "--days", "30"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    let calls = |agent: &str| {
        v["sources"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["agent"] == agent)
            .map(|s| s["tool_calls"].as_u64().unwrap())
            .unwrap()
    };
    // t1 once, t2, t3, t4 (t5 is too old); 3 Codex calls; 2 Gemini calls.
    assert_eq!(calls("claude-code"), 4, "{v:#}");
    assert_eq!(calls("codex"), 3, "{v:#}");
    assert_eq!(calls("gemini-cli"), 2, "{v:#}");
    let rules: Vec<(&str, &str)> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["agent"].as_str().unwrap(), f["rule_id"].as_str().unwrap()))
        .collect();
    for want in [
        ("claude-code", "floor-rm-home-or-root-denied"),
        ("claude-code", "floor-private-keys-denied"),
        ("claude-code", "floor-cloud-destroy-asks"),
        ("codex", "floor-force-push-main-denied"),
        ("codex", "floor-discard-uncommitted-work-asks"),
        ("gemini-cli", "floor-disk-and-system-wipe-denied"),
    ] {
        assert!(rules.contains(&want), "missing {want:?} in {rules:?}");
    }
    // The old force push (outside the window) is not reported for Claude Code.
    assert!(
        !rules.contains(&("claude-code", "floor-force-push-main-denied")),
        "{rules:?}"
    );
    assert!(v["policy"].as_str().unwrap().contains("floor"), "{v:#}");

    // The shareable summary has counts and rule ids, never commands.
    let md = provio(&work, &home, &["scan", "--format", "markdown"]);
    let md = String::from_utf8_lossy(&md.stdout);
    assert!(md.contains("floor-rm-home-or-root-denied"), "{md}");
    assert!(!md.contains("$HOME") && !md.contains("mkfs"), "{md}");

    // Text scorecard runs and names the headline counts.
    let text = provio(&work, &home, &["scan"]);
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("would have been BLOCKED"), "{text}");
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn test_exit_codes_follow_the_verdict() {
    let home = empty_dir("home");
    let work = empty_dir("work");
    let code = |args: &[&str]| provio(&work, &home, args).status.code().unwrap();
    assert_eq!(code(&["test", "rm -rf ~"]), 2);
    assert_eq!(code(&["test", "terraform destroy"]), 3);
    assert_eq!(code(&["test", "cargo", "build"]), 0);
    assert_eq!(
        code(&["test", "--tool", "fs.read", "--path", "/h/.aws/credentials"]),
        2
    );
    assert_eq!(code(&["test"]), 1);
    // The script behind the command decides.
    std::fs::write(
        work.join("cleanup.sh"),
        "#!/bin/sh\ntrap 'rm -rf \"$HOME\"' EXIT\n",
    )
    .unwrap();
    let out = provio(&work, &home, &["test", "--json", "bash cleanup.sh"]);
    assert_eq!(out.status.code(), Some(2));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["verdict"]["rule_id"], "floor-rm-home-or-root-denied");
    assert!(
        v["verdict"]["reason"]
            .as_str()
            .unwrap()
            .contains("cleanup.sh line 2"),
        "{v:#}"
    );
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn init_writes_a_policy_wires_agents_and_is_idempotent() {
    let home = empty_dir("home");
    let work = empty_dir("work");
    std::fs::create_dir_all(work.join(".git")).unwrap();
    let out = provio(&work, &home, &["init", "--agent", "claude-code,gemini"]);
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let policy = std::fs::read_to_string(work.join("provio.yaml")).unwrap();
    assert!(policy.contains("packs: [floor, secrets-guard]"), "{policy}");
    let cc = std::fs::read_to_string(work.join(".claude/settings.json")).unwrap();
    assert!(
        cc.contains("--format") && cc.contains("claude-code"),
        "{cc}"
    );
    assert!(work.join(".gemini/settings.json").is_file());
    let gi = std::fs::read_to_string(work.join(".gitignore")).unwrap();
    assert_eq!(gi.matches(".provio/").count(), 1, "{gi}");

    // Again: the edited policy is kept, hooks are not duplicated, .gitignore unchanged.
    std::fs::write(
        work.join("provio.yaml"),
        policy.replace("default: allow", "default: ask"),
    )
    .unwrap();
    let out = provio(&work, &home, &["init", "--agent", "claude-code"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(std::fs::read_to_string(work.join("provio.yaml"))
        .unwrap()
        .contains("default: ask"));
    let cc2 = std::fs::read_to_string(work.join(".claude/settings.json")).unwrap();
    assert_eq!(
        cc2.matches("PreToolUse").count(),
        cc.matches("PreToolUse").count()
    );
    let gi2 = std::fs::read_to_string(work.join(".gitignore")).unwrap();
    assert_eq!(gi, gi2);

    // A broken policy is refused, not overwritten.
    std::fs::write(work.join("provio.yaml"), "version: 1\ndefault: maybe\n").unwrap();
    let out = provio(&work, &home, &["init", "--agent", "claude-code"]);
    assert!(!out.status.success());
    assert_eq!(
        std::fs::read_to_string(work.join("provio.yaml")).unwrap(),
        "version: 1\ndefault: maybe\n"
    );
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn init_global_uses_the_home_directory() {
    let home = empty_dir("home");
    let work = empty_dir("work");
    let out = provio(
        &work,
        &home,
        &["init", "--global", "--agent", "claude-code"],
    );
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(home.join(".provio/provio.yaml").is_file());
    let cc = std::fs::read_to_string(home.join(".claude/settings.json")).unwrap();
    assert!(cc.contains(".provio"), "{cc}");
    assert!(!work.join(".claude").exists());
    assert!(!work.join("provio.yaml").exists());
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn report_summarizes_the_ledger_and_embeds_a_verifiable_receipt() {
    let home = empty_dir("home");
    let work = empty_dir("work");
    std::fs::copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/starter.yaml"),
        work.join("provio.yaml"),
    )
    .unwrap();
    for (id, cmd) in [
        ("t1", "git push --force origin main"),
        ("t2", "cargo test"),
        ("t3", "terraform destroy"),
    ] {
        let payload = json!({"hook_event_name": "PreToolUse", "session_id": "night-1",
            "tool_use_id": id, "tool_name": "Bash", "tool_input": {"command": cmd}});
        let mut child = Command::new(env!("CARGO_BIN_EXE_provio"))
            .args(["check", "--format", "claude-code"])
            .current_dir(&work)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes())
            .unwrap();
        child.wait().unwrap();
    }
    let out = provio(&work, &home, &["receipt", "keygen", "--out", "k.pem"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = provio(
        &work,
        &home,
        &[
            "report", "--format", "json", "--since", "1h", "--sign", "k.pem", "--out", "r.json",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value =
        serde_json::from_str(&std::fs::read_to_string(work.join("r.json")).unwrap()).unwrap();
    assert_eq!(v["totals"]["calls"], 3, "{v:#}");
    assert_eq!(v["totals"]["stopped"], 1, "{v:#}");
    assert_eq!(v["totals"]["asked"], 1, "{v:#}");
    assert_eq!(v["integrity"]["intact"], true);
    assert!(v["receipt"]["checkpoint"]["tip_hash"].is_string(), "{v:#}");
    // The receipt written next to the report verifies against the ledger.
    let out = provio(
        &work,
        &home,
        &[
            "receipt",
            "verify",
            "r.receipt.json",
            "--pubkey",
            "k.pem.pub",
        ],
    );
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The HTML page is self-contained and leads with what was stopped.
    let out = provio(&work, &home, &["report"]);
    assert!(out.status.success());
    let page = std::fs::read_to_string(work.join("provio-report.html")).unwrap();
    assert!(page.contains("Stopped by provio") && page.contains("floor-force-push-main-denied"));
    assert!(
        !page.contains("<script"),
        "the report must not carry scripts"
    );
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn check_without_a_policy_fails_closed_unless_told_to_use_the_starter() {
    use std::io::Write;
    let home = empty_dir("home");
    let work = empty_dir("work");
    let run = |extra: &[&str], cmd: &str| {
        let mut args = vec!["check", "--format", "claude-code"];
        args.extend_from_slice(extra);
        let mut child = Command::new(env!("CARGO_BIN_EXE_provio"))
            .args(&args)
            .current_dir(&work)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let payload = json!({"hook_event_name": "PreToolUse", "session_id": "s",
            "tool_use_id": cmd, "tool_name": "Bash", "tool_input": {"command": cmd}});
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    // No provio.yaml: every call is refused (fail closed)...
    assert!(run(&[], "cargo test").contains("\"deny\""));
    // ...unless the starter floor is asked for: ordinary calls pass,
    // disasters do not, and the ledger goes to ~/.provio/.
    assert!(run(&["--if-no-policy", "starter"], "cargo test").contains("\"allow\""));
    let d = run(&["--if-no-policy", "starter"], "rm -rf ~");
    assert!(d.contains("floor-rm-home-or-root-denied"), "{d}");
    assert!(home.join(".provio/ledger.jsonl").is_file());
    assert!(!work.join(".provio").exists());
    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&work);
}
