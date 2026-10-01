//! End-to-end tests for `provio check` (Contract 6) and `provio integrate`,
//! driving the built binary exactly as adapters and Claude Code do.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Value};

const POLICY: &str = r#"version: 1
default: ask
rules:
  - id: no-rm
    when: tool == "bash" and command matches "rm -rf"
    verdict: deny
    reason: "Destructive command."
  - id: deploy
    when: tool == "bash" and command matches "^deploy"
    verdict: ask
    irreversible: true
    timeout: 10m
    reason: "Deploys need a human."
  - id: quick
    when: tool == "bash" and command matches "^quick"
    verdict: ask
    timeout: 1s
    reason: "Quick approval window."
  - id: ls-ok
    when: tool == "bash" and command matches "^(ls|echo)"
    verdict: allow
  - id: secrets
    when: path matches "\\.env$"
    verdict: deny
    reason: "Secrets are off limits."
  - id: read-ok
    when: tool == "fs.read"
    verdict: allow
  - id: egress
    when: tool == "http" and not url.host in hosts.allowed
    verdict: deny
    reason: "Host is not on the egress allow-list."
  - id: pii
    when: tool == "query"
    verdict: redact
    patterns:
      - "\\b\\d{3}-\\d{2}-\\d{4}\\b"
hosts:
  allowed: [api.github.com]
"#;

/// A scratch project directory: `provio.yaml` + `.provio/ledger.jsonl`.
struct Project(PathBuf);

impl Project {
    fn new() -> Self {
        let p = Self::bare();
        std::fs::write(p.0.join("provio.yaml"), POLICY).unwrap();
        p
    }

    fn bare() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("provio-check-test-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Project(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn ledger(&self) -> PathBuf {
        self.0.join(".provio").join("ledger.jsonl")
    }

    fn records(&self) -> Vec<Value> {
        match std::fs::read_to_string(self.ledger()) {
            Ok(s) => s
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| serde_json::from_str(l).unwrap())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Run `provio <args>` in the project with `stdin`; retries the spawn when
    /// Windows Application Control transiently blocks a fresh binary.
    fn provio(&self, args: &[&str], stdin: &str) -> Output {
        let mut attempt = 0;
        loop {
            let child = Command::new(env!("CARGO_BIN_EXE_provio"))
                .args(args)
                .current_dir(&self.0)
                .env("RUST_LOG", "off")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();
            match child {
                Ok(mut c) => {
                    {
                        let mut i = c.stdin.take().unwrap();
                        let _ = i.write_all(stdin.as_bytes());
                    }
                    return c.wait_with_output().unwrap();
                }
                Err(e) if e.raw_os_error() == Some(4551) && attempt < 10 => {
                    attempt += 1;
                    std::thread::sleep(std::time::Duration::from_millis(300));
                }
                Err(e) => panic!("spawn provio: {e}"),
            }
        }
    }

    /// One-shot `provio check` in provio format; returns (response, exit code).
    fn check(&self, extra: &[&str], req: &Value) -> (Value, i32) {
        let mut args = vec!["check"];
        args.extend_from_slice(extra);
        let out = self.provio(&args, &req.to_string());
        (single_json(&out), out.status.code().unwrap())
    }

    fn claude(&self, extra: &[&str], payload: &Value) -> (Value, i32, String) {
        let mut args = vec!["check", "--format", "claude-code"];
        args.extend_from_slice(extra);
        let out = self.provio(&args, &payload.to_string());
        (
            single_json(&out),
            out.status.code().unwrap(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn verify(&self) -> String {
        let out = self.provio(&["verify"], "");
        assert!(
            out.status.success(),
            "verify failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn single_json(out: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one stdout line, got {stdout:?} (stderr: {})",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(lines[0]).unwrap()
}

fn decide(id: &str, session: &str, call_id: &str, tool: &str, args: Value) -> Value {
    json!({"v": 1, "id": id, "op": "decide", "call": {
        "call_id": call_id, "session_id": session, "tool": tool, "args": args,
        "caller": {"agent": "test-adapter", "agent_version": "0.1", "user": "alice"}
    }})
}

fn bash(id: &str, call_id: &str, command: &str) -> Value {
    decide(id, "s1", call_id, "bash", json!({"command": command}))
}

fn complete(id: &str, r: &Value, output: Option<&str>) -> Value {
    let mut v = json!({"v": 1, "id": id, "op": "complete", "ref": r, "ok": true, "exit": 0});
    if let Some(o) = output {
        v["output"] = json!(o);
    }
    v
}

fn resolve(id: &str, r: &Value, approved: bool) -> Value {
    json!({"v": 1, "id": id, "op": "resolve", "ref": r, "approved": approved, "approver": "human:alice"})
}

fn sha256_hex(bytes: &[u8]) -> String {
    // Use the ledger's own hash through provio-core to avoid a test-only dep.
    provio_core::ledger::LedgerRecord::hash_bytes(bytes)
}

fn decisions_for<'a>(records: &'a [Value], call_id: &str) -> Vec<&'a Value> {
    records
        .iter()
        .filter(|r| r["call_id"] == call_id && r["kind"] == "decision")
        .collect()
}

// ---------------------------------------------------------------------------
// --format provio, one-shot

#[test]
fn allow_then_complete() {
    let p = Project::new();
    let (r, code) = p.check(&[], &bash("r1", "c-allow", "ls -la"));
    assert_eq!(code, 0, "{r}");
    assert_eq!(r["v"], 1);
    assert_eq!(r["id"], "r1");
    assert_eq!(r["decision"], "allow");
    assert_eq!(r["dispatch"], true);
    assert_eq!(r["rule_id"], "ls-ok");
    assert_eq!(r["call_id"], "c-allow");
    let rf = r["ref"].clone();
    assert!(rf.as_str().unwrap().starts_with("w1.0."));

    let (c, code) = p.check(&[], &complete("r2", &rf, Some("file-a\nfile-b")));
    assert_eq!(code, 0, "{c}");
    assert_eq!(c["recorded"], true);
    assert!(c.get("output").is_none(), "output echoed only for redact");

    let recs = p.records();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0]["kind"], "decision");
    assert_eq!(recs[0]["call"]["mode"], "sdkhook");
    assert_eq!(recs[0]["call"]["caller"]["agent"], "test-adapter");
    assert_eq!(recs[1]["kind"], "execution");
    assert_eq!(recs[1]["decision_index"], 0);
    assert_eq!(recs[1]["backend"], "sdk-hook");
    assert_eq!(recs[1]["output_hash"], sha256_hex(b"file-a\nfile-b"));
    assert!(
        !std::fs::read_to_string(p.ledger())
            .unwrap()
            .contains("file-a"),
        "output is never stored"
    );

    // A second complete for the same call is refused and records nothing.
    let (e, code) = p.check(&[], &complete("r3", &rf, None));
    assert_eq!(code, 1);
    assert_eq!(e["error"]["code"], "invalid_state");
    assert_eq!(p.records().len(), 2);
    assert!(p.verify().contains("chain intact"));
}

#[test]
fn generated_call_id_and_default_caller() {
    let p = Project::new();
    let req = json!({"v": 1, "id": 7, "op": "decide", "call": {"session_id": "s", "tool": "bash", "args": {"command": "echo hi"}}});
    let (r, code) = p.check(&[], &req);
    assert_eq!(code, 0, "{r}");
    assert_eq!(r["id"], 7);
    assert!(r["call_id"].as_str().unwrap().starts_with("wc-"));
    assert_eq!(p.records()[0]["call"]["caller"]["agent"], "unknown");
}

#[test]
fn deny_carries_rule_reason_and_location() {
    let p = Project::new();
    let (r, code) = p.check(&[], &bash("r1", "c-rm", "rm -rf /"));
    assert_eq!(code, 2, "{r}");
    assert_eq!(r["decision"], "deny");
    assert_eq!(r["dispatch"], false);
    assert_eq!(r["rule_id"], "no-rm");
    assert_eq!(r["reason"], "Destructive command.");
    assert!(
        r["location"].as_str().unwrap().starts_with("provio.yaml:"),
        "{r}"
    );
    // Exactly one decision record, even though nothing will run.
    let recs = p.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0]["verdict"]["kind"], "deny");
    // A denied call cannot be completed.
    let (e, code) = p.check(&[], &complete("r2", &r["ref"], None));
    assert_eq!(
        (code, e["error"]["code"].as_str()),
        (1, Some("invalid_state"))
    );
}

#[test]
fn ask_with_default_deny_mode_fails_closed() {
    let p = Project::new();
    let (r, code) = p.check(&[], &bash("r1", "c-dep", "deploy prod"));
    assert_eq!(code, 2, "{r}");
    assert_eq!(r["decision"], "deny");
    assert_eq!(r["dispatch"], false);
    assert_eq!(r["rule_id"], "deploy");
    assert_eq!(r["verdict"], "ask");
    assert!(r.get("approval").is_none());
    let recs = p.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(
        recs[0]["verdict"]["kind"], "ask",
        "the engine verdict is recorded"
    );
    assert!(recs[0]["approver"]["id"]
        .as_str()
        .unwrap()
        .starts_with("fail-closed"));
    // Nothing to resolve: the fail-closed approver already answered.
    let (e, code) = p.check(&["--ask", "defer"], &resolve("r2", &r["ref"], true));
    assert_eq!(
        (code, e["error"]["code"].as_str()),
        (1, Some("invalid_state"))
    );
}

#[test]
fn deferred_ask_approved_across_processes() {
    let p = Project::new();
    let (r, code) = p.check(&["--ask", "defer"], &bash("r1", "c-dep", "deploy prod"));
    assert_eq!(code, 2, "an unresolved ask never dispatches: {r}");
    assert_eq!(r["decision"], "ask");
    assert_eq!(r["approval"], "required");
    assert_eq!(r["dispatch"], false);
    assert_eq!(r["irreversible"], true);
    assert_eq!(r["timeout_ms"], 600_000);
    assert_eq!(r["reason"], "Deploys need a human.");
    let ask_ref = r["ref"].clone();

    // complete before resolve is refused.
    let (e, code) = p.check(&["--ask", "defer"], &complete("r2", &ask_ref, None));
    assert_eq!(
        (code, e["error"]["code"].as_str()),
        (1, Some("invalid_state"))
    );

    let (f, code) = p.check(&["--ask", "defer"], &resolve("r3", &ask_ref, true));
    assert_eq!(code, 0, "{f}");
    assert_eq!(f["decision"], "allow");
    assert_eq!(f["dispatch"], true);
    assert_eq!(f["rule_id"], "deploy");
    let approved_ref = f["ref"].clone();
    assert_ne!(approved_ref, ask_ref);
    // Resolve writes nothing: still exactly one record for the call.
    assert_eq!(p.records().len(), 1);

    // An approved ref cannot be resolved again.
    let (e, _) = p.check(&["--ask", "defer"], &resolve("r4", &approved_ref, false));
    assert_eq!(e["error"]["code"], "invalid_state");

    let (c, code) = p.check(
        &["--ask", "defer"],
        &complete("r5", &approved_ref, Some("ok")),
    );
    assert_eq!(code, 0, "{c}");
    let recs = p.records();
    assert_eq!(recs.len(), 2);
    assert_eq!(decisions_for(&recs, "c-dep").len(), 1);
    assert_eq!(recs[0]["verdict"]["kind"], "ask");
    assert!(recs[0]["approver"].is_null());
    assert_eq!(recs[1]["kind"], "execution");
    assert_eq!(recs[1]["approver"], json!({"kind": "tui", "id": "alice"}));
    assert!(p.verify().contains("chain intact · 2 records"));

    // `provio log` credits the human approval.
    let log = p.provio(&["log"], "");
    assert!(String::from_utf8_lossy(&log.stdout).contains("1 sessions with your approvals"));
}

#[test]
fn deferred_ask_rejected() {
    let p = Project::new();
    let (r, _) = p.check(&["--ask", "defer"], &bash("r1", "c-dep", "deploy prod"));
    let (f, code) = p.check(&["--ask", "defer"], &resolve("r2", &r["ref"], false));
    assert_eq!(code, 2, "{f}");
    assert_eq!(f["decision"], "deny");
    assert_eq!(f["dispatch"], false);
    assert_eq!(f["rule_id"], "deploy");
    assert!(f["reason"].as_str().unwrap().contains("alice"));
    let (e, code) = p.check(&["--ask", "defer"], &complete("r3", &f["ref"], None));
    assert_eq!(
        (code, e["error"]["code"].as_str()),
        (1, Some("invalid_state"))
    );
    assert_eq!(p.records().len(), 1, "only the decision record");
}

#[test]
fn deferred_ask_times_out_closed() {
    let p = Project::new();
    let (r, _) = p.check(&["--ask", "defer"], &bash("r1", "c-q", "quick fix"));
    assert_eq!(r["timeout_ms"], 1000);
    std::thread::sleep(std::time::Duration::from_millis(2200));
    let (f, code) = p.check(&["--ask", "defer"], &resolve("r2", &r["ref"], true));
    assert_eq!(code, 2, "{f}");
    assert_eq!(f["decision"], "deny");
    assert!(f["reason"].as_str().unwrap().contains("timeout"), "{f}");
}

#[test]
fn redact_masks_completed_output_and_hashes_the_original() {
    let p = Project::new();
    let req = decide(
        "r1",
        "s1",
        "c-q",
        "query",
        json!({"sql": "select * from users"}),
    );
    let (r, code) = p.check(&[], &req);
    assert_eq!(code, 0, "{r}");
    assert_eq!(r["decision"], "redact");
    assert_eq!(r["dispatch"], true);
    assert_eq!(r["patterns"][0], "\\b\\d{3}-\\d{2}-\\d{4}\\b");
    let original = "alice 123-45-6789, bob 987-65-4321";
    let (c, code) = p.check(&[], &complete("r2", &r["ref"], Some(original)));
    assert_eq!(code, 0, "{c}");
    assert_eq!(
        c["output"],
        "alice [redacted-by-provio], bob [redacted-by-provio]"
    );
    let recs = p.records();
    assert_eq!(recs[1]["output_hash"], sha256_hex(original.as_bytes()));
}

// ---------------------------------------------------------------------------
// Fail-closed error paths

#[test]
fn malformed_and_invalid_requests_fail_closed() {
    let p = Project::new();
    let cases: Vec<(&str, &str)> = vec![
        ("{not json", "bad_request"),
        ("[1,2]", "bad_request"),
        (r#"{"id":"x","op":"decide"}"#, "bad_request"),
        (r#"{"v":2,"id":"x","op":"decide"}"#, "bad_request"),
        (r#"{"v":1,"id":"x","op":"launch"}"#, "unknown_op"),
        (r#"{"v":1,"id":"x"}"#, "bad_request"),
        (
            r#"{"v":1,"id":"x","op":"decide","call":{"tool":"bash"}}"#,
            "bad_request",
        ),
        (
            r#"{"v":1,"id":"x","op":"decide","call":{"session_id":"s","tool":""}}"#,
            "bad_request",
        ),
        (
            r#"{"v":1,"id":"x","op":"decide","call":{"session_id":"s","tool":"bash","trust":"sketchy"}}"#,
            "bad_request",
        ),
        (
            r#"{"v":1,"id":"x","op":"complete","ref":"nope","ok":true}"#,
            "bad_ref",
        ),
        (
            r#"{"v":1,"id":"x","op":"resolve","ref":"w1.0.00","approved":true}"#,
            "bad_ref",
        ),
        (
            r#"{"v":1,"id":"x","op":"complete","ok":true}"#,
            "bad_request",
        ),
        ("", "bad_request"),
    ];
    for (input, code) in cases {
        let out = p.provio(&["check"], input);
        assert_eq!(out.status.code(), Some(1), "input {input:?}");
        let v = single_json(&out);
        assert_eq!(v["error"]["code"], code, "input {input:?} -> {v}");
        assert!(v.get("dispatch").is_none());
    }
    assert!(
        p.records().is_empty(),
        "no request above may write a record"
    );
}

#[test]
fn well_formed_refs_are_validated_against_the_ledger() {
    let p = Project::new();
    let (r, _) = p.check(&[], &bash("r1", "c1", "ls"));
    p.check(&[], &complete("r2", &r["ref"], None));
    let good = r["ref"].as_str().unwrap().to_string();
    let parts: Vec<&str> = good.split('.').collect();
    let forged = [
        // Right index, wrong hash.
        format!("w1.0.{}", "f".repeat(64)),
        // Index of the execution record, with its decision's hash.
        format!("w1.1.{}", parts[2]),
        // Beyond the ledger.
        format!("w1.99.{}", parts[2]),
    ];
    for f in &forged {
        let (e, code) = p.check(&[], &complete("r3", &json!(f), None));
        assert_eq!(code, 1);
        assert_eq!(e["error"]["code"], "bad_ref", "{f}");
    }
    assert_eq!(p.records().len(), 2);
}

#[test]
fn missing_policy_fails_closed() {
    let p = Project::bare();
    let (e, code) = p.check(&[], &bash("r1", "c1", "ls"));
    assert_eq!(code, 1);
    assert_eq!(e["id"], "r1");
    assert_eq!(e["error"]["code"], "policy_error");
    assert!(p.records().is_empty());

    let payload = cc_pre("sess", "toolu_x", "Bash", json!({"command": "ls"}));
    let (out, code, _) = p.claude(&[], &payload);
    assert_eq!(code, 2, "claude-code errors must exit 2 to block");
    assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn invalid_policy_fails_closed() {
    let p = Project::bare();
    std::fs::write(p.path().join("provio.yaml"), "version: 1\nrules: [[[").unwrap();
    let (e, code) = p.check(&[], &bash("r1", "c1", "ls"));
    assert_eq!(
        (code, e["error"]["code"].as_str()),
        (1, Some("policy_error"))
    );
}

// ---------------------------------------------------------------------------
// --stdio

#[test]
fn stdio_answers_every_request_in_order() {
    let p = Project::new();
    let lines = [
        bash("a", "c1", "ls").to_string(),
        String::new(), // blank lines are not requests
        "{broken".to_string(),
        bash("b", "c2", "rm -rf /tmp/x").to_string(),
        json!({"v": 1, "id": "c", "op": "frobnicate"}).to_string(),
        bash("d", "c3", "echo hi").to_string(),
    ];
    let out = p.provio(&["check", "--stdio"], &(lines.join("\n") + "\n"));
    assert_eq!(out.status.code(), Some(0));
    let resp: Vec<Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(resp.len(), 5, "{resp:?}");
    assert_eq!(resp[0]["id"], "a");
    assert_eq!(resp[0]["decision"], "allow");
    assert_eq!(resp[1]["id"], Value::Null);
    assert_eq!(resp[1]["error"]["code"], "bad_request");
    assert_eq!(resp[2]["id"], "b");
    assert_eq!(resp[2]["decision"], "deny");
    assert_eq!(resp[3]["id"], "c");
    assert_eq!(resp[3]["error"]["code"], "unknown_op");
    assert_eq!(resp[4]["id"], "d");
    assert_eq!(resp[4]["decision"], "allow");
    assert_eq!(p.records().len(), 3, "one decision per decide");
}

#[test]
fn stdio_decide_resolve_complete_in_one_session() {
    let p = Project::new();
    // The ref from decide is only known after the response, so drive the
    // child interactively.
    let mut child = Command::new(env!("CARGO_BIN_EXE_provio"))
        .args(["check", "--stdio", "--ask", "defer"])
        .current_dir(p.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut roundtrip = |req: Value| -> Value {
        use std::io::BufRead;
        writeln!(stdin, "{req}").unwrap();
        stdin.flush().unwrap();
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    };
    let d = roundtrip(bash("1", "c-dep", "deploy now"));
    assert_eq!(d["approval"], "required");
    let f = roundtrip(resolve("2", &d["ref"], true));
    assert_eq!(f["dispatch"], true);
    let c = roundtrip(complete("3", &f["ref"], Some("deployed")));
    assert_eq!(c["recorded"], true);
    drop(stdin);
    assert!(child.wait().unwrap().success());
    let recs = p.records();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[1]["approver"]["id"], "alice");
}

// ---------------------------------------------------------------------------
// --format claude-code

fn cc_pre(session: &str, tool_use_id: &str, tool: &str, input: Value) -> Value {
    json!({
        "session_id": session,
        "transcript_path": "/tmp/t.jsonl",
        "cwd": "/tmp",
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": input,
        "tool_use_id": tool_use_id
    })
}

fn cc_post(session: &str, tool_use_id: &str, tool: &str, input: Value, response: Value) -> Value {
    let mut v = cc_pre(session, tool_use_id, tool, input);
    v["hook_event_name"] = json!("PostToolUse");
    v["tool_response"] = response;
    v
}

#[test]
fn claude_code_allow_round_trip() {
    let p = Project::new();
    let input = json!({"command": "ls -la", "description": "list"});
    let (out, code, _) = p.claude(&[], &cc_pre("sess-1", "toolu_01", "Bash", input.clone()));
    assert_eq!(code, 0, "{out}");
    let hso = &out["hookSpecificOutput"];
    assert_eq!(hso["hookEventName"], "PreToolUse");
    assert_eq!(hso["permissionDecision"], "allow");
    assert!(hso["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .contains("ls-ok"));

    let resp = json!({"stdout": "a\nb", "stderr": "", "interrupted": false, "isImage": false});
    let (out, code, err) = p.claude(
        &[],
        &cc_post("sess-1", "toolu_01", "Bash", input, resp.clone()),
    );
    assert_eq!(code, 0, "{out} {err}");
    assert_eq!(out["hookSpecificOutput"]["hookEventName"], "PostToolUse");
    assert!(out["hookSpecificOutput"].get("updatedToolOutput").is_none());

    let recs = p.records();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0]["call_id"], "toolu_01");
    assert_eq!(recs[0]["session_id"], "sess-1");
    assert_eq!(recs[0]["call"]["tool"], "bash");
    assert_eq!(recs[0]["call"]["caller"]["agent"], "claude-code");
    assert_eq!(recs[1]["decision_index"], 0);
    assert_eq!(recs[1]["backend"], "claude-code");
    assert_eq!(recs[1]["exit_status"], 0);
    assert_eq!(
        recs[1]["output_hash"],
        sha256_hex(&serde_json::to_vec(&resp).unwrap())
    );
    assert!(p.verify().contains("chain intact · 2 records"));
}

#[test]
fn claude_code_deny_blocks_with_exit_2() {
    let p = Project::new();
    let (out, code, err) = p.claude(
        &[],
        &cc_pre("s", "toolu_rm", "Bash", json!({"command": "rm -rf /"})),
    );
    assert_eq!(code, 2);
    let hso = &out["hookSpecificOutput"];
    assert_eq!(hso["permissionDecision"], "deny");
    let reason = hso["permissionDecisionReason"].as_str().unwrap();
    assert!(
        reason.contains("no-rm") && reason.contains("Destructive command."),
        "{reason}"
    );
    assert!(err.contains("no-rm"), "stderr carries the reason too");

    // Read of a secret (file_path → path) and WebFetch egress (url.host).
    let (out, code, _) = p.claude(
        &[],
        &cc_pre(
            "s",
            "toolu_env",
            "Read",
            json!({"file_path": "C:\\proj\\.env"}),
        ),
    );
    assert_eq!(
        (
            code,
            out["hookSpecificOutput"]["permissionDecision"].as_str()
        ),
        (2, Some("deny"))
    );
    let (out, code, _) = p.claude(
        &[],
        &cc_pre(
            "s",
            "toolu_rd",
            "Read",
            json!({"file_path": "/proj/src/main.rs"}),
        ),
    );
    assert_eq!(
        (
            code,
            out["hookSpecificOutput"]["permissionDecision"].as_str()
        ),
        (0, Some("allow"))
    );
    let (out, code, _) = p.claude(
        &[],
        &cc_pre(
            "s",
            "toolu_web",
            "WebFetch",
            json!({"url": "https://evil.example/x", "prompt": "p"}),
        ),
    );
    assert_eq!(code, 2);
    assert!(out["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .contains("egress"));
}

#[test]
fn claude_code_ask_maps_to_the_permission_prompt() {
    let p = Project::new();
    let input = json!({"command": "deploy prod"});
    let (out, code, _) = p.claude(
        &["--ask", "defer"],
        &cc_pre("s", "toolu_dep", "Bash", input.clone()),
    );
    assert_eq!(code, 0);
    assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "ask");
    // The human approved in Claude Code, the tool ran, PostToolUse arrives.
    let (_, code, err) = p.claude(
        &["--ask", "defer"],
        &cc_post(
            "s",
            "toolu_dep",
            "Bash",
            input,
            json!({"stdout": "done", "stderr": ""}),
        ),
    );
    assert_eq!(code, 0, "{err}");
    let recs = p.records();
    assert_eq!(recs.len(), 2);
    assert_eq!(
        recs[1]["approver"],
        json!({"kind": "tui", "id": "claude-code-prompt"})
    );

    // Default --ask deny: fail closed.
    let (out, code, _) = p.claude(
        &[],
        &cc_pre("s", "toolu_dep2", "Bash", json!({"command": "deploy x"})),
    );
    assert_eq!(
        (
            code,
            out["hookSpecificOutput"]["permissionDecision"].as_str()
        ),
        (2, Some("deny"))
    );
}

#[test]
fn claude_code_redacts_mcp_output() {
    let p = Project::new();
    let input = json!({"sql": "select ssn from people"});
    let (out, code, _) = p.claude(
        &[],
        &cc_pre("s", "toolu_q", "mcp__db__query", input.clone()),
    );
    assert_eq!(
        (
            code,
            out["hookSpecificOutput"]["permissionDecision"].as_str()
        ),
        (0, Some("allow"))
    );
    assert_eq!(p.records()[0]["call"]["server"]["name"], "db");
    assert_eq!(p.records()[0]["call"]["tool"], "query");

    let resp = json!({"content": [{"type": "text", "text": "ssn=123-45-6789"}], "isError": false});
    let (out, code, err) = p.claude(
        &[],
        &cc_post("s", "toolu_q", "mcp__db__query", input, resp.clone()),
    );
    assert_eq!(code, 0, "{err}");
    let updated = &out["hookSpecificOutput"]["updatedToolOutput"];
    assert_eq!(updated["content"][0]["text"], "ssn=[redacted-by-provio]");
    assert_eq!(updated["isError"], false, "shape preserved");
    assert_eq!(
        p.records()[1]["output_hash"],
        sha256_hex(&serde_json::to_vec(&resp).unwrap())
    );
}

#[test]
fn claude_code_failure_event_records_exit_code() {
    let p = Project::new();
    let input = json!({"command": "echo boom"});
    p.claude(&[], &cc_pre("s", "toolu_f", "Bash", input.clone()));
    let mut fail = cc_pre("s", "toolu_f", "Bash", input);
    fail["hook_event_name"] = json!("PostToolUseFailure");
    fail["error"] = json!("Exit code 3\nboom");
    let (out, code, _) = p.claude(&[], &fail);
    assert_eq!(code, 0);
    assert_eq!(
        out["hookSpecificOutput"]["hookEventName"],
        "PostToolUseFailure"
    );
    let recs = p.records();
    assert_eq!(recs[1]["exit_status"], 3);
    assert_eq!(recs[1]["output_hash"], sha256_hex(b"Exit code 3\nboom"));
}

#[test]
fn claude_code_errors_fail_closed() {
    let p = Project::new();
    for bad in [
        "",
        "not json",
        "[]",
        r#"{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Bash"}"#,
        r#"{"hook_event_name":"Stop","session_id":"s"}"#,
    ] {
        let out = p.provio(&["check", "--format", "claude-code"], bad);
        assert_eq!(out.status.code(), Some(2), "{bad:?}");
        let v = single_json(&out);
        assert_eq!(
            v["hookSpecificOutput"]["permissionDecision"], "deny",
            "{bad:?}"
        );
    }
    // PostToolUse with no recorded decision: exit 2, whole output masked.
    let resp = json!({"stdout": "secret stuff", "stderr": ""});
    let (out, code, err) = p.claude(
        &[],
        &cc_post("s", "toolu_ghost", "Bash", json!({"command": "ls"}), resp),
    );
    assert_eq!(code, 2);
    assert!(err.contains("no provio decision"), "{err}");
    assert_eq!(
        out["hookSpecificOutput"]["updatedToolOutput"]["stdout"],
        "[redacted-by-provio]"
    );
    // --stdio is not a Claude Code transport.
    let (out, code, _) = p.claude(
        &["--stdio"],
        &cc_pre("s", "t", "Bash", json!({"command": "ls"})),
    );
    assert_eq!(
        (
            code,
            out["hookSpecificOutput"]["permissionDecision"].as_str()
        ),
        (2, Some("deny"))
    );
    assert!(p.records().is_empty());
}

// ---------------------------------------------------------------------------
// Concurrency: many processes, one ledger

#[test]
fn parallel_processes_share_one_linear_chain() {
    // Distinct commands: the same call 5 times in a row would trip the
    // loop breaker (session_guards.repeated_call), which is not under test.
    const N: usize = 16;
    let p = Project::new();
    std::thread::scope(|s| {
        for i in 0..N {
            let p = &p;
            s.spawn(move || {
                if i % 2 == 0 {
                    let (r, code) = p.check(
                        &[],
                        &bash(&format!("r{i}"), &format!("par-{i}"), &format!("ls d{i}")),
                    );
                    assert_eq!(code, 0, "{r}");
                    let (c, code) = p.check(&[], &complete("c", &r["ref"], Some("x")));
                    assert_eq!(code, 0, "{c}");
                } else {
                    let id = format!("toolu_par_{i}");
                    let input = json!({"command": format!("echo par {i}")});
                    let (o, code, e) = p.claude(&[], &cc_pre("par", &id, "Bash", input.clone()));
                    assert_eq!(code, 0, "{o} {e}");
                    let (o, code, e) = p.claude(
                        &[],
                        &cc_post("par", &id, "Bash", input, json!({"stdout": "par"})),
                    );
                    assert_eq!(code, 0, "{o} {e}");
                }
            });
        }
    });
    let recs = p.records();
    assert_eq!(recs.len(), 2 * N);
    for (i, r) in recs.iter().enumerate() {
        assert_eq!(r["index"], i as u64);
    }
    // Every execution links its own call's decision.
    for r in recs.iter().filter(|r| r["kind"] == "execution") {
        let d = &recs[r["decision_index"].as_u64().unwrap() as usize];
        assert_eq!(d["call_id"], r["call_id"]);
    }
    assert!(p
        .verify()
        .contains(&format!("chain intact · {} records", 2 * N)));
}

// ---------------------------------------------------------------------------
// provio integrate claude-code

#[test]
fn integrate_preserves_settings_and_is_idempotent() {
    let p = Project::new();
    let claude = p.path().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    let existing = json!({
        "model": "opus",
        "permissions": {"allow": ["Bash(ls:*)"]},
        "hooks": {"PostToolUse": [{"matcher": "Edit|Write", "hooks": [{"type": "command", "command": "fmt.sh"}]}]}
    });
    std::fs::write(
        claude.join("settings.json"),
        serde_json::to_string_pretty(&existing).unwrap(),
    )
    .unwrap();

    // --print does not write.
    let printed = p.provio(&["integrate", "claude-code", "--print"], "");
    assert!(
        printed.status.success(),
        "{}",
        String::from_utf8_lossy(&printed.stderr)
    );
    let printed: Value = serde_json::from_slice(&printed.stdout).unwrap();
    let on_disk: Value =
        serde_json::from_str(&std::fs::read_to_string(claude.join("settings.json")).unwrap())
            .unwrap();
    assert_eq!(on_disk, existing);

    let out = p.provio(&["integrate", "claude-code"], "");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let once = std::fs::read_to_string(claude.join("settings.json")).unwrap();
    let v: Value = serde_json::from_str(&once).unwrap();
    assert_eq!(v, printed, "--print shows exactly what gets written");
    assert_eq!(v["model"], "opus");
    assert_eq!(v["permissions"], existing["permissions"]);
    let post = v["hooks"]["PostToolUse"].as_array().unwrap();
    assert_eq!(post.len(), 2);
    assert_eq!(post[0]["hooks"][0]["command"], "fmt.sh");
    let provio_hook = &v["hooks"]["PreToolUse"][0]["hooks"][0];
    let exe = Path::new(provio_hook["command"].as_str().unwrap());
    assert!(exe.is_absolute() && exe.exists(), "{exe:?}");
    let args: Vec<&str> = provio_hook["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap())
        .collect();
    assert!(Path::new(args[1]).is_absolute() && args[1].ends_with("provio.yaml"));
    assert!(Path::new(args[3]).is_absolute() && args[3].ends_with("ledger.jsonl"));
    assert_eq!(
        &args[4..],
        ["check", "--format", "claude-code", "--ask", "defer"]
    );
    assert!(v["hooks"]["PostToolUseFailure"].is_array());

    let out = p.provio(&["integrate", "claude-code"], "");
    assert!(out.status.success());
    let twice = std::fs::read_to_string(claude.join("settings.json")).unwrap();
    assert_eq!(once, twice, "second run changes nothing");

    // The written hook actually works: run it as Claude Code would.
    let hook_out = Command::new(exe)
        .args(&args)
        .current_dir(std::env::temp_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .and_then(|mut c| {
            c.stdin.take().unwrap().write_all(
                cc_pre("s", "toolu_i", "Bash", json!({"command": "ls"}))
                    .to_string()
                    .as_bytes(),
            )?;
            c.wait_with_output()
        })
        .unwrap();
    assert_eq!(hook_out.status.code(), Some(0));
    assert_eq!(p.records().len(), 1);
}

#[test]
fn integrate_refuses_a_broken_settings_file_or_missing_policy() {
    let p = Project::new();
    let claude = p.path().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    std::fs::write(claude.join("settings.json"), "{ nope").unwrap();
    let out = p.provio(&["integrate", "claude-code"], "");
    assert!(!out.status.success());
    assert_eq!(
        std::fs::read_to_string(claude.join("settings.json")).unwrap(),
        "{ nope"
    );

    let bare = Project::bare();
    let out = bare.provio(&["integrate", "claude-code"], "");
    assert!(!out.status.success());
    assert!(!bare.path().join(".claude").exists());
}

// ---------------------------------------------------------------------------
// Every provio-side failure in claude-code format blocks: exit 2, never 0/1.

fn assert_blocks(out: &Output, what: &str) {
    assert_eq!(out.status.code(), Some(2), "{what}: must exit 2");
    assert!(!out.stderr.is_empty(), "{what}: reason on stderr");
}

fn assert_pre_denies(out: &Output, what: &str) {
    assert_blocks(out, what);
    let v = single_json(out);
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecision"], "deny",
        "{what}"
    );
}

#[test]
fn claude_code_every_pre_failure_class_blocks() {
    let pre = cc_pre("s", "toolu_1", "Bash", json!({"command": "ls"})).to_string();
    let cc = ["check", "--format", "claude-code"];

    // Malformed payloads.
    let p = Project::new();
    for (bad, what) in [
        ("", "empty stdin"),
        ("{\"hook_event_name\":", "truncated JSON"),
        ("42", "non-object"),
        (
            r#"{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Bash","tool_input":{}}"#,
            "no tool_use_id",
        ),
        (
            r#"{"hook_event_name":"PreToolUse","session_id":"s","tool_use_id":"t","tool_name":"Bash","tool_input":"ls"}"#,
            "tool_input not an object",
        ),
        (
            r#"{"session_id":"s","tool_use_id":"t","tool_name":"Bash"}"#,
            "no hook_event_name",
        ),
    ] {
        assert_pre_denies(&p.provio(&cc, bad), what);
    }

    // Policy missing / unparseable.
    let bare = Project::bare();
    assert_pre_denies(&bare.provio(&cc, &pre), "missing policy");
    std::fs::write(bare.path().join("provio.yaml"), "version: 1\nrules: [[[").unwrap();
    assert_pre_denies(&bare.provio(&cc, &pre), "unparseable policy");

    // Ledger errors: the ledger path is a directory; a corrupt ledger.
    let p = Project::new();
    std::fs::create_dir_all(p.path().join("dir.jsonl")).unwrap();
    let mut args = vec!["--ledger", "dir.jsonl"];
    args.extend_from_slice(&cc);
    assert_pre_denies(&p.provio(&args, &pre), "ledger is a directory");

    let p = Project::new();
    p.check(&[], &bash("r", "c1", "ls"));
    p.check(&[], &bash("r", "c2", "ls"));
    let text = std::fs::read_to_string(p.ledger()).unwrap();
    std::fs::write(p.ledger(), text.replacen('{', "X", 1)).unwrap();
    assert_pre_denies(&p.provio(&cc, &pre), "corrupt ledger");
}

#[test]
fn claude_code_post_failures_are_loud() {
    let p = Project::new();
    let input = json!({"command": "ls"});
    let (_, code, _) = p.claude(&[], &cc_pre("s", "toolu_a", "Bash", input.clone()));
    assert_eq!(code, 0);
    p.claude(&[], &cc_pre("s", "toolu_b", "Bash", input.clone()));
    // Corrupt the first record: the ledger can no longer be read or appended.
    let text = std::fs::read_to_string(p.ledger()).unwrap();
    std::fs::write(p.ledger(), text.replacen('{', "X", 1)).unwrap();
    let post = cc_post("s", "toolu_b", "Bash", input, json!({"stdout": "x"})).to_string();
    let out = p.provio(&["check", "--format", "claude-code"], &post);
    assert_blocks(&out, "PostToolUse on an unreadable ledger");
    // Nothing is known about the call, so the whole output is masked.
    let v = single_json(&out);
    assert_eq!(
        v["hookSpecificOutput"]["updatedToolOutput"]["stdout"],
        "[redacted-by-provio]"
    );
}

// ---------------------------------------------------------------------------
// Clarifications adapters rely on

#[test]
fn repeated_call_id_is_a_new_intercepted_call() {
    let p = Project::new();
    let (a, _) = p.check(&[], &bash("r1", "same", "ls"));
    let (b, _) = p.check(&[], &bash("r2", "same", "ls"));
    assert_ne!(a["ref"], b["ref"], "fresh ref, never a silent reuse");
    assert_eq!(decisions_for(&p.records(), "same").len(), 2);
    // Each attempt completes independently, exactly once.
    assert_eq!(p.check(&[], &complete("r3", &a["ref"], None)).1, 0);
    assert_eq!(p.check(&[], &complete("r4", &b["ref"], None)).1, 0);
    assert_eq!(p.check(&[], &complete("r5", &a["ref"], None)).1, 1);
    assert!(p.verify().contains("chain intact · 4 records"));
}

#[test]
fn refs_survive_gateway_restarts() {
    let p = Project::new();
    // decide in one long-lived process, then that process exits...
    let out = p.provio(
        &["check", "--stdio", "--ask", "defer"],
        &(bash("1", "c-dep", "deploy x").to_string() + "\n"),
    );
    let d: Value = serde_json::from_slice(&out.stdout).unwrap();
    // ...and a new process resolves and completes with those refs.
    let (f, code) = p.check(&["--ask", "defer"], &resolve("2", &d["ref"], true));
    assert_eq!(code, 0, "{f}");
    let (c, code) = p.check(&[], &complete("3", &f["ref"], None));
    assert_eq!(code, 0, "{c}");
}

#[test]
fn redact_masks_output_of_failed_calls_too() {
    let p = Project::new();
    let (r, _) = p.check(
        &[],
        &decide("r1", "s1", "c-q", "query", json!({"sql": "x"})),
    );
    let req = json!({"v": 1, "id": "r2", "op": "complete", "ref": r["ref"], "ok": false,
                     "output": "error near 123-45-6789"});
    let (c, code) = p.check(&[], &req);
    assert_eq!(code, 0, "{c}");
    assert_eq!(c["output"], "error near [redacted-by-provio]");
    assert_eq!(p.records()[1]["exit_status"], 1);
}
