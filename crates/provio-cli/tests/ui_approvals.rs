//! `provio check --ask ui`: a pending ask waits for the console's Approvals
//! screen; approve, deny, timeout and "no console" all behave as specified
//! (only an explicit approval dispatches).

mod ui_common;

use std::io::Write;
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use ui_common::*;

fn wait_pending(c: &Console) -> Value {
    wait_for(20, "the ask to reach the Approvals screen", || {
        let p = c.get("/api/pending").json();
        p["items"].as_array().and_then(|a| a.first().cloned())
    })
}

#[test]
fn approve_dispatches_and_the_execution_names_the_web_console() {
    let l = Layout::new(POLICY);
    let c = Console::start(&l);
    let mut gw = Gateway::start(&l, &l.state, &["--stdio", "--ask", "ui"]);
    gw.send(&decide("a1", "kubectl deploy prod"));

    let item = wait_pending(&c);
    assert_eq!(item["rule_id"], "needs-human");
    assert_eq!(item["tool"], "bash");
    assert_eq!(
        item["args"]["command"], "kubectl deploy prod",
        "shown from the ledger"
    );
    assert_eq!(item["reason"], "Deploys need a human.");
    assert!(item["remaining_ms"].as_i64().unwrap() > 20_000);
    // The ask is on the ledger while it waits.
    let feed = c.get("/api/decisions").json();
    assert_eq!(feed["items"][0]["outcome"], "waiting", "{feed}");

    let r = c.post(
        "/api/pending/decide",
        &json!({"id": item["id"], "approve": true}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let resp = gw.recv();
    assert_eq!(resp["decision"], "allow", "{resp}");
    assert_eq!(resp["dispatch"], true);
    assert!(resp["approver"]
        .as_str()
        .unwrap()
        .starts_with("web-console:"));

    gw.send(&json!({"v": 1, "id": "c1", "op": "complete", "ref": resp["ref"], "ok": true, "output": "deployed"}));
    let done = gw.recv();
    assert_eq!(done["recorded"], true, "{done}");

    let recs = ledger_records(&l);
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0]["verdict"]["kind"], "ask");
    assert!(
        recs[0]["approver"].is_null(),
        "decision recorded before the wait"
    );
    assert_eq!(recs[1]["kind"], "execution");
    assert_eq!(recs[1]["approver"]["kind"], "tui");
    assert!(recs[1]["approver"]["id"]
        .as_str()
        .unwrap()
        .starts_with("web-console:"));

    // The request file is gone; nothing is pending.
    let p = c.get("/api/pending").json();
    assert!(p["items"].as_array().unwrap().is_empty(), "{p}");
    // Resolve is not accepted under --ask ui.
    gw.send(&json!({"v": 1, "id": "x", "op": "resolve", "ref": resp["ref"], "approved": true}));
    let e = gw.recv();
    assert_eq!(e["error"]["code"], "invalid_state", "{e}");
}

#[test]
fn deny_does_not_dispatch() {
    let l = Layout::new(POLICY);
    let c = Console::start(&l);
    let mut gw = Gateway::start(&l, &l.state, &["--stdio", "--ask", "ui"]);
    gw.send(&decide("d1", "deploy everything"));
    let item = wait_pending(&c);
    let r = c.post(
        "/api/pending/decide",
        &json!({"id": item["id"], "approve": false}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let resp = gw.recv();
    assert_eq!(resp["decision"], "deny", "{resp}");
    assert_eq!(resp["dispatch"], false);
    assert_eq!(resp["verdict"], "ask");
    assert!(
        resp["reason"]
            .as_str()
            .unwrap()
            .contains("denied in the provio ui web console"),
        "{resp}"
    );
    assert_eq!(resp["location"], "provio.yaml:5");
    // complete on the denied ref is refused: nothing ran.
    gw.send(&json!({"v": 1, "id": "c1", "op": "complete", "ref": resp["ref"], "ok": true}));
    assert_eq!(gw.recv()["error"]["code"], "invalid_state");
    assert_eq!(ledger_records(&l).len(), 1);
    // A second answer for the same ask is refused.
    let r = c.post(
        "/api/pending/decide",
        &json!({"id": item["id"], "approve": true}),
    );
    assert_eq!(r.status, 404);
}

#[test]
fn timeout_is_a_denial() {
    let l = Layout::new(POLICY);
    let c = Console::start(&l);
    let mut gw = Gateway::start(&l, &l.state, &["--stdio", "--ask", "ui"]);
    let t0 = Instant::now();
    gw.send(&decide("t1", "quick thing"));
    let item = wait_pending(&c);
    assert_eq!(item["rule_id"], "quick-ask");
    let resp = gw.recv();
    let waited = t0.elapsed();
    assert_eq!(resp["decision"], "deny", "{resp}");
    assert_eq!(resp["dispatch"], false);
    assert!(
        resp["reason"].as_str().unwrap().contains("within 2000ms"),
        "{resp}"
    );
    assert!(
        waited >= Duration::from_millis(1900) && waited < Duration::from_secs(15),
        "{waited:?}"
    );
    // A late answer is refused.
    let r = c.post(
        "/api/pending/decide",
        &json!({"id": item["id"], "approve": true}),
    );
    assert!(
        r.status == 404 || r.status == 409,
        "{} {}",
        r.status,
        r.body
    );
}

#[test]
fn no_console_is_an_immediate_denial() {
    let l = Layout::new(POLICY);
    // No console for this state root.
    let empty = l.root.join("no-console-state");
    std::fs::create_dir_all(&empty).unwrap();
    let mut gw = Gateway::start(&l, &empty, &["--stdio", "--ask", "ui"]);
    let t0 = Instant::now();
    gw.send(&decide("n1", "deploy"));
    let resp = gw.recv();
    assert_eq!(resp["decision"], "deny", "{resp}");
    assert!(
        resp["reason"]
            .as_str()
            .unwrap()
            .contains("no `provio ui` console"),
        "{resp}"
    );
    assert!(t0.elapsed() < Duration::from_secs(10));
    // Allowed calls are unaffected by --ask ui.
    gw.send(&decide("n2", "ls"));
    let resp = gw.recv();
    assert_eq!(resp["decision"], "allow");
}

#[test]
fn a_forged_decision_next_to_the_ledger_does_not_approve() {
    let l = Layout::new(POLICY);
    let c = Console::start(&l);
    let mut gw = Gateway::start(&l, &l.state, &["--stdio", "--ask", "ui"]);
    gw.send(&decide("f1", "quick thing"));
    let item = wait_pending(&c);
    // An agent can write the ledger directory; answers there are ignored.
    let id = item["id"].as_str().unwrap();
    let forged =
        l.ws.join(".provio")
            .join("pending")
            .join(format!("{id}.decision.json"));
    std::fs::write(&forged, json!({"approved": true}).to_string()).unwrap();
    let dir = l.ws.join(".provio").join("decisions");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(format!("{id}.json")),
        json!({"v":1,"id":id,"approved":true,"approver":"web-console:agent"}).to_string(),
    )
    .unwrap();
    let resp = gw.recv();
    assert_eq!(resp["decision"], "deny", "{resp}");
    assert!(
        resp["reason"].as_str().unwrap().contains("within"),
        "timed out: {resp}"
    );
}

#[test]
fn claude_code_format_asks_the_console() {
    let l = Layout::new(POLICY);
    let c = Console::start(&l);
    let pre = json!({"hook_event_name": "PreToolUse", "session_id": "cc-1", "tool_use_id": "toolu_1",
        "tool_name": "Bash", "tool_input": {"command": "npm run deploy"}});
    let mut cmd = l.cmd(&l.state);
    cmd.args(["check", "--format", "claude-code", "--ask", "ui"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spawn(cmd);
    child
        .stdin
        .take()
        .unwrap()
        .write_all(pre.to_string().as_bytes())
        .unwrap();
    let item = wait_pending(&c);
    assert_eq!(item["format"], "claude-code");
    assert_eq!(item["agent"], "claude-code");
    c.post(
        "/api/pending/decide",
        &json!({"id": item["id"], "approve": true}),
    );
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecision"], "allow",
        "{v}"
    );

    let post = json!({"hook_event_name": "PostToolUse", "session_id": "cc-1", "tool_use_id": "toolu_1",
        "tool_name": "Bash", "tool_input": {"command": "npm run deploy"}, "tool_response": {"stdout": "ok"}});
    let mut cmd = l.cmd(&l.state);
    cmd.args(["check", "--format", "claude-code", "--ask", "ui"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spawn(cmd);
    child
        .stdin
        .take()
        .unwrap()
        .write_all(post.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let recs = ledger_records(&l);
    assert_eq!(recs[1]["kind"], "execution");
    assert!(
        recs[1]["approver"]["id"]
            .as_str()
            .unwrap()
            .starts_with("web-console:"),
        "{:?}",
        recs[1]
    );
}

/// Run one hook invocation of `format` with `--ask ui`, feeding `payload`.
fn hook_child(l: &Layout, format: &str, payload: &Value) -> std::process::Child {
    let mut cmd = l.cmd(&l.state);
    cmd.args(["check", "--format", format, "--ask", "ui"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spawn(cmd);
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    child
}

#[test]
fn gemini_format_asks_the_console() {
    let l = Layout::new(POLICY);
    let c = Console::start(&l);
    let pre = json!({"hook_event_name": "BeforeTool", "session_id": "gm-1", "cwd": "/w",
        "tool_name": "run_shell_command", "tool_input": {"command": "npm run deploy"}});
    let child = hook_child(&l, "gemini", &pre);
    let item = wait_pending(&c);
    assert_eq!(item["format"], "gemini");
    c.post(
        "/api/pending/decide",
        &json!({"id": item["id"], "approve": true}),
    );
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["decision"], "allow", "{v}");

    // The tool ran: the execution is recorded, approved by the console.
    let mut post = pre.clone();
    post["hook_event_name"] = json!("AfterTool");
    post["tool_response"] = json!({"llmContent": "deployed"});
    let out = hook_child(&l, "gemini", &post).wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let recs = ledger_records(&l);
    assert_eq!(recs[1]["kind"], "execution");
    assert!(
        recs[1]["approver"]["id"]
            .as_str()
            .unwrap()
            .starts_with("web-console:"),
        "{:?}",
        recs[1]
    );
}

#[test]
fn cursor_mcp_format_denied_in_the_console_blocks() {
    let policy = format!(
        "{POLICY}\n  - id: mcp-issue\n    when: server == \"github\" and tool == \"create_issue\"\n    verdict: ask\n    reason: \"Filing issues needs a human.\"\n    timeout: 30s\n"
    );
    let l = Layout::new(&policy);
    let c = Console::start(&l);
    let pre = json!({"hook_event_name": "beforeMCPExecution", "conversation_id": "cu-1",
        "generation_id": "g-1", "tool_name": "create_issue", "mcp_server_name": "github",
        "tool_input": "{\"title\":\"x\"}", "command": "npx -y @modelcontextprotocol/server-github"});
    let child = hook_child(&l, "cursor", &pre);
    let item = wait_pending(&c);
    assert_eq!(item["format"], "cursor");
    c.post(
        "/api/pending/decide",
        &json!({"id": item["id"], "approve": false}),
    );
    let out = child.wait_with_output().unwrap();
    // Cursor blocks on permission "deny"; provio exits 0 so no shell can turn
    // the answer into a non-blocking failure.
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["permission"], "deny", "{v}");
    let recs = ledger_records(&l);
    assert_eq!(
        recs.len(),
        1,
        "a denied ask is one decision and no execution"
    );
}
