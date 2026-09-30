//! `provio ui`: request security, the live feed, verify, the policy screen and
//! the sandbox screen, exercised through the HTTP API of a real console.

mod ui_common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Stdio;
use std::time::Duration;

use serde_json::json;
use ui_common::*;

fn record_some_decisions(l: &Layout) {
    for (i, cmd) in ["ls -la", "rm -rf /tmp/x", "cat README.md"]
        .iter()
        .enumerate()
    {
        let mut c = l.cmd(&l.state);
        c.arg("check")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = spawn(c);
        let req = decide(&format!("r{i}"), cmd);
        child
            .stdin
            .take()
            .unwrap()
            .write_all(req.to_string().as_bytes())
            .unwrap();
        let _ = child.wait_with_output().unwrap();
    }
}

#[test]
fn requests_without_the_token_or_from_elsewhere_are_refused() {
    let l = Layout::new(POLICY);
    let c = Console::start(&l);
    let host = c.host();

    // The static page needs no token but carries the security headers.
    let r = http(c.port, "GET", "/", &[("Host", &host)], None);
    assert_eq!(r.status, 200);
    let csp = r.header("content-security-policy").expect("CSP");
    assert!(
        csp.contains("default-src 'none'") && csp.contains("script-src 'self'"),
        "{csp}"
    );
    assert!(
        !csp.contains("unsafe-inline") && !csp.contains("http"),
        "{csp}"
    );
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(r.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(r.header("x-frame-options"), Some("DENY"));
    assert!(r.body.contains("/app.js") && !r.body.contains("<script>"));

    // API: no token, wrong token.
    let r = http(c.port, "GET", "/api/info", &[("Host", &host)], None);
    assert_eq!(r.status, 401, "{}", r.body);
    let wrong = "0".repeat(64);
    let r = http(
        c.port,
        "GET",
        "/api/info",
        &[("Host", &host), ("X-Provio-Token", &wrong)],
        None,
    );
    assert_eq!(r.status, 401);
    let short = &c.token[..10];
    let r = http(
        c.port,
        "GET",
        "/api/info",
        &[("Host", &host), ("X-Provio-Token", short)],
        None,
    );
    assert_eq!(r.status, 401);

    // DNS rebinding: a foreign Host with the right token.
    for bad in [
        "evil.example",
        "evil.example:80",
        "127.0.0.1",
        "127.0.0.1:1",
    ] {
        let r = http(
            c.port,
            "GET",
            "/api/info",
            &[("Host", bad), ("X-Provio-Token", &c.token)],
            None,
        );
        assert_eq!(r.status, 421, "host {bad}: {}", r.body);
    }
    let r = http(
        c.port,
        "GET",
        "/api/info",
        &[("X-Provio-Token", &c.token)],
        None,
    );
    assert_eq!(r.status, 421, "missing Host");

    // Cross-origin.
    let r = http(
        c.port,
        "GET",
        "/api/info",
        &[
            ("Host", &host),
            ("X-Provio-Token", &c.token),
            ("Origin", "http://evil.example"),
        ],
        None,
    );
    assert_eq!(r.status, 403);
    let own = format!("http://{host}");
    let r = http(
        c.port,
        "GET",
        "/api/info",
        &[
            ("Host", &host),
            ("X-Provio-Token", &c.token),
            ("Origin", &own),
        ],
        None,
    );
    assert_eq!(r.status, 200, "own origin is fine: {}", r.body);
    let r = http(
        c.port,
        "GET",
        "/api/info",
        &[
            ("Host", &host),
            ("X-Provio-Token", &c.token),
            ("Sec-Fetch-Site", "cross-site"),
        ],
        None,
    );
    assert_eq!(r.status, 403);

    // localhost:<port> is the same console.
    let lh = format!("localhost:{}", c.port);
    let r = http(
        c.port,
        "GET",
        "/api/info",
        &[("Host", &lh), ("X-Provio-Token", &c.token)],
        None,
    );
    assert_eq!(r.status, 200);

    // State changes: POST + JSON only.
    let r = http(
        c.port,
        "POST",
        "/api/policy/save",
        &[
            ("Host", &host),
            ("X-Provio-Token", &c.token),
            ("Content-Type", "text/plain"),
        ],
        Some("{\"source\":\"x\"}"),
    );
    assert_eq!(r.status, 415);
    let r = c.get("/api/policy/save");
    assert_eq!(r.status, 405);
    let r = http(
        c.port,
        "POST",
        "/api/sandbox/run",
        &[("Host", &host), ("Content-Type", "application/json")],
        Some("{\"command\":\"echo hi\"}"),
    );
    assert_eq!(r.status, 401, "sandbox without token");

    // A chunked body is refused, not guessed at.
    let r = http(
        c.port,
        "POST",
        "/api/policy/validate",
        &[
            ("Host", &host),
            ("X-Provio-Token", &c.token),
            ("Content-Type", "application/json"),
            ("Transfer-Encoding", "chunked"),
        ],
        None,
    );
    assert_eq!(r.status, 501);

    // The good path.
    let r = c.get("/api/info");
    assert_eq!(r.status, 200);
    assert!(r.header("content-security-policy").is_some());
    let info = r.json();
    assert_eq!(info["policy"], json!(l.policy.display().to_string()));
    assert!(info["approver"]
        .as_str()
        .unwrap()
        .starts_with("web-console:"));
}

#[test]
fn live_feed_record_detail_stream_and_verify() {
    let l = Layout::new(POLICY);
    record_some_decisions(&l);
    let c = Console::start(&l);

    let d = c.get("/api/decisions").json();
    let items = d["items"].as_array().unwrap();
    assert_eq!(items.len(), 3, "{d}");
    // Newest first.
    assert_eq!(items[0]["summary"], "cat README.md");
    assert_eq!(items[0]["verdict"], "allow");
    assert_eq!(items[1]["verdict"], "deny");
    assert_eq!(items[1]["rule_id"], "no-rm");
    assert_eq!(items[1]["outcome"], "blocked");
    assert!(items[1]["location"]
        .as_str()
        .unwrap()
        .starts_with("provio.yaml:"));

    let idx = items[1]["index"].as_u64().unwrap();
    let r = c.get(&format!("/api/record?index={idx}")).json();
    assert_eq!(r["decision"]["call"]["args"]["command"], "rm -rf /tmp/x");
    let line = r["rule_line"].as_u64().unwrap();
    let src_line = POLICY.lines().nth(line as usize - 1).unwrap();
    assert!(src_line.contains("id: no-rm"), "line {line}: {src_line}");
    assert_eq!(r["decision"]["record_hash"].as_str().unwrap().len(), 64);
    assert_eq!(c.get("/api/record?index=999").status, 404);

    let v = c.get("/api/verify").json();
    assert_eq!(v["intact"], true);
    assert_eq!(v["records"], 3);

    // The stream sends what is appended after the given index.
    let mut s = TcpStream::connect(("127.0.0.1", c.port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    write!(
        s,
        "GET /api/stream?after={} HTTP/1.1\r\nHost: {}\r\nX-Provio-Token: {}\r\n\r\n",
        items[0]["index"],
        c.host(),
        c.token
    )
    .unwrap();
    let mut c2 = l.cmd(&l.state);
    c2.arg("check")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = spawn(c2);
    child
        .stdin
        .take()
        .unwrap()
        .write_all(decide("s1", "echo streamed").to_string().as_bytes())
        .unwrap();
    let _ = child.wait_with_output().unwrap();
    let mut got = String::new();
    let mut buf = [0u8; 4096];
    while !got.contains("echo streamed") {
        let n = s.read(&mut buf).expect("stream read");
        assert!(n > 0, "stream closed early: {got}");
        got.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    assert!(got.starts_with("HTTP/1.1 200"));
    assert!(got.contains("text/event-stream"));
    assert!(got.contains("event: decisions"));
    assert!(
        !got.contains("cat README.md"),
        "only records after the cursor"
    );

    // Tamper with the ledger: verify names the record.
    let text = std::fs::read_to_string(&l.ledger).unwrap();
    std::fs::write(&l.ledger, text.replacen("ls -la", "ls -lb", 1)).unwrap();
    let v = c.get("/api/verify").json();
    assert_eq!(v["intact"], false);
    assert_eq!(v["broken_at"], 0);
}

#[test]
fn policy_validate_test_and_save() {
    let l = Layout::new(POLICY);
    let c = Console::start(&l);

    let p = c.get("/api/policy").json();
    assert_eq!(p["source"], POLICY);
    assert_eq!(p["validation"]["ok"], true);
    let sha = p["sha256"].as_str().unwrap().to_string();

    let bad = POLICY.replace(
        "verdict: deny\n    reason: \"Destructive.\"",
        "verdict: nope\n    reason: \"Destructive.\"",
    );
    let v = c
        .post("/api/policy/validate", &json!({"source": bad}))
        .json();
    assert_eq!(v["ok"], false, "{v}");
    assert!(v["error"].as_str().unwrap().contains("provio.yaml"), "{v}");
    let broken =
        "version: 1\ndefault: ask\nrules:\n  - id: x\n    when: tool == \n    verdict: deny\n";
    let v = c
        .post("/api/policy/validate", &json!({"source": broken}))
        .json();
    assert_eq!(v["ok"], false);
    assert!(v["line"].as_u64().is_some(), "error carries a line: {v}");

    // The tester: verdict, rule, line — and no ledger write.
    let r = c
        .post(
            "/api/policy/test",
            &json!({"tool": "bash", "args": {"command": "rm -rf /"}}),
        )
        .json();
    assert_eq!(r["result"]["verdict"], "deny", "{r}");
    assert_eq!(r["result"]["rule_id"], "no-rm");
    let line = r["result"]["line"].as_u64().unwrap() as usize;
    assert!(POLICY.lines().nth(line - 1).unwrap().contains("no-rm"));
    assert_eq!(r["recorded"], false);
    let r = c
        .post(
            "/api/policy/test",
            &json!({"tool": "postgres.query", "server": "pg", "args": {"query": "select 1"}}),
        )
        .json();
    assert_eq!(r["result"]["verdict"], "deny");
    assert_eq!(r["result"]["default"], true, "{r}");
    // Against an unsaved draft.
    let draft = POLICY.replace("default: deny", "default: allow");
    let r = c
        .post(
            "/api/policy/test",
            &json!({"source": draft, "tool": "http", "args": {"url": "https://x.example"}}),
        )
        .json();
    assert_eq!(r["result"]["verdict"], "allow");
    assert!(
        !l.ledger.exists() || ledger_records(&l).is_empty(),
        "the tester records nothing"
    );

    // Save: stale base, invalid source, then a good save with a .bak.
    let r = c.post(
        "/api/policy/save",
        &json!({"source": draft, "base_sha256": "00"}),
    );
    assert_eq!(r.status, 409);
    let r = c.post(
        "/api/policy/save",
        &json!({"source": bad, "base_sha256": sha}),
    );
    assert_eq!(r.status, 422);
    assert_eq!(std::fs::read_to_string(&l.policy).unwrap(), POLICY);
    let r = c.post(
        "/api/policy/save",
        &json!({"source": draft, "base_sha256": sha}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(std::fs::read_to_string(&l.policy).unwrap(), draft);
    let bak = l.ws.join("provio.yaml.bak");
    assert_eq!(std::fs::read_to_string(bak).unwrap(), POLICY);

    let packs = c.get("/api/packs").json();
    let on_disk = std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../../packs"))
        .unwrap()
        .flatten()
        .filter(|e| e.path().join("pack.yaml").is_file())
        .count();
    assert_eq!(packs["packs"].as_array().unwrap().len(), on_disk);
}

fn sandbox_available(c: &Console) -> bool {
    let st = c.get("/api/sandbox").json();
    if st["available"] == true {
        return true;
    }
    if std::env::var("PROVIO_SANDBOX_REQUIRE_ENFORCEMENT").as_deref() == Ok("1") {
        panic!("PROVIO_SANDBOX_REQUIRE_ENFORCEMENT=1 but the kernel boundary is unavailable: {st}");
    }
    eprintln!(
        "skipping: the kernel boundary is unavailable here ({})",
        st["notes"]
    );
    false
}

#[test]
fn sandbox_runs_inside_the_boundary_and_escapes_fail() {
    let l = Layout::new(POLICY);
    let c = Console::start(&l);
    if !sandbox_available(&c) {
        // The screen must refuse, never run unconfined.
        let r = c
            .post("/api/sandbox/run", &json!({"command": "echo hi"}))
            .json();
        assert_eq!(r["stage"], "refused", "{r}");
        return;
    }

    // Allowed by `shell-ok`: runs, recorded twice (decision + execution).
    let r = c.post("/api/sandbox/run", &json!({"demo": "list"})).json();
    assert_eq!(r["stage"], "ran", "{r}");
    assert_eq!(r["exit_code"], 0, "{r}");
    assert_eq!(r["report"]["filesystem_writes"], "enforced");
    assert_eq!(r["report"]["network_egress"], "enforced");
    assert!(
        r["stdout"].as_str().unwrap().contains("provio-ui-sbx"),
        "{r}"
    );
    let recs = ledger_records(&l);
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0]["call"]["caller"]["agent"], "provio-ui-sandbox");
    assert_eq!(recs[1]["kind"], "execution");
    assert_eq!(recs[1]["backend"], "local-os");

    // Escape 1: a write outside the workspace.
    let r = c
        .post("/api/sandbox/run", &json!({"demo": "write-outside"}))
        .json();
    assert_eq!(r["stage"], "ran", "{r}");
    assert_eq!(r["escape"]["escaped"], false, "{r}");
    let err = format!("{}{}", r["stderr"], r["stdout"]).to_lowercase();
    assert!(
        err.contains("access is denied")
            || err.contains("permission denied")
            || err.contains("operation not permitted"),
        "the OS error is shown: {r}"
    );
    assert_ne!(r["exit_code"], 0);

    // Escape 2: a network connection (to a loopback listener).
    let r = c
        .post("/api/sandbox/run", &json!({"demo": "network"}))
        .json();
    assert_eq!(r["stage"], "ran", "{r}");
    assert_eq!(r["escape"]["escaped"], false, "{r}");
    let out = r["stdout"].as_str().unwrap();
    assert!(
        out.contains("provio probe tcp") && out.contains("blocked"),
        "{r}"
    );
    assert!(!out.contains("SUCCEEDED"), "{r}");

    // The policy runs first: a denied command never starts.
    let before = ledger_records(&l).len();
    let r = c
        .post("/api/sandbox/run", &json!({"command": "rm -rf ./x"}))
        .json();
    assert_eq!(r["stage"], "blocked");
    assert_eq!(r["verdict"]["rule_id"], "no-rm");
    assert_eq!(
        ledger_records(&l).len(),
        before + 1,
        "one decision, no execution"
    );

    // An ask is shown first and recorded only once approved.
    let r = c
        .post("/api/sandbox/run", &json!({"command": "echo deploy"}))
        .json();
    assert_eq!(r["stage"], "needs_approval", "{r}");
    assert_eq!(r["recorded"], false);
    assert_eq!(ledger_records(&l).len(), before + 1);
    let r = c
        .post(
            "/api/sandbox/run",
            &json!({"command": "echo deploy", "approve": true}),
        )
        .json();
    assert_eq!(r["stage"], "ran", "{r}");
    assert!(r["approver"]["id"]
        .as_str()
        .unwrap()
        .starts_with("web-console:"));
    let recs = ledger_records(&l);
    let dec = &recs[recs.len() - 2];
    assert_eq!(dec["verdict"]["kind"], "ask");
    assert!(dec["approver"]["id"]
        .as_str()
        .unwrap()
        .starts_with("web-console:"));
}

#[test]
fn connect_screen_sees_the_first_tool_call() {
    let l = Layout::new(POLICY);
    let c = Console::start(&l);
    let k = c.get("/api/connect").json();
    assert!(k["cards"].as_object().unwrap().is_empty(), "{k}");
    record_some_decisions(&l);
    let k = c.get("/api/connect").json();
    let py = &k["cards"]["python"];
    assert_eq!(py["agent"], "langgraph", "{k}");
    assert_eq!(py["tool"], "bash");
    assert_eq!(py["since_start"], true);
}
