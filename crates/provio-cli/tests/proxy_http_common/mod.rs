//! Shared harness for `provio proxy --transport http` tests: a scratch
//! project, an in-process fake upstream MCP server (Streamable HTTP, JSON
//! and SSE replies, sessions, GET stream, DELETE), the `provio` binary as the
//! proxy, and a ureq-based fake agent.
#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use provio_mcp::http::server::{self, Limits, Request, Responder, ShutdownHandle};
use provio_mcp::http::sse::{SseEvent, SseReader};
use serde_json::{json, Value};

pub const SSN: &str = "123-45-6789";
pub const SESSION: &str = "sess-cli-42";

pub const POLICY: &str = r#"version: 1
default: ask
rules:
  - id: echo-ok
    when: tool == "echo"
    verdict: allow
  - id: no-drop
    when: tool == "db.drop"
    verdict: deny
    reason: "Dropping tables is irreversible."
  - id: deploy
    when: tool == "deploy"
    verdict: ask
    reason: "Deploys need a human."
  - id: pii
    when: tool == "lookup"
    verdict: redact
    patterns:
      - "\\b\\d{3}-\\d{2}-\\d{4}\\b"
  - id: pii-sse
    when: tool == "lookup_sse"
    verdict: redact
    patterns:
      - "\\b\\d{3}-\\d{2}-\\d{4}\\b"
  - id: broken-redact
    when: tool == "broken"
    verdict: redact
    patterns:
      - "(unclosed"
"#;

pub struct Project(pub PathBuf);

impl Project {
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("provio-proxy-http-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("provio.yaml"), POLICY).unwrap();
        Project(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn records(&self) -> Vec<Value> {
        match std::fs::read_to_string(self.0.join(".provio").join("ledger.jsonl")) {
            Ok(s) => s
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| serde_json::from_str(l).unwrap())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn decisions_for(&self, tool: &str) -> Vec<Value> {
        self.records()
            .into_iter()
            .filter(|r| r["kind"] == "decision" && r["call"]["tool"] == tool)
            .collect()
    }

    pub fn executions_for(&self, call_id: &str) -> Vec<Value> {
        self.records()
            .into_iter()
            .filter(|r| r["kind"] == "execution" && r["call_id"] == call_id)
            .collect()
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Value,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub type Log = Arc<Mutex<Vec<Seen>>>;

/// The upstream's tools/call result for `name` (what the ledger hashes).
pub fn tool_result(name: &str) -> Value {
    json!({"content": [{"type": "text", "text": format!("{name}: customer SSN {SSN}")}]})
}

fn json_reply(resp: Responder<'_>, extra: &[(&str, &str)], v: &Value) -> std::io::Result<()> {
    let mut h = vec![("Content-Type".to_string(), "application/json".to_string())];
    h.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    resp.send(200, &h, v.to_string().as_bytes())
}

fn sse_reply(resp: Responder<'_>, data: &[Value]) -> std::io::Result<()> {
    let mut body = resp.stream(200, &[("Content-Type".into(), "text/event-stream".into())])?;
    body.write(
        &SseEvent {
            id: Some("e-0".into()),
            ..Default::default()
        }
        .encode(),
    )?;
    for (i, d) in data.iter().enumerate() {
        body.write(
            &SseEvent {
                id: Some(format!("e-{}", i + 1)),
                data: d.to_string(),
                ..Default::default()
            }
            .encode(),
        )?;
    }
    body.finish()
}

pub struct Upstream {
    pub url: String,
    pub log: Log,
    _stop: StopOnDrop,
}

struct StopOnDrop(ShutdownHandle);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

impl Upstream {
    pub fn tool_calls(&self) -> Vec<Seen> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.body["method"] == "tools/call")
            .cloned()
            .collect()
    }
}

/// Streamable HTTP MCP server, 2025-11-25 shape.
pub fn fake_upstream() -> Upstream {
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let log2 = Arc::clone(&log);
    let handler = move |req: &Request, resp: Responder<'_>| -> std::io::Result<()> {
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        log2.lock().unwrap().push(Seen {
            method: req.method.clone(),
            headers: req.headers.clone(),
            body: body.clone(),
        });
        let has_session = req.header("mcp-session-id") == Some(SESSION);
        match req.method.as_str() {
            "GET" if has_session => sse_reply(
                resp,
                &[json!({"jsonrpc":"2.0","method":"notifications/resources/list_changed"})],
            ),
            "DELETE" if has_session => resp.send(200, &[], b""),
            "POST" => {
                let method = body["method"].as_str().unwrap_or("");
                let Some(id) = body.get("id").cloned() else {
                    return resp.send(202, &[], b"");
                };
                if body.get("method").is_none() {
                    return resp.send(202, &[], b"");
                }
                if method == "initialize" {
                    return json_reply(
                        resp,
                        &[("Mcp-Session-Id", SESSION)],
                        &json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"2025-11-25",
                            "capabilities":{"tools":{}},"serverInfo":{"name":"fake","version":"0"}}}),
                    );
                }
                if !has_session {
                    return resp.send(400, &[], b"missing session");
                }
                if method == "tools/call" {
                    let name = body["params"]["name"].as_str().unwrap_or("");
                    let r = json!({"jsonrpc":"2.0","id":id,"result":tool_result(name)});
                    if name.ends_with("_sse") {
                        let note = json!({"jsonrpc":"2.0","method":"notifications/message",
                            "params":{"level":"info","data":format!("working on {SSN}")}});
                        return sse_reply(resp, &[note, r]);
                    }
                    return json_reply(resp, &[], &r);
                }
                json_reply(
                    resp,
                    &[],
                    &json!({"jsonrpc":"2.0","id":id,"result":{"tools":[]}}),
                )
            }
            _ => resp.send(405, &[], b""),
        }
    };
    let (addr, stop) = server::spawn("127.0.0.1:0", Limits::default(), Arc::new(handler)).unwrap();
    Upstream {
        url: format!("http://{addr}/mcp"),
        log,
        _stop: StopOnDrop(stop),
    }
}

/// A running `provio proxy --transport http`.
pub struct ProvioProxy {
    pub url: String,
    child: Child,
    pub stderr: Arc<Mutex<String>>,
}

impl Drop for ProvioProxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_provio(project: &Project, args: &[&str], env: &[(&str, &str)]) -> Child {
    let mut attempt = 0;
    loop {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_provio"));
        cmd.args(args)
            .current_dir(project.path())
            .env("RUST_LOG", "debug")
            .env_remove("PROVIO_PROXY_TOKEN")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in env {
            cmd.env(k, v);
        }
        match cmd.spawn() {
            Ok(c) => return c,
            Err(e) if e.raw_os_error() == Some(4551) && attempt < 10 => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(300));
            }
            Err(e) => panic!("spawn provio: {e}"),
        }
    }
}

/// Start the proxy in front of `upstream_url`; waits for the listening line.
pub fn start_provio(
    project: &Project,
    upstream_url: &str,
    extra: &[&str],
    env: &[(&str, &str)],
) -> ProvioProxy {
    let mut args = vec![
        "proxy",
        "--mcp",
        "--server",
        "fake",
        "--transport",
        "http",
        "--listen",
        "127.0.0.1:0",
        "--upstream",
        upstream_url,
    ];
    args.extend_from_slice(extra);
    let mut child = spawn_provio(project, &args, env);
    let stderr = child.stderr.take().unwrap();
    let log = Arc::new(Mutex::new(String::new()));
    let log2 = Arc::clone(&log);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut tx = Some(tx);
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            if let Some(url) = line.trim().strip_prefix("listening: ") {
                if let Some(tx) = tx.take() {
                    let _ = tx.send(url.to_string());
                }
            }
            let mut l = log2.lock().unwrap();
            l.push_str(&line);
            l.push('\n');
        }
    });
    let url = match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(u) => u,
        Err(_) => {
            let _ = child.kill();
            panic!("provio proxy did not start: {}", log.lock().unwrap());
        }
    };
    ProvioProxy {
        url,
        child,
        stderr: log,
    }
}

/// Run `provio <args>` to completion (for argument-validation tests).
pub fn run_provio(project: &Project, args: &[&str], env: &[(&str, &str)]) -> (i32, String) {
    let child = spawn_provio(project, args, env);
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Resp {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|_| panic!("not JSON: {:?}", self.body))
    }
    pub fn events(&self) -> Vec<SseEvent> {
        SseReader::new(self.body.as_bytes(), 1 << 20)
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap()
    }
}

pub fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into()
}

pub fn finish(r: ureq::http::Response<ureq::Body>) -> Resp {
    let status = r.status().as_u16();
    let headers = r
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = r.into_body().read_to_string().unwrap_or_default();
    Resp {
        status,
        headers,
        body,
    }
}

pub fn post(url: &str, headers: &[(&str, &str)], body: &Value) -> Resp {
    let mut rb = agent()
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");
    for (k, v) in headers {
        rb = rb.header(*k, *v);
    }
    finish(rb.send(body.to_string()).unwrap())
}

pub fn session() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Mcp-Session-Id", SESSION),
        ("MCP-Protocol-Version", "2025-11-25"),
    ]
}

pub fn call(id: u64, tool: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
           "params":{"name":tool,"arguments":{"q":"customers"}}})
}

/// initialize + notifications/initialized; returns the relayed session id.
pub fn handshake(url: &str) -> String {
    let r = post(
        url,
        &[],
        &json!({"jsonrpc":"2.0","id":0,"method":"initialize",
                "params":{"protocolVersion":"2025-11-25","capabilities":{},
                          "clientInfo":{"name":"test","version":"0"}}}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let sid = r.header("mcp-session-id").expect("session id").to_string();
    let n = post(
        url,
        &session(),
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    assert_eq!(n.status, 202);
    sid
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    provio_core::ledger::LedgerRecord::hash_bytes(bytes)
}
