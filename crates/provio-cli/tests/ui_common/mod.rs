//! Shared helpers for the `provio ui` integration tests: temp layouts, a
//! running console, a raw HTTP/1.1 client, and `provio check` children.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;

pub const POLICY: &str = r#"version: 1
default: deny

rules:
  - id: needs-human
    when: tool == "bash" and command contains "deploy"
    verdict: ask
    reason: "Deploys need a human."
    timeout: 30s

  - id: quick-ask
    when: tool == "bash" and command contains "quick"
    verdict: ask
    reason: "Quick ask."
    timeout: 2s

  - id: no-rm
    when: tool == "bash" and command matches "rm -rf"
    verdict: deny
    reason: "Destructive."

  - id: shell-ok
    when: tool == "bash"
    verdict: allow
"#;

static SEQ: AtomicU64 = AtomicU64::new(0);

/// `<tmp>/provio-ui-test-<pid>-<n>/{ws,state}`: the workspace holds the
/// policy and the ledger; `state` is the console state root (outside it).
pub struct Layout {
    pub root: PathBuf,
    pub ws: PathBuf,
    pub state: PathBuf,
    pub policy: PathBuf,
    pub ledger: PathBuf,
}

impl Layout {
    pub fn new(policy: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "provio-ui-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let ws = root.join("ws");
        let state = root.join("state");
        std::fs::create_dir_all(ws.join(".provio")).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        let policy_path = ws.join("provio.yaml");
        std::fs::write(&policy_path, policy).unwrap();
        Layout {
            ledger: ws.join(".provio").join("ledger.jsonl"),
            policy: policy_path,
            root,
            ws,
            state,
        }
    }

    /// A command with this layout's cwd and console state root.
    pub fn cmd(&self, state: &Path) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_provio"));
        c.current_dir(&self.ws);
        if cfg!(windows) {
            c.env("LOCALAPPDATA", state);
        } else {
            c.env("XDG_STATE_HOME", state);
        }
        c.arg("--policy")
            .arg(&self.policy)
            .arg("--ledger")
            .arg(&self.ledger);
        c
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Windows Application Control intermittently blocks a fresh executable
/// (os error 4551); retry the spawn.
pub fn spawn(mut c: Command) -> Child {
    let mut last = None;
    for _ in 0..20 {
        match c.spawn() {
            Ok(ch) => return ch,
            Err(e) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(300));
            }
        }
    }
    panic!("spawn provio: {:?}", last);
}

pub struct Console {
    pub child: Child,
    pub port: u16,
    pub token: String,
}

impl Console {
    pub fn start(l: &Layout) -> Console {
        let mut c = l.cmd(&l.state);
        c.args(["ui", "--no-open", "--port", "0"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = spawn(c);
        let out = child.stdout.take().unwrap();
        let mut line = String::new();
        BufReader::new(out).read_line(&mut line).unwrap();
        // provio ui · http://127.0.0.1:PORT/#token=TOKEN
        let url = line.trim().rsplit(' ').next().unwrap().to_string();
        let rest = url.strip_prefix("http://127.0.0.1:").expect("loopback url");
        let (port, token) = rest.split_once("/#token=").expect("token in url");
        let con = Console {
            child,
            port: port.parse().unwrap(),
            token: token.to_string(),
        };
        // Wait for the heartbeat file (asks need it).
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if find_heartbeat(&l.state) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        con
    }

    pub fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    pub fn get(&self, path: &str) -> Resp {
        http(
            self.port,
            "GET",
            path,
            &[("Host", &self.host()), ("X-Provio-Token", &self.token)],
            None,
        )
    }

    pub fn post(&self, path: &str, body: &Value) -> Resp {
        http(
            self.port,
            "POST",
            path,
            &[
                ("Host", &self.host()),
                ("X-Provio-Token", &self.token),
                ("Content-Type", "application/json"),
            ],
            Some(&body.to_string()),
        )
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn find_heartbeat(dir: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return false;
    };
    rd.flatten().any(|e| {
        let p = e.path();
        if p.is_dir() {
            p.join("console.json").is_file() || find_heartbeat(&p)
        } else {
            false
        }
    })
}

pub struct Resp {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

impl Resp {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {} {}", self.status, self.body))
    }
    pub fn header(&self, k: &str) -> Option<&str> {
        self.headers
            .get(&k.to_ascii_lowercase())
            .map(String::as_str)
    }
}

/// One raw HTTP/1.1 request (the server always closes the connection).
pub fn http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Resp {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(b) = body {
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");
    if let Some(b) = body {
        req.push_str(b);
    }
    s.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    parse(&raw)
}

pub fn parse(raw: &[u8]) -> Resp {
    let text = String::from_utf8_lossy(raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Resp {
        status,
        headers,
        body: body.to_string(),
    }
}

/// A `provio check --stdio` child speaking Contract 6.
pub struct Gateway {
    pub child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Gateway {
    pub fn start(l: &Layout, state: &Path, extra: &[&str]) -> Gateway {
        let mut c = l.cmd(state);
        c.arg("check")
            .args(extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = spawn(c);
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Gateway {
            child,
            stdin,
            stdout,
        }
    }

    pub fn send(&mut self, v: &Value) {
        writeln!(self.stdin, "{v}").unwrap();
        self.stdin.flush().unwrap();
    }

    pub fn recv(&mut self) -> Value {
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("gateway line {line:?}: {e}"))
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn decide(id: &str, command: &str) -> Value {
    serde_json::json!({"v": 1, "id": id, "op": "decide", "call": {
        "session_id": "ui-test", "tool": "bash", "args": {"command": command},
        "caller": {"agent": "langgraph"}}})
}

/// Records in the JSONL ledger.
pub fn ledger_records(l: &Layout) -> Vec<Value> {
    std::fs::read_to_string(&l.ledger)
        .unwrap_or_default()
        .lines()
        .filter(|x| !x.trim().is_empty())
        .map(|x| serde_json::from_str(x).unwrap())
        .collect()
}

/// Poll `f` until it returns Some, or panic after `secs`.
pub fn wait_for<T>(secs: u64, what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(v) = f() {
            return v;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for {what}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
