//! Sandbox screen: run one command inside the `local-os` kernel boundary
//! (prepare → exec → collect → teardown) in a throwaway workspace, after
//! the policy has decided it and the decision is on the ledger.
//!
//! Remote code execution by design, so every run is:
//! - token-gated (the HTTP layer),
//! - policy-checked and recorded (`handle_call`: one Decision record; an
//!   `ask` needs the console user's explicit confirmation, recorded as the
//!   `web-console:<user>` approver; one Execution record after the run),
//! - boundary-enforced: `LocalOsBackend::new()` is fail closed
//!   (`EnforcementMode::Required`); when this kernel cannot enforce both the
//!   write boundary and deny-all network, the screen refuses before anything
//!   is recorded or run. There is no unconfined or best-effort path here.

use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use provio_core::approver::{
    ApprovalDecision, ApprovalOutcome, Approver, ApproverIdentity, ApproverKind, AskView,
};
use provio_core::call::{CallerIdentity, InterceptMode, ToolCall};
use provio_core::ledger::LedgerWriter;
use provio_core::pipeline::handle_call;
use provio_core::sandbox::{ExecRequest, SandboxBackend, SandboxSpec};
use provio_core::verdict::Verdict;
use provio_core::{PolicyEngine, Timestamp, ToolCallContext};
use provio_sandbox::{EnforcementReport, Level, LocalOsBackend, Support};
use serde_json::{json, Value};

use super::approvals::console_approver;
use super::http::Response;
use super::policy::{describe_verdict, engine_for};
use super::Console;

/// Wall-clock limit for one sandboxed command.
const EXEC_TIMEOUT_MS: u64 = 20_000;
/// Output shown in the console (the ledger hashes all of it).
const MAX_SHOWN: usize = 64 * 1024;
/// Agent name recorded for sandbox-screen calls.
pub(crate) const SANDBOX_AGENT: &str = "provio-ui-sandbox";

fn support(s: &Support) -> Value {
    match s {
        Support::Full => json!({"level": "enforced"}),
        Support::Partial(w) => json!({"level": "partial", "detail": w}),
        Support::Unavailable(w) => json!({"level": "not-enforced", "detail": w}),
    }
}

fn level(l: Level) -> &'static str {
    match l {
        Level::Enforced => "enforced",
        Level::Partial => "partial",
        Level::NotEnforced => "not-enforced",
    }
}

/// What this machine's kernel boundary can enforce.
pub(crate) fn status() -> Value {
    let kh = provio_sandbox::kernel_hardening();
    json!({
        "available": kh.enforced,
        "platform": kh.platform,
        "mechanism": kh.mechanism,
        "filesystem": support(&kh.filesystem),
        "network": support(&kh.network),
        "notes": kh.notes,
        "shell": if cfg!(windows) { "cmd.exe (the command runs as a batch script)" } else { "/bin/sh -c" },
    })
}

fn report_json(r: &EnforcementReport) -> Value {
    json!({
        "filesystem_writes": level(r.filesystem_writes),
        "network_egress": level(r.network_egress),
        "mechanism": r.mechanism,
        "notes": r.notes,
        "fully_enforced": r.fully_enforced(),
        "mode": format!("{:?}", r.mode),
    })
}

/// Records the console user's explicit confirmation of an `ask`.
struct ConsoleApprover;

impl Approver for ConsoleApprover {
    fn request(&self, _call: &ToolCall, _ask: &AskView) -> provio_core::Result<ApprovalOutcome> {
        Ok(ApprovalOutcome {
            decision: ApprovalDecision::AllowOnce,
            approver: ApproverIdentity {
                kind: ApproverKind::Tui,
                id: console_approver(),
            },
            waited_ms: 0,
        })
    }
}

static SEQ: AtomicU64 = AtomicU64::new(0);
static WS_SEQ: AtomicU64 = AtomicU64::new(0);

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// A throwaway workspace, removed on drop.
struct Workspace(PathBuf);

impl Workspace {
    fn create() -> std::io::Result<Self> {
        let p = std::env::temp_dir().join(format!(
            "provio-ui-sbx-{}-{}-{}",
            std::process::id(),
            Timestamp::now().epoch_ms(),
            WS_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p)?;
        Ok(Workspace(p))
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One of the built-in "try to escape" demos.
struct Demo {
    command: String,
    /// Setup inside the workspace before the run (Windows: copy the probe).
    copy_probe: bool,
    check: DemoCheck,
}

enum DemoCheck {
    FileMustNotExist(PathBuf),
    NoConnection(TcpListener),
    None,
}

fn home() -> PathBuf {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(std::env::temp_dir)
}

fn probe_invocation(exe: &Path, op: &str, arg: &str) -> String {
    if cfg!(windows) {
        // The AppContainer can only execute images it can read: a copy of
        // provio in the workspace, resolved from the working directory.
        format!("provio-probe.exe ui --probe {op} --probe-arg {arg}")
    } else {
        format!(
            "{} ui --probe {op} --probe-arg {}",
            sh_quote(&exe.display().to_string()),
            sh_quote(arg)
        )
    }
}

fn demo(name: &str, exe: &Path) -> Result<Demo, String> {
    match name {
        "write-outside" => {
            let target = home().join(format!("provio-sandbox-escape-{}.txt", std::process::id()));
            let t = target.display().to_string();
            let command = if cfg!(windows) {
                format!("echo escaped> \"{t}\"")
            } else {
                format!("echo escaped > {}", sh_quote(&t))
            };
            Ok(Demo {
                command,
                copy_probe: false,
                check: DemoCheck::FileMustNotExist(target),
            })
        }
        "network" => {
            // A loopback listener owned by the console: no external traffic,
            // and proof of whether anything reached it.
            let l = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
            l.set_nonblocking(true).map_err(|e| e.to_string())?;
            let addr = l.local_addr().map_err(|e| e.to_string())?.to_string();
            Ok(Demo {
                command: probe_invocation(exe, "tcp", &addr),
                copy_probe: cfg!(windows),
                check: DemoCheck::NoConnection(l),
            })
        }
        "list" => Ok(Demo {
            // `dir` itself is denied inside an AppContainer (it reads
            // outside the workspace); `for` lists without that.
            command: if cfg!(windows) {
                "cd\nfor /d %%d in (*) do @echo [dir]  %%d\nfor %%f in (*) do @echo %%~zf bytes  %%f"
                    .into()
            } else {
                "pwd && ls -la".into()
            },
            copy_probe: false,
            check: DemoCheck::None,
        }),
        other => Err(format!("unknown demo {other:?}")),
    }
}

fn shown(bytes: &[u8]) -> (String, bool) {
    let cut = bytes.len() > MAX_SHOWN;
    let s = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_SHOWN)]).into_owned();
    (s, cut)
}

fn mask(text: &str, patterns: &[String]) -> Result<String, String> {
    let mut out = text.to_string();
    for p in patterns {
        let re = regex::Regex::new(p)
            .map_err(|e| format!("redact pattern {p:?} does not compile ({e}); output withheld"))?;
        out = re.replace_all(&out, "[redacted-by-provio]").into_owned();
    }
    Ok(out)
}

/// `POST /api/sandbox/run` — `{command}` or `{demo}`, plus `approve` to
/// confirm an `ask`.
pub(crate) fn run(c: &Console, body: &Value) -> Response {
    let approve = body.get("approve").and_then(Value::as_bool) == Some(true);
    let exe = c.provio_exe.clone();
    let demo = match body.get("demo").and_then(Value::as_str) {
        Some(d) => match demo(d, &exe) {
            Ok(d) => Some(d),
            Err(e) => return Response::error(400, "bad_request", &e),
        },
        None => None,
    };
    let command = match (&demo, body.get("command").and_then(Value::as_str)) {
        (Some(d), _) => d.command.clone(),
        (None, Some(cmd)) if !cmd.trim().is_empty() && cmd.len() <= 8192 => cmd.to_string(),
        _ => {
            return Response::error(
                400,
                "bad_request",
                "send a non-empty \"command\" (at most 8 KiB)",
            )
        }
    };
    if command.contains('\0') {
        return Response::error(400, "bad_request", "command contains NUL");
    }

    // 1. The boundary must be fully enforceable, or nothing happens.
    let st = status();
    if st["available"] != json!(true) {
        return Response::ok(json!({
            "stage": "refused",
            "command": command,
            "message": "The kernel boundary is not fully available on this machine, so the \
                        sandbox refuses to run anything (it never runs outside the boundary).",
            "sandbox": st,
        }));
    }

    // 2. Policy. An ask is shown first and only runs on explicit confirmation.
    let source = match std::fs::read_to_string(&c.policy) {
        Ok(s) => s,
        Err(e) => {
            return Response::error(
                409,
                "policy_error",
                &format!("cannot read {}: {e} (fail closed)", c.policy.display()),
            )
        }
    };
    let engine = match engine_for(&source, c.yolo) {
        Ok(e) => e,
        Err(e) => return Response::error(409, "policy_error", &format!("{e} (fail closed)")),
    };
    let call = ToolCall {
        call_id: format!(
            "{}-{}",
            c.sandbox_session,
            SEQ.fetch_add(1, Ordering::Relaxed)
        ),
        session_id: c.sandbox_session.clone(),
        caller: CallerIdentity {
            agent: SANDBOX_AGENT.into(),
            agent_version: Some(env!("CARGO_PKG_VERSION").into()),
            user: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .ok(),
            non_human_id: None,
        },
        mode: InterceptMode::ProcessWrap,
        tool: "bash".into(),
        args: json!({ "command": command }),
        server: None,
        trust: None,
        captured_at: Timestamp::now(),
    };
    let preview = engine.evaluate(&ToolCallContext::from_call(&call));
    if matches!(preview, Verdict::Ask { .. }) && !approve {
        return Response::ok(json!({
            "stage": "needs_approval",
            "command": command,
            "verdict": describe_verdict(&preview, &source),
            "recorded": false,
        }));
    }

    let _one_at_a_time = match c.sandbox_lock.try_lock() {
        Ok(g) => g,
        Err(_) => return Response::error(409, "busy", "another sandbox run is in progress"),
    };

    // 3. Record the decision (the pipeline, exactly as every interceptor).
    let mut store = match provio_ledger::open_store(&c.ledger) {
        Ok(s) => s,
        Err(e) => return Response::error(500, "ledger_error", &e.to_string()),
    };
    let outcome = match provio_ledger::retry_append(|| {
        let mut w = LedgerWriter::new(&mut *store);
        handle_call(&call, &engine, &mut w, &ConsoleApprover)
    }) {
        Ok(o) => o,
        Err(e) => return Response::error(500, "ledger_error", &e.to_string()),
    };
    crate::cmds::emit_span(&c.ledger, &call, &outcome.verdict);
    let verdict = describe_verdict(&outcome.record.verdict.clone().unwrap_or(preview), &source);
    if !outcome.should_dispatch() {
        return Response::ok(json!({
            "stage": "blocked",
            "command": command,
            "verdict": verdict,
            "decision_index": outcome.record.index,
            "recorded": true,
        }));
    }
    let patterns = match &outcome.verdict {
        Verdict::Redact { patterns, .. } => patterns.clone(),
        _ => Vec::new(),
    };

    // 4. Run inside the boundary.
    let ws = match Workspace::create() {
        Ok(w) => w,
        Err(e) => return Response::error(500, "io", &format!("create workspace: {e}")),
    };
    let (exit, stdout, stderr, duration, report, err) = execute(
        &ws,
        &command,
        demo.as_ref().is_some_and(|d| d.copy_probe),
        &exe,
    );
    let mut all = stdout.clone();
    all.extend_from_slice(&stderr);
    let exec_rec = provio_ledger::retry_append(|| {
        LedgerWriter::new(&mut *store).record_execution(
            &outcome.record,
            "local-os",
            exit.unwrap_or(-1),
            &all,
        )
    });

    // 5. What the boundary did, checked from outside.
    let escape = demo.map(|d| match d.check {
        DemoCheck::FileMustNotExist(p) => {
            let exists = p.exists();
            if exists {
                let _ = std::fs::remove_file(&p);
            }
            json!({"kind": "write-outside", "target": p.display().to_string(),
                   "escaped": exists})
        }
        DemoCheck::NoConnection(l) => {
            std::thread::sleep(Duration::from_millis(50));
            let reached = l.accept().is_ok();
            json!({"kind": "network", "target": l.local_addr().map(|a| a.to_string()).unwrap_or_default(),
                   "escaped": reached})
        }
        DemoCheck::None => json!({"kind": "list", "escaped": false}),
    });

    let (mut out_s, out_cut) = shown(&stdout);
    let (mut err_s, err_cut) = shown(&stderr);
    if !patterns.is_empty() {
        match (mask(&out_s, &patterns), mask(&err_s, &patterns)) {
            (Ok(a), Ok(b)) => {
                out_s = a;
                err_s = b;
            }
            (Err(e), _) | (_, Err(e)) => {
                out_s = format!("[output withheld: {e}]");
                err_s = String::new();
            }
        }
    }
    Response::ok(json!({
        "stage": if err.is_some() { "error" } else { "ran" },
        "command": command,
        "verdict": verdict,
        "decision_index": outcome.record.index,
        "execution_index": exec_rec.as_ref().ok().map(|r| r.index),
        "ledger_error": exec_rec.err().map(|e| e.to_string()),
        "approver": outcome.approval.map(|a| a.approver),
        "exit_code": exit,
        "stdout": out_s,
        "stderr": err_s,
        "truncated": out_cut || err_cut,
        "duration_ms": duration,
        "error": err,
        "report": report,
        "escape": escape,
        "workspace": ws.0.display().to_string(),
        "redacted": !patterns.is_empty(),
        "recorded": true,
    }))
}

type ExecResult = (Option<i32>, Vec<u8>, Vec<u8>, u64, Value, Option<String>);

fn execute(ws: &Workspace, command: &str, copy_probe: bool, exe: &Path) -> ExecResult {
    let fail = |e: String| (None, Vec::new(), Vec::new(), 0, Value::Null, Some(e));
    let mut b = LocalOsBackend::new();
    let spec = SandboxSpec {
        workspace: ws.0.clone(),
        allowed_hosts: Vec::new(),
        env: Default::default(),
    };
    let id = match b.prepare(&spec) {
        Ok(id) => id,
        Err(e) => return fail(e.to_string()),
    };
    let report = b.enforcement(&id).map(report_json).unwrap_or(Value::Null);
    if copy_probe {
        if let Err(e) = std::fs::copy(exe, ws.0.join("provio-probe.exe")) {
            let _ = b.teardown(id);
            return fail(format!("copy the probe into the workspace: {e}"));
        }
    }
    let req = if cfg!(windows) {
        let script = ws.0.join("provio-sandbox.cmd");
        let body = format!("@echo off\r\n{}\r\n", command.replace('\n', "\r\n"));
        if let Err(e) =
            std::fs::File::create(&script).and_then(|mut f| f.write_all(body.as_bytes()))
        {
            let _ = b.teardown(id);
            return fail(format!("write the batch script: {e}"));
        }
        ExecRequest {
            program: "cmd".into(),
            // Relative to the working directory (the workspace): an
            // AppContainer cannot traverse the absolute path from the root.
            args: vec!["/d".into(), "/c".into(), "provio-sandbox.cmd".into()],
            cwd: None,
            env: Default::default(),
            timeout_ms: Some(EXEC_TIMEOUT_MS),
        }
    } else {
        ExecRequest {
            program: "sh".into(),
            args: vec!["-c".into(), command.to_string()],
            cwd: None,
            env: Default::default(),
            timeout_ms: Some(EXEC_TIMEOUT_MS),
        }
    };
    let out = b.exec(&id, &req);
    let _ = b.collect(&id);
    let _ = b.teardown(id);
    match out {
        Ok(o) => (
            Some(o.exit_code),
            o.stdout,
            o.stderr,
            o.duration_ms,
            report,
            None,
        ),
        Err(e) => (None, Vec::new(), Vec::new(), 0, report, Some(e.to_string())),
    }
}

/// `provio ui --probe <op> --probe-arg <arg>`: one raw syscall-level attempt,
/// run by the sandbox demos inside the boundary. Prints the exact OS error.
pub(crate) fn probe(op: &str, arg: &str) -> i32 {
    let r: std::io::Result<()> = match op {
        "tcp" => arg
            .parse()
            .map_err(std::io::Error::other)
            .and_then(|a| TcpStream::connect_timeout(&a, Duration::from_secs(3)).map(|_| ())),
        "write" => std::fs::File::create(arg).and_then(|mut f| f.write_all(b"escaped")),
        other => Err(std::io::Error::other(format!("unknown probe {other}"))),
    };
    match r {
        Ok(()) => {
            println!("provio probe {op} {arg}: SUCCEEDED (the boundary did not block it)");
            0
        }
        Err(e) => {
            match e.raw_os_error() {
                // std's message already ends in "(os error N)".
                Some(_) => println!("provio probe {op} {arg}: blocked: {e}"),
                // Windows' AppContainer filter drops the packets: the
                // connect never completes, so there is no error code.
                None => println!(
                    "provio probe {op} {arg}: blocked: {e} (no OS error code: nothing answered, the \
                     packets were dropped)"
                ),
            }
            1
        }
    }
}
