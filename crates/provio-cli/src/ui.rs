//! `provio ui`: the local web console.
//!
//! Serves a single-page console on `127.0.0.1` (never another interface)
//! and opens the browser at `http://127.0.0.1:<port>/#token=<token>`. The
//! token (256 bits, fresh per run) travels in the URL fragment, which the
//! browser never sends to a server or puts in a `Referer`; the page keeps it
//! in `sessionStorage` and sends it as `X-Provio-Token` on every API request.
//! See [`http`] for every check a request passes, and `docs/ui.md`.
//!
//! Screens: Connect (per-agent snippets with this machine's paths, one-click
//! Claude Code hook setup, a live "first tool call" indicator), Live (the
//! ledger as a stream, record detail, `verify`), Approvals (`provio check
//! --ask ui`, see [`approvals`]), Policy (edit with live validation, a tool
//! call tester that records nothing, packs), Sandbox (a command inside the
//! `local-os` kernel boundary, policy-checked and recorded, plus escape
//! demos).
//!
//! No telemetry, no external requests; every asset is embedded.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use provio_core::ledger::RecordKind;
use provio_core::verdict::Verdict;
use provio_core::Timestamp;
use serde_json::{json, Value};

pub(crate) mod approvals;
mod http;
mod ledger;
mod policy;
mod sandbox;

use http::{Request, Response};
use ledger::{summary, LedgerView};

/// Flags for `provio ui`.
#[derive(Clone, Debug, clap::Args)]
pub struct UiArgs {
    /// Port on 127.0.0.1 (0 picks a free one).
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    /// Do not open a browser.
    #[arg(long)]
    pub no_open: bool,
    /// Internal: one syscall-level attempt (tcp, write) for the sandbox's
    /// escape demos; prints the exact OS error.
    #[arg(long, hide = true, value_name = "OP")]
    pub probe: Option<String>,
    /// Internal: the probe's target.
    #[arg(long, hide = true, value_name = "ARG", default_value = "")]
    pub probe_arg: String,
}

/// Everything the handlers share.
pub(crate) struct Console {
    pub policy: PathBuf,
    pub ledger: PathBuf,
    pub yolo: bool,
    pub provio_exe: PathBuf,
    pub cwd: PathBuf,
    pub started_ms: i64,
    pub port: u16,
    pub console_dir: PathBuf,
    pub sandbox_session: String,
    pub sandbox_lock: Mutex<()>,
    pub view: Mutex<LedgerView>,
    pub stop: AtomicBool,
}

// Embedded assets (no CDN, no build step).
const INDEX_HTML: &str = include_str!("ui/index.html");
const APP_JS: &str = include_str!("ui/app.js");
const APP_CSS: &str = include_str!("ui/app.css");
const ICON_SVG: &str = include_str!("../../../docs/assets/brand/icon.svg");
const WORDMARK_LIGHT: &str = include_str!("../../../docs/assets/brand/wordmark-light.svg");
const WORDMARK_DARK: &str = include_str!("../../../docs/assets/brand/wordmark-dark.svg");
const ICON_32: &[u8] = include_bytes!("../../../docs/assets/brand/icon-32.png");

/// 256 bits from the OS: `/dev/urandom` where it exists; elsewhere the
/// standard library's per-thread OS-seeded SipHash keys (BCryptGenRandom /
/// ProcessPrng on Windows), each thread contributing fresh 128-bit keys,
/// folded through SHA-256.
fn random_token() -> String {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut b = [0u8; 32];
        if std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut b))
            .is_ok()
        {
            return b.iter().map(|x| format!("{x:02x}")).collect();
        }
    }
    use std::hash::{BuildHasher, Hasher};
    let mut material = Vec::new();
    for i in 0..8u64 {
        let h = std::thread::spawn(move || {
            let mut out = Vec::new();
            for j in 0..4u64 {
                let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
                hasher.write_u64(i);
                hasher.write_u64(j);
                out.extend_from_slice(&hasher.finish().to_le_bytes());
            }
            out
        })
        .join()
        .unwrap_or_default();
        material.extend(h);
    }
    material.extend_from_slice(&Timestamp::now().epoch_ms().to_le_bytes());
    material.extend_from_slice(&std::process::id().to_le_bytes());
    provio_core::ledger::LedgerRecord::hash_bytes(&material)
}

fn open_browser(url: &str) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("rundll32.exe");
        c.arg("url.dll,FileProtocolHandler").arg(url);
        c
    } else if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        c.arg(url);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
}

pub fn serve(policy: &Path, ledger: &Path, yolo: bool, args: &UiArgs) -> Result<()> {
    if let Some(op) = &args.probe {
        std::process::exit(sandbox::probe(op, &args.probe_arg));
    }
    let cwd = std::env::current_dir().context("current directory")?;
    let policy = std::path::absolute(policy).context("resolve --policy")?;
    let pg = ledger.to_str().is_some_and(provio_ledger::is_postgres_url);
    let ledger = if pg {
        ledger.to_path_buf()
    } else {
        std::path::absolute(ledger).context("resolve --ledger")?
    };
    if !pg {
        if let Some(dir) = ledger.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        }
    }
    let console_dir = approvals::console_dir(&ledger)
        .map_err(|e| anyhow!("cannot locate the console state directory: {e}"))?;
    std::fs::create_dir_all(console_dir.join("decisions"))
        .with_context(|| format!("create {}", console_dir.display()))?;

    let listener = TcpListener::bind(("127.0.0.1", args.port))
        .with_context(|| format!("bind 127.0.0.1:{}", args.port))?;
    let port = listener.local_addr()?.port();
    let token = random_token();
    let started_ms = Timestamp::now().epoch_ms();
    let console = Arc::new(Console {
        policy,
        ledger: ledger.clone(),
        yolo,
        provio_exe: std::env::current_exe().context("locate the provio binary")?,
        cwd,
        started_ms,
        port,
        console_dir: console_dir.clone(),
        sandbox_session: format!("ui-sandbox-{}-{started_ms}", std::process::id()),
        sandbox_lock: Mutex::new(()),
        view: Mutex::new(LedgerView::new(&ledger)),
        stop: AtomicBool::new(false),
    });

    if let Some(h) = approvals::read_heartbeat(&console_dir) {
        if approvals::heartbeat_fresh(&h) && h.pid != std::process::id() {
            eprintln!(
                "  provio ui · note: another console (pid {}, port {}) is also serving this ledger",
                h.pid, h.port
            );
        }
    }
    // Heartbeat: `provio check --ask ui` waits only while this is fresh.
    {
        let c = console.clone();
        std::thread::Builder::new()
            .name("provio-ui-heartbeat".into())
            .spawn(move || {
                let mut last_gc = Instant::now() - Duration::from_secs(3600);
                while !c.stop.load(Ordering::SeqCst) {
                    let hb = approvals::Heartbeat {
                        pid: std::process::id(),
                        port: c.port,
                        started_ms: c.started_ms,
                        updated_ms: Timestamp::now().epoch_ms(),
                        ledger: provio_ledger::display_ledger(&c.ledger),
                    };
                    if let Ok(b) = serde_json::to_vec_pretty(&hb) {
                        let _ = approvals::write_atomic(&c.console_dir.join("console.json"), &b);
                    }
                    if last_gc.elapsed() > Duration::from_secs(600) {
                        approvals::gc_decisions(&c.console_dir);
                        last_gc = Instant::now();
                    }
                    std::thread::sleep(approvals::HEARTBEAT_EVERY);
                }
            })?;
    }

    let url = format!("http://127.0.0.1:{port}/#token={token}");
    {
        use std::io::Write;
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "provio ui · {url}");
        let _ = out.flush();
    }
    eprintln!(
        "  provio ui · policy {} · ledger {}\n  provio ui · listening on 127.0.0.1:{port} only; the token in the URL is required for every API call. Ctrl-C stops the console.",
        console.policy.display(),
        provio_ledger::display_ledger(&console.ledger)
    );
    if !args.no_open {
        if let Err(e) = open_browser(&url) {
            eprintln!("  provio ui · could not open a browser ({e}); open the URL above yourself");
        }
    }

    let security = Arc::new(http::Security { port, token });
    let c = console.clone();
    http::serve(
        listener,
        security,
        Arc::new(move |req: Request| route(&c, req)),
    );
    console.stop.store(true, Ordering::SeqCst);
    Ok(())
}

// ---------------------------------------------------------------------------
// Routing

fn asset(content_type: &'static str, body: &[u8]) -> Response {
    Response::bytes(200, content_type, body.to_vec())
}

fn route(c: &Arc<Console>, req: Request) -> Response {
    let get = req.method == "GET" || req.method == "HEAD";
    let post = req.method == "POST";
    let path = req.path.clone();
    match (path.as_str(), get, post) {
        ("/" | "/index.html", true, _) => asset("text/html; charset=utf-8", INDEX_HTML.as_bytes()),
        ("/app.js", true, _) => asset("text/javascript; charset=utf-8", APP_JS.as_bytes()),
        ("/app.css", true, _) => asset("text/css; charset=utf-8", APP_CSS.as_bytes()),
        ("/icon.svg", true, _) => asset("image/svg+xml", ICON_SVG.as_bytes()),
        ("/wordmark-light.svg", true, _) => asset("image/svg+xml", WORDMARK_LIGHT.as_bytes()),
        ("/wordmark-dark.svg", true, _) => asset("image/svg+xml", WORDMARK_DARK.as_bytes()),
        ("/favicon.ico" | "/icon-32.png", true, _) => asset("image/png", ICON_32),

        ("/api/info", true, _) => api_info(c),
        ("/api/decisions", true, _) => api_decisions(c, &req),
        ("/api/record", true, _) => api_record(c, &req),
        ("/api/verify", true, _) => api_verify(c),
        ("/api/stream", true, _) => api_stream(c, &req),
        ("/api/pending", true, _) => Response::ok(pending_json(c)),
        ("/api/pending/decide", _, true) => with_json(&req, |b| api_decide(c, b)),
        ("/api/connect", true, _) => Response::ok(connect_json(c)),
        ("/api/policy", true, _) => api_policy(c),
        ("/api/policy/validate", _, true) => with_json(&req, |b| {
            let src = b.get("source").and_then(Value::as_str).unwrap_or("");
            Response::ok(policy::validate(src))
        }),
        ("/api/policy/test", _, true) => with_json(&req, |b| {
            let src = match b.get("source").and_then(Value::as_str) {
                Some(s) => s.to_string(),
                None => std::fs::read_to_string(&c.policy).unwrap_or_default(),
            };
            policy::test(b, &src, c.yolo)
        }),
        ("/api/policy/save", _, true) => with_json(&req, |b| policy::save(&c.policy, b)),
        ("/api/packs", true, _) => Response::ok(policy::packs()),
        ("/api/integrate/claude-code", _, true) => with_json(&req, |b| api_integrate(c, b)),
        ("/api/sandbox", true, _) => Response::ok(sandbox::status()),
        ("/api/sandbox/run", _, true) => with_json(&req, |b| sandbox::run(c, b)),
        ("/api/scan", true, _) => api_scan(c, &req),
        (p, _, _) if p.starts_with("/api/") => {
            let known = [
                "/api/info",
                "/api/decisions",
                "/api/record",
                "/api/verify",
                "/api/stream",
                "/api/pending",
                "/api/pending/decide",
                "/api/connect",
                "/api/policy",
                "/api/policy/validate",
                "/api/policy/test",
                "/api/policy/save",
                "/api/packs",
                "/api/integrate/claude-code",
                "/api/sandbox",
                "/api/sandbox/run",
                "/api/scan",
            ];
            if known.contains(&p) {
                let mut r =
                    Response::error(405, "method_not_allowed", "wrong method for this endpoint");
                r.headers.push((
                    "Allow",
                    if p.ends_with("decide")
                        || p.contains("/policy/")
                        || p.contains("integrate")
                        || p.ends_with("/run")
                    {
                        "POST".into()
                    } else {
                        "GET".into()
                    },
                ));
                r
            } else {
                Response::error(404, "not_found", "no such endpoint")
            }
        }
        (_, false, _) => Response::error(405, "method_not_allowed", "GET only"),
        _ => Response::error(404, "not_found", "not found"),
    }
}

fn with_json(req: &Request, f: impl FnOnce(&Value) -> Response) -> Response {
    match req.json() {
        Ok(v @ Value::Object(_)) => f(&v),
        Ok(_) => Response::error(400, "bad_request", "body must be a JSON object"),
        Err(r) => r,
    }
}

// ---------------------------------------------------------------------------
// Handlers

fn claude_settings_status(c: &Console) -> Value {
    let path = c.cwd.join(".claude").join("settings.json");
    let mut mode: Option<String> = None;
    let mut found = false;
    if let Ok(s) = std::fs::read_to_string(&path) {
        if let Ok(v) = serde_json::from_str::<Value>(&s) {
            if let Some(groups) = v.pointer("/hooks/PreToolUse").and_then(Value::as_array) {
                for g in groups {
                    for h in g
                        .get("hooks")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let args: Vec<&str> = h
                            .get("args")
                            .and_then(Value::as_array)
                            .map(|a| a.iter().filter_map(Value::as_str).collect())
                            .unwrap_or_default();
                        if args.contains(&"check") && args.contains(&"claude-code") {
                            found = true;
                            mode = args
                                .iter()
                                .position(|a| *a == "--ask")
                                .and_then(|i| args.get(i + 1))
                                .map(|s| s.to_string());
                        }
                    }
                }
            }
        }
    }
    json!({"path": path.display().to_string(), "exists": path.exists(),
           "has_provio_hooks": found, "ask": mode})
}

fn api_info(c: &Console) -> Response {
    let policy_ok = std::fs::read_to_string(&c.policy)
        .map(|s| policy::validate(&s)["ok"] == json!(true))
        .unwrap_or(false);
    Response::ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "policy": c.policy.display().to_string(),
        "policy_exists": c.policy.exists(),
        "policy_ok": policy_ok,
        "ledger": provio_ledger::display_ledger(&c.ledger),
        "ledger_exists": c.ledger.exists(),
        "ledger_kind": policy::ledger_kind(&c.ledger),
        "provio": c.provio_exe.display().to_string(),
        "cwd": c.cwd.display().to_string(),
        "yolo": c.yolo,
        "platform": std::env::consts::OS,
        "started_ms": c.started_ms,
        "approver": approvals::console_approver(),
        "state_dir": c.console_dir.display().to_string(),
        "pending_dir": approvals::pending_dir(&c.ledger).map(|p| p.display().to_string()).unwrap_or_default(),
        "claude_settings": claude_settings_status(c),
        "sandbox": sandbox::status(),
    }))
}

fn refreshed(c: &Console) -> std::sync::MutexGuard<'_, LedgerView> {
    let mut v = c.view.lock().unwrap_or_else(|p| p.into_inner());
    v.refresh();
    v
}

fn pending_indices(c: &Console, view: &LedgerView) -> Vec<u64> {
    validated_pending(c, view)
        .into_iter()
        .map(|p| p.0.index)
        .collect()
}

/// Requests in the queue that match an unresolved `ask` on the ledger.
fn validated_pending<'a>(
    c: &Console,
    view: &'a LedgerView,
) -> Vec<(
    approvals::PendingRequest,
    &'a provio_core::ledger::LedgerRecord,
)> {
    approvals::list_requests(&c.ledger)
        .into_iter()
        .filter_map(|r| {
            let rec = view.decision(r.index)?;
            let ok = rec.record_hash == r.record_hash
                && approvals::request_id(rec) == r.id
                && matches!(rec.verdict, Some(Verdict::Ask { .. }))
                && rec.approver.is_none()
                && view.executions(rec.index).is_empty();
            ok.then_some((r, rec))
        })
        .collect()
}

fn pending_json(c: &Console) -> Value {
    let view = refreshed(c);
    let all = approvals::list_requests(&c.ledger).len();
    let now = Timestamp::now().epoch_ms();
    let pend = validated_pending(c, &view);
    let idx: Vec<u64> = pend.iter().map(|p| p.0.index).collect();
    let items: Vec<Value> = pend
        .iter()
        .map(|(r, rec)| {
            let mut s = summary(&view, rec, &idx);
            s["id"] = json!(r.id);
            s["deadline_ms"] = json!(r.deadline_ms);
            s["created_ms"] = json!(r.created_ms);
            s["remaining_ms"] = json!((r.deadline_ms - now).max(0));
            s["format"] = json!(r.format);
            s["args"] = rec
                .call
                .as_ref()
                .map(|c| c.args.clone())
                .unwrap_or(Value::Null);
            if let Some(Verdict::Ask {
                irreversible,
                timeout_ms,
                ..
            }) = &rec.verdict
            {
                s["irreversible"] = json!(irreversible);
                s["timeout_ms"] = json!(timeout_ms);
            }
            s["decided"] = approvals::read_console_decision(&c.console_dir, &r.id)
                .filter(|d| d.record_hash == rec.record_hash)
                .map(|d| json!({"approved": d.approved, "approver": d.approver}))
                .unwrap_or(Value::Null);
            s
        })
        .collect();
    json!({"items": items, "ignored": all - items.len(), "approver": approvals::console_approver()})
}

fn api_decide(c: &Console, b: &Value) -> Response {
    let Some(id) = b.get("id").and_then(Value::as_str) else {
        return Response::error(400, "bad_request", "decide needs \"id\"");
    };
    let Some(approve) = b.get("approve").and_then(Value::as_bool) else {
        return Response::error(400, "bad_request", "decide needs a boolean \"approve\"");
    };
    if !approvals::valid_id(id) {
        return Response::error(400, "bad_request", "malformed id");
    }
    let view = refreshed(c);
    let pend = validated_pending(c, &view);
    let Some((r, rec)) = pend.iter().find(|p| p.0.id == id) else {
        return Response::error(
            404,
            "not_pending",
            "no pending ask with that id (it may have timed out or been answered)",
        );
    };
    if Timestamp::now().epoch_ms() > r.deadline_ms {
        return Response::error(409, "expired", "this ask already timed out (denied)");
    }
    match approvals::write_decision(&c.console_dir, id, &rec.record_hash, approve) {
        Ok(d) => Response::ok(json!({"ok": true, "decision": d})),
        Err(e) => Response::error(500, "io", &format!("could not write the decision: {e}")),
    }
}

/// `provio scan` over this machine's agent transcripts (read-only): the
/// Look back screen. `days` (default 30, 1..365); `packs=all` judges with
/// every bundled pack instead of the console's policy.
fn api_scan(c: &Console, req: &Request) -> Response {
    let days: u32 = req
        .query
        .get("days")
        .and_then(|d| d.parse().ok())
        .unwrap_or(30)
        .clamp(1, 365);
    let packs: Vec<String> = match req.query.get("packs").map(String::as_str) {
        Some("all") => vec!["all".to_string()],
        _ => Vec::new(),
    };
    match crate::scan::json_report(&c.policy, days, &packs) {
        Ok(v) => Response::ok(v),
        Err(e) => Response::error(500, "scan_failed", &e.to_string()),
    }
}

fn api_decisions(c: &Console, req: &Request) -> Response {
    let limit: usize = req
        .query
        .get("limit")
        .and_then(|l| l.parse().ok())
        .unwrap_or(300)
        .clamp(1, 2000);
    let before: Option<u64> = req.query.get("before").and_then(|b| b.parse().ok());
    let view = refreshed(c);
    let pend = pending_indices(c, &view);
    let items: Vec<Value> = view
        .decisions()
        .rev()
        .filter(|r| before.is_none_or(|b| r.index < b))
        .take(limit)
        .map(|r| summary(&view, r, &pend))
        .collect();
    Response::ok(json!({
        "items": items,
        "records": view.records.len(),
        "decisions": view.decisions().count(),
        "error": view.error,
        "pending": pend,
    }))
}

fn api_record(c: &Console, req: &Request) -> Response {
    let Some(index) = req.query.get("index").and_then(|i| i.parse::<u64>().ok()) else {
        return Response::error(400, "bad_request", "record needs ?index=N");
    };
    let view = refreshed(c);
    let Some(rec) = view.decision(index) else {
        return Response::error(404, "not_found", "no decision record at that index");
    };
    let source = std::fs::read_to_string(&c.policy).unwrap_or_default();
    let line = match &rec.verdict {
        Some(Verdict::Deny {
            location: Some(l), ..
        })
        | Some(Verdict::Ask {
            location: Some(l), ..
        }) => l.rsplit(':').next().and_then(|n| n.parse::<usize>().ok()),
        _ => rec
            .rule_id
            .as_deref()
            .and_then(|r| policy::rule_line(&source, r)),
    };
    let excerpt = line.map(|l| {
        source
            .lines()
            .enumerate()
            .skip(l.saturating_sub(1))
            .take(8)
            .map(|(i, t)| json!({"n": i + 1, "text": t}))
            .collect::<Vec<_>>()
    });
    let pend = pending_indices(c, &view);
    let console_decision =
        approvals::read_console_decision(&c.console_dir, &approvals::request_id(rec))
            .filter(|d| d.record_hash == rec.record_hash);
    Response::ok(json!({
        "summary": summary(&view, rec, &pend),
        "decision": rec,
        "executions": view.executions(index),
        "rule_line": line,
        "policy_excerpt": excerpt,
        "console_decision": console_decision,
    }))
}

fn api_verify(c: &Console) -> Response {
    let pg = c
        .ledger
        .to_str()
        .is_some_and(provio_ledger::is_postgres_url);
    if !pg && !c.ledger.exists() {
        return Response::ok(json!({"exists": false, "intact": true, "records": 0}));
    }
    match provio_ledger::verify(&c.ledger) {
        Ok(r) => Response::ok(json!({
            "exists": true, "intact": r.intact, "records": r.records, "broken_at": r.broken_at,
            "ledger": provio_ledger::display_ledger(&c.ledger),
        })),
        Err(e) => Response::ok(json!({"exists": true, "intact": false, "error": e.to_string()})),
    }
}

fn api_policy(c: &Console) -> Response {
    match std::fs::read(&c.policy) {
        Ok(bytes) => {
            let source = String::from_utf8_lossy(&bytes).into_owned();
            Response::ok(json!({
                "path": c.policy.display().to_string(),
                "exists": true,
                "source": source,
                "sha256": provio_core::ledger::LedgerRecord::hash_bytes(&bytes),
                "validation": policy::validate(&source),
                "yolo": c.yolo,
            }))
        }
        Err(_) => Response::ok(json!({
            "path": c.policy.display().to_string(),
            "exists": false,
            "source": "",
            "sha256": null,
            "validation": policy::validate(""),
            "yolo": c.yolo,
        })),
    }
}

/// `{ask: "defer"}` runs `provio integrate claude-code` as is; `{ask: "ui"}`
/// merges the same hook entries with `--ask ui`, so asks come to this
/// console.
fn api_integrate(c: &Console, b: &Value) -> Response {
    let ask = b.get("ask").and_then(Value::as_str).unwrap_or("defer");
    let result = match ask {
        "defer" => crate::integrate::integrate(
            &c.policy,
            &c.ledger,
            crate::integrate::Target::ClaudeCode,
            false,
        ),
        "ui" => integrate_ui(c),
        other => {
            return Response::error(400, "bad_request", &format!("unknown ask mode {other:?}"))
        }
    };
    match result {
        Ok(()) => Response::ok(json!({"ok": true, "settings": claude_settings_status(c)})),
        Err(e) => Response::error(409, "integrate_failed", &format!("{e:#}")),
    }
}

fn integrate_ui(c: &Console) -> Result<()> {
    crate::cmds::load_engine(&c.policy, false).with_context(|| {
        format!(
            "refusing to integrate: the hooks would deny every tool call until {} loads",
            c.policy.display()
        )
    })?;
    let mut fragment =
        crate::integrate::claude_code_hook_settings(&c.provio_exe, &c.policy, &c.ledger);
    for event in ["PreToolUse", "PostToolUse", "PostToolUseFailure"] {
        if let Some(args) = fragment
            .pointer_mut(&format!("/hooks/{event}/0/hooks/0/args"))
            .and_then(Value::as_array_mut)
        {
            for a in args.iter_mut() {
                if a == "defer" {
                    *a = json!("ui");
                }
            }
        }
    }
    let path = c.cwd.join(".claude").join("settings.json");
    let existing = match std::fs::read_to_string(&path) {
        Ok(s) if s.trim().is_empty() => json!({}),
        Ok(s) => serde_json::from_str::<Value>(&s)
            .with_context(|| format!("{} is not valid JSON; not touching it", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let merged = crate::integrate::merge_hook_settings(existing, &fragment)?;
    let text = serde_json::to_string_pretty(&merged)? + "\n";
    approvals::write_atomic(&path, text.as_bytes())
        .with_context(|| format!("write {}", path.display()))
}

/// Which card a decision belongs to.
fn card_for(rec: &provio_core::ledger::LedgerRecord) -> Vec<&'static str> {
    let Some(call) = &rec.call else {
        return Vec::new();
    };
    let agent = call.caller.agent.as_str();
    if agent == sandbox::SANDBOX_AGENT {
        return Vec::new();
    }
    let mut out = Vec::new();
    match call.mode {
        provio_core::call::InterceptMode::Mcp => out.push("mcp"),
        provio_core::call::InterceptMode::ProcessWrap => out.push("cli"),
        provio_core::call::InterceptMode::SdkHook => {
            if agent == "claude-code" {
                out.push("claude-code");
            } else {
                if matches!(
                    agent,
                    "langgraph" | "openai-agents" | "provio-sdk" | "claude-agent-sdk"
                ) {
                    out.push("python");
                }
                out.push("typescript");
            }
        }
    }
    out
}

fn connect_json(c: &Console) -> Value {
    let view = refreshed(c);
    let mut cards = serde_json::Map::new();
    for rec in view.decisions().rev() {
        for card in card_for(rec) {
            if cards.contains_key(card) {
                continue;
            }
            let call = rec.call.as_ref().expect("card_for checked");
            cards.insert(
                card.to_string(),
                json!({
                    "index": rec.index,
                    "agent": call.caller.agent,
                    "tool": call.tool,
                    "verdict": rec.verdict.as_ref().map(ledger::verdict_kind),
                    "recorded_at": rec.recorded_at.to_rfc3339(),
                    "since_start": rec.recorded_at.epoch_ms() >= c.started_ms - 1000,
                }),
            );
        }
        if cards.len() == 5 {
            break;
        }
    }
    json!({"cards": cards, "started_ms": c.started_ms})
}

/// A server-sent event stream (read with `fetch`, so the token can travel
/// as a header): `decisions` (new or changed summaries), `pending`,
/// `connect`, `ledger`, and a comment every 15 s.
fn api_stream(c: &Arc<Console>, req: &Request) -> Response {
    let after: Option<u64> = req.query.get("after").and_then(|a| a.parse().ok());
    let c = c.clone();
    Response::stream(Box::new(move |out| {
        use std::io::Write;
        fn raw(out: &mut std::net::TcpStream, bytes: &[u8]) -> bool {
            out.write_all(bytes).is_ok() && out.flush().is_ok()
        }
        fn send(out: &mut std::net::TcpStream, event: &str, data: &Value) -> bool {
            raw(out, format!("event: {event}\ndata: {data}\n\n").as_bytes())
        }
        let mut seen_records: usize = 0;
        let mut last_pending = Value::Null;
        let mut last_connect = Value::Null;
        let mut last_beat = Instant::now();
        let mut first = true;
        if !send(out, "hello", &json!({"version": env!("CARGO_PKG_VERSION")})) {
            return;
        }
        while !c.stop.load(Ordering::SeqCst) {
            let (items, meta) = {
                let view = refreshed(&c);
                let pend = pending_indices(&c, &view);
                if view.records.len() < seen_records {
                    seen_records = 0;
                }
                let mut affected: Vec<u64> = Vec::new();
                for r in &view.records[seen_records..] {
                    match r.kind {
                        RecordKind::Decision => {
                            if !first || after.is_none_or(|a| r.index > a) {
                                affected.push(r.index)
                            }
                        }
                        RecordKind::Execution => {
                            if let Some(d) = r.decision_index {
                                if !first || after.is_none_or(|a| d > a) {
                                    affected.push(d)
                                }
                            }
                        }
                    }
                }
                seen_records = view.records.len();
                affected.sort_unstable();
                affected.dedup();
                if first {
                    // Only a bounded catch-up on connect.
                    let n = affected.len();
                    affected = affected.split_off(n.saturating_sub(500));
                }
                let items: Vec<Value> = affected
                    .iter()
                    .filter_map(|i| view.decision(*i))
                    .map(|r| summary(&view, r, &pend))
                    .collect();
                (
                    items,
                    json!({"records": view.records.len(), "error": view.error}),
                )
            };
            if (!items.is_empty() || first)
                && !send(out, "decisions", &json!({"items": items, "ledger": meta}))
            {
                return;
            }
            let p = pending_json(&c);
            if p != last_pending {
                if !send(out, "pending", &p) {
                    return;
                }
                last_pending = p;
            }
            let k = connect_json(&c);
            if k != last_connect {
                if !send(out, "connect", &k) {
                    return;
                }
                last_connect = k;
            }
            if last_beat.elapsed() > Duration::from_secs(15) {
                if out.write_all(b": keep-alive\n\n").is_err() || out.flush().is_err() {
                    return;
                }
                last_beat = Instant::now();
            }
            first = false;
            std::thread::sleep(Duration::from_millis(600));
        }
    }))
}
