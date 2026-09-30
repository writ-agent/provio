//! Command implementations. Every path honours the core invariants:
//! exactly one decision record per call, dispatch only after the record is
//! durable, fail closed on any ambiguity.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use anyhow::{anyhow, bail, Context, Result};
use writ_core::approver::FailClosedApprover;
use writ_core::call::{CallerIdentity, InterceptMode, ToolCall};
use writ_core::ledger::{LedgerRecord, LedgerWriter};
use writ_core::pipeline::handle_call;
use writ_core::verdict::Verdict;
use writ_core::{PolicyEngine, Timestamp};
use writ_ledger::SessionSummary;
use writ_mcp::{
    stdio_transport, CredentialStore, Interceptor, McpProxy, ProxyConfig, ProxyDecision,
};
use writ_policy::NativePolicyEngine;
use writ_tui::{render_call_line, render_rule_note};

type DecisionMap = Rc<RefCell<HashMap<String, (LedgerRecord, Vec<String>)>>>;

pub(crate) fn load_engine(policy_path: &Path, yolo: bool) -> Result<NativePolicyEngine> {
    if !policy_path.exists() {
        bail!(
            "no policy file at {} — create one (see examples/writ.yaml) or pass --policy",
            policy_path.display()
        );
    }
    let mut source = std::fs::read_to_string(policy_path)
        .with_context(|| format!("read {}", policy_path.display()))?;
    if yolo {
        eprintln!("\x1b[31m⚠ --yolo: policy default flipped to ALLOW. Nothing will ask.\x1b[0m");
        source = source.replacen("default: ask", "default: allow", 1);
    }
    NativePolicyEngine::from_source(&source).map_err(|e| anyhow!(e.to_string()))
}

/// Whether the ledger location is a Postgres URL rather than a file path.
pub(crate) fn is_pg(ledger: &Path) -> bool {
    ledger.to_str().is_some_and(writ_ledger::is_postgres_url)
}

/// Whether there is a ledger to read. A Postgres URL cannot be checked on
/// the filesystem; the store itself reports a missing ledger.
pub(crate) fn ledger_present(ledger: &Path) -> bool {
    is_pg(ledger) || ledger.exists()
}

/// The ledger as shown to people: a Postgres URL has its password redacted.
pub(crate) fn show_ledger(ledger: &Path) -> String {
    writ_ledger::display_ledger(ledger)
}

pub(crate) fn banner(engine: &NativePolicyEngine, policy: &Path, ledger: &Path) {
    eprintln!(
        "  writ · {} rules loaded from {} · ledger: {}",
        engine.rule_count(),
        policy.display(),
        show_ledger(ledger)
    );
}

pub(crate) fn make_call(
    session: &str,
    seq: u64,
    tool: &str,
    args: serde_json::Value,
    mode: InterceptMode,
) -> ToolCall {
    ToolCall {
        call_id: format!("{session}-{seq}"),
        session_id: session.to_string(),
        caller: CallerIdentity {
            agent: std::env::var("WRIT_AGENT").unwrap_or_else(|_| "unknown-agent".into()),
            agent_version: None,
            user: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .ok(),
            non_human_id: None,
        },
        mode,
        tool: tool.to_string(),
        args,
        server: None,
        trust: None,
        captured_at: Timestamp::now(),
    }
}

/// `writ proxy --mcp --server <name> -- <cmd>`: real interception (mode A).
/// stdout is the JSON-RPC channel, so all human output goes to stderr.
/// `ask` fails closed here (headless) — interactive approval needs the TUI
/// in `writ run` or an out-of-band approver (wave 2+).
pub fn proxy(
    policy: &Path,
    ledger: &Path,
    yolo: bool,
    mcp: bool,
    server: &str,
    cmd: &[String],
    pin: bool,
) -> Result<()> {
    if !mcp {
        bail!("only --mcp is supported in this build (SSE/HTTP: wave 2)");
    }
    let engine = load_engine(policy, yolo)?;
    banner(&engine, policy, ledger);
    eprintln!(
        "  mode: mcp proxy · downstream server: {server} · cmd: {}",
        cmd.join(" ")
    );

    let mut creds = CredentialStore::new();
    creds.load_from_env(server);
    if creds.has_any(server) {
        eprintln!("  credentials: injected at dispatch for '{server}' (agent never sees them)");
    }

    let spawned =
        writ_mcp::spawn_stdio_server(&cmd[0], &cmd[1..], server, &creds, &BTreeMap::new())
            .map_err(|e| anyhow!(e.to_string()))?;

    let core = mcp_interceptor(engine, ledger, server, "stdio", pin)?;
    let mut proxy = McpProxy::with_interceptor(stdio_transport(), spawned.transport, core);

    proxy.run().map_err(|e| anyhow!(e.to_string()))?;
    eprintln!("  writ · session closed · ledger: {}", show_ledger(ledger));
    Ok(())
}

/// The MCP interception wiring shared by every proxy transport (stdio here,
/// Streamable HTTP in `mcp_http`): per `tools/call` evaluate policy, ask
/// fail-closed, record exactly one decision, forward only on allow/redact,
/// record the execution with the output hash, and mask redact patterns
/// before the result reaches the agent.
pub(crate) fn mcp_interceptor(
    engine: NativePolicyEngine,
    ledger: &Path,
    server: &str,
    transport: &str,
    pin: bool,
) -> Result<Interceptor> {
    let store = Rc::new(RefCell::new(
        writ_ledger::open_store(ledger).map_err(|e| anyhow!(e.to_string()))?,
    ));
    // call_id → (decision record, redact patterns from the verdict)
    let decisions: DecisionMap = Rc::new(RefCell::new(HashMap::new()));

    // Decision hook: full pipeline per call — evaluate, approve-or-fail-closed,
    // record. Forward only on allow/redact.
    let (store_d, decisions_d, engine_d) = (Rc::clone(&store), Rc::clone(&decisions), engine);
    let ledger_d = ledger.to_path_buf();
    let decide = Box::new(move |call: &ToolCall| {
        let mut s = store_d.borrow_mut();
        let mut writer = LedgerWriter::new(&mut **s);
        match handle_call(call, &engine_d, &mut writer, &FailClosedApprover) {
            Ok(outcome) => {
                emit_span(&ledger_d, call, &outcome.verdict);
                eprintln!(
                    "{}",
                    render_call_line(&call.tool, &summarize(&call.args), &outcome.verdict)
                );
                if let Some(note) = render_rule_note(&outcome.verdict) {
                    eprintln!("{note}");
                }
                if outcome.should_dispatch() {
                    let patterns = match &outcome.verdict {
                        Verdict::Redact { patterns, .. } => patterns.clone(),
                        _ => Vec::new(),
                    };
                    decisions_d
                        .borrow_mut()
                        .insert(call.call_id.clone(), (outcome.record, patterns));
                    ProxyDecision::Forward
                } else {
                    ProxyDecision::Refuse {
                        message: refusal_message(&outcome.verdict),
                    }
                }
            }
            Err(e) => ProxyDecision::Refuse {
                message: format!("writ internal error (fail closed): {e}"),
            },
        }
    }) as Box<dyn FnMut(&ToolCall) -> ProxyDecision>;

    // Observation hook: execution record with output hash for forwarded calls.
    let (store_o, decisions_o) = (Rc::clone(&store), Rc::clone(&decisions));
    let mut proxy = Interceptor::new(
        ProxyConfig {
            server_name: server.to_string(),
            agent: std::env::var("WRIT_AGENT").unwrap_or_else(|_| "unknown-agent".into()),
            trust: None,
        },
        transport,
        decide,
    );
    // Tool pinning: a changed tool definition is hidden and its calls are
    // refused (and recorded as denied) until a human accepts it.
    if pin {
        let path = writ_mcp::pins::pin_path(&crate::mcp_pins::pins_dir(ledger), server);
        let pins = writ_mcp::pins::ToolPins::load(&path, server).map_err(|e| anyhow!(e))?;
        let held = pins.file().pending.len();
        if held > 0 {
            eprintln!(
                "  \x1b[33mtool pins: {held} changed tool(s) of `{server}` held — `writ mcp pins --server {server}`\x1b[0m"
            );
        }
        proxy.set_pins(pins);
        let store_r = Rc::clone(&store);
        proxy.on_refusal(Box::new(
            move |call: &ToolCall, rule_id: &str, reason: &str| {
                let verdict = Verdict::Deny {
                    rule_id: rule_id.to_string(),
                    reason: reason.to_string(),
                    location: None,
                };
                eprintln!(
                    "{}",
                    render_call_line(&call.tool, &summarize(&call.args), &verdict)
                );
                let mut s = store_r.borrow_mut();
                let mut writer = LedgerWriter::new(&mut **s);
                if let Err(e) = writer.record_decision(call, &verdict, None) {
                    eprintln!("  writ · could not record the refusal: {e}");
                }
            },
        ));
    }
    proxy.on_result(Box::new(
        move |call: &ToolCall, result: &serde_json::Value| {
            let Some(entry) = decisions_o.borrow().get(&call.call_id).cloned() else {
                return;
            };
            let bytes = serde_json::to_vec(result).unwrap_or_default();
            let mut s = store_o.borrow_mut();
            let mut writer = LedgerWriter::new(&mut **s);
            let _ = writer.record_execution(&entry.0, "mcp-proxy", 0, &bytes);
        },
    ));

    // Redact verdicts: mask matched patterns in results before they re-enter
    // the model's context (spec §7). The ledger already hashed the original.
    let decisions_t = Rc::clone(&decisions);
    proxy.set_result_transform(Box::new(
        move |call: &ToolCall, result: serde_json::Value| {
            let patterns = decisions_t
                .borrow()
                .get(&call.call_id)
                .map(|e| e.1.clone())
                .unwrap_or_default();
            if patterns.is_empty() {
                return result;
            }
            let mut text = result.to_string();
            for p in &patterns {
                match regex::Regex::new(p) {
                    Ok(re) => text = re.replace_all(&text, "[redacted-by-writ]").to_string(),
                    // A pattern that does not compile cannot be applied, so the
                    // result is withheld rather than passed through unmasked.
                    Err(_) => {
                        return serde_json::json!({"content": [{"type": "text",
                            "text": "[output withheld by writ: a redact pattern for this call is invalid]"}],
                            "isError": true});
                    }
                }
            }
            // Prefer returning valid JSON; if masking broke structure, return the
            // masked text as a plain content block instead (never the original).
            serde_json::from_str(&text).unwrap_or_else(
                |_| serde_json::json!({"content": [{"type": "text", "text": text}]}),
            )
        },
    ));
    Ok(proxy)
}

/// Structured refusal text (spec §12 voice: name the rule, give the reason).
fn refusal_message(v: &Verdict) -> String {
    match v {
        Verdict::Deny {
            rule_id,
            reason,
            location,
        } => format!(
            "writ denied this: rule \"{rule_id}\" — {reason} ({})",
            location.as_deref().unwrap_or("policy default")
        ),
        Verdict::Ask { rule_id, .. } => format!(
            "writ denied this: rule \"{rule_id}\" requires human approval; none available in this context (fail closed)"
        ),
        other => format!("writ denied this: {other:?}"),
    }
}

fn summarize(args: &serde_json::Value) -> String {
    let s = match args {
        serde_json::Value::Object(m) => m
            .values()
            .next()
            .map(|v| {
                v.as_str()
                    .map(String::from)
                    .unwrap_or_else(|| v.to_string())
            })
            .unwrap_or_default(),
        other => other.to_string(),
    };
    let s = s.replace('\n', " ");
    if s.chars().count() > 72 {
        format!("{}…", s.chars().take(71).collect::<String>())
    } else {
        s
    }
}
/// `writ log` — the answer to "what did my agent do last night".
pub fn log(ledger: &Path) -> Result<()> {
    if !ledger_present(ledger) {
        bail!(
            "no ledger at {} — nothing recorded yet",
            show_ledger(ledger)
        );
    }
    let sessions: Vec<SessionSummary> =
        writ_ledger::sessions(ledger).map_err(|e| anyhow!(e.to_string()))?;
    let total: u64 = sessions.iter().map(|s| s.records).sum();
    let denied: u64 = sessions.iter().map(|s| s.denied).sum();
    let human: u64 = sessions.iter().filter(|s| s.approved_by_human).count() as u64;
    println!(
        "{} sessions · {} records · {} denied · {} sessions with your approvals",
        sessions.len(),
        total,
        denied,
        human
    );
    println!(
        "{:<34} {:>8} {:>8}  approved",
        "session", "records", "denied"
    );
    for s in sessions {
        println!(
            "{:<34} {:>8} {:>8}  {}",
            s.session_id,
            s.records,
            s.denied,
            if s.approved_by_human { "yes" } else { "-" }
        );
    }
    Ok(())
}

/// `writ show <call-id>` — one decision, in full.
pub fn show(ledger: &Path, call_id: &str) -> Result<()> {
    let records =
        writ_ledger::find_by_call_id(ledger, call_id).map_err(|e| anyhow!(e.to_string()))?;
    if records.is_empty() {
        bail!("no records for call-id {call_id}");
    }
    for r in &records {
        println!("{}", serde_json::to_string_pretty(r)?);
    }
    Ok(())
}

/// `writ verify` — verify the local hash chain and name the first break.
pub fn verify(ledger: &Path) -> Result<()> {
    if !ledger_present(ledger) {
        bail!("no ledger at {}", show_ledger(ledger));
    }
    let report = writ_ledger::verify(ledger).map_err(|e| anyhow!(e.to_string()))?;
    if report.intact {
        println!("chain intact · {} records · no gaps", report.records);
        Ok(())
    } else {
        eprintln!(
            "chain BROKEN at record {} · {} records verified before the break",
            report.broken_at.unwrap_or(0),
            report.records
        );
        std::process::exit(1);
    }
}

/// `writ policy test` — unit-test rules against fixtures.
pub fn policy_test(policy: &Path, fixtures: Option<PathBuf>) -> Result<()> {
    let source =
        std::fs::read_to_string(policy).with_context(|| format!("read {}", policy.display()))?;
    let dir = fixtures.unwrap_or_else(|| PathBuf::from("fixtures"));
    if !dir.is_dir() {
        bail!(
            "no fixture directory at {} — pass --fixtures (repo copy: crates/writ-policy/fixtures)",
            dir.display()
        );
    }
    let cases = writ_policy::load_fixtures_dir(&dir).map_err(|e| anyhow!(e.to_string()))?;
    let report = writ_policy::run_fixtures(&source, &cases);
    println!("{}", report.summary());
    if !report.is_pass() {
        std::process::exit(1);
    }
    Ok(())
}

/// `writ policy add <pack>` — install a community pack; print its checksum
/// so the operator can verify it (registry verification lands in wave 3).
pub fn policy_add(pack: &str) -> Result<()> {
    let search = [
        PathBuf::from(format!("packs/{pack}/pack.yaml")),
        PathBuf::from(format!("packs/{pack}.yaml")),
    ];
    // A local ./packs (a checkout, or your own packs) wins; otherwise the
    // packs bundled into this binary.
    let bytes = match search.iter().find(|p| p.exists()) {
        Some(src) => std::fs::read(src)?,
        None => crate::packs::bundled(pack)
            .map(|s| s.as_bytes().to_vec())
            .ok_or_else(|| {
                anyhow!(
                    "pack '{pack}' not found in ./packs or in this build; bundled packs: {}",
                    crate::packs::names()
                )
            })?,
    };
    let dest_dir = PathBuf::from(".writ/packs");
    std::fs::create_dir_all(&dest_dir)?;
    let dest = dest_dir.join(format!("{pack}.yaml"));
    std::fs::write(&dest, &bytes)?;
    println!(
        "installed pack '{pack}' → {}\nsha256: {}\nverify this checksum against the pack registry before trusting it in production",
        dest.display(),
        LedgerRecord::hash_bytes(&bytes)
    );
    Ok(())
}
/// `writ doctor` — coverage honesty (spec §6): exactly which call paths are
/// governed on this machine and which are blind.
pub fn doctor(policy: &Path, ledger: &Path) -> Result<()> {
    println!("writ doctor · {}", env!("CARGO_PKG_VERSION"));
    println!();

    match std::fs::read_to_string(policy) {
        Ok(src) => match NativePolicyEngine::from_source(&src) {
            Ok(e) => println!(
                "policy    : {} ({} rules, default applies to unmatched calls)",
                policy.display(),
                e.rule_count()
            ),
            Err(e) => println!("policy    : {} FAILED TO COMPILE: {e}", policy.display()),
        },
        Err(_) => println!("policy    : none at {}", policy.display()),
    }

    if ledger_present(ledger) {
        match writ_ledger::verify(ledger) {
            Ok(r) if r.intact => println!(
                "ledger    : {} · {} records · chain intact",
                show_ledger(ledger),
                r.records
            ),
            Ok(r) => println!(
                "ledger    : {} · CHAIN BROKEN at record {}",
                show_ledger(ledger),
                r.broken_at.unwrap_or(0)
            ),
            Err(e) => println!("ledger    : {} · unreadable: {e}", show_ledger(ledger)),
        }
    } else {
        println!("ledger    : none at {} yet", show_ledger(ledger));
    }
    println!();

    println!("sandbox backends:");
    for b in writ_sandbox::detect_backends() {
        println!(
            "  {:<14} {} — {}",
            b.name,
            if b.available {
                "available"
            } else {
                "not available"
            },
            b.notes
        );
    }
    let kh = writ_sandbox::kernel_hardening();
    println!();
    println!("kernel boundary ({}): {}", kh.platform, kh.mechanism);
    println!("  enforced: {} — {}", kh.enforced, kh.notes);
    println!("  applies to: commands executed through the local-os sandbox backend");
    let ic = writ_sandbox::interactive::capabilities();
    let level = |s: &writ_sandbox::Support| match s {
        writ_sandbox::Support::Full => "enforced".to_string(),
        writ_sandbox::Support::Partial(w) => format!("PARTIAL — {w}"),
        writ_sandbox::Support::Unavailable(w) => format!("NOT available — {w}"),
    };
    println!("  `writ run` agent boundary: {}", ic.mechanism);
    println!(
        "    writes confined to workspace + private temp + agent profile dirs: {}",
        level(&ic.filesystem)
    );
    println!("    network: open and NOT filtered by default (no mechanism filters by host);");
    println!("    --net none: {}", level(&ic.network_deny));
    println!();
    println!("interception coverage:");
    println!("  MCP proxy (mode A)     : ready — `writ proxy --mcp` governs every MCP tool call");
    if ic.filesystem.is_full() {
        println!("  process wrap (mode B)  : ready — `writ run` records the launch and confines the agent's writes (network open unless --net none); Claude Code tool calls go through `writ check` hooks");
    } else {
        println!("  process wrap (mode B)  : launch supervision only here — the agent boundary is unavailable, so `writ run` refuses unless --best-effort or --unconfined");
    }
    println!(
        "  SDK hooks (mode C)     : ready — `writ check` gateway; writ-sdk (LangGraph, OpenAI Agents SDK, Claude Agent SDK), @writ-agent/sdk"
    );
    println!();
    println!("\x1b[33mblind spots, stated plainly:\x1b[0m");
    println!("  · in MCP-proxy-only mode the agent's own shell, file writes and direct HTTP are NOT governed");
    println!("  · an agent can bypass Writ entirely unless you pair mode A with mode B or C");
    println!("  · see docs/THREAT_MODEL.md for the full residual-risk table");
    Ok(())
}

/// Emit one GenAI-convention span for a governed call (spec §13).
/// Spans land in spans.jsonl next to the ledger; OTLP export is wave 2.
pub(crate) fn emit_span(ledger: &Path, call: &ToolCall, verdict: &Verdict) {
    // Spans sit next to a file ledger; a Postgres ledger has no directory,
    // so they go to ./.writ/ instead.
    let dir = if is_pg(ledger) {
        let dir = Path::new(".writ").to_path_buf();
        let _ = std::fs::create_dir_all(&dir);
        dir
    } else {
        ledger
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    };
    let path = dir.join("spans.jsonl");
    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return; // observability must never break the security path
    };
    let trace = writ_otel::GenAiTrace::begin(&call.caller.agent);
    let mut span = trace.execute_tool(call);
    trace.record_decision(&mut span, verdict);
    span.finish();
    let _ = writ_otel::JsonLinesExporter::new(file).export(&span);
    let mut root = trace.invoke_agent;
    root.finish();
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|f| {
            writ_otel::JsonLinesExporter::new(f)
                .export(&root)
                .map_err(|e| std::io::Error::other(e.to_string()))
        });
}

/// `writ replay <session>` — inspect a trajectory, test a candidate policy
/// against it, or plan a guarded re-branch (spec §10).
pub fn replay(
    ledger: &Path,
    session: &str,
    candidate: Option<PathBuf>,
    branch_from: Option<u64>,
    ack: bool,
) -> Result<()> {
    let steps =
        writ_replay::load_trajectory(ledger, session).map_err(|e| anyhow!(e.to_string()))?;
    if steps.is_empty() {
        bail!("no recorded calls for session '{session}' (see `writ log`)");
    }

    println!("session {session} · {} recorded calls", steps.len());
    for s in &steps {
        if let (Some(call), Some(v)) = (&s.decision.call, &s.decision.verdict) {
            println!(
                "  #{} {}",
                s.decision.index,
                render_call_line(&call.tool, &summarize(&call.args), v)
            );
            if let Some(exec) = &s.execution {
                println!(
                    "      executed on {} · exit {:?}",
                    exec.backend.as_deref().unwrap_or("?"),
                    exec.exit_status
                );
            }
        }
    }

    if let Some(candidate_path) = candidate {
        let source = std::fs::read_to_string(&candidate_path)
            .with_context(|| format!("read {}", candidate_path.display()))?;
        let report =
            writ_replay::policy_replay(&steps, &source).map_err(|e| anyhow!(e.to_string()))?;
        println!();
        println!("{}", report.summary());
        for c in &report.changes {
            println!(
                "  {} {} : {} → {} (rule: {})",
                c.call_id,
                c.tool,
                c.was,
                c.now,
                c.now_rule.as_deref().unwrap_or("default")
            );
        }
    }

    if let Some(from) = branch_from {
        match writ_replay::branch_from(&steps, from, ack) {
            Ok(plan) => println!(
                "re-branch plan from #{from}: {} step(s) replayable, {} irreversible ({})",
                plan.replayable.len(),
                plan.irreversible.len(),
                if plan.acknowledged {
                    "acknowledged"
                } else {
                    "none"
                }
            ),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
