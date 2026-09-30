//! `writ scan`: replay what your AI agents already did through a policy.
//!
//! Reads the transcripts the agents keep on this machine (nothing is
//! installed, hooked or written), maps every tool call the way that agent's
//! writ hook would, and judges it with the policy (including the scripts
//! it ran or wrote, see `inspect`). The result is a scorecard: what writ
//! would have blocked, asked about, or masked.
//!
//! | agent       | transcripts                                                   |
//! |-------------|---------------------------------------------------------------|
//! | Claude Code | `$CLAUDE_CONFIG_DIR` or `~/.claude`, `projects/**/*.jsonl`     |
//! | Codex       | `$CODEX_HOME` or `~/.codex`, `sessions/**/*.jsonl`            |
//! | Gemini CLI  | `~/.gemini/tmp/*/chats/*.json(l)`                             |
//!
//! Transcripts record what the agent *asked* to run. A call writ would
//! have blocked may also have been stopped by the agent's own permission
//! prompt; the scorecard says so rather than claiming damage was done.

use std::collections::{BTreeMap, HashSet};
use std::io::{BufRead, BufReader, IsTerminal};
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde_json::{json, Map, Value};
use writ_core::call::{CallerIdentity, InterceptMode, ToolCall};
use writ_core::verdict::Verdict;
use writ_core::Timestamp;

/// Agents `writ scan` reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ScanAgent {
    ClaudeCode,
    Codex,
    Gemini,
}

impl ScanAgent {
    const ALL: [ScanAgent; 3] = [ScanAgent::ClaudeCode, ScanAgent::Codex, ScanAgent::Gemini];

    fn id(self) -> &'static str {
        match self {
            ScanAgent::ClaudeCode => "claude-code",
            ScanAgent::Codex => "codex",
            ScanAgent::Gemini => "gemini-cli",
        }
    }

    fn label(self) -> &'static str {
        match self {
            ScanAgent::ClaudeCode => "Claude Code",
            ScanAgent::Codex => "Codex",
            ScanAgent::Gemini => "Gemini CLI",
        }
    }
}

/// Output of `writ scan`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ScanFormat {
    /// A scorecard for the terminal, with example commands.
    Text,
    /// Every finding, machine-readable.
    Json,
    /// A shareable summary: counts per rule, no commands or paths.
    Markdown,
}

#[derive(clap::Args, Debug)]
pub struct ScanArgs {
    /// How far back to look.
    #[arg(long, default_value_t = 30)]
    pub days: u32,
    /// Only these agents (default: every agent with transcripts here).
    #[arg(long, value_enum, value_delimiter = ',')]
    pub agent: Vec<ScanAgent>,
    /// Judge with these bundled packs (default allow for everything else)
    /// instead of the policy file, e.g. `--packs floor,secrets-guard`, or
    /// `--packs all`.
    #[arg(long, value_delimiter = ',')]
    pub packs: Vec<String>,
    /// Read transcripts from this directory instead of the agent's default
    /// (with a single --agent).
    #[arg(long)]
    pub dir: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ScanFormat::Text)]
    pub format: ScanFormat,
    /// Example calls shown per rule (text format).
    #[arg(long, default_value_t = 3)]
    pub examples: usize,
}

/// One tool call read back from a transcript.
struct Found {
    agent: ScanAgent,
    session: String,
    when: Option<String>,
    cwd: Option<String>,
    call: ToolCall,
}

/// One judged call that a rule named (allow-by-default calls are counted,
/// not kept).
#[derive(serde::Serialize)]
struct Finding {
    agent: &'static str,
    session: String,
    when: Option<String>,
    cwd: Option<String>,
    tool: String,
    summary: String,
    verdict: &'static str,
    rule_id: String,
    reason: String,
    location: Option<String>,
}

#[derive(Default)]
struct Source {
    files: usize,
    sessions: HashSet<String>,
    calls: usize,
    found_dir: Option<PathBuf>,
}

pub fn scan(policy: &Path, args: &ScanArgs) -> Result<()> {
    let (engine, policy_label) = crate::onboard::judging_policy(policy, &args.packs)?;
    let cutoff = iso_days_ago(args.days);
    let agents: Vec<ScanAgent> = if args.agent.is_empty() {
        ScanAgent::ALL.to_vec()
    } else {
        args.agent.clone()
    };
    if args.dir.is_some() && agents.len() != 1 {
        anyhow::bail!("--dir reads one agent's transcripts: pass exactly one --agent");
    }

    let mut sources: BTreeMap<&'static str, Source> = BTreeMap::new();
    let mut findings: Vec<Finding> = Vec::new();
    let (mut allowed, mut defaulted) = (0usize, 0usize);
    let mut seen_ids: HashSet<String> = HashSet::new();

    for agent in &agents {
        let src = sources.entry(agent.id()).or_default();
        let root = match &args.dir {
            Some(d) => Some(d.clone()),
            None => default_dir(*agent),
        };
        let Some(root) = root.filter(|r| r.is_dir()) else {
            continue;
        };
        src.found_dir = Some(root.clone());
        let files = transcript_files(*agent, &root, &cutoff);
        src.files = files.len();
        for file in files {
            read_transcript(*agent, &file, &cutoff, &mut |f: Found| {
                if !seen_ids.insert(format!("{}:{}", f.agent.id(), f.call.call_id)) {
                    return; // resumed sessions repeat earlier tool calls
                }
                let src = sources.get_mut(f.agent.id()).expect("entry above");
                src.sessions.insert(f.session.clone());
                src.calls += 1;
                let cwd = f.cwd.as_deref().map(PathBuf::from).filter(|p| p.is_dir());
                let v = match &cwd {
                    Some(dir) => crate::inspect::evaluate_in(&engine, &f.call, dir),
                    None => crate::inspect::evaluate_in(&engine, &f.call, Path::new("\0")),
                };
                let (verdict, rule_id, reason, location) = match &v {
                    Verdict::Allow { rule_id } => {
                        if rule_id.as_deref() == Some("default") {
                            defaulted += 1;
                        } else {
                            allowed += 1;
                        }
                        return;
                    }
                    Verdict::Deny {
                        rule_id,
                        reason,
                        location,
                    } => ("deny", rule_id, reason.clone(), location.clone()),
                    Verdict::Ask {
                        rule_id,
                        diff,
                        location,
                        ..
                    } => ("ask", rule_id, diff.clone(), location.clone()),
                    Verdict::Redact { rule_id, .. } => (
                        "redact",
                        rule_id,
                        "Output would have been masked before the model saw it.".to_string(),
                        None,
                    ),
                };
                if rule_id == "default" {
                    defaulted += 1;
                    return;
                }
                findings.push(Finding {
                    agent: f.agent.id(),
                    session: f.session,
                    when: f.when,
                    cwd: f.cwd,
                    tool: f.call.tool.clone(),
                    summary: summarize(&f.call),
                    verdict,
                    rule_id: rule_id.clone(),
                    reason,
                    location,
                });
            });
        }
    }
    findings.sort_by(|a, b| b.when.cmp(&a.when));

    match args.format {
        ScanFormat::Json => {
            let out = json!({
                "days": args.days,
                "since": cutoff,
                "policy": policy_label,
                "sources": sources.iter().map(|(id, s)| json!({
                    "agent": id,
                    "dir": s.found_dir,
                    "files": s.files,
                    "sessions": s.sessions.len(),
                    "tool_calls": s.calls,
                })).collect::<Vec<_>>(),
                "totals": totals_json(&findings, allowed, defaulted),
                "findings": findings,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        ScanFormat::Markdown => print!(
            "{}",
            markdown(args.days, &policy_label, &sources, &findings)
        ),
        ScanFormat::Text => text(args, &policy_label, &sources, &findings, allowed, defaulted),
    }
    Ok(())
}

fn totals_json(findings: &[Finding], allowed: usize, defaulted: usize) -> Value {
    let n = |v: &str| findings.iter().filter(|f| f.verdict == v).count();
    json!({
        "deny": n("deny"),
        "ask": n("ask"),
        "redact": n("redact"),
        "allow_by_rule": allowed,
        "no_rule_matched": defaulted,
    })
}

/// Per-rule counts of deny and ask findings, strictest verdict first, then
/// most frequent. Redact rules match whole call classes (every file read),
/// so a per-rule count would say nothing about secrets; they are left out.
fn by_rule(findings: &[Finding]) -> Vec<(&str, &str, usize, &Finding)> {
    let mut m: BTreeMap<(&str, &str), (usize, &Finding)> = BTreeMap::new();
    for f in findings.iter().filter(|f| f.verdict != "redact") {
        let e = m.entry((f.verdict, f.rule_id.as_str())).or_insert((0, f));
        e.0 += 1;
    }
    let rank = |v: &str| match v {
        "deny" => 0,
        "ask" => 1,
        _ => 2,
    };
    let mut v: Vec<_> = m
        .into_iter()
        .map(|((verdict, rule), (n, f))| (verdict, rule, n, f))
        .collect();
    v.sort_by(|a, b| {
        rank(a.0)
            .cmp(&rank(b.0))
            .then(b.2.cmp(&a.2))
            .then(a.1.cmp(b.1))
    });
    v
}

/// The first sentence of a rule's reason (the part after any "script …
/// runs `…`." prefix that `inspect` adds).
fn gist(reason: &str) -> String {
    let r = match reason.find("`. ") {
        Some(i)
            if reason.starts_with("script ")
                || reason.starts_with("the file")
                || reason.starts_with("package.json") =>
        {
            &reason[i + 3..]
        }
        _ => reason,
    };
    let end = r.find(". ").map(|i| i + 1).unwrap_or(r.len());
    r[..end].trim().to_string()
}

fn markdown(
    days: u32,
    policy_label: &str,
    sources: &BTreeMap<&'static str, Source>,
    findings: &[Finding],
) -> String {
    let mut s = String::new();
    let calls: usize = sources.values().map(|x| x.calls).sum();
    let sessions: usize = sources.values().map(|x| x.sessions.len()).sum();
    let n = |v: &str| findings.iter().filter(|f| f.verdict == v).count();
    s.push_str(&format!(
        "### What my AI agents did in the last {days} days\n\n\
         {calls} tool calls in {sessions} sessions ({agents}), judged by {policy_label}.\n\n\
         | | calls |\n|---|---:|\n\
         | would have been **blocked** | {} |\n\
         | would have **asked** first | {} |\n\n",
        n("deny"),
        n("ask"),
        agents = sources
            .iter()
            .filter(|(_, x)| x.calls > 0)
            .map(|(id, x)| format!("{id}: {}", x.calls))
            .collect::<Vec<_>>()
            .join(", "),
    ));
    let rules = by_rule(findings);
    if !rules.is_empty() {
        s.push_str("| verdict | rule | calls |\n|---|---|---:|\n");
        for (verdict, rule, count, _) in rules {
            s.push_str(&format!("| {verdict} | `{rule}` | {count} |\n"));
        }
        s.push('\n');
    }
    s.push_str(
        "Scanned with [writ](https://github.com/writ-agent/writ) `writ scan`: \
         reads local agent transcripts, installs nothing.\n",
    );
    s
}

struct Paint(bool);

impl Paint {
    fn wrap(&self, code: &str, s: &str) -> String {
        if self.0 {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn red(&self, s: &str) -> String {
        self.wrap("1;31", s)
    }
    fn yellow(&self, s: &str) -> String {
        self.wrap("1;33", s)
    }
    fn cyan(&self, s: &str) -> String {
        self.wrap("36", s)
    }
    fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
}

fn text(
    args: &ScanArgs,
    policy_label: &str,
    sources: &BTreeMap<&'static str, Source>,
    findings: &[Finding],
    allowed: usize,
    defaulted: usize,
) {
    let p = Paint(std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none());
    println!();
    println!(
        "  {}  what your AI agents did in the last {} days",
        p.bold("writ scan"),
        args.days
    );
    println!("  {}", p.dim(&format!("judged by {policy_label}")));
    println!();
    for agent in ScanAgent::ALL {
        let Some(s) = sources.get(agent.id()) else {
            continue;
        };
        if s.found_dir.is_none() {
            println!("  {:<12} {}", agent.label(), p.dim("no transcripts found"));
        } else {
            println!(
                "  {:<12} {:>6} tool calls in {} sessions",
                agent.label(),
                s.calls,
                s.sessions.len()
            );
        }
    }
    let total: usize = sources.values().map(|s| s.calls).sum();
    if total == 0 {
        println!();
        println!(
            "  No agent tool calls found in the last {} days.",
            args.days
        );
        println!("  Try a longer window (--days 90) or point --dir at a transcript folder.");
        return;
    }
    let n = |v: &str| findings.iter().filter(|f| f.verdict == v).count();
    println!();
    println!(
        "  {}   {}   {}   {}",
        p.red(&format!("{} would have been BLOCKED", n("deny"))),
        p.yellow(&format!("{} would have ASKED you", n("ask"))),
        p.cyan(&format!("{} outputs scanned for secrets", n("redact"))),
        p.dim(&format!("{} allowed", allowed + defaulted)),
    );
    let rules = by_rule(findings);
    if !rules.is_empty() {
        println!();
        for (verdict, rule, count, f) in &rules {
            let tag = match *verdict {
                "deny" => p.red("BLOCK"),
                _ => p.yellow("ASK  "),
            };
            println!("  {tag} {count:>5}  {}", p.bold(rule));
            println!("               {}", p.dim(&gist(&f.reason)));
            if args.examples > 0 {
                for ex in findings
                    .iter()
                    .filter(|x| x.verdict == *verdict && x.rule_id == *rule)
                    .take(args.examples)
                {
                    let day = ex
                        .when
                        .as_deref()
                        .map(|w| &w[..w.len().min(10)])
                        .unwrap_or("?");
                    let project = ex
                        .cwd
                        .as_deref()
                        .map(|c| c.rsplit(['/', '\\']).next().unwrap_or(c).to_string())
                        .unwrap_or_default();
                    println!(
                        "               {} {} {}",
                        p.dim(day),
                        p.dim(&format!("{:<11}", ex.agent)),
                        clip(&ex.summary, 90)
                    );
                    if !project.is_empty() {
                        println!(
                            "                          {}",
                            p.dim(&format!("in {project}"))
                        );
                    }
                }
            }
        }
    }
    println!();
    println!(
        "  {}",
        p.dim("Transcripts show what the agent asked to run; its own permission prompt may have stopped some of these.")
    );
    println!();
    println!("  Protect every agent here:    {}", p.bold("writ init"));
    println!(
        "  Try one command:             {}",
        p.bold("writ test \"rm -rf ~\"")
    );
    println!(
        "  Share the counts (no commands): {}",
        p.bold("writ scan --format markdown")
    );
    println!();
}

fn clip(s: &str, max: usize) -> String {
    let one: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.chars().count() > max {
        format!("{}…", one.chars().take(max).collect::<String>())
    } else {
        one
    }
}

/// What the call did, in one line.
fn summarize(call: &ToolCall) -> String {
    let s = |k: &str| call.args.get(k).and_then(Value::as_str);
    if let Some(c) = s("command").filter(|_| call.tool == "bash") {
        return c.to_string();
    }
    if let Some(p) = s("path") {
        return format!("{} {p}", call.tool);
    }
    if let Some(q) = s("query").or_else(|| s("sql")) {
        return format!("{} {q}", call.tool);
    }
    if let Some(u) = s("url") {
        return format!("{} {u}", call.tool);
    }
    match &call.server {
        Some(srv) => format!("{} (mcp {})", call.tool, srv.name),
        None => call.tool.clone(),
    }
}

// --- transcripts ------------------------------------------------------------

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn default_dir(agent: ScanAgent) -> Option<PathBuf> {
    match agent {
        ScanAgent::ClaudeCode => std::env::var_os("CLAUDE_CONFIG_DIR")
            .map(PathBuf::from)
            .or_else(|| home().map(|h| h.join(".claude")))
            .map(|d| d.join("projects")),
        ScanAgent::Codex => std::env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .or_else(|| home().map(|h| h.join(".codex")))
            .map(|d| d.join("sessions")),
        ScanAgent::Gemini => home().map(|h| h.join(".gemini").join("tmp")),
    }
}

/// Transcript files under `root` modified since `cutoff` (by mtime).
fn transcript_files(agent: ScanAgent, root: &Path, cutoff: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                if depth < 6 {
                    stack.push((p, depth + 1));
                }
                continue;
            }
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let wanted = match agent {
                ScanAgent::ClaudeCode | ScanAgent::Codex => name.ends_with(".jsonl"),
                ScanAgent::Gemini => {
                    (name.ends_with(".json") || name.ends_with(".jsonl"))
                        && p.parent()
                            .and_then(|d| d.file_name())
                            .is_some_and(|d| d == "chats")
                }
            };
            if !wanted {
                continue;
            }
            let recent = e
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| iso_of(t).as_str() >= cutoff)
                .unwrap_or(true);
            if recent {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

fn read_transcript(agent: ScanAgent, file: &Path, cutoff: &str, sink: &mut dyn FnMut(Found)) {
    let Ok(f) = std::fs::File::open(file) else {
        return;
    };
    let stem = file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    match agent {
        ScanAgent::ClaudeCode => {
            for line in BufReader::new(f).lines().map_while(|l| l.ok()) {
                if !line.contains("\"tool_use\"") {
                    continue;
                }
                let Ok(v) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                claude_line(&v, &stem, cutoff, sink);
            }
        }
        ScanAgent::Codex => {
            let mut session = stem.clone();
            let mut cwd: Option<String> = None;
            for line in BufReader::new(f).lines().map_while(|l| l.ok()) {
                let Ok(v) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                codex_line(&v, &mut session, &mut cwd, cutoff, sink);
            }
        }
        ScanAgent::Gemini => {
            let text = std::fs::read_to_string(file).unwrap_or_default();
            let docs: Vec<Value> = match serde_json::from_str::<Value>(&text) {
                Ok(v) => vec![v],
                Err(_) => text
                    .lines()
                    .filter_map(|l| serde_json::from_str(l).ok())
                    .collect(),
            };
            for d in &docs {
                let session = d
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .unwrap_or(&stem)
                    .to_string();
                gemini_walk(d, &session, cutoff, sink, 0);
            }
        }
    }
}

fn str_of(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_string)
}

fn new_call(
    agent: ScanAgent,
    session: &str,
    id: String,
    tool: String,
    args: Map<String, Value>,
    server: Option<writ_core::call::ServerIdentity>,
) -> ToolCall {
    ToolCall {
        call_id: id,
        session_id: session.to_string(),
        caller: CallerIdentity {
            agent: agent.id().into(),
            agent_version: None,
            user: None,
            non_human_id: None,
        },
        mode: InterceptMode::SdkHook,
        tool,
        args: Value::Object(args),
        server,
        trust: None,
        captured_at: Timestamp::now(),
    }
}

#[allow(clippy::too_many_arguments)]
fn emit(
    agent: ScanAgent,
    session: &str,
    id: &str,
    when: Option<String>,
    cwd: Option<String>,
    name: &str,
    input: Map<String, Value>,
    mcp: Option<&Value>,
    sink: &mut dyn FnMut(Found),
) {
    let calls = crate::hook::native_calls(agent.id(), name, input, cwd.as_deref(), mcp);
    let many = calls.len() > 1;
    for (i, (tool, args, server)) in calls.into_iter().enumerate() {
        let cid = if many {
            format!("{id}#{i}")
        } else {
            id.to_string()
        };
        sink(Found {
            agent,
            session: session.to_string(),
            when: when.clone(),
            cwd: cwd.clone(),
            call: new_call(agent, session, cid, tool, args, server),
        });
    }
}

fn claude_line(v: &Value, stem: &str, cutoff: &str, sink: &mut dyn FnMut(Found)) {
    let when = str_of(v, "timestamp");
    if when.as_deref().is_some_and(|w| w < cutoff) {
        return;
    }
    let session = str_of(v, "sessionId").unwrap_or_else(|| stem.to_string());
    let cwd = str_of(v, "cwd");
    let Some(Value::Array(content)) = v.get("message").and_then(|m| m.get("content")) else {
        return;
    };
    for item in content {
        if item.get("type").and_then(Value::as_str) != Some("tool_use") {
            continue;
        }
        let (Some(id), Some(name)) = (str_of(item, "id"), str_of(item, "name")) else {
            continue;
        };
        let input = match item.get("input") {
            Some(Value::Object(m)) => m.clone(),
            _ => Map::new(),
        };
        emit(
            ScanAgent::ClaudeCode,
            &session,
            &id,
            when.clone(),
            cwd.clone(),
            &name,
            input,
            None,
            sink,
        );
    }
}

/// `["bash", "-lc", "cmd"]` → `cmd`; other argv arrays are joined.
fn codex_argv(argv: &[Value]) -> String {
    let parts: Vec<&str> = argv.iter().filter_map(Value::as_str).collect();
    if parts.len() == 3
        && [
            "bash",
            "sh",
            "zsh",
            "/bin/bash",
            "/bin/sh",
            "/bin/zsh",
            "pwsh",
            "powershell",
            "powershell.exe",
        ]
        .contains(&parts[0])
        && ["-lc", "-c", "-Command", "-command"].contains(&parts[1])
    {
        return parts[2].to_string();
    }
    parts.join(" ")
}

fn codex_line(
    v: &Value,
    session: &mut String,
    cwd: &mut Option<String>,
    cutoff: &str,
    sink: &mut dyn FnMut(Found),
) {
    let kind = v.get("type").and_then(Value::as_str).unwrap_or("");
    let Some(p) = v.get("payload") else { return };
    if kind == "session_meta" {
        if let Some(id) = str_of(p, "id") {
            *session = id;
        }
        if let Some(c) = str_of(p, "cwd") {
            *cwd = Some(c);
        }
        return;
    }
    if kind == "turn_context" {
        if let Some(c) = str_of(p, "cwd") {
            *cwd = Some(c);
        }
        return;
    }
    if kind != "response_item" {
        return;
    }
    let when = str_of(v, "timestamp");
    if when.as_deref().is_some_and(|w| w < cutoff) {
        return;
    }
    let ptype = p.get("type").and_then(Value::as_str).unwrap_or("");
    let id = str_of(p, "call_id")
        .or_else(|| str_of(p, "id"))
        .unwrap_or_default();
    let (name, mut input) = match ptype {
        "function_call" => {
            let args = p
                .get("arguments")
                .and_then(Value::as_str)
                .and_then(|a| serde_json::from_str::<Value>(a).ok())
                .and_then(|a| a.as_object().cloned())
                .unwrap_or_default();
            (str_of(p, "name").unwrap_or_default(), args)
        }
        "custom_tool_call" => {
            let mut m = Map::new();
            if let Some(i) = p.get("input") {
                m.insert("command".into(), i.clone());
            }
            (str_of(p, "name").unwrap_or_default(), m)
        }
        "local_shell_call" => {
            let mut m = Map::new();
            if let Some(Value::Array(argv)) = p.get("action").and_then(|a| a.get("command")) {
                m.insert("command".into(), json!(codex_argv(argv)));
            }
            ("local_shell".to_string(), m)
        }
        _ => return,
    };
    if name.is_empty() || id.is_empty() {
        return;
    }
    // Shell calls: `cmd` or an argv array → one command string.
    let shell = matches!(
        name.as_str(),
        "shell" | "shell_command" | "local_shell" | "exec_command" | "container.exec"
    );
    let name = if shell { "Bash".to_string() } else { name };
    if shell {
        if let Some(Value::Array(argv)) = input.get("command").cloned() {
            input.insert("command".into(), json!(codex_argv(&argv)));
        } else if !input.contains_key("command") {
            if let Some(c) = input.get("cmd").cloned() {
                input.insert("command".into(), c);
            }
        }
    }
    let here = input
        .get("workdir")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| cwd.clone());
    emit(
        ScanAgent::Codex,
        session,
        &id,
        when,
        here,
        &name,
        input,
        None,
        sink,
    );
}

/// Gemini CLI chat recordings: find `{name, args}` tool-call objects
/// anywhere in the document (the recording format has changed between
/// releases; the tool-call shape has not).
fn gemini_walk(v: &Value, session: &str, cutoff: &str, sink: &mut dyn FnMut(Found), depth: usize) {
    if depth > 12 {
        return;
    }
    match v {
        Value::Object(m) => {
            if let (Some(Value::String(name)), Some(Value::Object(args))) =
                (m.get("name"), m.get("args"))
            {
                let when = str_of(v, "timestamp");
                if when.as_deref().is_none_or(|w| w >= cutoff) {
                    let id = str_of(v, "id").unwrap_or_else(|| {
                        format!(
                            "{}:{}",
                            name,
                            writ_core::ledger::LedgerRecord::hash_bytes(
                                serde_json::to_string(args).unwrap_or_default().as_bytes()
                            )
                        )
                    });
                    emit(
                        ScanAgent::Gemini,
                        session,
                        &id,
                        when,
                        None,
                        name,
                        args.clone(),
                        m.get("mcp_context"),
                        sink,
                    );
                }
                return;
            }
            for child in m.values() {
                gemini_walk(child, session, cutoff, sink, depth + 1);
            }
        }
        Value::Array(a) => {
            for child in a {
                gemini_walk(child, session, cutoff, sink, depth + 1);
            }
        }
        _ => {}
    }
}

// --- time ---------------------------------------------------------------------

/// `YYYY-MM-DDTHH:MM:SS` (UTC) of a system time; ISO strings compare in
/// time order.
fn iso_of(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn iso_days_ago(days: u32) -> String {
    let now = std::time::SystemTime::now();
    iso_of(now - std::time::Duration::from_secs(u64::from(days) * 86_400))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_dates() {
        assert_eq!(iso_of(std::time::UNIX_EPOCH), "1970-01-01T00:00:00");
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_790_000_000);
        assert_eq!(iso_of(t), "2026-09-21T14:13:20");
    }

    #[test]
    fn codex_argv_unwraps_shell_c() {
        let v: Vec<Value> = vec![json!("bash"), json!("-lc"), json!("rm -rf ~")];
        assert_eq!(codex_argv(&v), "rm -rf ~");
        let v: Vec<Value> = vec![json!("ls"), json!("-la")];
        assert_eq!(codex_argv(&v), "ls -la");
    }

    #[test]
    fn gist_drops_the_script_prefix() {
        assert_eq!(
            gist("script ./x.sh line 3 runs `rm -rf ~`. Recursive delete of home. More."),
            "Recursive delete of home."
        );
        assert_eq!(gist("Shuts down this machine."), "Shuts down this machine.");
    }
}
