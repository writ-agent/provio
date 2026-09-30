//! `writ report`: what your agents did, as one self-contained page (or
//! Markdown for a pull request, or JSON), straight from the ledger.
//!
//! The report leads with what matters after an unattended run: what writ
//! stopped, what needed a human and what they decided, then a timeline per
//! session and the ledger's integrity. With `--sign <key>` it embeds a
//! signed receipt over the ledger, so whoever receives the report can check
//! it against the ledger with `writ receipt verify` instead of trusting the
//! page.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use writ_core::ledger::{LedgerRecord, RecordKind};
use writ_core::verdict::Verdict;
use writ_core::Timestamp;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ReportFormat {
    /// A single self-contained HTML page.
    Html,
    /// Markdown, for a pull request or a chat message.
    Markdown,
    /// Everything, machine-readable.
    Json,
}

#[derive(clap::Args, Debug)]
pub struct ReportArgs {
    /// Output file (default: writ-report.html / .md / .json; `-` for stdout).
    #[arg(long)]
    pub out: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ReportFormat::Html)]
    pub format: ReportFormat,
    /// Only records from this long ago: `12h`, `90m`, `2d`, or an RFC 3339
    /// time.
    #[arg(long)]
    pub since: Option<String>,
    /// Only this session (see `writ log`).
    #[arg(long)]
    pub session: Option<String>,
    /// Sign a receipt over the ledger with this key (`writ receipt keygen`)
    /// and embed it, with the command that verifies it.
    #[arg(long, value_name = "KEY")]
    pub sign: Option<PathBuf>,
}

/// One decision, with what happened to it.
struct Row {
    rec: LedgerRecord,
    /// Exit status of its execution record, when the call ran.
    ran: Option<i32>,
}

impl Row {
    fn kind(&self) -> &'static str {
        match &self.rec.verdict {
            Some(Verdict::Allow { .. }) => "allow",
            Some(Verdict::Deny { .. }) => "deny",
            Some(Verdict::Ask { .. }) => "ask",
            Some(Verdict::Redact { .. }) => "redact",
            None => "?",
        }
    }
    fn rule(&self) -> String {
        match &self.rec.verdict {
            Some(Verdict::Allow { rule_id }) => rule_id.clone().unwrap_or_else(|| "default".into()),
            Some(Verdict::Deny { rule_id, .. })
            | Some(Verdict::Ask { rule_id, .. })
            | Some(Verdict::Redact { rule_id, .. }) => rule_id.clone(),
            None => String::new(),
        }
    }
    fn reason(&self) -> String {
        match &self.rec.verdict {
            Some(Verdict::Deny { reason, .. }) => reason.clone(),
            Some(Verdict::Ask { diff, .. }) => diff.clone(),
            _ => String::new(),
        }
    }
    fn tool(&self) -> String {
        self.rec
            .call
            .as_ref()
            .map(|c| match &c.server {
                Some(s) => format!("{} ({})", c.tool, s.name),
                None => c.tool.clone(),
            })
            .unwrap_or_else(|| "?".into())
    }
    fn agent(&self) -> String {
        self.rec
            .call
            .as_ref()
            .map(|c| c.caller.agent.clone())
            .unwrap_or_default()
    }
    fn what(&self) -> String {
        let Some(c) = &self.rec.call else {
            return String::new();
        };
        let s = |k: &str| c.args.get(k).and_then(Value::as_str);
        s("command")
            .or_else(|| s("path"))
            .or_else(|| s("url"))
            .or_else(|| s("query"))
            .or_else(|| s("sql"))
            .map(str::to_string)
            .unwrap_or_else(|| {
                let t = c.args.to_string();
                if t == "null" || t == "{}" {
                    String::new()
                } else {
                    t
                }
            })
    }
    /// Who decided an ask, and how it ended.
    fn outcome(&self) -> String {
        match (&self.rec.verdict, &self.rec.approver, self.ran) {
            (Some(Verdict::Ask { .. }), Some(a), Some(_)) => format!("approved by {}", a.id),
            (Some(Verdict::Ask { .. }), Some(a), None) if a.id.starts_with("fail-closed") => {
                "refused: no human was there to approve it".into()
            }
            (Some(Verdict::Ask { .. }), Some(a), None) => format!("declined by {}", a.id),
            (Some(Verdict::Ask { .. }), None, Some(_)) => "approved in the agent's prompt".into(),
            (Some(Verdict::Ask { .. }), None, None) => "not run".into(),
            (_, _, Some(code)) => format!("ran, exit {code}"),
            (Some(Verdict::Deny { .. }), _, None) => "stopped".into(),
            _ => "not run".into(),
        }
    }
}

/// `12h`, `90m`, `2d`, `45s` or RFC 3339 → the cut-off time.
fn parse_since(s: &str) -> Result<Timestamp> {
    let s = s.trim();
    if let Some(t) = writ_core::time::parse_rfc3339(s) {
        return Ok(t);
    }
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: i64 = num
        .parse()
        .map_err(|_| anyhow!("--since {s:?}: use 12h, 90m, 2d, 45s or an RFC 3339 time"))?;
    let ms = match unit {
        "s" => n * 1_000,
        "m" => n * 60_000,
        "h" => n * 3_600_000,
        "d" => n * 86_400_000,
        _ => bail!("--since {s:?}: use 12h, 90m, 2d, 45s or an RFC 3339 time"),
    };
    Ok(Timestamp::from_epoch_ms(Timestamp::now().epoch_ms() - ms))
}

pub fn report(ledger: &Path, args: &ReportArgs) -> Result<()> {
    if !crate::cmds::ledger_present(ledger) {
        bail!("no ledger at {}", crate::cmds::show_ledger(ledger));
    }
    let since = args.since.as_deref().map(parse_since).transpose()?;
    let store = writ_ledger::open_store(ledger).map_err(|e| anyhow!(e.to_string()))?;
    let mut rows: Vec<Row> = Vec::new();
    let mut by_index: HashMap<u64, usize> = HashMap::new();
    let mut total_records = 0u64;
    for rec in store.iter() {
        let rec = rec.map_err(|e| anyhow!(e.to_string()))?;
        total_records += 1;
        match rec.kind {
            RecordKind::Decision => {
                if since.is_some_and(|t| rec.recorded_at.epoch_ms() < t.epoch_ms()) {
                    continue;
                }
                if args.session.as_deref().is_some_and(|s| s != rec.session_id) {
                    continue;
                }
                by_index.insert(rec.index, rows.len());
                rows.push(Row { rec, ran: None });
            }
            RecordKind::Execution => {
                if let Some(i) = rec.decision_index.and_then(|d| by_index.get(&d)) {
                    rows[*i].ran = Some(rec.exit_status.unwrap_or(0));
                }
            }
        }
    }
    let verify = writ_ledger::verify(ledger).map_err(|e| anyhow!(e.to_string()))?;
    let receipt = match &args.sign {
        Some(key) => Some(crate::receipt::sign_receipt(
            ledger,
            key,
            args.session.as_deref(),
        )?),
        None => None,
    };

    let ext = match args.format {
        ReportFormat::Html => "html",
        ReportFormat::Markdown => "md",
        ReportFormat::Json => "json",
    };
    let out = args
        .out
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("writ-report.{ext}")));
    let scope = Scope {
        ledger: crate::cmds::show_ledger(ledger),
        since: args.since.clone(),
        session: args.session.clone(),
        total_records,
        intact: verify.intact,
        broken_at: verify.broken_at,
        verified: verify.records,
    };
    let text = match args.format {
        ReportFormat::Html => html(&rows, &scope, receipt.as_ref())?,
        ReportFormat::Markdown => markdown(&rows, &scope, receipt.as_ref())?,
        ReportFormat::Json => {
            serde_json::to_string_pretty(&json_report(&rows, &scope, receipt.as_ref())?)?
        }
    };
    if out.as_os_str() == "-" {
        print!("{text}");
        return Ok(());
    }
    std::fs::write(&out, &text)?;
    if let Some(r) = &receipt {
        let rpath = out.with_extension("receipt.json");
        std::fs::write(&rpath, r.to_json().map_err(|e| anyhow!(e.to_string()))?)?;
        eprintln!(
            "  receipt  {} (signer {})",
            rpath.display(),
            r.checkpoint.signer
        );
    }
    println!(
        "wrote {} · {} decisions · self-contained, open it anywhere",
        out.display(),
        rows.len()
    );
    Ok(())
}

struct Scope {
    ledger: String,
    since: Option<String>,
    session: Option<String>,
    total_records: u64,
    intact: bool,
    broken_at: Option<u64>,
    verified: u64,
}

impl Scope {
    fn describe(&self) -> String {
        let mut parts = vec![format!("ledger {}", self.ledger)];
        if let Some(s) = &self.since {
            parts.push(format!("since {s}"));
        }
        if let Some(s) = &self.session {
            parts.push(format!("session {s}"));
        }
        parts.join(" · ")
    }
    fn integrity(&self) -> String {
        if self.intact {
            format!(
                "chain intact · {} records verified · no gaps",
                self.verified
            )
        } else {
            format!(
                "chain BROKEN at record {} ({} records verified before the break)",
                self.broken_at.unwrap_or(0),
                self.verified
            )
        }
    }
}

struct Counts {
    calls: usize,
    ran: usize,
    stopped: usize,
    asked: usize,
    masked: usize,
    sessions: usize,
    agents: Vec<String>,
    first: Option<String>,
    last: Option<String>,
}

fn counts(rows: &[Row]) -> Counts {
    let mut sessions = std::collections::BTreeSet::new();
    let mut agents = std::collections::BTreeSet::new();
    for r in rows {
        sessions.insert(r.rec.session_id.clone());
        let a = r.agent();
        if !a.is_empty() {
            agents.insert(a);
        }
    }
    Counts {
        calls: rows.len(),
        ran: rows.iter().filter(|r| r.ran.is_some()).count(),
        stopped: rows.iter().filter(|r| r.kind() == "deny").count(),
        asked: rows.iter().filter(|r| r.kind() == "ask").count(),
        masked: rows.iter().filter(|r| r.kind() == "redact").count(),
        sessions: sessions.len(),
        agents: agents.into_iter().collect(),
        first: rows.first().map(|r| r.rec.recorded_at.to_rfc3339()),
        last: rows.last().map(|r| r.rec.recorded_at.to_rfc3339()),
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn clip(s: &str, n: usize) -> String {
    let one: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.chars().count() > n {
        format!("{}…", one.chars().take(n).collect::<String>())
    } else {
        one
    }
}

fn hhmm(t: &Timestamp) -> String {
    let s = t.to_rfc3339();
    s.get(0..19).unwrap_or(&s).replace('T', " ")
}

fn html(rows: &[Row], scope: &Scope, receipt: Option<&writ_receipts::Receipt>) -> Result<String> {
    let c = counts(rows);
    let mut body = String::new();
    let period = match (&c.first, &c.last) {
        (Some(a), Some(b)) => format!(
            "{} → {}",
            a[..a.len().min(16)].replace('T', " "),
            b[..b.len().min(16)].replace('T', " ")
        ),
        _ => "no decisions in scope".into(),
    };
    body.push_str(&format!(
        "<header><h1>What your agents did</h1><p class=\"sub\">{} · {} session(s) · {}</p><p class=\"sub\">{}</p></header>",
        esc(&period),
        c.sessions,
        esc(&if c.agents.is_empty() { "—".to_string() } else { c.agents.join(", ") }),
        esc(&scope.describe())
    ));
    body.push_str(&format!(
        "<div class=\"cards\"><div class=\"card\"><b>{}</b>tool calls</div><div class=\"card\"><b>{}</b>ran</div><div class=\"card deny\"><b>{}</b>stopped by writ</div><div class=\"card ask\"><b>{}</b>needed a human</div><div class=\"card redact\"><b>{}</b>output masked</div></div>",
        c.calls, c.ran, c.stopped, c.asked, c.masked
    ));

    let stopped: Vec<&Row> = rows.iter().filter(|r| r.kind() == "deny").collect();
    body.push_str("<h2>Stopped by writ</h2>");
    if stopped.is_empty() {
        body.push_str("<p class=\"muted\">Nothing was refused in this period.</p>");
    } else {
        body.push_str("<table><thead><tr><th>time (UTC)</th><th>agent</th><th>call</th><th>rule</th><th>why</th></tr></thead><tbody>");
        for r in stopped {
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td><code>{}</code> {}</td><td><span class=\"badge deny\">{}</span></td><td>{}</td></tr>",
                esc(&hhmm(&r.rec.recorded_at)),
                esc(&r.agent()),
                esc(&r.tool()),
                esc(&clip(&r.what(), 140)),
                esc(&r.rule()),
                esc(&clip(&r.reason(), 260))
            ));
        }
        body.push_str("</tbody></table>");
    }

    let asked: Vec<&Row> = rows.iter().filter(|r| r.kind() == "ask").collect();
    body.push_str("<h2>Needed a human</h2>");
    if asked.is_empty() {
        body.push_str("<p class=\"muted\">No call waited for approval.</p>");
    } else {
        body.push_str("<table><thead><tr><th>time (UTC)</th><th>agent</th><th>call</th><th>rule</th><th>outcome</th></tr></thead><tbody>");
        for r in asked {
            body.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td><code>{}</code> {}</td><td><span class=\"badge ask\">{}</span></td><td>{}</td></tr>",
                esc(&hhmm(&r.rec.recorded_at)),
                esc(&r.agent()),
                esc(&r.tool()),
                esc(&clip(&r.what(), 140)),
                esc(&r.rule()),
                esc(&r.outcome())
            ));
        }
        body.push_str("</tbody></table>");
    }

    body.push_str("<h2>Timeline</h2>");
    let mut sessions: BTreeMap<String, Vec<&Row>> = BTreeMap::new();
    for r in rows {
        sessions
            .entry(r.rec.session_id.clone())
            .or_default()
            .push(r);
    }
    for (sid, rs) in &sessions {
        let denied = rs.iter().filter(|r| r.kind() == "deny").count();
        body.push_str(&format!(
            "<details{}><summary><code>{}</code> · {} calls{}</summary><table><tbody>",
            if denied > 0 { " open" } else { "" },
            esc(sid),
            rs.len(),
            if denied > 0 {
                format!(" · <span class=\"badge deny\">{denied} stopped</span>")
            } else {
                String::new()
            }
        ));
        for r in rs {
            body.push_str(&format!(
                "<tr><td>#{}</td><td>{}</td><td><span class=\"badge {}\">{}</span></td><td><code>{}</code> {}</td><td>{}</td><td>{}</td></tr>",
                r.rec.index,
                esc(&hhmm(&r.rec.recorded_at)),
                r.kind(),
                r.kind(),
                esc(&r.tool()),
                esc(&clip(&r.what(), 120)),
                esc(&r.rule()),
                esc(&r.outcome())
            ));
        }
        body.push_str("</tbody></table></details>");
    }

    body.push_str("<h2>Integrity</h2>");
    body.push_str(&format!(
        "<p class=\"{}\">{}</p>",
        if scope.intact { "ok" } else { "bad" },
        esc(&scope.integrity())
    ));
    match receipt {
        Some(r) => {
            let cp = &r.checkpoint;
            body.push_str(&format!(
                "<p>Signed receipt over records 0..={} (tip <code>{}</code>, Merkle root <code>{}</code>), signer <code>{}</code>, at {}.</p>\
                 <p>Check this report against the ledger instead of trusting the page: save the receipt below as <code>receipt.json</code> (writ also wrote it next to this file) and run</p>\
                 <pre>writ receipt verify receipt.json --pubkey &lt;signer's public key&gt;</pre>\
                 <details><summary>receipt.json</summary><pre>{}</pre></details>",
                cp.tip_index,
                esc(&cp.tip_hash[..cp.tip_hash.len().min(16)]),
                esc(&cp.merkle_root[..cp.merkle_root.len().min(16)]),
                esc(&cp.signer),
                esc(&cp.created_at),
                esc(&r.to_json().map_err(|e| anyhow!(e.to_string()))?)
            ));
        }
        None => body.push_str(
            "<p class=\"muted\">Unsigned. <code>writ report --sign &lt;key&gt;</code> embeds a signed receipt that anyone can verify against the ledger.</p>",
        ),
    }
    Ok(format!(
        include_str!("report_template.html"),
        title = "writ report",
        body = body,
        generated = esc(&Timestamp::now().to_rfc3339()),
        version = env!("CARGO_PKG_VERSION"),
    ))
}

fn markdown(
    rows: &[Row],
    scope: &Scope,
    receipt: Option<&writ_receipts::Receipt>,
) -> Result<String> {
    let c = counts(rows);
    let md = |s: &str| s.replace('|', "\\|").replace('`', "'");
    let mut s = format!(
        "### What the agents did\n\n{} tool calls in {} session(s) ({}): **{} stopped by writ**, {} needed a human, {} ran.\n\n",
        c.calls,
        c.sessions,
        if c.agents.is_empty() { "—".into() } else { c.agents.join(", ") },
        c.stopped,
        c.asked,
        c.ran
    );
    let stopped: Vec<&Row> = rows.iter().filter(|r| r.kind() == "deny").collect();
    if !stopped.is_empty() {
        s.push_str("| stopped | rule | call |\n|---|---|---|\n");
        for r in stopped.iter().take(50) {
            s.push_str(&format!(
                "| {} | `{}` | `{}` {} |\n",
                hhmm(&r.rec.recorded_at),
                md(&r.rule()),
                md(&r.tool()),
                md(&clip(&r.what(), 100))
            ));
        }
        s.push('\n');
    }
    let asked: Vec<&Row> = rows.iter().filter(|r| r.kind() == "ask").collect();
    if !asked.is_empty() {
        s.push_str("| needed a human | rule | outcome |\n|---|---|---|\n");
        for r in asked.iter().take(50) {
            s.push_str(&format!(
                "| {} `{}` | `{}` | {} |\n",
                hhmm(&r.rec.recorded_at),
                md(&clip(&r.what(), 80)),
                md(&r.rule()),
                md(&r.outcome())
            ));
        }
        s.push('\n');
    }
    s.push_str(&format!(
        "Ledger: {} ({}).",
        scope.integrity(),
        md(&scope.describe())
    ));
    if let Some(r) = receipt {
        s.push_str(&format!(
            " Signed receipt: tip `{}`, signer `{}` (verify with `writ receipt verify`).",
            &r.checkpoint.tip_hash[..r.checkpoint.tip_hash.len().min(16)],
            md(&r.checkpoint.signer)
        ));
    }
    s.push('\n');
    Ok(s)
}

fn json_report(
    rows: &[Row],
    scope: &Scope,
    receipt: Option<&writ_receipts::Receipt>,
) -> Result<Value> {
    let c = counts(rows);
    Ok(json!({
        "scope": { "ledger": scope.ledger, "since": scope.since, "session": scope.session },
        "totals": { "calls": c.calls, "ran": c.ran, "stopped": c.stopped, "asked": c.asked, "masked": c.masked, "sessions": c.sessions, "agents": c.agents },
        "integrity": { "intact": scope.intact, "records": scope.total_records, "verified": scope.verified, "broken_at": scope.broken_at },
        "decisions": rows.iter().map(|r| json!({
            "index": r.rec.index,
            "session": r.rec.session_id,
            "at": r.rec.recorded_at.to_rfc3339(),
            "agent": r.agent(),
            "tool": r.tool(),
            "what": r.what(),
            "verdict": r.kind(),
            "rule": r.rule(),
            "reason": r.reason(),
            "outcome": r.outcome(),
        })).collect::<Vec<_>>(),
        "receipt": match receipt {
            Some(r) => serde_json::from_str::<Value>(&r.to_json().map_err(|e| anyhow!(e.to_string()))?)?,
            None => Value::Null,
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_parses_durations_and_times() {
        let now = Timestamp::now().epoch_ms();
        let t = parse_since("2h").unwrap().epoch_ms();
        assert!((now - t - 7_200_000).abs() < 5_000);
        assert!(parse_since("2026-09-01T00:00:00Z").is_ok());
        assert!(parse_since("soon").is_err());
        assert!(parse_since("3w").is_err());
    }
}
