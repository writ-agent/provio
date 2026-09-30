//! Read-only, incremental view of the ledger for the console.
//!
//! JSONL ledgers are tailed directly (byte offset; complete lines only; no
//! lock taken, nothing written or repaired). SQLite ledgers are read through
//! `provio_ledger::open_store` (iteration only). The console never appends:
//! its own records (sandbox runs) go through `LedgerWriter` like every
//! other writer.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use provio_core::ledger::{LedgerRecord, RecordKind};
use provio_core::verdict::Verdict;
use provio_ledger::StoreKind;
use serde_json::{json, Value};

pub(crate) struct LedgerView {
    path: PathBuf,
    offset: u64,
    pub records: Vec<LedgerRecord>,
    /// decision index → execution record positions
    execs: HashMap<u64, Vec<usize>>,
    pub error: Option<String>,
    /// Bumped whenever the view changes.
    pub version: u64,
}

impl LedgerView {
    pub fn new(path: &Path) -> Self {
        LedgerView {
            path: path.to_path_buf(),
            offset: 0,
            records: Vec::new(),
            execs: HashMap::new(),
            error: None,
            version: 0,
        }
    }

    fn reset(&mut self) {
        self.offset = 0;
        self.records.clear();
        self.execs.clear();
        self.version += 1;
    }

    fn push(&mut self, rec: LedgerRecord, affected: &mut Vec<u64>) {
        let pos = self.records.len();
        match rec.kind {
            RecordKind::Decision => affected.push(rec.index),
            RecordKind::Execution => {
                if let Some(d) = rec.decision_index {
                    self.execs.entry(d).or_default().push(pos);
                    affected.push(d);
                }
            }
        }
        self.records.push(rec);
    }

    /// Read what was appended since the last call. Returns the decision
    /// indices whose summary changed (new decisions and decisions that
    /// gained an execution). A ledger that shrank or was replaced is
    /// re-read from the start.
    pub fn refresh(&mut self) -> Vec<u64> {
        let mut affected = Vec::new();
        let pg = self
            .path
            .to_str()
            .is_some_and(provio_ledger::is_postgres_url);
        if !pg && !self.path.exists() {
            if !self.records.is_empty() {
                self.reset();
            }
            self.error = None;
            return affected;
        }
        let kind = match provio_ledger::detect_store_kind(&self.path) {
            Ok(k) => k,
            Err(e) => {
                self.error = Some(e.to_string());
                return affected;
            }
        };
        let before = self.records.len();
        match kind {
            StoreKind::Jsonl => self.refresh_jsonl(&mut affected),
            StoreKind::Sqlite | StoreKind::Postgres => self.refresh_store(&mut affected),
        }
        if self.records.len() != before {
            self.version += 1;
        }
        affected.sort_unstable();
        affected.dedup();
        affected
    }

    fn refresh_jsonl(&mut self, affected: &mut Vec<u64>) {
        let mut f = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) => {
                self.error = Some(e.to_string());
                return;
            }
        };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if len < self.offset {
            self.reset();
        }
        if len == self.offset {
            return;
        }
        if f.seek(SeekFrom::Start(self.offset)).is_err() {
            return;
        }
        let mut buf = Vec::new();
        if f.take(len - self.offset).read_to_end(&mut buf).is_err() {
            return;
        }
        // Only complete lines; an unterminated tail is a write in progress.
        let Some(end) = buf.iter().rposition(|b| *b == b'\n') else {
            return;
        };
        let mut consumed = 0usize;
        for line in buf[..=end].split(|b| *b == b'\n') {
            let n = line.len() + 1;
            let text = String::from_utf8_lossy(line);
            let t = text.trim();
            if t.is_empty() {
                consumed += n;
                continue;
            }
            match serde_json::from_str::<LedgerRecord>(t) {
                Ok(rec) => {
                    if rec.index != self.records.len() as u64 && self.error.is_none() {
                        self.error = Some(format!(
                            "record at position {} carries index {} — run verify",
                            self.records.len(),
                            rec.index
                        ));
                    }
                    self.push(rec, affected);
                    consumed += n;
                }
                Err(e) => {
                    self.error = Some(format!(
                        "record at position {} is not a valid ledger record ({e}) — run verify",
                        self.records.len()
                    ));
                    // Stop here; records after a corrupt line are not shown.
                    break;
                }
            }
        }
        self.offset += consumed.min(end + 1) as u64;
    }

    fn refresh_store(&mut self, affected: &mut Vec<u64>) {
        let store = match provio_ledger::open_store(&self.path) {
            Ok(s) => s,
            Err(e) => {
                self.error = Some(e.to_string());
                return;
            }
        };
        if store.len() < self.records.len() as u64 {
            self.reset();
        }
        let have = self.records.len() as u64;
        for item in store.iter() {
            match item {
                Ok(rec) if rec.index < have => {}
                Ok(rec) => self.push(rec, affected),
                Err(e) => {
                    self.error = Some(e.to_string());
                    break;
                }
            }
        }
    }

    pub fn decision(&self, index: u64) -> Option<&LedgerRecord> {
        let r = self.records.get(usize::try_from(index).ok()?)?;
        (r.index == index && r.kind == RecordKind::Decision)
            .then_some(r)
            .or_else(|| {
                self.records
                    .iter()
                    .find(|r| r.index == index && r.kind == RecordKind::Decision)
            })
    }

    pub fn executions(&self, decision: u64) -> Vec<&LedgerRecord> {
        self.execs
            .get(&decision)
            .map(|v| v.iter().filter_map(|p| self.records.get(*p)).collect())
            .unwrap_or_default()
    }

    pub fn decisions(&self) -> impl DoubleEndedIterator<Item = &LedgerRecord> {
        self.records
            .iter()
            .filter(|r| r.kind == RecordKind::Decision)
    }
}

/// One line of text describing what the call does.
pub(crate) fn summarize(args: &Value) -> String {
    let pick = [
        "command",
        "cmd",
        "path",
        "file_path",
        "url",
        "uri",
        "query",
        "sql",
    ];
    let s = match args {
        Value::Object(m) => pick
            .iter()
            .find_map(|k| m.get(*k).and_then(Value::as_str).map(str::to_string))
            .or_else(|| {
                m.values().next().map(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| v.to_string())
                })
            })
            .unwrap_or_default(),
        Value::Null => String::new(),
        other => other.to_string(),
    };
    let s = s.replace(['\n', '\r'], " ");
    if s.chars().count() > 160 {
        format!("{}…", s.chars().take(159).collect::<String>())
    } else {
        s
    }
}

pub(crate) fn verdict_kind(v: &Verdict) -> &'static str {
    match v {
        Verdict::Allow { .. } => "allow",
        Verdict::Deny { .. } => "deny",
        Verdict::Ask { .. } => "ask",
        Verdict::Redact { .. } => "redact",
    }
}

/// Summary of one decision (and its execution) for the feed.
pub(crate) fn summary(view: &LedgerView, rec: &LedgerRecord, pending: &[u64]) -> Value {
    let call = rec.call.as_ref();
    let verdict = rec.verdict.as_ref();
    let execs = view.executions(rec.index);
    let exec = execs.first();
    let kind = verdict.map(verdict_kind).unwrap_or("?");
    let (reason, location) = match verdict {
        Some(Verdict::Deny {
            reason, location, ..
        }) => (Some(reason.clone()), location.clone()),
        Some(Verdict::Ask { diff, location, .. }) => (Some(diff.clone()), location.clone()),
        _ => (None, None),
    };
    // What happened to the call, in one word.
    let outcome = match (kind, exec) {
        (_, Some(_)) if kind == "ask" => "approved",
        (_, Some(_)) => "ran",
        ("allow" | "redact", None) => "allowed",
        ("deny", None) => "blocked",
        ("ask", None) if pending.contains(&rec.index) => "waiting",
        ("ask", None) if rec.approver.is_some() => "blocked",
        ("ask", None) => "not run",
        _ => "?",
    };
    json!({
        "index": rec.index,
        "call_id": rec.call_id,
        "session_id": rec.session_id,
        "recorded_at": rec.recorded_at.to_rfc3339(),
        "recorded_ms": rec.recorded_at.epoch_ms(),
        "tool": call.map(|c| c.tool.as_str()).unwrap_or("?"),
        "summary": call.map(|c| summarize(&c.args)).unwrap_or_default(),
        "agent": call.map(|c| c.caller.agent.as_str()).unwrap_or("?"),
        "mode": call.map(|c| serde_json::to_value(c.mode).unwrap_or(Value::Null)),
        "server": call.and_then(|c| c.server.as_ref()).map(|s| s.name.clone()),
        "verdict": kind,
        "rule_id": rec.rule_id,
        "reason": reason,
        "location": location,
        "approver": rec.approver.as_ref().or(exec.and_then(|e| e.approver.as_ref())),
        "outcome": outcome,
        "exec": exec.map(|e| json!({
            "index": e.index,
            "exit_status": e.exit_status,
            "backend": e.backend,
            "approver": e.approver,
            "recorded_at": e.recorded_at.to_rfc3339(),
        })),
    })
}
