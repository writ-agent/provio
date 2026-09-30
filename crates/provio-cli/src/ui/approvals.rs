//! `provio check --ask ui`: the approval queue between the hook gateway and
//! the `provio ui` console.
//!
//! # Flow
//!
//! 1. The gateway records the `Decision` (engine verdict `ask`, no approver)
//!    first, so a pending ask is on the ledger before anyone waits for it.
//! 2. It checks that a console is serving this ledger (a fresh heartbeat,
//!    see below). No console: deny at once (fail closed).
//! 3. It writes a request, `<ledger dir>/pending/<id>.json`, atomically
//!    (temp file + rename). `<id>` is `<decision index>-<first 16 hex of
//!    its record_hash>`.
//! 4. It polls for `<console dir>/decisions/<id>.json` until the ask's
//!    `timeout_ms` (default [`DEFAULT_TIMEOUT_MS`]) runs out. A decision
//!    counts only if it names this exact record hash and an approver of the
//!    form `web-console:<user>`. Timeout, a vanished console, a malformed
//!    file or any I/O error: deny.
//! 5. The request file is removed however the wait ends.
//!
//! # Why decisions live somewhere else
//!
//! The ledger directory is writable by the agent under `provio run` (the
//! gateway runs inside the agent's boundary and must append there). If the
//! console's answers were written next to the ledger, a confined agent could
//! approve its own asks. So the console keeps its heartbeat and decisions in
//! a per-user state directory that `provio run` never grants:
//! `%LOCALAPPDATA%\provio\ui\<key>` on Windows,
//! `$XDG_STATE_HOME/provio/ui/<key>` (else `~/.local/state/provio/ui/<key>`)
//! elsewhere, `<key>` being derived from the canonical ledger path. The
//! gateway reads it (reads are not confined) but cannot write it. The
//! gateway refuses a state directory inside its ledger directory or its
//! working directory.
//!
//! The console, for its part, never trusts the request file's description of
//! the call: it shows the call from the ledger record the request names
//! (index + hash), and ignores requests that do not match an `ask` decision
//! without an execution.
//!
//! An approval is evidenced on the ledger by the `Execution` record written
//! at `complete` (provio format) or `PostToolUse` (claude-code format), whose
//! approver is `{kind: tui, id: "web-console:<user>"}`; a denial writes
//! nothing further (an `ask` with no execution = never dispatched), exactly
//! as for `--ask defer`.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use provio_core::approver::{ApproverIdentity, ApproverKind};
use provio_core::ledger::LedgerRecord;
use provio_core::verdict::Verdict;
use provio_core::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Wait when the `ask` rule has no `timeout`.
pub(crate) const DEFAULT_TIMEOUT_MS: u64 = 120_000;
/// Upper bound on a `--format claude-code` wait: Claude Code does not block
/// the tool when a hook times out (its default command-hook timeout has
/// been 60 s), so provio answers "deny" before that can happen.
pub(crate) const CLAUDE_CODE_CAP_MS: u64 = 55_000;
/// A console heartbeat older than this means no console.
pub(crate) const HEARTBEAT_STALE_MS: i64 = 10_000;
/// How often the console refreshes its heartbeat.
pub(crate) const HEARTBEAT_EVERY: Duration = Duration::from_secs(2);
/// Prefix of every approver id the console records.
pub(crate) const APPROVER_PREFIX: &str = "web-console:";
const POLL: Duration = Duration::from_millis(150);

/// What the gateway writes for the console.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PendingRequest {
    pub v: u32,
    pub id: String,
    /// Decision record index + hash: the console validates both.
    pub index: u64,
    pub record_hash: String,
    pub created_ms: i64,
    pub deadline_ms: i64,
    /// Informational only (the console shows the ledger's copy of the call).
    pub rule_id: String,
    pub format: String,
    pub pid: u32,
}

/// What the console writes for the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ConsoleDecision {
    pub v: u32,
    pub id: String,
    pub record_hash: String,
    pub approved: bool,
    pub approver: String,
    pub decided_ms: i64,
}

/// The console's heartbeat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Heartbeat {
    pub pid: u32,
    pub port: u16,
    pub started_ms: i64,
    pub updated_ms: i64,
    pub ledger: String,
}

/// How a `--ask ui` wait ended.
pub(crate) enum UiDecision {
    Approved(ApproverIdentity),
    Denied(String),
}

pub(crate) fn request_id(rec: &LedgerRecord) -> String {
    let h = rec.record_hash.get(..16).unwrap_or(&rec.record_hash);
    format!("{}-{h}", rec.index)
}

/// Well-formed ids only (they become file names).
pub(crate) fn valid_id(id: &str) -> bool {
    let Some((idx, h)) = id.split_once('-') else {
        return false;
    };
    !idx.is_empty()
        && idx.len() <= 20
        && idx.bytes().all(|b| b.is_ascii_digit())
        && h.len() == 16
        && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `canonicalize` of the ledger's directory joined with its file name (the
/// ledger itself may not exist yet). The same function on both sides keeps
/// the key stable.
pub(crate) fn canonical_ledger(ledger: &Path) -> std::io::Result<PathBuf> {
    if ledger.to_str().is_some_and(provio_ledger::is_postgres_url) {
        // No directory to hold the request queue; `--ask ui` fails closed.
        return Err(std::io::Error::other(
            "`--ask ui` needs a file ledger (JSONL or SQLite); this ledger is a Postgres URL",
        ));
    }
    let abs = std::path::absolute(ledger)?;
    let name = abs
        .file_name()
        .ok_or_else(|| std::io::Error::other("ledger path has no file name"))?
        .to_owned();
    let dir = abs.parent().unwrap_or(Path::new("."));
    Ok(dir.canonicalize()?.join(name))
}

/// `<ledger dir>/pending`.
pub(crate) fn pending_dir(ledger: &Path) -> std::io::Result<PathBuf> {
    let c = canonical_ledger(ledger)?;
    Ok(c.parent().unwrap_or(Path::new(".")).join("pending"))
}

fn state_root() -> Option<PathBuf> {
    let abs = |v: std::ffi::OsString| {
        let p = PathBuf::from(v);
        p.is_absolute().then_some(p)
    };
    if cfg!(windows) {
        return std::env::var_os("LOCALAPPDATA")
            .and_then(abs)
            .map(|p| p.join("provio").join("ui"));
    }
    if let Some(p) = std::env::var_os("XDG_STATE_HOME").and_then(abs) {
        return Some(p.join("provio").join("ui"));
    }
    std::env::var_os("HOME")
        .and_then(abs)
        .map(|p| p.join(".local").join("state").join("provio").join("ui"))
}

/// The console-owned directory for this ledger (heartbeat + decisions).
pub(crate) fn console_dir(ledger: &Path) -> std::io::Result<PathBuf> {
    let mut key_src = match ledger.to_str() {
        Some(url) if provio_ledger::is_postgres_url(url) => url.to_string(),
        _ => canonical_ledger(ledger)?.to_string_lossy().into_owned(),
    };
    if cfg!(windows) {
        key_src = key_src.to_lowercase();
    }
    let key = LedgerRecord::hash_bytes(key_src.as_bytes());
    let root = state_root().ok_or_else(|| {
        std::io::Error::other(if cfg!(windows) {
            "LOCALAPPDATA is not set to an absolute path"
        } else {
            "neither XDG_STATE_HOME nor HOME is set to an absolute path"
        })
    })?;
    Ok(root.join(&key[..16]))
}

pub(crate) fn decision_path(console: &Path, id: &str) -> PathBuf {
    console.join("decisions").join(format!("{id}.json"))
}

/// Temp file in the same directory, then rename: readers never see a
/// partial file.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp = dir.join(format!(
        ".{}.{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("f"),
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&tmp, bytes)?;
    // Windows: a reader holding the target open makes the rename fail
    // transiently; retry briefly.
    let mut last = None;
    for _ in 0..20 {
        match std::fs::rename(&tmp, path) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    let _ = std::fs::remove_file(&tmp);
    Err(last.unwrap_or_else(|| std::io::Error::other("rename failed")))
}

pub(crate) fn read_heartbeat(console: &Path) -> Option<Heartbeat> {
    let s = std::fs::read(console.join("console.json")).ok()?;
    serde_json::from_slice(&s).ok()
}

pub(crate) fn heartbeat_fresh(h: &Heartbeat) -> bool {
    let age = Timestamp::now().epoch_ms() - h.updated_ms;
    (-HEARTBEAT_STALE_MS..=HEARTBEAT_STALE_MS).contains(&age)
}

/// Removes the request file however the wait ends.
struct RequestFile(PathBuf);

impl Drop for RequestFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Gateway side: wait for the console's answer to the ask recorded in
/// `rec`. `cap_ms` bounds the wait below the calling agent's own hook
/// timeout. Every failure is a denial.
pub(crate) fn await_decision(
    ledger: &Path,
    rec: &LedgerRecord,
    format: &str,
    cap_ms: Option<u64>,
) -> UiDecision {
    match await_inner(ledger, rec, format, cap_ms) {
        Ok(d) => d,
        Err(e) => UiDecision::Denied(format!(
            "`--ask ui` could not reach the provio ui console: {e} (fail closed)"
        )),
    }
}

fn await_inner(
    ledger: &Path,
    rec: &LedgerRecord,
    format: &str,
    cap_ms: Option<u64>,
) -> std::io::Result<UiDecision> {
    let (rule_id, timeout_ms) = match &rec.verdict {
        Some(Verdict::Ask {
            rule_id,
            timeout_ms,
            ..
        }) => (rule_id.clone(), timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
        _ => return Err(std::io::Error::other("not an ask decision")),
    };
    let wait_ms = cap_ms.map_or(timeout_ms, |c| timeout_ms.min(c));
    let console = console_dir(ledger)?;
    // The agent must not be able to write the console's answers.
    let ledger_dir = canonical_ledger(ledger)?
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let cwd = std::env::current_dir()
        .and_then(|c| c.canonicalize())
        .unwrap_or_default();
    let console_c = console
        .parent()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p.join(console.file_name().unwrap_or_default()))
        .unwrap_or_else(|| console.clone());
    if console_c.starts_with(&ledger_dir)
        || (!cwd.as_os_str().is_empty() && console_c.starts_with(&cwd))
    {
        return Ok(UiDecision::Denied(format!(
            "the provio ui state directory {} is inside the ledger directory or the working \
             directory, where an agent could write its own approval; refusing (fail closed)",
            console.display()
        )));
    }
    match read_heartbeat(&console) {
        Some(h) if heartbeat_fresh(&h) => {}
        _ => {
            return Ok(UiDecision::Denied(format!(
                "rule \"{rule_id}\" requires human approval and no `provio ui` console is \
                 running for this ledger (fail closed); start `provio ui` to approve asks"
            )))
        }
    }

    let id = request_id(rec);
    let now = Timestamp::now().epoch_ms();
    let req = PendingRequest {
        v: 1,
        id: id.clone(),
        index: rec.index,
        record_hash: rec.record_hash.clone(),
        created_ms: now,
        deadline_ms: now + i64::try_from(wait_ms).unwrap_or(i64::MAX / 2),
        rule_id: rule_id.clone(),
        format: format.to_string(),
        pid: std::process::id(),
    };
    let file = pending_dir(ledger)?.join(format!("{id}.json"));
    write_atomic(&file, &serde_json::to_vec_pretty(&req)?)?;
    let _guard = RequestFile(file);

    let start = Instant::now();
    let deadline = Duration::from_millis(wait_ms);
    let dfile = decision_path(&console, &id);
    let mut last_beat = Instant::now();
    loop {
        if let Some(d) = read_decision(&dfile) {
            if d.id != id || d.record_hash != rec.record_hash {
                return Ok(UiDecision::Denied(
                    "the console decision does not name this call (fail closed)".into(),
                ));
            }
            return Ok(match approver_identity(&d.approver) {
                None => UiDecision::Denied(
                    "the console decision carries no web-console approver (fail closed)".into(),
                ),
                Some(who) if d.approved => UiDecision::Approved(who),
                Some(who) => UiDecision::Denied(format!(
                    "rule \"{rule_id}\": denied in the provio ui web console by {}",
                    who.id
                )),
            });
        }
        if start.elapsed() >= deadline {
            return Ok(UiDecision::Denied(format!(
                "rule \"{rule_id}\": no decision from the provio ui console within {wait_ms}ms \
                 (fail closed)"
            )));
        }
        if last_beat.elapsed() >= HEARTBEAT_EVERY {
            last_beat = Instant::now();
            if !read_heartbeat(&console).is_some_and(|h| heartbeat_fresh(&h)) {
                return Ok(UiDecision::Denied(format!(
                    "rule \"{rule_id}\": the provio ui console stopped while the ask was \
                     waiting (fail closed)"
                )));
            }
        }
        std::thread::sleep(POLL.min(deadline.saturating_sub(start.elapsed())));
    }
}

fn read_decision(path: &Path) -> Option<ConsoleDecision> {
    let bytes = std::fs::read(path).ok()?;
    // A file that exists but does not parse is not an approval; it is
    // treated as absent until the deadline (then: deny).
    serde_json::from_slice(&bytes).ok()
}

/// `web-console:<user>` → the identity recorded with an approval.
pub(crate) fn approver_identity(s: &str) -> Option<ApproverIdentity> {
    let user = s.strip_prefix(APPROVER_PREFIX)?;
    let ok = !user.is_empty()
        && user.len() <= 128
        && user
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'));
    ok.then(|| ApproverIdentity {
        kind: ApproverKind::Tui,
        id: s.to_string(),
    })
}

/// PostToolUse side (claude-code format): the approver the console
/// recorded for this decision, if it approved it.
pub(crate) fn console_approval(ledger: &Path, rec: &LedgerRecord) -> Option<ApproverIdentity> {
    let console = console_dir(ledger).ok()?;
    let d = read_decision(&decision_path(&console, &request_id(rec)))?;
    if d.approved && d.record_hash == rec.record_hash {
        approver_identity(&d.approver)
    } else {
        None
    }
}

/// Console side: the approver string for this machine's user.
pub(crate) fn console_approver() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "local-user".into());
    let clean: String = user
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
        .take(64)
        .collect();
    format!(
        "{APPROVER_PREFIX}{}",
        if clean.is_empty() {
            "local-user"
        } else {
            &clean
        }
    )
}

/// Console side: every request file currently in the queue (unvalidated;
/// the caller checks each against the ledger).
pub(crate) fn list_requests(ledger: &Path) -> Vec<PendingRequest> {
    let Ok(dir) = pending_dir(ledger) else {
        return Vec::new();
    };
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(id) = name.strip_suffix(".json") else {
            continue;
        };
        if !valid_id(id) {
            continue;
        }
        let Ok(meta) = e.metadata() else { continue };
        if !meta.is_file() || meta.len() > 64 * 1024 {
            continue;
        }
        let Ok(bytes) = std::fs::read(e.path()) else {
            continue;
        };
        if let Ok(r) = serde_json::from_slice::<PendingRequest>(&bytes) {
            if r.id == id {
                out.push(r);
            }
        }
    }
    out.sort_by_key(|r| r.index);
    out
}

/// Console side: write the answer for a validated request.
pub(crate) fn write_decision(
    console: &Path,
    id: &str,
    record_hash: &str,
    approved: bool,
) -> std::io::Result<ConsoleDecision> {
    let d = ConsoleDecision {
        v: 1,
        id: id.to_string(),
        record_hash: record_hash.to_string(),
        approved,
        approver: console_approver(),
        decided_ms: Timestamp::now().epoch_ms(),
    };
    write_atomic(&decision_path(console, id), &serde_json::to_vec_pretty(&d)?)?;
    Ok(d)
}

/// Console side: decisions the console has written (for the history view).
pub(crate) fn read_console_decision(console: &Path, id: &str) -> Option<ConsoleDecision> {
    read_decision(&decision_path(console, id))
}

/// Console side: drop decision files older than a day (they are only
/// needed until the call's PostToolUse / complete).
pub(crate) fn gc_decisions(console: &Path) {
    let Ok(rd) = std::fs::read_dir(console.join("decisions")) else {
        return;
    };
    let cutoff = Timestamp::now().epoch_ms() - 24 * 3_600_000;
    for e in rd.flatten() {
        let Ok(bytes) = std::fs::read(e.path()) else {
            continue;
        };
        let old = match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) => v
                .get("decided_ms")
                .and_then(Value::as_i64)
                .is_none_or(|t| t < cutoff),
            Err(_) => true,
        };
        if old {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_approvers() {
        assert!(valid_id("12-0123456789abcdef"));
        assert!(!valid_id("12-0123456789ABCDEF"));
        assert!(!valid_id("../x-0123456789abcdef"));
        assert!(!valid_id("12-0123"));
        assert!(approver_identity("web-console:alice").is_some());
        assert!(approver_identity("human:alice").is_none());
        assert!(approver_identity("web-console:").is_none());
        assert!(approver_identity("web-console:a/b").is_none());
        assert!(console_approver().starts_with(APPROVER_PREFIX));
    }
}
