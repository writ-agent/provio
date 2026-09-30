//! Read-only query helpers for the CLI (`provio log`, `provio show`).
//!
//! All helpers stream the ledger record by record (JSONL or SQLite, see
//! [`detect_store_kind`](crate::detect_store_kind)); none load the ledger
//! into memory beyond the records they return. The `*_in` variants take any
//! record stream, e.g. [`LedgerStore::iter`](provio_core::ledger::LedgerStore::iter).

use std::collections::HashMap;
use std::path::Path;

use provio_core::approver::ApproverKind;
use provio_core::error::Result;
use provio_core::ledger::LedgerRecord;
use provio_core::verdict::Verdict;
use serde::{Deserialize, Serialize};

use crate::store::read_records;

/// Per-session rollup for `provio log`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    /// Total ledger records (decisions + executions) in the session.
    pub records: u64,
    /// Decision records whose verdict was `Deny`.
    pub denied: u64,
    /// True if any record carries a human approver (TUI or RBAC; an
    /// out-of-band webhook is automation, not a human at the keyboard).
    pub approved_by_human: bool,
}

/// Summarize every session in the ledger at `path`, in first-seen order.
pub fn sessions(path: impl AsRef<Path>) -> Result<Vec<SessionSummary>> {
    sessions_in(read_records(path.as_ref())?)
}

/// [`sessions`] over any record stream.
pub fn sessions_in(
    records: impl IntoIterator<Item = Result<LedgerRecord>>,
) -> Result<Vec<SessionSummary>> {
    let mut order: Vec<String> = Vec::new();
    let mut by_id: HashMap<String, SessionSummary> = HashMap::new();
    for item in records {
        let rec = item?;
        let summary = by_id.entry(rec.session_id.clone()).or_insert_with(|| {
            order.push(rec.session_id.clone());
            SessionSummary {
                session_id: rec.session_id.clone(),
                records: 0,
                denied: 0,
                approved_by_human: false,
            }
        });
        summary.records += 1;
        if matches!(rec.verdict, Some(Verdict::Deny { .. })) {
            summary.denied += 1;
        }
        if let Some(approver) = &rec.approver {
            if matches!(approver.kind, ApproverKind::Tui | ApproverKind::Rbac) {
                summary.approved_by_human = true;
            }
        }
    }
    Ok(order
        .into_iter()
        .map(|id| by_id.remove(&id).expect("inserted above"))
        .collect())
}

/// All records for one call — normally the `Decision` plus its linked
/// `Execution` (ADR-003) — in ledger order.
pub fn find_by_call_id(path: impl AsRef<Path>, call_id: &str) -> Result<Vec<LedgerRecord>> {
    find_by_call_id_in(read_records(path.as_ref())?, call_id)
}

/// [`find_by_call_id`] over any record stream.
pub fn find_by_call_id_in(
    records: impl IntoIterator<Item = Result<LedgerRecord>>,
    call_id: &str,
) -> Result<Vec<LedgerRecord>> {
    let mut found = Vec::new();
    for item in records {
        let rec = item?;
        if rec.call_id == call_id {
            found.push(rec);
        }
    }
    Ok(found)
}
