//! Contract 3: `LedgerRecord` schema v1 and the `LedgerStore` trait.
//!
//! STABILITY RULE (plan §2, Q3): this schema is frozen. Changes are additive
//! only, under a bumped `schema_version`. `provio verify` must validate every
//! historical version forever — verify-forever is the product's core promise.
//!
//! Two-phase audit design: every intercepted call produces exactly one
//! `Decision` record at verdict time (even if execution never starts), and
//! allowed calls produce one linked `Execution` record at completion. No
//! record is ever mutated — that is what makes the chain tamper-evident.

use crate::approver::ApproverIdentity;
use crate::call::ToolCall;
use crate::error::Result;
use crate::time::Timestamp;
use crate::verdict::Verdict;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SCHEMA_VERSION: u32 = 1;
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordKind {
    Decision,
    Execution,
}

/// One tamper-evident ledger entry. `record_hash` chains over every field
/// except itself; `prev_hash` links to the previous record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerRecord {
    pub schema_version: u32,
    pub kind: RecordKind,
    pub index: u64,
    pub call_id: String,
    pub session_id: String,
    /// Present on decision records.
    pub call: Option<ToolCall>,
    /// Present on decision records.
    pub verdict: Option<Verdict>,
    pub rule_id: Option<String>,
    /// Set when a human/out-of-band approver authorised the call.
    pub approver: Option<ApproverIdentity>,
    /// Present on execution records: links back to the decision.
    pub decision_index: Option<u64>,
    pub backend: Option<String>,
    pub exit_status: Option<i32>,
    /// sha256 hex of the canonical call (content-free commitment).
    pub input_hash: String,
    /// sha256 hex of execution output, when available.
    pub output_hash: Option<String>,
    pub recorded_at: Timestamp,
    pub prev_hash: String,
    pub record_hash: String,
}

/// Everything except `record_hash` — the canonical hash input.
#[derive(Serialize)]
struct RecordPayload<'a> {
    schema_version: u32,
    kind: RecordKind,
    index: u64,
    call_id: &'a str,
    session_id: &'a str,
    call: &'a Option<ToolCall>,
    verdict: &'a Option<Verdict>,
    rule_id: &'a Option<String>,
    approver: &'a Option<ApproverIdentity>,
    decision_index: Option<u64>,
    backend: &'a Option<String>,
    exit_status: Option<i32>,
    input_hash: &'a str,
    output_hash: &'a Option<String>,
    recorded_at: &'a Timestamp,
    prev_hash: &'a str,
}

impl LedgerRecord {
    /// Deterministic SHA-256 over the canonical payload (struct field order
    /// is fixed by declaration, so serde_json output is canonical).
    pub fn compute_hash(&self) -> Result<String> {
        let payload = RecordPayload {
            schema_version: self.schema_version,
            kind: self.kind,
            index: self.index,
            call_id: &self.call_id,
            session_id: &self.session_id,
            call: &self.call,
            verdict: &self.verdict,
            rule_id: &self.rule_id,
            approver: &self.approver,
            decision_index: self.decision_index,
            backend: &self.backend,
            exit_status: self.exit_status,
            input_hash: &self.input_hash,
            output_hash: &self.output_hash,
            recorded_at: &self.recorded_at,
            prev_hash: &self.prev_hash,
        };
        let bytes = serde_json::to_vec(&payload)?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }

    pub fn hash_call(call: &ToolCall) -> Result<String> {
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(call)?)))
    }

    pub fn hash_bytes(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }
}

/// Append-only storage. SQLite (WAL) on workstations, Postgres + object
/// storage in clusters (spec §9); both must pass the same verify suite.
pub trait LedgerStore {
    /// Append a record. Implementations must reject a record whose `index`
    /// is not `len()` or whose `prev_hash` does not match the stored tip.
    fn append(&mut self, record: &LedgerRecord) -> Result<()>;
    fn tip(&self) -> Result<Option<LedgerRecord>>;
    fn get(&self, index: u64) -> Result<Option<LedgerRecord>>;
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Ascending by index.
    fn iter(&self) -> Box<dyn Iterator<Item = Result<LedgerRecord>> + '_>;
}
/// Writes correctly-chained records on top of any `LedgerStore`.
pub struct LedgerWriter<'a> {
    store: &'a mut dyn LedgerStore,
}

impl<'a> LedgerWriter<'a> {
    pub fn new(store: &'a mut dyn LedgerStore) -> Self {
        LedgerWriter { store }
    }

    fn next_index_and_prev(&self) -> Result<(u64, String)> {
        match self.store.tip()? {
            Some(t) => Ok((t.index + 1, t.record_hash)),
            None => Ok((0, GENESIS_HASH.to_string())),
        }
    }

    fn finalize(&mut self, mut rec: LedgerRecord) -> Result<LedgerRecord> {
        rec.record_hash = rec.compute_hash()?;
        self.store.append(&rec)?;
        Ok(rec)
    }

    /// Record a decision. Called exactly once per intercepted call.
    pub fn record_decision(
        &mut self,
        call: &ToolCall,
        verdict: &Verdict,
        approver: Option<ApproverIdentity>,
    ) -> Result<LedgerRecord> {
        let (index, prev_hash) = self.next_index_and_prev()?;
        self.finalize(LedgerRecord {
            schema_version: SCHEMA_VERSION,
            kind: RecordKind::Decision,
            index,
            call_id: call.call_id.clone(),
            session_id: call.session_id.clone(),
            call: Some(call.clone()),
            verdict: Some(verdict.clone()),
            rule_id: verdict.rule_id().map(|s| s.to_string()),
            approver,
            decision_index: None,
            backend: None,
            exit_status: None,
            input_hash: LedgerRecord::hash_call(call)?,
            output_hash: None,
            recorded_at: Timestamp::now(),
            prev_hash,
            record_hash: String::new(),
        })
    }

    /// Record an execution outcome, linked to its decision record.
    pub fn record_execution(
        &mut self,
        decision: &LedgerRecord,
        backend: &str,
        exit_status: i32,
        output: &[u8],
    ) -> Result<LedgerRecord> {
        if decision.kind != RecordKind::Decision {
            return Err(crate::error::ProvioError::Ledger(
                "record_execution requires a decision record".into(),
            ));
        }
        let (index, prev_hash) = self.next_index_and_prev()?;
        self.finalize(LedgerRecord {
            schema_version: SCHEMA_VERSION,
            kind: RecordKind::Execution,
            index,
            call_id: decision.call_id.clone(),
            session_id: decision.session_id.clone(),
            call: None,
            verdict: None,
            rule_id: decision.rule_id.clone(),
            approver: None,
            decision_index: Some(decision.index),
            backend: Some(backend.to_string()),
            exit_status: Some(exit_status),
            input_hash: decision.input_hash.clone(),
            output_hash: Some(LedgerRecord::hash_bytes(output)),
            recorded_at: Timestamp::now(),
            prev_hash,
            record_hash: String::new(),
        })
    }
}

/// Result of `provio verify` (spec §9: report the exact index where it broke).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub records: u64,
    pub intact: bool,
    /// First index whose hash or chain link failed.
    pub broken_at: Option<u64>,
}

/// Verify any store's chain. Store-independent so SQLite and Postgres
/// backends share one evidentiary code path.
pub fn verify_chain(records: impl Iterator<Item = Result<LedgerRecord>>) -> Result<VerifyReport> {
    let mut prev = GENESIS_HASH.to_string();
    let mut count = 0u64;
    for item in records {
        let rec = item?;
        let ok = rec.index == count
            && rec.prev_hash == prev
            && rec
                .compute_hash()
                .map(|h| h == rec.record_hash)
                .unwrap_or(false);
        if !ok {
            return Ok(VerifyReport {
                records: count,
                intact: false,
                broken_at: Some(rec.index),
            });
        }
        prev = rec.record_hash.clone();
        count += 1;
    }
    Ok(VerifyReport {
        records: count,
        intact: true,
        broken_at: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the hash encoding every existing ledger was written with
    /// (FIPS 180-2 "abc" vector, lowercase hex). A dependency bump that
    /// changed the digest or its formatting would break `provio verify` on
    /// every historical ledger; this catches it first.
    #[test]
    fn sha256_encoding_is_stable() {
        assert_eq!(
            LedgerRecord::hash_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(GENESIS_HASH.len(), 64);
    }
}
