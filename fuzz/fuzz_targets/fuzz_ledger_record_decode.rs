//! Fuzz target: provio-ledger record decode (plan §8 fuzzing gate: ledger
//! record decode).
//!
//! The decode entry point is `serde_json::from_slice::<LedgerRecord>` — the
//! same parse every store performs when reading a JSONL line. Decode failures
//! are expected outcomes; a panic is a bug. For any record that does decode,
//! `compute_hash` must also complete (it is the core of `provio verify`), and a
//! hash-mismatch oracle exercises the tamper-detection comparison without
//! asserting (an arbitrary record may legitimately carry a wrong hash).

#![no_main]

use libfuzzer_sys::fuzz_target;
use provio_core::ledger::LedgerRecord;

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = serde_json::from_slice::<LedgerRecord>(data) {
        if let Ok(hash) = record.compute_hash() {
            let _matches_chain = hash == record.record_hash;
        }
        let _kind = record.kind;
    }
});