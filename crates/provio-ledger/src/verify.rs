//! `provio verify` backend: whole-ledger chain verification.
//!
//! Wraps [`provio_core::verify_chain`] so every store shares one evidentiary
//! code path (ADR-002: verify-forever). Adds one thing the raw iterator
//! cannot express: a record so tampered it no longer parses. That is
//! reported as a verification failure at that record's position, not as an
//! opaque error — the exact broken index is the product's promise (spec §9).

use std::cell::Cell;
use std::fs::File;
use std::path::Path;
use std::rc::Rc;

use provio_core::error::{ProvioError, Result};
use provio_core::ledger::{verify_chain, LedgerRecord, VerifyReport};

use crate::file_store::record_iter;
use crate::store::{detect_store_kind, StoreKind};

/// Verify the hash chain of the ledger at `path`, whichever store holds it
/// (see [`detect_store_kind`]).
///
/// Returns `VerifyReport { intact: false, broken_at: Some(i), records: i }`
/// when record `i` fails its hash, its chain link, or fails to parse at all.
pub fn verify(path: impl AsRef<Path>) -> Result<VerifyReport> {
    let path = path.as_ref();
    match detect_store_kind(path)? {
        StoreKind::Jsonl => verify_jsonl(path),
        #[cfg(feature = "sqlite")]
        StoreKind::Sqlite => crate::sqlite::verify_sqlite(path),
        #[cfg(not(feature = "sqlite"))]
        StoreKind::Sqlite => Err(crate::store::sqlite_unavailable(path)),
        #[cfg(feature = "postgres")]
        StoreKind::Postgres => crate::postgres::verify_postgres(crate::store::postgres_url(path)),
        #[cfg(not(feature = "postgres"))]
        StoreKind::Postgres => Err(crate::store::postgres_unavailable(path)),
    }
}

/// Verify the JSONL ledger at `path` (no format detection).
pub fn verify_jsonl(path: impl AsRef<Path>) -> Result<VerifyReport> {
    let file = File::open(path.as_ref())?;
    verify_records(record_iter(file))
}

/// Shared by every store: run `verify_chain`, mapping the first record
/// that cannot be read at all to a break at its ordinal position.
pub(crate) fn verify_records(
    records: impl Iterator<Item = Result<LedgerRecord>>,
) -> Result<VerifyReport> {
    // Position (record ordinal) of the first unreadable record, if any.
    let parse_failure: Rc<Cell<Option<u64>>> = Rc::new(Cell::new(None));
    let flag = Rc::clone(&parse_failure);
    let mut ordinal = 0u64;
    let records = records.map(move |item| {
        item.map_err(|e| {
            // Store iterators only error on IO / storage or parse; either
            // way the record at this ordinal cannot be verified.
            if flag.get().is_none() {
                flag.set(Some(ordinal));
            }
            match e {
                ProvioError::Serde(s) => ProvioError::Ledger(format!(
                    "record {} is not a valid LedgerRecord: {}",
                    ordinal, s
                )),
                other => other,
            }
        })
        .inspect(|_| {
            ordinal += 1;
        })
    });
    match verify_chain(records) {
        Ok(report) => Ok(report),
        Err(e) => match parse_failure.get() {
            // Tampered/unparseable record: surface position as a broken chain.
            Some(i) => Ok(VerifyReport {
                records: i,
                intact: false,
                broken_at: Some(i),
            }),
            None => Err(e),
        },
    }
}
