//! provio-ledger — the tamper-evident provenance ledger store (Contract 3).
//!
//! Append-only hash-chained provenance ledger with verify, receipts and
//! anchors. Implements the schema frozen in `provio_core::ledger`. Two
//! stores, one evidence format:
//!
//! - [`FileLedgerStore`] (ADR-005 default, every platform): one JSONL file,
//!   one serialized `LedgerRecord` per line, durable on append (`flush` +
//!   `sync_data`), crash-tolerant on open (a torn final line is ignored;
//!   anything worse is reported, never silently dropped). Safe for many
//!   concurrent writer processes: appends take an exclusive lock on
//!   `<ledger>.lock` and check against the tip on disk (see
//!   [`file_store`]); [`retry_append`] is the retry loop for writers that
//!   lost the race for the tip.
//! - `SqliteLedgerStore` (`sqlite` cargo feature): the same serialized
//!   records, one per row, in a WAL-mode SQLite database with transactional
//!   append. See the `sqlite` module docs for schema and concurrency.
//! - `PostgresLedgerStore` (`postgres` cargo feature): the same serialized
//!   records, one per row, in a Postgres table that many hosts append to;
//!   selected by a `postgres://` / `postgresql://` URL. See the `postgres`
//!   module docs and `docs/ledger-postgres.md`.
//!
//! Hashes cover the record, not the container, so both stores pass the same
//! `provio_core::verify_chain` suite and a record moved between them verifies
//! identically. [`verify()`], [`sessions`] and [`find_by_call_id`] take a path
//! and pick the store with [`detect_store_kind`]; [`open_store`] does the
//! same for writers.
//!
//! No content is captured beyond what `LedgerRecord` already holds, and
//! this crate emits zero telemetry (Contract 3 invariants).

#![forbid(unsafe_code)]

pub mod file_store;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod query;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod store;
pub mod verify;

#[cfg(feature = "postgres")]
pub use crate::postgres::{verify_postgres, PostgresLedgerStore};
pub use file_store::{is_append_race, retry_append, FileLedgerStore, APPEND_RETRIES, LOCK_TIMEOUT};
pub use query::{find_by_call_id, find_by_call_id_in, sessions, sessions_in, SessionSummary};
#[cfg(feature = "sqlite")]
pub use sqlite::{verify_sqlite, SqliteLedgerStore};
pub use store::{
    detect_store_kind, display_ledger, is_postgres_url, open_store, redact_postgres_url, StoreKind,
};
pub use verify::{verify, verify_jsonl};
