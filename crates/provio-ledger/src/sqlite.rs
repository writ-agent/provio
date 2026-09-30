//! `SqliteLedgerStore`: the ledger in a SQLite database (WAL mode), behind
//! the `sqlite` cargo feature (ADR-005).
//!
//! # Same evidence, different container
//!
//! Each row stores the record exactly as [`FileLedgerStore`] writes a JSONL
//! line: `serde_json::to_string(&LedgerRecord)`. Hashes are computed over
//! the record (`LedgerRecord::compute_hash`), never over anything
//! SQLite-specific, so the chain is store-independent: records exported
//! from one store and appended to the other keep their hashes and verify
//! identically.
//!
//! # Schema (store version 1)
//!
//! ```sql
//! CREATE TABLE ledger (
//!     idx    INTEGER PRIMARY KEY NOT NULL CHECK (idx >= 0),
//!     record TEXT NOT NULL CHECK (json_valid(record)),
//!     CHECK (idx = json_extract(record, '$.index'))
//! ) STRICT;
//! -- + BEFORE INSERT trigger: idx must equal the ledger length and
//! --   record.prev_hash must equal the tip's record_hash (genesis: 64 zeros)
//! -- + BEFORE UPDATE / BEFORE DELETE triggers: RAISE(ABORT)
//! ```
//!
//! The file is tagged `PRAGMA application_id = 0x57524954` ("PROVIO") and
//! `PRAGMA user_version = 1`; opening any other SQLite database fails
//! instead of adding tables to it.
//!
//! # Tamper-evidence, not prevention
//!
//! The triggers and CHECK constraints stop *accidental* rewrites and
//! stray writers (a `sqlite3` shell, another tool) from forking or editing
//! the chain. They are not a security boundary: anyone who can write the
//! file can `DROP TRIGGER`, set `PRAGMA ignore_check_constraints`, or edit
//! pages directly. What survives that is the hash chain — [`verify_sqlite`]
//! (and `provio verify`) report the exact index of any edited, deleted or
//! reordered record.
//!
//! # Durability and concurrency
//!
//! - `journal_mode = WAL`: readers never block the writer and vice versa.
//!   Opening fails if SQLite cannot enter WAL mode.
//! - `synchronous = FULL`: every committed append is fsync'd before `Ok`,
//!   matching `FileLedgerStore`'s `sync_data` per append (ADR-003: a
//!   decision on disk is evidence even if the process dies right after).
//! - `busy_timeout = 5s`: concurrent writers wait instead of failing fast.
//! - [`append`](LedgerStore::append) runs in a `BEGIN IMMEDIATE`
//!   transaction: it takes the write lock, re-reads the tip *from the
//!   database* (not from this handle's memory), checks `index` and
//!   `prev_hash` against it, inserts, and commits. Two writers — threads or
//!   processes — can therefore never both append after the same tip: the
//!   loser gets a `ProvioError::Ledger` and must rebuild its record on the new
//!   tip (as [`LedgerWriter`](provio_core::ledger::LedgerWriter) does when
//!   retried, since it reads `tip()` fresh). The primary key and the
//!   insert trigger enforce the same rule inside SQLite itself.
//!
//! # Opening a damaged ledger
//!
//! [`SqliteLedgerStore::open`] scans every row (index sequence, `prev_hash`
//! links, parseability), like `FileLedgerStore::open`. There is no torn-tail
//! case — a SQLite transaction is atomic, so a crash never leaves half a
//! record — which means *any* unparseable row, including the last, is a
//! hard error.
//!
//! [`FileLedgerStore`]: crate::FileLedgerStore

use std::borrow::Borrow;
use std::cell::Cell;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use provio_core::error::{ProvioError, Result};
use provio_core::ledger::{LedgerRecord, LedgerStore, VerifyReport, GENESIS_HASH};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};

use crate::verify::verify_records;

/// `PRAGMA application_id` of a PROVIO ledger database: ASCII "PROVIO".
pub const APPLICATION_ID: i32 = 0x5752_4954;
/// `PRAGMA user_version`: the SQLite store's table layout version. This is
/// independent of `LedgerRecord::schema_version`, which versions records.
pub const STORE_VERSION: i32 = 1;
/// How long a connection waits for a competing writer before failing.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Rows fetched per query by the lazy iterators.
const PAGE_SIZE: i64 = 512;

fn schema_sql() -> String {
    format!(
        r#"
CREATE TABLE ledger (
    idx    INTEGER PRIMARY KEY NOT NULL CHECK (idx >= 0),
    record TEXT NOT NULL CHECK (json_valid(record)),
    CHECK (idx = json_extract(record, '$.index'))
) STRICT;

CREATE TRIGGER ledger_append_sequential BEFORE INSERT ON ledger
BEGIN
    SELECT RAISE(ABORT, 'provio ledger is append-only: index must equal the ledger length')
    WHERE NEW.idx IS NOT (SELECT COALESCE(MAX(idx) + 1, 0) FROM ledger);
    SELECT RAISE(ABORT, 'provio ledger is append-only: prev_hash must equal the chain tip')
    WHERE json_extract(NEW.record, '$.prev_hash') IS NOT COALESCE(
        (SELECT json_extract(record, '$.record_hash') FROM ledger ORDER BY idx DESC LIMIT 1),
        '{GENESIS_HASH}'
    );
END;

CREATE TRIGGER ledger_no_update BEFORE UPDATE ON ledger
BEGIN
    SELECT RAISE(ABORT, 'provio ledger is append-only: UPDATE rejected');
END;

CREATE TRIGGER ledger_no_delete BEFORE DELETE ON ledger
BEGIN
    SELECT RAISE(ABORT, 'provio ledger is append-only: DELETE rejected');
END;
"#
    )
}

/// rusqlite errors become `ProvioError::Ledger` (provio-core has no SQLite
/// variant, and must not depend on rusqlite).
fn sql_err(e: rusqlite::Error) -> ProvioError {
    ProvioError::Ledger(format!("sqlite: {e}"))
}

/// Whether a mapped error is SQLite's SQLITE_BUSY / SQLITE_LOCKED.
fn is_busy(message: &str) -> bool {
    message.contains("database is locked") || message.contains("database table is locked")
}

trait SqlResultExt<T> {
    fn sql(self) -> Result<T>;
}

impl<T> SqlResultExt<T> for rusqlite::Result<T> {
    fn sql(self) -> Result<T> {
        self.map_err(sql_err)
    }
}

/// Append-only SQLite ledger. See the [module docs](self) for schema,
/// durability and concurrency guarantees.
#[derive(Debug)]
pub struct SqliteLedgerStore {
    path: PathBuf,
    conn: Connection,
    /// Last length observed; only a fallback for the infallible `len()`.
    /// `append` never trusts it — it re-reads the tip under the write lock.
    len: Cell<u64>,
}

impl SqliteLedgerStore {
    /// Open (creating the file, its parent dirs and the schema if absent)
    /// and validate the stored chain links. A database that is not a PROVIO
    /// ledger, or whose chain is broken, is a `ProvioError::Ledger`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        // Opening takes locks that SQLite can refuse with SQLITE_BUSY without
        // consulting the busy handler (WAL-index setup and recovery while
        // another connection opens the same file). Retry those, bounded by
        // the same budget writers get.
        let deadline = Instant::now() + BUSY_TIMEOUT;
        loop {
            match Self::open_once(&path) {
                Err(ProvioError::Ledger(m)) if is_busy(&m) && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                other => return other,
            }
        }
    }

    fn open_once(path: &Path) -> Result<Self> {
        let path = path.to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .sql()?;
        conn.busy_timeout(BUSY_TIMEOUT).sql()?;
        // WAL is persistent in the file: only a new database needs the
        // switch, which takes an exclusive lock.
        let mut mode: String = conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .sql()?;
        if !mode.eq_ignore_ascii_case("wal") {
            mode = conn
                .pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))
                .sql()?;
        }
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(ProvioError::Ledger(format!(
                "ledger {path:?}: SQLite refused WAL journal mode (got {mode:?})"
            )));
        }
        conn.pragma_update(None, "synchronous", "FULL").sql()?;
        init_or_check_schema(&mut conn, &path)?;
        let store = SqliteLedgerStore {
            path,
            conn,
            len: Cell::new(0),
        };
        store.rescan()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Cheap link checks only (index sequence + prev_hash chain + every row
    /// parses), mirroring `FileLedgerStore::open`; full hash verification
    /// is [`verify_sqlite`].
    fn rescan(&self) -> Result<()> {
        // One read transaction so the scan sees a single snapshot.
        let tx = self.conn.unchecked_transaction().sql()?;
        let mut expected = 0u64;
        let mut prev = GENESIS_HASH.to_string();
        for item in RowCursor::new(&*tx) {
            let rec = item.map_err(|e| {
                ProvioError::Ledger(format!(
                    "ledger {:?}: corrupt record at index {} (mid-ledger corruption): {}",
                    self.path, expected, e
                ))
            })?;
            if rec.index != expected {
                return Err(ProvioError::Ledger(format!(
                    "ledger {:?}: record index {} out of sequence (expected {})",
                    self.path, rec.index, expected
                )));
            }
            if rec.prev_hash != prev {
                return Err(ProvioError::Ledger(format!(
                    "ledger {:?}: record {} prev_hash does not match the chain tip",
                    self.path, rec.index
                )));
            }
            prev = rec.record_hash;
            expected += 1;
        }
        tx.commit().sql()?;
        self.len.set(expected);
        Ok(())
    }
}

/// Create the schema in an empty database, or confirm an existing one is a
/// PROVIO ledger of a supported store version. Fails closed on anything else.
fn init_or_check_schema(conn: &mut Connection, path: &Path) -> Result<()> {
    // IMMEDIATE: two processes creating the same new ledger must not both
    // run the DDL.
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .sql()?;
    if !check_format(&tx, path)? {
        tx.execute_batch(&schema_sql()).sql()?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)
            .sql()?;
        tx.pragma_update(None, "user_version", STORE_VERSION)
            .sql()?;
    }
    tx.commit().sql()
}

/// `Ok(true)`: a PROVIO ledger of a supported version. `Ok(false)`: a blank
/// database (no header tags, no objects). Anything else is an error.
fn check_format(conn: &Connection, path: &Path) -> Result<bool> {
    let app: i32 = conn
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .sql()?;
    let version: i32 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .sql()?;
    match (app, version) {
        (APPLICATION_ID, STORE_VERSION) => Ok(true),
        (APPLICATION_ID, v) => Err(ProvioError::Ledger(format!(
            "ledger {path:?}: unsupported SQLite store version {v} (this build reads {STORE_VERSION})"
        ))),
        (0, 0) => {
            let objects: i64 = conn
                .query_row("SELECT COUNT(*) FROM sqlite_schema", [], |r| r.get(0))
                .sql()?;
            if objects == 0 {
                Ok(false)
            } else {
                Err(ProvioError::Ledger(format!(
                    "{path:?} is a SQLite database but not a PROVIO ledger"
                )))
            }
        }
        _ => Err(ProvioError::Ledger(format!(
            "{path:?} is a SQLite database but not a PROVIO ledger (application_id {app:#x})"
        ))),
    }
}

/// Parse one row. The row key must agree with the record's own index.
fn decode_row(idx: i64, text: rusqlite::Result<String>) -> Result<LedgerRecord> {
    let text = text.map_err(|e| {
        ProvioError::Ledger(format!(
            "row {idx}: record column is not readable text: {e}"
        ))
    })?;
    let rec: LedgerRecord = serde_json::from_str(&text)?;
    if i64::try_from(rec.index).ok() != Some(idx) {
        return Err(ProvioError::Ledger(format!(
            "row key {idx} does not match record index {}",
            rec.index
        )));
    }
    Ok(rec)
}

fn tip_record(conn: &Connection) -> Result<Option<LedgerRecord>> {
    let row = conn
        .query_row(
            "SELECT idx, record FROM ledger ORDER BY idx DESC LIMIT 1",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1))),
        )
        .optional()
        .sql()?;
    row.map(|(idx, text)| decode_row(idx, text)).transpose()
}

impl LedgerStore for SqliteLedgerStore {
    fn append(&mut self, record: &LedgerRecord) -> Result<()> {
        let idx = i64::try_from(record.index).map_err(|_| {
            ProvioError::Ledger(format!(
                "append rejected: record index {} exceeds the SQLite key range",
                record.index
            ))
        })?;
        // Content check needs no lock: a record whose hash is not its own
        // would verify as broken the moment it landed.
        if record.compute_hash()? != record.record_hash {
            return Err(ProvioError::Ledger(format!(
                "append rejected: record {} record_hash does not match its contents",
                record.index
            )));
        }
        let line = serde_json::to_string(record)?;
        // Write lock first, then read the tip: check-and-insert is atomic
        // across every connection to this file.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .sql()?;
        let (len, tip_hash) = match tip_record(&tx)? {
            Some(tip) => (tip.index + 1, tip.record_hash),
            None => (0, GENESIS_HASH.to_string()),
        };
        if record.index != len {
            return Err(ProvioError::Ledger(format!(
                "append rejected: record index {} but ledger length is {} \
                 (records are append-only and sequential)",
                record.index, len
            )));
        }
        if record.prev_hash != tip_hash {
            return Err(ProvioError::Ledger(format!(
                "append rejected: record {} prev_hash does not match the ledger tip",
                record.index
            )));
        }
        tx.execute(
            "INSERT INTO ledger (idx, record) VALUES (?1, ?2)",
            params![idx, line],
        )
        .sql()?;
        // synchronous=FULL: durable once commit returns.
        tx.commit().sql()?;
        self.len.set(len + 1);
        Ok(())
    }

    fn tip(&self) -> Result<Option<LedgerRecord>> {
        tip_record(&self.conn)
    }

    fn get(&self, index: u64) -> Result<Option<LedgerRecord>> {
        let Ok(idx) = i64::try_from(index) else {
            return Ok(None);
        };
        let row = self
            .conn
            .query_row(
                "SELECT idx, record FROM ledger WHERE idx = ?1",
                params![idx],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1))),
            )
            .optional()
            .sql()?;
        row.map(|(idx, text)| decode_row(idx, text)).transpose()
    }

    /// Next index to append, read from the database (so appends by other
    /// connections are visible). Falls back to the last observed value only
    /// if the query itself fails; `append` re-checks under the write lock.
    fn len(&self) -> u64 {
        match self
            .conn
            .query_row("SELECT COALESCE(MAX(idx) + 1, 0) FROM ledger", [], |r| {
                r.get::<_, i64>(0)
            }) {
            Ok(n) => {
                let n = u64::try_from(n).unwrap_or(0);
                self.len.set(n);
                n
            }
            Err(_) => self.len.get(),
        }
    }

    fn iter(&self) -> Box<dyn Iterator<Item = Result<LedgerRecord>> + '_> {
        Box::new(RowCursor::new(&self.conn))
    }
}

/// Lazy, keyset-paginated scan in ascending `idx` order. Owns or borrows
/// its connection; never holds a statement across `next()` calls. A row
/// that fails to decode yields an `Err` item and the scan continues.
pub(crate) struct RowCursor<C> {
    conn: C,
    next_idx: i64,
    buf: VecDeque<Result<LedgerRecord>>,
    done: bool,
}

impl<C: Borrow<Connection>> RowCursor<C> {
    fn new(conn: C) -> Self {
        RowCursor {
            conn,
            next_idx: 0,
            buf: VecDeque::new(),
            done: false,
        }
    }

    fn fill(&mut self) {
        type Row = (i64, rusqlite::Result<String>);
        let page: rusqlite::Result<Vec<Row>> = (|| {
            let mut stmt = self.conn.borrow().prepare_cached(
                "SELECT idx, record FROM ledger WHERE idx >= ?1 ORDER BY idx LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![self.next_idx, PAGE_SIZE], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)))
            })?;
            rows.collect()
        })();
        match page {
            Err(e) => {
                self.buf.push_back(Err(sql_err(e)));
                self.done = true;
            }
            Ok(rows) => {
                if (rows.len() as i64) < PAGE_SIZE {
                    self.done = true;
                }
                for (idx, text) in rows {
                    match idx.checked_add(1) {
                        Some(n) => self.next_idx = n,
                        None => self.done = true,
                    }
                    self.buf.push_back(decode_row(idx, text));
                }
            }
        }
    }
}

impl<C: Borrow<Connection>> Iterator for RowCursor<C> {
    type Item = Result<LedgerRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() && !self.done {
            self.fill();
        }
        self.buf.pop_front()
    }
}

/// Open an existing ledger database read-only, inside one read transaction
/// (a consistent snapshot for the whole scan). Never creates the file or
/// the schema. `None`: a blank database, i.e. an empty ledger.
fn open_read_only(path: &Path) -> Result<Option<Connection>> {
    // Match FileLedgerStore semantics: a missing ledger is an IO NotFound.
    std::fs::metadata(path)?;
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .sql()?;
    conn.busy_timeout(BUSY_TIMEOUT).sql()?;
    conn.execute_batch("BEGIN DEFERRED").sql()?;
    if !check_format(&conn, path)? {
        return Ok(None);
    }
    Ok(Some(conn))
}

/// Read-only record stream over the ledger database at `path`.
pub(crate) fn read_only_records(
    path: &Path,
) -> Result<Box<dyn Iterator<Item = Result<LedgerRecord>>>> {
    Ok(match open_read_only(path)? {
        Some(conn) => Box::new(RowCursor::new(conn)),
        None => Box::new(std::iter::empty()),
    })
}

/// Verify the hash chain of the SQLite ledger at `path` without opening it
/// as a store (so a ledger too damaged to open can still be diagnosed).
///
/// Same contract as [`verify`](crate::verify()): a record that fails its
/// hash, its chain link, or cannot be decoded at all (including a row key
/// that disagrees with the record's index) is reported as
/// `broken_at: Some(i)`.
pub fn verify_sqlite(path: impl AsRef<Path>) -> Result<VerifyReport> {
    verify_records(read_only_records(path.as_ref())?)
}
