//! Store selection: which backend holds the ledger at a given path.
//!
//! Detection is content-first, extension-second, and fails closed:
//!
//! - a file that starts with the 16-byte SQLite header is a SQLite ledger,
//!   whatever it is called;
//! - a non-empty file without that header is a JSONL ledger — unless its
//!   extension claims SQLite (`.db`, `.sqlite`, `.sqlite3`), which is
//!   ambiguous and therefore an error rather than a guess;
//! - a missing or empty file is decided by extension (SQLite for the three
//!   extensions above, JSONL otherwise), so `open_store` can create it.
//!
//! Without the `sqlite` cargo feature, a SQLite ledger is reported as an
//! error — it is never parsed as JSONL.
//!
//! A location whose text starts with `postgres://` or `postgresql://` is a
//! Postgres ledger (checked before anything touches the filesystem).
//! Without the `postgres` cargo feature it is reported as an error, never
//! treated as a file path. Display such locations with [`display_ledger`],
//! which redacts the password.

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;

use provio_core::error::{ProvioError, Result};
use provio_core::ledger::{LedgerRecord, LedgerStore};

use crate::file_store::{record_iter, FileLedgerStore};

/// The 16-byte header every SQLite 3 database file starts with.
pub(crate) const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// Which backend a ledger path refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    /// [`FileLedgerStore`]: one JSON record per line (ADR-005 default).
    Jsonl,
    /// `SqliteLedgerStore` (WAL mode; needs the `sqlite` feature to open).
    Sqlite,
    /// `PostgresLedgerStore`: a `postgres://` / `postgresql://` URL (needs
    /// the `postgres` feature to open).
    Postgres,
}

/// Whether `location` is a Postgres connection URL (`postgres://` or
/// `postgresql://`, scheme case-insensitive).
pub fn is_postgres_url(location: &str) -> bool {
    let scheme = |p: &str| {
        location
            .get(..p.len())
            .is_some_and(|s| s.eq_ignore_ascii_case(p))
    };
    scheme("postgres://") || scheme("postgresql://")
}

/// The Postgres URL held by a ledger path, if it is one.
pub(crate) fn postgres_location(path: &Path) -> Option<&str> {
    path.to_str().filter(|s| is_postgres_url(s))
}

/// `url` with its password replaced by `***` (both the userinfo password
/// and a `password=` query parameter). Safe to log.
pub fn redact_postgres_url(url: &str) -> String {
    let Some(pos) = url.find("://") else {
        return "<postgres url>".to_string();
    };
    let (scheme, rest) = url.split_at(pos + 3);
    let (before_query, query) = match rest.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (rest, None),
    };
    // Userinfo ends at the last '@' before the query, so a password with a
    // raw '/' or '@' is still fully covered.
    let authority_and_path = match before_query.rfind('@') {
        Some(at) => {
            let (userinfo, host) = before_query.split_at(at);
            match userinfo.split_once(':') {
                Some((user, _)) => format!("{user}:***{host}"),
                None => before_query.to_string(),
            }
        }
        None => before_query.to_string(),
    };
    let mut out = format!("{scheme}{authority_and_path}");
    if let Some(q) = query {
        let pairs: Vec<String> = q
            .split('&')
            .map(|kv| {
                let key = kv.split('=').next().unwrap_or("");
                if key.eq_ignore_ascii_case("password") {
                    "password=***".to_string()
                } else {
                    kv.to_string()
                }
            })
            .collect();
        out.push('?');
        out.push_str(&pairs.join("&"));
    }
    out
}

/// A ledger location fit for display: file paths as-is, Postgres URLs with
/// the password redacted. Use this (never `Path::display`) when printing
/// `--ledger`.
pub fn display_ledger(path: impl AsRef<Path>) -> String {
    let path = path.as_ref();
    match postgres_location(path) {
        Some(url) => redact_postgres_url(url),
        None => path.display().to_string(),
    }
}

fn kind_by_extension(path: &Path) -> StoreKind {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("db" | "sqlite" | "sqlite3") => StoreKind::Sqlite,
        _ => StoreKind::Jsonl,
    }
}

/// Decide which backend holds (or will hold) the ledger at `path`.
/// See the module docs for the rules.
pub fn detect_store_kind(path: impl AsRef<Path>) -> Result<StoreKind> {
    let path = path.as_ref();
    if postgres_location(path).is_some() {
        return Ok(StoreKind::Postgres);
    }
    let mut head = Vec::with_capacity(SQLITE_MAGIC.len());
    match File::open(path) {
        Ok(f) => {
            f.take(SQLITE_MAGIC.len() as u64).read_to_end(&mut head)?;
        }
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(kind_by_extension(path)),
        Err(e) => return Err(e.into()),
    }
    if head.as_slice() == SQLITE_MAGIC {
        return Ok(StoreKind::Sqlite);
    }
    if head.is_empty() {
        return Ok(kind_by_extension(path));
    }
    if kind_by_extension(path) == StoreKind::Sqlite {
        return Err(ProvioError::Ledger(format!(
            "ledger {path:?} has a SQLite file extension but no SQLite header; \
             refusing to guess its format"
        )));
    }
    Ok(StoreKind::Jsonl)
}

#[cfg(not(feature = "sqlite"))]
pub(crate) fn sqlite_unavailable(path: &Path) -> ProvioError {
    ProvioError::Ledger(format!(
        "ledger {path:?} is a SQLite ledger, but this build of provio-ledger was \
         compiled without the `sqlite` feature"
    ))
}

#[cfg(not(feature = "postgres"))]
pub(crate) fn postgres_unavailable(path: &Path) -> ProvioError {
    ProvioError::Ledger(format!(
        "ledger {} is a Postgres ledger, but this build of provio-ledger was          compiled without the `postgres` feature",
        display_ledger(path)
    ))
}

/// The URL of a path already classified as [`StoreKind::Postgres`].
#[cfg(feature = "postgres")]
pub(crate) fn postgres_url(path: &Path) -> &str {
    postgres_location(path).expect("classified as a Postgres URL")
}

/// Open (creating if absent) the ledger at `path` with the backend chosen
/// by [`detect_store_kind`].
pub fn open_store(path: impl AsRef<Path>) -> Result<Box<dyn LedgerStore>> {
    let path = path.as_ref();
    match detect_store_kind(path)? {
        StoreKind::Jsonl => Ok(Box::new(FileLedgerStore::open(path)?)),
        #[cfg(feature = "sqlite")]
        StoreKind::Sqlite => Ok(Box::new(crate::sqlite::SqliteLedgerStore::open(path)?)),
        #[cfg(not(feature = "sqlite"))]
        StoreKind::Sqlite => Err(sqlite_unavailable(path)),
        #[cfg(feature = "postgres")]
        StoreKind::Postgres => Ok(Box::new(crate::postgres::PostgresLedgerStore::open(
            postgres_url(path),
        )?)),
        #[cfg(not(feature = "postgres"))]
        StoreKind::Postgres => Err(postgres_unavailable(path)),
    }
}

/// Read-only record stream over an existing ledger, in ledger order. Does
/// not create, repair or lock anything; used by `verify` and the query
/// helpers.
pub(crate) fn read_records(path: &Path) -> Result<Box<dyn Iterator<Item = Result<LedgerRecord>>>> {
    match detect_store_kind(path)? {
        StoreKind::Jsonl => Ok(Box::new(record_iter(File::open(path)?))),
        #[cfg(feature = "sqlite")]
        StoreKind::Sqlite => Ok(Box::new(crate::sqlite::read_only_records(path)?)),
        #[cfg(not(feature = "sqlite"))]
        StoreKind::Sqlite => Err(sqlite_unavailable(path)),
        #[cfg(feature = "postgres")]
        StoreKind::Postgres => crate::postgres::read_only_records(postgres_url(path)),
        #[cfg(not(feature = "postgres"))]
        StoreKind::Postgres => Err(postgres_unavailable(path)),
    }
}
