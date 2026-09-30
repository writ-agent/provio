//! Acceptance tests for SqliteLedgerStore (`sqlite` feature): the shared
//! store-generic suite plus SQLite-specific schema, concurrency and
//! cross-store tests. Tampering is done with raw SQL, the way an attacker
//! with write access to the database file would do it.

#![cfg(feature = "sqlite")]

#[macro_use]
mod common;

use std::path::Path;

use common::{allow, call, deny, ledger_path, populated, Backend, TempDir};
use provio_core::error::ProvioError;
use provio_core::ledger::{LedgerRecord, LedgerStore, LedgerWriter};
use provio_ledger::sqlite::{APPLICATION_ID, STORE_VERSION};
use provio_ledger::{
    detect_store_kind, verify, verify_jsonl, verify_sqlite, FileLedgerStore, SqliteLedgerStore,
    StoreKind,
};
use rusqlite::{params, Connection};

struct SqliteBackend;

/// A raw connection with the append-only guards removed — demonstrating
/// that the triggers are tamper-*evidence* support, not prevention: the
/// hash chain is what catches the edit.
fn attacker(path: &Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "DROP TRIGGER ledger_no_update;
         DROP TRIGGER ledger_no_delete;
         PRAGMA ignore_check_constraints = ON;",
    )
    .unwrap();
    conn
}

impl Backend for SqliteBackend {
    type Store = SqliteLedgerStore;
    const FILE_NAME: &'static str = "ledger.db";
    const CORRUPTION_MSG: &'static str = "mid-ledger corruption";

    fn open(path: &Path) -> Result<Self::Store, ProvioError> {
        SqliteLedgerStore::open(path)
    }

    fn tamper_session(path: &Path, idx: u64, session_id: &str) {
        let n = attacker(path)
            .execute(
                "UPDATE ledger SET record = json_set(record, '$.session_id', ?1) WHERE idx = ?2",
                params![session_id, idx as i64],
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    fn make_unparseable(path: &Path, idx: u64) {
        // Not even JSON any more ('{' -> 'X'); only possible with the CHECK
        // constraints switched off.
        let n = attacker(path)
            .execute(
                "UPDATE ledger SET record = 'X' || substr(record, 2) WHERE idx = ?1",
                params![idx as i64],
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    fn delete_record(path: &Path, idx: u64) {
        let n = attacker(path)
            .execute("DELETE FROM ledger WHERE idx = ?1", params![idx as i64])
            .unwrap();
        assert_eq!(n, 1);
    }
}

ledger_suite!(SqliteBackend);

fn raw(path: &Path) -> Connection {
    Connection::open(path).unwrap()
}

#[test]
fn database_is_tagged_and_in_wal_mode() {
    let dir = TempDir::new();
    let path = populated::<SqliteBackend>(&dir);
    assert_eq!(detect_store_kind(&path).unwrap(), StoreKind::Sqlite);
    let conn = raw(&path);
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode.to_ascii_lowercase(), "wal");
    let app: i32 = conn
        .query_row("PRAGMA application_id", [], |r| r.get(0))
        .unwrap();
    assert_eq!(app, APPLICATION_ID);
    let ver: i32 = conn
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(ver, STORE_VERSION);
}

#[test]
fn triggers_reject_update_delete_and_forked_insert() {
    let dir = TempDir::new();
    let path = populated::<SqliteBackend>(&dir);
    let conn = raw(&path);

    let err = conn
        .execute("UPDATE ledger SET record = record WHERE idx = 1", [])
        .unwrap_err();
    assert!(err.to_string().contains("append-only"), "got {err}");
    let err = conn
        .execute("DELETE FROM ledger WHERE idx = 2", [])
        .unwrap_err();
    assert!(err.to_string().contains("append-only"), "got {err}");
    let err = conn.execute("DELETE FROM ledger", []).unwrap_err();
    assert!(err.to_string().contains("append-only"), "got {err}");

    // A second record claiming index 1 (a fork), via plain INSERT and via
    // INSERT OR REPLACE (which would otherwise delete the original row).
    let store = SqliteLedgerStore::open(&path).unwrap();
    let mut fork = store.get(1).unwrap().unwrap();
    fork.session_id = "fork".into();
    fork.record_hash = fork.compute_hash().unwrap();
    let text = serde_json::to_string(&fork).unwrap();
    for sql in [
        "INSERT INTO ledger (idx, record) VALUES (?1, ?2)",
        "INSERT OR REPLACE INTO ledger (idx, record) VALUES (?1, ?2)",
    ] {
        let err = conn.execute(sql, params![1i64, text]).unwrap_err();
        assert!(err.to_string().contains("append-only"), "{sql}: got {err}");
    }
    // Right index, wrong link.
    let mut orphan = store.tip().unwrap().unwrap();
    orphan.index = 3;
    orphan.prev_hash = "f".repeat(64);
    orphan.record_hash = orphan.compute_hash().unwrap();
    let err = conn
        .execute(
            "INSERT INTO ledger (idx, record) VALUES (3, ?1)",
            params![serde_json::to_string(&orphan).unwrap()],
        )
        .unwrap_err();
    assert!(err.to_string().contains("prev_hash"), "got {err}");
    // Row key disagreeing with the record's own index.
    orphan.prev_hash = store.tip().unwrap().unwrap().record_hash;
    let err = conn
        .execute(
            "INSERT INTO ledger (idx, record) VALUES (3, ?1)",
            params![serde_json::to_string(&LedgerRecord { index: 9, ..orphan }).unwrap()],
        )
        .unwrap_err();
    assert!(err.to_string().contains("CHECK"), "got {err}");

    // Nothing got through.
    let report = verify(&path).unwrap();
    assert!(report.intact);
    assert_eq!(report.records, 3);
}

#[test]
fn corrupt_last_row_is_a_hard_error_on_open() {
    // A SQLite commit is atomic, so there is no torn-tail allowance: even
    // the final record being unparseable means tampering.
    let dir = TempDir::new();
    let path = populated::<SqliteBackend>(&dir);
    SqliteBackend::make_unparseable(&path, 2);
    let err = SqliteLedgerStore::open(&path).unwrap_err();
    assert!(
        err.to_string().contains("mid-ledger corruption"),
        "got {err}"
    );
    let report = verify(&path).unwrap();
    assert_eq!(report.broken_at, Some(2));
    assert_eq!(report.records, 2);
}

#[test]
fn row_key_mismatch_is_reported_at_its_position() {
    let dir = TempDir::new();
    let path = populated::<SqliteBackend>(&dir);
    // Move record 2 to key 10 (rows now 0, 1, 10) without touching its JSON.
    attacker(&path)
        .execute("UPDATE ledger SET idx = 10 WHERE idx = 2", [])
        .unwrap();
    let report = verify_sqlite(&path).unwrap();
    assert!(!report.intact);
    assert_eq!(report.broken_at, Some(2));
    assert_eq!(report.records, 2);
    assert!(SqliteLedgerStore::open(&path).is_err());
}

#[test]
fn stale_writer_cannot_fork_the_chain() {
    let dir = TempDir::new();
    let path = populated::<SqliteBackend>(&dir);
    let mut a = SqliteLedgerStore::open(&path).unwrap();
    let mut b = SqliteLedgerStore::open(&path).unwrap();

    // b prepares a record on the current tip (index 3)...
    let tip = b.tip().unwrap().unwrap();
    let mut stale = tip.clone();
    stale.index = 3;
    stale.call_id = "b-call".into();
    stale.prev_hash = tip.record_hash.clone();
    stale.record_hash = stale.compute_hash().unwrap();

    // ...but a appends first.
    LedgerWriter::new(&mut a)
        .record_decision(&call("a-call", "s1"), &allow(), None)
        .unwrap();

    // b's view is refreshed from the database, and its append is rejected.
    assert_eq!(b.len(), 4);
    let err = b.append(&stale).unwrap_err();
    assert!(matches!(err, ProvioError::Ledger(_)), "got {err:?}");
    assert!(err.to_string().contains("append rejected"), "got {err}");

    // Retrying through LedgerWriter rebuilds on the new tip and succeeds.
    LedgerWriter::new(&mut b)
        .record_decision(&call("b-call", "s1"), &allow(), None)
        .unwrap();
    assert_eq!(a.len(), 5);
    assert_eq!(a.tip().unwrap().unwrap().call_id, "b-call");
    let report = verify(&path).unwrap();
    assert!(report.intact);
    assert_eq!(report.records, 5);
}

#[test]
fn concurrent_writers_produce_one_linear_chain() {
    const THREADS: usize = 4;
    const PER_THREAD: usize = 20;
    let dir = TempDir::new();
    let path = ledger_path::<SqliteBackend>(&dir);
    drop(SqliteLedgerStore::open(&path).unwrap()); // create the schema

    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut store = SqliteLedgerStore::open(&path).unwrap();
                let mut rejected = 0u32;
                for i in 0..PER_THREAD {
                    let c = call(&format!("t{t}-c{i}"), &format!("t{t}"));
                    loop {
                        match LedgerWriter::new(&mut store).record_decision(&c, &allow(), None) {
                            Ok(_) => break,
                            // Lost the race for the tip: rebuild and retry.
                            Err(ProvioError::Ledger(m)) if m.contains("append rejected") => {
                                rejected += 1;
                            }
                            Err(e) => panic!("thread {t}: {e}"),
                        }
                    }
                }
                rejected
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }

    let report = verify(&path).unwrap();
    assert!(report.intact, "{report:?}");
    assert_eq!(report.records, (THREADS * PER_THREAD) as u64);
    let store = SqliteLedgerStore::open(&path).unwrap();
    let mut ids: Vec<String> = store.iter().map(|r| r.unwrap().call_id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), THREADS * PER_THREAD, "every call recorded once");
}

/// Copy every record from one store into another, unchanged.
fn import(from: &dyn LedgerStore, to: &mut dyn LedgerStore) {
    for rec in from.iter() {
        to.append(&rec.unwrap()).unwrap();
    }
}

#[test]
fn records_move_between_stores_and_verify_identically() {
    let dir = TempDir::new();
    let jsonl = populated::<common::FileBackend>(&dir);
    let db = dir.path().join("imported.db");

    // JSONL -> SQLite.
    let file_store = FileLedgerStore::open(&jsonl).unwrap();
    let mut sql_store = SqliteLedgerStore::open(&db).unwrap();
    import(&file_store, &mut sql_store);
    LedgerWriter::new(&mut sql_store)
        .record_decision(&call("c4", "s3"), &deny(), None)
        .unwrap();

    // Each SQLite row is byte-for-byte the JSONL line.
    let lines: Vec<String> = std::fs::read_to_string(&jsonl)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let rows: Vec<String> = {
        let conn = raw(&db);
        let mut stmt = conn
            .prepare("SELECT record FROM ledger ORDER BY idx")
            .unwrap();
        let rows = stmt.query_map([], |r| r.get(0)).unwrap();
        rows.collect::<Result<_, _>>().unwrap()
    };
    assert_eq!(rows[..3], lines[..]);

    // SQLite -> JSONL (including the record first written by SQLite).
    let round = dir.path().join("round.jsonl");
    let mut back = FileLedgerStore::open(&round).unwrap();
    import(&sql_store, &mut back);

    let a = verify_jsonl(&jsonl).unwrap();
    let b = verify_sqlite(&db).unwrap();
    let c = verify(&round).unwrap();
    assert!(a.intact && b.intact && c.intact);
    assert_eq!((a.records, b.records, c.records), (3, 4, 4));
    assert_eq!(std::fs::read_to_string(&round).unwrap().lines().count(), 4);
    let hashes =
        |s: &dyn LedgerStore| -> Vec<String> { s.iter().map(|r| r.unwrap().record_hash).collect() };
    assert_eq!(hashes(&sql_store), hashes(&back));
}

#[test]
fn refuses_foreign_and_future_databases() {
    let dir = TempDir::new();

    let foreign = dir.path().join("app.db");
    raw(&foreign)
        .execute_batch("CREATE TABLE users (id INTEGER PRIMARY KEY);")
        .unwrap();
    let err = SqliteLedgerStore::open(&foreign).unwrap_err();
    assert!(err.to_string().contains("not a PROVIO ledger"), "got {err}");
    assert!(verify(&foreign).is_err());
    // Nothing was added to the foreign database.
    let tables: i64 = raw(&foreign)
        .query_row("SELECT COUNT(*) FROM sqlite_schema", [], |r| r.get(0))
        .unwrap();
    assert_eq!(tables, 1);

    let other_app = dir.path().join("other.db");
    raw(&other_app)
        .execute_batch("PRAGMA application_id = 42;")
        .unwrap();
    let err = SqliteLedgerStore::open(&other_app).unwrap_err();
    assert!(err.to_string().contains("not a PROVIO ledger"), "got {err}");

    let future = populated::<SqliteBackend>(&dir);
    raw(&future)
        .execute_batch(&format!("PRAGMA user_version = {};", STORE_VERSION + 1))
        .unwrap();
    let err = SqliteLedgerStore::open(&future).unwrap_err();
    assert!(err.to_string().contains("unsupported"), "got {err}");
    assert!(verify(&future).is_err());
}

#[test]
fn read_paths_do_not_create_ledgers() {
    let dir = TempDir::new();
    let missing = dir.path().join("missing.db");
    assert!(matches!(verify(&missing), Err(ProvioError::Io(_))));
    assert!(matches!(verify_sqlite(&missing), Err(ProvioError::Io(_))));
    assert!(provio_ledger::sessions(&missing).is_err());
    assert!(!missing.exists());

    // A blank (zero-byte) database is an empty, intact ledger.
    let blank = dir.path().join("blank.db");
    std::fs::write(&blank, b"").unwrap();
    let report = verify(&blank).unwrap();
    assert!(report.intact);
    assert_eq!(report.records, 0);
    assert!(provio_ledger::sessions(&blank).unwrap().is_empty());
}
