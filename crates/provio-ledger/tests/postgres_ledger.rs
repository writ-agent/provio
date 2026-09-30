//! Acceptance tests for PostgresLedgerStore (`postgres` feature): the shared
//! store-generic suite plus Postgres-specific schema, trigger, concurrency,
//! TLS and cross-store tests. Tampering is done with raw SQL, the way the
//! table owner (or a superuser) would do it.
//!
//! Needs a server: set `PROVIO_POSTGRES_URL` (e.g.
//! `postgres://provio:pw@localhost/provio_test`) to a database the role may
//! create schemas in. Each test works in its own schema `provio_test_<pid>_<n>`;
//! schemas left by earlier runs are dropped on first use. Without the
//! variable every test here prints a skip notice and passes.
//!
//! Optional: `PROVIO_POSTGRES_TLS=1` when the server accepts TLS (checks
//! `sslmode=require`), and `PROVIO_POSTGRES_SSLROOTCERT=<pem>` naming the CA
//! (or self-signed certificate) that signed the server certificate (checks
//! `verify-ca`).

#![cfg(feature = "postgres")]

#[macro_use]
mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Once};
use std::time::Duration;

use common::{allow, call, deny, ledger_path, populated, Backend, TempDir};
use postgres::Client;
use provio_core::error::ProvioError;
use provio_core::ledger::{LedgerRecord, LedgerStore, LedgerWriter};
use provio_ledger::postgres::{connect, APPLICATION, STORE_VERSION};
use provio_ledger::{
    detect_store_kind, display_ledger, open_store, retry_append, verify, verify_jsonl,
    verify_postgres, FileLedgerStore, PostgresLedgerStore, StoreKind,
};

const ENV: &str = "PROVIO_POSTGRES_URL";

fn base_url() -> Option<String> {
    std::env::var(ENV).ok().filter(|s| !s.is_empty())
}

/// Guard for every test in this file (and the generic suite).
fn pg_available() -> bool {
    if base_url().is_none() {
        eprintln!(
            "skipping Postgres ledger test: set {ENV}=postgres://user:pass@host/db to run it"
        );
        return false;
    }
    static CLEANUP: Once = Once::new();
    CLEANUP.call_once(drop_stale_schemas);
    true
}

/// Drop test schemas left behind by earlier runs (other process ids).
fn drop_stale_schemas() {
    let mut c = raw();
    let mine = format!("provio_test_{}_", std::process::id());
    let rows = c
        .query(
            "SELECT nspname::text FROM pg_namespace WHERE nspname LIKE 'provio\\_test\\_%'",
            &[],
        )
        .unwrap();
    for row in rows {
        let name: String = row.get(0);
        if !name.starts_with(&mine) {
            c.batch_execute(&format!("DROP SCHEMA IF EXISTS \"{name}\" CASCADE"))
                .unwrap();
        }
    }
}

/// `PROVIO_POSTGRES_URL` plus extra query parameters.
fn url_with(extra: &str) -> String {
    let base = base_url().expect("guarded by pg_available");
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{base}{sep}{extra}")
}

/// A schema name unique to `dir` (which is unique per test).
fn schema_for(dir: &TempDir) -> String {
    let name = dir.path().file_name().unwrap().to_str().unwrap();
    name.replace("provio-ledger-test-", "provio_test_")
        .replace('-', "_")
}

fn url_str(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// The `provio_schema` parameter of a test location.
fn schema_of(path: &Path) -> String {
    let url = url_str(path);
    let start = url.find("provio_schema=").unwrap() + "provio_schema=".len();
    url[start..].split('&').next().unwrap().to_string()
}

fn ledger_table(path: &Path) -> String {
    format!("\"{}\".\"ledger\"", schema_of(path))
}

fn meta_table(path: &Path) -> String {
    format!("\"{}\".\"ledger_meta\"", schema_of(path))
}

/// A plain connection to the test database (same TLS / URL handling).
fn raw() -> Client {
    connect(&base_url().unwrap()).unwrap()
}

/// A raw connection with the append-only guards removed — demonstrating
/// that the triggers are tamper-*evidence* support, not prevention: the
/// hash chain is what catches the edit.
fn attacker(path: &Path) -> Client {
    let mut c = raw();
    let t = ledger_table(path);
    c.batch_execute(&format!(
        "ALTER TABLE {t} DISABLE TRIGGER USER;
         ALTER TABLE {t} DROP CONSTRAINT IF EXISTS ledger_idx_is_record_index;"
    ))
    .unwrap();
    c
}

struct PgBackend;

impl Backend for PgBackend {
    type Store = PostgresLedgerStore;
    const FILE_NAME: &'static str = "ledger";
    const CORRUPTION_MSG: &'static str = "mid-ledger corruption";

    fn open(path: &Path) -> Result<Self::Store, ProvioError> {
        PostgresLedgerStore::open(url_str(path))
    }

    fn location(dir: &TempDir) -> PathBuf {
        PathBuf::from(url_with(&format!("provio_schema={}", schema_for(dir))))
    }

    fn tamper_session(path: &Path, idx: u64, session_id: &str) {
        let n = attacker(path)
            .execute(
                &format!(
                    "UPDATE {} SET record = (record::jsonb || jsonb_build_object('session_id', $1::text))::text \
                     WHERE idx = $2",
                    ledger_table(path)
                ),
                &[&session_id, &(idx as i64)],
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    fn make_unparseable(path: &Path, idx: u64) {
        // Not even JSON any more ('{' -> 'X'); only possible with the CHECK
        // constraint dropped.
        let n = attacker(path)
            .execute(
                &format!(
                    "UPDATE {} SET record = 'X' || substr(record, 2) WHERE idx = $1",
                    ledger_table(path)
                ),
                &[&(idx as i64)],
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    fn delete_record(path: &Path, idx: u64) {
        let n = attacker(path)
            .execute(
                &format!("DELETE FROM {} WHERE idx = $1", ledger_table(path)),
                &[&(idx as i64)],
            )
            .unwrap();
        assert_eq!(n, 1);
    }
}

ledger_suite!(PgBackend, guard = pg_available);

fn assert_err_contains(err: impl std::fmt::Display, needle: &str) {
    let s = err.to_string();
    assert!(s.contains(needle), "expected {needle:?} in: {s}");
}

fn db_err(e: postgres::Error) -> String {
    e.as_db_error()
        .map(|d| d.message().to_string())
        .unwrap_or_else(|| e.to_string())
}

fn schema_exists(schema: &str) -> bool {
    raw()
        .query_opt("SELECT 1 FROM pg_namespace WHERE nspname = $1", &[&schema])
        .unwrap()
        .is_some()
}

#[test]
fn schema_is_created_tagged_and_guarded() {
    if !pg_available() {
        return;
    }
    let dir = TempDir::new();
    let path = populated::<PgBackend>(&dir);
    assert_eq!(detect_store_kind(&path).unwrap(), StoreKind::Postgres);
    let store = PgBackend::open(&path).unwrap();
    assert_eq!(store.schema(), schema_of(&path));
    assert_eq!(store.table(), "ledger");

    let mut c = raw();
    let row = c
        .query_one(
            &format!(
                "SELECT application, store_version, ledger_table FROM {}",
                meta_table(&path)
            ),
            &[],
        )
        .unwrap();
    assert_eq!(row.get::<_, String>(0), APPLICATION);
    assert_eq!(row.get::<_, i32>(1), STORE_VERSION);
    assert_eq!(row.get::<_, String>(2), "ledger");
    let triggers: i64 = c
        .query_one(
            "SELECT count(*) FROM pg_trigger t JOIN pg_class r ON r.oid = t.tgrelid \
             JOIN pg_namespace n ON n.oid = r.relnamespace \
             WHERE n.nspname = $1 AND NOT t.tgisinternal AND t.tgenabled = 'O'",
            &[&schema_of(&path)],
        )
        .unwrap()
        .get(0);
    assert_eq!(triggers, 7, "insert guard + 3 on ledger + 3 on marker");
    // The record column is TEXT (byte-exact), not JSONB.
    let ty: String = c
        .query_one(
            "SELECT data_type::text FROM information_schema.columns \
             WHERE table_schema = $1 AND table_name = 'ledger' AND column_name = 'record'",
            &[&schema_of(&path)],
        )
        .unwrap()
        .get(0);
    assert_eq!(ty, "text");
}

#[test]
fn custom_table_names_and_several_ledgers_per_schema() {
    if !pg_available() {
        return;
    }
    let dir = TempDir::new();
    let schema = schema_for(&dir);
    let a = url_with(&format!("provio_schema={schema}&provio_table=audit_a"));
    let b = url_with(&format!("provio_schema={schema}&provio_table=audit_b"));
    for (url, n) in [(&a, 2), (&b, 1)] {
        let mut store = PostgresLedgerStore::open(url).unwrap();
        assert_eq!(store.table(), &url[url.len() - 7..]);
        let mut w = LedgerWriter::new(&mut store);
        for i in 0..n {
            w.record_decision(&call(&format!("c{i}"), "s"), &allow(), None)
                .unwrap();
        }
    }
    assert_eq!(verify(&a).unwrap().records, 2);
    assert_eq!(verify(&b).unwrap().records, 1);
    // Both reopen: a schema holding only PROVIO ledgers is accepted.
    assert_eq!(PostgresLedgerStore::open(&a).unwrap().len(), 2);
    assert_eq!(PostgresLedgerStore::open(&b).unwrap().len(), 1);

    for bad in ["Ledger", "1x", "a-b", "pg_x", "x;drop"] {
        let err = PostgresLedgerStore::open(url_with(&format!("provio_table={bad}"))).unwrap_err();
        assert_err_contains(err, "invalid provio_table");
    }
}

#[test]
fn triggers_reject_update_delete_truncate_and_forked_insert() {
    if !pg_available() {
        return;
    }
    let dir = TempDir::new();
    let path = populated::<PgBackend>(&dir);
    let (ledger, meta) = (ledger_table(&path), meta_table(&path));
    let mut c = raw();

    for sql in [
        format!("UPDATE {ledger} SET record = record WHERE idx = 1"),
        format!("UPDATE {ledger} SET record = record WHERE false"),
        format!("DELETE FROM {ledger} WHERE idx = 2"),
        format!("DELETE FROM {ledger}"),
        format!("TRUNCATE {ledger}"),
        format!("UPDATE {meta} SET store_version = 1"),
        format!("DELETE FROM {meta}"),
        format!("TRUNCATE {meta}"),
    ] {
        let err = c.batch_execute(&sql).unwrap_err();
        let msg = db_err(err);
        assert!(msg.contains("append-only"), "{sql}: got {msg}");
    }

    // A second record claiming index 1 (a fork), via plain INSERT and via
    // an upsert that would otherwise overwrite the original row.
    let store = PgBackend::open(&path).unwrap();
    let mut fork = store.get(1).unwrap().unwrap();
    fork.session_id = "fork".into();
    fork.record_hash = fork.compute_hash().unwrap();
    let text = serde_json::to_string(&fork).unwrap();
    for sql in [
        format!("INSERT INTO {ledger} (idx, record) VALUES ($1, $2)"),
        format!(
            "INSERT INTO {ledger} (idx, record) VALUES ($1, $2) \
             ON CONFLICT (idx) DO UPDATE SET record = EXCLUDED.record"
        ),
    ] {
        let err = c.execute(&sql, &[&1i64, &text]).unwrap_err();
        let msg = db_err(err);
        assert!(msg.contains("append-only"), "{sql}: got {msg}");
    }
    // Right index, wrong link.
    let mut orphan = store.tip().unwrap().unwrap();
    orphan.index = 3;
    orphan.prev_hash = "f".repeat(64);
    orphan.record_hash = orphan.compute_hash().unwrap();
    let err = c
        .execute(
            &format!("INSERT INTO {ledger} (idx, record) VALUES (3, $1)"),
            &[&serde_json::to_string(&orphan).unwrap()],
        )
        .unwrap_err();
    assert!(db_err(err).contains("prev_hash"));
    // Row key disagreeing with the record's own index.
    orphan.prev_hash = store.tip().unwrap().unwrap().record_hash;
    let err = c
        .execute(
            &format!("INSERT INTO {ledger} (idx, record) VALUES (3, $1)"),
            &[&serde_json::to_string(&LedgerRecord { index: 9, ..orphan }).unwrap()],
        )
        .unwrap_err();
    assert!(db_err(err).contains("check constraint"));
    // Not JSON at all.
    let err = c
        .execute(
            &format!("INSERT INTO {ledger} (idx, record) VALUES (3, 'not json')"),
            &[],
        )
        .unwrap_err();
    let msg = db_err(err);
    assert!(msg.contains("json"), "got {msg}");

    // Nothing got through.
    let report = verify(&path).unwrap();
    assert!(report.intact);
    assert_eq!(report.records, 3);
}

#[test]
fn raw_inserters_are_serialized_by_the_trigger_lock() {
    if !pg_available() {
        return;
    }
    // Two raw SQL writers build index 3 on the same tip. The first holds
    // the marker lock (taken inside the insert trigger) until it commits;
    // the second waits, then sees the new tip and is rejected.
    let dir = TempDir::new();
    let path = populated::<PgBackend>(&dir);
    let ledger = ledger_table(&path);
    let store = PgBackend::open(&path).unwrap();
    let tip = store.tip().unwrap().unwrap();
    let make = |call_id: &str| {
        let mut r = tip.clone();
        r.index = 3;
        r.call_id = call_id.into();
        r.prev_hash = tip.record_hash.clone();
        r.record_hash = r.compute_hash().unwrap();
        serde_json::to_string(&r).unwrap()
    };
    let (first, second) = (make("raw-a"), make("raw-b"));

    let mut a = raw();
    let mut tx = a.transaction().unwrap();
    tx.execute(
        &format!("INSERT INTO {ledger} (idx, record) VALUES (3, $1)"),
        &[&first],
    )
    .unwrap();
    let ledger2 = ledger.clone();
    let loser = std::thread::spawn(move || {
        raw()
            .execute(
                &format!("INSERT INTO {ledger2} (idx, record) VALUES (3, $1)"),
                &[&second],
            )
            .map_err(db_err)
    });
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !loser.is_finished(),
        "second inserter must wait for the lock"
    );
    tx.commit().unwrap();
    let msg = loser.join().unwrap().unwrap_err();
    assert!(msg.contains("append-only"), "got {msg}");

    let report = verify(&path).unwrap();
    assert!(report.intact);
    assert_eq!(report.records, 4);
    assert_eq!(store.tip().unwrap().unwrap().call_id, "raw-a");
}

#[test]
fn corrupt_last_row_is_a_hard_error_on_open() {
    if !pg_available() {
        return;
    }
    // A Postgres commit is atomic, so there is no torn-tail allowance.
    let dir = TempDir::new();
    let path = populated::<PgBackend>(&dir);
    PgBackend::make_unparseable(&path, 2);
    let err = PgBackend::open(&path).unwrap_err();
    assert_err_contains(err, "mid-ledger corruption");
    let report = verify(&path).unwrap();
    assert_eq!(report.broken_at, Some(2));
    assert_eq!(report.records, 2);
}

#[test]
fn row_key_mismatch_is_reported_at_its_position() {
    if !pg_available() {
        return;
    }
    let dir = TempDir::new();
    let path = populated::<PgBackend>(&dir);
    // Move record 2 to key 10 (rows now 0, 1, 10) without touching its JSON.
    attacker(&path)
        .execute(
            &format!("UPDATE {} SET idx = 10 WHERE idx = 2", ledger_table(&path)),
            &[],
        )
        .unwrap();
    let report = verify_postgres(url_str(&path)).unwrap();
    assert!(!report.intact);
    assert_eq!(report.broken_at, Some(2));
    assert_eq!(report.records, 2);
    assert!(PgBackend::open(&path).is_err());
}

#[test]
fn stale_writer_cannot_fork_the_chain() {
    if !pg_available() {
        return;
    }
    let dir = TempDir::new();
    let path = populated::<PgBackend>(&dir);
    let mut a = PgBackend::open(&path).unwrap();
    let mut b = PgBackend::open(&path).unwrap();

    // b prepares a record on the current tip (index 3)...
    let tip = b.tip().unwrap().unwrap();
    let mut stale = tip.clone();
    stale.index = 3;
    stale.call_id = "b-call".into();
    stale.prev_hash = tip.record_hash.clone();
    stale.record_hash = stale.compute_hash().unwrap();

    // ...but a (another connection, as on another host) appends first.
    LedgerWriter::new(&mut a)
        .record_decision(&call("a-call", "s1"), &allow(), None)
        .unwrap();

    assert_eq!(b.len(), 4);
    let err = b.append(&stale).unwrap_err();
    assert!(matches!(err, ProvioError::Ledger(_)), "got {err:?}");
    assert_err_contains(&err, "append rejected");
    assert!(provio_ledger::is_append_race(&err));

    // Retrying through LedgerWriter rebuilds on the new tip and succeeds.
    retry_append(|| {
        LedgerWriter::new(&mut b).record_decision(&call("b-call", "s1"), &allow(), None)
    })
    .unwrap();
    assert_eq!(a.len(), 5);
    assert_eq!(a.tip().unwrap().unwrap().call_id, "b-call");
    let report = verify(&path).unwrap();
    assert!(report.intact);
    assert_eq!(report.records, 5);
}

fn assert_linear(path: &Path, expected: usize) {
    let report = verify(path).unwrap();
    assert!(report.intact, "{report:?}");
    assert_eq!(report.records, expected as u64);
    let store = PgBackend::open(path).unwrap();
    let mut ids: Vec<String> = store.iter().map(|r| r.unwrap().call_id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), expected, "every call recorded exactly once");
}

#[test]
fn concurrent_writers_on_separate_connections_produce_one_linear_chain() {
    if !pg_available() {
        return;
    }
    const THREADS: usize = 6;
    const PER_THREAD: usize = 25;
    let dir = TempDir::new();
    let path = ledger_path::<PgBackend>(&dir);
    drop(PgBackend::open(&path).unwrap()); // create the schema
    let start = Arc::new(Barrier::new(THREADS));

    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let path = path.clone();
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                // One long-lived connection per writer (a `provio check --stdio`
                // per host).
                let mut store = PgBackend::open(&path).unwrap();
                start.wait();
                let mut rejected = 0u32;
                for i in 0..PER_THREAD {
                    let c = call(&format!("t{t}-c{i}"), &format!("t{t}"));
                    loop {
                        match LedgerWriter::new(&mut store).record_decision(&c, &allow(), None) {
                            Ok(_) => break,
                            // Lost the race for the tip: rebuild and retry.
                            Err(e) if provio_ledger::is_append_race(&e) => rejected += 1,
                            Err(e) => panic!("thread {t}: {e}"),
                        }
                    }
                }
                rejected
            })
        })
        .collect();
    let rejected: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    eprintln!("{rejected} lost races were retried");
    assert_linear(&path, THREADS * PER_THREAD);
}

#[test]
fn concurrent_short_lived_writers_produce_one_linear_chain() {
    if !pg_available() {
        return;
    }
    // A fresh connection per append through the path dispatcher, as with
    // one `provio check` process per tool call across many hosts.
    const THREADS: usize = 4;
    const PER_THREAD: usize = 8;
    let dir = TempDir::new();
    let path = ledger_path::<PgBackend>(&dir);
    drop(open_store(&path).unwrap());
    let start = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let path = path.clone();
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                for i in 0..PER_THREAD {
                    let mut store = open_store(&path).unwrap();
                    let c = call(&format!("p{t}-c{i}"), &format!("p{t}"));
                    retry_append(|| {
                        LedgerWriter::new(&mut *store).record_decision(&c, &deny(), None)
                    })
                    .unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_linear(&path, THREADS * PER_THREAD);
}

/// Copy every record from one store into another, unchanged.
fn import(from: &dyn LedgerStore, to: &mut dyn LedgerStore) {
    for rec in from.iter() {
        to.append(&rec.unwrap()).unwrap();
    }
}

#[test]
fn jsonl_to_postgres_to_jsonl_is_byte_identical() {
    if !pg_available() {
        return;
    }
    let dir = TempDir::new();
    let jsonl = populated::<common::FileBackend>(&dir);
    let pg = ledger_path::<PgBackend>(&dir);

    // JSONL -> Postgres, then one record first written by Postgres, with
    // text that JSONB or a non-UTF8 encoding would not keep byte-exact.
    let file_store = FileLedgerStore::open(&jsonl).unwrap();
    let mut pg_store = PgBackend::open(&pg).unwrap();
    import(&file_store, &mut pg_store);
    LedgerWriter::new(&mut pg_store)
        .record_decision(&call("c4-\u{e9}\u{6f22}", "s3 \u{0} \"q\""), &deny(), None)
        .unwrap();

    // Each row is byte-for-byte the JSONL line.
    let lines: Vec<String> = std::fs::read_to_string(&jsonl)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    let rows: Vec<String> = raw()
        .query(
            &format!("SELECT record FROM {} ORDER BY idx", ledger_table(&pg)),
            &[],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[..3], lines[..]);

    // Postgres -> JSONL (including the record first written by Postgres).
    let round = dir.path().join("round.jsonl");
    let mut back = FileLedgerStore::open(&round).unwrap();
    import(&pg_store, &mut back);
    let round_text = std::fs::read_to_string(&round).unwrap();
    let original = std::fs::read_to_string(&jsonl).unwrap();
    assert!(
        round_text.starts_with(&original),
        "JSONL prefix is byte-identical"
    );
    assert_eq!(round_text, rows.join("\n") + "\n");

    let a = verify_jsonl(&jsonl).unwrap();
    let b = verify_postgres(url_str(&pg)).unwrap();
    let c = verify(&round).unwrap();
    assert!(a.intact && b.intact && c.intact);
    assert_eq!((a.records, b.records, c.records), (3, 4, 4));
    let hashes =
        |s: &dyn LedgerStore| -> Vec<String> { s.iter().map(|r| r.unwrap().record_hash).collect() };
    assert_eq!(hashes(&pg_store), hashes(&back));
}

#[test]
fn refuses_foreign_and_future_schemas() {
    if !pg_available() {
        return;
    }
    let mut c = raw();

    // A schema with someone else's table: refused, and left untouched.
    let dir = TempDir::new();
    let foreign = schema_for(&dir);
    c.batch_execute(&format!(
        "CREATE SCHEMA {foreign}; CREATE TABLE {foreign}.users (id INT PRIMARY KEY);"
    ))
    .unwrap();
    let url = url_with(&format!("provio_schema={foreign}"));
    let err = PostgresLedgerStore::open(&url).unwrap_err();
    assert_err_contains(err, "not a PROVIO ledger");
    assert!(verify(&url).is_err());
    let tables: i64 = c
        .query_one(
            "SELECT count(*) FROM pg_tables WHERE schemaname = $1",
            &[&foreign],
        )
        .unwrap()
        .get(0);
    assert_eq!(tables, 1, "nothing was added to the foreign schema");

    // A `ledger` table without a marker.
    let dir2 = TempDir::new();
    let bare = schema_for(&dir2);
    c.batch_execute(&format!(
        "CREATE SCHEMA {bare}; CREATE TABLE {bare}.ledger (idx BIGINT PRIMARY KEY, record TEXT);"
    ))
    .unwrap();
    let err = PostgresLedgerStore::open(url_with(&format!("provio_schema={bare}"))).unwrap_err();
    assert_err_contains(err, "not a PROVIO ledger");

    // A marker naming another application.
    let dir3 = TempDir::new();
    let other = schema_for(&dir3);
    c.batch_execute(&format!(
        "CREATE SCHEMA {other};
         CREATE TABLE {other}.ledger_meta (singleton BOOLEAN PRIMARY KEY, application TEXT,
             store_version INT, ledger_table TEXT);
         INSERT INTO {other}.ledger_meta VALUES (true, 'not-provio', 1, 'ledger');
         CREATE TABLE {other}.ledger (idx BIGINT PRIMARY KEY, record TEXT);"
    ))
    .unwrap();
    let err = PostgresLedgerStore::open(url_with(&format!("provio_schema={other}"))).unwrap_err();
    assert_err_contains(err, "not a PROVIO ledger");

    // A ledger written by a future store version.
    let dir4 = TempDir::new();
    let future = populated::<PgBackend>(&dir4);
    let meta = meta_table(&future);
    c.batch_execute(&format!(
        "ALTER TABLE {meta} DISABLE TRIGGER USER;
         UPDATE {meta} SET store_version = {};",
        STORE_VERSION + 1
    ))
    .unwrap();
    let err = PgBackend::open(&future).unwrap_err();
    assert_err_contains(err, "unsupported");
    assert!(verify(&future).is_err());
}

#[test]
fn read_paths_do_not_create_ledgers() {
    if !pg_available() {
        return;
    }
    let dir = TempDir::new();
    let path = ledger_path::<PgBackend>(&dir);
    let err = verify(&path).unwrap_err();
    assert_err_contains(err, "no PROVIO ledger");
    assert!(provio_ledger::sessions(&path).is_err());
    assert!(provio_ledger::find_by_call_id(&path, "c1").is_err());
    assert!(!schema_exists(&schema_of(&path)));
}

#[test]
fn passwords_never_appear_in_errors_or_debug() {
    if !pg_available() {
        return;
    }
    let base: postgres::Config = {
        // Strip our own parameters before handing the URL to the driver.
        let u = base_url().unwrap();
        let no_query = u.split('?').next().unwrap().to_string();
        no_query.parse().unwrap()
    };
    let host = match &base.get_hosts()[0] {
        postgres::config::Host::Tcp(h) => h.clone(),
        #[allow(unreachable_patterns)]
        _ => "localhost".to_string(),
    };
    let port = base.get_ports().first().copied().unwrap_or(5432);
    let db = base.get_dbname().unwrap_or("postgres");
    let secret = "s3cr3t-Hunter2";
    let url = format!("postgres://provio_no_such_role:{secret}@{host}:{port}/{db}?sslmode=disable");
    let err = PostgresLedgerStore::open(&url).unwrap_err().to_string();
    assert!(!err.contains(secret), "password leaked: {err}");
    assert!(err.contains("provio_no_such_role:***@"), "got {err}");
    let err = verify(&url).unwrap_err().to_string();
    assert!(!err.contains(secret), "password leaked: {err}");
    assert!(!display_ledger(&url).contains(secret));

    // An open store's Debug output names the ledger without the password.
    let dir = TempDir::new();
    let path = ledger_path::<PgBackend>(&dir);
    let store = PgBackend::open(&path).unwrap();
    let dbg = format!("{store:?}");
    if let Some(pw) = base.get_password() {
        let pw = String::from_utf8_lossy(pw);
        assert!(!dbg.contains(&*pw), "password leaked: {dbg}");
        assert!(!store.url().contains(&*pw));
    }
    assert!(dbg.contains(&schema_of(&path)));
}

#[test]
fn appends_survive_a_dropped_connection() {
    if !pg_available() {
        return;
    }
    let dir = TempDir::new();
    let schema = schema_for(&dir);
    let app = format!("provio_reconnect_{schema}");
    let url = url_with(&format!("provio_schema={schema}&application_name={app}"));
    let mut store = PostgresLedgerStore::open(&url).unwrap();
    LedgerWriter::new(&mut store)
        .record_decision(&call("before", "s"), &allow(), None)
        .unwrap();
    // The server drops the store's connection (restart, failover, idle
    // timeout).
    let killed: i64 = raw()
        .query_one(
            "SELECT count(*) FROM (SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE application_name = $1) t",
            &[&app],
        )
        .unwrap()
        .get(0);
    assert_eq!(killed, 1);
    std::thread::sleep(Duration::from_millis(100));
    LedgerWriter::new(&mut store)
        .record_decision(&call("after", "s"), &allow(), None)
        .unwrap();
    assert_eq!(store.len(), 2);
    assert!(verify(&url).unwrap().intact);
}

#[test]
fn sslmode_disable_and_require() {
    if !pg_available() {
        return;
    }
    fn ssl_in_use(url: &str) -> bool {
        connect(url)
            .unwrap()
            .query_one(
                "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()",
                &[],
            )
            .unwrap()
            .get(0)
    }
    let dir = TempDir::new();
    let schema = schema_for(&dir);
    let plain = url_with(&format!("provio_schema={schema}&sslmode=disable"));
    assert!(!ssl_in_use(&plain));
    let mut store = PostgresLedgerStore::open(&plain).unwrap();
    LedgerWriter::new(&mut store)
        .record_decision(&call("c1", "s"), &allow(), None)
        .unwrap();

    let err = PostgresLedgerStore::open(url_with("sslmode=bogus")).unwrap_err();
    assert_err_contains(err, "invalid sslmode");

    if std::env::var("PROVIO_POSTGRES_TLS").as_deref() != Ok("1") {
        eprintln!("skipping TLS half: set PROVIO_POSTGRES_TLS=1 when the server accepts TLS");
        return;
    }
    let tls = url_with(&format!("provio_schema={schema}&sslmode=require"));
    assert!(ssl_in_use(&tls));
    let store = PostgresLedgerStore::open(&tls).unwrap();
    assert_eq!(store.len(), 1);
    assert!(verify(&tls).unwrap().intact);

    if let Ok(root) = std::env::var("PROVIO_POSTGRES_SSLROOTCERT") {
        let ca = url_with(&format!(
            "provio_schema={schema}&sslmode=verify-ca&sslrootcert={root}"
        ));
        assert!(ssl_in_use(&ca));
        assert_eq!(PostgresLedgerStore::open(&ca).unwrap().len(), 1);
    }
    // A certificate that chains to nothing trusted is refused under
    // verify-full with an unrelated root.
    let bogus_root = dir.path().join("empty.pem");
    std::fs::write(&bogus_root, "").unwrap();
    let err = PostgresLedgerStore::open(url_with(&format!(
        "provio_schema={schema}&sslmode=verify-full&sslrootcert={}",
        bogus_root.display()
    )))
    .unwrap_err();
    assert_err_contains(err, "sslrootcert");
}
