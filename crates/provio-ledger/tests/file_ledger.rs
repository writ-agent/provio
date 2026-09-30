//! Acceptance tests for FileLedgerStore (Contract 3 / ADR-005): the shared
//! store-generic suite plus JSONL-specific crash-tolerance tests.

#[macro_use]
mod common;

use std::fs::OpenOptions;
use std::io::Write;

use common::{allow, call, ledger_path, populated, FileBackend, TempDir};
use provio_core::error::ProvioError;
use provio_core::ledger::{LedgerStore, LedgerWriter};
use provio_ledger::{
    detect_store_kind, is_append_race, retry_append, verify, FileLedgerStore, StoreKind,
};

ledger_suite!(FileBackend);

#[test]
fn crash_tolerant_tail() {
    let dir = TempDir::new();
    let path = populated::<FileBackend>(&dir);

    // Simulate a crash mid-write: a torn final line.
    {
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"schema_version\":1,\"kind\":\"deci")
            .unwrap();
        f.flush().unwrap();
    }

    // open() stops at the last valid record instead of failing.
    let mut store = FileLedgerStore::open(&path).unwrap();
    assert_eq!(store.len(), 3);
    assert_eq!(store.tip().unwrap().unwrap().index, 2);

    // The torn tail was truncated at open, so the ledger keeps accepting
    // records and the chain still verifies end-to-end.
    let mut w = LedgerWriter::new(&mut store);
    w.record_decision(&call("c9", "s9"), &allow(), None)
        .unwrap();
    assert_eq!(store.len(), 4);
    let report = verify(&path).unwrap();
    assert!(report.intact);
    assert_eq!(report.records, 4);

    // And a subsequent reopen sees all four valid records.
    let store = FileLedgerStore::open(&path).unwrap();
    assert_eq!(store.len(), 4);
}

#[test]
fn store_kind_detection() {
    let dir = TempDir::new();
    let jsonl = populated::<FileBackend>(&dir);
    assert_eq!(detect_store_kind(&jsonl).unwrap(), StoreKind::Jsonl);
    // Missing files are decided by extension.
    for (name, kind) in [
        ("x.jsonl", StoreKind::Jsonl),
        ("x.log", StoreKind::Jsonl),
        ("x.db", StoreKind::Sqlite),
        ("x.SQLite", StoreKind::Sqlite),
        ("x.sqlite3", StoreKind::Sqlite),
    ] {
        assert_eq!(detect_store_kind(dir.path().join(name)).unwrap(), kind);
    }
    // Content wins over the name: a SQLite header is SQLite whatever the
    // file is called.
    let disguised = dir.path().join("disguised.jsonl");
    std::fs::write(&disguised, b"SQLite format 3\0rest-of-header").unwrap();
    assert_eq!(detect_store_kind(&disguised).unwrap(), StoreKind::Sqlite);
}

#[test]
fn jsonl_content_under_a_sqlite_name_is_refused() {
    let dir = TempDir::new();
    let jsonl = populated::<FileBackend>(&dir);
    let misnamed = dir.path().join("ledger.db");
    std::fs::copy(&jsonl, &misnamed).unwrap();
    let err = detect_store_kind(&misnamed).unwrap_err();
    assert!(err.to_string().contains("refusing to guess"), "got {err}");
    assert!(verify(&misnamed).is_err());
    assert!(provio_ledger::open_store(&misnamed).is_err());
}

#[cfg(not(feature = "sqlite"))]
#[test]
fn sqlite_ledgers_fail_closed_without_the_feature() {
    let dir = TempDir::new();
    let db = dir.path().join("ledger.db");
    let err = provio_ledger::open_store(&db).err().expect("must not open");
    assert!(err.to_string().contains("`sqlite` feature"), "got {err}");
    assert!(!db.exists(), "nothing may be created");

    std::fs::write(&db, b"SQLite format 3\0rest-of-header").unwrap();
    for err in [
        verify(&db).unwrap_err(),
        provio_ledger::sessions(&db).unwrap_err(),
        provio_ledger::find_by_call_id(&db, "c1").unwrap_err(),
    ] {
        assert!(err.to_string().contains("`sqlite` feature"), "got {err}");
    }
}

#[test]
fn stale_writer_cannot_fork_the_chain() {
    let dir = TempDir::new();
    let path = populated::<FileBackend>(&dir);
    let mut a = FileLedgerStore::open(&path).unwrap();
    let mut b = FileLedgerStore::open(&path).unwrap();

    // b prepares a record on the tip it has seen (index 3)...
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

    // b sees a's record on disk, and its stale append is rejected as a race.
    assert_eq!(b.len(), 4);
    assert_eq!(b.tip().unwrap().unwrap().call_id, "a-call");
    let err = b.append(&stale).unwrap_err();
    assert!(is_append_race(&err), "got {err:?}");
    assert_eq!(b.len(), 4);

    // Retrying through LedgerWriter rebuilds on the new tip and succeeds.
    LedgerWriter::new(&mut b)
        .record_decision(&call("b-call", "s1"), &allow(), None)
        .unwrap();
    assert_eq!(a.len(), 5);
    assert_eq!(a.tip().unwrap().unwrap().call_id, "b-call");
    assert_eq!(a.get(4).unwrap().unwrap().call_id, "b-call");
    let report = verify(&path).unwrap();
    assert!(report.intact);
    assert_eq!(report.records, 5);
}

#[test]
fn hash_mismatch_is_not_a_race() {
    let dir = TempDir::new();
    let path = populated::<FileBackend>(&dir);
    let mut store = FileLedgerStore::open(&path).unwrap();
    let mut bad = store.tip().unwrap().unwrap();
    bad.index = 3;
    bad.prev_hash = bad.record_hash.clone();
    bad.record_hash = "0".repeat(64);
    let err = store.append(&bad).unwrap_err();
    assert!(!is_append_race(&err), "got {err:?}");
    // retry_append gives up immediately on a non-race error.
    let mut calls = 0;
    let res: Result<(), ProvioError> = retry_append(|| {
        calls += 1;
        store.append(&bad)
    });
    assert!(res.is_err());
    assert_eq!(calls, 1);
}

#[test]
fn concurrent_writers_produce_one_linear_chain() {
    const THREADS: usize = 8;
    const PER_THREAD: usize = 25;
    let dir = TempDir::new();
    let path = ledger_path::<FileBackend>(&dir);
    drop(FileLedgerStore::open(&path).unwrap());

    // Every thread has its own store (its own file handles and lock-file
    // handle), exactly like separate processes.
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut store = FileLedgerStore::open(&path).unwrap();
                for i in 0..PER_THREAD {
                    let c = call(&format!("t{t}-c{i}"), &format!("t{t}"));
                    retry_append(|| {
                        LedgerWriter::new(&mut store).record_decision(&c, &allow(), None)
                    })
                    .unwrap_or_else(|e| panic!("thread {t}: {e}"));
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }

    let report = verify(&path).unwrap();
    assert!(report.intact, "{report:?}");
    assert_eq!(report.records, (THREADS * PER_THREAD) as u64);
    let store = FileLedgerStore::open(&path).unwrap();
    let mut ids: Vec<String> = store.iter().map(|r| r.unwrap().call_id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), THREADS * PER_THREAD, "every call recorded once");
}

#[test]
fn torn_tail_is_repaired_by_the_next_append_and_hidden_from_readers() {
    let dir = TempDir::new();
    let path = populated::<FileBackend>(&dir);
    let mut store = FileLedgerStore::open(&path).unwrap();

    // Another writer "crashes" mid-line after this store was opened.
    {
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"schema_version\":1,\"ind").unwrap();
    }
    // Readers see only committed records.
    assert_eq!(store.len(), 3);
    assert_eq!(store.iter().count(), 3);
    assert!(store.get(3).unwrap().is_none());

    // The next append (under the lock) drops the debris and extends the chain.
    LedgerWriter::new(&mut store)
        .record_decision(&call("c4", "s1"), &allow(), None)
        .unwrap();
    let report = verify(&path).unwrap();
    assert!(report.intact, "{report:?}");
    assert_eq!(report.records, 4);
}

#[test]
fn final_record_without_newline_is_kept() {
    let dir = TempDir::new();
    let path = populated::<FileBackend>(&dir);
    // Strip the trailing newline from the last (complete) record.
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.trim_end()).unwrap();

    let mut store = FileLedgerStore::open(&path).unwrap();
    assert_eq!(store.len(), 3);
    LedgerWriter::new(&mut store)
        .record_decision(&call("c4", "s1"), &allow(), None)
        .unwrap();
    let report = verify(&path).unwrap();
    assert!(report.intact, "{report:?}");
    assert_eq!(report.records, 4);
}

#[test]
fn lock_file_sits_next_to_the_ledger() {
    let dir = TempDir::new();
    let path = populated::<FileBackend>(&dir);
    let store = FileLedgerStore::open(&path).unwrap();
    assert_eq!(
        store.lock_path().file_name().unwrap().to_str().unwrap(),
        "ledger.jsonl.lock"
    );
    assert!(store.lock_path().exists(), "created by the first append");
}

// ---------------------------------------------------------------------------
// Multi-process stress: writer *processes* (this test binary re-invoked)
// append large records while reader threads open / tip / iter / get /
// verify the same file without the lock. Readers must never see
// corruption or a broken chain for a write that is still in progress.

const STRESS_LEDGER_ENV: &str = "PROVIO_STRESS_LEDGER";
const STRESS_WRITER_ENV: &str = "PROVIO_STRESS_WRITER";
const STRESS_RECORDS_ENV: &str = "PROVIO_STRESS_RECORDS";

/// Child half of `multi_process_writers_with_lock_free_readers`; a no-op
/// unless the parent set the stress environment.
#[test]
fn stress_child_writer() {
    let Ok(path) = std::env::var(STRESS_LEDGER_ENV) else {
        return;
    };
    let writer: usize = std::env::var(STRESS_WRITER_ENV).unwrap().parse().unwrap();
    let n: usize = std::env::var(STRESS_RECORDS_ENV).unwrap().parse().unwrap();
    let mut store = FileLedgerStore::open(&path).unwrap();
    // ~24 KiB per record: every append spans several pages, so a reader
    // can observe it half-copied.
    let filler = "x".repeat(24 * 1024);
    for i in 0..n {
        let mut c = call(&format!("w{writer}-c{i}"), &format!("w{writer}"));
        c.args = serde_json::json!({"command": "ls", "content": filler});
        retry_append(|| LedgerWriter::new(&mut store).record_decision(&c, &allow(), None))
            .unwrap_or_else(|e| panic!("writer {writer}: {e}"));
    }
}

fn spawn_writer(path: &std::path::Path, writer: usize, n: usize) -> std::process::Child {
    let exe = std::env::current_exe().unwrap();
    let mut attempt = 0;
    loop {
        let r = std::process::Command::new(&exe)
            .args([
                "stress_child_writer",
                "--exact",
                "--test-threads=1",
                "--quiet",
            ])
            .env(STRESS_LEDGER_ENV, path)
            .env(STRESS_WRITER_ENV, writer.to_string())
            .env(STRESS_RECORDS_ENV, n.to_string())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();
        match r {
            Ok(c) => return c,
            // Windows Application Control transiently blocks fresh binaries.
            Err(e) if e.raw_os_error() == Some(4551) && attempt < 10 => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            Err(e) => panic!("spawn writer: {e}"),
        }
    }
}

#[test]
fn multi_process_writers_with_lock_free_readers() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    const WRITERS: usize = 8;
    const PER_WRITER: usize = 30;
    const READERS: usize = 4;
    let dir = TempDir::new();
    let path = ledger_path::<FileBackend>(&dir);
    drop(FileLedgerStore::open(&path).unwrap());

    let done = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicU64::new(0));
    let readers: Vec<_> = (0..READERS)
        .map(|r| {
            let (path, done, reads) = (path.clone(), done.clone(), reads.clone());
            std::thread::spawn(move || {
                // One long-lived handle (incremental refresh) plus fresh
                // opens, iteration and full verification, in a tight loop.
                let held = FileLedgerStore::open(&path).unwrap();
                let mut last_len = 0u64;
                while !done.load(Ordering::SeqCst) {
                    held.tip()
                        .unwrap_or_else(|e| panic!("reader {r}: tip: {e}"));
                    let len = held.len();
                    assert!(len >= last_len, "reader {r}: len went backwards");
                    last_len = len;

                    let fresh = FileLedgerStore::open(&path)
                        .unwrap_or_else(|e| panic!("reader {r}: open: {e}"));
                    let mut expected = 0u64;
                    for item in fresh.iter() {
                        let rec = item.unwrap_or_else(|e| panic!("reader {r}: iter: {e}"));
                        assert_eq!(rec.index, expected, "reader {r}: iter out of order");
                        expected += 1;
                    }
                    if expected > 0 {
                        assert!(fresh.get(expected - 1).unwrap().is_some());
                    }
                    let report =
                        verify(&path).unwrap_or_else(|e| panic!("reader {r}: verify: {e}"));
                    assert!(
                        report.intact,
                        "reader {r}: verify during writes: {report:?}"
                    );
                    reads.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();

    let mut children: Vec<_> = (0..WRITERS)
        .map(|w| spawn_writer(&path, w, PER_WRITER))
        .collect();
    let mut failed = Vec::new();
    for (w, c) in children.drain(..).enumerate() {
        let out = c.wait_with_output().unwrap();
        if !out.status.success() {
            failed.push(format!(
                "writer {w}: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    done.store(true, Ordering::SeqCst);
    for r in readers {
        r.join().expect("reader thread panicked");
    }
    assert!(failed.is_empty(), "writer processes failed: {failed:?}");
    assert!(reads.load(Ordering::Relaxed) > 0, "readers never ran");

    let report = verify(&path).unwrap();
    assert!(report.intact, "{report:?}");
    assert_eq!(report.records, (WRITERS * PER_WRITER) as u64);
    let store = FileLedgerStore::open(&path).unwrap();
    let mut ids: Vec<String> = store.iter().map(|r| r.unwrap().call_id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), WRITERS * PER_WRITER, "every record once");
}

#[test]
fn terminated_garbage_mid_file_is_still_corruption() {
    // The in-progress rule must not weaken tamper detection: a complete
    // (newline-terminated) line that does not parse, followed by records,
    // is a hard error on open and a break at its index in verify.
    let dir = TempDir::new();
    let path = populated::<FileBackend>(&dir);
    let text = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let half = lines[1].len() / 2;
    lines[1].truncate(half);
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
    let err = FileLedgerStore::open(&path).expect_err("open must fail");
    assert!(err.to_string().contains("mid-file corruption"), "{err}");
    let report = verify(&path).unwrap();
    assert_eq!((report.intact, report.broken_at), (false, Some(1)));
}

#[test]
fn unterminated_partial_tail_is_invisible_to_every_reader() {
    // Exactly what a concurrent reader can observe mid-append: a prefix of
    // the next record with no newline. tip/iter/get/verify see the
    // committed records only, and none reports corruption.
    let dir = TempDir::new();
    let path = populated::<FileBackend>(&dir);
    let held = FileLedgerStore::open(&path).unwrap();
    let mut next = held.tip().unwrap().unwrap();
    next.index = 3;
    next.prev_hash = next.record_hash.clone();
    next.record_hash = next.compute_hash().unwrap();
    let line = serde_json::to_string(&next).unwrap();
    let committed = std::fs::read(&path).unwrap();
    for cut in [1, line.len() / 3, line.len() - 1] {
        let mut bytes = committed.clone();
        bytes.extend_from_slice(&line.as_bytes()[..cut]);
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(held.tip().unwrap().unwrap().index, 2, "cut {cut}");
        assert_eq!(
            held.iter()
                .filter(|r| r.as_ref().unwrap().index < 3)
                .count(),
            3
        );
        assert!(held.get(3).unwrap().is_none());
        let report = verify(&path).unwrap();
        assert!(report.intact, "cut {cut}: {report:?}");
        assert_eq!(report.records, 3);
        std::fs::write(&path, &committed).unwrap();
    }
    // The whole line minus its newline is a complete record.
    let mut bytes = committed.clone();
    bytes.extend_from_slice(line.as_bytes());
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(held.tip().unwrap().unwrap().index, 3);
    assert_eq!(verify(&path).unwrap().records, 4);
}
