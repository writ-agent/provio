//! Shared fixtures and the store-generic verify/tamper suite. Every store
//! implements [`Backend`] and instantiates [`ledger_suite!`], so the JSONL
//! and SQLite stores run the exact same assertions (Contract 3: "all pass
//! verify_chain").

#![allow(dead_code)] // each test crate uses a different subset

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use provio_core::approver::{ApproverIdentity, ApproverKind};
use provio_core::error::ProvioError;
use provio_core::ledger::{LedgerStore, LedgerWriter, RecordKind, GENESIS_HASH};
use provio_core::{CallerIdentity, InterceptMode, Timestamp, ToolCall, Verdict};
use provio_ledger::{
    find_by_call_id, find_by_call_id_in, sessions, sessions_in, verify, FileLedgerStore,
};

/// Zero-dependency tempdir (this environment builds offline; no tempfile).
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("provio-ledger-test-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn call(call_id: &str, session_id: &str) -> ToolCall {
    ToolCall {
        call_id: call_id.into(),
        session_id: session_id.into(),
        caller: CallerIdentity {
            agent: "test-agent".into(),
            agent_version: None,
            user: None,
            non_human_id: None,
        },
        mode: InterceptMode::Mcp,
        tool: "bash".into(),
        args: serde_json::json!({"command": "ls -la"}),
        server: None,
        trust: None,
        captured_at: Timestamp::now(),
    }
}

pub fn allow() -> Verdict {
    Verdict::Allow {
        rule_id: Some("r-allow".into()),
    }
}

pub fn deny() -> Verdict {
    Verdict::Deny {
        rule_id: "r-deny".into(),
        reason: "destructive command".into(),
        location: Some("provio.yaml:14".into()),
    }
}

/// One ledger store under test, plus the raw (out-of-band) edits an
/// attacker with write access to its file could make.
pub trait Backend {
    type Store: LedgerStore;
    /// File name inside `.provio/` (the extension selects the store).
    const FILE_NAME: &'static str;
    /// Substring of the `open` error for a corrupt record mid-ledger.
    const CORRUPTION_MSG: &'static str;

    fn open(path: &Path) -> Result<Self::Store, ProvioError>;
    /// Where a test's ledger lives. Default: `<dir>/.provio/FILE_NAME` (a
    /// nested path, which also exercises parent-dir creation in `open`).
    /// Non-file stores return a location string derived from `dir`, which
    /// is unique per test.
    fn location(dir: &TempDir) -> PathBuf {
        dir.path().join(".provio").join(Self::FILE_NAME)
    }
    /// Rewrite record `idx`'s `session_id`, keeping it well-formed JSON.
    fn tamper_session(path: &Path, idx: u64, session_id: &str);
    /// Make record `idx` impossible to parse as a `LedgerRecord`.
    fn make_unparseable(path: &Path, idx: u64);
    /// Remove record `idx` entirely.
    fn delete_record(path: &Path, idx: u64);
}

pub fn ledger_path<B: Backend>(dir: &TempDir) -> PathBuf {
    B::location(dir)
}

/// Default guard for [`ledger_suite!`]: always run.
pub fn always() -> bool {
    true
}

/// Three records: decision(allow) + execution in s1, decision(deny) in s2.
pub fn populated<B: Backend>(dir: &TempDir) -> PathBuf {
    let path = ledger_path::<B>(dir);
    let mut store = B::open(&path).unwrap();
    let mut w = LedgerWriter::new(&mut store);
    let d = w
        .record_decision(&call("c1", "s1"), &allow(), None)
        .unwrap();
    w.record_execution(&d, "local-os", 0, b"ok").unwrap();
    w.record_decision(&call("c2", "s2"), &deny(), None).unwrap();
    path
}

pub fn roundtrip_append_iter_and_reopen<B: Backend>() {
    let dir = TempDir::new();
    let path = populated::<B>(&dir);

    let mut store = B::open(&path).unwrap();
    assert_eq!(store.len(), 3);
    let tip = store.tip().unwrap().unwrap();
    assert_eq!(tip.index, 2);
    assert_eq!(tip.kind, RecordKind::Decision);

    let exec = store.get(1).unwrap().unwrap();
    assert_eq!(exec.kind, RecordKind::Execution);
    assert_eq!(exec.decision_index, Some(0));
    assert!(store.get(3).unwrap().is_none());
    assert!(store.get(u64::MAX).unwrap().is_none());

    let all: Vec<_> = store.iter().collect::<Result<_, _>>().unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].index, 0);
    assert_eq!(all[2].index, 2);
    // Chain links hold across a reopen.
    assert_eq!(all[1].prev_hash, all[0].record_hash);
    assert_eq!(all[2].prev_hash, all[1].record_hash);

    // Append continues seamlessly after reopen.
    let mut w = LedgerWriter::new(&mut store);
    w.record_decision(&call("c3", "s1"), &allow(), None)
        .unwrap();
    assert_eq!(store.len(), 4);
    assert!(verify(&path).unwrap().intact);
}

pub fn genesis_record_has_zero_prev_hash<B: Backend>() {
    let dir = TempDir::new();
    let path = ledger_path::<B>(&dir);
    let mut store = B::open(&path).unwrap();
    let mut w = LedgerWriter::new(&mut store);
    w.record_decision(&call("c1", "s1"), &allow(), None)
        .unwrap();
    let first = store.get(0).unwrap().unwrap();
    assert_eq!(first.prev_hash, GENESIS_HASH);
    assert_eq!(first.prev_hash.len(), 64);
    assert!(first.prev_hash.chars().all(|c| c == '0'));
}

pub fn rejects_out_of_order_append<B: Backend>() {
    let dir = TempDir::new();
    let path = populated::<B>(&dir);
    let mut store = B::open(&path).unwrap();
    let mut bad = store.tip().unwrap().unwrap();
    bad.index = 7; // len() is 3
    bad.record_hash = bad.compute_hash().unwrap();
    let err = store.append(&bad).unwrap_err();
    assert!(matches!(err, ProvioError::Ledger(_)), "got {err:?}");
    assert!(err.to_string().contains("index 7"), "got {err}");
    assert_eq!(store.len(), 3); // unchanged
}

pub fn rejects_wrong_prev_hash<B: Backend>() {
    let dir = TempDir::new();
    let path = populated::<B>(&dir);
    let mut store = B::open(&path).unwrap();
    let mut bad = store.tip().unwrap().unwrap();
    bad.index = 3;
    bad.prev_hash = "f".repeat(64);
    bad.record_hash = bad.compute_hash().unwrap();
    let err = store.append(&bad).unwrap_err();
    assert!(matches!(err, ProvioError::Ledger(_)), "got {err:?}");
    assert!(err.to_string().contains("prev_hash"), "got {err}");
    assert_eq!(store.len(), 3);
}

pub fn rejects_wrong_record_hash<B: Backend>() {
    let dir = TempDir::new();
    let path = populated::<B>(&dir);
    let mut store = B::open(&path).unwrap();
    let tip = store.tip().unwrap().unwrap();
    let mut bad = tip.clone();
    bad.index = 3;
    bad.prev_hash = tip.record_hash.clone();
    bad.record_hash = "0".repeat(64);
    let err = store.append(&bad).unwrap_err();
    assert!(matches!(err, ProvioError::Ledger(_)), "got {err:?}");
    assert!(err.to_string().contains("record_hash"), "got {err}");
    assert_eq!(store.len(), 3);
    assert!(verify(&path).unwrap().intact);
}

pub fn verify_reports_exact_index_on_valid_json_tamper<B: Backend>() {
    let dir = TempDir::new();
    let path = populated::<B>(&dir);
    assert!(verify(&path).unwrap().intact);

    // The stored record_hash no longer matches the edited payload.
    B::tamper_session(&path, 1, "evil-session");

    let report = verify(&path).unwrap();
    assert!(!report.intact);
    assert_eq!(report.broken_at, Some(1));
    assert_eq!(report.records, 1);
}

pub fn verify_reports_tip_tamper<B: Backend>() {
    let dir = TempDir::new();
    let path = populated::<B>(&dir);
    B::tamper_session(&path, 2, "evil-session");
    let report = verify(&path).unwrap();
    assert!(!report.intact);
    assert_eq!(report.broken_at, Some(2));
    assert_eq!(report.records, 2);
}

pub fn verify_reports_exact_index_on_unparseable_tamper<B: Backend>() {
    let dir = TempDir::new();
    let path = populated::<B>(&dir);
    B::make_unparseable(&path, 1);

    let report = verify(&path).unwrap();
    assert!(!report.intact);
    assert_eq!(report.broken_at, Some(1));
    assert_eq!(report.records, 1);
}

pub fn verify_detects_deleted_middle_record_as_chain_break<B: Backend>() {
    let dir = TempDir::new();
    let path = populated::<B>(&dir);
    assert!(verify(&path).unwrap().intact);

    B::delete_record(&path, 1);

    let report = verify(&path).unwrap();
    assert!(!report.intact);
    assert_eq!(report.records, 1);
    assert_eq!(report.broken_at, Some(2));
}

pub fn mid_ledger_corruption_is_a_hard_error_on_open<B: Backend>() {
    let dir = TempDir::new();
    let path = populated::<B>(&dir);
    B::make_unparseable(&path, 1); // record 2 follows

    let err = B::open(&path).err().expect("open must fail");
    assert!(matches!(err, ProvioError::Ledger(_)), "got {err:?}");
    assert!(err.to_string().contains(B::CORRUPTION_MSG), "got {err}");
}

pub fn deleted_record_is_a_hard_error_on_open<B: Backend>() {
    let dir = TempDir::new();
    let path = populated::<B>(&dir);
    B::delete_record(&path, 1);
    let err = B::open(&path).err().expect("open must fail");
    assert!(matches!(err, ProvioError::Ledger(_)), "got {err:?}");
    assert!(err.to_string().contains("out of sequence"), "got {err}");
}

pub fn sessions_and_find_by_call_id<B: Backend>() {
    let dir = TempDir::new();
    let path = ledger_path::<B>(&dir);
    let human = ApproverIdentity {
        kind: ApproverKind::Tui,
        id: "bhaskar".into(),
    };
    {
        let mut store = B::open(&path).unwrap();
        let mut w = LedgerWriter::new(&mut store);
        // s1: allowed + executed, plus a human-approved ask resolution.
        let d1 = w
            .record_decision(&call("c1", "s1"), &allow(), None)
            .unwrap();
        w.record_execution(&d1, "local-os", 0, b"ok").unwrap();
        w.record_decision(&call("c2", "s1"), &allow(), Some(human))
            .unwrap();
        // s2: one denial.
        w.record_decision(&call("c3", "s2"), &deny(), None).unwrap();
    }

    let summaries = sessions(&path).unwrap();
    assert_eq!(summaries.len(), 2);
    let s1 = &summaries[0];
    assert_eq!(s1.session_id, "s1");
    assert_eq!(s1.records, 3);
    assert_eq!(s1.denied, 0);
    assert!(s1.approved_by_human);
    let s2 = &summaries[1];
    assert_eq!(s2.session_id, "s2");
    assert_eq!(s2.records, 1);
    assert_eq!(s2.denied, 1);
    assert!(!s2.approved_by_human);

    // find_by_call_id returns the decision and its linked execution.
    let recs = find_by_call_id(&path, "c1").unwrap();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].kind, RecordKind::Decision);
    assert_eq!(recs[1].kind, RecordKind::Execution);
    assert_eq!(recs[1].decision_index, Some(recs[0].index));
    assert!(find_by_call_id(&path, "nope").unwrap().is_empty());

    // The stream variants agree when fed the store's own iterator.
    let store = B::open(&path).unwrap();
    assert_eq!(sessions_in(store.iter()).unwrap(), summaries);
    let via_store = find_by_call_id_in(store.iter(), "c1").unwrap();
    assert_eq!(via_store.len(), 2);
    assert_eq!(via_store[1].record_hash, recs[1].record_hash);
}

pub fn empty_ledger_verifies_intact<B: Backend>() {
    let dir = TempDir::new();
    let path = ledger_path::<B>(&dir);
    let store = B::open(&path).unwrap();
    assert_eq!(store.len(), 0);
    assert!(store.is_empty());
    assert!(store.tip().unwrap().is_none());
    assert!(store.iter().next().is_none());
    let report = verify(&path).unwrap();
    assert!(report.intact);
    assert_eq!(report.records, 0);
    assert_eq!(report.broken_at, None);
}

pub fn open_store_picks_this_backend<B: Backend>() {
    let dir = TempDir::new();
    let path = ledger_path::<B>(&dir);
    {
        let mut store = provio_ledger::open_store(&path).unwrap();
        let mut w = LedgerWriter::new(&mut *store);
        w.record_decision(&call("c1", "s1"), &allow(), None)
            .unwrap();
    }
    // Written through the dispatcher, readable through the concrete store.
    let store = B::open(&path).unwrap();
    assert_eq!(store.len(), 1);
    assert!(verify(&path).unwrap().intact);
}

/// The JSONL store, tampered with by editing lines of the file.
pub struct FileBackend;

fn read_lines(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}

fn write_lines(path: &Path, lines: &[String]) {
    std::fs::write(path, lines.join("\n") + "\n").unwrap();
}

impl Backend for FileBackend {
    type Store = FileLedgerStore;
    const FILE_NAME: &'static str = "ledger.jsonl";
    const CORRUPTION_MSG: &'static str = "mid-file corruption";

    fn open(path: &Path) -> Result<Self::Store, ProvioError> {
        FileLedgerStore::open(path)
    }

    fn tamper_session(path: &Path, idx: u64, session_id: &str) {
        let mut lines = read_lines(path);
        let i = idx as usize;
        let mut v: serde_json::Value = serde_json::from_str(&lines[i]).unwrap();
        v["session_id"] = serde_json::json!(session_id);
        lines[i] = serde_json::to_string(&v).unwrap();
        write_lines(path, &lines);
    }

    fn make_unparseable(path: &Path, idx: u64) {
        // Flip the first byte of the line ('{' -> 'X').
        let mut lines = read_lines(path);
        lines[idx as usize].replace_range(0..1, "X");
        write_lines(path, &lines);
    }

    fn delete_record(path: &Path, idx: u64) {
        let mut lines = read_lines(path);
        lines.remove(idx as usize);
        write_lines(path, &lines);
    }
}

/// Instantiate the whole generic suite for one backend. With
/// `guard = path::to::fn`, each test first calls the guard and returns
/// early (skips) when it is false — for stores that need an external
/// service.
macro_rules! ledger_suite {
    ($backend:ty) => {
        ledger_suite!($backend, guard = common::always);
    };
    ($backend:ty, guard = $guard:path) => {
        #[test]
        fn roundtrip_append_iter_and_reopen() {
            if !$guard() {
                return;
            }
            common::roundtrip_append_iter_and_reopen::<$backend>();
        }
        #[test]
        fn genesis_record_has_zero_prev_hash() {
            if !$guard() {
                return;
            }
            common::genesis_record_has_zero_prev_hash::<$backend>();
        }
        #[test]
        fn rejects_out_of_order_append() {
            if !$guard() {
                return;
            }
            common::rejects_out_of_order_append::<$backend>();
        }
        #[test]
        fn rejects_wrong_prev_hash() {
            if !$guard() {
                return;
            }
            common::rejects_wrong_prev_hash::<$backend>();
        }
        #[test]
        fn rejects_wrong_record_hash() {
            if !$guard() {
                return;
            }
            common::rejects_wrong_record_hash::<$backend>();
        }
        #[test]
        fn verify_reports_exact_index_on_valid_json_tamper() {
            if !$guard() {
                return;
            }
            common::verify_reports_exact_index_on_valid_json_tamper::<$backend>();
        }
        #[test]
        fn verify_reports_tip_tamper() {
            if !$guard() {
                return;
            }
            common::verify_reports_tip_tamper::<$backend>();
        }
        #[test]
        fn verify_reports_exact_index_on_unparseable_tamper() {
            if !$guard() {
                return;
            }
            common::verify_reports_exact_index_on_unparseable_tamper::<$backend>();
        }
        #[test]
        fn verify_detects_deleted_middle_record_as_chain_break() {
            if !$guard() {
                return;
            }
            common::verify_detects_deleted_middle_record_as_chain_break::<$backend>();
        }
        #[test]
        fn mid_ledger_corruption_is_a_hard_error_on_open() {
            if !$guard() {
                return;
            }
            common::mid_ledger_corruption_is_a_hard_error_on_open::<$backend>();
        }
        #[test]
        fn deleted_record_is_a_hard_error_on_open() {
            if !$guard() {
                return;
            }
            common::deleted_record_is_a_hard_error_on_open::<$backend>();
        }
        #[test]
        fn sessions_and_find_by_call_id() {
            if !$guard() {
                return;
            }
            common::sessions_and_find_by_call_id::<$backend>();
        }
        #[test]
        fn empty_ledger_verifies_intact() {
            if !$guard() {
                return;
            }
            common::empty_ledger_verifies_intact::<$backend>();
        }
        #[test]
        fn open_store_picks_this_backend() {
            if !$guard() {
                return;
            }
            common::open_store_picks_this_backend::<$backend>();
        }
    };
}
