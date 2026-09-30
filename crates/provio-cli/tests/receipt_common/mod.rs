//! Shared fixtures for the `provio receipt` tests: a scratch project with a
//! real hash-chained ledger, and a runner for the built binary.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use provio_core::call::{CallerIdentity, InterceptMode, ToolCall};
use provio_core::ledger::{LedgerRecord, LedgerWriter};
use provio_core::{Timestamp, Verdict};
use provio_ledger::FileLedgerStore;

pub struct Project(PathBuf);

impl Project {
    pub fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("provio-receipt-{tag}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(path.join(".provio")).unwrap();
        Project(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    pub fn ledger(&self) -> PathBuf {
        self.0.join(".provio").join("ledger.jsonl")
    }

    /// Append `n` calls (decision + execution each) in `session`.
    /// Returns their call ids.
    pub fn add_calls(&self, session: &str, n: usize) -> Vec<String> {
        let mut store = FileLedgerStore::open(self.ledger()).unwrap();
        let mut w = LedgerWriter::new(&mut store);
        let mut ids = Vec::new();
        for _ in 0..n {
            static CALL: AtomicU64 = AtomicU64::new(0);
            let id = format!("call-{}", CALL.fetch_add(1, Ordering::SeqCst));
            let call = ToolCall {
                call_id: id.clone(),
                session_id: session.into(),
                caller: CallerIdentity {
                    agent: "test".into(),
                    agent_version: None,
                    user: None,
                    non_human_id: None,
                },
                mode: InterceptMode::SdkHook,
                tool: "bash".into(),
                args: serde_json::json!({"command": format!("echo {id}")}),
                server: None,
                trust: None,
                captured_at: Timestamp::now(),
            };
            let d = w
                .record_decision(
                    &call,
                    &Verdict::Allow {
                        rule_id: Some("ok".into()),
                    },
                    None,
                )
                .unwrap();
            w.record_execution(&d, "local-os", 0, id.as_bytes())
                .unwrap();
            ids.push(id);
        }
        ids
    }

    pub fn lines(&self) -> Vec<String> {
        std::fs::read_to_string(self.ledger())
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    pub fn write_lines(&self, lines: &[String]) {
        let mut s = lines.join("\n");
        s.push('\n');
        std::fs::write(self.ledger(), s).unwrap();
    }

    pub fn records(&self) -> Vec<LedgerRecord> {
        self.lines()
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    pub fn write_records(&self, recs: &[LedgerRecord]) {
        let lines: Vec<String> = recs
            .iter()
            .map(|r| serde_json::to_string(r).unwrap())
            .collect();
        self.write_lines(&lines);
    }

    /// Run `provio --ledger <ledger> <args>` in the project directory.
    pub fn provio(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_provio"));
        cmd.current_dir(&self.0)
            .arg("--ledger")
            .arg(self.ledger())
            .args(args);
        // Windows Application Control can transiently refuse a fresh
        // binary (os error 4551); retry a few times.
        let mut last = None;
        for _ in 0..30 {
            match cmd.output() {
                Ok(o) => return o,
                Err(e) if e.raw_os_error() == Some(4551) => {
                    last = Some(e);
                    std::thread::sleep(std::time::Duration::from_millis(1000));
                }
                Err(e) => panic!("run provio: {e}"),
            }
        }
        panic!("run provio: {last:?}");
    }

    /// Keygen to `<dir>/<name>` and return (private, public) paths.
    pub fn keygen(&self, name: &str) -> (PathBuf, PathBuf) {
        let key = self.file(name);
        let o = self.provio(&["receipt", "keygen", "--out", key.to_str().unwrap()]);
        assert_ok(&o);
        let mut p = key.as_os_str().to_owned();
        p.push(".pub");
        (key, PathBuf::from(p))
    }

    /// `provio receipt create` into `<dir>/<name>`.
    pub fn create(&self, key: &Path, name: &str, extra: &[&str]) -> PathBuf {
        let out = self.file(name);
        let mut args = vec![
            "receipt",
            "create",
            "--key",
            key.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        assert_ok(&self.provio(&args));
        out
    }

    pub fn verify(&self, file: &Path, extra: &[&str]) -> Output {
        let mut args = vec!["receipt", "verify", file.to_str().unwrap()];
        args.extend_from_slice(extra);
        self.provio(&args)
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

pub fn assert_ok(o: &Output) {
    assert!(o.status.success(), "expected success, got:\n{}", text(o));
}

/// Exit code 1 and `needle` somewhere in the output.
pub fn assert_fails_with(o: &Output, needle: &str) {
    assert_eq!(
        o.status.code(),
        Some(1),
        "expected exit 1, got:\n{}",
        text(o)
    );
    assert!(
        text(o).contains(needle),
        "expected {needle:?} in output:\n{}",
        text(o)
    );
}
