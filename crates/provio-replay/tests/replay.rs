//! Acceptance tests for provio-replay against a real on-disk ledger.

use provio_core::call::{CallerIdentity, InterceptMode, ToolCall};
use provio_core::ledger::LedgerWriter;
use provio_core::verdict::Verdict;
use provio_core::Timestamp;
use provio_ledger::FileLedgerStore;
use provio_replay::{branch_from, load_trajectory, policy_replay};

struct TestDir(std::path::PathBuf);
impl TestDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("provio-replay-{}-{}", std::process::id(), {
            // A counter, not a timestamp: clock resolution is coarse on some
            // platforms (macOS: µs), so parallel tests collided on one dir.
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        }));
        std::fs::create_dir_all(&p).unwrap();
        TestDir(p)
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn call(session: &str, seq: u64, tool: &str, args: serde_json::Value) -> ToolCall {
    ToolCall {
        call_id: format!("{session}-{seq}"),
        session_id: session.into(),
        caller: CallerIdentity {
            agent: "test".into(),
            agent_version: None,
            user: None,
            non_human_id: None,
        },
        mode: InterceptMode::Mcp,
        tool: tool.into(),
        args,
        server: None,
        trust: None,
        captured_at: Timestamp::now(),
    }
}

/// Ledger with: allow(bash ls) + execution, deny(bash rm), ask(postgres DROP, irreversible).
fn fixture_ledger() -> (TestDir, std::path::PathBuf, String) {
    let dir = TestDir::new();
    let path = dir.0.join("ledger.jsonl");
    let session = "s-replay".to_string();
    let mut store = FileLedgerStore::open(&path).unwrap();
    let mut w = LedgerWriter::new(&mut store);

    let c0 = call(&session, 0, "bash", serde_json::json!({"command": "ls"}));
    let d0 = w
        .record_decision(&c0, &Verdict::Allow { rule_id: None }, None)
        .unwrap();
    w.record_execution(&d0, "local-os", 0, b"file.rs\n")
        .unwrap();

    let c1 = call(
        &session,
        1,
        "bash",
        serde_json::json!({"command": "rm -rf /"}),
    );
    w.record_decision(
        &c1,
        &Verdict::Deny {
            rule_id: "block-destructive-shell".into(),
            reason: "no".into(),
            location: Some("provio.yaml:6".into()),
        },
        None,
    )
    .unwrap();

    let c2 = call(
        &session,
        2,
        "postgres.query",
        serde_json::json!({"query": "DROP TABLE users;"}),
    );
    w.record_decision(
        &c2,
        &Verdict::Ask {
            rule_id: "protect-production-db".into(),
            diff: "DROP TABLE users;".into(),
            timeout_ms: Some(300_000),
            irreversible: true,
            location: Some("provio.yaml:11".into()),
        },
        None,
    )
    .unwrap();

    (dir, path, session)
}

#[test]
fn trajectory_pairs_decisions_with_executions() {
    let (_d, path, session) = fixture_ledger();
    let steps = load_trajectory(&path, &session).unwrap();
    assert_eq!(steps.len(), 3);
    assert!(steps[0].execution.is_some());
    assert!(steps[1].execution.is_none()); // denied calls never execute
    assert!(steps[2].execution.is_none()); // unanswered ask
}

#[test]
fn policy_replay_flags_newly_blocked_calls() {
    let (_d, path, session) = fixture_ledger();
    let steps = load_trajectory(&path, &session).unwrap();
    // Candidate policy: deny even `ls`.
    let candidate = "version: 1\ndefault: deny\nrules: []\n";
    let report = policy_replay(&steps, candidate).unwrap();
    // allow→deny for ls; deny→deny unchanged; ask→deny changes too.
    assert!(report
        .changes
        .iter()
        .any(|c| c.tool == "bash" && c.was == "allow" && c.now == "deny"));
    assert!(report.summary().contains("previously-allowed"));
}

#[test]
fn guarded_branching_refuses_irreversible_by_default() {
    let (_d, path, session) = fixture_ledger();
    let steps = load_trajectory(&path, &session).unwrap();
    let err = branch_from(&steps, 0, false).unwrap_err();
    assert!(err.to_string().contains("refusing to re-branch"), "{err}");
    assert!(err.to_string().contains("s-replay-2"), "{err}");

    let plan = branch_from(&steps, 0, true).unwrap();
    assert!(plan.acknowledged);
    assert_eq!(plan.irreversible, vec!["s-replay-2".to_string()]);
    assert_eq!(plan.replayable.len(), 3);
}
