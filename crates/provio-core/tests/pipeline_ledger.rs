use provio_core::approver::{
    ApprovalDecision, ApprovalOutcome, Approver, ApproverIdentity, ApproverKind, AskView,
    FailClosedApprover,
};
use provio_core::call::{CallerIdentity, InterceptMode, ToolCall};
use provio_core::ledger::{LedgerRecord, LedgerStore, LedgerWriter, RecordKind, GENESIS_HASH};
use provio_core::policy::PolicyEngine;
use provio_core::verdict::Verdict;
use provio_core::{handle_call, ProvioError, Result, Timestamp};

#[derive(Default)]
struct MemStore(Vec<LedgerRecord>);

impl LedgerStore for MemStore {
    fn append(&mut self, record: &LedgerRecord) -> Result<()> {
        let expected = self.0.len() as u64;
        if record.index != expected {
            return Err(ProvioError::Ledger("bad index".into()));
        }
        let expected_prev = self
            .0
            .last()
            .map(|r| r.record_hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_string());
        if record.prev_hash != expected_prev {
            return Err(ProvioError::Ledger("bad prev".into()));
        }
        self.0.push(record.clone());
        Ok(())
    }
    fn tip(&self) -> Result<Option<LedgerRecord>> {
        Ok(self.0.last().cloned())
    }
    fn get(&self, index: u64) -> Result<Option<LedgerRecord>> {
        Ok(self.0.get(index as usize).cloned())
    }
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn iter(&self) -> Box<dyn Iterator<Item = Result<LedgerRecord>> + '_> {
        Box::new(self.0.clone().into_iter().map(Ok))
    }
}

struct AskPolicy;
impl PolicyEngine for AskPolicy {
    fn name(&self) -> &'static str {
        "test"
    }
    fn evaluate(&self, _ctx: &provio_core::ToolCallContext) -> Verdict {
        Verdict::Ask {
            rule_id: "irreversible-step".into(),
            diff: "DROP TABLE users".into(),
            timeout_ms: Some(1000),
            irreversible: true,
            location: Some("provio.yaml:9".into()),
        }
    }
    fn reload(&mut self, _source: &str) -> Result<()> {
        Ok(())
    }
    fn rule_count(&self) -> usize {
        1
    }
}

struct AllowApprover;
impl Approver for AllowApprover {
    fn request(&self, _call: &ToolCall, _ask: &AskView) -> Result<ApprovalOutcome> {
        Ok(ApprovalOutcome {
            decision: ApprovalDecision::AllowOnce,
            approver: ApproverIdentity {
                kind: ApproverKind::Tui,
                id: "tester".into(),
            },
            waited_ms: 0,
        })
    }
}

#[test]
fn approved_ask_records_engine_verdict_with_irreversible_flag() {
    let call = ToolCall {
        call_id: "c1".into(),
        session_id: "s1".into(),
        caller: CallerIdentity {
            agent: "test".into(),
            agent_version: None,
            user: None,
            non_human_id: None,
        },
        mode: InterceptMode::Mcp,
        tool: "postgres.query".into(),
        args: serde_json::json!({"query": "DROP TABLE users"}),
        server: None,
        trust: None,
        captured_at: Timestamp::now(),
    };
    let mut store = MemStore::default();
    let outcome = {
        let mut writer = LedgerWriter::new(&mut store);
        handle_call(&call, &AskPolicy, &mut writer, &AllowApprover).unwrap()
    };
    assert!(outcome.should_dispatch(), "approved ask dispatches");
    assert_eq!(store.0.len(), 1);
    assert_eq!(store.0[0].kind, RecordKind::Decision);
    match store.0[0].verdict.as_ref().unwrap() {
        Verdict::Ask {
            rule_id,
            irreversible,
            ..
        } => {
            assert_eq!(rule_id, "irreversible-step");
            assert!(
                *irreversible,
                "ledger must preserve irreversible ask for replay/branching"
            );
        }
        other => panic!("ledger must store engine ask verdict, got {other:?}"),
    }
}

fn postgres_drop_call() -> ToolCall {
    ToolCall {
        call_id: "c-headless".into(),
        session_id: "s-headless".into(),
        caller: CallerIdentity {
            agent: "test".into(),
            agent_version: None,
            user: None,
            non_human_id: None,
        },
        mode: InterceptMode::ProcessWrap,
        tool: "postgres.query".into(),
        args: serde_json::json!({"query": "DROP TABLE users"}),
        server: None,
        trust: None,
        captured_at: Timestamp::now(),
    }
}

#[test]
fn headless_ask_fails_closed_and_records_decision() {
    let call = postgres_drop_call();
    let mut store = MemStore::default();
    let outcome = {
        let mut writer = LedgerWriter::new(&mut store);
        handle_call(&call, &AskPolicy, &mut writer, &FailClosedApprover).unwrap()
    };

    assert!(!outcome.should_dispatch(), "headless ask must not dispatch");
    assert!(matches!(outcome.verdict, Verdict::Deny { .. }));
    let approval = outcome
        .approval
        .expect("fail-closed approver records denial");
    assert_eq!(approval.decision, ApprovalDecision::Deny);
    assert_eq!(approval.approver.kind, ApproverKind::OutOfBand);

    assert_eq!(
        store.0.len(),
        1,
        "decision is still recorded before refusal"
    );
    assert_eq!(store.0[0].kind, RecordKind::Decision);
    assert_eq!(
        store.0[0].approver.as_ref().unwrap().kind,
        ApproverKind::OutOfBand
    );
    assert!(matches!(
        store.0[0].verdict.as_ref().unwrap(),
        Verdict::Ask { .. }
    ));
}
