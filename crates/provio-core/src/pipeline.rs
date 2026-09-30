//! The decision pipeline (spec §5): intercept → decide → (approve) → record.
//!
//! Invariants enforced here (plan §4.3):
//! - every intercepted call produces exactly one decision record, including
//!   denials and redactions;
//! - an `ask` never dispatches without an approver outcome;
//! - dispatch happens only after the decision record is durably written.

use crate::approver::{ApprovalDecision, ApprovalOutcome, Approver, AskView};
use crate::call::{ToolCall, ToolCallContext};
use crate::error::{ProvioError, Result};
use crate::ledger::{LedgerRecord, LedgerWriter};
use crate::policy::PolicyEngine;
use crate::verdict::Verdict;

pub struct DecisionOutcome {
    /// Final verdict after any approval step.
    pub verdict: Verdict,
    /// Present iff the engine returned `ask`.
    pub approval: Option<ApprovalOutcome>,
    /// Replacement args when the approver chose `EditArgs`.
    pub edited_args: Option<serde_json::Value>,
    /// The persisted decision record (its index links execution records).
    pub record: LedgerRecord,
}

impl DecisionOutcome {
    pub fn should_dispatch(&self) -> bool {
        matches!(self.verdict, Verdict::Allow { .. } | Verdict::Redact { .. })
    }
}

/// Evaluate one intercepted call end-to-end and write its decision record.
pub fn handle_call(
    call: &ToolCall,
    policy: &dyn PolicyEngine,
    ledger: &mut LedgerWriter,
    approver: &dyn Approver,
) -> Result<DecisionOutcome> {
    let ctx = ToolCallContext::from_call(call);
    let mut verdict = policy.evaluate(&ctx);
    // The ledger records the ENGINE's verdict (spec §9: "the verdict and the
    // rule that produced it"). If a human approves an `ask`, the record keeps
    // the ask — including its irreversible marking, which replay/branching
    // depends on (spec §10) — and the approver identity carries the outcome.
    let engine_verdict = verdict.clone();
    let mut approval = None;
    let mut edited_args = None;

    if let Some(ask) = AskView::from_verdict(&verdict) {
        let outcome = approver.request(call, &ask)?;
        verdict = resolve_approval(&ask, &outcome)?;
        approval = Some(outcome);
        if let Some(ApprovalOutcome {
            decision: ApprovalDecision::EditArgs(v),
            ..
        }) = &approval
        {
            edited_args = Some(v.clone());
        }
    }

    let record = ledger.record_decision(
        call,
        &engine_verdict,
        approval.as_ref().map(|a| a.approver.clone()),
    )?;

    Ok(DecisionOutcome {
        verdict,
        approval,
        edited_args,
        record,
    })
}

fn resolve_approval(ask: &AskView, outcome: &ApprovalOutcome) -> Result<Verdict> {
    Ok(match &outcome.decision {
        ApprovalDecision::AllowOnce
        | ApprovalDecision::AlwaysAllowRule
        | ApprovalDecision::EditArgs(_) => Verdict::Allow {
            rule_id: Some(ask.rule_id.clone()),
        },
        ApprovalDecision::Deny => Verdict::Deny {
            rule_id: ask.rule_id.clone(),
            reason: format!("denied by approver {}", outcome.approver.id),
            location: None,
        },
    })
}

/// Record the execution outcome of a dispatched call (linked follow-on record).
pub fn record_execution(
    ledger: &mut LedgerWriter,
    decision: &LedgerRecord,
    backend: &str,
    exit_status: i32,
    output: &[u8],
) -> Result<LedgerRecord> {
    if !decision.kind.eq(&crate::ledger::RecordKind::Decision) {
        return Err(ProvioError::Ledger("execution must link a decision".into()));
    }
    ledger.record_execution(decision, backend, exit_status, output)
}
