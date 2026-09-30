//! provio-replay — record & replay, the honest version (spec §10).
//!
//! Implemented here:
//! - **Policy replay**: evaluate a candidate `provio.yaml` against recorded
//!   runs — "this rule change would have blocked 3 calls that previously
//!   succeeded". The platform-team trust feature.
//! - **Guarded branching**: re-branch from step N; steps marked
//!   `irreversible` refuse by default.
//!
//! Deterministic I/O replay against a cached model provider needs agent-side
//! capture (an SDK hook, mode C) and lands in wave 2 — stated plainly rather
//! than promised early. There is no rewind for tool calls that already
//! changed the world; nothing here pretends otherwise.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;

use provio_core::call::ToolCallContext;
use provio_core::error::{ProvioError, Result};
use provio_core::ledger::{LedgerRecord, RecordKind};
use provio_core::verdict::Verdict;
use provio_core::PolicyEngine;
use provio_ledger::open_store;
use provio_policy::NativePolicyEngine;

/// One ledger decision plus its linked execution, if the call was dispatched.
#[derive(Debug, Clone)]
pub struct RecordedStep {
    pub decision: LedgerRecord,
    pub execution: Option<LedgerRecord>,
}

/// Load a session's trajectory: decision records in order, each paired with
/// its execution record where one exists. The store (JSONL or SQLite) is
/// chosen by `provio_ledger::open_store`.
pub fn load_trajectory(ledger: &Path, session_id: &str) -> Result<Vec<RecordedStep>> {
    let store = open_store(ledger)?;
    let mut decisions: Vec<LedgerRecord> = Vec::new();
    let mut executions: HashMap<u64, LedgerRecord> = HashMap::new();
    for rec in store.iter() {
        let rec = rec?;
        if rec.session_id != session_id {
            continue;
        }
        match rec.kind {
            RecordKind::Decision => decisions.push(rec),
            RecordKind::Execution => {
                if let Some(di) = rec.decision_index {
                    executions.insert(di, rec);
                }
            }
        }
    }
    Ok(decisions
        .into_iter()
        .map(|d| {
            let e = executions.get(&d.index).cloned();
            RecordedStep {
                decision: d,
                execution: e,
            }
        })
        .collect())
}

fn verdict_label(v: &Verdict) -> &'static str {
    match v {
        Verdict::Allow { .. } => "allow",
        Verdict::Deny { .. } => "deny",
        Verdict::Ask { .. } => "ask",
        Verdict::Redact { .. } => "redact",
    }
}

/// One verdict that a candidate policy would change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictChange {
    pub call_id: String,
    pub tool: String,
    pub was: String,
    pub now: String,
    pub now_rule: Option<String>,
}

/// Result of replaying recorded calls against a candidate policy.
#[derive(Debug)]
pub struct ReplayReport {
    pub steps: usize,
    pub unchanged: usize,
    pub changes: Vec<VerdictChange>,
}

impl ReplayReport {
    /// The platform-team sentence (spec §10).
    pub fn summary(&self) -> String {
        let newly_blocked = self
            .changes
            .iter()
            .filter(|c| c.was == "allow" && (c.now == "deny" || c.now == "ask"))
            .count();
        format!(
            "policy replay: {} recorded calls · {} unchanged · {} would change · {} previously-allowed call(s) would now be blocked",
            self.steps,
            self.unchanged,
            self.changes.len(),
            newly_blocked
        )
    }
}

/// Evaluate a candidate policy against a recorded trajectory.
pub fn policy_replay(steps: &[RecordedStep], candidate_source: &str) -> Result<ReplayReport> {
    let engine = NativePolicyEngine::from_source(candidate_source)
        .map_err(|e| ProvioError::Policy(e.to_string()))?;
    let mut changes = Vec::new();
    let mut unchanged = 0usize;
    for step in steps {
        let Some(call) = &step.decision.call else {
            continue;
        };
        let Some(was_verdict) = &step.decision.verdict else {
            continue;
        };
        let ctx = ToolCallContext::from_call(call);
        let now = engine.evaluate(&ctx);
        let (was, now_l) = (verdict_label(was_verdict), verdict_label(&now));
        if was == now_l {
            unchanged += 1;
        } else {
            changes.push(VerdictChange {
                call_id: call.call_id.clone(),
                tool: call.tool.clone(),
                was: was.to_string(),
                now: now_l.to_string(),
                now_rule: now.rule_id().map(|s| s.to_string()),
            });
        }
    }
    Ok(ReplayReport {
        steps: steps.len(),
        unchanged,
        changes,
    })
}
/// The plan for re-branching from a recorded step.
#[derive(Debug)]
pub struct BranchPlan {
    /// Steps in the replay window (from `from_index` onward).
    pub replayable: Vec<RecordedStep>,
    /// Irreversible steps in the window (excluded by default; included,
    /// flagged, only with the explicit acknowledgement).
    pub irreversible: Vec<String>,
    pub acknowledged: bool,
}

/// Guarded branching (spec §10): default posture is refusal.
pub fn branch_from(
    steps: &[RecordedStep],
    from_decision_index: u64,
    ack_irreversible: bool,
) -> Result<BranchPlan> {
    let window: Vec<&RecordedStep> = steps
        .iter()
        .filter(|s| s.decision.index >= from_decision_index)
        .collect();
    if window.is_empty() {
        return Err(ProvioError::Ledger(format!(
            "no recorded step at or after decision index {from_decision_index}"
        )));
    }
    let irreversible: Vec<String> = window
        .iter()
        .filter(|s| {
            s.decision
                .verdict
                .as_ref()
                .map(|v| v.is_irreversible())
                .unwrap_or(false)
        })
        .map(|s| s.decision.call_id.clone())
        .collect();

    if !irreversible.is_empty() && !ack_irreversible {
        return Err(ProvioError::Ledger(format!(
            "refusing to re-branch: {} irreversible step(s) in window [{}]; pass the explicit acknowledgement flag to include them",
            irreversible.len(),
            irreversible.join(", ")
        )));
    }
    Ok(BranchPlan {
        replayable: window.into_iter().cloned().collect(),
        irreversible,
        acknowledged: ack_irreversible,
    })
}
