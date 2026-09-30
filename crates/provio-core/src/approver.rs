//! Contract 5: the `Approver` trait — plumbing for the `ask` verdict.
//!
//! Three implementations across topologies (plan §4.2):
//! TUI approver (workstation), out-of-band approver (CI webhook),
//! RBAC-checked approver (cluster). Headless timeout ALWAYS fails closed
//! and is always recorded with the approver's identity (spec §7).

use crate::call::ToolCall;
use crate::error::Result;
use serde::{Deserialize, Serialize};

/// What the human (or out-of-band system) decided.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum ApprovalDecision {
    AllowOnce,
    /// Suppresses this rule for the rest of the session (TUI `[!]` key).
    AlwaysAllowRule,
    Deny,
    /// Human edited the planned arguments before allowing.
    EditArgs(serde_json::Value),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApproverKind {
    Tui,
    OutOfBand,
    Rbac,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverIdentity {
    pub kind: ApproverKind,
    /// Local username, SSO subject, or webhook responder id.
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalOutcome {
    pub decision: ApprovalDecision,
    pub approver: ApproverIdentity,
    pub waited_ms: u64,
}

/// Rendered view of an `ask` verdict, ready for a human.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AskView {
    pub rule_id: String,
    pub diff: String,
    pub timeout_ms: Option<u64>,
    pub irreversible: bool,
}

impl AskView {
    pub fn from_verdict(v: &crate::verdict::Verdict) -> Option<Self> {
        match v {
            crate::verdict::Verdict::Ask {
                rule_id,
                diff,
                timeout_ms,
                irreversible,
                ..
            } => Some(AskView {
                rule_id: rule_id.clone(),
                diff: diff.clone(),
                timeout_ms: *timeout_ms,
                irreversible: *irreversible,
            }),
            _ => None,
        }
    }
}

pub trait Approver {
    /// Suspend the call and request a decision. Implementations must honour
    /// `ask.timeout_ms` by returning `Deny` (fail closed) on timeout.
    fn request(&self, call: &ToolCall, ask: &AskView) -> Result<ApprovalOutcome>;
}

/// Headless default (CI before an out-of-band approver is configured):
/// every `ask` is denied. Fail closed, always (spec §7).
pub struct FailClosedApprover;

impl Approver for FailClosedApprover {
    fn request(&self, _call: &ToolCall, ask: &AskView) -> Result<ApprovalOutcome> {
        Ok(ApprovalOutcome {
            decision: ApprovalDecision::Deny,
            approver: ApproverIdentity {
                kind: ApproverKind::OutOfBand,
                id: format!("fail-closed(timeout={:?})", ask.timeout_ms),
            },
            waited_ms: 0,
        })
    }
}
