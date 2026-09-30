//! provio-core — the frozen contracts of the Provio platform.
//!
//! Authorization and provenance for AI agents: every tool call is checked
//! against one policy file, executed inside a chosen sandbox, and written to
//! a tamper-evident ledger (spec v2.0, §5).
//!
//! The five contracts (docs/INTERFACES.md):
//! 1. [`call::ToolCall`] — interception envelope
//! 2. [`policy::PolicyEngine`] + [`verdict::Verdict`] — decision IR
//! 3. [`ledger::LedgerRecord`] schema v1 + [`ledger::LedgerStore`]
//! 4. [`sandbox::SandboxBackend`] — prepare/exec/collect/teardown
//! 5. [`approver::Approver`] — ask-verdict plumbing

#![forbid(unsafe_code)]

pub mod approver;
pub mod call;
pub mod error;
pub mod ledger;
pub mod pipeline;
pub mod policy;
pub mod sandbox;
pub mod time;
pub mod verdict;

pub use approver::{
    ApprovalDecision, ApprovalOutcome, Approver, ApproverIdentity, AskView, FailClosedApprover,
};
pub use call::{
    CallerIdentity, InterceptMode, ServerIdentity, ToolCall, ToolCallContext, TrustVerdict,
};
pub use error::{ProvioError, Result};
pub use ledger::{verify_chain, LedgerRecord, LedgerStore, LedgerWriter, RecordKind, VerifyReport};
pub use pipeline::{handle_call, DecisionOutcome};
pub use policy::PolicyEngine;
pub use sandbox::{Artifacts, ExecOutput, ExecRequest, SandboxBackend, SandboxId, SandboxSpec};
pub use time::Timestamp;
pub use verdict::{DefaultVerdict, Verdict};

/// Wrapper for credential material. `Debug`, `Clone` and `Serialize` are
/// deliberately absent so credentials can never leak into a ledger record
/// or log line (plan §4.3 invariant; spec §11 credential injection).
pub struct SecretString(String);

impl SecretString {
    pub fn new(s: impl Into<String>) -> Self {
        SecretString(s.into())
    }

    /// Expose the secret for the single permitted use: dispatch-time injection.
    pub fn expose(&self) -> &str {
        &self.0
    }
}
