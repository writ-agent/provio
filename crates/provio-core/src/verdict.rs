//! Contract 2 (output half): the `Verdict` decision IR.
//!
//! All policy engines (native DSL, Rego, Cedar) must compile to these exact
//! verdicts (spec §7). Denials always carry rule id + reason + file location
//! so the model can self-correct (spec §12: never "denied by policy").

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Verdict {
    /// Dispatch to the sandbox backend. Recorded.
    Allow { rule_id: Option<String> },
    /// Structured refusal returned to the agent. Recorded.
    Deny {
        rule_id: String,
        reason: String,
        /// e.g. "provio.yaml:14"
        location: Option<String>,
    },
    /// Suspend for a human. In headless mode: out-of-band approver or
    /// fail closed on timeout. Recorded with the approver's identity.
    Ask {
        rule_id: String,
        /// Precise human-readable diff of the planned action.
        diff: String,
        timeout_ms: Option<u64>,
        /// Irreversible calls are excluded from automated replay (spec §10).
        irreversible: bool,
        location: Option<String>,
    },
    /// Execute, but mask matched patterns in the result before it re-enters
    /// the model's context. Recorded with a hash of the original.
    Redact {
        rule_id: String,
        patterns: Vec<String>,
    },
}

impl Verdict {
    pub fn rule_id(&self) -> Option<&str> {
        match self {
            Verdict::Allow { rule_id } => rule_id.as_deref(),
            Verdict::Deny { rule_id, .. } => Some(rule_id),
            Verdict::Ask { rule_id, .. } => Some(rule_id),
            Verdict::Redact { rule_id, .. } => Some(rule_id),
        }
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow { .. })
    }

    pub fn is_irreversible(&self) -> bool {
        matches!(
            self,
            Verdict::Ask {
                irreversible: true,
                ..
            }
        )
    }
}

/// What a policy does when no rule matches. Spec §7: fail-closed
/// (`default: ask`); `--yolo` flips to `Allow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultVerdict {
    Allow,
    Ask,
    Deny,
}
