//! Contract 2 (input half): the `PolicyEngine` trait.
//!
//! Implementations: native DSL (provio-policy), Rego (provio-policy-rego),
//! Cedar (provio-policy-cedar). All three must produce identical verdicts on
//! the shared fixture corpus (spec §7, plan §4.2).

use crate::call::ToolCallContext;
use crate::error::Result;
use crate::verdict::Verdict;

pub trait PolicyEngine {
    /// Engine identifier: "native" | "rego" | "cedar".
    fn name(&self) -> &'static str;

    /// Evaluate one call. Must always return a verdict — engines apply their
    /// configured default when no rule matches (fail-closed means the default
    /// is `ask` unless the operator says otherwise).
    fn evaluate(&self, ctx: &ToolCallContext) -> Verdict;

    /// Atomic hot-reload (spec §7). On parse/compile failure the engine MUST
    /// keep serving the last-good policy and return the error with file:line.
    fn reload(&mut self, source: &str) -> Result<()>;

    /// Number of loaded rules (surfaced in the CLI banner: "4 rules loaded").
    fn rule_count(&self) -> usize;
}

/// The policy file's declared default, applied by engines — mirrored here so
/// the CLI can print/override it (`--yolo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyMeta {
    pub version: u32,
    pub default: crate::verdict::DefaultVerdict,
}
