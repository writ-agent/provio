//! Native writ.yaml policy engine: parser, evaluator, four verdicts, hot-reload, policy test harness.
//!
//! Implements `writ_core::PolicyEngine` (INTERFACES.md Contract 2):
//!
//! - [`NativePolicyEngine`] compiles `writ.yaml` (serde_yaml) into a validated
//!   rule set. Rule `when` strings are parsed by a small recursive-descent
//!   parser into an AST with `and`/`or`/`not`/parens, comparison operators
//!   (`==`, `!=`, `startswith`, `endswith`, `contains`, `matches`), and
//!   named-list membership (`url.host in hosts.allowed`) with `*.example.com`
//!   wildcard host matching.
//! - First matching rule wins; unmatched calls hit the policy's `default`
//!   (fail-closed `ask`). Every Deny/Ask carries rule id, a human reason, and
//!   a `writ.yaml:LINE` location (spec §12).
//! - `reload` is atomic: the new source is fully compiled before swapping;
//!   on any error the last-good policy keeps serving (spec §7).
//! - [`fixtures`] is the policy-test harness behind `writ policy test`.

#![forbid(unsafe_code)]

pub mod ast;
mod engine;
pub mod fixtures;
pub mod packs;
mod parser;
pub mod policy_file;

pub use engine::NativePolicyEngine;
/// Canonical verdict construction, shared by every engine backend (Rego,
/// Cedar) so a matched rule or a policy default yields byte-identical
/// verdicts regardless of the engine that decided it.
pub use engine::{default_verdict, eval_expr, verdict_for};
pub use fixtures::{
    load_fixtures_dir, run_fixtures, Expectation, ExpectedKind, Fixture, FixtureCtx,
    FixtureFailure, TestReport,
};
pub use policy_file::{parse_duration, POLICY_FILE_NAME};
