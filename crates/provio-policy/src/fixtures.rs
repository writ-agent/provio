//! Policy-test harness backing `provio policy test` (built by the CLI crate).
//!
//! Fixtures are plain YAML/JSON-deserializable values; `run_fixtures`
//! evaluates each against a policy source and reports agreement. All engines
//! (native, Rego, Cedar) must agree on `crates/provio-policy/fixtures/`
//! (INTERFACES.md Contract 2).

use provio_core::call::{CallerIdentity, InterceptMode, ToolCall, ToolCallContext};
use provio_core::error::{ProvioError, Result};
use provio_core::verdict::Verdict;
use provio_core::{PolicyEngine, Timestamp};
use serde::Deserialize;
use std::path::Path;

use crate::engine::NativePolicyEngine;

/// A single policy test case.
#[derive(Debug, Clone, Deserialize)]
pub struct Fixture {
    /// Human-readable case name, shown in test output.
    pub name: String,
    /// Optional per-fixture policy override (YAML source). When present this
    /// policy is used instead of the one passed to `run_fixtures`.
    #[serde(default)]
    pub policy: Option<String>,
    /// The call context to evaluate.
    #[serde(default)]
    pub ctx: FixtureCtx,
    /// What the engine must return.
    pub expect: Expectation,
}

/// Expected outcome of a fixture.
#[derive(Debug, Clone, Deserialize)]
pub struct Expectation {
    pub verdict: ExpectedKind,
    /// Optional exact rule id check (e.g. `block-destructive-shell`).
    #[serde(default)]
    pub rule_id: Option<String>,
}

/// The verdict kind a fixture expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExpectedKind {
    Allow,
    Deny,
    Ask,
    Redact,
}

/// Evaluation input for a fixture: either explicit `ToolCallContext` fields
/// or raw `args` JSON (normalized through `ToolCallContext::from_call`,
/// exactly as real interceptions are). Explicit fields override derived ones.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FixtureCtx {
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub url_host: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub trust: Option<String>,
    /// "mcp" | "processwrap" | "sdkhook"
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub agent: Option<String>,
    /// Raw tool-call arguments JSON (e.g. `{"command": "rm -rf /"}`).
    #[serde(default)]
    pub args: Option<serde_json::Value>,
}

impl FixtureCtx {
    /// Build the evaluation context. If `args` is present, fields are derived
    /// via `ToolCallContext::from_call` (the real normalization path) and any
    /// explicitly-set fields take precedence over the derived values.
    pub fn to_context(&self) -> std::result::Result<ToolCallContext, String> {
        let mode = match self.mode.as_deref() {
            None => InterceptMode::Mcp,
            Some("mcp") => InterceptMode::Mcp,
            Some("processwrap") => InterceptMode::ProcessWrap,
            Some("sdkhook") => InterceptMode::SdkHook,
            Some(other) => {
                return Err(format!(
                    "unknown mode {:?} (expected mcp, processwrap, sdkhook)",
                    other
                ))
            }
        };
        if let Some(args) = &self.args {
            let call = ToolCall {
                call_id: "fixture-call".to_string(),
                session_id: "fixture-session".to_string(),
                caller: CallerIdentity {
                    agent: self
                        .agent
                        .clone()
                        .unwrap_or_else(|| "fixture-agent".to_string()),
                    agent_version: None,
                    user: None,
                    non_human_id: None,
                },
                mode,
                tool: self.tool.clone().unwrap_or_default(),
                args: args.clone(),
                server: self
                    .server
                    .clone()
                    .map(|name| provio_core::call::ServerIdentity {
                        name,
                        transport: "stdio".to_string(),
                        version: None,
                    }),
                trust: None,
                captured_at: Timestamp::now(),
            };
            let mut ctx = ToolCallContext::from_call(&call);
            if let Some(v) = &self.command {
                ctx.command = Some(v.clone());
            }
            if let Some(v) = &self.path {
                ctx.path = Some(v.clone());
            }
            if let Some(v) = &self.url_host {
                ctx.url_host = Some(v.clone());
            }
            if let Some(v) = &self.query {
                ctx.query = Some(v.clone());
            }
            if let Some(v) = &self.trust {
                ctx.trust = Some(v.clone());
            }
            Ok(ctx)
        } else {
            Ok(ToolCallContext {
                tool: self.tool.clone().unwrap_or_default(),
                command: self.command.clone(),
                path: self.path.clone(),
                url_host: self.url_host.clone(),
                query: self.query.clone(),
                server: self.server.clone(),
                trust: self.trust.clone(),
                mode,
                agent: self.agent.clone().unwrap_or_default(),
            })
        }
    }
}

/// One fixture disagreement.
#[derive(Debug, Clone)]
pub struct FixtureFailure {
    pub name: String,
    pub expected: String,
    pub actual: String,
}

/// Aggregate result of a fixture run.
#[derive(Debug, Clone)]
pub struct TestReport {
    pub total: usize,
    pub passed: usize,
    pub failures: Vec<FixtureFailure>,
    /// Set when the policy source itself failed to compile (no fixtures ran).
    pub error: Option<String>,
}

impl TestReport {
    pub fn is_pass(&self) -> bool {
        self.error.is_none() && self.failures.is_empty()
    }

    /// One line per outcome, suitable for CLI output.
    pub fn summary(&self) -> String {
        if let Some(e) = &self.error {
            return format!("policy error: {}", e);
        }
        let mut out = format!("{}/{} fixtures passed", self.passed, self.total);
        for f in &self.failures {
            out.push_str(&format!(
                "\n  FAIL {}: expected {}, got {}",
                f.name, f.expected, f.actual
            ));
        }
        out
    }
}

fn verdict_kind(v: &Verdict) -> ExpectedKind {
    match v {
        Verdict::Allow { .. } => ExpectedKind::Allow,
        Verdict::Deny { .. } => ExpectedKind::Deny,
        Verdict::Ask { .. } => ExpectedKind::Ask,
        Verdict::Redact { .. } => ExpectedKind::Redact,
    }
}

fn kind_str(k: ExpectedKind) -> &'static str {
    match k {
        ExpectedKind::Allow => "allow",
        ExpectedKind::Deny => "deny",
        ExpectedKind::Ask => "ask",
        ExpectedKind::Redact => "redact",
    }
}

/// Evaluate every fixture against `policy_source` (or the fixture's own
/// `policy` override) and report agreement. Never fails as a whole: compile
/// errors and mismatches are reported inside the `TestReport`.
pub fn run_fixtures(policy_source: &str, fixtures: &[Fixture]) -> TestReport {
    let shared_engine = match NativePolicyEngine::from_source(policy_source) {
        Ok(e) => Some(e),
        Err(e) => {
            return TestReport {
                total: fixtures.len(),
                passed: 0,
                failures: Vec::new(),
                error: Some(e.to_string()),
            }
        }
    };

    let mut report = TestReport {
        total: fixtures.len(),
        passed: 0,
        failures: Vec::new(),
        error: None,
    };

    for fx in fixtures {
        match run_one(fx, shared_engine.as_ref()) {
            Ok(()) => report.passed += 1,
            Err(f) => report.failures.push(f),
        }
    }
    report
}

fn run_one(
    fx: &Fixture,
    shared: Option<&NativePolicyEngine>,
) -> std::result::Result<(), FixtureFailure> {
    let fail = |actual: String| FixtureFailure {
        name: fx.name.clone(),
        expected: format!(
            "{}{}",
            kind_str(fx.expect.verdict),
            fx.expect
                .rule_id
                .as_deref()
                .map(|r| format!(" (rule {})", r))
                .unwrap_or_default()
        ),
        actual,
    };

    let local_engine;
    let engine: &NativePolicyEngine = match &fx.policy {
        Some(src) => {
            local_engine = NativePolicyEngine::from_source(src)
                .map_err(|e| fail(format!("fixture policy failed to compile: {}", e)))?;
            &local_engine
        }
        None => shared.expect("shared engine exists when no error"),
    };

    let ctx = fx
        .ctx
        .to_context()
        .map_err(|e| fail(format!("bad ctx: {}", e)))?;
    let verdict = engine.evaluate(&ctx);

    let actual_kind = verdict_kind(&verdict);
    if actual_kind != fx.expect.verdict {
        return Err(fail(format!(
            "{} ({})",
            kind_str(actual_kind),
            serde_json::to_string(&verdict).unwrap_or_default()
        )));
    }
    if let Some(expected_rule) = &fx.expect.rule_id {
        let actual_rule = verdict.rule_id().unwrap_or("<none>");
        if actual_rule != expected_rule {
            return Err(fail(format!("rule {}", actual_rule)));
        }
    }
    // Invariants every verdict must uphold, checked here so all fixtures
    // enforce them: Deny/Ask always carry a human reason/diff.
    match &verdict {
        Verdict::Deny { reason, .. } if reason.trim().is_empty() => {
            return Err(fail("deny verdict with empty reason".to_string()))
        }
        Verdict::Ask { diff, .. } if diff.trim().is_empty() => {
            return Err(fail("ask verdict with empty diff".to_string()))
        }
        _ => {}
    }
    Ok(())
}

/// Load every `*.yaml` / `*.yml` file in `dir` (sorted by name) as a list of
/// fixtures. This is the shared corpus all engines must agree on.
pub fn load_fixtures_dir(dir: &Path) -> Result<Vec<Fixture>> {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map_err(ProvioError::Io)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            matches!(
                p.extension().and_then(|e| e.to_str()),
                Some("yaml") | Some("yml")
            )
        })
        .collect();
    files.sort();

    let mut out = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).map_err(ProvioError::Io)?;
        let mut fixtures: Vec<Fixture> = serde_yaml::from_str(&text)
            .map_err(|e| ProvioError::Policy(format!("{}: {}", path.display(), e)))?;
        out.append(&mut fixtures);
    }
    Ok(out)
}
