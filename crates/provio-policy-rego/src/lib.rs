//! provio-policy-rego — the Rego engine backend (Contract 2, spec §7).
//!
//! Translates the native provio.yaml IR (`provio_policy::policy_file::CompiledPolicy`)
//! into a Rego module and evaluates it with the `regorus` interpreter. The
//! whole translation is a load-time step: `from_source`/`reload` compile the
//! policy and generate + parse the Rego module; `evaluate` only feeds the
//! call context as the Rego `input` document and reads
//! `data.provio.decision`, the index of the first matching rule (source
//! order) or `"default"`.
//!
//! # Mapping (provio IR → Rego)
//!
//! - `when` expression trees become matcher rules `w0..wN`: `and` is body
//!   sequencing, `or` is additional bodies of the same matcher, `not X`
//!   becomes `not cN` over a generated helper rule holding X's disjunction.
//! - `==`/`!=` map to the same operators; `startswith`/`endswith`/`contains`
//!   map to the identically-named Rego builtins.
//! - `matches` maps to `regex.match`, which regorus implements with the same
//!   Rust `regex` crate the native engine compiles patterns with (unanchored
//!   `is_match`) — no hybrid pre-evaluation needed.
//! - `in hosts.allowed` becomes one body per list entry; `*.host.tld`
//!   wildcard entries expand to `lower(...) == host` / `endswith(lower(...),
//!   ".host")`, the native dot-boundary wildcard matcher.
//! - Absent context fields are omitted from the `input` object, so their
//!   references are undefined and every predicate over them fails — the
//!   native "absent field never matches" rule, including under `not`.
//!
//! The verdict itself is constructed in Rust from the matched rule index
//! with the same logic as the native engine, so Deny/Ask carry rule_id,
//! human reason and `provio.yaml:LINE` byte-identically (spec §12).
//!
//! # Documented deltas (fail-closed, never silent)
//!
//! - regorus caps compiled-regex size at 100 KiB where the `regex` crate's
//!   own default is 10 MiB. A pattern beyond that cap is a hard evaluation
//!   error; this engine returns a fail-closed Deny instead of silently not
//!   matching (see the pinned test).
//! - Rego's `lower()` is Unicode-aware; the native wildcard matcher
//!   lowercases ASCII only. Observable only for non-ASCII list entries.
//! - Any evaluation failure (builtin error, poisoned engine lock) yields a
//!   fail-closed Deny. Engines never panic and never invent an Allow.
//!
//! Parity with the native engine is enforced by the fixture test: every
//! case in `crates/provio-policy/fixtures/` must produce the identical
//! `Verdict` (kind, rule_id, reason, location) from both engines
//! (INTERFACES.md Contract 2).

#![forbid(unsafe_code)]

mod codegen;

use std::sync::{Arc, Mutex};

use provio_core::call::{InterceptMode, ToolCallContext};
use provio_core::error::{ProvioError, Result};
use provio_core::policy::{PolicyEngine, PolicyMeta};
use provio_core::verdict::Verdict;
use provio_policy::policy_file::{compile, CompiledPolicy};

use provio_policy::{default_verdict, verdict_for};

use crate::codegen::generate_module;

/// The rule the engine reads the decision from.
const DECISION_RULE: &str = "data.provio.decision";

/// The Rego engine (`name() == "rego"`).
#[derive(Debug, Clone)]
pub struct RegoPolicyEngine {
    policy: CompiledPolicy,
    /// regorus parses the generated module into its AST at
    /// `from_source`/`reload` time; `evaluate` only sets input and
    /// evaluates the decision rule. Guarded by a mutex because regorus's
    /// evaluation methods take `&mut self`; the `Arc` keeps the engine
    /// cloneable like the native engine.
    engine: Arc<Mutex<regorus::Engine>>,
}

impl RegoPolicyEngine {
    /// Compile a policy from provio.yaml source. Errors carry `provio.yaml:LINE`
    /// detail exactly like the native engine (spec §7/§12).
    pub fn from_source(source: &str) -> Result<Self> {
        let (policy, engine) = build(source)?;
        Ok(RegoPolicyEngine {
            policy,
            engine: Arc::new(Mutex::new(engine)),
        })
    }

    /// The policy file's declared version and default verdict (for the CLI
    /// banner and `--yolo` override).
    pub fn meta(&self) -> PolicyMeta {
        PolicyMeta {
            version: self.policy.version,
            default: self.policy.default,
        }
    }

    /// The verdict for a decision the Rego module produced. `decision` is
    /// the matched rule's index as a string, or `"default"`.
    fn verdict_for_decision(&self, decision: &str, ctx: &ToolCallContext) -> Verdict {
        if decision == "default" {
            return default_verdict(self.policy.default);
        }
        match decision.parse::<usize>() {
            Ok(i) => match self.policy.rules.get(i) {
                Some(rule) => verdict_for(rule, ctx),
                None => self.fail_closed(&format!(
                    "decision references rule index {} but the policy has {} rules",
                    i,
                    self.policy.rules.len()
                )),
            },
            Err(_) => self.fail_closed(&format!("decision {:?} is not a rule index", decision)),
        }
    }

    /// Fail-closed Deny for anything evaluation could not decide (builtin
    /// error, corrupted state). Spec §7: engines fail closed, never open.
    fn fail_closed(&self, why: &str) -> Verdict {
        Verdict::Deny {
            rule_id: "engine-rego-fail-closed".to_string(),
            reason: format!(
                "The Rego engine could not evaluate this call ({}); the call is denied (fail closed).",
                why
            ),
            location: None,
        }
    }
}

/// Compile the policy and the regorus engine from one source. Pure: nothing
/// is swapped on `Err` — callers implement atomic reload by only assigning
/// on `Ok`.
fn build(source: &str) -> Result<(CompiledPolicy, regorus::Engine)> {
    let policy = compile(source).map_err(ProvioError::Policy)?;
    let module = generate_module(&policy);

    let mut engine = regorus::Engine::new();
    // Strict builtin errors: a failing builtin (e.g. a regex beyond
    // regorus's compiled-size cap) surfaces as an evaluation error and
    // fails closed below, instead of silently making the rule not match.
    engine.set_strict_builtin_errors(true);
    engine
        .add_policy("provio-policy-rego/generated.rego".to_string(), module)
        .map_err(|e| {
            ProvioError::Policy(format!("generated Rego module failed to compile: {}", e))
        })?;
    Ok((policy, engine))
}

/// The call context as the Rego `input` document. Absent optional fields
/// are omitted (not null): an undefined reference fails every predicate,
/// which is exactly the native engine's "absent field never matches" rule.
fn input_value(ctx: &ToolCallContext) -> regorus::Value {
    let mut map = serde_json::Map::new();
    map.insert(
        "tool".to_string(),
        serde_json::Value::String(ctx.tool.clone()),
    );
    for (key, value) in [
        ("command", &ctx.command),
        ("path", &ctx.path),
        ("url_host", &ctx.url_host),
        ("query", &ctx.query),
        ("server", &ctx.server),
        ("trust", &ctx.trust),
    ] {
        if let Some(v) = value {
            map.insert(key.to_string(), serde_json::Value::String(v.clone()));
        }
    }
    map.insert(
        "mode".to_string(),
        serde_json::Value::String(mode_str(ctx.mode).to_string()),
    );
    map.insert(
        "agent".to_string(),
        serde_json::Value::String(ctx.agent.clone()),
    );
    regorus::Value::from(serde_json::Value::Object(map))
}

fn mode_str(mode: InterceptMode) -> &'static str {
    match mode {
        InterceptMode::Mcp => "mcp",
        InterceptMode::ProcessWrap => "processwrap",
        InterceptMode::SdkHook => "sdkhook",
    }
}

impl PolicyEngine for RegoPolicyEngine {
    fn name(&self) -> &'static str {
        "rego"
    }

    fn evaluate(&self, ctx: &ToolCallContext) -> Verdict {
        let mut engine = match self.engine.lock() {
            Ok(guard) => guard,
            // A poisoned lock means a panic happened mid-evaluation; the
            // engine state is not trustworthy. Fail closed, never panic.
            Err(_) => return self.fail_closed("engine lock poisoned"),
        };
        engine.set_input(input_value(ctx));
        match engine.eval_rule(DECISION_RULE.to_string()) {
            Ok(regorus::Value::String(s)) => self.verdict_for_decision(&s, ctx),
            Ok(_) => self.fail_closed("decision rule returned a non-string value"),
            Err(e) => self.fail_closed(&format!("evaluation failed: {}", e)),
        }
    }

    /// Atomic hot-reload (spec §7): the new source is fully compiled and the
    /// Rego module fully generated and parsed first; on any error the
    /// last-good policy keeps serving. The engine is swapped as one object,
    /// which also heals a poisoned lock.
    fn reload(&mut self, source: &str) -> Result<()> {
        let (policy, engine) = build(source)?;
        self.policy = policy;
        self.engine = Arc::new(Mutex::new(engine));
        Ok(())
    }

    fn rule_count(&self) -> usize {
        self.policy.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use provio_core::verdict::DefaultVerdict;
    use provio_policy::fixtures::{load_fixtures_dir, Fixture};
    use provio_policy::NativePolicyEngine;

    const FIXTURES_DIR: &str = "../provio-policy/fixtures";
    const EXAMPLES_POLICY: &str = "../../examples/provio.yaml";

    fn fixture_path(rel: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
    }

    /// Contract 2: same fixtures, same verdicts as native — full Verdict
    /// equality (kind, rule_id, reason/diff, location), not just the kind.
    #[test]
    fn fixture_corpus_matches_native() {
        let shared_source =
            std::fs::read_to_string(fixture_path(EXAMPLES_POLICY)).expect("examples/provio.yaml");
        let fixtures: Vec<Fixture> =
            load_fixtures_dir(&fixture_path(FIXTURES_DIR)).expect("fixture corpus");
        assert!(
            fixtures.len() >= 6,
            "expected the shared corpus, got {} fixtures",
            fixtures.len()
        );

        let native_shared = NativePolicyEngine::from_source(&shared_source).unwrap();
        let rego_shared = RegoPolicyEngine::from_source(&shared_source).unwrap();

        for fx in &fixtures {
            let native = match &fx.policy {
                Some(src) => NativePolicyEngine::from_source(src)
                    .unwrap_or_else(|e| panic!("fixture {} policy: {}", fx.name, e)),
                None => native_shared.clone(),
            };
            let rego = match &fx.policy {
                Some(src) => RegoPolicyEngine::from_source(src)
                    .unwrap_or_else(|e| panic!("fixture {} policy: {}", fx.name, e)),
                None => rego_shared.clone(),
            };
            let ctx = fx
                .ctx
                .to_context()
                .unwrap_or_else(|e| panic!("fixture {} ctx: {}", fx.name, e));
            let native_verdict = native.evaluate(&ctx);
            let rego_verdict = rego.evaluate(&ctx);
            assert_eq!(
                rego_verdict, native_verdict,
                "fixture {:?}: rego verdict must equal native verdict",
                fx.name
            );
        }
    }

    /// Every operator, absent fields, unknown fields and wildcard lists
    /// agree with the native engine on a hand-built policy.
    #[test]
    fn hand_policy_matches_native() {
        let source = r#"version: 1
default: ask
rules:
  - id: eq-bash
    when: tool == "bash"
    verdict: deny
  - id: ne-anything
    when: not tool == "bash" and command != "safe"
    verdict: ask
    reason: "check it"
  - id: prefix-suffix
    when: tool startswith "post" and query endswith ";"
    verdict: ask
  - id: contains-secret
    when: command contains "token" or path contains ".pem"
    verdict: deny
  - id: egress
    when: tool == "http" and not url.host in hosts.allowed
    verdict: deny
  - id: mode-sdkhook
    when: mode == "sdkhook" and agent == "claude-code"
    verdict: allow
  - id: unknown-field
    when: nosuchfield == "x"
    verdict: deny
  - id: redact-crm
    when: tool matches "^crm\\."
    verdict: redact
    patterns: ["sSN\\d+"]
hosts:
  allowed: [api.github.com, "*.internal.acme.com"]
"#;

        let contexts = vec![
            (
                "eq-bash",
                ToolCallContext {
                    tool: "bash".to_string(),
                    command: Some("ls".to_string()),
                    path: None,
                    url_host: None,
                    query: None,
                    server: None,
                    trust: None,
                    mode: InterceptMode::Mcp,
                    agent: "claude-code".to_string(),
                },
            ),
            // `!=` over an absent field never matches; falls through to default.
            (
                "default",
                ToolCallContext {
                    tool: "other".to_string(),
                    command: None,
                    path: None,
                    url_host: None,
                    query: None,
                    server: None,
                    trust: None,
                    mode: InterceptMode::ProcessWrap,
                    agent: "other-agent".to_string(),
                },
            ),
            (
                "ne-anything",
                ToolCallContext {
                    tool: "other".to_string(),
                    command: Some("risky".to_string()),
                    path: None,
                    url_host: None,
                    query: None,
                    server: None,
                    trust: None,
                    mode: InterceptMode::Mcp,
                    agent: "x".to_string(),
                },
            ),
            (
                "prefix-suffix",
                ToolCallContext {
                    tool: "postgres.query".to_string(),
                    command: None,
                    path: None,
                    url_host: None,
                    query: Some("SELECT 1;".to_string()),
                    server: None,
                    trust: None,
                    mode: InterceptMode::Mcp,
                    agent: "x".to_string(),
                },
            ),
            // First match wins: `ne-anything` precedes `contains-secret` and
            // matches too (tool != "bash", command != "safe").
            (
                "ne-anything",
                ToolCallContext {
                    tool: "fs.read".to_string(),
                    command: Some("read token".to_string()),
                    path: Some("/etc/server.pem".to_string()),
                    url_host: None,
                    query: None,
                    server: None,
                    trust: None,
                    mode: InterceptMode::Mcp,
                    agent: "x".to_string(),
                },
            ),
            // Wildcard list entry on a dot boundary; case-insensitive.
            (
                "default",
                ToolCallContext {
                    tool: "http".to_string(),
                    command: None,
                    path: None,
                    url_host: Some("API.Internal.Acme.COM".to_string()),
                    query: None,
                    server: None,
                    trust: None,
                    mode: InterceptMode::Mcp,
                    agent: "x".to_string(),
                },
            ),
            (
                "egress",
                ToolCallContext {
                    tool: "http".to_string(),
                    command: None,
                    path: None,
                    url_host: Some("evilinternal.acme.com".to_string()),
                    query: None,
                    server: None,
                    trust: None,
                    mode: InterceptMode::Mcp,
                    agent: "x".to_string(),
                },
            ),
            // Absent url_host under `not`: native treats the predicate as
            // non-matching, so `not` matches. Rego must agree.
            (
                "egress",
                ToolCallContext {
                    tool: "http".to_string(),
                    command: None,
                    path: None,
                    url_host: None,
                    query: None,
                    server: None,
                    trust: None,
                    mode: InterceptMode::Mcp,
                    agent: "x".to_string(),
                },
            ),
            (
                "mode-sdkhook",
                ToolCallContext {
                    tool: "fs.write".to_string(),
                    command: None,
                    path: None,
                    url_host: None,
                    query: None,
                    server: None,
                    trust: None,
                    mode: InterceptMode::SdkHook,
                    agent: "claude-code".to_string(),
                },
            ),
            // Unknown DSL fields never match (native: Field::Unknown -> None
            // -> false for every operator); the call falls to the default.
            (
                "default",
                ToolCallContext {
                    tool: "anything".to_string(),
                    command: None,
                    path: None,
                    url_host: None,
                    query: None,
                    server: None,
                    trust: None,
                    mode: InterceptMode::Mcp,
                    agent: "x".to_string(),
                },
            ),
            (
                "redact-crm",
                ToolCallContext {
                    tool: "crm.contacts".to_string(),
                    command: None,
                    path: None,
                    url_host: None,
                    query: None,
                    server: None,
                    trust: None,
                    mode: InterceptMode::Mcp,
                    agent: "x".to_string(),
                },
            ),
        ];

        let native = NativePolicyEngine::from_source(source).unwrap();
        let rego = RegoPolicyEngine::from_source(source).unwrap();
        for (expected_rule, ctx) in &contexts {
            let nv = native.evaluate(ctx);
            let rv = rego.evaluate(ctx);
            assert_eq!(rv, nv, "context expecting rule {:?}", expected_rule);
            assert_eq!(rv.rule_id(), Some(*expected_rule), "context {:?}", ctx.tool);
        }
    }

    /// Reload failure keeps the last-good policy serving (spec §7).
    #[test]
    fn reload_failure_keeps_last_good() {
        let good = r#"version: 1
default: ask
rules:
  - id: deny-bash
    when: tool == "bash"
    verdict: deny
"#;
        let ctx = ToolCallContext {
            tool: "bash".to_string(),
            command: None,
            path: None,
            url_host: None,
            query: None,
            server: None,
            trust: None,
            mode: InterceptMode::Mcp,
            agent: "x".to_string(),
        };

        let mut engine = RegoPolicyEngine::from_source(good).unwrap();
        assert_eq!(engine.evaluate(&ctx).rule_id(), Some("deny-bash"));
        assert_eq!(engine.rule_count(), 1);

        // Broken source: unknown verdict keyword with line detail.
        let broken = r#"version: 1
default: ask
rules:
  - id: oops
    when: tool == "bash"
    verdict: maybe
"#;
        let err = engine.reload(broken).unwrap_err().to_string();
        // `provio.yaml:4` is the `- id: oops` line of the broken rule.
        assert!(
            err.contains("provio.yaml:4"),
            "error should carry line: {}",
            err
        );
        // Last-good still serves, unchanged.
        assert_eq!(engine.evaluate(&ctx).rule_id(), Some("deny-bash"));
        assert_eq!(engine.rule_count(), 1);

        // Parse-level breakage too (not just semantic validation).
        let unparsable = r#"version: 1
default:
  - not: a scalar
"#;
        assert!(engine.reload(unparsable).is_err());
        assert_eq!(engine.evaluate(&ctx).rule_id(), Some("deny-bash"));

        // A good reload swaps atomically.
        let v2 = r#"version: 1
default: ask
rules:
  - id: ask-bash
    when: tool == "bash"
    verdict: ask
    reason: "approved path"
"#;
        engine.reload(v2).unwrap();
        let verdict = engine.evaluate(&ctx);
        assert_eq!(verdict.rule_id(), Some("ask-bash"));
        assert_eq!(engine.rule_count(), 1);
    }

    /// `from_source` errors carry `provio.yaml:LINE` detail like native.
    #[test]
    fn from_source_error_carries_line() {
        let bad = r#"version: 1
default: ask
rules:
  - id: no-patterns
    when: tool == "http"
    verdict: redact
"#;
        let native_err = NativePolicyEngine::from_source(bad)
            .unwrap_err()
            .to_string();
        let rego_err = RegoPolicyEngine::from_source(bad).unwrap_err().to_string();
        // `provio.yaml:4` is the `- id: no-patterns` line of the broken rule.
        assert!(native_err.contains("provio.yaml:4"), "{}", native_err);
        assert_eq!(native_err, rego_err, "both engines surface the same error");
    }

    /// Documented delta: regorus caps compiled-regex size at 100 KiB where
    /// the native engine's limit is the regex crate default (10 MiB). A
    /// pattern that fits native's limit but not regorus's is a hard
    /// evaluation error; this engine returns a fail-closed Deny instead of
    /// silently not matching (pinned here so an upstream change is caught,
    /// not silent).
    #[test]
    fn regex_beyond_regorus_cap_fails_closed() {
        let source = r#"version: 1
default: ask
rules:
  - id: huge-regex
    when: command matches "(ab|cd){5000}"
    verdict: allow
"#;
        let ctx = ToolCallContext {
            tool: "x".to_string(),
            command: Some("ab".repeat(5000)),
            path: None,
            url_host: None,
            query: None,
            server: None,
            trust: None,
            mode: InterceptMode::Mcp,
            agent: "x".to_string(),
        };
        let native = NativePolicyEngine::from_source(source).unwrap();
        let rego = RegoPolicyEngine::from_source(source).unwrap();
        assert_eq!(
            native.evaluate(&ctx).rule_id(),
            Some("huge-regex"),
            "native compiles and matches the big regex"
        );
        match rego.evaluate(&ctx) {
            Verdict::Deny { rule_id, .. } => {
                assert_eq!(rule_id, "engine-rego-fail-closed");
            }
            other => panic!("expected fail-closed deny, got {:?}", other),
        }
    }

    /// The engine name and meta mirror the policy.
    #[test]
    fn name_and_meta() {
        let engine = RegoPolicyEngine::from_source("version: 1\ndefault: deny\n").unwrap();
        assert_eq!(engine.name(), "rego");
        assert_eq!(engine.rule_count(), 0);
        assert_eq!(engine.meta().default, DefaultVerdict::Deny);
        assert_eq!(engine.meta().version, 1);
    }
}
