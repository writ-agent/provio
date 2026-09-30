//! provio-policy-cedar — the Cedar engine backend (Contract 2, spec §7).
//!
//! Translates the native provio.yaml IR (`provio_policy::policy_file::CompiledPolicy`)
//! into a Cedar policy set and evaluates it with the `cedar-policy`
//! authorizer. The translation is a load-time step: `from_source`/`reload`
//! compile the policy, generate one Cedar `permit` policy per provio rule and
//! parse them; `evaluate` only builds the request context from the call and
//! runs the authorizer.
//!
//! # Mapping (provio IR → Cedar)
//!
//! - Rule `i` becomes the Cedar policy `r<i>`:
//!   `permit(principal, action, resource) when { <when> };`. The policy is
//!   satisfied exactly when the rule's `when` matches. The authorizer's
//!   response `reason` lists every satisfied permit; the host takes the
//!   **lowest** rule index — the native first-match-wins order. No match
//!   means the policy default. Cedar's own Allow/Deny decision is not the
//!   verdict; it is only cross-checked for consistency.
//! - `and`/`or`/`not` map to `&&`/`||`/`!`; `==`/`!=` map directly;
//!   `startswith`/`endswith`/`contains` map to `like` globs with `*`
//!   escaped in the operand.
//! - **`matches` is evaluated host-side.** Cedar has no regex (only `like`
//!   globs), so each `matches` predicate is assigned a slot and compiles to
//!   the context boolean `context.re.m<k>`. Before every authorization the
//!   host computes each slot with the same compiled `regex::Regex` the
//!   native engine uses (unanchored `is_match`; `false` for an absent
//!   field). The boolean structure around it — including `not` and rule
//!   ordering — stays in Cedar.
//! - **`*.host` wildcard list entries use a host-lowercased value.** Cedar
//!   has no `lower()`, so the context carries `context.lc.<field>`, the
//!   ASCII-lowercased value (exactly the native wildcard matcher's
//!   lowercasing), compared as `== "base" || like "*.base"`.
//! - Optional context fields are only present in the context record when
//!   set, and every predicate over one is guarded by `context has <f>`: an
//!   absent field never matches (also under `not`), as natively. Unknown DSL
//!   fields and empty lists compile to `false`.
//!
//! The verdict itself is constructed in Rust from the matched rule index
//! with the same logic as the native engine, so Deny/Ask carry rule_id,
//! human reason and `provio.yaml:LINE` byte-identically (spec §12).
//!
//! # Documented deltas (fail-closed, never silent)
//!
//! - No verdict deltas on well-formed input: the parity tests below pin
//!   full `Verdict` equality with the native engine.
//! - Cedar evaluates every policy per request (no short-circuit across
//!   rules), and every regex slot is computed per call. This costs time,
//!   not semantics: first-match order is recovered from the policy ids.
//! - Any authorization error (a policy that failed to evaluate), an
//!   unexpected policy id in the response, or a Cedar decision inconsistent
//!   with the satisfied set yields a fail-closed Deny with rule id
//!   `engine-cedar-fail-closed`. Errors are never treated as "rule did not
//!   match". Engines never panic and never invent an Allow.
//!
//! Parity with the native engine is enforced by the fixture test: every
//! case in `crates/provio-policy/fixtures/` must produce the identical
//! `Verdict` (kind, rule_id, reason, location) from both engines
//! (INTERFACES.md Contract 2).

#![forbid(unsafe_code)]

mod codegen;

use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, Policy, PolicyId, PolicySet, Request,
    RestrictedExpression,
};
use provio_core::call::{InterceptMode, ToolCallContext};
use provio_core::error::{ProvioError, Result};
use provio_core::policy::{PolicyEngine, PolicyMeta};
use provio_core::verdict::Verdict;
use provio_policy::ast::Field;
use provio_policy::policy_file::{compile, CompiledPolicy};

use provio_policy::{default_verdict, verdict_for};

use crate::codegen::{field_name, generate, policy_id, rule_index, RegexSlot};

/// Rule id of every fail-closed Deny this engine produces.
const FAIL_CLOSED_RULE_ID: &str = "engine-cedar-fail-closed";

/// The Cedar engine (`name() == "cedar"`).
#[derive(Debug, Clone)]
pub struct CedarPolicyEngine {
    policy: CompiledPolicy,
    compiled: CedarCompiled,
}

/// Everything built at load time for Cedar evaluation.
#[derive(Debug, Clone)]
struct CedarCompiled {
    policies: PolicySet,
    regex_slots: Vec<RegexSlot>,
    principal: EntityUid,
    action: EntityUid,
    resource: EntityUid,
}

impl CedarPolicyEngine {
    /// Compile a policy from provio.yaml source. Errors carry `provio.yaml:LINE`
    /// detail exactly like the native engine (spec §7/§12).
    pub fn from_source(source: &str) -> Result<Self> {
        let (policy, compiled) = build(source)?;
        Ok(CedarPolicyEngine { policy, compiled })
    }

    /// The policy file's declared version and default verdict (for the CLI
    /// banner and `--yolo` override).
    pub fn meta(&self) -> PolicyMeta {
        PolicyMeta {
            version: self.policy.version,
            default: self.policy.default,
        }
    }

    /// Run the Cedar authorizer over a prepared context and turn the
    /// response into a verdict. Split from `evaluate` so fail-closed paths
    /// can be exercised with a deliberately malformed context.
    fn decide(&self, context: Context, ctx: &ToolCallContext) -> Verdict {
        let c = &self.compiled;
        let request = match Request::new(
            c.principal.clone(),
            c.action.clone(),
            c.resource.clone(),
            context,
            None,
        ) {
            Ok(r) => r,
            Err(e) => return fail_closed(&format!("request construction failed: {}", e)),
        };
        let response = Authorizer::new().is_authorized(&request, &c.policies, &Entities::empty());

        // Strict: any policy evaluation error fails closed. Cedar itself
        // would skip an erroring policy (treat it as not satisfied), which
        // could let a later, more permissive rule win — never acceptable.
        if let Some(err) = response.diagnostics().errors().next() {
            return fail_closed(&format!("policy evaluation failed: {}", err));
        }

        let mut first: Option<usize> = None;
        for id in response.diagnostics().reason() {
            match rule_index(id.as_ref()) {
                Some(i) if i < self.policy.rules.len() => {
                    first = Some(first.map_or(i, |f| f.min(i)));
                }
                _ => {
                    return fail_closed(&format!(
                        "response references unknown policy {:?}",
                        id.as_ref() as &str
                    ))
                }
            }
        }

        // Cross-check: all policies are permits, so Cedar allows iff at
        // least one rule matched.
        let consistent = match response.decision() {
            Decision::Allow => first.is_some(),
            Decision::Deny => first.is_none(),
        };
        if !consistent {
            return fail_closed("Cedar decision is inconsistent with the satisfied rule set");
        }

        match first {
            Some(i) => verdict_for(&self.policy.rules[i], ctx),
            None => default_verdict(self.policy.default),
        }
    }
}

/// Fail-closed Deny for anything evaluation could not decide. Spec §7:
/// engines fail closed, never open.
fn fail_closed(why: &str) -> Verdict {
    Verdict::Deny {
        rule_id: FAIL_CLOSED_RULE_ID.to_string(),
        reason: format!(
            "The Cedar engine could not evaluate this call ({}); the call is denied (fail closed).",
            why
        ),
        location: None,
    }
}

/// Compile the policy and the Cedar policy set from one source. Pure:
/// nothing is swapped on `Err` — callers implement atomic reload by only
/// assigning on `Ok`.
fn build(source: &str) -> Result<(CompiledPolicy, CedarCompiled)> {
    let policy = compile(source).map_err(ProvioError::Policy)?;
    let generated = generate(&policy);

    let mut policies = PolicySet::new();
    for (i, text) in generated.policies.iter().enumerate() {
        let parsed = Policy::parse(Some(PolicyId::new(policy_id(i))), text).map_err(|e| {
            ProvioError::Policy(format!(
                "generated Cedar policy for rule `{}` failed to parse: {}",
                policy.rules[i].id, e
            ))
        })?;
        policies.add(parsed).map_err(|e| {
            ProvioError::Policy(format!("generated Cedar policy set is invalid: {}", e))
        })?;
    }

    let uid = |s: &str| {
        EntityUid::from_str(s)
            .map_err(|e| ProvioError::Policy(format!("Cedar entity uid {}: {}", s, e)))
    };
    let compiled = CedarCompiled {
        policies,
        regex_slots: generated.regex_slots,
        principal: uid(r#"Provio::Agent::"agent""#)?,
        action: uid(r#"Provio::Action::"call""#)?,
        resource: uid(r#"Provio::Tool::"tool""#)?,
    };
    Ok((policy, compiled))
}

/// The value of a DSL field in the call, `None` when absent or unknown
/// (mirror of the native `field_value`).
fn field_value(field: Field, ctx: &ToolCallContext) -> Option<&str> {
    match field {
        Field::Tool => Some(&ctx.tool),
        Field::Command => ctx.command.as_deref(),
        Field::Path => ctx.path.as_deref(),
        Field::UrlHost => ctx.url_host.as_deref(),
        Field::Query => ctx.query.as_deref(),
        Field::Agent => Some(&ctx.agent),
        Field::Mode => Some(mode_str(ctx.mode)),
        Field::Server => ctx.server.as_deref(),
        Field::Trust => ctx.trust.as_deref(),
        Field::Unknown => None,
    }
}

fn mode_str(mode: InterceptMode) -> &'static str {
    match mode {
        InterceptMode::Mcp => "mcp",
        InterceptMode::ProcessWrap => "processwrap",
        InterceptMode::SdkHook => "sdkhook",
    }
}

const CONTEXT_FIELDS: [Field; 9] = [
    Field::Tool,
    Field::Command,
    Field::Path,
    Field::UrlHost,
    Field::Query,
    Field::Agent,
    Field::Mode,
    Field::Server,
    Field::Trust,
];

/// The Cedar request context for a call:
///
/// - one string attribute per present field (absent ones omitted, so
///   `context has <f>` is false);
/// - `lc`: a record of the same present fields, ASCII-lowercased (for
///   wildcard list entries);
/// - `re`: a record of the host-evaluated regex slots `m0..mN`.
fn context_for(
    compiled: &CedarCompiled,
    ctx: &ToolCallContext,
) -> std::result::Result<Context, String> {
    let mut pairs: Vec<(String, RestrictedExpression)> = Vec::new();
    let mut lowered: Vec<(String, RestrictedExpression)> = Vec::new();
    for field in CONTEXT_FIELDS {
        let (Some(name), Some(value)) = (field_name(field), field_value(field, ctx)) else {
            continue;
        };
        pairs.push((
            name.to_string(),
            RestrictedExpression::new_string(value.to_string()),
        ));
        lowered.push((
            name.to_string(),
            RestrictedExpression::new_string(value.to_ascii_lowercase()),
        ));
    }
    let slots = compiled.regex_slots.iter().enumerate().map(|(k, slot)| {
        let hit = field_value(slot.field, ctx).is_some_and(|v| slot.regex.is_match(v));
        (format!("m{}", k), RestrictedExpression::new_bool(hit))
    });
    let re = RestrictedExpression::new_record(slots).map_err(|e| e.to_string())?;
    let lc = RestrictedExpression::new_record(lowered).map_err(|e| e.to_string())?;
    pairs.push(("lc".to_string(), lc));
    pairs.push(("re".to_string(), re));
    Context::from_pairs(pairs).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Verdict construction (parity with the native engine)
// ---------------------------------------------------------------------------

impl PolicyEngine for CedarPolicyEngine {
    fn name(&self) -> &'static str {
        "cedar"
    }

    fn evaluate(&self, ctx: &ToolCallContext) -> Verdict {
        match context_for(&self.compiled, ctx) {
            Ok(context) => self.decide(context, ctx),
            Err(e) => fail_closed(&format!("context construction failed: {}", e)),
        }
    }

    /// Atomic hot-reload (spec §7): the new source is fully compiled and
    /// the Cedar policy set fully generated and parsed first; on any error
    /// the last-good policy keeps serving.
    fn reload(&mut self, source: &str) -> Result<()> {
        let (policy, compiled) = build(source)?;
        self.policy = policy;
        self.compiled = compiled;
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

    fn call(tool: &str) -> ToolCallContext {
        ToolCallContext {
            tool: tool.to_string(),
            command: None,
            path: None,
            url_host: None,
            query: None,
            server: None,
            trust: None,
            mode: InterceptMode::Mcp,
            agent: "x".to_string(),
        }
    }

    fn assert_fail_closed(v: Verdict) {
        match v {
            Verdict::Deny {
                rule_id,
                reason,
                location,
            } => {
                assert_eq!(rule_id, FAIL_CLOSED_RULE_ID);
                assert!(reason.contains("fail closed"), "{}", reason);
                assert_eq!(location, None);
            }
            other => panic!("expected fail-closed deny, got {:?}", other),
        }
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
        let cedar_shared = CedarPolicyEngine::from_source(&shared_source).unwrap();

        for fx in &fixtures {
            let native = match &fx.policy {
                Some(src) => NativePolicyEngine::from_source(src)
                    .unwrap_or_else(|e| panic!("fixture {} policy: {}", fx.name, e)),
                None => native_shared.clone(),
            };
            let cedar = match &fx.policy {
                Some(src) => CedarPolicyEngine::from_source(src)
                    .unwrap_or_else(|e| panic!("fixture {} policy: {}", fx.name, e)),
                None => cedar_shared.clone(),
            };
            let ctx = fx
                .ctx
                .to_context()
                .unwrap_or_else(|e| panic!("fixture {} ctx: {}", fx.name, e));
            assert_eq!(
                cedar.evaluate(&ctx),
                native.evaluate(&ctx),
                "fixture {:?}: cedar verdict must equal native verdict",
                fx.name
            );
        }
    }

    /// Every operator, absent fields, unknown fields, wildcard lists, `like`
    /// metacharacters and escaping agree with the native engine.
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
  - id: star-literal
    when: path contains "*" or path startswith "a\"b\\c"
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
  - id: not-regex
    when: tool == "fs.write" and not path matches "^/tmp/"
    verdict: ask
  - id: redact-crm
    when: tool matches "^crm\\."
    verdict: redact
    patterns: ["sSN\\d+"]
hosts:
  allowed: [api.github.com, "*.internal.acme.com"]
"#;

        let with = |tool: &str, f: &dyn Fn(&mut ToolCallContext)| {
            let mut c = call(tool);
            f(&mut c);
            c
        };
        let contexts: Vec<(&str, ToolCallContext)> = vec![
            ("eq-bash", with("bash", &|c| c.command = Some("ls".into()))),
            // `!=` over an absent field never matches; falls through.
            (
                "default",
                with("other", &|c| {
                    c.mode = InterceptMode::ProcessWrap;
                    c.agent = "other-agent".into();
                }),
            ),
            (
                "ne-anything",
                with("other", &|c| c.command = Some("risky".into())),
            ),
            (
                "prefix-suffix",
                with("postgres.query", &|c| c.query = Some("SELECT 1;".into())),
            ),
            // `*` in a `like` operand is literal, not a wildcard.
            ("default", with("x", &|c| c.path = Some("/a/b".into()))),
            ("star-literal", with("x", &|c| c.path = Some("/a/*".into()))),
            (
                "star-literal",
                with("x", &|c| c.path = Some("a\"b\\c/d".into())),
            ),
            // First match wins: `ne-anything` precedes `contains-secret`.
            (
                "ne-anything",
                with("fs.read", &|c| {
                    c.command = Some("read token".into());
                    c.path = Some("/etc/server.pem".into());
                }),
            ),
            (
                "contains-secret",
                with("fs.read", &|c| c.path = Some("/etc/server.pem".into())),
            ),
            // Wildcard list entry on a dot boundary; case-insensitive.
            (
                "default",
                with("http", &|c| {
                    c.url_host = Some("API.Internal.Acme.COM".into())
                }),
            ),
            (
                "default",
                with("http", &|c| c.url_host = Some("internal.acme.com".into())),
            ),
            (
                "default",
                with("http", &|c| c.url_host = Some("api.github.com".into())),
            ),
            // Plain entries are exact (case-sensitive).
            (
                "egress",
                with("http", &|c| c.url_host = Some("API.github.com".into())),
            ),
            (
                "egress",
                with("http", &|c| {
                    c.url_host = Some("evilinternal.acme.com".into())
                }),
            ),
            // Absent url_host under `not`: the predicate is false, so `not`
            // matches — natively and in Cedar.
            ("egress", call("http")),
            (
                "mode-sdkhook",
                with("fs.write", &|c| {
                    c.mode = InterceptMode::SdkHook;
                    c.agent = "claude-code".into();
                }),
            ),
            // Unknown DSL fields never match.
            ("default", call("anything")),
            // Host-evaluated regex under `not`, absent and present.
            ("not-regex", call("fs.write")),
            (
                "not-regex",
                with("fs.write", &|c| c.path = Some("/etc/x".into())),
            ),
            (
                "default",
                with("fs.write", &|c| c.path = Some("/tmp/x".into())),
            ),
            ("redact-crm", call("crm.contacts")),
            ("default", call("xcrm.contacts")),
        ];

        let native = NativePolicyEngine::from_source(source).unwrap();
        let cedar = CedarPolicyEngine::from_source(source).unwrap();
        for (expected_rule, ctx) in &contexts {
            let nv = native.evaluate(ctx);
            let cv = cedar.evaluate(ctx);
            assert_eq!(
                cv, nv,
                "context expecting rule {:?}: {:?}",
                expected_rule, ctx
            );
            assert_eq!(cv.rule_id(), Some(*expected_rule), "context {:?}", ctx);
        }
    }

    /// Verdict details (Ask fallback diff, Deny fallback reason, location,
    /// timeout, irreversible) and all three defaults match native.
    #[test]
    fn verdict_details_and_defaults_match_native() {
        for default in ["allow", "ask", "deny"] {
            let source = format!(
                r#"version: 1
default: {}
rules:
  - id: ask-no-reason
    when: tool == "a"
    verdict: ask
    irreversible: true
    timeout: 30s
  - id: deny-no-reason
    when: tool == "d"
    verdict: deny
"#,
                default
            );
            let native = NativePolicyEngine::from_source(&source).unwrap();
            let cedar = CedarPolicyEngine::from_source(&source).unwrap();
            let mut a = call("a");
            a.command = Some("c".into());
            a.path = Some("p".into());
            a.query = Some("q".into());
            a.url_host = Some("h".into());
            for ctx in [a, call("d"), call("none")] {
                assert_eq!(cedar.evaluate(&ctx), native.evaluate(&ctx), "{:?}", ctx);
            }
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
        let ctx = call("bash");
        let mut engine = CedarPolicyEngine::from_source(good).unwrap();
        assert_eq!(engine.evaluate(&ctx).rule_id(), Some("deny-bash"));
        assert_eq!(engine.rule_count(), 1);

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
        assert_eq!(engine.evaluate(&ctx).rule_id(), Some("deny-bash"));
        assert_eq!(engine.rule_count(), 1);

        let unparsable = "version: 1\ndefault:\n  - not: a scalar\n";
        assert!(engine.reload(unparsable).is_err());
        assert_eq!(engine.evaluate(&ctx).rule_id(), Some("deny-bash"));

        let v2 = r#"version: 1
default: ask
rules:
  - id: ask-bash
    when: tool == "bash"
    verdict: ask
    reason: "approved path"
"#;
        engine.reload(v2).unwrap();
        assert_eq!(engine.evaluate(&ctx).rule_id(), Some("ask-bash"));
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
        let cedar_err = CedarPolicyEngine::from_source(bad).unwrap_err().to_string();
        assert!(native_err.contains("provio.yaml:4"), "{}", native_err);
        assert_eq!(native_err, cedar_err, "both engines surface the same error");
    }

    /// Strictness pin: a Cedar policy evaluation error (here: the regex
    /// slot record is missing from the context) must fail closed — not be
    /// skipped as "rule did not match", which Cedar's authorizer does by
    /// default and which would let the later `allow-all` rule win.
    #[test]
    fn evaluation_error_fails_closed() {
        let source = r#"version: 1
default: allow
rules:
  - id: deny-rm
    when: command matches "rm"
    verdict: deny
  - id: allow-all
    when: tool == "bash"
    verdict: allow
"#;
        let engine = CedarPolicyEngine::from_source(source).unwrap();
        let mut ctx = call("bash");
        ctx.command = Some("rm -rf /".into());
        assert_eq!(engine.evaluate(&ctx).rule_id(), Some("deny-rm"));

        let broken = Context::from_pairs([(
            "tool".to_string(),
            RestrictedExpression::new_string("bash".to_string()),
        )])
        .unwrap();
        assert_fail_closed(engine.decide(broken, &ctx));
    }

    /// A response naming a policy the codegen did not emit fails closed.
    #[test]
    fn unknown_policy_id_fails_closed() {
        let source = "version: 1\ndefault: allow\nrules:\n  - id: a\n    when: tool == \"x\"\n    verdict: allow\n";
        let mut engine = CedarPolicyEngine::from_source(source).unwrap();
        // Inject a satisfied policy with an id outside the rule range.
        let rogue = Policy::parse(
            Some(PolicyId::new("r7")),
            "permit(principal, action, resource);",
        )
        .unwrap();
        engine.compiled.policies.add(rogue).unwrap();
        assert_fail_closed(engine.evaluate(&call("y")));
    }

    /// A foreign `forbid` (the codegen only emits permits) overrides the
    /// satisfied rule: Cedar denies and names only the forbid — fail closed,
    /// never a silent fall-through to the default.
    #[test]
    fn foreign_forbid_fails_closed() {
        let source = "version: 1\ndefault: deny\nrules:\n  - id: a\n    when: tool == \"x\"\n    verdict: allow\n";
        let mut engine = CedarPolicyEngine::from_source(source).unwrap();
        let forbid = Policy::parse(
            Some(PolicyId::new("r0-forbid")),
            "forbid(principal, action, resource);",
        )
        .unwrap();
        engine.compiled.policies.add(forbid).unwrap();
        // Rule 0 is satisfied but Cedar denies (forbid overrides permit);
        // `reason` then names only the forbid, an unknown id — fail closed.
        assert_fail_closed(engine.evaluate(&call("x")));
    }

    /// The engine name and meta mirror the policy.
    #[test]
    fn name_and_meta() {
        let engine = CedarPolicyEngine::from_source("version: 1\ndefault: deny\n").unwrap();
        assert_eq!(engine.name(), "cedar");
        assert_eq!(engine.rule_count(), 0);
        assert_eq!(engine.meta().default, DefaultVerdict::Deny);
        assert_eq!(engine.meta().version, 1);
        assert_eq!(engine.evaluate(&call("x")).rule_id(), Some("default"));
    }
}
