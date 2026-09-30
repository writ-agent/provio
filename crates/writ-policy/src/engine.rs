//! The native policy engine: implements `writ_core::PolicyEngine` over a
//! compiled writ.yaml policy.
//!
//! Semantics (spec §7): first matching rule wins; no match -> the policy's
//! `default` (fail-closed `ask` unless the operator says otherwise). Every
//! Deny/Ask carries rule_id + human reason + `writ.yaml:LINE` location.

use crate::ast::{Expr, Field, Op, Predicate};
use crate::policy_file::{compile, CompiledPolicy, CompiledRule, RuleVerdict, POLICY_FILE_NAME};
use writ_core::call::ToolCallContext;
use writ_core::error::{Result, WritError};
use writ_core::policy::{PolicyEngine, PolicyMeta};
use writ_core::verdict::{DefaultVerdict, Verdict};

/// The native writ.yaml engine (`name() == "native"`).
#[derive(Debug, Clone)]
pub struct NativePolicyEngine {
    policy: CompiledPolicy,
}

impl NativePolicyEngine {
    /// Compile a policy from source. Returns `Err` with `writ.yaml:LINE`
    /// detail on any parse/validation failure.
    pub fn from_source(source: &str) -> Result<Self> {
        Ok(NativePolicyEngine {
            policy: compile(source).map_err(WritError::Policy)?,
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
}

impl PolicyEngine for NativePolicyEngine {
    fn name(&self) -> &'static str {
        "native"
    }

    fn evaluate(&self, ctx: &ToolCallContext) -> Verdict {
        for rule in &self.policy.rules {
            if eval_expr(&rule.when, ctx) {
                return verdict_for(rule, ctx);
            }
        }
        default_verdict(self.policy.default)
    }

    /// Atomic hot-reload (spec §7): the new source is fully parsed and
    /// compiled first; on any error the last-good policy keeps serving.
    fn reload(&mut self, source: &str) -> Result<()> {
        let new_policy = compile(source).map_err(WritError::Policy)?;
        self.policy = new_policy;
        Ok(())
    }

    fn rule_count(&self) -> usize {
        self.policy.rules.len()
    }
}

/// The policy default, always carrying rule_id + human reason for Deny/Ask
/// (spec §12: never "denied by policy").
///
/// Public so sibling engine crates (Rego, Cedar) construct verdicts
/// byte-identical to the native engine (Contract 2 parity).
pub fn default_verdict(default: DefaultVerdict) -> Verdict {
    match default {
        DefaultVerdict::Allow => Verdict::Allow { rule_id: Some("default".to_string()) },
        DefaultVerdict::Ask => Verdict::Ask {
            rule_id: "default".to_string(),
            diff: "No policy rule matched this call; the policy default is `ask`. A human must approve it.".to_string(),
            timeout_ms: None,
            irreversible: false,
            location: None,
        },
        DefaultVerdict::Deny => Verdict::Deny {
            rule_id: "default".to_string(),
            reason: "No policy rule matched this call; the policy default is `deny`.".to_string(),
            location: None,
        },
    }
}

/// Canonical verdict construction for a matched rule. Public so sibling
/// engine crates (Rego, Cedar) stay verdict-identical to the native engine
/// (Contract 2 parity).
pub fn verdict_for(rule: &CompiledRule, ctx: &ToolCallContext) -> Verdict {
    let location = match &rule.pack {
        Some(pack) => Some(format!("pack:{pack}")),
        None => rule.line.map(|l| format!("{}:{}", POLICY_FILE_NAME, l)),
    };
    match rule.verdict {
        RuleVerdict::Allow => Verdict::Allow {
            rule_id: Some(rule.id.clone()),
        },
        RuleVerdict::Deny => {
            Verdict::Deny {
                rule_id: rule.id.clone(),
                reason: rule.reason.clone().unwrap_or_else(|| {
                    format!(
                    "Denied by rule `{}`. The policy author did not provide a reason; inspect {}.",
                    rule.id,
                    location.clone().unwrap_or_else(|| POLICY_FILE_NAME.to_string())
                )
                }),
                location,
            }
        }
        RuleVerdict::Ask => Verdict::Ask {
            rule_id: rule.id.clone(),
            diff: rule.reason.clone().unwrap_or_else(|| ask_diff(rule, ctx)),
            timeout_ms: rule.timeout_ms,
            irreversible: rule.irreversible,
            location,
        },
        RuleVerdict::Redact => Verdict::Redact {
            rule_id: rule.id.clone(),
            patterns: rule.patterns.clone(),
        },
    }
}

/// Fallback Ask diff when the rule omits `reason`: describe the planned call.
fn ask_diff(rule: &CompiledRule, ctx: &ToolCallContext) -> String {
    let mut detail = format!("tool `{}`", ctx.tool);
    if let Some(c) = &ctx.command {
        detail.push_str(&format!(", command `{}`", c));
    }
    if let Some(p) = &ctx.path {
        detail.push_str(&format!(", path `{}`", p));
    }
    if let Some(q) = &ctx.query {
        detail.push_str(&format!(", query `{}`", q));
    }
    if let Some(h) = &ctx.url_host {
        detail.push_str(&format!(", host `{}`", h));
    }
    format!("Rule `{}` requires human approval for {}", rule.id, detail)
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Predicate evaluator over the shared rule AST. Public so sibling engine
/// crates (Rego, Cedar) evaluate predicates identically (Contract 2 parity).
pub fn eval_expr(expr: &Expr, ctx: &ToolCallContext) -> bool {
    match expr {
        Expr::Or(a, b) => eval_expr(a, ctx) || eval_expr(b, ctx),
        Expr::And(a, b) => eval_expr(a, ctx) && eval_expr(b, ctx),
        Expr::Not(inner) => !eval_expr(inner, ctx),
        Expr::Pred(p) => eval_pred(p, ctx),
    }
}

/// A predicate against an absent (`None`) or unknown field is non-matching —
/// for every operator, including `!=`. Fail-closed is the policy default's
/// job, not the predicate's.
fn eval_pred(pred: &Predicate, ctx: &ToolCallContext) -> bool {
    match pred {
        Predicate::Compare { field, op } => match field_value(*field, ctx) {
            None => false,
            Some(v) => match op {
                Op::Eq(w) => v == *w,
                Op::Ne(w) => v != *w,
                Op::StartsWith(w) => v.starts_with(w.as_str()),
                Op::EndsWith(w) => v.ends_with(w.as_str()),
                Op::Contains(w) => v.contains(w.as_str()),
                Op::Matches(re) => re.is_match(&v),
            },
        },
        Predicate::In { field, list } => match field_value(*field, ctx) {
            None => false,
            Some(v) => list.iter().any(|entry| list_entry_matches(entry, &v)),
        },
    }
}

fn field_value(field: Field, ctx: &ToolCallContext) -> Option<String> {
    match field {
        Field::Tool => Some(ctx.tool.clone()),
        Field::Command => ctx.command.clone(),
        Field::Path => ctx.path.clone(),
        Field::UrlHost => ctx.url_host.clone(),
        Field::Query => ctx.query.clone(),
        Field::Agent => Some(ctx.agent.clone()),
        Field::Mode => Some(
            match ctx.mode {
                writ_core::call::InterceptMode::Mcp => "mcp",
                writ_core::call::InterceptMode::ProcessWrap => "processwrap",
                writ_core::call::InterceptMode::SdkHook => "sdkhook",
            }
            .to_string(),
        ),
        Field::Server => ctx.server.clone(),
        Field::Trust => ctx.trust.clone(),
        Field::Unknown => None,
    }
}

/// List membership with `*.example.com` wildcard host support: a `*.`-prefixed
/// entry matches the bare domain and any subdomain (suffix match on a dot
/// boundary), case-insensitively. Plain entries match exactly.
fn list_entry_matches(entry: &str, value: &str) -> bool {
    if let Some(base) = entry.strip_prefix("*.") {
        let v = value.to_ascii_lowercase();
        let b = base.to_ascii_lowercase();
        v == b || v.ends_with(&format!(".{}", b))
    } else {
        entry == value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matches_dot_boundary_only() {
        assert!(list_entry_matches(
            "*.internal.acme.com",
            "api.internal.acme.com"
        ));
        assert!(list_entry_matches(
            "*.internal.acme.com",
            "internal.acme.com"
        ));
        assert!(list_entry_matches(
            "*.internal.acme.com",
            "API.Internal.Acme.COM"
        ));
        assert!(!list_entry_matches(
            "*.internal.acme.com",
            "evilinternal.acme.com"
        ));
        assert!(!list_entry_matches(
            "*.internal.acme.com",
            "internal.acme.com.evil.net"
        ));
        assert!(list_entry_matches("api.github.com", "api.github.com"));
        assert!(!list_entry_matches(
            "api.github.com",
            "api.github.com.evil.net"
        ));
    }
}
