//! provio.yaml loading: serde structs, compilation (regexes, list refs,
//! durations), and per-rule source line tracking.
//!
//! Every error message carries `provio.yaml:LINE` detail (spec §7/§12) so a
//! failed `reload` tells the operator exactly where the policy broke.

use crate::ast::{Expr, Op, Predicate, RawExpr, RawOp, RawPredicate};
use crate::parser::parse_when;
use provio_core::verdict::DefaultVerdict;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;

/// The display name used in all diagnostics and verdict locations.
pub const POLICY_FILE_NAME: &str = "provio.yaml";

#[derive(Debug, Deserialize)]
struct RawPolicyFile {
    version: u32,
    default: DefaultVerdict,
    #[serde(default)]
    rules: Vec<RawRule>,
    /// Bundled policy packs to compose with `rules` (see [`crate::packs`]).
    #[serde(default)]
    packs: Vec<PackRef>,
    /// Any other top-level mapping (e.g. `hosts: { allowed: [...] }`) is a
    /// namespace of named lists addressable from `in` expressions.
    #[serde(flatten)]
    lists: HashMap<String, serde_yaml::Value>,
}

/// One `packs:` entry: a bundled pack id, or `{ id, skip: [rule ids] }` to
/// leave out rules the policy author wants to decide differently.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PackRef {
    Id(String),
    Spec {
        id: String,
        #[serde(default)]
        skip: Vec<String>,
    },
}

impl PackRef {
    fn id(&self) -> &str {
        match self {
            PackRef::Id(id) | PackRef::Spec { id, .. } => id,
        }
    }

    fn skip(&self) -> &[String] {
        match self {
            PackRef::Id(_) => &[],
            PackRef::Spec { skip, .. } => skip,
        }
    }
}

/// A pack's `pack.yaml` (`description` and any other keys are ignored).
#[derive(Debug, Deserialize)]
struct RawPack {
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    rules: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    id: String,
    when: String,
    verdict: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    irreversible: bool,
    #[serde(default)]
    timeout: Option<String>,
    #[serde(default)]
    patterns: Option<Vec<String>>,
}

/// The four rule verdicts of the native engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleVerdict {
    Allow,
    Deny,
    Ask,
    Redact,
}

/// A fully validated, evaluation-ready rule.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: String,
    pub when: Expr,
    pub verdict: RuleVerdict,
    pub reason: Option<String>,
    pub irreversible: bool,
    pub timeout_ms: Option<u64>,
    pub patterns: Vec<String>,
    /// 1-based line of `- id: <id>` in the source, if found.
    pub line: Option<usize>,
    /// `<pack id>@<version>` when the rule comes from a `packs:` entry
    /// (`line` is then `None`).
    pub pack: Option<String>,
}

/// A fully validated, evaluation-ready policy.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub version: u32,
    pub default: DefaultVerdict,
    pub rules: Vec<CompiledRule>,
}

/// Parse `"30s"`, `"5m"`, `"1h"`, `"250ms"` (or a bare integer = milliseconds)
/// into milliseconds.
pub fn parse_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix("ms") {
        (n, 1u64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1_000)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60_000)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3_600_000)
    } else {
        (s, 1)
    };
    let v: u64 = num.trim().parse().map_err(|_| {
        format!(
            "invalid duration {:?} (expected e.g. \"30s\", \"5m\", \"1h\")",
            s
        )
    })?;
    v.checked_mul(mult)
        .ok_or_else(|| format!("duration {:?} overflows milliseconds", s))
}

/// Parse and compile a provio.yaml source. Pure: on `Err` nothing is mutated —
/// callers implement atomic reload by only swapping on `Ok`.
pub fn compile(source: &str) -> Result<CompiledPolicy, String> {
    let raw: RawPolicyFile = serde_yaml::from_str(source).map_err(|e| match e.location() {
        Some(loc) => format!(
            "{}:{}:{}: {}",
            POLICY_FILE_NAME,
            loc.line(),
            loc.column(),
            e
        ),
        None => format!("{}: {}", POLICY_FILE_NAME, e),
    })?;

    // Flatten named lists: "hosts.allowed" -> ["api.github.com", ...].
    let mut lists: HashMap<String, Vec<String>> = HashMap::new();
    for (ns, value) in &raw.lists {
        let mapping = value.as_mapping().ok_or_else(|| {
            format!(
                "{}: top-level key {:?} must be a mapping of list names to string lists",
                POLICY_FILE_NAME, ns
            )
        })?;
        for (k, v) in mapping {
            let list_name = k.as_str().ok_or_else(|| {
                format!(
                    "{}: list names under {:?} must be strings",
                    POLICY_FILE_NAME, ns
                )
            })?;
            let seq = v.as_sequence().ok_or_else(|| {
                format!(
                    "{}: list {:?} must be a sequence of strings",
                    POLICY_FILE_NAME, list_name
                )
            })?;
            let mut items = Vec::with_capacity(seq.len());
            for item in seq {
                let s = item.as_str().ok_or_else(|| {
                    format!(
                        "{}: entries of list {:?} must be strings, got {:?}",
                        POLICY_FILE_NAME, list_name, item
                    )
                })?;
                items.push(s.to_string());
            }
            lists.insert(format!("{}.{}", ns, list_name), items);
        }
    }

    // Track each rule's `- id: <id>` source line.
    let id_lines = extract_rule_id_lines(source);
    let mut cursor = 0usize;
    let mut own = Vec::with_capacity(raw.rules.len());
    for (i, rr) in raw.rules.iter().enumerate() {
        let line = locate_rule_line(&id_lines, &rr.id, i, &mut cursor);
        let at = |msg: String| match line {
            Some(l) => format!("{}:{}: rule {:?}: {}", POLICY_FILE_NAME, l, rr.id, msg),
            None => format!("{}: rule {:?}: {}", POLICY_FILE_NAME, rr.id, msg),
        };
        own.push(compile_rule(rr, &lists, line, None).map_err(at)?);
    }

    // Packs compose around the policy's own rules the way the packs README
    // says to merge them by hand: their deny and ask rules first (a broad
    // allow of your own cannot open a floor), their allow rules after yours
    // (your denies still win), their redact rules last (redact dispatches).
    let (mut front, mut allows, mut redacts) = (Vec::new(), Vec::new(), Vec::new());
    let mut seen_packs: Vec<&str> = Vec::new();
    for pr in &raw.packs {
        let id = pr.id();
        let at = |msg: String| format!("{}: pack {:?}: {}", POLICY_FILE_NAME, id, msg);
        if seen_packs.contains(&id) {
            return Err(at("listed twice under `packs:`".to_string()));
        }
        seen_packs.push(id);
        let src = crate::packs::bundled(id).ok_or_else(|| {
            at(format!(
                "not bundled in this build (bundled packs: {})",
                match crate::packs::names() {
                    n if n.is_empty() => "<none>".to_string(),
                    n => n,
                }
            ))
        })?;
        let pack: RawPack =
            serde_yaml::from_str(src).map_err(|e| at(format!("invalid pack.yaml: {e}")))?;
        for skip in pr.skip() {
            if !pack.rules.iter().any(|r| &r.id == skip) {
                return Err(at(format!(
                    "`skip` names {skip:?}, which is not a rule of this pack"
                )));
            }
        }
        let tag = match &pack.version {
            Some(v) => format!("{id}@{v}"),
            None => id.to_string(),
        };
        for rr in pack.rules.iter().filter(|r| !pr.skip().contains(&r.id)) {
            let rule = compile_rule(rr, &lists, None, Some(&tag))
                .map_err(|e| at(format!("rule {:?}: {e}", rr.id)))?;
            match rule.verdict {
                RuleVerdict::Deny | RuleVerdict::Ask => front.push(rule),
                RuleVerdict::Allow => allows.push(rule),
                RuleVerdict::Redact => redacts.push(rule),
            }
        }
    }
    let mut rules = front;
    rules.extend(own);
    rules.extend(allows);
    rules.extend(redacts);

    /// Validate and compile one rule. Errors carry no location; the caller
    /// prefixes the policy line or the pack.
    fn compile_rule(
        rr: &RawRule,
        lists: &HashMap<String, Vec<String>>,
        line: Option<usize>,
        pack: Option<&str>,
    ) -> Result<CompiledRule, String> {
        if rr.id.trim().is_empty() {
            return Err("rule id must not be empty".to_string());
        }
        let raw_expr = parse_when(&rr.when).map_err(|e| format!("invalid `when`: {}", e))?;
        let when = compile_expr(&raw_expr, lists)?;
        let verdict = match rr.verdict.as_str() {
            "allow" => RuleVerdict::Allow,
            "deny" => RuleVerdict::Deny,
            "ask" => RuleVerdict::Ask,
            "redact" => RuleVerdict::Redact,
            other => {
                return Err(format!(
                    "unknown verdict {:?} (expected allow, deny, ask, redact)",
                    other
                ))
            }
        };
        let timeout_ms = rr.timeout.as_deref().map(parse_duration).transpose()?;
        let patterns = rr.patterns.clone().unwrap_or_default();
        if verdict == RuleVerdict::Redact && patterns.is_empty() {
            return Err("`verdict: redact` requires a non-empty `patterns` list".to_string());
        }
        Ok(CompiledRule {
            id: rr.id.clone(),
            when,
            verdict,
            reason: rr.reason.clone(),
            irreversible: rr.irreversible,
            timeout_ms,
            patterns,
            line,
            pack: pack.map(str::to_string),
        })
    }

    /// Compile a raw expression: build regexes and resolve `in` list refs.
    fn compile_expr(raw: &RawExpr, lists: &HashMap<String, Vec<String>>) -> Result<Expr, String> {
        Ok(match raw {
            RawExpr::Or(a, b) => Expr::Or(
                Box::new(compile_expr(a, lists)?),
                Box::new(compile_expr(b, lists)?),
            ),
            RawExpr::And(a, b) => Expr::And(
                Box::new(compile_expr(a, lists)?),
                Box::new(compile_expr(b, lists)?),
            ),
            RawExpr::Not(inner) => Expr::Not(Box::new(compile_expr(inner, lists)?)),
            RawExpr::Pred(RawPredicate::Compare { field, op }) => Expr::Pred(Predicate::Compare {
                field: *field,
                op: compile_op(op)?,
            }),
            RawExpr::Pred(RawPredicate::In { field, list_ref }) => {
                let list = lists.get(list_ref).cloned().ok_or_else(|| {
                    let mut known: Vec<&str> = lists.keys().map(String::as_str).collect();
                    known.sort();
                    format!(
                        "unknown list reference {:?} (defined lists: {})",
                        list_ref,
                        if known.is_empty() {
                            "<none>".to_string()
                        } else {
                            known.join(", ")
                        }
                    )
                })?;
                Expr::Pred(Predicate::In {
                    field: *field,
                    list,
                })
            }
        })
    }

    fn compile_op(op: &RawOp) -> Result<Op, String> {
        Ok(match op {
            RawOp::Eq(v) => Op::Eq(v.clone()),
            RawOp::Ne(v) => Op::Ne(v.clone()),
            RawOp::StartsWith(v) => Op::StartsWith(v.clone()),
            RawOp::EndsWith(v) => Op::EndsWith(v.clone()),
            RawOp::Contains(v) => Op::Contains(v.clone()),
            RawOp::Matches(pat) => {
                Op::Matches(Regex::new(pat).map_err(|e| format!("invalid regex {:?}: {}", pat, e))?)
            }
        })
    }

    /// All lines (1-based) of sequence entries declaring an id: `- id: <value>`.
    fn extract_rule_id_lines(source: &str) -> Vec<(usize, String)> {
        let re = Regex::new(r#"^\s*-\s*id\s*:\s*(.+?)\s*(?:#.*)?$"#).expect("static regex");
        source
            .lines()
            .enumerate()
            .filter_map(|(i, line)| {
                re.captures(line).map(|c| {
                    let id = c[1].trim().trim_matches('"').trim_matches('\'').to_string();
                    (i + 1, id)
                })
            })
            .collect()
    }

    /// Match rules to source lines in order of appearance. Falls back to the
    /// nth `- id:` line if an exact id match cannot be found ahead of the cursor.
    fn locate_rule_line(
        id_lines: &[(usize, String)],
        id: &str,
        index: usize,
        cursor: &mut usize,
    ) -> Option<usize> {
        if let Some(pos) = id_lines[*cursor..].iter().position(|(_, v)| v == id) {
            let abs = *cursor + pos;
            *cursor = abs + 1;
            return Some(id_lines[abs].0);
        }
        if let Some(pos) = id_lines.iter().position(|(_, v)| v == id) {
            return Some(id_lines[pos].0);
        }
        id_lines.get(index).map(|(l, _)| *l)
    }
    Ok(CompiledPolicy {
        version: raw.version,
        default: raw.default,
        rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("30s").unwrap(), 30_000);
        assert_eq!(parse_duration("5m").unwrap(), 300_000);
        assert_eq!(parse_duration("1h").unwrap(), 3_600_000);
        assert_eq!(parse_duration("250ms").unwrap(), 250);
        assert_eq!(parse_duration("500").unwrap(), 500);
        assert!(parse_duration("5d").is_err());
        assert!(parse_duration("soon").is_err());
    }
}
