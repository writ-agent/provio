//! Live call tree with verdict badges (spec §12): the developer watches
//! policy working rather than taking it on faith. Pure ANSI, no deps.

use provio_core::verdict::Verdict;

/// One rendered call line, e.g. `✓ bash    cargo test --lib`
/// or `⚠ bash    rm -rf ./build  [ask]`.
pub fn render_call_line(tool: &str, summary: &str, verdict: &Verdict) -> String {
    let (badge, tag) = match verdict {
        Verdict::Allow { .. } => ("\x1b[32m✓\x1b[0m", ""),
        Verdict::Deny { .. } => ("\x1b[31m✗\x1b[0m", "  \x1b[31m[denied]\x1b[0m"),
        Verdict::Ask { .. } => ("\x1b[33m⚠\x1b[0m", "  \x1b[33m[ask]\x1b[0m"),
        Verdict::Redact { .. } => ("\x1b[36m◆\x1b[0m", "  \x1b[36m[redact]\x1b[0m"),
    };
    format!("{badge} {tool:<7} {summary}{tag}")
}

/// The rule attribution line under a flagged call (spec §12: always name
/// the rule and its file:line).
pub fn render_rule_note(verdict: &Verdict) -> Option<String> {
    match verdict {
        Verdict::Deny {
            rule_id,
            reason,
            location,
        } => Some(format!(
            "  rule: {rule_id} ({})\n  → {reason}",
            location.as_deref().unwrap_or("policy default")
        )),
        Verdict::Ask {
            rule_id, location, ..
        } => Some(format!(
            "  rule: {rule_id} ({})",
            location.as_deref().unwrap_or("policy default")
        )),
        Verdict::Redact { rule_id, .. } => Some(format!("  rule: {rule_id}")),
        Verdict::Allow { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn badges_per_verdict() {
        let allow = Verdict::Allow { rule_id: None };
        let deny = Verdict::Deny {
            rule_id: "r".into(),
            reason: "why".into(),
            location: Some("provio.yaml:6".into()),
        };
        assert!(render_call_line("bash", "ls", &allow).contains('✓'));
        assert!(render_call_line("bash", "rm", &deny).contains("[denied]"));
        let note = render_rule_note(&deny).unwrap();
        assert!(note.contains("r"));
        assert!(note.contains("provio.yaml:6"));
        assert!(render_rule_note(&allow).is_none());
    }
}
