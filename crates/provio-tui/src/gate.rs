//! The approval gate — the hero moment (spec §12). Renders the exact planned
//! action and waits for a human: `[a]llow [d]eny [e]dit [!] always allow`.
//!
//! Wave 1 is dependency-free (ADR-008): ANSI + line input instead of
//! ratatui/crossterm, so the static binary has zero terminal deps. Rendering
//! goes to **stderr**, because in proxy mode stdout is the JSON-RPC channel.

use std::cell::RefCell;
use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::time::Instant;

use provio_core::approver::{
    ApprovalDecision, ApprovalOutcome, Approver, ApproverIdentity, ApproverKind, AskView,
};
use provio_core::call::ToolCall;
use provio_core::error::Result;

/// Interactive human gate. Not usable when stdin is not a terminal — use
/// `FailClosedApprover` (headless) or an out-of-band approver (CI) instead.
pub struct TuiApprover {
    /// Rules the operator permanently allowed this session (`[!]` key).
    always_allowed: RefCell<HashSet<String>>,
}

impl Default for TuiApprover {
    fn default() -> Self {
        Self::new()
    }
}

impl TuiApprover {
    pub fn new() -> Self {
        TuiApprover {
            always_allowed: RefCell::new(HashSet::new()),
        }
    }

    fn me() -> ApproverIdentity {
        ApproverIdentity {
            kind: ApproverKind::Tui,
            id: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "local-operator".into()),
        }
    }
}

impl Approver for TuiApprover {
    fn request(&self, call: &ToolCall, ask: &AskView) -> Result<ApprovalOutcome> {
        let start = Instant::now();
        let me = Self::me();

        if self.always_allowed.borrow().contains(&ask.rule_id) {
            return Ok(ApprovalOutcome {
                decision: ApprovalDecision::AllowOnce,
                approver: ApproverIdentity {
                    id: format!("{} (always-allow {})", me.id, ask.rule_id),
                    ..me
                },
                waited_ms: 0,
            });
        }

        let mut err = std::io::stderr();
        let _ = writeln!(
            err,
            "\n\x1b[33m⚠ provio asks:\x1b[0m {} {}",
            call.tool,
            summarize(&call.args)
        );
        for line in ask.diff.lines() {
            let _ = writeln!(err, "  {line}");
        }
        let _ = writeln!(err, "  rule: {}", ask.rule_id);
        if ask.irreversible {
            let _ = writeln!(err, "  \x1b[31mthis action is marked IRREVERSIBLE\x1b[0m");
        }
        let _ = write!(err, "  [a]llow  [d]eny  [e]dit  [!] always allow > ");
        let _ = err.flush();

        let mut stdin = std::io::stdin().lock();
        let mut line = String::new();
        let decision = loop {
            line.clear();
            if stdin.read_line(&mut line)? == 0 {
                break ApprovalDecision::Deny; // EOF: fail closed
            }
            match line.trim().chars().next() {
                Some('a') => break ApprovalDecision::AllowOnce,
                Some('d') => break ApprovalDecision::Deny,
                Some('!') => {
                    self.always_allowed.borrow_mut().insert(ask.rule_id.clone());
                    break ApprovalDecision::AlwaysAllowRule;
                }
                Some('e') => {
                    let _ = write!(err, "  replacement args JSON > ");
                    let _ = err.flush();
                    line.clear();
                    if stdin.read_line(&mut line)? == 0 {
                        break ApprovalDecision::Deny;
                    }
                    match serde_json::from_str::<serde_json::Value>(line.trim()) {
                        Ok(v) => break ApprovalDecision::EditArgs(v),
                        Err(e) => {
                            let _ = writeln!(err, "  invalid JSON ({e}); try again");
                            let _ = write!(err, "  [a]llow  [d]eny  [e]dit  [!] always allow > ");
                            let _ = err.flush();
                        }
                    }
                }
                _ => {
                    let _ = write!(err, "  a / d / e / ! > ");
                    let _ = err.flush();
                }
            }
        };

        Ok(ApprovalOutcome {
            decision,
            approver: me,
            waited_ms: start.elapsed().as_millis() as u64,
        })
    }
}

/// One-line summary of call args for the gate header.
fn summarize(args: &serde_json::Value) -> String {
    let s = match args {
        serde_json::Value::Object(m) => m
            .values()
            .next()
            .map(|v| {
                v.as_str()
                    .map(String::from)
                    .unwrap_or_else(|| v.to_string())
            })
            .unwrap_or_default(),
        other => other.to_string(),
    };
    let s = s.replace('\n', " ");
    if s.chars().count() > 72 {
        format!("{}…", s.chars().take(71).collect::<String>())
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn summarize_truncates_and_flattens() {
        let long = "x".repeat(200);
        let s = summarize(&json!({"command": long}));
        assert!(s.chars().count() <= 72);
        let multiline = summarize(&json!({"command": "a\nb"}));
        assert!(!multiline.contains('\n'));
    }
}
