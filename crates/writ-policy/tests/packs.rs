//! `packs:` in writ.yaml: bundled packs compose around the policy's own
//! rules (deny/ask first, allow after, redact last).

use writ_core::call::ToolCallContext;
use writ_core::policy::PolicyEngine;
use writ_core::verdict::Verdict;
use writ_policy::NativePolicyEngine;

fn bash(command: &str) -> ToolCallContext {
    ToolCallContext {
        tool: "bash".into(),
        command: Some(command.into()),
        ..Default::default()
    }
}

fn engine(src: &str) -> NativePolicyEngine {
    NativePolicyEngine::from_source(src).unwrap_or_else(|e| panic!("policy should compile: {e}"))
}

fn rule_of(v: &Verdict) -> Option<&str> {
    match v {
        Verdict::Allow { rule_id } => rule_id.as_deref(),
        Verdict::Deny { rule_id, .. }
        | Verdict::Ask { rule_id, .. }
        | Verdict::Redact { rule_id, .. } => Some(rule_id),
    }
}

#[test]
fn every_bundled_pack_composes() {
    assert!(
        !writ_policy::packs::BUNDLED.is_empty(),
        "packs/ should be bundled into writ-policy"
    );
    for (id, _) in writ_policy::packs::BUNDLED {
        let e = engine(&format!("version: 1\ndefault: ask\npacks: [{id}]\n"));
        assert!(e.rule_count() > 0, "pack {id} contributed no rules");
    }
}

#[test]
fn a_broad_allow_cannot_open_the_floor() {
    let e = engine(
        "version: 1\ndefault: ask\npacks: [floor]\nrules:\n  - id: allow-all-shell\n    when: tool == \"bash\"\n    verdict: allow\n",
    );
    let v = e.evaluate(&bash("rm -rf \"$HOME\""));
    assert!(matches!(v, Verdict::Deny { .. }), "{v:?}");
    assert_eq!(rule_of(&v), Some("floor-rm-home-or-root-denied"));
    // The broad allow still decides everything the floor does not name.
    let v = e.evaluate(&bash("cargo build"));
    assert_eq!(rule_of(&v), Some("allow-all-shell"));
}

#[test]
fn pack_rules_carry_their_pack_as_location() {
    let e = engine("version: 1\ndefault: allow\npacks: [floor]\n");
    match e.evaluate(&bash("git push --force origin main")) {
        Verdict::Deny { location, .. } => {
            let loc = location.expect("pack rules have a location");
            assert!(loc.starts_with("pack:floor@"), "{loc}");
        }
        other => panic!("expected deny, got {other:?}"),
    }
}

#[test]
fn own_denies_win_over_pack_allows() {
    // github-safety allows read-only git; a deny of the policy's own must
    // still decide first.
    let e = engine(
        "version: 1\ndefault: ask\npacks: [github-safety]\nrules:\n  - id: no-git-log\n    when: tool == \"bash\" and command startswith \"git log\"\n    verdict: deny\n    reason: no\n",
    );
    assert_eq!(
        rule_of(&e.evaluate(&bash("git log -3"))),
        Some("no-git-log")
    );
    assert_eq!(
        rule_of(&e.evaluate(&bash("git status"))),
        Some("github-git-read-only-allowed")
    );
}

#[test]
fn skip_leaves_a_rule_out() {
    let e = engine(
        "version: 1\ndefault: allow\npacks:\n  - id: floor\n    skip: [floor-shutdown-asks]\n",
    );
    assert_eq!(rule_of(&e.evaluate(&bash("sudo reboot"))), Some("default"));
}

#[test]
fn bad_pack_entries_fail_closed_with_a_reason() {
    let err = |src: &str| {
        NativePolicyEngine::from_source(src)
            .unwrap_err()
            .to_string()
    };

    let e = err("version: 1\ndefault: ask\npacks: [no-such-pack]\n");
    assert!(
        e.contains("no-such-pack") && e.contains("bundled packs"),
        "{e}"
    );

    let e = err("version: 1\ndefault: ask\npacks: [floor, floor]\n");
    assert!(e.contains("listed twice"), "{e}");

    let e = err("version: 1\ndefault: ask\npacks:\n  - id: floor\n    skip: [floor-typo]\n");
    assert!(e.contains("floor-typo"), "{e}");
}
