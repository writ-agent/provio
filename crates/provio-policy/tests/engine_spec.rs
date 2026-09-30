//! Acceptance tests for the native engine against examples/provio.yaml
//! (spec §7) and the shared fixture corpus.

use provio_core::verdict::{DefaultVerdict, Verdict};
use provio_core::{PolicyEngine, ToolCallContext};
use provio_policy::{load_fixtures_dir, run_fixtures, NativePolicyEngine};
use std::path::PathBuf;

fn examples_policy() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/provio.yaml");
    std::fs::read_to_string(path).expect("examples/provio.yaml readable")
}

fn ctx(tool: &str) -> ToolCallContext {
    ToolCallContext {
        tool: tool.to_string(),
        ..Default::default()
    }
}

fn engine() -> NativePolicyEngine {
    NativePolicyEngine::from_source(&examples_policy()).expect("examples/provio.yaml compiles")
}

#[test]
fn parses_examples_policy() {
    let e = engine();
    assert_eq!(e.name(), "native");
    assert_eq!(e.rule_count(), 5);
    let meta = e.meta();
    assert_eq!(meta.version, 1);
    assert_eq!(meta.default, DefaultVerdict::Ask);
}

#[test]
fn denies_destructive_rm_rf() {
    let mut c = ctx("bash");
    c.command = Some("rm -rf /".to_string());
    match engine().evaluate(&c) {
        Verdict::Deny {
            rule_id,
            reason,
            location,
        } => {
            assert_eq!(rule_id, "block-destructive-shell");
            assert_eq!(
                reason,
                "Destructive system command. Narrow the path and retry."
            );
            assert_eq!(location.as_deref(), Some("provio.yaml:6"));
        }
        v => panic!("expected deny, got {:?}", v),
    }
}

#[test]
fn drop_table_asks_irreversible_with_timeout() {
    let mut c = ctx("postgres.query");
    c.query = Some("DROP TABLE users;".to_string());
    match engine().evaluate(&c) {
        Verdict::Ask {
            rule_id,
            diff,
            timeout_ms,
            irreversible,
            location,
        } => {
            assert_eq!(rule_id, "protect-production-db");
            assert!(
                !diff.trim().is_empty(),
                "ask must carry a human reason/diff"
            );
            assert_eq!(timeout_ms, Some(300_000)); // 5m
            assert!(irreversible);
            assert_eq!(location.as_deref(), Some("provio.yaml:11"));
        }
        v => panic!("expected ask, got {:?}", v),
    }
}

#[test]
fn disallowed_egress_denied_with_fallback_reason() {
    let mut c = ctx("http");
    c.url_host = Some("evil.example.net".to_string());
    match engine().evaluate(&c) {
        Verdict::Deny {
            rule_id,
            reason,
            location,
        } => {
            assert_eq!(rule_id, "egress-allowlist");
            assert!(
                !reason.trim().is_empty(),
                "deny must carry a human reason even when the rule omits one"
            );
            assert_eq!(location.as_deref(), Some("provio.yaml:18"));
        }
        v => panic!("expected deny, got {:?}", v),
    }
}

#[test]
fn allowlisted_egress_is_not_denied() {
    let e = engine();
    for host in [
        "api.github.com",
        "registry.npmjs.org",
        "api.internal.acme.com",
    ] {
        let mut c = ctx("http");
        c.url_host = Some(host.to_string());
        let v = e.evaluate(&c);
        assert!(
            matches!(v, Verdict::Ask { .. }),
            "host {} should fall through to default ask, got {:?}",
            host,
            v
        );
    }
}

#[test]
fn env_read_denied() {
    let mut c = ctx("fs.read");
    c.path = Some("/home/app/.env".to_string());
    match engine().evaluate(&c) {
        Verdict::Deny {
            rule_id,
            reason,
            location,
        } => {
            assert_eq!(rule_id, "never-read-secrets");
            assert_eq!(reason, "Secrets are masked from the agent by design.");
            assert_eq!(location.as_deref(), Some("provio.yaml:31"));
        }
        v => panic!("expected deny, got {:?}", v),
    }
}

#[test]
fn unmatched_call_hits_default_ask() {
    let mut c = ctx("bash");
    c.command = Some("ls -la".to_string());
    match engine().evaluate(&c) {
        Verdict::Ask {
            rule_id,
            diff,
            location,
            ..
        } => {
            assert_eq!(rule_id, "default");
            assert!(!diff.trim().is_empty());
            assert!(location.is_none());
        }
        v => panic!("expected default ask, got {:?}", v),
    }
}

#[test]
fn reload_keeps_last_good_on_garbage() {
    let mut e = engine();
    let before = e.rule_count();
    let mut c = ctx("bash");
    c.command = Some("rm -rf /".to_string());
    let verdict_before = e.evaluate(&c);

    for garbage in [
        "not: [valid yaml",
        "version: 1\ndefault: ask\nrules:\n  - id: x\n    when: tool == ",
        "version: 1\ndefault: ask\nrules:\n  - id: x\n    when: 'tool == \"bash\"'\n    verdict: maybe",
        "version: 1\ndefault: ask\nrules:\n  - id: x\n    when: tool == \"bash\" in nosuch.list\n    verdict: deny",
        "version: 1\ndefault: ask\nrules:\n  - id: x\n    when: tool matches \"(unclosed\"\n    verdict: deny",
    ] {
        let err = e.reload(garbage).expect_err("garbage must fail to load");
        let msg = err.to_string();
        assert!(msg.contains("provio.yaml"), "error must carry file detail: {}", msg);
        assert_eq!(e.rule_count(), before, "last-good policy must be kept");
        assert_eq!(e.evaluate(&c), verdict_before, "verdicts must be unchanged");
    }

    // A valid reload swaps atomically.
    e.reload("version: 1\ndefault: deny\nrules:\n  - id: allow-all-bash\n    when: tool == \"bash\"\n    verdict: allow\n")
        .unwrap();
    assert_eq!(e.rule_count(), 1);
    assert!(e.evaluate(&c).is_allow());
}

#[test]
fn redact_verdict_carries_patterns() {
    let src = "version: 1\ndefault: allow\nrules:\n  - id: mask-keys\n    when: tool == \"http\" and query matches \"(?i)key\"\n    verdict: redact\n    patterns: [\"sk-[A-Za-z0-9]+\"]\n";
    let e = NativePolicyEngine::from_source(src).unwrap();
    let mut c = ctx("http");
    c.query = Some("get the key".to_string());
    match e.evaluate(&c) {
        Verdict::Redact { rule_id, patterns } => {
            assert_eq!(rule_id, "mask-keys");
            assert_eq!(patterns, vec!["sk-[A-Za-z0-9]+".to_string()]);
        }
        v => panic!("expected redact, got {:?}", v),
    }
}

#[test]
fn redact_without_patterns_is_a_load_error() {
    let src = "version: 1\ndefault: allow\nrules:\n  - id: bad\n    when: tool == \"http\"\n    verdict: redact\n";
    let err = NativePolicyEngine::from_source(src)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("provio.yaml:4"),
        "error should point at the rule: {}",
        err
    );
}

#[test]
fn unknown_fields_are_non_matching_and_never_panic() {
    let src = "version: 1\ndefault: ask\nrules:\n  - id: nope\n    when: nosuchfield == \"x\" or another.bogus contains \"y\"\n    verdict: deny\n";
    let e = NativePolicyEngine::from_source(src).unwrap();
    match e.evaluate(&ctx("bash")) {
        Verdict::Ask { rule_id, .. } => assert_eq!(rule_id, "default"),
        v => panic!("expected default ask, got {:?}", v),
    }
}

#[test]
fn first_matching_rule_wins() {
    let src = "version: 1\ndefault: ask\nrules:\n  - id: first\n    when: tool == \"bash\"\n    verdict: allow\n  - id: second\n    when: tool == \"bash\"\n    verdict: deny\n    reason: never reached\n";
    let e = NativePolicyEngine::from_source(src).unwrap();
    match e.evaluate(&ctx("bash")) {
        Verdict::Allow { rule_id } => assert_eq!(rule_id.as_deref(), Some("first")),
        v => panic!("expected allow from first rule, got {:?}", v),
    }
}

#[test]
fn default_deny_carries_reason() {
    let e = NativePolicyEngine::from_source("version: 1\ndefault: deny\nrules: []\n").unwrap();
    match e.evaluate(&ctx("anything")) {
        Verdict::Deny {
            rule_id, reason, ..
        } => {
            assert_eq!(rule_id, "default");
            assert!(!reason.trim().is_empty());
        }
        v => panic!("expected default deny, got {:?}", v),
    }
}

#[test]
fn shared_fixture_corpus_passes() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let fixtures = load_fixtures_dir(&dir).expect("fixtures load");
    assert!(
        fixtures.len() >= 6,
        "expected at least 6 fixtures, got {}",
        fixtures.len()
    );
    let report = run_fixtures(&examples_policy(), &fixtures);
    assert!(report.is_pass(), "{}", report.summary());
    assert_eq!(report.passed, report.total);
}

#[test]
fn harness_reports_mismatches() {
    let src = "version: 1\ndefault: allow\nrules: []\n";
    let fixtures = vec![provio_policy::Fixture {
        name: "expect deny but policy allows".to_string(),
        policy: None,
        ctx: provio_policy::FixtureCtx {
            tool: Some("bash".to_string()),
            ..Default::default()
        },
        expect: provio_policy::Expectation {
            verdict: provio_policy::ExpectedKind::Deny,
            rule_id: None,
        },
    }];
    let report = run_fixtures(src, &fixtures);
    assert!(!report.is_pass());
    assert_eq!(report.failures.len(), 1);
    assert!(report.summary().contains("expect deny but policy allows"));
}

#[test]
fn harness_reports_policy_compile_error() {
    let report = run_fixtures("not: [valid", &[]);
    assert!(!report.is_pass());
    assert!(report.error.is_some());
}
