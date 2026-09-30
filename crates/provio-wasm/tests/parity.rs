//! Parity: the playground's wasm API (called natively here — the same Rust
//! functions the browser calls) must agree with the real thing:
//!
//! - `evaluate` ≡ `NativePolicyEngine::evaluate` on the shared fixture corpus
//!   (`crates/provio-policy/fixtures/`) and on every preset call × policy preset;
//! - ledger records ≡ what `provio_core::LedgerWriter` writes, and they pass
//!   `provio_ledger::verify` (the `provio verify` backend) and `verify_chain`;
//! - tamper → `ledger_verify` reports the same broken index as `provio verify`;
//! - `replay` ≡ `provio_replay::load_trajectory` + `policy_replay` on a file.

use std::path::{Path, PathBuf};

use provio_core::approver::{ApproverIdentity, ApproverKind};
use provio_core::error::Result as WResult;
use provio_core::ledger::{LedgerRecord, LedgerStore, LedgerWriter};
use provio_core::verdict::Verdict;
use provio_core::{verify_chain, PolicyEngine, ToolCall, ToolCallContext};
use provio_policy::{load_fixtures_dir, NativePolicyEngine};
use serde_json::{json, Value};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(p: impl AsRef<Path>) -> String {
    std::fs::read_to_string(repo().join(p.as_ref())).expect("read repo file")
}

fn parse(s: &str) -> Value {
    serde_json::from_str(s).expect("api returns JSON")
}

const NOW: f64 = 1_790_021_315_000.0;

/// Every policy preset the page bakes in: examples/*.yaml and packs.
fn policy_presets() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for name in ["provio.yaml", "ci.yaml", "strict.yaml"] {
        out.push((format!("examples/{name}"), read(format!("examples/{name}"))));
    }
    let mut packs: Vec<_> = std::fs::read_dir(repo().join("packs"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path().join("pack.yaml"))
        .filter(|p| p.exists())
        .collect();
    packs.sort();
    for p in packs {
        let src = std::fs::read_to_string(&p).unwrap();
        out.push((p.display().to_string(), provio_wasm::pack_to_policy(&src)));
    }
    out
}

fn presets() -> Value {
    parse(&read("crates/provio-wasm/presets/calls.json"))
}

// ---------------------------------------------------------------------------
// Policy parity

#[test]
fn fixture_corpus_matches_native_engine() {
    let fixtures =
        load_fixtures_dir(&repo().join("crates/provio-policy/fixtures")).expect("fixtures load");
    assert!(fixtures.len() >= 6);
    let shared = read("examples/provio.yaml");
    for fx in &fixtures {
        let src = fx.policy.clone().unwrap_or_else(|| shared.clone());
        let native = NativePolicyEngine::from_source(&src).unwrap();
        let native_ctx = fx.ctx.to_context().unwrap();
        let native_verdict = native.evaluate(&native_ctx);

        // The same case, as the playground would send it.
        let c = &fx.ctx;
        let mut args = c.args.clone().unwrap_or_else(|| json!({}));
        let m = args.as_object_mut().unwrap();
        if let Some(v) = &c.command {
            m.insert("command".into(), json!(v));
        }
        if let Some(v) = &c.path {
            m.insert("path".into(), json!(v));
        }
        if let Some(v) = &c.query {
            m.insert("query".into(), json!(v));
        }
        if let Some(v) = &c.url_host {
            m.insert("url".into(), json!(format!("https://{v}/")));
        }
        let agent = c.agent.clone().unwrap_or_else(|| {
            if c.args.is_some() {
                "fixture-agent".into()
            } else {
                String::new()
            }
        });
        let sim = json!({
            "agent": agent,
            "tool": c.tool.clone().unwrap_or_default(),
            "args": args,
            "server": c.server,
            "trust": c.trust,
            "mode": c.mode.clone().unwrap_or_else(|| "mcp".into()),
        });
        let out = parse(&provio_wasm::evaluate(&src, &sim.to_string(), NOW));
        assert_eq!(out["ok"], true, "{}: {out}", fx.name);
        assert_eq!(
            out["ctx"],
            serde_json::to_value(&native_ctx).unwrap(),
            "{}: normalised context differs",
            fx.name
        );
        let v: Verdict = serde_json::from_value(out["verdict"].clone()).unwrap();
        assert_eq!(v, native_verdict, "{}: verdict differs", fx.name);
        // And the fixture's own expectation holds.
        let want = format!("{:?}", fx.expect.verdict).to_lowercase();
        assert_eq!(out["kind"], want.as_str(), "{}", fx.name);
        if let Some(r) = &fx.expect.rule_id {
            assert_eq!(v.rule_id(), Some(r.as_str()), "{}", fx.name);
        }
    }
}

#[test]
fn every_preset_call_matches_native_engine_under_every_policy() {
    let calls = presets()["calls"].as_array().unwrap().clone();
    for (name, src) in policy_presets() {
        let compiled = parse(&provio_wasm::compile_policy(&src));
        assert_eq!(compiled["ok"], true, "{name} must compile: {compiled}");
        let native = NativePolicyEngine::from_source(&src).unwrap();
        assert_eq!(
            compiled["rules"].as_array().unwrap().len(),
            native.rule_count()
        );
        for c in &calls {
            let out = parse(&provio_wasm::evaluate(&src, &c["call"].to_string(), NOW));
            assert_eq!(out["ok"], true, "{name} / {}: {out}", c["id"]);
            let call: ToolCall = serde_json::from_value(out["call"].clone()).unwrap();
            let want = native.evaluate(&ToolCallContext::from_call(&call));
            let got: Verdict = serde_json::from_value(out["verdict"].clone()).unwrap();
            assert_eq!(got, want, "{name} / {}", c["id"]);
        }
    }
}

#[test]
fn headline_presets_decide_as_documented() {
    let src = read("examples/provio.yaml");
    let calls = presets()["calls"].as_array().unwrap().clone();
    let by_id = |id: &str| {
        calls
            .iter()
            .find(|c| c["id"] == id)
            .unwrap_or_else(|| panic!("preset {id}"))["call"]
            .to_string()
    };
    let cases = [
        ("cc-bash-rm", "deny", "block-destructive-shell"),
        ("cc-write-env", "deny", "never-read-secrets"),
        ("cc-webfetch-evil", "deny", "egress-allowlist"),
        ("cc-webfetch-github", "ask", "default"),
        ("mcp-postgres-select", "redact", "mask-pii"),
        ("mcp-postgres-drop", "ask", "protect-production-db"),
        ("oa-read-key", "deny", "never-read-secrets"),
    ];
    for (id, kind, rule) in cases {
        let out = parse(&provio_wasm::evaluate(&src, &by_id(id), NOW));
        assert_eq!(
            (out["kind"].as_str(), out["verdict"]["rule_id"].as_str()),
            (Some(kind), Some(rule)),
            "{id}"
        );
    }
    // Deny carries provio.yaml:LINE of the rule's `- id:` line.
    let out = parse(&provio_wasm::evaluate(&src, &by_id("cc-bash-rm"), NOW));
    let line = src
        .lines()
        .position(|l| l.contains("id: block-destructive-shell"))
        .unwrap()
        + 1;
    assert_eq!(out["verdict"]["location"], format!("provio.yaml:{line}"));
}

#[test]
fn claude_code_mapping_matches_the_hook_table() {
    let cases = [
        ("Bash", json!({"command": "ls"}), "bash", None),
        ("PowerShell", json!({"command": "ls"}), "bash", None),
        ("Read", json!({"file_path": "/a"}), "fs.read", None),
        ("Write", json!({"file_path": "/a"}), "fs.write", None),
        (
            "NotebookEdit",
            json!({"notebook_path": "/n"}),
            "fs.write",
            None,
        ),
        ("WebFetch", json!({"url": "https://x"}), "http", None),
        ("WebSearch", json!({"query": "q"}), "web.search", None),
        (
            "mcp__postgres__query",
            json!({"sql": "select 1"}),
            "query",
            Some("postgres"),
        ),
        (
            "mcp__plugin_x_db__run__fast",
            json!({}),
            "run__fast",
            Some("plugin_x_db"),
        ),
        ("mcp__broken", json!({}), "mcp__broken", None),
        ("SomethingElse", json!({}), "SomethingElse", None),
    ];
    for (name, args, tool, server) in cases {
        let (t, a, s) = provio_wasm::map_claude_tool(name, args.as_object().unwrap().clone(), None);
        assert_eq!(t, tool, "{name}");
        assert_eq!(s.map(|s| s.name).as_deref(), server, "{name}");
        if name == "Read" || name == "Write" {
            assert_eq!(a["path"], "/a");
        }
        if name == "NotebookEdit" {
            assert_eq!(a["path"], "/n");
        }
    }
}

#[test]
fn compile_errors_carry_line_numbers() {
    let bad_when = "version: 1\ndefault: ask\nrules:\n  - id: a\n    when: tool == \"x\"\n    verdict: allow\n  - id: broken\n    when: tool ==== \"x\"\n    verdict: deny\n";
    let out = parse(&provio_wasm::compile_policy(bad_when));
    assert_eq!(out["ok"], false);
    assert_eq!(out["errors"][0]["line"], 7);
    let bad_yaml = "version: 1\ndefault: ask\nrules:\n  - id: a\n   when: [\n";
    let out = parse(&provio_wasm::compile_policy(bad_yaml));
    assert_eq!(out["ok"], false);
    assert!(out["errors"][0]["line"].is_u64(), "{out}");
    let out = parse(&provio_wasm::evaluate(bad_when, r#"{"tool":"Bash"}"#, NOW));
    assert_eq!(out["ok"], false);
}

#[test]
fn mask_output_matches_the_cli_mark() {
    let pats = json!([
        "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}",
        "\\b\\d{3}-\\d{2}-\\d{4}\\b"
    ])
    .to_string();
    let out = parse(&provio_wasm::mask_output(
        &pats,
        "ssn 123-45-6789, mail a@b.io",
    ));
    assert_eq!(
        out["masked"],
        "ssn [redacted-by-provio], mail [redacted-by-provio]"
    );
    assert_eq!(out["matches"], 2);
    let out = parse(&provio_wasm::mask_output(
        &pats,
        r#"{"rows":[["x@y.com", 3]]}"#,
    ));
    let masked: Value = serde_json::from_str(out["masked"].as_str().unwrap()).unwrap();
    assert_eq!(masked, json!({"rows": [["[redacted-by-provio]", 3]]}));
    let out = parse(&provio_wasm::mask_output(r#"["("]"#, "x"));
    assert_eq!(out["ok"], false);
}

// ---------------------------------------------------------------------------
// Ledger parity

#[derive(Default)]
struct MemStore(Vec<LedgerRecord>);

impl LedgerStore for MemStore {
    fn append(&mut self, r: &LedgerRecord) -> WResult<()> {
        self.0.push(r.clone());
        Ok(())
    }
    fn tip(&self) -> WResult<Option<LedgerRecord>> {
        Ok(self.0.last().cloned())
    }
    fn get(&self, i: u64) -> WResult<Option<LedgerRecord>> {
        Ok(self.0.get(i as usize).cloned())
    }
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn iter(&self) -> Box<dyn Iterator<Item = WResult<LedgerRecord>> + '_> {
        Box::new(self.0.iter().cloned().map(Ok))
    }
}

fn sim_call(id: &str) -> ToolCall {
    let calls = presets()["calls"].as_array().unwrap().clone();
    let c = calls.iter().find(|c| c["id"] == id).unwrap();
    let out = parse(&provio_wasm::evaluate(
        &read("examples/provio.yaml"),
        &c["call"].to_string(),
        NOW,
    ));
    serde_json::from_value(out["call"].clone()).unwrap()
}

#[test]
fn records_are_identical_to_ledger_writer_output() {
    let mut store = MemStore::default();
    let call = sim_call("mcp-postgres-drop");
    let engine = NativePolicyEngine::from_source(&read("examples/provio.yaml")).unwrap();
    let verdict = engine.evaluate(&ToolCallContext::from_call(&call));
    let approver = Some(ApproverIdentity {
        kind: ApproverKind::Tui,
        id: "playground".into(),
    });
    let (a, b) = {
        let mut w = LedgerWriter::new(&mut store);
        let a = w
            .record_decision(&call, &verdict, approver.clone())
            .unwrap();
        let b = w
            .record_execution(&a, "playground-sim", 0, b"DROP TABLE")
            .unwrap();
        (a, b)
    };
    let mine_a = provio_wasm::decision_record(
        "",
        &call,
        &verdict,
        approver,
        a.recorded_at.epoch_ms() as f64,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&mine_a).unwrap(),
        serde_json::to_value(&a).unwrap()
    );
    let mine_b = provio_wasm::execution_record(
        &serde_json::to_string(&mine_a).unwrap(),
        &mine_a,
        "playground-sim",
        0,
        b"DROP TABLE",
        b.recorded_at.epoch_ms() as f64,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&mine_b).unwrap(),
        serde_json::to_value(&b).unwrap()
    );
}

/// Build a whole playground ledger through the JSON API: every preset call,
/// a decision record each and an execution record for dispatched calls.
fn api_ledger(session: &str) -> Vec<String> {
    let src = read("examples/provio.yaml");
    let approver = provio_wasm::playground_approver();
    let mut lines: Vec<String> = Vec::new();
    for (i, c) in presets()["calls"].as_array().unwrap().iter().enumerate() {
        let mut call = c["call"].clone();
        call["session_id"] = json!(session);
        call["call_id"] = json!(format!("call-{i}"));
        let now = NOW + (i as f64) * 1000.0;
        let ev = parse(&provio_wasm::evaluate(&src, &call.to_string(), now));
        let kind = ev["kind"].as_str().unwrap().to_string();
        let appr = if kind == "ask" { approver.as_str() } else { "" };
        let prev = lines.last().cloned().unwrap_or_default();
        let d = parse(&provio_wasm::ledger_record_decision(
            &prev,
            &ev["call"].to_string(),
            &ev["verdict"].to_string(),
            appr,
            now,
        ));
        assert_eq!(d["ok"], true, "{d}");
        let dec = d["record"].to_string();
        lines.push(dec.clone());
        if kind != "deny" {
            let e = parse(&provio_wasm::ledger_record_execution(
                &dec,
                &dec,
                "playground-sim",
                0,
                c["output"].as_str().unwrap_or(""),
                now + 250.0,
            ));
            assert_eq!(e["ok"], true, "{e}");
            lines.push(e["record"].to_string());
        }
    }
    lines
}

fn tmp_file(name: &str, body: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("provio-wasm-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, format!("{body}\n")).unwrap();
    p
}

#[test]
fn api_ledger_passes_provio_verify() {
    let lines = api_ledger("s-verify");
    let jsonl = lines.join("\n");
    let recs: Vec<LedgerRecord> = lines
        .iter()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let r = verify_chain(recs.into_iter().map(Ok)).unwrap();
    assert!(r.intact);
    assert_eq!(r.records, lines.len() as u64);

    let path = tmp_file("intact.jsonl", &jsonl);
    let r = provio_ledger::verify(&path).unwrap();
    assert!(r.intact, "provio verify rejected the playground ledger");
    let mine = parse(&provio_wasm::ledger_verify(&jsonl));
    assert_eq!(mine["intact"], true);
    assert_eq!(mine["records"], r.records);
    assert_eq!(
        mine["message"],
        format!("chain intact · {} records · no gaps", r.records)
    );
}

#[test]
fn tamper_breaks_where_provio_verify_says() {
    let lines = api_ledger("s-tamper");
    let jsonl = lines.join("\n");
    let n = lines.len() as u32;
    for (mode, idx) in [
        ("edit", 0),
        ("edit", 3),
        ("edit", n - 1),
        ("edit-rehash", 2),
        ("edit-rehash", n - 1),
        ("delete", 4),
        ("delete", 0),
    ] {
        let t = parse(&provio_wasm::ledger_tamper(&jsonl, idx, mode));
        assert_eq!(t["ok"], true, "{t}");
        let edited = t["jsonl"].as_str().unwrap();
        let path = tmp_file(&format!("tamper-{mode}-{idx}.jsonl"), edited);
        let theirs = provio_ledger::verify(&path).unwrap();
        let mine = parse(&provio_wasm::ledger_verify(edited));
        assert_eq!(mine["intact"], theirs.intact, "{mode}@{idx}");
        assert_eq!(mine["broken_at"].as_u64(), theirs.broken_at, "{mode}@{idx}");
        assert_eq!(mine["records"], theirs.records, "{mode}@{idx}");
        match (mode, idx) {
            ("edit", i) => assert_eq!(theirs.broken_at, Some(i as u64)),
            ("edit-rehash", i) if i == n - 1 => {
                // Rewriting the tip AND its hash is not visible to a chain
                // check alone — the deletion/tail gap anchoring closes.
                assert!(theirs.intact)
            }
            ("edit-rehash", i) => assert_eq!(theirs.broken_at, Some(i as u64 + 1)),
            ("delete", i) => assert_eq!(theirs.broken_at, Some(i as u64 + 1)),
            _ => unreachable!(),
        }
    }
    // An unparseable line is a break at its position, as in provio verify.
    let mut garbled = lines.clone();
    garbled[2] = "{not json".into();
    let edited = garbled.join("\n");
    let path = tmp_file("garbled.jsonl", &edited);
    let theirs = provio_ledger::verify(&path).unwrap();
    let mine = parse(&provio_wasm::ledger_verify(&edited));
    assert_eq!(mine["broken_at"].as_u64(), theirs.broken_at);
    assert_eq!(theirs.broken_at, Some(2));
}

#[test]
fn replay_matches_provio_replay_on_a_file() {
    let lines = api_ledger("s-replay");
    let jsonl = lines.join("\n");
    let path = tmp_file("replay.jsonl", &jsonl);
    for (_, candidate) in policy_presets() {
        let steps = provio_replay::load_trajectory(&path, "s-replay").unwrap();
        let theirs = provio_replay::policy_replay(&steps, &candidate).unwrap();
        let mine = parse(&provio_wasm::replay(&jsonl, "s-replay", &candidate));
        assert_eq!(mine["ok"], true, "{mine}");
        assert_eq!(mine["summary"], theirs.summary());
        assert_eq!(
            mine["changes"].as_array().unwrap().len(),
            theirs.changes.len()
        );
        let rows = mine["rows"].as_array().unwrap();
        assert_eq!(
            rows.iter().filter(|r| r["changed"] == true).count(),
            theirs.changes.len()
        );
    }
    let out = parse(&provio_wasm::replay(
        &jsonl,
        "nope",
        "version: 1\ndefault: ask\n",
    ));
    assert_eq!(out["ok"], false);
}

#[test]
fn sample_sessions_reference_real_presets_and_compile() {
    let p = presets();
    let ids: Vec<&str> = p["calls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    for s in p["sessions"].as_array().unwrap() {
        let src = s["recorded_under"].as_str().unwrap();
        assert_eq!(parse(&provio_wasm::compile_policy(src))["ok"], true);
        for c in s["calls"].as_array().unwrap() {
            assert!(ids.contains(&c.as_str().unwrap()), "{c}");
        }
    }
}
