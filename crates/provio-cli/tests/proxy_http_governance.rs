//! `provio proxy --transport http`: every tools/call goes through the real
//! decision pipeline (policy file, ledger records, redaction), exactly as
//! the stdio proxy does.

mod proxy_http_common;

use proxy_http_common::*;
use serde_json::Value;

#[test]
fn allowed_call_is_forwarded_and_both_records_are_written() {
    let project = Project::new();
    let up = fake_upstream();
    let provio = start_provio(&project, &up.url, &[], &[]);
    handshake(&provio.url);

    let r = post(&provio.url, &session(), &call(1, "echo"));
    assert_eq!(r.status, 200);
    let v = r.json();
    assert_eq!(v["id"], 1);
    assert_eq!(v["result"], tool_result("echo"));
    assert_eq!(up.tool_calls().len(), 1);

    let decisions = project.decisions_for("echo");
    assert_eq!(decisions.len(), 1, "exactly one decision record");
    let d = &decisions[0];
    assert_eq!(d["rule_id"], "echo-ok");
    assert_eq!(d["call"]["server"]["name"], "fake");
    assert_eq!(d["call"]["server"]["transport"], "streamable-http");
    let call_id = d["call_id"].as_str().unwrap();
    let execs = project.executions_for(call_id);
    assert_eq!(execs.len(), 1);
    assert_eq!(execs[0]["decision_index"], d["index"]);
    assert_eq!(
        execs[0]["output_hash"].as_str().unwrap(),
        sha256_hex(&serde_json::to_vec(&tool_result("echo")).unwrap())
    );
}

#[test]
fn denied_call_is_refused_with_rule_and_reason_and_never_forwarded() {
    let project = Project::new();
    let up = fake_upstream();
    let provio = start_provio(&project, &up.url, &[], &[]);
    handshake(&provio.url);

    let v = post(&provio.url, &session(), &call(2, "db.drop")).json();
    assert_eq!(v["id"], 2);
    assert_eq!(v["error"]["code"], -32043);
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(msg.contains("no-drop"), "{msg}");
    assert!(msg.contains("irreversible"), "{msg}");
    assert_eq!(v["error"]["data"]["provio_refusal"], true);
    assert!(
        up.tool_calls().is_empty(),
        "denied call reached the upstream"
    );

    let decisions = project.decisions_for("db.drop");
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["rule_id"], "no-drop");
    assert!(project
        .executions_for(decisions[0]["call_id"].as_str().unwrap())
        .is_empty());
}

#[test]
fn ask_fails_closed_without_an_approver() {
    let project = Project::new();
    let up = fake_upstream();
    let provio = start_provio(&project, &up.url, &[], &[]);
    handshake(&provio.url);
    let v = post(&provio.url, &session(), &call(3, "deploy")).json();
    assert_eq!(v["error"]["code"], -32043);
    // The ask was resolved fail-closed (no approver), naming the rule.
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(msg.contains("\"deploy\""), "{msg}");
    assert!(up.tool_calls().is_empty());
    assert_eq!(project.decisions_for("deploy").len(), 1);
}

#[test]
fn redact_masks_json_and_sse_results_but_the_ledger_hashes_the_original() {
    let project = Project::new();
    let up = fake_upstream();
    let provio = start_provio(&project, &up.url, &[], &[]);
    handshake(&provio.url);

    let r = post(&provio.url, &session(), &call(4, "lookup"));
    assert!(!r.body.contains(SSN), "{}", r.body);
    assert!(r.body.contains("[redacted-by-provio]"));

    let s = post(&provio.url, &session(), &call(5, "lookup_sse"));
    assert!(s
        .header("content-type")
        .unwrap()
        .starts_with("text/event-stream"));
    assert!(!s.body.contains(SSN), "{}", s.body);
    let evs = s.events();
    let last: Value = serde_json::from_str(&evs.last().unwrap().data).unwrap();
    assert_eq!(last["id"], 5);
    assert!(last["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("[redacted-by-provio]"));
    // The request-scoped log notification was masked too.
    assert!(evs.iter().any(|e| e.data.contains("notifications/message")));

    for tool in ["lookup", "lookup_sse"] {
        let d = &project.decisions_for(tool)[0];
        let e = &project.executions_for(d["call_id"].as_str().unwrap())[0];
        assert_eq!(
            e["output_hash"].as_str().unwrap(),
            sha256_hex(&serde_json::to_vec(&tool_result(tool)).unwrap()),
            "execution record hashes the unmasked result"
        );
    }
}

#[test]
fn invalid_redact_pattern_withholds_the_result() {
    let project = Project::new();
    let up = fake_upstream();
    let provio = start_provio(&project, &up.url, &[], &[]);
    handshake(&provio.url);
    let r = post(&provio.url, &session(), &call(6, "broken"));
    assert!(!r.body.contains(SSN), "{}", r.body);
    let v = r.json();
    assert_eq!(v["result"]["isError"], true);
    assert!(v["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("withheld"));
}

#[test]
fn upstream_down_is_a_structured_fail_closed_error() {
    let project = Project::new();
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}/mcp", l.local_addr().unwrap())
    };
    let provio = start_provio(
        &project,
        &dead,
        &["--upstream-transport", "streamable"],
        &[],
    );
    let r = post(&provio.url, &[], &call(7, "echo"));
    assert_eq!(r.status, 200);
    let v = r.json();
    assert_eq!(v["id"], 7);
    assert_eq!(v["error"]["code"], -32044);
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("fail closed"));
    let d = project.decisions_for("echo");
    assert_eq!(d.len(), 1, "the decision is recorded before dispatch");
    assert!(project
        .executions_for(d[0]["call_id"].as_str().unwrap())
        .is_empty());
}
