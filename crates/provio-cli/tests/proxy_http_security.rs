//! `provio proxy --transport http`: credentials, Origin/Host validation,
//! loopback-only listening, and the session lifecycle.

mod proxy_http_common;

use proxy_http_common::*;
use serde_json::json;

#[test]
fn credential_headers_are_injected_upstream_and_never_leak() {
    let project = Project::new();
    let up = fake_upstream();
    let provio = start_provio(
        &project,
        &up.url,
        &[],
        &[
            ("PROVIO_CRED_FAKE_BEARER_TOKEN", "tok-live-7788"),
            ("PROVIO_CRED_FAKE_HEADER_X_API_KEY", "apikey-9911"),
        ],
    );
    handshake(&provio.url);
    let mut h = session();
    h.push(("Authorization", "Bearer agent-token-0001"));
    let r = post(&provio.url, &h, &call(1, "echo"));
    assert_eq!(r.status, 200);

    let calls = up.tool_calls();
    assert_eq!(
        calls[0].header("authorization"),
        Some("Bearer tok-live-7788")
    );
    assert_eq!(calls[0].header("x-api-key"), Some("apikey-9911"));
    assert!(calls[0]
        .headers
        .iter()
        .all(|(_, v)| !v.contains("agent-token-0001")));

    let agent_view = format!("{:?}{}", r.headers, r.body);
    let ledger = std::fs::read_to_string(project.path().join(".provio/ledger.jsonl")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(200));
    let logs = provio.stderr.lock().unwrap().clone();
    for secret in ["tok-live-7788", "apikey-9911"] {
        assert!(!agent_view.contains(secret), "leaked to agent");
        assert!(!ledger.contains(secret), "leaked to ledger");
        assert!(!logs.contains(secret), "leaked to logs: {logs}");
    }
    assert!(logs.contains("Authorization, X-Api-Key"), "{logs}");
}

#[test]
fn foreign_origin_is_rejected_with_403() {
    let project = Project::new();
    let up = fake_upstream();
    let provio = start_provio(&project, &up.url, &[], &[]);
    let r = post(
        &provio.url,
        &[("Origin", "https://evil.example")],
        &call(1, "echo"),
    );
    assert_eq!(r.status, 403);
    assert!(up.log.lock().unwrap().is_empty());
    assert!(project.records().is_empty());

    let allowed = start_provio(
        &project,
        &up.url,
        &["--allow-origin", "https://console.example"],
        &[],
    );
    let r = post(
        &allowed.url,
        &[("Origin", "https://console.example")],
        &json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}),
    );
    assert_eq!(r.status, 200);
}

#[test]
fn non_loopback_listen_requires_allow_remote_and_a_token() {
    let project = Project::new();
    let base = [
        "proxy",
        "--mcp",
        "--server",
        "fake",
        "--transport",
        "http",
        "--upstream",
        "http://127.0.0.1:9/mcp",
        "--listen",
        "0.0.0.0:0",
    ];
    let (code, err) = run_provio(&project, &base, &[]);
    assert_ne!(code, 0);
    assert!(err.contains("--allow-remote"), "{err}");

    let mut remote = base.to_vec();
    remote.push("--allow-remote");
    let (code, err) = run_provio(&project, &remote, &[]);
    assert_ne!(code, 0);
    assert!(err.contains("PROVIO_PROXY_TOKEN"), "{err}");

    let (code, err) = run_provio(
        &project,
        &["proxy", "--mcp", "--server", "fake", "--transport", "http"],
        &[],
    );
    assert_ne!(code, 0);
    assert!(err.contains("--upstream"), "{err}");
}

#[test]
fn session_id_round_trips_with_get_stream_and_delete() {
    let project = Project::new();
    let up = fake_upstream();
    let provio = start_provio(&project, &up.url, &[], &[]);
    let sid = handshake(&provio.url);
    assert_eq!(sid, SESSION);
    post(&provio.url, &session(), &call(1, "echo"));

    let g = finish(
        agent()
            .get(&provio.url)
            .header("Accept", "text/event-stream")
            .header("Mcp-Session-Id", &sid)
            .call()
            .unwrap(),
    );
    assert_eq!(g.status, 200);
    assert!(g
        .events()
        .iter()
        .any(|e| e.data.contains("resources/list_changed")));

    let d = finish(
        agent()
            .delete(&provio.url)
            .header("Mcp-Session-Id", &sid)
            .call()
            .unwrap(),
    );
    assert_eq!(d.status, 200);

    let log = up.log.lock().unwrap();
    assert!(log
        .iter()
        .skip(1)
        .all(|s| s.header("mcp-session-id") == Some(SESSION)));
    assert!(log.iter().any(|s| s.method == "DELETE"));
}
