//! Streamable HTTP proxy, end to end in-process: a fake agent (ureq / raw
//! TCP) → `HttpProxy` → a fake upstream MCP server (JSON and SSE replies,
//! session ids, notifications, a server-initiated GET stream, DELETE), plus
//! a fake legacy HTTP+SSE upstream.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use provio_core::{SecretString, ToolCall};
use provio_mcp::http::server::{self, Limits, Request, Responder, ShutdownHandle};
use provio_mcp::http::sse::{SseEvent, SseReader};
use provio_mcp::http::{
    AutoUpstream, HttpProxy, HttpProxyOptions, StreamableUpstream, Upstream, UpstreamOptions,
    HEADER_MISMATCH_CODE, PROVIO_UPSTREAM_ERROR_CODE,
};
use provio_mcp::{CredentialStore, Interceptor, ProxyConfig, ProxyDecision, PROVIO_REFUSAL_CODE};
use serde_json::{json, Value};

const SSN: &str = "123-45-6789";
const SESSION: &str = "sess-abc-123";

// ---------------------------------------------------------------- upstream

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    headers: Vec<(String, String)>,
    body: Value,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

type Log = Arc<Mutex<Vec<Seen>>>;

fn json_reply(
    resp: Responder<'_>,
    status: u16,
    extra: &[(&str, &str)],
    v: &Value,
) -> std::io::Result<()> {
    let mut h = vec![("Content-Type".to_string(), "application/json".to_string())];
    h.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    resp.send(status, &h, v.to_string().as_bytes())
}

fn sse_reply(resp: Responder<'_>, events: &[SseEvent]) -> std::io::Result<()> {
    let mut body = resp.stream(200, &[("Content-Type".into(), "text/event-stream".into())])?;
    for e in events {
        body.write(&e.encode())?;
    }
    body.finish()
}

fn result(id: &Value, r: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": r})
}

/// A Streamable HTTP MCP server (2025-11-25 shape: sessions, GET stream).
fn fake_upstream() -> (String, Log, ShutdownHandle) {
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let log2 = Arc::clone(&log);
    let handler = move |req: &Request, resp: Responder<'_>| -> std::io::Result<()> {
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        log2.lock().unwrap().push(Seen {
            method: req.method.clone(),
            headers: req.headers.clone(),
            body: body.clone(),
        });
        let has_session = req.header("mcp-session-id") == Some(SESSION);
        match req.method.as_str() {
            "GET" => {
                if !has_session {
                    return resp.send(400, &[], b"");
                }
                sse_reply(
                    resp,
                    &[
                        SseEvent {
                            id: Some("g-1".into()),
                            data:
                                json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"})
                                    .to_string(),
                            ..Default::default()
                        },
                        SseEvent {
                            id: Some("g-2".into()),
                            data: json!({"jsonrpc":"2.0","id":"srv-1","method":"roots/list"})
                                .to_string(),
                            ..Default::default()
                        },
                    ],
                )
            }
            "DELETE" => resp.send(if has_session { 200 } else { 404 }, &[], b""),
            "POST" => {
                let method = body["method"].as_str().unwrap_or("").to_string();
                let id = body.get("id").cloned();
                if method == "initialize" {
                    return json_reply(
                        resp,
                        200,
                        &[("Mcp-Session-Id", SESSION)],
                        &result(
                            id.as_ref().unwrap(),
                            json!({"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                                   "serverInfo": {"name": "fake", "version": "0"}}),
                        ),
                    );
                }
                if !has_session {
                    return resp.send(400, &[], b"missing session");
                }
                let Some(id) = id else {
                    return resp.send(202, &[], b""); // notification or response
                };
                if body.get("method").is_none() {
                    return resp.send(202, &[], b"");
                }
                match method.as_str() {
                    "tools/list" => json_reply(
                        resp,
                        200,
                        &[],
                        &result(
                            &id,
                            json!({"tools": [{"name": "echo"}, {"name": "danger"}, {"name": "pii"}]}),
                        ),
                    ),
                    "tools/call" => {
                        let name = body["params"]["name"].as_str().unwrap_or("");
                        let text = format!("{name} says: customer SSN {SSN}");
                        let res = result(&id, json!({"content": [{"type": "text", "text": text}]}));
                        if name.ends_with("_sse") {
                            sse_reply(
                                resp,
                                &[
                                    SseEvent {
                                        id: Some("p-0".into()),
                                        ..Default::default()
                                    },
                                    SseEvent {
                                        id: Some("p-1".into()),
                                        data: json!({"jsonrpc":"2.0","method":"notifications/progress",
                                            "params":{"progressToken":1,"progress":1,"message":format!("found {SSN}")}})
                                        .to_string(),
                                        ..Default::default()
                                    },
                                    SseEvent {
                                        id: Some("p-2".into()),
                                        data: res.to_string(),
                                        ..Default::default()
                                    },
                                ],
                            )
                        } else {
                            json_reply(resp, 200, &[], &res)
                        }
                    }
                    _ => json_reply(resp, 200, &[], &result(&id, json!({}))),
                }
            }
            _ => resp.send(405, &[], b""),
        }
    };
    let (addr, stop) = server::spawn("127.0.0.1:0", Limits::default(), Arc::new(handler)).unwrap();
    (format!("http://{addr}/mcp"), log, stop)
}

// ------------------------------------------------------------------- proxy

#[derive(Default)]
struct Records {
    decisions: Vec<ToolCall>,
    executions: Vec<(String, Value)>,
}

struct Proxy {
    url: String,
    records: Arc<Mutex<Records>>,
    stop: ShutdownHandle,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.shutdown();
    }
}

/// Start an HttpProxy whose decider refuses `danger*`, and whose transform
/// masks the SSN for `pii*` tools (the CLI uses the policy's regexes).
fn start_proxy(upstream: Arc<dyn Upstream>, opts: HttpProxyOptions) -> Proxy {
    let records = Arc::new(Mutex::new(Records::default()));
    let rec = Arc::clone(&records);
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (rd, ro) = (Arc::clone(&rec), Arc::clone(&rec));
        let mut core = Interceptor::new(
            ProxyConfig {
                server_name: "fake".into(),
                agent: "test-agent".into(),
                trust: None,
            },
            upstream.kind(),
            Box::new(move |call: &ToolCall| {
                rd.lock().unwrap().decisions.push(call.clone());
                if call.tool.starts_with("danger") {
                    ProxyDecision::Refuse {
                        message:
                            "provio denied this: rule \"no-danger\" — dangerous tools need approval"
                                .into(),
                    }
                } else {
                    ProxyDecision::Forward
                }
            }),
        );
        core.on_result(Box::new(move |call: &ToolCall, result: &Value| {
            ro.lock()
                .unwrap()
                .executions
                .push((call.call_id.clone(), result.clone()));
        }));
        core.set_result_transform(Box::new(|call: &ToolCall, v: Value| {
            if call.tool.starts_with("pii") {
                serde_json::from_str(&v.to_string().replace(SSN, "[redacted-by-provio]")).unwrap()
            } else {
                v
            }
        }));
        let proxy = HttpProxy::bind("127.0.0.1:0", opts, upstream).unwrap();
        tx.send((proxy.url(), proxy.shutdown_handle())).unwrap();
        proxy.run(core);
    });
    let (url, stop) = rx.recv().unwrap();
    Proxy { url, records, stop }
}

fn streamable(url: &str, creds: CredentialStore) -> Arc<dyn Upstream> {
    Arc::new(StreamableUpstream::new(
        url,
        "fake",
        Arc::new(creds),
        UpstreamOptions {
            connect_timeout: Duration::from_secs(2),
            response_timeout: Duration::from_secs(10),
            ..Default::default()
        },
    ))
}

// ------------------------------------------------------------------- agent

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(20)))
        .build()
        .into()
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|_| panic!("not JSON: {:?}", self.body))
    }
    fn events(&self) -> Vec<SseEvent> {
        SseReader::new(self.body.as_bytes(), 1 << 20)
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap()
    }
}

fn post(url: &str, headers: &[(&str, &str)], body: &Value) -> Resp {
    let mut rb = agent()
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");
    for (k, v) in headers {
        rb = rb.header(*k, *v);
    }
    finish(rb.send(body.to_string()).unwrap())
}

fn finish(r: ureq::http::Response<ureq::Body>) -> Resp {
    let status = r.status().as_u16();
    let headers = r
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = r.into_body().read_to_string().unwrap_or_default();
    Resp {
        status,
        headers,
        body,
    }
}

fn call(id: u64, tool: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
           "params": {"name": tool, "arguments": {"q": "x"}}})
}

fn with_session<'a>() -> Vec<(&'a str, &'a str)> {
    vec![
        ("Mcp-Session-Id", SESSION),
        ("MCP-Protocol-Version", "2025-11-25"),
    ]
}

/// initialize + initialized, returning the session id the agent saw.
fn handshake(url: &str) -> String {
    let r = post(
        url,
        &[],
        &json!({"jsonrpc":"2.0","id":0,"method":"initialize",
                "params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let sid = r
        .header("mcp-session-id")
        .expect("session id relayed")
        .to_string();
    let n = post(
        url,
        &with_session(),
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    assert_eq!(n.status, 202);
    assert!(n.body.is_empty());
    sid
}

fn tools_calls(log: &Log) -> Vec<Seen> {
    log.lock()
        .unwrap()
        .iter()
        .filter(|s| s.body["method"] == "tools/call")
        .cloned()
        .collect()
}

// ------------------------------------------------------------------- tests

#[test]
fn allowed_call_is_forwarded_and_execution_observed() {
    let (up, log, _s) = fake_upstream();
    let p = start_proxy(
        streamable(&up, CredentialStore::new()),
        HttpProxyOptions::default(),
    );
    assert_eq!(handshake(&p.url), SESSION);

    let list = post(
        &p.url,
        &with_session(),
        &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    );
    assert_eq!(list.json()["result"]["tools"].as_array().unwrap().len(), 3);

    let r = post(&p.url, &with_session(), &call(2, "echo"));
    assert_eq!(r.status, 200);
    let v = r.json();
    assert_eq!(v["id"], 2);
    assert!(v["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("echo says"));

    let rec = p.records.lock().unwrap();
    assert_eq!(rec.decisions.len(), 1, "exactly one decision");
    assert_eq!(rec.decisions[0].tool, "echo");
    assert_eq!(
        rec.decisions[0].server.as_ref().unwrap().transport,
        "streamable-http"
    );
    assert_eq!(rec.executions.len(), 1);
    assert_eq!(rec.executions[0].0, rec.decisions[0].call_id);
    assert_eq!(tools_calls(&log).len(), 1);
}

#[test]
fn denied_call_is_refused_with_rule_and_never_forwarded() {
    let (up, log, _s) = fake_upstream();
    let p = start_proxy(
        streamable(&up, CredentialStore::new()),
        HttpProxyOptions::default(),
    );
    handshake(&p.url);
    let r = post(&p.url, &with_session(), &call(5, "danger"));
    assert_eq!(r.status, 200);
    let v = r.json();
    assert_eq!(v["id"], 5);
    assert_eq!(v["error"]["code"], PROVIO_REFUSAL_CODE);
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("no-danger"));
    assert_eq!(v["error"]["data"]["provio_refusal"], true);
    assert!(
        tools_calls(&log).is_empty(),
        "refused call reached the upstream"
    );
    let rec = p.records.lock().unwrap();
    assert_eq!(rec.decisions.len(), 1);
    assert!(rec.executions.is_empty());
}

#[test]
fn redact_masks_json_results() {
    let (up, _log, _s) = fake_upstream();
    let p = start_proxy(
        streamable(&up, CredentialStore::new()),
        HttpProxyOptions::default(),
    );
    handshake(&p.url);
    let r = post(&p.url, &with_session(), &call(3, "pii"));
    assert!(!r.body.contains(SSN), "{}", r.body);
    assert!(r.body.contains("[redacted-by-provio]"));
    // The ledger side saw the original (it hashes the unmasked output).
    let rec = p.records.lock().unwrap();
    assert!(rec.executions[0].1.to_string().contains(SSN));
}

#[test]
fn redact_masks_sse_results_and_request_scoped_notifications() {
    let (up, _log, _s) = fake_upstream();
    let p = start_proxy(
        streamable(&up, CredentialStore::new()),
        HttpProxyOptions::default(),
    );
    handshake(&p.url);
    let r = post(&p.url, &with_session(), &call(4, "pii_sse"));
    assert_eq!(r.status, 200);
    assert!(r
        .header("content-type")
        .unwrap()
        .starts_with("text/event-stream"));
    assert!(!r.body.contains(SSN), "{}", r.body);
    let evs = r.events();
    // priming event (id only), progress notification, final response —
    // ids preserved for resumability.
    assert_eq!(evs.len(), 3, "{evs:?}");
    assert_eq!(evs[0].id.as_deref(), Some("p-0"));
    assert!(evs[0].data.is_empty());
    let note: Value = serde_json::from_str(&evs[1].data).unwrap();
    assert_eq!(note["method"], "notifications/progress");
    assert!(note["params"]["message"]
        .as_str()
        .unwrap()
        .contains("[redacted-by-provio]"));
    let fin: Value = serde_json::from_str(&evs[2].data).unwrap();
    assert_eq!(fin["id"], 4);
    assert_eq!(evs[2].id.as_deref(), Some("p-2"));
    assert!(fin["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("[redacted-by-provio]"));
    assert_eq!(p.records.lock().unwrap().executions.len(), 1);
}

#[test]
fn sse_reply_is_collapsed_for_json_only_agents() {
    let (up, _log, _s) = fake_upstream();
    let p = start_proxy(
        streamable(&up, CredentialStore::new()),
        HttpProxyOptions::default(),
    );
    handshake(&p.url);
    let r = finish(
        agent()
            .post(&p.url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("Mcp-Session-Id", SESSION)
            .send(call(9, "echo_sse").to_string())
            .unwrap(),
    );
    assert!(r
        .header("content-type")
        .unwrap()
        .starts_with("application/json"));
    assert_eq!(r.json()["id"], 9);
}

#[test]
fn credentials_are_injected_upstream_and_never_reach_the_agent() {
    let (up, log, _s) = fake_upstream();
    let mut creds = CredentialStore::new();
    creds.add("fake", "BEARER_TOKEN", SecretString::new("up-secret-token"));
    creds.add("fake", "HEADER_X_API_KEY", SecretString::new("key-456"));
    creds.add("fake", "GITHUB_TOKEN", SecretString::new("env-only"));
    let p = start_proxy(streamable(&up, creds), HttpProxyOptions::default());
    handshake(&p.url);
    let mut h = with_session();
    h.push(("Authorization", "Bearer agent-own-token"));
    h.push(("Cookie", "sid=agent-cookie"));
    let r = post(&p.url, &h, &call(7, "echo"));
    assert_eq!(r.status, 200);

    let seen = tools_calls(&log);
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].header("authorization"),
        Some("Bearer up-secret-token")
    );
    assert_eq!(seen[0].header("x-api-key"), Some("key-456"));
    assert!(seen[0]
        .headers
        .iter()
        .all(|(_, v)| !v.contains("agent-own-token")));
    assert!(seen[0].header("cookie").is_none());
    assert!(seen[0].headers.iter().all(|(_, v)| !v.contains("env-only")));
    // The agent never sees injected values, in headers or body.
    let everything = format!("{:?}{}", r.headers, r.body);
    for secret in ["up-secret-token", "key-456"] {
        assert!(!everything.contains(secret));
    }
    // Every upstream request (initialize included) carried the credential.
    assert!(log
        .lock()
        .unwrap()
        .iter()
        .all(|s| s.header("authorization") == Some("Bearer up-secret-token")));
}

#[test]
fn agent_auth_is_forwarded_only_when_configured() {
    let (up, log, _s) = fake_upstream();
    let p = start_proxy(
        streamable(&up, CredentialStore::new()),
        HttpProxyOptions {
            forward_agent_auth: true,
            ..Default::default()
        },
    );
    post(
        &p.url,
        &[("Authorization", "Bearer agent-own-token")],
        &json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}),
    );
    assert_eq!(
        log.lock().unwrap()[0].header("authorization"),
        Some("Bearer agent-own-token")
    );
}

#[test]
fn bad_origin_and_host_are_rejected_before_anything_happens() {
    let (up, log, _s) = fake_upstream();
    let p = start_proxy(
        streamable(&up, CredentialStore::new()),
        HttpProxyOptions::default(),
    );
    let r = post(
        &p.url,
        &[("Origin", "http://evil.example")],
        &call(1, "echo"),
    );
    assert_eq!(r.status, 403);
    assert!(r.json().get("id").is_none());
    let ok = post(
        &p.url,
        &[("Origin", "http://localhost:6274")],
        &json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}),
    );
    assert_eq!(ok.status, 200);

    // DNS rebinding: loopback socket, foreign Host header, no Origin (a
    // same-origin GET from the rebound page).
    let addr = p
        .url
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap()
        .to_string();
    let mut s = TcpStream::connect(&addr).unwrap();
    s.write_all(b"GET /mcp HTTP/1.1\r\nHost: evil.example:80\r\nAccept: text/event-stream\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");

    let before = log.lock().unwrap().len();
    assert_eq!(before, 1, "only the allowed initialize reached upstream");
    assert!(p.records.lock().unwrap().decisions.is_empty());
}

#[test]
fn proxy_token_is_required_when_configured() {
    let (up, log, _s) = fake_upstream();
    let p = start_proxy(
        streamable(&up, CredentialStore::new()),
        HttpProxyOptions {
            agent_token: Some(SecretString::new("proxy-tok")),
            ..Default::default()
        },
    );
    let init = json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{}});
    assert_eq!(post(&p.url, &[], &init).status, 401);
    assert_eq!(
        post(&p.url, &[("Authorization", "Bearer nope")], &init).status,
        401
    );
    assert!(log.lock().unwrap().is_empty());
    assert_eq!(
        post(&p.url, &[("Authorization", "Bearer proxy-tok")], &init).status,
        200
    );
    // The proxy token is consumed by provio, never forwarded.
    assert!(log.lock().unwrap()[0].header("authorization").is_none());
}

#[test]
fn session_id_round_trips_get_stream_and_delete() {
    let (up, log, _s) = fake_upstream();
    let p = start_proxy(
        streamable(&up, CredentialStore::new()),
        HttpProxyOptions::default(),
    );
    let sid = handshake(&p.url);
    post(&p.url, &with_session(), &call(2, "echo"));
    assert!(log
        .lock()
        .unwrap()
        .iter()
        .skip(1)
        .all(|s| s.header("mcp-session-id") == Some(&sid)));

    // Server-initiated stream via GET: notification + server request relayed,
    // Last-Event-ID forwarded for resumption.
    let r = finish(
        agent()
            .get(&p.url)
            .header("Accept", "text/event-stream")
            .header("Mcp-Session-Id", &sid)
            .header("Last-Event-ID", "g-0")
            .call()
            .unwrap(),
    );
    assert_eq!(r.status, 200);
    let evs = r.events();
    assert_eq!(evs.len(), 2);
    assert!(evs[0].data.contains("tools/list_changed"));
    assert_eq!(evs[1].id.as_deref(), Some("g-2"));
    let get = log
        .lock()
        .unwrap()
        .iter()
        .find(|s| s.method == "GET")
        .cloned()
        .unwrap();
    assert_eq!(get.header("last-event-id"), Some("g-0"));

    // The agent answers the server's request: forwarded upstream, 202.
    let a = post(
        &p.url,
        &with_session(),
        &json!({"jsonrpc":"2.0","id":"srv-1","result":{"roots":[]}}),
    );
    assert_eq!(a.status, 202);

    let d = finish(
        agent()
            .delete(&p.url)
            .header("Mcp-Session-Id", &sid)
            .call()
            .unwrap(),
    );
    assert_eq!(d.status, 200);
    let del = log
        .lock()
        .unwrap()
        .iter()
        .find(|s| s.method == "DELETE")
        .cloned()
        .unwrap();
    assert_eq!(del.header("mcp-session-id"), Some(SESSION));
    // Upstream errors are relayed (session-less request → 400 from upstream).
    let bad = post(
        &p.url,
        &[],
        &json!({"jsonrpc":"2.0","id":8,"method":"tools/list"}),
    );
    assert_eq!(bad.status, 400);
}

#[test]
fn upstream_down_fails_closed_with_structured_error() {
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}/mcp", l.local_addr().unwrap())
    }; // listener dropped: connection refused
    let p = start_proxy(
        streamable(&dead, CredentialStore::new()),
        HttpProxyOptions::default(),
    );
    let r = post(&p.url, &[], &call(11, "echo"));
    assert_eq!(r.status, 200);
    let v = r.json();
    assert_eq!(v["id"], 11);
    assert_eq!(v["error"]["code"], PROVIO_UPSTREAM_ERROR_CODE);
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("fail closed"));
    let rec = p.records.lock().unwrap();
    assert_eq!(rec.decisions.len(), 1);
    assert!(rec.executions.is_empty(), "no execution without a result");
    drop(rec);
    let n = post(
        &p.url,
        &[],
        &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    assert_eq!(n.status, 502);
}

#[test]
fn mirrored_header_mismatch_is_refused_without_a_decision() {
    let (up, log, _s) = fake_upstream();
    let p = start_proxy(
        streamable(&up, CredentialStore::new()),
        HttpProxyOptions::default(),
    );
    let r = post(
        &p.url,
        &[("Mcp-Method", "tools/call"), ("Mcp-Name", "echo")],
        &call(1, "danger"),
    );
    assert_eq!(r.status, 400);
    assert_eq!(r.json()["error"]["code"], HEADER_MISMATCH_CODE);
    let ok = post(
        &p.url,
        &[
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "=?base64?ZGFuZ2Vy?="),
        ],
        &call(2, "danger"),
    );
    assert_eq!(ok.json()["error"]["code"], PROVIO_REFUSAL_CODE);
    assert!(log.lock().unwrap().is_empty());
    assert_eq!(p.records.lock().unwrap().decisions.len(), 1);
}

#[test]
fn batches_follow_protocol_version_rules() {
    let (up, log, _s) = fake_upstream();
    let p = start_proxy(
        streamable(&up, CredentialStore::new()),
        HttpProxyOptions::default(),
    );
    handshake(&p.url);
    let batch =
        json!([call(20, "echo"), call(21, "danger"), {"jsonrpc":"2.0","method":"notifications/x"}]);
    let rejected = post(&p.url, &with_session(), &batch);
    assert_eq!(rejected.status, 400, "batches are not part of 2025-11-25");

    let r = post(
        &p.url,
        &[
            ("Mcp-Session-Id", SESSION),
            ("MCP-Protocol-Version", "2025-03-26"),
        ],
        &batch,
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let arr = r.json();
    let arr = arr.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["id"], 20);
    assert!(arr[0]["result"].is_object());
    assert_eq!(arr[1]["error"]["code"], PROVIO_REFUSAL_CODE);
    assert_eq!(tools_calls(&log).len(), 1);
}

#[test]
fn oversized_and_non_json_bodies_are_rejected() {
    let (up, _log, _s) = fake_upstream();
    let p = start_proxy(
        streamable(&up, CredentialStore::new()),
        HttpProxyOptions {
            limits: Limits {
                max_body_bytes: 1024,
                ..Limits::default()
            },
            ..Default::default()
        },
    );
    let big = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"x":"a".repeat(4096)}}});
    let r = agent()
        .post(&p.url)
        .header("Content-Type", "application/json")
        .send(big.to_string());
    if let Ok(r) = r {
        assert_eq!(r.status().as_u16(), 413);
    } // (a reset before the body is fully sent is also a rejection)
    let r = finish(
        agent()
            .post(&p.url)
            .header("Content-Type", "text/plain")
            .send("hi")
            .unwrap(),
    );
    assert_eq!(r.status, 415);
    assert!(p.records.lock().unwrap().decisions.is_empty());
}

// ------------------------------------------------------------ legacy SSE

/// A 2024-11-05 HTTP+SSE server: GET /sse → `endpoint` event, then
/// responses as `message` events; POST /messages → 202. POST to /sse → 405.
fn fake_legacy_upstream() -> (String, Log, ShutdownHandle) {
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let log2 = Arc::clone(&log);
    let (tx, rx) = mpsc::channel::<String>();
    let tx = Mutex::new(tx);
    let rx = Mutex::new(Some(rx));
    let handler = move |req: &Request, resp: Responder<'_>| -> std::io::Result<()> {
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        log2.lock().unwrap().push(Seen {
            method: req.method.clone(),
            headers: req.headers.clone(),
            body: body.clone(),
        });
        match (req.method.as_str(), req.path()) {
            ("GET", "/sse") => {
                let Some(rx) = rx.lock().unwrap().take() else {
                    return resp.send(409, &[], b"");
                };
                let mut s =
                    resp.stream(200, &[("Content-Type".into(), "text/event-stream".into())])?;
                s.write(
                    &SseEvent {
                        event: Some("endpoint".into()),
                        data: "/messages?sessionId=L1".into(),
                        ..Default::default()
                    }
                    .encode(),
                )?;
                while let Ok(data) = rx.recv() {
                    s.write(
                        &SseEvent {
                            event: Some("message".into()),
                            data,
                            ..Default::default()
                        }
                        .encode(),
                    )?;
                }
                s.finish()
            }
            ("POST", "/messages") => {
                assert_eq!(req.target, "/messages?sessionId=L1");
                if let (Some(id), Some(m)) = (body.get("id"), body["method"].as_str()) {
                    let r = match m {
                        "tools/call" => result(
                            id,
                            json!({"content":[{"type":"text","text":format!("legacy {SSN}")}]}),
                        ),
                        _ => result(
                            id,
                            json!({"protocolVersion":"2024-11-05","capabilities":{}}),
                        ),
                    };
                    let tx = tx.lock().unwrap().clone();
                    let note = json!({"jsonrpc":"2.0","method":"notifications/message","params":{"data":"hi"}});
                    let _ = tx.send(note.to_string());
                    let _ = tx.send(r.to_string());
                }
                resp.send(202, &[], b"Accepted")
            }
            ("POST", "/sse") => resp.send(405, &[], b"Method Not Allowed"),
            _ => resp.send(404, &[], b""),
        }
    };
    let (addr, stop) = server::spawn("127.0.0.1:0", Limits::default(), Arc::new(handler)).unwrap();
    (format!("http://{addr}/sse"), log, stop)
}

#[test]
fn legacy_sse_upstream_is_detected_and_governed() {
    let (up, log, _s) = fake_legacy_upstream();
    let mut creds = CredentialStore::new();
    creds.add("fake", "BEARER_TOKEN", SecretString::new("legacy-secret"));
    let upstream: Arc<dyn Upstream> = Arc::new(AutoUpstream::new(
        &up,
        "fake",
        Arc::new(creds),
        UpstreamOptions {
            connect_timeout: Duration::from_secs(5),
            response_timeout: Duration::from_secs(10),
            ..Default::default()
        },
    ));
    let p = start_proxy(upstream, HttpProxyOptions::default());
    let init = post(
        &p.url,
        &[],
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}),
    );
    assert_eq!(init.status, 200, "{}", init.body);
    assert_eq!(init.json()["result"]["protocolVersion"], "2024-11-05");

    let r = post(&p.url, &[], &call(2, "pii"));
    let v = r.json();
    assert_eq!(v["id"], 2);
    assert!(v["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("[redacted-by-provio]"));
    let refused = post(&p.url, &[], &call(3, "danger"));
    assert_eq!(refused.json()["error"]["code"], PROVIO_REFUSAL_CODE);

    let rec = p.records.lock().unwrap();
    assert_eq!(rec.decisions.len(), 2);
    assert_eq!(
        rec.decisions[0].server.as_ref().unwrap().transport,
        "http+sse"
    );
    assert_eq!(rec.executions.len(), 1);
    drop(rec);
    let l = log.lock().unwrap();
    assert_eq!(
        l.iter()
            .filter(|s| s.body["method"] == "tools/call")
            .count(),
        1,
        "refused call never reached the legacy upstream"
    );
    // Every upstream request (probe, SSE GET, message POSTs) carried the
    // injected credential.
    assert!(l
        .iter()
        .all(|s| s.header("authorization") == Some("Bearer legacy-secret")));
}
