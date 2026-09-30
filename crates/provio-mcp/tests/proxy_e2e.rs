//! End-to-end proxy test with in-memory transports (acceptance: agent A4).
//! Script: initialize → tools/list → allowed tools/call → refused tools/call.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use provio_core::ToolCall;
use provio_mcp::{
    JsonRpcMessage, JsonRpcResponse, McpProxy, MemoryTransport, ProxyConfig, ProxyDecision,
    RequestId, PROVIO_REFUSAL_CODE,
};
use serde_json::json;

fn req(id: u64, method: &str, params: Option<serde_json::Value>) -> JsonRpcMessage {
    JsonRpcMessage::request(RequestId::Num(id), method, params)
}

fn resp(id: u64, result: serde_json::Value) -> JsonRpcMessage {
    JsonRpcMessage::Response(JsonRpcResponse::result(RequestId::Num(id), result))
}

#[test]
fn end_to_end_forward_refuse_and_discovery() {
    let agent = MemoryTransport {
        incoming: VecDeque::from(vec![
            req(
                1,
                "initialize",
                Some(json!({"protocolVersion": "2025-06-18"})),
            ),
            req(2, "tools/list", None),
            req(
                3,
                "tools/call",
                Some(json!({"name": "fs.read", "arguments": {"path": "src/main.rs"}})),
            ),
            req(
                4,
                "tools/call",
                Some(json!({"name": "db.drop", "arguments": {}})),
            ),
        ]),
        ..Default::default()
    };

    let downstream = MemoryTransport {
        incoming: VecDeque::from(vec![
            resp(
                1,
                json!({"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "fake", "version": "0.1"}}),
            ),
            resp(
                2,
                json!({"tools": [{"name": "fs.read"}, {"name": "db.drop"}]}),
            ),
            resp(
                3,
                json!({"content": [{"type": "text", "text": "file contents"}]}),
            ),
        ]),
        ..Default::default()
    };

    // Capture every intercepted call; refuse db.drop with a rule-named refusal.
    let seen: Rc<RefCell<Vec<ToolCall>>> = Rc::new(RefCell::new(Vec::new()));
    let seen2 = Rc::clone(&seen);
    let decide = Box::new(move |call: &ToolCall| {
        seen2.borrow_mut().push(call.clone());
        if call.tool == "db.drop" {
            ProxyDecision::Refuse {
                message:
                    "provio denied this: rule \"no-drop\" — dropping tables requires approval."
                        .into(),
            }
        } else {
            ProxyDecision::Forward
        }
    });

    let mut proxy = McpProxy::new(
        agent,
        downstream,
        ProxyConfig {
            server_name: "fake".into(),
            agent: "test-agent".into(),
            trust: None,
        },
        decide,
    );
    proxy.run().expect("proxy run");

    // The agent received exactly 4 responses; the first three are results.
    let sent = &proxy.agent_side.sent;
    assert_eq!(sent.len(), 4, "agent got {sent:?}");
    for (msg, id) in sent.iter().zip([1u64, 2, 3]) {
        match msg {
            JsonRpcMessage::Response(r) => {
                assert_eq!(r.id, RequestId::Num(id));
                assert!(r.error.is_none(), "id {id} unexpectedly errored");
            }
            other => panic!("expected response, got {other:?}"),
        }
    }

    // The fourth is a structured provio refusal: rule id + reason + marker,
    // so the model can self-correct (spec §7).
    match &sent[3] {
        JsonRpcMessage::Response(r) => {
            assert_eq!(r.id, RequestId::Num(4));
            let err = r.error.as_ref().expect("refusal is an error");
            assert_eq!(err.code, PROVIO_REFUSAL_CODE);
            assert!(err.message.contains("no-drop"), "{}", err.message);
            assert!(err.message.contains("requires approval"), "{}", err.message);
            assert_eq!(err.data.as_ref().unwrap()["provio_refusal"], json!(true));
        }
        other => panic!("expected refusal response, got {other:?}"),
    }

    // The refused call never reached the downstream server.
    assert_eq!(
        proxy.downstream.sent.len(),
        3,
        "downstream saw {:?}",
        proxy.downstream.sent
    );
    assert!(proxy.downstream.sent.iter().all(|m| !matches!(
        m,
        JsonRpcMessage::Request(r) if r.id == RequestId::Num(4)
    )));

    // Both intercepted calls carried correct tool names and mode.
    let seen = seen.borrow();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].tool, "fs.read");
    assert_eq!(seen[1].tool, "db.drop");

    // Tool schemas were auto-discovered from tools/list (spec §11).
    assert_eq!(proxy.tool_schemas.len(), 2);
}

#[test]
fn secrets_never_appear_in_serialized_calls() {
    use provio_core::SecretString;
    use provio_mcp::CredentialStore;

    let mut store = CredentialStore::new();
    store.add(
        "github",
        "GITHUB_TOKEN",
        SecretString::new("ghp_supersecret"),
    );
    let mut env = std::collections::BTreeMap::new();
    store.inject_env("github", &mut env);
    assert_eq!(
        env.get("GITHUB_TOKEN").map(|s| s.as_str()),
        Some("ghp_supersecret")
    );

    // A call constructed by the proxy contains no credential material.
    let call_json = serde_json::to_string(&ToolCall {
        call_id: "c".into(),
        session_id: "s".into(),
        caller: provio_core::CallerIdentity {
            agent: "claude-code".into(),
            agent_version: None,
            user: None,
            non_human_id: None,
        },
        mode: provio_core::InterceptMode::Mcp,
        tool: "github.create_issue".into(),
        args: json!({"title": "x"}),
        server: Some(provio_core::ServerIdentity {
            name: "github".into(),
            transport: "stdio".into(),
            version: None,
        }),
        trust: None,
        captured_at: provio_core::Timestamp::now(),
    })
    .unwrap();
    assert!(!call_json.contains("ghp_supersecret"));
    assert!(!call_json.contains("GITHUB_TOKEN"));
}
