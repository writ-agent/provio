//! The MCP proxy core (interception mode A, spec §6/§11): an MCP server to
//! the agent, an MCP client to the real server. `tools/call` is intercepted
//! and routed through a decision callback; everything else passes through.
//!
//! The decision pipeline lives in [`Interceptor`], which knows nothing about
//! framing: the stdio proxy ([`McpProxy`]) and the Streamable HTTP proxy
//! (`crate::http`) both drive the same interceptor, so every transport gets
//! the same decide → record → forward/refuse → observe → redact sequence.
//!
//! stdio limitation (documented): downstream-initiated requests
//! (server→agent) are answered with method-not-found, not proxied.

use std::ops::{Deref, DerefMut};

use provio_core::call::{CallerIdentity, InterceptMode, ServerIdentity, ToolCall, TrustVerdict};
use provio_core::{ProvioError, Result, Timestamp};
use serde_json::Value;

use crate::jsonrpc::{JsonRpcError, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId};
use crate::pins::ToolPins;
use crate::transport::Transport;

/// What policy decided about one `tools/call`.
pub enum ProxyDecision {
    Forward,
    /// Full structured refusal message (rule id + reason), shown to the
    /// model so it can self-correct (spec §7).
    Refuse {
        message: String,
    },
}

/// Configuration for one proxied downstream server.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub server_name: String,
    /// Human name of the agent product on the upstream side.
    pub agent: String,
    pub trust: Option<TrustVerdict>,
}

/// JSON-RPC error code used for provio refusals (server-defined range).
pub const PROVIO_REFUSAL_CODE: i64 = -32043;

pub type DecisionHook = Box<dyn FnMut(&ToolCall) -> ProxyDecision>;
pub type ObserveHook = Box<dyn FnMut(&ToolCall, &Value)>;
pub type TransformHook = Box<dyn FnMut(&ToolCall, Value) -> Value>;
/// Records a call the interceptor refused before policy ran (a held tool):
/// `(call, rule_id, reason)`.
pub type RefusalHook = Box<dyn FnMut(&ToolCall, &str, &str)>;

/// Rule id recorded when a call to a held (changed, unaccepted) tool is
/// refused.
pub const TOOL_PIN_RULE: &str = "mcp-tool-pin";

/// Outcome of intercepting one `tools/call` request.
pub enum Interception {
    /// Policy allowed (or redact-allowed) the call: forward the request
    /// unchanged and route its response through [`Interceptor::complete`].
    Forward(ToolCall),
    /// Policy refused: send this structured JSON-RPC error to the agent and
    /// never forward the request.
    Refused(JsonRpcResponse),
}

/// Transport-agnostic `tools/call` interception: decision, observation
/// (execution record) and result transform (redaction).
pub struct Interceptor {
    pub config: ProxyConfig,
    pub session_id: String,
    /// Auto-discovered downstream tool schemas (spec §11), populated on
    /// tools/list responses.
    pub tool_schemas: Vec<Value>,
    /// Transport label recorded in `ToolCall.server.transport`.
    pub transport: String,
    decide: DecisionHook,
    observe: Option<ObserveHook>,
    /// Result transform applied BEFORE the result re-enters the agent's
    /// context (the `redact` verdict, spec §7). The observation hook sees the
    /// original; the agent sees the transform's output.
    transform: Option<TransformHook>,
    /// Tool definition pins (see [`crate::pins`]); `None` disables pinning.
    pins: Option<ToolPins>,
    refused: Option<RefusalHook>,
}

impl Interceptor {
    pub fn new(config: ProxyConfig, transport: &str, decide: DecisionHook) -> Self {
        let session_id = format!("mcp-{}-{}", std::process::id(), Timestamp::now().epoch_ms());
        Interceptor {
            config,
            session_id,
            tool_schemas: Vec::new(),
            transport: transport.to_string(),
            decide,
            observe: None,
            transform: None,
            pins: None,
            refused: None,
        }
    }

    /// Pin tool definitions (trust on first use): changed tools are hidden
    /// from `tools/list` and their calls refused until accepted.
    pub fn set_pins(&mut self, pins: ToolPins) {
        self.pins = Some(pins);
    }

    pub fn pins(&self) -> Option<&ToolPins> {
        self.pins.as_ref()
    }

    /// Record calls refused before policy ran (a held tool), so every
    /// intercepted call still gets exactly one decision record.
    pub fn on_refusal(&mut self, hook: RefusalHook) {
        self.refused = Some(hook);
    }

    pub fn on_result(&mut self, hook: ObserveHook) {
        self.observe = Some(hook);
    }

    /// Register the redaction transform (see field docs for ordering).
    pub fn set_result_transform(&mut self, hook: TransformHook) {
        self.transform = Some(hook);
    }

    /// Build the ToolCall for a `tools/call` request. `call_id` defaults to
    /// `<session>:<request id>` (unique on a single stdio connection);
    /// transports multiplexing several agent sessions pass their own.
    pub fn make_call(&self, req: &JsonRpcRequest, call_id: Option<String>) -> ToolCall {
        let params = req.params.clone().unwrap_or(Value::Null);
        ToolCall {
            call_id: call_id.unwrap_or_else(|| format!("{}:{}", self.session_id, req.id)),
            session_id: self.session_id.clone(),
            caller: CallerIdentity {
                agent: self.config.agent.clone(),
                agent_version: None,
                user: std::env::var("USER")
                    .or_else(|_| std::env::var("USERNAME"))
                    .ok(),
                non_human_id: None,
            },
            mode: InterceptMode::Mcp,
            tool: params
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("<unknown>")
                .to_string(),
            args: params.get("arguments").cloned().unwrap_or(Value::Null),
            server: Some(ServerIdentity {
                name: self.config.server_name.clone(),
                transport: self.transport.clone(),
                version: None,
            }),
            trust: self.config.trust,
            captured_at: Timestamp::now(),
        }
    }

    /// Run the decision hook for one `tools/call` (exactly one decision per
    /// call: the hook records it).
    pub fn intercept(&mut self, req: &JsonRpcRequest, call_id: Option<String>) -> Interception {
        let call = self.make_call(req, call_id);
        if let Some(held) = self.pins.as_ref().and_then(|p| p.held(&call.tool)) {
            let reason = format!(
                "The definition of MCP tool `{}` on server `{}` changed since it was pinned \
                 (new definition first seen {}). A changed tool description can carry \
                 instructions to the model, so provio holds the tool until a human reviews it: \
                 `provio mcp pins --server {}` shows the change, `provio mcp accept {} {}` trusts it.",
                call.tool,
                self.config.server_name,
                held.seen_at,
                self.config.server_name,
                self.config.server_name,
                call.tool
            );
            if let Some(hook) = &mut self.refused {
                hook(&call, TOOL_PIN_RULE, &reason);
            }
            return Interception::Refused(refusal(
                req.id.clone(),
                format!("provio refused this call: rule \"{TOOL_PIN_RULE}\" — {reason}"),
            ));
        }
        match (self.decide)(&call) {
            ProxyDecision::Forward => Interception::Forward(call),
            ProxyDecision::Refuse { message } => {
                Interception::Refused(refusal(req.id.clone(), message))
            }
        }
    }

    /// A forwarded call's response arrived: observe the ORIGINAL result
    /// (the ledger hashes the unmasked output — spec §7 records "a hash of
    /// the original"), then transform (redact) before the agent sees it.
    pub fn complete(&mut self, call: &ToolCall, mut resp: JsonRpcResponse) -> JsonRpcResponse {
        if let (Some(hook), Some(result)) = (&mut self.observe, resp.result.as_ref()) {
            hook(call, result);
        }
        if let (Some(t), Some(result)) = (&mut self.transform, resp.result.take()) {
            resp.result = Some(t(call, result));
        }
        resp
    }

    /// Apply only the result transform to a value produced while `call` was
    /// in flight (e.g. a progress/log notification's params). Used so a
    /// redact verdict also covers request-scoped notifications.
    pub fn mask(&mut self, call: &ToolCall, value: Value) -> Value {
        match &mut self.transform {
            Some(t) => t(call, value),
            None => value,
        }
    }

    /// Passive observation of non-intercepted responses (schema discovery).
    pub fn observe_response(&mut self, method: &str, resp: &JsonRpcResponse) {
        if method == "tools/list" {
            if let Some(tools) = resp
                .result
                .as_ref()
                .and_then(|r| r.get("tools"))
                .and_then(|t| t.as_array())
            {
                self.tool_schemas = tools.clone();
            }
        }
    }

    /// Observe a non-intercepted response and, for `tools/list` with
    /// pinning on, pin new tools and remove held (changed) ones from what
    /// the agent sees.
    pub fn filter_response(&mut self, method: &str, resp: &mut JsonRpcResponse) {
        self.observe_response(method, resp);
        if method != "tools/list" {
            return;
        }
        let Some(pins) = self.pins.as_mut() else {
            return;
        };
        let Some(tools) = resp
            .result
            .as_mut()
            .and_then(|r| r.get_mut("tools"))
            .and_then(|t| t.as_array_mut())
        else {
            return;
        };
        let obs = pins.observe(tools);
        if !obs.pinned.is_empty() {
            tracing::info!(server = %self.config.server_name, tools = ?obs.pinned, "pinned new MCP tools");
            eprintln!(
                "  provio · pinned {} tool definition(s) of `{}` on first use",
                obs.pinned.len(),
                self.config.server_name
            );
        }
        if !obs.changed.is_empty() {
            eprintln!(
                "  \x1b[33mprovio · `{}` changed the definition of: {} — held (hidden from the agent) until `provio mcp accept {}`\x1b[0m",
                self.config.server_name,
                obs.changed.join(", "),
                self.config.server_name
            );
            tools.retain(|t| {
                t.get("name")
                    .and_then(Value::as_str)
                    .is_none_or(|n| !obs.changed.iter().any(|c| c == n))
            });
        }
    }
}

/// The structured provio refusal the agent receives for a refused call.
pub fn refusal(id: RequestId, message: String) -> JsonRpcResponse {
    JsonRpcResponse::error(
        id,
        JsonRpcError {
            code: PROVIO_REFUSAL_CODE,
            message,
            data: Some(serde_json::json!({ "provio_refusal": true })),
        },
    )
}

/// The stdio proxy: one agent connection, one downstream connection.
pub struct McpProxy<A: Transport, D: Transport> {
    /// Public so tests and the CLI can inspect traffic after `run`.
    pub agent_side: A,
    pub downstream: D,
    core: Interceptor,
}

/// `proxy.config`, `proxy.session_id`, `proxy.tool_schemas` read through to
/// the shared interceptor.
impl<A: Transport, D: Transport> Deref for McpProxy<A, D> {
    type Target = Interceptor;
    fn deref(&self) -> &Interceptor {
        &self.core
    }
}

impl<A: Transport, D: Transport> DerefMut for McpProxy<A, D> {
    fn deref_mut(&mut self) -> &mut Interceptor {
        &mut self.core
    }
}

impl<A: Transport, D: Transport> McpProxy<A, D> {
    pub fn new(agent_side: A, downstream: D, config: ProxyConfig, decide: DecisionHook) -> Self {
        Self::with_interceptor(
            agent_side,
            downstream,
            Interceptor::new(config, "stdio", decide),
        )
    }

    /// Build the proxy around an already-wired interceptor.
    pub fn with_interceptor(agent_side: A, downstream: D, core: Interceptor) -> Self {
        McpProxy {
            agent_side,
            downstream,
            core,
        }
    }

    pub fn on_result(&mut self, hook: ObserveHook) {
        self.core.on_result(hook);
    }

    /// Register the redaction transform (see [`Interceptor`] docs).
    pub fn set_result_transform(&mut self, hook: TransformHook) {
        self.core.set_result_transform(hook);
    }

    /// Forward a request downstream and wait for its response. Server→agent
    /// notifications received while waiting are relayed (through `mask` when
    /// a tool call is in flight); server→agent requests get method-not-found
    /// (documented limitation above).
    fn roundtrip(
        &mut self,
        req: &JsonRpcRequest,
        call: Option<&ToolCall>,
    ) -> Result<JsonRpcResponse> {
        self.downstream
            .send(&JsonRpcMessage::Request(req.clone()))?;
        loop {
            match self.downstream.recv()? {
                Some(JsonRpcMessage::Response(resp)) => {
                    if resp.id == req.id {
                        return Ok(resp);
                    }
                    tracing::warn!(id = %resp.id, "dropping unmatched downstream response");
                }
                Some(JsonRpcMessage::Notification(mut n)) => {
                    if let (Some(call), Some(p)) = (call, n.params.take()) {
                        n.params = Some(self.core.mask(call, p));
                    }
                    self.agent_side.send(&JsonRpcMessage::Notification(n))?;
                }
                Some(JsonRpcMessage::Request(r)) => {
                    let err = JsonRpcResponse::error(
                        r.id,
                        JsonRpcError {
                            code: -32601,
                            message:
                                "provio proxy: server-initiated requests are not proxied over stdio"
                                    .into(),
                            data: None,
                        },
                    );
                    self.downstream.send(&JsonRpcMessage::Response(err))?;
                }
                None => {
                    return Err(ProvioError::Intercept(match call {
                        Some(_) => "downstream closed during tools/call".into(),
                        None => "downstream closed while awaiting response".into(),
                    }))
                }
            }
        }
    }

    fn forward_request(&mut self, req: &JsonRpcRequest) -> Result<()> {
        let mut resp = self.roundtrip(req, None)?;
        self.core.filter_response(&req.method, &mut resp);
        self.agent_side.send(&JsonRpcMessage::Response(resp))
    }

    /// Intercept a `tools/call`: ask the decider, then forward or refuse.
    fn handle_tool_call(&mut self, req: &JsonRpcRequest) -> Result<()> {
        match self.core.intercept(req, None) {
            Interception::Forward(call) => {
                let resp = self.roundtrip(req, Some(&call))?;
                let resp = self.core.complete(&call, resp);
                self.agent_side.send(&JsonRpcMessage::Response(resp))
            }
            Interception::Refused(resp) => self.agent_side.send(&JsonRpcMessage::Response(resp)),
        }
    }

    /// Run the proxy loop until the agent closes the connection (EOF).
    pub fn run(&mut self) -> Result<()> {
        loop {
            match self.agent_side.recv()? {
                None => return Ok(()),
                Some(JsonRpcMessage::Request(req)) => {
                    if req.method == "tools/call" {
                        self.handle_tool_call(&req)?;
                    } else {
                        self.forward_request(&req)?;
                    }
                }
                Some(JsonRpcMessage::Notification(n)) => {
                    self.downstream.send(&JsonRpcMessage::Notification(n))?;
                }
                Some(JsonRpcMessage::Response(resp)) => {
                    // Agent answering a server-initiated request; forward.
                    self.downstream.send(&JsonRpcMessage::Response(resp))?;
                }
            }
        }
    }
}
