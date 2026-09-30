//! The Streamable HTTP proxy: an MCP Streamable HTTP *server* to the agent
//! and an MCP HTTP *client* to the upstream server.
//!
//! Threading: connections are served on their own threads; the
//! [`Interceptor`] (policy decision, ledger records, redaction) lives on the
//! thread that calls [`HttpProxy::run`] and is driven through a job
//! channel. Decisions and ledger writes are therefore serialized exactly as
//! in the stdio proxy, and the interceptor's hooks need not be `Send`.
//!
//! Per request:
//! * `POST` a `tools/call` → one decision (via the interceptor). Refused →
//!   structured JSON-RPC refusal, never forwarded. Forwarded → the response
//!   (JSON body, or the matching event of an SSE stream) is observed
//!   (execution record, output hash of the original) and transformed
//!   (redact) before it is written to the agent; request-scoped
//!   notifications on that stream are masked too.
//! * Any other `POST`, `GET` (server stream / resumption) and `DELETE`
//!   (session end) are relayed. A `tools/call` response that arrives on a
//!   *different* stream (e.g. replayed after `Last-Event-ID` resumption) is
//!   still recognised by (session, id) and goes through the same path.
//! * The body forwarded upstream is the re-serialization of what policy
//!   evaluated, never the agent's raw bytes (no parser differentials).

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use serde_json::{json, Value};
use writ_core::{SecretString, ToolCall};

use crate::http::server::{self, Limits, Request, Responder, ShutdownHandle};
use crate::http::sse::SseEvent;
use crate::http::upstream::{Reply, Upstream};
use crate::jsonrpc::{JsonRpcError, JsonRpcMessage, JsonRpcRequest, JsonRpcResponse, RequestId};
use crate::proxy::{Interception, Interceptor};

/// JSON-RPC error code for "the upstream could not be reached or answered
/// unusably" (fail closed). Server-defined range, next to the refusal code.
pub const WRIT_UPSTREAM_ERROR_CODE: i64 = -32044;
/// MCP `HeaderMismatch` (2026-07-28): mirrored headers disagree with body.
pub const HEADER_MISMATCH_CODE: i64 = -32020;

/// Agent-facing settings.
pub struct HttpProxyOptions {
    /// The MCP endpoint path (default `/mcp`).
    pub path: String,
    /// Accept non-loopback `Host` headers (the listener is not loopback).
    pub allow_remote: bool,
    /// Extra `Origin` values accepted besides loopback origins.
    pub allowed_origins: Vec<String>,
    /// When set, the agent must send `Authorization: Bearer <token>`.
    pub agent_token: Option<SecretString>,
    /// Forward the agent's own `Authorization` header upstream (off by
    /// default; never combined with `agent_token`). Credential headers
    /// configured for the server always win.
    pub forward_agent_auth: bool,
    pub limits: Limits,
}

impl Default for HttpProxyOptions {
    fn default() -> Self {
        HttpProxyOptions {
            path: "/mcp".into(),
            allow_remote: false,
            allowed_origins: Vec::new(),
            agent_token: None,
            forward_agent_auth: false,
            limits: Limits::default(),
        }
    }
}

enum Job {
    Intercept {
        req: JsonRpcRequest,
        seq: u64,
        transport: &'static str,
        reply: Sender<Interception>,
    },
    Complete {
        call: Box<ToolCall>,
        resp: JsonRpcResponse,
        reply: Sender<JsonRpcResponse>,
    },
    Mask {
        call: Box<ToolCall>,
        value: Value,
        reply: Sender<Value>,
    },
    Observe {
        method: String,
        resp: JsonRpcResponse,
        reply: Sender<JsonRpcResponse>,
    },
}

/// Forwarded tools/calls, keyed by (agent session id, JSON-RPC id).
struct Inflight {
    map: HashMap<(String, RequestId), (ToolCall, bool)>,
    order: VecDeque<(String, RequestId)>,
}

/// A reply reduced to (status, relayed headers, content type, body).
type Collapsed = (u16, Vec<(String, String)>, Option<String>, Vec<u8>);

const INFLIGHT_CAP: usize = 4096;
const MAX_BATCH: usize = 64;

impl Inflight {
    fn insert(&mut self, key: (String, RequestId), call: ToolCall) {
        if self.map.insert(key.clone(), (call, false)).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > INFLIGHT_CAP {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }

    fn remove(&mut self, key: &(String, RequestId)) {
        self.map.remove(key);
        self.order.retain(|k| k != key);
    }

    fn drop_session(&mut self, session: &str) {
        self.map.retain(|k, _| k.0 != session);
        self.order.retain(|k| k.0 != session);
    }
}

/// What a relay is answering.
#[derive(Clone)]
struct Ctx {
    session: String,
    /// The JSON-RPC id of the POSTed request (None for GET / notifications).
    req_id: Option<RequestId>,
    method: Option<String>,
    /// Set when the POSTed request is a forwarded tools/call.
    call: Option<ToolCall>,
}

struct Shared {
    opts: HttpProxyOptions,
    upstream: Arc<dyn Upstream>,
    jobs: Mutex<Sender<Job>>,
    seq: AtomicU64,
    inflight: Mutex<Inflight>,
}

/// The HTTP MCP proxy. Bind, report [`HttpProxy::url`], then [`HttpProxy::run`].
pub struct HttpProxy {
    listener: TcpListener,
    local: SocketAddr,
    opts: HttpProxyOptions,
    upstream: Arc<dyn Upstream>,
    shutdown: ShutdownHandle,
}

impl HttpProxy {
    pub fn bind(
        addr: &str,
        opts: HttpProxyOptions,
        upstream: Arc<dyn Upstream>,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let local = listener.local_addr()?;
        Ok(HttpProxy {
            listener,
            local,
            opts,
            upstream,
            shutdown: ShutdownHandle::new(local),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The MCP endpoint URL to give the agent.
    pub fn url(&self) -> String {
        format!("http://{}{}", self.local, self.opts.path)
    }

    pub fn shutdown_handle(&self) -> ShutdownHandle {
        self.shutdown.clone()
    }

    /// Serve until shut down. The interceptor runs on the calling thread.
    pub fn run(self, mut core: Interceptor) {
        let (tx, rx) = mpsc::channel::<Job>();
        let limits = self.opts.limits.clone();
        let shared = Arc::new(Shared {
            opts: self.opts,
            upstream: self.upstream,
            jobs: Mutex::new(tx),
            seq: AtomicU64::new(0),
            inflight: Mutex::new(Inflight {
                map: HashMap::new(),
                order: VecDeque::new(),
            }),
        });
        let handler: Arc<dyn server::Handler> = Arc::new(Gateway(Arc::clone(&shared)));
        let (listener, stop) = (self.listener, self.shutdown.clone());
        let accept = std::thread::Builder::new()
            .name("writ-mcp-http-accept".into())
            .spawn(move || server::serve(listener, limits, handler, stop));
        if accept.is_err() {
            tracing::error!("could not start the HTTP accept thread");
            return;
        }
        drop(shared);
        loop {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(job) => run_job(&mut core, job),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if self.shutdown.is_shutdown() {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }
}

fn run_job(core: &mut Interceptor, job: Job) {
    match job {
        Job::Intercept {
            req,
            seq,
            transport,
            reply,
        } => {
            core.transport = transport.to_string();
            let call_id = format!("{}:{}:{}", core.session_id, seq, req.id);
            let _ = reply.send(core.intercept(&req, Some(call_id)));
        }
        Job::Complete { call, resp, reply } => {
            let _ = reply.send(core.complete(&call, resp));
        }
        Job::Mask { call, value, reply } => {
            let _ = reply.send(core.mask(&call, value));
        }
        Job::Observe {
            method,
            mut resp,
            reply,
        } => {
            core.filter_response(&method, &mut resp);
            let _ = reply.send(resp);
        }
    }
}

struct Gateway(Arc<Shared>);

impl server::Handler for Gateway {
    fn handle(&self, req: &Request, resp: Responder<'_>) -> io::Result<()> {
        self.0.handle(req, resp)
    }
}

/// `{"jsonrpc":"2.0","id":…,"error":{…}}`; `id` omitted when unknown.
fn error_body(id: Option<&RequestId>, code: i64, message: &str) -> Vec<u8> {
    let mut v = json!({"jsonrpc": "2.0", "error": {"code": code, "message": message}});
    if let Some(id) = id {
        v["id"] = json!(id);
    }
    serde_json::to_vec(&v).unwrap_or_default()
}

fn json_headers(extra: &[(String, String)]) -> Vec<(String, String)> {
    let mut h = vec![("Content-Type".to_string(), "application/json".to_string())];
    h.extend(extra.iter().cloned());
    h
}

fn host_part(authority: &str) -> &str {
    let a = authority.trim();
    if let Some(rest) = a.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("");
    }
    match a.rsplit_once(':') {
        Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => a,
    }
}

fn is_loopback_name(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// `http://localhost:6274` → true; `https://evil.example` → false.
fn origin_is_loopback(origin: &str) -> bool {
    let Some((scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let authority = rest.split('/').next().unwrap_or("");
    is_loopback_name(host_part(authority))
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Decode an `Mcp-Name` / `Mcp-Param-*` value (`=?base64?…?=` sentinel).
fn decode_mirrored(v: &str) -> Option<String> {
    match v
        .strip_prefix("=?base64?")
        .and_then(|r| r.strip_suffix("?="))
    {
        Some(b64) => base64::engine::general_purpose::STANDARD
            .decode(b64)
            .ok()
            .and_then(|b| String::from_utf8(b).ok()),
        None => Some(v.to_string()),
    }
}

/// Headers forwarded from the agent to the upstream.
const FORWARD: &[&str] = &[
    "mcp-session-id",
    "mcp-protocol-version",
    "last-event-id",
    "mcp-method",
    "mcp-name",
];

impl Shared {
    fn job(&self, job: Job) -> bool {
        self.jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .send(job)
            .is_ok()
    }

    fn intercept(&self, req: &JsonRpcRequest) -> Interception {
        let (tx, rx) = mpsc::channel();
        let seq = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        let sent = self.job(Job::Intercept {
            req: req.clone(),
            seq,
            transport: self.upstream.kind(),
            reply: tx,
        });
        match (sent, rx.recv()) {
            (true, Ok(i)) => i,
            _ => Interception::Refused(crate::proxy::refusal(
                req.id.clone(),
                "writ internal error (fail closed): decision pipeline unavailable".into(),
            )),
        }
    }

    /// Complete (first sighting) or mask (repeat) a tools/call response;
    /// passively observe other responses to the POSTed request.
    fn finish_response(&self, ctx: &Ctx, mut r: JsonRpcResponse) -> JsonRpcResponse {
        let key = (ctx.session.clone(), r.id.clone());
        let state = {
            let mut inflight = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            inflight.map.get_mut(&key).map(|(call, done)| {
                let first = !*done;
                *done = true;
                (call.clone(), first)
            })
        };
        match state {
            Some((call, true)) => {
                let (tx, rx) = mpsc::channel();
                let fallback = withheld_response(r.id.clone());
                if self.job(Job::Complete {
                    call: Box::new(call),
                    resp: r,
                    reply: tx,
                }) {
                    rx.recv().unwrap_or(fallback)
                } else {
                    fallback
                }
            }
            Some((call, false)) => {
                if let Some(result) = r.result.take() {
                    r.result = Some(self.mask(&call, result));
                }
                r
            }
            None => {
                if let (Some(m), Some(id)) = (&ctx.method, &ctx.req_id) {
                    if *id == r.id {
                        // tools/list may be filtered (held tools removed), so
                        // wait for the interceptor; if it is gone, a
                        // tools/list is withheld rather than passed unfiltered.
                        let (tx, rx) = mpsc::channel();
                        let fallback = if m == "tools/list" {
                            withheld_response(r.id.clone())
                        } else {
                            r.clone()
                        };
                        if self.job(Job::Observe {
                            method: m.clone(),
                            resp: r,
                            reply: tx,
                        }) {
                            return rx.recv().unwrap_or(fallback);
                        }
                        return fallback;
                    }
                }
                r
            }
        }
    }

    fn mask(&self, call: &ToolCall, value: Value) -> Value {
        let (tx, rx) = mpsc::channel();
        if self.job(Job::Mask {
            call: Box::new(call.clone()),
            value,
            reply: tx,
        }) {
            if let Ok(v) = rx.recv() {
                return v;
            }
        }
        json!({"withheld_by_writ": true})
    }

    fn forward_headers(&self, req: &Request) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for (k, v) in &req.headers {
            let lower = k.to_ascii_lowercase();
            let pass = FORWARD.contains(&lower.as_str())
                || lower.starts_with("mcp-param-")
                || (lower == "authorization"
                    && self.opts.forward_agent_auth
                    && self.opts.agent_token.is_none());
            if pass {
                out.push((k.clone(), v.clone()));
            }
        }
        out
    }

    fn check_security(&self, req: &Request) -> Result<(), (u16, &'static str)> {
        if !self.opts.allow_remote {
            let host_ok = req
                .header("host")
                .map(|h| is_loopback_name(host_part(h)))
                .unwrap_or(false);
            if !host_ok {
                return Err((
                    403,
                    "writ proxy: Host is not a loopback name (DNS-rebinding guard)",
                ));
            }
        }
        if let Some(origin) = req.header("origin") {
            let listed = self.opts.allowed_origins.iter().any(|o| {
                o.trim_end_matches('/')
                    .eq_ignore_ascii_case(origin.trim_end_matches('/'))
            });
            if !listed && !origin_is_loopback(origin) {
                return Err((403, "writ proxy: Origin not allowed (DNS-rebinding guard)"));
            }
        }
        if let Some(token) = &self.opts.agent_token {
            let presented = req
                .header("authorization")
                .and_then(|a| {
                    a.strip_prefix("Bearer ")
                        .or_else(|| a.strip_prefix("bearer "))
                })
                .unwrap_or("");
            if !ct_eq(presented.trim().as_bytes(), token.expose().as_bytes()) {
                return Err((401, "writ proxy: missing or wrong proxy token"));
            }
        }
        Ok(())
    }

    fn handle(&self, req: &Request, resp: Responder<'_>) -> io::Result<()> {
        if req.path() != self.opts.path {
            return resp.send(404, &[], b"");
        }
        if let Err((status, msg)) = self.check_security(req) {
            tracing::warn!(status, peer = ?req.peer, "rejected agent request: {msg}");
            let mut headers = json_headers(&[]);
            if status == 401 {
                headers.push(("WWW-Authenticate".into(), "Bearer".into()));
            }
            return resp.send(status, &headers, &error_body(None, -32000, msg));
        }
        match req.method.as_str() {
            "POST" => self.post(req, resp),
            "GET" => {
                let ctx = Ctx {
                    session: session_of(req),
                    req_id: None,
                    method: None,
                    call: None,
                };
                match self.upstream.get(&self.forward_headers(req)) {
                    Ok(reply) => self.relay(reply, &ctx, resp, true),
                    Err(e) => resp.send(
                        502,
                        &json_headers(&[]),
                        &error_body(None, WRIT_UPSTREAM_ERROR_CODE, &upstream_msg(&e.0)),
                    ),
                }
            }
            "DELETE" => match self.upstream.delete(&self.forward_headers(req)) {
                Ok(reply) => {
                    if (200..300).contains(&reply.status()) {
                        self.inflight
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .drop_session(&session_of(req));
                    }
                    let ctx = Ctx {
                        session: session_of(req),
                        req_id: None,
                        method: None,
                        call: None,
                    };
                    self.relay(reply, &ctx, resp, false)
                }
                Err(e) => resp.send(
                    502,
                    &json_headers(&[]),
                    &error_body(None, WRIT_UPSTREAM_ERROR_CODE, &upstream_msg(&e.0)),
                ),
            },
            _ => resp.send(405, &[("Allow".into(), "GET, POST, DELETE".into())], b""),
        }
    }

    fn post(&self, req: &Request, resp: Responder<'_>) -> io::Result<()> {
        let ct = req
            .header("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        if !ct.starts_with("application/json") {
            return resp.send(
                415,
                &json_headers(&[]),
                &error_body(
                    None,
                    -32600,
                    "writ proxy: POST body must be application/json",
                ),
            );
        }
        let value: Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(_) => {
                return resp.send(
                    400,
                    &json_headers(&[]),
                    &error_body(None, -32700, "Parse error"),
                )
            }
        };
        let accepts_sse = req
            .header("accept")
            .map(|a| a.contains("text/event-stream") || a.contains("*/*"))
            .unwrap_or(false);
        if let Value::Array(items) = value {
            return self.batch(req, items, resp);
        }
        let msg: JsonRpcMessage = match serde_json::from_value(value) {
            Ok(m) => m,
            Err(_) => {
                return resp.send(
                    400,
                    &json_headers(&[]),
                    &error_body(None, -32600, "Invalid Request: not a JSON-RPC 2.0 message"),
                )
            }
        };
        if let Err(m) = check_mirrored(req, &msg) {
            let id = match &msg {
                JsonRpcMessage::Request(r) => Some(&r.id),
                _ => None,
            };
            return resp.send(
                400,
                &json_headers(&[]),
                &error_body(id, HEADER_MISMATCH_CODE, &m),
            );
        }
        let ctx = Ctx {
            session: session_of(req),
            req_id: None,
            method: None,
            call: None,
        };
        let fwd = self.forward_headers(req);
        match &msg {
            JsonRpcMessage::Request(r) => {
                let mut ctx = Ctx {
                    req_id: Some(r.id.clone()),
                    method: Some(r.method.clone()),
                    ..ctx
                };
                if r.method == "tools/call" {
                    match self.intercept(r) {
                        Interception::Refused(refusal) => {
                            let body = serde_json::to_vec(&JsonRpcMessage::Response(refusal))
                                .unwrap_or_default();
                            return resp.send(200, &json_headers(&[]), &body);
                        }
                        Interception::Forward(call) => {
                            self.inflight
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert((ctx.session.clone(), r.id.clone()), call.clone());
                            ctx.call = Some(call);
                        }
                    }
                }
                let body = serde_json::to_vec(&msg).unwrap_or_default();
                match self.upstream.post(&body, &fwd) {
                    Ok(reply) => self.relay(reply, &ctx, resp, accepts_sse),
                    Err(e) => {
                        if ctx.call.is_some() {
                            self.inflight
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&(ctx.session.clone(), r.id.clone()));
                        }
                        tracing::warn!(method = %r.method, "upstream unavailable: {}", e.0);
                        resp.send(
                            200,
                            &json_headers(&[]),
                            &error_body(Some(&r.id), WRIT_UPSTREAM_ERROR_CODE, &upstream_msg(&e.0)),
                        )
                    }
                }
            }
            _ => {
                let body = serde_json::to_vec(&msg).unwrap_or_default();
                match self.upstream.post(&body, &fwd) {
                    Ok(reply) => self.relay(reply, &ctx, resp, accepts_sse),
                    Err(e) => resp.send(
                        502,
                        &json_headers(&[]),
                        &error_body(None, WRIT_UPSTREAM_ERROR_CODE, &upstream_msg(&e.0)),
                    ),
                }
            }
        }
    }

    /// JSON-RPC batches (protocol 2025-03-26 only; removed in 2025-06-18):
    /// each element is decided and forwarded as its own POST, responses are
    /// collected into one JSON array.
    fn batch(&self, req: &Request, items: Vec<Value>, resp: Responder<'_>) -> io::Result<()> {
        if let Some(v) = req.header("mcp-protocol-version") {
            if v != "2025-03-26" {
                return resp.send(
                    400,
                    &json_headers(&[]),
                    &error_body(
                        None,
                        -32600,
                        &format!("Invalid Request: JSON-RPC batches are not part of MCP {v}"),
                    ),
                );
            }
        }
        if items.is_empty() || items.len() > MAX_BATCH {
            return resp.send(
                400,
                &json_headers(&[]),
                &error_body(None, -32600, "Invalid Request: empty or oversized batch"),
            );
        }
        let session = session_of(req);
        let fwd = self.forward_headers(req);
        let mut out: Vec<Value> = Vec::new();
        let mut relay_headers: Vec<(String, String)> = Vec::new();
        for item in items {
            let msg: JsonRpcMessage = match serde_json::from_value(item) {
                Ok(m) => m,
                Err(_) => {
                    out.push(json!({"jsonrpc": "2.0", "id": null,
                        "error": {"code": -32600, "message": "Invalid Request"}}));
                    continue;
                }
            };
            let JsonRpcMessage::Request(r) = &msg else {
                let body = serde_json::to_vec(&msg).unwrap_or_default();
                if let Err(e) = self.upstream.post(&body, &fwd) {
                    tracing::warn!("upstream unavailable for batched message: {}", e.0);
                }
                continue;
            };
            let mut ctx = Ctx {
                session: session.clone(),
                req_id: Some(r.id.clone()),
                method: Some(r.method.clone()),
                call: None,
            };
            if r.method == "tools/call" {
                match self.intercept(r) {
                    Interception::Refused(refusal) => {
                        out.push(
                            serde_json::to_value(JsonRpcMessage::Response(refusal))
                                .unwrap_or(Value::Null),
                        );
                        continue;
                    }
                    Interception::Forward(call) => {
                        self.inflight
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert((session.clone(), r.id.clone()), call.clone());
                        ctx.call = Some(call);
                    }
                }
            }
            let body = serde_json::to_vec(&msg).unwrap_or_default();
            match self.upstream.post(&body, &fwd) {
                Ok(reply) => {
                    let (_, headers, _, bytes) = self.collapse(reply, &ctx);
                    if relay_headers.is_empty() {
                        relay_headers = headers;
                    }
                    out.push(serde_json::from_slice(&bytes).unwrap_or_else(|_| {
                        json!({"jsonrpc": "2.0", "id": r.id,
                            "error": {"code": WRIT_UPSTREAM_ERROR_CODE,
                                      "message": "writ proxy: unusable upstream reply (withheld)"}})
                    }));
                }
                Err(e) => out.push(
                    serde_json::from_slice(&error_body(
                        Some(&r.id),
                        WRIT_UPSTREAM_ERROR_CODE,
                        &upstream_msg(&e.0),
                    ))
                    .unwrap_or(Value::Null),
                ),
            }
        }
        if out.is_empty() {
            return resp.send(202, &relay_headers, b"");
        }
        let body = serde_json::to_vec(&Value::Array(out)).unwrap_or_default();
        resp.send(200, &json_headers(&relay_headers), &body)
    }

    /// Rewrite one SSE event. Returns the event to emit (None = drop) and
    /// whether it carried the final response to the POSTed request.
    fn process_event(&self, ctx: &Ctx, mut ev: SseEvent) -> (Option<SseEvent>, bool) {
        if ev.data.is_empty() {
            return (Some(ev), false); // priming event, retry hint, keep-alive
        }
        let foreign_type = ev.event.as_deref().is_some_and(|e| e != "message");
        let parsed = if foreign_type {
            None
        } else {
            serde_json::from_str::<JsonRpcMessage>(&ev.data).ok()
        };
        let Some(msg) = parsed else {
            if ctx.call.is_some() {
                // Cannot be inspected, so cannot be redacted: withhold.
                tracing::warn!("dropping an uninspectable SSE event on a tools/call stream");
                return (None, false);
            }
            return (Some(ev), false);
        };
        let (out, is_final) = match msg {
            JsonRpcMessage::Response(r) => {
                let is_final = ctx.req_id.as_ref() == Some(&r.id);
                (
                    JsonRpcMessage::Response(self.finish_response(ctx, r)),
                    is_final,
                )
            }
            JsonRpcMessage::Notification(mut n) => {
                if let (Some(call), Some(p)) = (&ctx.call, n.params.take()) {
                    n.params = Some(self.mask(call, p));
                }
                (JsonRpcMessage::Notification(n), false)
            }
            JsonRpcMessage::Request(mut q) => {
                if let (Some(call), Some(p)) = (&ctx.call, q.params.take()) {
                    q.params = Some(self.mask(call, p));
                }
                (JsonRpcMessage::Request(q), false)
            }
        };
        ev.data = serde_json::to_string(&out).unwrap_or_default();
        (Some(ev), is_final)
    }

    /// Rewrite a complete (non-SSE) upstream body.
    fn rewrite_full(
        &self,
        ctx: &Ctx,
        status: u16,
        ctype: Option<String>,
        body: Vec<u8>,
    ) -> (u16, Option<String>, Vec<u8>) {
        if body.is_empty() {
            return (status, ctype, body);
        }
        let is_json = ctype
            .as_deref()
            .map(|c| c.to_ascii_lowercase().starts_with("application/json"))
            .unwrap_or(false);
        if is_json {
            if let Ok(JsonRpcMessage::Response(r)) = serde_json::from_slice::<JsonRpcMessage>(&body)
            {
                let r = self.finish_response(ctx, r);
                let bytes = serde_json::to_vec(&JsonRpcMessage::Response(r)).unwrap_or_default();
                return (status, ctype, bytes);
            }
        }
        match (&ctx.call, &ctx.req_id) {
            (Some(_), Some(id)) => {
                tracing::warn!(
                    status,
                    "withholding an unparseable upstream reply to tools/call"
                );
                let status = if (200..300).contains(&status) {
                    200
                } else {
                    status
                };
                (
                    status,
                    Some("application/json".into()),
                    serde_json::to_vec(&JsonRpcMessage::Response(withheld_response(id.clone())))
                        .unwrap_or_default(),
                )
            }
            _ => (status, ctype, body),
        }
    }

    /// Reduce any reply to one complete body (for batches and for agents
    /// that do not accept SSE).
    fn collapse(&self, reply: Reply, ctx: &Ctx) -> Collapsed {
        match reply {
            Reply::Full {
                status,
                headers,
                content_type,
                body,
            } => {
                let (s, c, b) = self.rewrite_full(ctx, status, content_type, body);
                (s, headers, c, b)
            }
            Reply::Stream {
                headers, events, ..
            } => {
                for ev in events {
                    let Ok(ev) = ev else { break };
                    if let (Some(out), true) = self.process_event(ctx, ev) {
                        return (
                            200,
                            headers,
                            Some("application/json".into()),
                            out.data.into_bytes(),
                        );
                    }
                }
                let body = match &ctx.req_id {
                    Some(id) => error_body(
                        Some(id),
                        WRIT_UPSTREAM_ERROR_CODE,
                        "writ proxy: upstream stream ended without a response",
                    ),
                    None => error_body(
                        None,
                        -32000,
                        "writ proxy: this client does not accept text/event-stream",
                    ),
                };
                let status = if ctx.req_id.is_some() { 200 } else { 406 };
                (status, headers, Some("application/json".into()), body)
            }
        }
    }

    fn relay(
        &self,
        reply: Reply,
        ctx: &Ctx,
        resp: Responder<'_>,
        accepts_sse: bool,
    ) -> io::Result<()> {
        let reply = match reply {
            Reply::Stream {
                status,
                headers,
                events,
            } if accepts_sse => {
                let mut h = headers.clone();
                h.push(("Content-Type".into(), "text/event-stream".into()));
                h.push(("Cache-Control".into(), "no-cache".into()));
                h.push(("X-Accel-Buffering".into(), "no".into()));
                let mut body = resp.stream(status, &h)?;
                for ev in events {
                    let ev = match ev {
                        Ok(ev) => ev,
                        // Upstream broke mid-stream: close abruptly (the
                        // agent may resume with Last-Event-ID).
                        Err(e) => {
                            tracing::warn!("upstream SSE stream error: {e}");
                            return Ok(());
                        }
                    };
                    let (out, is_final) = self.process_event(ctx, ev);
                    if let Some(out) = out {
                        if body.write(&out.encode()).is_err() {
                            // Agent went away: that is cancellation (2026-07-28).
                            return Ok(());
                        }
                    }
                    if is_final {
                        break;
                    }
                }
                return body.finish();
            }
            other => other,
        };
        let (status, headers, ctype, body) = self.collapse(reply, ctx);
        let mut h = headers;
        if let Some(c) = ctype {
            if !body.is_empty() {
                h.push(("Content-Type".into(), c));
            }
        }
        resp.send(status, &h, &body)
    }
}

fn session_of(req: &Request) -> String {
    req.header("mcp-session-id").unwrap_or("").to_string()
}

fn upstream_msg(detail: &str) -> String {
    format!("writ proxy: upstream MCP server unavailable (fail closed): {detail}")
}

fn withheld_response(id: RequestId) -> JsonRpcResponse {
    JsonRpcResponse::error(
        id,
        JsonRpcError {
            code: WRIT_UPSTREAM_ERROR_CODE,
            message: "writ proxy: the upstream reply could not be inspected and was withheld (fail closed)"
                .into(),
            data: Some(json!({"writ_withheld": true})),
        },
    )
}

/// 2026-07-28 request metadata: `Mcp-Method` / `Mcp-Name` must match the
/// body. Policy decides on the body, so a mismatch is refused outright.
fn check_mirrored(req: &Request, msg: &JsonRpcMessage) -> Result<(), String> {
    let (method, params) = match msg {
        JsonRpcMessage::Request(r) => (r.method.as_str(), r.params.as_ref()),
        JsonRpcMessage::Notification(n) => (n.method.as_str(), n.params.as_ref()),
        JsonRpcMessage::Response(_) => return Ok(()),
    };
    if let Some(h) = req.header("mcp-method") {
        if h != method {
            return Err(format!(
                "Header mismatch: Mcp-Method header value '{h}' does not match body value '{method}'"
            ));
        }
    }
    if let Some(h) = req.header("mcp-name") {
        let decoded = decode_mirrored(h).ok_or("Header mismatch: Mcp-Name is not valid base64")?;
        let body = params
            .and_then(|p| p.get("name").or_else(|| p.get("uri")))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if decoded != body {
            return Err(format!(
                "Header mismatch: Mcp-Name header value '{decoded}' does not match body value '{body}'"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_name(host_part("127.0.0.1:8080")));
        assert!(is_loopback_name(host_part("localhost")));
        assert!(is_loopback_name(host_part("[::1]:9")));
        assert!(!is_loopback_name(host_part("evil.example:8080")));
        assert!(!is_loopback_name(host_part("192.168.1.2")));
        assert!(origin_is_loopback("http://localhost:6274"));
        assert!(origin_is_loopback("https://127.0.0.1"));
        assert!(!origin_is_loopback("http://evil.example"));
        assert!(!origin_is_loopback("null"));
        assert!(!origin_is_loopback("file://localhost"));
    }

    #[test]
    fn sentinel_decoding() {
        assert_eq!(
            decode_mirrored("get_weather").as_deref(),
            Some("get_weather")
        );
        assert_eq!(
            decode_mirrored("=?base64?SGVsbG8sIOS4lueVjA==?=").as_deref(),
            Some("Hello, 世界")
        );
        assert_eq!(decode_mirrored("=?base64?!!?="), None);
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
