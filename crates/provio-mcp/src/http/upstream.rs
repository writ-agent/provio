//! Client side of the HTTP proxy: how provio talks to the real (upstream) MCP
//! server.
//!
//! * [`StreamableUpstream`] — MCP Streamable HTTP (2025-03-26 … 2026-07-28):
//!   every message is a POST to one endpoint, the reply is JSON or an SSE
//!   stream; GET/DELETE are relayed for the session-era revisions.
//! * [`LegacySseUpstream`] — the deprecated 2024-11-05 HTTP+SSE transport:
//!   a long-lived GET stream whose first `endpoint` event names the POST
//!   URL; responses arrive on that stream and are matched to callers by id.
//! * [`AutoUpstream`] — Streamable HTTP first, falling back to legacy on
//!   the spec's detection rule (400/404/405 without a recognised JSON-RPC
//!   error body, then a GET that yields an `endpoint` event).
//!
//! Credentials are injected here, at dispatch, as request headers
//! ([`CredentialStore::inject_http_headers`]); they never enter a
//! [`Reply`], a log line, or anything the agent receives. Redirects are
//! not followed (a redirect could carry injected credentials to another
//! host).

use std::collections::{HashMap, VecDeque};
use std::io::{self, BufReader};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use serde_json::Value;

use crate::credentials::CredentialStore;
use crate::http::sse::{SseEvent, SseReader};
use crate::jsonrpc::{JsonRpcMessage, JsonRpcResponse, RequestId};

/// Stream of SSE events from the upstream.
pub type SseStream = Box<dyn Iterator<Item = io::Result<SseEvent>> + Send>;

/// An upstream HTTP reply, bounded and stripped to what may be relayed.
pub enum Reply {
    /// A complete (non-SSE) reply. `body` is at most the configured limit.
    Full {
        status: u16,
        /// Relayable MCP headers (session id, protocol version) only.
        headers: Vec<(String, String)>,
        content_type: Option<String>,
        body: Vec<u8>,
    },
    /// A `text/event-stream` reply.
    Stream {
        status: u16,
        headers: Vec<(String, String)>,
        events: SseStream,
    },
}

impl Reply {
    pub fn status(&self) -> u16 {
        match self {
            Reply::Full { status, .. } | Reply::Stream { status, .. } => *status,
        }
    }
}

/// Transport failure reaching the upstream (connect, TLS, timeout, size).
/// The message never includes credential material.
#[derive(Debug, Clone)]
pub struct UpstreamError(pub String);

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The upstream side of the proxy. `headers` are the MCP headers the
/// proxy decided to forward from the agent request.
pub trait Upstream: Send + Sync {
    fn post(&self, body: &[u8], headers: &[(String, String)]) -> Result<Reply, UpstreamError>;
    fn get(&self, headers: &[(String, String)]) -> Result<Reply, UpstreamError>;
    fn delete(&self, headers: &[(String, String)]) -> Result<Reply, UpstreamError>;
    /// Label recorded as the call's server transport.
    fn kind(&self) -> &'static str;
}

/// Upstream client settings.
#[derive(Debug, Clone)]
pub struct UpstreamOptions {
    pub connect_timeout: Duration,
    /// Time to wait for response headers (and, for legacy SSE, for the
    /// response event).
    pub response_timeout: Duration,
    pub max_response_bytes: u64,
    pub max_event_bytes: usize,
}

impl Default for UpstreamOptions {
    fn default() -> Self {
        UpstreamOptions {
            connect_timeout: Duration::from_secs(10),
            response_timeout: Duration::from_secs(300),
            max_response_bytes: 16 * 1024 * 1024,
            max_event_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Headers relayed from upstream replies to the agent.
const RELAY_REPLY_HEADERS: &[&str] = &["mcp-session-id", "mcp-protocol-version"];

fn agent(opts: &UpstreamOptions) -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .max_redirects_will_error(false)
        .timeout_connect(Some(opts.connect_timeout))
        .timeout_recv_response(Some(opts.response_timeout))
        .user_agent(concat!("provio-mcp-proxy/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

fn err(e: ureq::Error) -> UpstreamError {
    UpstreamError(format!("upstream request failed: {e}"))
}

/// Apply forwarded headers, then credential headers (which win).
fn apply_headers<B>(
    mut rb: ureq::RequestBuilder<B>,
    forwarded: &[(String, String)],
    creds: &CredentialStore,
    server: &str,
) -> ureq::RequestBuilder<B> {
    for (k, v) in forwarded {
        rb = rb.header(k.as_str(), v.as_str());
    }
    if let Some(h) = rb.headers_mut() {
        creds.inject_http_headers(server, &mut |name, value| {
            if let (Ok(n), Ok(mut v)) = (
                ureq::http::HeaderName::from_bytes(name.as_bytes()),
                ureq::http::HeaderValue::from_str(value),
            ) {
                v.set_sensitive(true);
                h.insert(n, v);
            }
        });
    }
    rb
}

fn to_reply(
    resp: ureq::http::Response<ureq::Body>,
    opts: &UpstreamOptions,
) -> Result<Reply, UpstreamError> {
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = RELAY_REPLY_HEADERS
        .iter()
        .filter_map(|name| {
            resp.headers()
                .get(*name)
                .and_then(|v| v.to_str().ok())
                .map(|v| (canonical(name), v.to_string()))
        })
        .collect();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let is_sse = content_type
        .as_deref()
        .map(|c| c.to_ascii_lowercase().starts_with("text/event-stream"))
        .unwrap_or(false);
    let body = resp.into_body();
    if is_sse {
        let reader = body.into_with_config().limit(u64::MAX).reader();
        let events = SseReader::new(BufReader::new(reader), opts.max_event_bytes);
        Ok(Reply::Stream {
            status,
            headers,
            events: Box::new(events),
        })
    } else {
        let bytes = body
            .into_with_config()
            .limit(opts.max_response_bytes)
            .read_to_vec()
            .map_err(|e| UpstreamError(format!("upstream reply unreadable or too large: {e}")))?;
        Ok(Reply::Full {
            status,
            headers,
            content_type,
            body: bytes,
        })
    }
}

fn canonical(name: &str) -> String {
    match name {
        "mcp-session-id" => "Mcp-Session-Id".into(),
        "mcp-protocol-version" => "MCP-Protocol-Version".into(),
        other => other.into(),
    }
}

/// MCP Streamable HTTP client.
pub struct StreamableUpstream {
    url: String,
    server: String,
    creds: Arc<CredentialStore>,
    agent: ureq::Agent,
    opts: UpstreamOptions,
}

impl StreamableUpstream {
    pub fn new(
        url: &str,
        server: &str,
        creds: Arc<CredentialStore>,
        opts: UpstreamOptions,
    ) -> Self {
        StreamableUpstream {
            url: url.to_string(),
            server: server.to_string(),
            creds,
            agent: agent(&opts),
            opts,
        }
    }
}

impl Upstream for StreamableUpstream {
    fn post(&self, body: &[u8], headers: &[(String, String)]) -> Result<Reply, UpstreamError> {
        let rb = self
            .agent
            .post(&self.url)
            .header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json");
        let rb = apply_headers(rb, headers, &self.creds, &self.server);
        to_reply(rb.send(body).map_err(err)?, &self.opts)
    }

    fn get(&self, headers: &[(String, String)]) -> Result<Reply, UpstreamError> {
        let rb = self
            .agent
            .get(&self.url)
            .header("Accept", "text/event-stream");
        let rb = apply_headers(rb, headers, &self.creds, &self.server);
        to_reply(rb.call().map_err(err)?, &self.opts)
    }

    fn delete(&self, headers: &[(String, String)]) -> Result<Reply, UpstreamError> {
        let rb = self.agent.delete(&self.url);
        let rb = apply_headers(rb, headers, &self.creds, &self.server);
        to_reply(rb.call().map_err(err)?, &self.opts)
    }

    fn kind(&self) -> &'static str {
        "streamable-http"
    }
}

/// Split `scheme://authority/path?q` into (`scheme://authority`, path+query).
fn split_origin(url: &str) -> Option<(&str, &str)> {
    let scheme_end = url.find("://")? + 3;
    let rest = &url[scheme_end..];
    let path_start = rest
        .find(['/', '?'])
        .map(|i| scheme_end + i)
        .unwrap_or(url.len());
    Some((&url[..path_start], &url[path_start..]))
}

/// Resolve the legacy `endpoint` event's URI against the SSE URL. The
/// result must stay on the SSE URL's origin: an endpoint on another host
/// would receive the injected credentials.
pub fn resolve_endpoint(sse_url: &str, endpoint: &str) -> Option<String> {
    let (origin, path) = split_origin(sse_url)?;
    let endpoint = endpoint.trim();
    if endpoint.contains("://") {
        let (o2, _) = split_origin(endpoint)?;
        return o2
            .eq_ignore_ascii_case(origin)
            .then(|| endpoint.to_string());
    }
    if endpoint.starts_with("//") {
        return None;
    }
    if endpoint.starts_with('/') {
        return Some(format!("{origin}{endpoint}"));
    }
    let path = path.split('?').next().unwrap_or("");
    let dir = match path.rfind('/') {
        Some(i) => &path[..=i],
        None => "/",
    };
    Some(format!("{origin}{dir}{endpoint}"))
}

/// Server-initiated messages waiting for the agent's GET stream.
struct Inbox {
    queue: Mutex<VecDeque<String>>,
    ready: Condvar,
}

const INBOX_CAP: usize = 1024;

struct LegacyConn {
    post_url: String,
    pending: Mutex<HashMap<RequestId, Sender<JsonRpcResponse>>>,
    inbox: Inbox,
    alive: AtomicBool,
    listening: AtomicBool,
}

/// Client for the deprecated 2024-11-05 HTTP+SSE transport. One upstream
/// SSE connection (one upstream session) is shared by the proxy; it is
/// re-established on the next request after it drops.
pub struct LegacySseUpstream {
    sse_url: String,
    server: String,
    creds: Arc<CredentialStore>,
    agent: ureq::Agent,
    opts: UpstreamOptions,
    conn: Mutex<Option<Arc<LegacyConn>>>,
}

impl LegacySseUpstream {
    pub fn new(
        sse_url: &str,
        server: &str,
        creds: Arc<CredentialStore>,
        opts: UpstreamOptions,
    ) -> Self {
        LegacySseUpstream {
            sse_url: sse_url.to_string(),
            server: server.to_string(),
            creds,
            agent: agent(&opts),
            opts,
            conn: Mutex::new(None),
        }
    }

    /// Open (or reuse) the upstream SSE connection.
    fn connect(&self) -> Result<Arc<LegacyConn>, UpstreamError> {
        let mut slot = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = slot.as_ref() {
            if c.alive.load(Ordering::SeqCst) {
                return Ok(Arc::clone(c));
            }
        }
        let rb = self
            .agent
            .get(&self.sse_url)
            .header("Accept", "text/event-stream");
        let rb = apply_headers(rb, &[], &self.creds, &self.server);
        let resp = rb.call().map_err(err)?;
        let status = resp.status().as_u16();
        let ctype = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if status != 200 || !ctype.starts_with("text/event-stream") {
            return Err(UpstreamError(format!(
                "legacy SSE endpoint answered {status} ({ctype}), not an event stream"
            )));
        }
        let reader = resp.into_body().into_with_config().limit(u64::MAX).reader();
        let mut events = SseReader::new(BufReader::new(reader), self.opts.max_event_bytes);

        let (ep_tx, ep_rx) = mpsc::channel::<Option<String>>();
        let sse_url = self.sse_url.clone();
        // The reader thread first reports the endpoint, then routes messages.
        let (conn_tx, conn_rx) = mpsc::channel::<Arc<LegacyConn>>();
        std::thread::Builder::new()
            .name("provio-legacy-sse".into())
            .spawn(move || {
                let endpoint = loop {
                    match events.next() {
                        Some(Ok(ev)) if ev.event.as_deref() == Some("endpoint") => {
                            break resolve_endpoint(&sse_url, &ev.data)
                        }
                        Some(Ok(_)) => continue,
                        _ => break None,
                    }
                };
                let ok = endpoint.is_some();
                let _ = ep_tx.send(endpoint);
                if !ok {
                    return;
                }
                let Ok(conn) = conn_rx.recv() else { return };
                for ev in events.by_ref() {
                    let Ok(ev) = ev else { break };
                    if ev.event.as_deref().is_some_and(|e| e != "message") || ev.data.is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<JsonRpcMessage>(&ev.data) {
                        Ok(JsonRpcMessage::Response(r)) => {
                            let tx = conn
                                .pending
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .remove(&r.id);
                            match tx {
                                Some(tx) => {
                                    let _ = tx.send(r);
                                }
                                None => {
                                    tracing::warn!(id = %r.id, "legacy SSE: unmatched response")
                                }
                            }
                        }
                        Ok(_) => {
                            let mut q = conn.inbox.queue.lock().unwrap_or_else(|e| e.into_inner());
                            if q.len() >= INBOX_CAP {
                                q.pop_front();
                            }
                            q.push_back(ev.data);
                            conn.inbox.ready.notify_all();
                        }
                        Err(_) => tracing::warn!("legacy SSE: dropping non-JSON-RPC event"),
                    }
                }
                conn.alive.store(false, Ordering::SeqCst);
                // Dropping the senders fails every waiter closed.
                conn.pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clear();
                conn.inbox.ready.notify_all();
            })
            .map_err(|e| UpstreamError(format!("spawn legacy SSE reader: {e}")))?;

        let endpoint = match ep_rx.recv_timeout(self.opts.connect_timeout) {
            Ok(Some(ep)) => ep,
            Ok(None) => {
                return Err(UpstreamError(
                    "legacy SSE stream sent no usable same-origin `endpoint` event".into(),
                ))
            }
            Err(_) => {
                return Err(UpstreamError(
                    "legacy SSE: timed out waiting for `endpoint`".into(),
                ))
            }
        };
        let conn = Arc::new(LegacyConn {
            post_url: endpoint,
            pending: Mutex::new(HashMap::new()),
            inbox: Inbox {
                queue: Mutex::new(VecDeque::new()),
                ready: Condvar::new(),
            },
            alive: AtomicBool::new(true),
            listening: AtomicBool::new(false),
        });
        let _ = conn_tx.send(Arc::clone(&conn));
        *slot = Some(Arc::clone(&conn));
        Ok(conn)
    }
}

/// The agent's GET stream over a legacy upstream: drains server-initiated
/// messages, emitting a keep-alive comment when idle so a vanished agent is
/// noticed on the next write.
struct InboxStream {
    conn: Arc<LegacyConn>,
}

impl Iterator for InboxStream {
    type Item = io::Result<SseEvent>;
    fn next(&mut self) -> Option<Self::Item> {
        let mut q = self
            .conn
            .inbox
            .queue
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(data) = q.pop_front() {
                return Some(Ok(SseEvent::message(data)));
            }
            if !self.conn.alive.load(Ordering::SeqCst) {
                return None;
            }
            let (guard, timeout) = self
                .conn
                .inbox
                .ready
                .wait_timeout(q, Duration::from_secs(15))
                .unwrap_or_else(|e| e.into_inner());
            q = guard;
            if timeout.timed_out() && q.is_empty() {
                return Some(Ok(SseEvent::keepalive()));
            }
        }
    }
}

impl Drop for InboxStream {
    fn drop(&mut self) {
        self.conn.listening.store(false, Ordering::SeqCst);
    }
}

impl Upstream for LegacySseUpstream {
    fn post(&self, body: &[u8], _headers: &[(String, String)]) -> Result<Reply, UpstreamError> {
        let conn = self.connect()?;
        let msg: Option<JsonRpcMessage> = serde_json::from_slice(body).ok();
        let waiter: Option<(RequestId, Receiver<JsonRpcResponse>)> = match &msg {
            Some(JsonRpcMessage::Request(r)) => {
                let (tx, rx) = mpsc::channel();
                conn.pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(r.id.clone(), tx);
                Some((r.id.clone(), rx))
            }
            _ => None,
        };
        let rb = self
            .agent
            .post(&conn.post_url)
            .header("Content-Type", "application/json");
        // Session-era MCP headers mean nothing to a 2024-11-05 server; only
        // credentials are sent.
        let rb = apply_headers(rb, &[], &self.creds, &self.server);
        let resp = match rb.send(body) {
            Ok(r) => r,
            Err(e) => {
                if let Some((id, _)) = &waiter {
                    conn.pending
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(id);
                }
                return Err(err(e));
            }
        };
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            if let Some((id, _)) = &waiter {
                conn.pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(id);
            }
            return to_reply(resp, &self.opts);
        }
        drop(resp);
        let Some((id, rx)) = waiter else {
            return Ok(Reply::Full {
                status: 202,
                headers: Vec::new(),
                content_type: None,
                body: Vec::new(),
            });
        };
        match rx.recv_timeout(self.opts.response_timeout) {
            Ok(r) => Ok(Reply::Full {
                status: 200,
                headers: Vec::new(),
                content_type: Some("application/json".into()),
                body: serde_json::to_vec(&JsonRpcMessage::Response(r)).unwrap_or_default(),
            }),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                conn.pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&id);
                Err(UpstreamError(
                    "legacy SSE: timed out waiting for the response".into(),
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(UpstreamError(
                "legacy SSE: upstream stream closed before responding".into(),
            )),
        }
    }

    fn get(&self, _headers: &[(String, String)]) -> Result<Reply, UpstreamError> {
        let conn = self.connect()?;
        if conn.listening.swap(true, Ordering::SeqCst) {
            // One listener: the same message must not go to two streams.
            return Ok(Reply::Full {
                status: 409,
                headers: Vec::new(),
                content_type: Some("text/plain".into()),
                body: b"a server-message stream is already open".to_vec(),
            });
        }
        Ok(Reply::Stream {
            status: 200,
            headers: Vec::new(),
            events: Box::new(InboxStream { conn }),
        })
    }

    fn delete(&self, _headers: &[(String, String)]) -> Result<Reply, UpstreamError> {
        Ok(Reply::Full {
            status: 405,
            headers: Vec::new(),
            content_type: None,
            body: Vec::new(),
        })
    }

    fn kind(&self) -> &'static str {
        "http+sse"
    }
}

/// True when `body` is a JSON-RPC error object: the mark of a modern MCP
/// server rejecting the request (so no fallback to legacy).
pub fn is_jsonrpc_error(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .map(|v| v.get("jsonrpc").is_some() && v.get("error").and_then(|e| e.get("code")).is_some())
        .unwrap_or(false)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Unknown,
    Streamable,
    Legacy,
}

/// Streamable HTTP with spec-defined fallback to legacy HTTP+SSE.
pub struct AutoUpstream {
    streamable: StreamableUpstream,
    legacy: LegacySseUpstream,
    mode: Mutex<Mode>,
}

impl AutoUpstream {
    pub fn new(
        url: &str,
        server: &str,
        creds: Arc<CredentialStore>,
        opts: UpstreamOptions,
    ) -> Self {
        AutoUpstream {
            streamable: StreamableUpstream::new(url, server, Arc::clone(&creds), opts.clone()),
            legacy: LegacySseUpstream::new(url, server, creds, opts),
            mode: Mutex::new(Mode::Unknown),
        }
    }

    fn mode(&self) -> Mode {
        *self.mode.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set(&self, m: Mode) {
        *self.mode.lock().unwrap_or_else(|e| e.into_inner()) = m;
    }
}

impl Upstream for AutoUpstream {
    fn post(&self, body: &[u8], headers: &[(String, String)]) -> Result<Reply, UpstreamError> {
        match self.mode() {
            Mode::Streamable => self.streamable.post(body, headers),
            Mode::Legacy => self.legacy.post(body, headers),
            Mode::Unknown => {
                let reply = self.streamable.post(body, headers)?;
                let status = reply.status();
                let fallback = matches!(status, 400 | 404 | 405)
                    && match &reply {
                        Reply::Full { body, .. } => !is_jsonrpc_error(body),
                        Reply::Stream { .. } => false,
                    };
                if !fallback {
                    if (200..300).contains(&status) {
                        self.set(Mode::Streamable);
                    }
                    return Ok(reply);
                }
                match self.legacy.connect() {
                    Ok(_) => {
                        tracing::info!(
                            "upstream speaks the legacy HTTP+SSE transport; falling back"
                        );
                        self.set(Mode::Legacy);
                        self.legacy.post(body, headers)
                    }
                    Err(_) => Ok(reply),
                }
            }
        }
    }

    fn get(&self, headers: &[(String, String)]) -> Result<Reply, UpstreamError> {
        match self.mode() {
            Mode::Legacy => self.legacy.get(headers),
            _ => self.streamable.get(headers),
        }
    }

    fn delete(&self, headers: &[(String, String)]) -> Result<Reply, UpstreamError> {
        match self.mode() {
            Mode::Legacy => self.legacy.delete(headers),
            _ => self.streamable.delete(headers),
        }
    }

    fn kind(&self) -> &'static str {
        match self.mode() {
            Mode::Legacy => "http+sse",
            _ => "streamable-http",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_resolution_stays_on_origin() {
        let base = "http://127.0.0.1:9000/sse";
        assert_eq!(
            resolve_endpoint(base, "/messages?sessionId=a").as_deref(),
            Some("http://127.0.0.1:9000/messages?sessionId=a")
        );
        assert_eq!(
            resolve_endpoint("http://h:1/a/sse", "msg?x=1").as_deref(),
            Some("http://h:1/a/msg?x=1")
        );
        assert_eq!(
            resolve_endpoint(base, "http://127.0.0.1:9000/m").as_deref(),
            Some("http://127.0.0.1:9000/m")
        );
        assert_eq!(resolve_endpoint(base, "http://evil.example/m"), None);
        assert_eq!(resolve_endpoint(base, "//evil.example/m"), None);
    }

    #[test]
    fn modern_error_detection() {
        assert!(is_jsonrpc_error(
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"x"}}"#
        ));
        assert!(!is_jsonrpc_error(b"Not Found"));
        assert!(!is_jsonrpc_error(b""));
    }
}
