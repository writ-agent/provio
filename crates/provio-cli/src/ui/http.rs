//! A small std-only HTTP/1.1 server for the console: one thread per
//! connection (bounded), `Connection: close` for every response except
//! streams, and the security checks every request passes before routing.
//!
//! Checks, in order (any failure answers and closes):
//! 1. request line and headers parse, within [`MAX_HEAD`] bytes and
//!    [`READ_TIMEOUT`]; no `Transfer-Encoding` (bodies need
//!    `Content-Length`, at most [`MAX_BODY`]);
//! 2. `Host` is exactly `127.0.0.1:<port>` or `localhost:<port>`
//!    (DNS-rebinding defence);
//! 3. `Origin`, when present, is this console's own origin, and
//!    `Sec-Fetch-Site`, when present, is not `cross-site`;
//! 4. `/api/*` carries `X-Provio-Token` equal to the session token (constant
//!    time);
//! 5. `POST` bodies are `application/json`.
//!
//! Every response carries a strict `Content-Security-Policy` (no inline
//! script or style, no remote origin), `X-Content-Type-Options: nosniff`,
//! `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`,
//! `Cross-Origin-Opener-Policy` / `-Resource-Policy: same-origin` and
//! `Cache-Control: no-store`.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub(crate) const MAX_HEAD: usize = 16 * 1024;
pub(crate) const MAX_BODY: usize = 2 * 1024 * 1024;
pub(crate) const READ_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CONNECTIONS: usize = 64;
pub(crate) const TOKEN_HEADER: &str = "x-provio-token";

pub(crate) const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; \
    img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; \
    base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub(crate) struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    /// Lower-cased names.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
    pub fn json(&self) -> Result<serde_json::Value, Response> {
        serde_json::from_slice(&self.body)
            .map_err(|e| Response::error(400, "bad_request", &format!("body is not JSON: {e}")))
    }
}

pub(crate) type StreamFn = Box<dyn FnOnce(&mut TcpStream) + Send>;

pub(crate) enum Body {
    Bytes(Vec<u8>),
    /// Headers are sent, then the function owns the connection.
    Stream(StreamFn),
}

pub(crate) struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Body,
    pub headers: Vec<(&'static str, String)>,
}

impl Response {
    pub fn bytes(status: u16, content_type: &'static str, body: Vec<u8>) -> Self {
        Response {
            status,
            content_type,
            body: Body::Bytes(body),
            headers: Vec::new(),
        }
    }
    pub fn json(status: u16, v: &serde_json::Value) -> Self {
        Self::bytes(
            status,
            "application/json; charset=utf-8",
            serde_json::to_vec(v).unwrap_or_default(),
        )
    }
    pub fn ok(v: serde_json::Value) -> Self {
        Self::json(200, &v)
    }
    pub fn error(status: u16, code: &str, message: &str) -> Self {
        Self::json(
            status,
            &serde_json::json!({"error": {"code": code, "message": message}}),
        )
    }
    pub fn stream(f: StreamFn) -> Self {
        Response {
            status: 200,
            content_type: "text/event-stream; charset=utf-8",
            body: Body::Stream(f),
            headers: Vec::new(),
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// Constant-time byte comparison (length is not secret: tokens are fixed
/// length).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    std::hint::black_box(d) == 0
}

pub(crate) struct Security {
    pub port: u16,
    pub token: String,
}

impl Security {
    fn hosts(&self) -> [String; 2] {
        [
            format!("127.0.0.1:{}", self.port),
            format!("localhost:{}", self.port),
        ]
    }

    /// `None` = pass; `Some(resp)` = reject with this response.
    pub fn check(&self, req: &Request) -> Option<Response> {
        let hosts = self.hosts();
        match req.header("host") {
            Some(h) if hosts.iter().any(|x| x.eq_ignore_ascii_case(h.trim())) => {}
            _ => {
                return Some(Response::error(
                    421,
                    "bad_host",
                    "Host must be this console's loopback address",
                ))
            }
        }
        if let Some(o) = req.header("origin") {
            let ok = hosts
                .iter()
                .any(|h| o.trim().eq_ignore_ascii_case(&format!("http://{h}")));
            if !ok {
                return Some(Response::error(
                    403,
                    "bad_origin",
                    "cross-origin requests are refused",
                ));
            }
        }
        if req
            .header("sec-fetch-site")
            .is_some_and(|s| s.eq_ignore_ascii_case("cross-site"))
        {
            return Some(Response::error(
                403,
                "bad_origin",
                "cross-site requests are refused",
            ));
        }
        if req.path.starts_with("/api/") {
            let ok = req
                .header(TOKEN_HEADER)
                .is_some_and(|t| ct_eq(t.trim().as_bytes(), self.token.as_bytes()));
            if !ok {
                return Some(Response::error(
                    401,
                    "bad_token",
                    "missing or wrong session token (open the URL provio ui printed)",
                ));
            }
            if req.method == "POST" {
                let ct = req.header("content-type").unwrap_or("");
                if !ct
                    .split(';')
                    .next()
                    .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
                {
                    return Some(Response::error(
                        415,
                        "bad_content_type",
                        "POST bodies must be application/json",
                    ));
                }
            }
        }
        None
    }
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(v) => {
                        out.push(v);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_query(q: &str) -> HashMap<String, String> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (pct_decode(k), pct_decode(v)),
            None => (pct_decode(p), String::new()),
        })
        .collect()
}

/// Read one request. `Err` carries the response to send.
fn read_request(stream: &TcpStream) -> Result<Request, Response> {
    let mut reader = BufReader::new(stream.take((MAX_HEAD + MAX_BODY + 1) as u64));
    let mut head_len = 0usize;
    let mut line = String::new();
    let mut read_line = |reader: &mut BufReader<_>, line: &mut String| -> Result<(), Response> {
        line.clear();
        let n = std::io::Read::by_ref(reader)
            .take((MAX_HEAD - head_len.min(MAX_HEAD)) as u64 + 1)
            .read_line(line)
            .map_err(|_| Response::error(400, "bad_request", "could not read request"))?;
        head_len += n;
        if n == 0 {
            return Err(Response::error(400, "bad_request", "connection closed"));
        }
        if head_len > MAX_HEAD {
            return Err(Response::error(431, "too_large", "request head too large"));
        }
        Ok(())
    };
    read_line(&mut reader, &mut line)?;
    let mut parts = line.trim_end().split(' ');
    let (method, target, version) = (
        parts.next().unwrap_or("").to_string(),
        parts.next().unwrap_or("").to_string(),
        parts.next().unwrap_or(""),
    );
    if method.is_empty() || !target.starts_with('/') || !version.starts_with("HTTP/1.") {
        return Err(Response::error(
            400,
            "bad_request",
            "malformed request line",
        ));
    }
    let mut headers = HashMap::new();
    loop {
        read_line(&mut reader, &mut line)?;
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            break;
        }
        let Some((k, v)) = l.split_once(':') else {
            return Err(Response::error(400, "bad_request", "malformed header"));
        };
        let k = k.trim().to_ascii_lowercase();
        if headers.contains_key(&k)
            && matches!(
                k.as_str(),
                "host" | "content-length" | "origin" | "x-provio-token"
            )
        {
            return Err(Response::error(400, "bad_request", "duplicate header"));
        }
        headers.insert(k, v.trim().to_string());
    }
    if headers.contains_key("transfer-encoding") {
        return Err(Response::error(
            501,
            "bad_request",
            "Transfer-Encoding is not supported; send Content-Length",
        ));
    }
    let len = match headers.get("content-length") {
        None => 0,
        Some(v) => v
            .parse::<usize>()
            .map_err(|_| Response::error(400, "bad_request", "bad Content-Length"))?,
    };
    if len > MAX_BODY {
        return Err(Response::error(413, "too_large", "request body too large"));
    }
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .map_err(|_| Response::error(400, "bad_request", "short body"))?;
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), parse_query(q)),
        None => (target.clone(), HashMap::new()),
    };
    Ok(Request {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn write_head(stream: &mut TcpStream, resp: &Response, len: Option<usize>) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\n",
        resp.status,
        reason(resp.status),
        resp.content_type
    );
    match len {
        Some(n) => head.push_str(&format!("Content-Length: {n}\r\nConnection: close\r\n")),
        None => head.push_str("Connection: close\r\nX-Accel-Buffering: no\r\n"),
    }
    head.push_str(&format!(
        "Content-Security-Policy: {CSP}\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\n\
         X-Frame-Options: DENY\r\n\
         Cross-Origin-Opener-Policy: same-origin\r\n\
         Cross-Origin-Resource-Policy: same-origin\r\n\
         Permissions-Policy: camera=(), microphone=(), geolocation=(), clipboard-read=()\r\n\
         Cache-Control: no-store\r\n"
    ));
    for (k, v) in &resp.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())
}

fn send(stream: &mut TcpStream, resp: Response, head_only: bool) {
    match resp.body {
        Body::Bytes(ref b) => {
            let len = b.len();
            if write_head(stream, &resp, Some(len)).is_ok() && !head_only {
                let _ = stream.write_all(b);
            }
            let _ = stream.flush();
        }
        Body::Stream(_) => {
            if write_head(stream, &resp, None).is_err() {
                return;
            }
            let _ = stream.flush();
            let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
            if let Body::Stream(f) = resp.body {
                f(stream);
            }
        }
    }
}

/// Serve forever on `listener`. `handler` runs after the security checks.
pub(crate) fn serve<H>(listener: TcpListener, security: Arc<Security>, handler: Arc<H>)
where
    H: Fn(Request) -> Response + Send + Sync + 'static,
{
    let active = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let Ok(mut stream) = conn else { continue };
        // Loopback only: the listener is bound to 127.0.0.1, but check.
        if !stream.peer_addr().is_ok_and(|a| a.ip().is_loopback()) {
            continue;
        }
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            send(
                &mut stream,
                Response::error(503, "busy", "too many connections"),
                false,
            );
            continue;
        }
        let (security, handler, active_c) = (security.clone(), handler.clone(), active.clone());
        let active = active_c.clone();
        let spawned = std::thread::Builder::new()
            .name("provio-ui-conn".into())
            .spawn(move || {
                let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
                let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
                let _ = stream.set_nodelay(true);
                let resp = match read_request(&stream) {
                    Err(r) => (r, false),
                    Ok(req) => {
                        let head = req.method == "HEAD";
                        match security.check(&req) {
                            Some(r) => (r, head),
                            None => {
                                let r =
                                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        handler(req)
                                    }))
                                    .unwrap_or_else(|_| {
                                        Response::error(500, "internal", "handler panicked")
                                    });
                                (r, head)
                            }
                        }
                    }
                };
                send(&mut stream, resp.0, resp.1);
                let _ = stream.shutdown(std::net::Shutdown::Both);
                active.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            // Thread creation failed; the closure (and the stream) was dropped.
            active_c.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn query_decoding() {
        let q = parse_query("a=1&b=x%20y&c=%zz&d");
        assert_eq!(q["b"], "x y");
        assert_eq!(q["c"], "%zz");
        assert_eq!(q["d"], "");
    }
}
