//! A small blocking HTTP/1.1 server (thread per connection) with the one
//! property MCP needs and generic micro-servers often lack: responses can be
//! streamed as SSE with every event flushed to the socket immediately.
//!
//! Bounded by design: header block size, body size, concurrent connections,
//! read/write timeouts. Request parsing uses `httparse`; bodies may be
//! `Content-Length` or `chunked` (both at once is refused: request
//! smuggling). `Expect: 100-continue` is honoured after the size check.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Resource bounds for the server.
#[derive(Debug, Clone)]
pub struct Limits {
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub max_connections: usize,
    /// Socket read timeout: bounds a slow request and keep-alive idleness.
    pub read_timeout: Duration,
    /// Socket write timeout: bounds a stalled reader.
    pub write_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_header_bytes: 64 * 1024,
            max_body_bytes: 4 * 1024 * 1024,
            max_connections: 128,
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
        }
    }
}

/// One parsed request.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    /// Request target as sent (path + optional query).
    pub target: String,
    /// HTTP minor version (0 or 1).
    pub minor: u8,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub peer: Option<SocketAddr>,
}

impl Request {
    /// First header value with this name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// All headers with this name.
    pub fn headers_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Path without the query string.
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }

    fn wants_close(&self) -> bool {
        let conn = self.header("connection").unwrap_or("").to_ascii_lowercase();
        if self.minor == 0 {
            !conn.split(',').any(|t| t.trim() == "keep-alive")
        } else {
            conn.split(',').any(|t| t.trim() == "close")
        }
    }
}

/// Status line reason phrases for the codes this crate emits.
pub fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        409 => "Conflict",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

fn header_safe(s: &str) -> bool {
    !s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

/// Writes exactly one response for one request.
pub struct Responder<'a> {
    stream: Option<&'a mut TcpStream>,
    minor: u8,
    keep_alive: bool,
}

impl Drop for Responder<'_> {
    fn drop(&mut self) {
        // A handler that returned without responding: answer 500 so the
        // connection is never left waiting.
        if let Some(stream) = self.stream.take() {
            simple(stream, 500, "no response");
        }
    }
}

impl<'a> Responder<'a> {
    fn head(
        stream: &mut TcpStream,
        minor: u8,
        keep_alive: bool,
        status: u16,
        headers: &[(String, String)],
        framing: &str,
    ) -> io::Result<()> {
        let mut head = format!("HTTP/1.{minor} {status} {}\r\n", reason(status));
        for (k, v) in headers {
            if header_safe(k) && header_safe(v) {
                head.push_str(k);
                head.push_str(": ");
                head.push_str(v);
                head.push_str("\r\n");
            }
        }
        head.push_str(framing);
        if !keep_alive {
            head.push_str("Connection: close\r\n");
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes())
    }

    /// Send a complete response with a `Content-Length` body.
    pub fn send(
        mut self,
        status: u16,
        headers: &[(String, String)],
        body: &[u8],
    ) -> io::Result<()> {
        let stream = self.stream.take().expect("responder is used once");
        let framing = format!("Content-Length: {}\r\n", body.len());
        Self::head(
            stream,
            self.minor,
            self.keep_alive,
            status,
            headers,
            &framing,
        )?;
        stream.write_all(body)?;
        stream.flush()
    }

    /// Start a streamed response (chunked on HTTP/1.1; close-delimited on
    /// HTTP/1.0). Each `StreamBody::write` is flushed immediately.
    pub fn stream(
        mut self,
        status: u16,
        headers: &[(String, String)],
    ) -> io::Result<StreamBody<'a>> {
        let stream = self.stream.take().expect("responder is used once");
        let chunked = self.minor >= 1;
        let framing = if chunked {
            "Transfer-Encoding: chunked\r\n"
        } else {
            ""
        };
        Self::head(
            stream,
            self.minor,
            self.keep_alive && chunked,
            status,
            headers,
            framing,
        )?;
        stream.flush()?;
        Ok(StreamBody {
            stream,
            chunked,
            finished: false,
        })
    }
}

/// The body of a streamed response.
pub struct StreamBody<'a> {
    stream: &'a mut TcpStream,
    chunked: bool,
    finished: bool,
}

impl StreamBody<'_> {
    pub fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        if self.chunked {
            self.stream
                .write_all(format!("{:x}\r\n", bytes.len()).as_bytes())?;
            self.stream.write_all(bytes)?;
            self.stream.write_all(b"\r\n")?;
        } else {
            self.stream.write_all(bytes)?;
        }
        self.stream.flush()
    }

    /// Terminate the body (final zero-length chunk).
    pub fn finish(mut self) -> io::Result<()> {
        self.finished = true;
        if self.chunked {
            self.stream.write_all(b"0\r\n\r\n")?;
        }
        self.stream.flush()
    }
}

impl Drop for StreamBody<'_> {
    fn drop(&mut self) {
        // An unfinished stream leaves the connection mid-body: close it so
        // the peer never parses a truncated body as a complete one.
        if !self.finished {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
    }
}

/// Why reading a request failed.
enum ReadError {
    /// Clean close or idle timeout between requests.
    Closed,
    /// Protocol error: respond with this status, then close.
    Status(u16, &'static str),
    Io,
}

struct Conn {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Conn {
    /// Read more bytes into the buffer. Ok(0) = EOF.
    fn fill(&mut self) -> io::Result<usize> {
        let mut tmp = [0u8; 8192];
        loop {
            match self.stream.read(&mut tmp) {
                Ok(n) => {
                    self.buf.extend_from_slice(&tmp[..n]);
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    fn fill_to(&mut self, n: usize) -> Result<(), ReadError> {
        while self.buf.len() < n {
            match self.fill() {
                Ok(0) => return Err(ReadError::Status(400, "truncated body")),
                Ok(_) => {}
                Err(_) => return Err(ReadError::Io),
            }
        }
        Ok(())
    }

    fn take_line(&mut self, limit: usize) -> Result<String, ReadError> {
        loop {
            if let Some(pos) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let line: Vec<u8> = self.buf.drain(..pos + 2).take(pos).collect();
                return String::from_utf8(line)
                    .map_err(|_| ReadError::Status(400, "bad chunk line"));
            }
            if self.buf.len() > limit {
                return Err(ReadError::Status(400, "chunk line too long"));
            }
            match self.fill() {
                Ok(0) => return Err(ReadError::Status(400, "truncated chunked body")),
                Ok(_) => {}
                Err(_) => return Err(ReadError::Io),
            }
        }
    }

    fn read_request(&mut self, limits: &Limits) -> Result<Request, ReadError> {
        // Header block.
        let (method, target, minor, headers, header_len) = loop {
            let mut hdrs = [httparse::EMPTY_HEADER; 96];
            let mut req = httparse::Request::new(&mut hdrs);
            match req.parse(&self.buf) {
                Ok(httparse::Status::Complete(n)) => {
                    let headers: Vec<(String, String)> = req
                        .headers
                        .iter()
                        .map(|h| {
                            (
                                h.name.to_string(),
                                String::from_utf8_lossy(h.value).trim().to_string(),
                            )
                        })
                        .collect();
                    break (
                        req.method.unwrap_or("").to_string(),
                        req.path.unwrap_or("").to_string(),
                        req.version.unwrap_or(1),
                        headers,
                        n,
                    );
                }
                Ok(httparse::Status::Partial) => {
                    if self.buf.len() > limits.max_header_bytes {
                        return Err(ReadError::Status(431, "header block too large"));
                    }
                    match self.fill() {
                        Ok(0) if self.buf.is_empty() => return Err(ReadError::Closed),
                        Ok(0) => return Err(ReadError::Status(400, "truncated request")),
                        Ok(_) => {}
                        Err(e)
                            if self.buf.is_empty()
                                && matches!(
                                    e.kind(),
                                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                                ) =>
                        {
                            return Err(ReadError::Closed)
                        }
                        Err(_) => return Err(ReadError::Io),
                    }
                }
                Err(httparse::Error::TooManyHeaders) => {
                    return Err(ReadError::Status(431, "too many headers"))
                }
                Err(_) => return Err(ReadError::Status(400, "malformed request")),
            }
        };
        self.buf.drain(..header_len);

        let mut req = Request {
            method,
            target,
            minor,
            headers,
            body: Vec::new(),
            peer: self.stream.peer_addr().ok(),
        };

        let chunked = req
            .header("transfer-encoding")
            .map(|v| v.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false);
        let lengths: Vec<&str> = req.headers_named("content-length").collect();
        if chunked && !lengths.is_empty() {
            return Err(ReadError::Status(400, "both Content-Length and chunked"));
        }
        if req.header("transfer-encoding").is_some() && !chunked {
            return Err(ReadError::Status(400, "unsupported transfer-encoding"));
        }
        let length = match lengths.as_slice() {
            [] => None,
            [one] => Some(
                one.parse::<usize>()
                    .map_err(|_| ReadError::Status(400, "bad Content-Length"))?,
            ),
            many => {
                if many.windows(2).any(|w| w[0] != w[1]) {
                    return Err(ReadError::Status(400, "conflicting Content-Length"));
                }
                Some(
                    many[0]
                        .parse::<usize>()
                        .map_err(|_| ReadError::Status(400, "bad Content-Length"))?,
                )
            }
        };
        if let Some(n) = length {
            if n > limits.max_body_bytes {
                return Err(ReadError::Status(413, "request body too large"));
            }
        }
        let expects_body = chunked || length.unwrap_or(0) > 0;
        if expects_body
            && req
                .header("expect")
                .map(|v| v.eq_ignore_ascii_case("100-continue"))
                .unwrap_or(false)
        {
            let _ = self
                .stream
                .write_all(format!("HTTP/1.{minor} 100 Continue\r\n\r\n").as_bytes());
        }

        if let Some(n) = length {
            self.fill_to(n)?;
            req.body = self.buf.drain(..n).collect();
        } else if chunked {
            loop {
                let line = self.take_line(1024)?;
                let size_str = line.split(';').next().unwrap_or("").trim();
                let size = usize::from_str_radix(size_str, 16)
                    .map_err(|_| ReadError::Status(400, "bad chunk size"))?;
                if size == 0 {
                    // Trailers until blank line.
                    loop {
                        let t = self.take_line(limits.max_header_bytes)?;
                        if t.is_empty() {
                            break;
                        }
                    }
                    break;
                }
                if req.body.len() + size > limits.max_body_bytes {
                    return Err(ReadError::Status(413, "request body too large"));
                }
                self.fill_to(size + 2)?;
                req.body.extend(self.buf.drain(..size));
                if self.buf.drain(..2).as_slice() != b"\r\n" {
                    return Err(ReadError::Status(400, "bad chunk terminator"));
                }
            }
        }
        Ok(req)
    }
}

/// Handler: must write exactly one response through the responder.
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, req: &Request, resp: Responder<'_>) -> io::Result<()>;
}

impl<F> Handler for F
where
    F: Fn(&Request, Responder<'_>) -> io::Result<()> + Send + Sync + 'static,
{
    fn handle(&self, req: &Request, resp: Responder<'_>) -> io::Result<()> {
        self(req, resp)
    }
}

/// Stops a running `serve` loop.
#[derive(Clone)]
pub struct ShutdownHandle {
    flag: Arc<AtomicBool>,
    addr: SocketAddr,
}

impl ShutdownHandle {
    pub fn new(addr: SocketAddr) -> Self {
        ShutdownHandle {
            flag: Arc::new(AtomicBool::new(false)),
            addr,
        }
    }

    pub fn shutdown(&self) {
        self.flag.store(true, Ordering::SeqCst);
        // Wake the blocking accept.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(500));
    }

    pub fn is_shutdown(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

fn simple(stream: &mut TcpStream, status: u16, msg: &str) {
    let body = msg.as_bytes();
    let _ = stream.write_all(
        format!(
            "HTTP/1.1 {status} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            reason(status),
            body.len()
        )
        .as_bytes(),
    );
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn handle_conn(stream: TcpStream, limits: &Limits, handler: &dyn Handler) {
    let _ = stream.set_read_timeout(Some(limits.read_timeout));
    let _ = stream.set_write_timeout(Some(limits.write_timeout));
    let _ = stream.set_nodelay(true);
    let mut conn = Conn {
        stream,
        buf: Vec::new(),
    };
    loop {
        let req = match conn.read_request(limits) {
            Ok(r) => r,
            Err(ReadError::Closed) | Err(ReadError::Io) => break,
            Err(ReadError::Status(code, msg)) => {
                simple(&mut conn.stream, code, msg);
                break;
            }
        };
        // HTTP/1.0 streams are close-delimited, so never reused.
        let keep_alive = !req.wants_close() && req.minor >= 1;
        let responder = Responder {
            stream: Some(&mut conn.stream),
            minor: req.minor,
            keep_alive,
        };
        if handler.handle(&req, responder).is_err() || !keep_alive {
            break;
        }
    }
    let _ = conn.stream.shutdown(Shutdown::Both);
}

/// Accept connections until `shutdown` fires; one thread per connection,
/// at most `limits.max_connections` at a time (excess gets 503).
pub fn serve(
    listener: TcpListener,
    limits: Limits,
    handler: Arc<dyn Handler>,
    shutdown: ShutdownHandle,
) {
    let active = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        if shutdown.is_shutdown() {
            break;
        }
        let Ok(mut stream) = incoming else { continue };
        if active.load(Ordering::SeqCst) >= limits.max_connections {
            simple(&mut stream, 503, "too many connections");
            continue;
        }
        active.fetch_add(1, Ordering::SeqCst);
        let (limits, handler, active) = (limits.clone(), Arc::clone(&handler), Arc::clone(&active));
        let spawned = std::thread::Builder::new()
            .name("provio-http-conn".into())
            .spawn(move || {
                handle_conn(stream, &limits, handler.as_ref());
                active.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            tracing::warn!("could not spawn connection thread");
        }
    }
}

/// Bind, then run `serve` on a background thread. Returns the bound address
/// and the shutdown handle. Convenience for tests and small servers.
pub fn spawn(
    addr: &str,
    limits: Limits,
    handler: Arc<dyn Handler>,
) -> io::Result<(SocketAddr, ShutdownHandle)> {
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    let handle = ShutdownHandle::new(local);
    let h2 = handle.clone();
    std::thread::Builder::new()
        .name("provio-http-accept".into())
        .spawn(move || serve(listener, limits, handler, h2))?;
    Ok((local, handle))
}
