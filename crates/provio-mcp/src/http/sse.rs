//! Server-Sent Events codec (WHATWG HTML §9.2 event stream format), as used
//! by MCP Streamable HTTP response streams and the legacy HTTP+SSE
//! transport. The reader is a relay-oriented parser: it keeps `id`,
//! `event`, `retry` and comment lines so a proxy can re-emit an event
//! faithfully, and bounds line and event sizes.

use std::io::{self, BufRead};

/// One SSE event block (everything up to a blank line).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SseEvent {
    /// `event:` field; `None` means the default type (`message`).
    pub event: Option<String>,
    /// `data:` lines joined with `\n` (the trailing newline removed).
    pub data: String,
    /// `id:` field (the resumption cursor, `Last-Event-ID`).
    pub id: Option<String>,
    /// `retry:` reconnection delay in milliseconds.
    pub retry: Option<u64>,
    /// Comment lines (text after the leading `:`), e.g. keep-alives.
    pub comments: Vec<String>,
}

impl SseEvent {
    /// A default-type event carrying `data`.
    pub fn message(data: impl Into<String>) -> Self {
        SseEvent {
            data: data.into(),
            ..Default::default()
        }
    }

    /// A comment-only block (keep-alive).
    pub fn keepalive() -> Self {
        SseEvent {
            comments: vec![String::new()],
            ..Default::default()
        }
    }

    /// Serialize as an event block terminated by a blank line. Field values
    /// never contain raw CR/LF (they are split into several `data:` lines
    /// or stripped), so one event cannot be forged into two.
    pub fn encode(&self) -> Vec<u8> {
        let clean = |s: &str| s.replace(['\r', '\n'], "");
        let mut out = String::new();
        for c in &self.comments {
            out.push(':');
            out.push_str(&clean(c));
            out.push('\n');
        }
        if let Some(e) = &self.event {
            out.push_str("event: ");
            out.push_str(&clean(e));
            out.push('\n');
        }
        if let Some(id) = &self.id {
            out.push_str("id: ");
            out.push_str(&clean(id));
            out.push('\n');
        }
        if let Some(r) = self.retry {
            out.push_str(&format!("retry: {r}\n"));
        }
        let has_fields = self.event.is_some() || self.id.is_some() || self.retry.is_some();
        if !self.data.is_empty() || has_fields {
            for line in self.data.split('\n') {
                out.push_str("data: ");
                out.push_str(line.trim_end_matches('\r'));
                out.push('\n');
            }
        }
        out.push('\n');
        out.into_bytes()
    }

    /// True when the block carries no event fields (comments only).
    pub fn is_comment_only(&self) -> bool {
        self.event.is_none() && self.id.is_none() && self.retry.is_none() && self.data.is_empty()
    }
}

/// Incremental SSE parser over any buffered reader.
pub struct SseReader<R: BufRead> {
    reader: R,
    max_event_bytes: usize,
    done: bool,
}

impl<R: BufRead> SseReader<R> {
    pub fn new(reader: R, max_event_bytes: usize) -> Self {
        SseReader {
            reader,
            max_event_bytes,
            done: false,
        }
    }

    /// Read one line (without its terminator) bounded by `limit` bytes.
    /// Ok(None) = EOF before any byte.
    fn read_line(&mut self, limit: usize) -> io::Result<Option<String>> {
        let mut buf = Vec::new();
        loop {
            let available = match self.reader.fill_buf() {
                Ok(b) => b,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if available.is_empty() {
                if buf.is_empty() {
                    return Ok(None);
                }
                break;
            }
            match available.iter().position(|b| *b == b'\n') {
                Some(pos) => {
                    buf.extend_from_slice(&available[..pos]);
                    self.reader.consume(pos + 1);
                    break;
                }
                None => {
                    let n = available.len();
                    buf.extend_from_slice(available);
                    self.reader.consume(n);
                }
            }
            if buf.len() > limit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSE line exceeds the size limit",
                ));
            }
        }
        if buf.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SSE line exceeds the size limit",
            ));
        }
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        String::from_utf8(buf)
            .map(Some)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "SSE stream is not UTF-8"))
    }

    /// Next event block, or Ok(None) at end of stream.
    pub fn next_event(&mut self) -> io::Result<Option<SseEvent>> {
        if self.done {
            return Ok(None);
        }
        let mut ev = SseEvent::default();
        let mut data_lines: Vec<String> = Vec::new();
        let mut seen = false;
        let mut size = 0usize;
        loop {
            let remaining = self.max_event_bytes.saturating_sub(size);
            let Some(line) = self.read_line(remaining)? else {
                self.done = true;
                // A block cut off by EOF is discarded (WHATWG: incomplete
                // events are not dispatched).
                return Ok(None);
            };
            size += line.len() + 1;
            if size > self.max_event_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSE event exceeds the size limit",
                ));
            }
            if line.is_empty() {
                if seen {
                    ev.data = data_lines.join("\n");
                    return Ok(Some(ev));
                }
                continue;
            }
            seen = true;
            if let Some(c) = line.strip_prefix(':') {
                ev.comments.push(c.to_string());
                continue;
            }
            let (field, value) = match line.find(':') {
                Some(i) => {
                    let v = &line[i + 1..];
                    (&line[..i], v.strip_prefix(' ').unwrap_or(v))
                }
                None => (line.as_str(), ""),
            };
            match field {
                "data" => data_lines.push(value.to_string()),
                "event" => ev.event = Some(value.to_string()),
                "id" => {
                    if !value.contains('\0') {
                        ev.id = Some(value.to_string());
                    }
                }
                "retry" => {
                    if let Ok(ms) = value.parse::<u64>() {
                        ev.retry = Some(ms);
                    }
                }
                _ => {} // unknown fields are ignored per the SSE spec
            }
        }
    }
}

impl<R: BufRead> Iterator for SseReader<R> {
    type Item = io::Result<SseEvent>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.next_event() {
            Ok(Some(e)) => Some(Ok(e)),
            Ok(None) => None,
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Vec<SseEvent> {
        SseReader::new(s.as_bytes(), 1 << 20)
            .collect::<io::Result<Vec<_>>>()
            .unwrap()
    }

    #[test]
    fn parses_fields_multiline_data_and_comments() {
        let evs = parse(": ping\n\nevent: endpoint\ndata: /messages?s=1\n\nid: 7\nretry: 500\ndata: a\ndata: b\n\n");
        assert_eq!(evs.len(), 3);
        assert!(evs[0].is_comment_only());
        assert_eq!(evs[1].event.as_deref(), Some("endpoint"));
        assert_eq!(evs[1].data, "/messages?s=1");
        assert_eq!(evs[2].id.as_deref(), Some("7"));
        assert_eq!(evs[2].retry, Some(500));
        assert_eq!(evs[2].data, "a\nb");
    }

    #[test]
    fn crlf_and_incomplete_trailing_block() {
        let evs = parse("data: x\r\n\r\ndata: cut-off");
        assert_eq!(evs, vec![SseEvent::message("x")]);
    }

    #[test]
    fn encode_roundtrip_including_priming_event() {
        let ev = SseEvent {
            id: Some("s1-0".into()),
            ..Default::default()
        };
        let back = parse(std::str::from_utf8(&ev.encode()).unwrap());
        assert_eq!(back, vec![ev]);

        let ev = SseEvent {
            event: Some("message".into()),
            data: "{\"a\":1}\nsecond".into(),
            id: Some("9".into()),
            retry: Some(10),
            comments: vec![],
        };
        let back = parse(std::str::from_utf8(&ev.encode()).unwrap());
        assert_eq!(back, vec![ev]);
    }

    #[test]
    fn encode_cannot_be_split_by_injected_newlines() {
        let ev = SseEvent {
            id: Some("1\n\ndata: forged".into()),
            data: "ok".into(),
            ..Default::default()
        };
        let back = parse(std::str::from_utf8(&ev.encode()).unwrap());
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].data, "ok");
    }

    #[test]
    fn oversized_event_is_an_error() {
        let big = format!("data: {}\n\n", "x".repeat(100));
        let mut r = SseReader::new(big.as_bytes(), 50);
        assert!(r.next().unwrap().is_err());
        assert!(r.next().is_none());
    }
}
