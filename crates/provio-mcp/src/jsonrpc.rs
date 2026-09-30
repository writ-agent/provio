//! JSON-RPC 2.0 message types and newline-delimited framing (MCP stdio
//! transport: one message per line, UTF-8, no embedded newlines).
//!
//! serde_json::to_string never emits raw U+000A inside strings (it escapes
//! them), so a serialized message is always exactly one frame line.

use provio_core::{ProvioError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::fmt;
use std::io::{BufRead, Write};

/// JSON-RPC request id: per spec, a number or a string (null ids are only
/// used on protocol-level parse errors, which we never generate).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    Num(u64),
    Str(String),
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RequestId::Num(n) => write!(f, "{n}"),
            RequestId::Str(s) => f.write_str(s),
        }
    }
}

/// JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: RequestId,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    pub fn new(id: RequestId, method: impl Into<String>, params: Option<Value>) -> Self {
        JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id,
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: RequestId,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn result(id: RequestId, result: Value) -> Self {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: RequestId, error: JsonRpcError) -> Self {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }

    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub params: Option<Value>,
}

impl JsonRpcNotification {
    pub fn new(method: impl Into<String>, params: Option<Value>) -> Self {
        JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params,
        }
    }
}

/// Any JSON-RPC 2.0 message on the wire. Deserialization sniffs the shape:
/// `method` + `id` → request, `method` without `id` → notification,
/// `result`/`error` → response.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonRpcMessage {
    Request(JsonRpcRequest),
    Response(JsonRpcResponse),
    Notification(JsonRpcNotification),
}

impl JsonRpcMessage {
    pub fn request(id: RequestId, method: impl Into<String>, params: Option<Value>) -> Self {
        JsonRpcMessage::Request(JsonRpcRequest::new(id, method, params))
    }

    pub fn notification(method: impl Into<String>, params: Option<Value>) -> Self {
        JsonRpcMessage::Notification(JsonRpcNotification::new(method, params))
    }
}

impl Serialize for JsonRpcMessage {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            JsonRpcMessage::Request(r) => r.serialize(s),
            JsonRpcMessage::Response(r) => r.serialize(s),
            JsonRpcMessage::Notification(n) => n.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for JsonRpcMessage {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error;
        let v = Value::deserialize(d)?;
        let has_method = v.get("method").is_some();
        let has_id = v.get("id").is_some();
        if has_method && has_id {
            serde_json::from_value(v)
                .map(JsonRpcMessage::Request)
                .map_err(D::Error::custom)
        } else if has_method {
            serde_json::from_value(v)
                .map(JsonRpcMessage::Notification)
                .map_err(D::Error::custom)
        } else if v.get("result").is_some() || v.get("error").is_some() {
            serde_json::from_value(v)
                .map(JsonRpcMessage::Response)
                .map_err(D::Error::custom)
        } else {
            Err(D::Error::custom(
                "not a JSON-RPC 2.0 request, response, or notification",
            ))
        }
    }
}

/// Write one newline-delimited frame.
pub fn write_frame<W: Write>(mut w: W, msg: &JsonRpcMessage) -> Result<()> {
    let line = serde_json::to_string(msg)?;
    w.write_all(line.as_bytes())?;
    w.write_all(b"\n")?;
    w.flush()?;
    Ok(())
}

/// Read one newline-delimited frame. Returns `Ok(None)` on clean EOF;
/// blank lines are skipped.
pub fn read_frame<R: BufRead>(mut r: R) -> Result<Option<JsonRpcMessage>> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = r.read_line(&mut line).map_err(ProvioError::Io)?;
        if n == 0 {
            return Ok(None);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return serde_json::from_str(trimmed)
            .map(Some)
            .map_err(ProvioError::Serde);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::BufReader;

    #[test]
    fn request_roundtrip_num_id() {
        let msg = JsonRpcMessage::request(
            RequestId::Num(7),
            "tools/call",
            Some(json!({"name": "bash", "arguments": {"command": "ls"}})),
        );
        let s = serde_json::to_string(&msg).unwrap();
        let back: JsonRpcMessage = serde_json::from_str(&s).unwrap();
        assert_eq!(msg, back);
        match back {
            JsonRpcMessage::Request(r) => {
                assert_eq!(r.jsonrpc, "2.0");
                assert_eq!(r.id, RequestId::Num(7));
                assert_eq!(r.method, "tools/call");
            }
            other => panic!("expected request, got {other:?}"),
        }
    }

    #[test]
    fn request_roundtrip_string_id() {
        let msg = JsonRpcMessage::request(RequestId::Str("abc-123".into()), "ping", None);
        let s = serde_json::to_string(&msg).unwrap();
        let back: JsonRpcMessage = serde_json::from_str(&s).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn response_result_roundtrip() {
        let msg = JsonRpcMessage::Response(JsonRpcResponse::result(
            RequestId::Num(1),
            json!({"tools": []}),
        ));
        let s = serde_json::to_string(&msg).unwrap();
        assert!(!s.contains("\"error\""));
        let back: JsonRpcMessage = serde_json::from_str(&s).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn response_error_roundtrip() {
        let err = JsonRpcError {
            code: -32000,
            message: "rule R07: denied".into(),
            data: Some(json!({"provio_refusal": true})),
        };
        let msg = JsonRpcMessage::Response(JsonRpcResponse::error(RequestId::Str("x".into()), err));
        let s = serde_json::to_string(&msg).unwrap();
        assert!(!s.contains("\"result\""));
        let back: JsonRpcMessage = serde_json::from_str(&s).unwrap();
        match back {
            JsonRpcMessage::Response(r) => {
                assert!(r.is_error());
                assert_eq!(r.error.unwrap().code, -32000);
            }
            other => panic!("expected response, got {other:?}"),
        }
    }

    #[test]
    fn notification_roundtrip() {
        let msg = JsonRpcMessage::notification("notifications/initialized", None);
        let s = serde_json::to_string(&msg).unwrap();
        let back: JsonRpcMessage = serde_json::from_str(&s).unwrap();
        assert_eq!(msg, back);
        match back {
            JsonRpcMessage::Notification(n) => assert_eq!(n.method, "notifications/initialized"),
            other => panic!("expected notification, got {other:?}"),
        }
    }

    #[test]
    fn rejects_garbage() {
        let r: std::result::Result<JsonRpcMessage, _> = serde_json::from_str("{\"foo\": 1}");
        assert!(r.is_err());
    }

    #[test]
    fn frame_roundtrip_with_embedded_newline_in_params() {
        let msg = JsonRpcMessage::request(
            RequestId::Num(9),
            "tools/call",
            Some(json!({"name": "write", "arguments": {"text": "line1\nline2"}})),
        );
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &msg).unwrap();
        // exactly one frame line despite the newline inside the payload
        assert_eq!(buf.iter().filter(|b| **b == b'\n').count(), 1);
        let back = read_frame(BufReader::new(&buf[..])).unwrap().unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn read_frame_eof_and_blank_lines() {
        let buf = b"\n\n".to_vec();
        assert!(read_frame(BufReader::new(&buf[..])).unwrap().is_none());
        let empty: Vec<u8> = Vec::new();
        assert!(read_frame(BufReader::new(&empty[..])).unwrap().is_none());
    }

    #[test]
    fn request_id_display() {
        assert_eq!(RequestId::Num(42).to_string(), "42");
        assert_eq!(RequestId::Str("s".into()).to_string(), "s");
    }
}
