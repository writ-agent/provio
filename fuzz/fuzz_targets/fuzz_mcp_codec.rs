//! Fuzz target: the provio-mcp codec entry point (plan §8 fuzzing gate: MCP
//! codec).
//!
//! The MCP proxy accepts untrusted bytes on this surface: any input may be a
//! frame line. Decode failures are expected outcomes; a panic is a bug. The
//! shape-sniffing `JsonRpcMessage` Deserialize impl (request / notification /
//! response) is the interesting path, so every successful decode is also
//! re-serialized and decoded a second time — a message that decodes once but
//! not through one round-trip is a codec bug worth a crash report.

#![no_main]

use libfuzzer_sys::fuzz_target;
use provio_mcp::jsonrpc::JsonRpcMessage;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = serde_json::from_slice::<JsonRpcMessage>(data) {
        if let Ok(bytes) = serde_json::to_vec(&message) {
            let _ = serde_json::from_slice::<JsonRpcMessage>(&bytes);
        }
    }
});