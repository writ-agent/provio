//! MCP codec benches (provio-mcp newline-delimited JSON-RPC framing).
//!
//! Measures the codec round-trip the proxy performs per message
//! (`write_frame` serialize + flush, then `read_frame` line read + decode)
//! on in-memory buffers, for two representative payloads: a `tools/call`
//! request and a `tools/list` response carrying tool schemas.
//!
//! Numbers live in criterion stdout for this machine only.

use std::io::BufReader;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json::json;
use provio_mcp::jsonrpc::{read_frame, write_frame, JsonRpcMessage, JsonRpcResponse, RequestId};

fn bench_mcp_codec(c: &mut Criterion) {
    let mut group = c.benchmark_group("mcp-codec");

    let request = JsonRpcMessage::request(
        RequestId::Num(1),
        "tools/call",
        Some(json!({
            "name": "bash",
            "arguments": { "command": "ls -la" },
        })),
    );
    group.bench_function("codec/roundtrip-tools-call", |b| {
        b.iter(|| {
            let mut buf = Vec::new();
            write_frame(&mut buf, black_box(&request)).expect("frame writes");
            let msg = read_frame(BufReader::new(buf.as_slice()))
                .expect("frame reads")
                .expect("exactly one frame");
            black_box(msg);
        })
    });

    // A response-sized payload: tool schemas are the proxy's largest bodies.
    let response = JsonRpcMessage::Response(JsonRpcResponse::result(
        RequestId::Num(2),
        json!({
            "tools": [
                {
                    "name": "bash",
                    "description": "Run a shell command in the workspace.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": { "type": "string" },
                            "timeout_ms": { "type": "integer" }
                        },
                        "required": ["command"]
                    }
                },
                {
                    "name": "fs.read",
                    "description": "Read a file from the allowed roots.",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "path": { "type": "string" } },
                        "required": ["path"]
                    }
                }
            ]
        }),
    ));
    group.bench_function("codec/roundtrip-tools-list", |b| {
        b.iter(|| {
            let mut buf = Vec::new();
            write_frame(&mut buf, black_box(&response)).expect("frame writes");
            let msg = read_frame(BufReader::new(buf.as_slice()))
                .expect("frame reads")
                .expect("exactly one frame");
            black_box(msg);
        })
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2));
    targets = bench_mcp_codec
}
criterion_main!(benches);
