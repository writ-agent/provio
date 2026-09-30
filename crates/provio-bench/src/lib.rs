//! Criterion benches for provio's hot paths (plan §3.4 / §8: published benches
//! replace all prose numbers — claim discipline).
//!
//! This crate is deliberately outside the root workspace: it depends on the
//! workspace crates via path and carries the bench-only dependency
//! (criterion). Run with `cargo bench` from this directory. Every number the
//! benches produce is criterion output measured on the machine that ran them;
//! nothing in this crate asserts or promises performance in prose.
//!
//! Shared helpers live here so each bench file stays a thin list of groups:
//! - [`EXAMPLE_POLICY`] / [`FIXTURES_DIR`] — the shared fixture corpus
//!   (INTERFACES.md Contract 2) evaluated against `examples/provio.yaml`.
//! - [`sample_call`] — a representative `ToolCall` for the ledger benches.
//! - [`unique_temp_dir`] — ADR-007 std-only temp dir (no `tempfile` dep).

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use provio_core::call::{CallerIdentity, ToolCall};
use provio_core::Timestamp;

/// The example policy all spec-example fixtures evaluate against.
pub const EXAMPLE_POLICY: &str = include_str!("../../../examples/provio.yaml");

/// The shared policy fixture corpus (INTERFACES.md Contract 2).
pub const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../provio-policy/fixtures");

/// A representative MCP-`tools/call`-shaped call for the ledger benches.
pub fn sample_call(id: &str) -> ToolCall {
    ToolCall {
        call_id: id.to_string(),
        session_id: "bench-session".to_string(),
        caller: CallerIdentity {
            agent: "provio-bench".to_string(),
            agent_version: None,
            user: None,
            non_human_id: None,
        },
        mode: provio_core::InterceptMode::Mcp,
        tool: "bash".to_string(),
        args: serde_json::json!({ "command": "ls -la" }),
        server: None,
        trust: None,
        captured_at: Timestamp::now(),
    }
}

/// Unique temp-dir path (ADR-007: std-only, no `tempfile` dependency).
pub fn unique_temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "provio-bench-{}-{}-{}",
        tag,
        std::process::id(),
        nanos
    ))
}

/// Best-effort cleanup; bench output must not depend on it succeeding.
pub fn remove_temp_dir(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}
