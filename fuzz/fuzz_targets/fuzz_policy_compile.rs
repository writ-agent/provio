//! Fuzz target: the provio.yaml DSL entry point `provio_policy::policy_file::compile`
//! (plan §8 fuzzing gate: DSL parser).
//!
//! Arbitrary bytes are decoded lossily to UTF-8 and compiled. Parse and
//! validation errors are expected outcomes; a panic, abort or hang is a bug.
//! When a policy does compile, one evaluation pass with representative
//! contexts runs too, so the evaluator hot path cannot panic on any
//! compilable policy either.

#![no_main]

use libfuzzer_sys::fuzz_target;
use provio_core::{PolicyEngine, ToolCallContext};
use provio_policy::NativePolicyEngine;

fuzz_target!(|data: &[u8]| {
    let source = String::from_utf8_lossy(data);
    if let Ok(policy) = provio_policy::policy_file::compile(&source) {
        let _ = policy; // the full compile result: version, default, rules
        if let Ok(engine) = NativePolicyEngine::from_source(&source) {
            for tool in ["bash", "http", "postgres.query", "fs.read", ""] {
                let ctx = ToolCallContext {
                    tool: tool.to_string(),
                    command: Some(data.iter().map(|&b| b as char).take(64).collect()),
                    ..ToolCallContext::default()
                };
                let _ = engine.evaluate(&ctx);
            }
        }
    }
});