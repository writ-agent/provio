//! Native policy engine benches (provio-core Contract 2).
//!
//! Measures:
//! - `evaluate` over the shared fixture corpus (first-match-wins rule scan),
//!   plus two single calls that pin the two default paths: a first-rule Deny
//!   and an unmatched call falling through to the policy default.
//! - `provio_policy::policy_file::compile` — the parse/compile path behind
//!   startup and atomic hot-reload (spec §7).
//!
//! Numbers live in criterion stdout for this machine only; there are no
//! performance claims in prose anywhere in the repo.

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use provio_core::{PolicyEngine, ToolCallContext};
use provio_policy::{load_fixtures_dir, NativePolicyEngine};

use provio_bench::{EXAMPLE_POLICY, FIXTURES_DIR};

fn corpus_contexts() -> Vec<ToolCallContext> {
    let fixtures =
        load_fixtures_dir(std::path::Path::new(FIXTURES_DIR)).expect("shared fixture corpus loads");
    fixtures
        .iter()
        .map(|f| f.ctx.to_context().expect("fixture ctx builds"))
        .collect()
}

fn bench_policy(c: &mut Criterion) {
    let mut group = c.benchmark_group("native-policy");
    let engine = NativePolicyEngine::from_source(EXAMPLE_POLICY).expect("example policy compiles");
    let contexts = corpus_contexts();

    group.bench_function("evaluate/fixture-corpus", |b| {
        b.iter(|| {
            for ctx in &contexts {
                black_box(engine.evaluate(black_box(ctx)));
            }
        })
    });

    let deny = ToolCallContext {
        tool: "bash".to_string(),
        command: Some("rm -rf /".to_string()),
        ..ToolCallContext::default()
    };
    group.bench_function("evaluate/single-deny", |b| {
        b.iter(|| black_box(engine.evaluate(black_box(&deny))))
    });

    let unmatched = ToolCallContext {
        tool: "bash".to_string(),
        command: Some("ls -la".to_string()),
        ..ToolCallContext::default()
    };
    group.bench_function("evaluate/single-default-ask", |b| {
        b.iter(|| black_box(engine.evaluate(black_box(&unmatched))))
    });

    group.bench_function("compile/examples-provio-yaml", |b| {
        b.iter(|| black_box(provio_policy::policy_file::compile(black_box(EXAMPLE_POLICY))))
    });

    group.finish();
}

criterion_group! {
    name = benches;
    // Short run so the suite completes in minutes; pass e.g.
    // `cargo bench -- --measurement-time 10` for longer runs.
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2));
    targets = bench_policy
}
criterion_main!(benches);
