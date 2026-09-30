//! Ledger benches on the ADR-005 default store (`FileLedgerStore`, JSONL).
//!
//! Measures:
//! - `append`: one decision record + one linked execution record per
//!   iteration via `LedgerWriter` — the two-phase write path (ADR-003).
//!   Every append is flushed and fsync'd, so these numbers track this
//!   machine's disk, not provio's code alone.
//! - `verify`: whole-file hash-chain verification (`provio_ledger::verify`)
//!   over a pre-built 200-record ledger (100 decision/execution pairs).
//!
//! The append ledger keeps growing across criterion iterations; that matches
//! the production shape (records are append-only, never mutated). Numbers
//! live in criterion stdout for this machine only.

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use provio_core::ledger::LedgerWriter;
use provio_core::verdict::Verdict;
use provio_ledger::FileLedgerStore;

use provio_bench::{remove_temp_dir, sample_call, unique_temp_dir};

const VERIFY_RECORDS: u64 = 200;

fn bench_ledger(c: &mut Criterion) {
    let mut group = c.benchmark_group("ledger");
    let verdict = Verdict::Allow {
        rule_id: Some("bench-allow".to_string()),
    };

    // Append: two records (decision + execution) per iteration. The writer
    // borrows the store, so both live in this block.
    let append_dir = unique_temp_dir("append");
    {
        let mut append_store = FileLedgerStore::open(&append_dir).expect("tempdir ledger opens");
        let call = sample_call("bench-call");
        let mut writer = LedgerWriter::new(&mut append_store);
        group.bench_function("append/decision+execution", |b| {
            b.iter(|| {
                let decision = writer
                    .record_decision(black_box(&call), black_box(&verdict), None)
                    .expect("append succeeds");
                writer
                    .record_execution(&decision, "local-os", 0, b"bench output")
                    .expect("append succeeds");
            })
        });
    }
    remove_temp_dir(&append_dir);

    // Verify: whole-file chain verification over a pre-built ledger.
    let verify_dir = unique_temp_dir("verify");
    let path = {
        let mut verify_store = FileLedgerStore::open(&verify_dir).expect("tempdir ledger opens");
        let mut writer = LedgerWriter::new(&mut verify_store);
        for i in 0..VERIFY_RECORDS / 2 {
            let decision = writer
                .record_decision(&sample_call(&format!("bench-call-{i}")), &verdict, None)
                .expect("append succeeds");
            writer
                .record_execution(&decision, "local-os", 0, b"bench output")
                .expect("append succeeds");
        }
        verify_store.path().to_path_buf()
    };
    group.bench_function("verify/200-records", |b| {
        b.iter(|| provio_ledger::verify(black_box(&path)).expect("verify runs"))
    });
    remove_temp_dir(&verify_dir);

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2));
    targets = bench_ledger
}
criterion_main!(benches);
