//! Criterion benchmarks for tenzro-training hot paths.
//!
//! - `compute_payload_hash` — runs on every outer-gradient publish + verify.
//! - `compute_state_root` — runs on every `finalize_round` per round.
//! - `compute_run_root` — Merkle tree over per-round state roots; runs once
//!   per finalize.
//! - `MeanAggregator::aggregate` — runs at the end of every fragment quorum.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ndarray::Array1;

use tenzro_training::{
    aggregator_for, compute_payload_hash, compute_run_root, compute_state_root, AggregationRule,
};
use tenzro_types::primitives::Hash;
use tenzro_types::training::FragmentQuorumStatus;

const TRAINER_COUNT: usize = 8;
const PARAM_DIM: usize = 4096;
const ROUNDS: usize = 64;
const FRAGMENTS: usize = 16;

fn bench_payload_hash(c: &mut Criterion) {
    // Typical safetensors per-fragment outer-gradient envelope is on the
    // order of 4-16 MiB. Bench at 4 MiB to keep the run reasonable.
    let payload = vec![0xab; 4 * 1024 * 1024];
    let mut group = c.benchmark_group("training_payload_hash");
    group.bench_function("sha256_4MiB", |b| {
        b.iter(|| {
            let h = compute_payload_hash(black_box(&payload));
            black_box(h);
        });
    });
    group.finish();
}

fn make_fragments(n: usize, per_fragment_acceptances: usize) -> Vec<FragmentQuorumStatus> {
    (0..n as u32)
        .map(|f| FragmentQuorumStatus {
            fragment: f,
            accepted: per_fragment_acceptances as u32,
            accepted_hashes: (0..per_fragment_acceptances)
                .map(|i| {
                    let mut bytes = [0u8; 32];
                    bytes[0] = f as u8;
                    bytes[1] = i as u8;
                    Hash::new(bytes)
                })
                .collect(),
            quorum_met: true,
            post_step_hash: Hash::new([f as u8; 32]),
        })
        .collect()
}

fn bench_state_root(c: &mut Criterion) {
    let fragments = make_fragments(FRAGMENTS, TRAINER_COUNT);
    let mut group = c.benchmark_group("training_state_root");
    group.bench_function("16_fragments_8_trainers", |b| {
        b.iter(|| {
            let h = compute_state_root(
                black_box("task-bench"),
                black_box(7),
                black_box(&fragments),
            );
            black_box(h);
        });
    });
    group.finish();
}

fn bench_run_root(c: &mut Criterion) {
    let roots: Vec<Hash> = (0..ROUNDS as u32)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&i.to_be_bytes());
            Hash::new(bytes)
        })
        .collect();
    let mut group = c.benchmark_group("training_run_root");
    group.bench_function("64_rounds_merkle", |b| {
        b.iter(|| {
            let h = compute_run_root(black_box(&roots));
            black_box(h);
        });
    });
    group.finish();
}

fn bench_mean_aggregator(c: &mut Criterion) {
    let aggregator = aggregator_for(AggregationRule::Mean);
    let gradients: Vec<Array1<f32>> = (0..TRAINER_COUNT)
        .map(|i| Array1::from_elem(PARAM_DIM, i as f32))
        .collect();
    let mut group = c.benchmark_group("training_aggregate");
    group.bench_function("mean_8_trainers_4096_dim", |b| {
        b.iter(|| {
            let views: Vec<_> = gradients.iter().map(|g| g.view()).collect();
            let aggregated = aggregator.aggregate(black_box(&views)).expect("aggregate");
            black_box(aggregated);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_payload_hash,
    bench_state_root,
    bench_run_root,
    bench_mean_aggregator,
);
criterion_main!(benches);
