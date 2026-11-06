//! Criterion benchmarks for proving and verifying the preimage statement in
//! each proof system, and for the two-system acceptance check.

use std::time::Duration;

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use tenzro_zk::{
    Circuit, DIVERSE_THRESHOLD, ProofSystem, prove, verify_k_of_n, verify_proof_envelope,
};

const WITNESS: [u8; 32] = [0x5a; 32];
const BINDING: [u8; 32] = [0x11; 32];

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("zk_prove");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));
    for system in ProofSystem::ALL {
        group.bench_function(system.as_str(), |b| {
            b.iter(|| black_box(prove(system, Circuit::Settlement, &WITNESS, &BINDING).unwrap()));
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("zk_verify");
    group.sample_size(20);
    for system in ProofSystem::ALL {
        let proof = prove(system, Circuit::Settlement, &WITNESS, &BINDING).unwrap();
        group.bench_function(system.as_str(), |b| {
            b.iter(|| verify_proof_envelope(black_box(&proof)).unwrap());
        });
    }
    let legs: Vec<_> = ProofSystem::ALL
        .into_iter()
        .map(|s| prove(s, Circuit::Settlement, &WITNESS, &BINDING).unwrap())
        .collect();
    group.bench_function("k_of_n_both_systems", |b| {
        b.iter(|| verify_k_of_n(black_box(&legs), DIVERSE_THRESHOLD).unwrap());
    });
    group.finish();
}

criterion_group!(benches, bench_prove, bench_verify);
criterion_main!(benches);
