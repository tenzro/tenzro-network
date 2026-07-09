//! Criterion benchmarks for the Red Stuff two-dimensional Reed-Solomon core
//! behind the committee data-availability backend.
//!
//! Covers, per committee shape (n=4/f=1 and n=10/f=3) and blob size:
//! - `encode` — blob → 2n slivers + Merkle commitment (the writer hot path)
//! - `verify_sliver` — Merkle proof check a member runs before custody
//! - `reconstruct` — quorum of secondary slivers → blob, including the
//!   fail-closed re-encode commitment check (the reader hot path)
//!
//! Throughput is reported in bytes of source blob per second, so the numbers
//! compare directly against other DA layers' MB/s figures.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use tenzro_storage::redstuff::{self, CommitteeShape, SliverPair};

const KIB: usize = 1024;
const MIB: usize = 1024 * 1024;

/// Deterministic non-uniform payload so RS coding does not run over all-zero
/// symbols.
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn shapes() -> Vec<(&'static str, CommitteeShape)> {
    vec![
        ("n4", CommitteeShape::from_committee_size(4).unwrap()),
        ("n10", CommitteeShape::from_committee_size(10).unwrap()),
    ]
}

fn blob_sizes() -> Vec<(&'static str, usize)> {
    vec![("64KiB", 64 * KIB), ("1MiB", MIB), ("8MiB", 8 * MIB)]
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("redstuff_encode");
    for (shape_label, shape) in shapes() {
        for (size_label, size) in blob_sizes() {
            let data = payload(size);
            group.throughput(Throughput::Bytes(size as u64));
            if size >= 8 * MIB {
                group.sample_size(20);
            }
            group.bench_with_input(
                BenchmarkId::new(shape_label, size_label),
                &data,
                |b, data| {
                    b.iter(|| redstuff::encode(black_box(data), shape).expect("encode"));
                },
            );
        }
    }
    group.finish();
}

fn bench_verify_sliver(c: &mut Criterion) {
    let mut group = c.benchmark_group("redstuff_verify_sliver");
    for (shape_label, shape) in shapes() {
        let data = payload(MIB);
        let enc = redstuff::encode(&data, shape).expect("encode");
        let sliver = enc.slivers[0].clone();
        group.bench_function(BenchmarkId::new(shape_label, "1MiB"), |b| {
            b.iter(|| {
                assert!(redstuff::verify_sliver(
                    black_box(&sliver),
                    shape,
                    enc.blob_len,
                    enc.symbol_len,
                    &enc.commitment,
                ));
            });
        });
    }
    group.finish();
}

fn bench_reconstruct(c: &mut Criterion) {
    let mut group = c.benchmark_group("redstuff_reconstruct");
    for (shape_label, shape) in shapes() {
        for (size_label, size) in [("1MiB", MIB), ("8MiB", 8 * MIB)] {
            let data = payload(size);
            let enc = redstuff::encode(&data, shape).expect("encode");
            // Exact quorum of secondary slivers, skipping the first f members
            // so decoding exercises actual RS recovery rather than a straight
            // copy of the systematic symbols.
            let subset: Vec<SliverPair> = enc
                .slivers
                .iter()
                .filter(|s| s.node_index >= shape.f)
                .take(shape.quorum())
                .cloned()
                .collect();
            assert_eq!(subset.len(), shape.quorum());
            group.throughput(Throughput::Bytes(size as u64));
            if size >= 8 * MIB {
                group.sample_size(20);
            }
            group.bench_with_input(
                BenchmarkId::new(shape_label, size_label),
                &subset,
                |b, subset| {
                    b.iter(|| {
                        let out = redstuff::reconstruct(
                            black_box(subset),
                            shape,
                            enc.blob_len,
                            enc.symbol_len,
                            &enc.commitment,
                        )
                        .expect("reconstruct");
                        assert_eq!(out.len(), data.len());
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_encode, bench_verify_sliver, bench_reconstruct);
criterion_main!(benches);
