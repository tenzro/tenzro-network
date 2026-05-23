//! Criterion benchmarks for the `tenzro://` URI parser + display round-trip.
//!
//! Every cross-node fetch over the iroh transport — DA receipts, outer
//! gradients, sealed shards, model weights, agent-memory archives — flows
//! through `TenzroUri::parse` to dispatch to the right resolver branch.
//! Display is the inverse: every URI emitted on the wire or persisted in
//! storage is rendered via `fmt::Display`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use tenzro_iroh::TenzroUri;

const BLAKE3_HEX: &str =
    "5b7a4d8c19f3e0a8b4c7d2e6f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9";

fn bench_parse(c: &mut Criterion) {
    let blob = format!("tenzro://blob/{}", BLAKE3_HEX);
    let blob_hint = format!(
        "tenzro://blob/{}?n={}",
        BLAKE3_HEX,
        "ab".repeat(32),
    );
    let node = format!("tenzro://node/{}", "ab".repeat(32));
    let did = "tenzro://did/did:tenzro:machine:autonomous:550e8400-e29b-41d4-a716-446655440000".to_string();
    let model = format!("tenzro://model/qwen3-0.6b@{}", BLAKE3_HEX);
    let gradient = format!("tenzro://gradient/run-42/17/{}", BLAKE3_HEX);
    let shard = format!("tenzro://shard/{}/{}", BLAKE3_HEX, BLAKE3_HEX);
    let manifest = format!("tenzro://manifest/{}", BLAKE3_HEX);
    let memory = "tenzro://memory/did:tenzro:machine:autonomous:550e8400-e29b-41d4-a716-446655440000/123e4567-e89b-12d3-a456-426614174000".to_string();
    let receipt = format!("tenzro://receipt/settlement/{}", BLAKE3_HEX);

    let mut group = c.benchmark_group("tenzro_uri_parse");
    group.bench_function("blob", |b| {
        b.iter(|| {
            let u = TenzroUri::parse(black_box(&blob)).expect("parse blob");
            black_box(u);
        });
    });
    group.bench_function("blob_with_hint", |b| {
        b.iter(|| {
            let u = TenzroUri::parse(black_box(&blob_hint)).expect("parse blob hint");
            black_box(u);
        });
    });
    group.bench_function("node", |b| {
        b.iter(|| {
            let u = TenzroUri::parse(black_box(&node)).expect("parse node");
            black_box(u);
        });
    });
    group.bench_function("did", |b| {
        b.iter(|| {
            let u = TenzroUri::parse(black_box(&did)).expect("parse did");
            black_box(u);
        });
    });
    group.bench_function("model", |b| {
        b.iter(|| {
            let u = TenzroUri::parse(black_box(&model)).expect("parse model");
            black_box(u);
        });
    });
    group.bench_function("gradient", |b| {
        b.iter(|| {
            let u = TenzroUri::parse(black_box(&gradient)).expect("parse gradient");
            black_box(u);
        });
    });
    group.bench_function("shard", |b| {
        b.iter(|| {
            let u = TenzroUri::parse(black_box(&shard)).expect("parse shard");
            black_box(u);
        });
    });
    group.bench_function("manifest", |b| {
        b.iter(|| {
            let u = TenzroUri::parse(black_box(&manifest)).expect("parse manifest");
            black_box(u);
        });
    });
    group.bench_function("memory", |b| {
        b.iter(|| {
            let u = TenzroUri::parse(black_box(&memory)).expect("parse memory");
            black_box(u);
        });
    });
    group.bench_function("receipt", |b| {
        b.iter(|| {
            let u = TenzroUri::parse(black_box(&receipt)).expect("parse receipt");
            black_box(u);
        });
    });
    group.finish();
}

fn bench_display_roundtrip(c: &mut Criterion) {
    let cases: Vec<TenzroUri> = vec![
        TenzroUri::parse(&format!("tenzro://blob/{}", BLAKE3_HEX)).unwrap(),
        TenzroUri::parse(&format!("tenzro://gradient/run-42/17/{}", BLAKE3_HEX)).unwrap(),
        TenzroUri::parse(&format!("tenzro://model/qwen3-0.6b@{}", BLAKE3_HEX)).unwrap(),
    ];
    let mut group = c.benchmark_group("tenzro_uri_display_roundtrip");
    group.bench_function("blob_gradient_model", |b| {
        b.iter(|| {
            for uri in &cases {
                let s = uri.to_string();
                let parsed = TenzroUri::parse(&s).expect("roundtrip parse");
                black_box(parsed);
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_parse, bench_display_roundtrip);
criterion_main!(benches);
