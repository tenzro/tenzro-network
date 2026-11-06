//! Criterion benchmarks for the tenzro-identity hot path.
//!
//! - `TenzroDid::parse` — every RPC that takes a DID string runs this once.
//! - `TenzroDid::from_passkey` / `from_device_key` — SHA-256 over the
//!   rooting key; the generation cost on the registration path.
//! - `IdentityRegistry::resolve` — DashMap lookup, the per-RPC hot path.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use tenzro_identity::{IdentityRegistry, TenzroDid};

fn bench_did_parse(c: &mut Criterion) {
    let human = TenzroDid::from_passkey(&[0x11u8; 65]).to_string();
    let machine_under = TenzroDid::delegated_machine("controller-uuid-stub", &[0x22u8; 65])
        .expect("device key")
        .to_string();
    let autonomous = TenzroDid::from_device_key(&[0x5Au8; 65])
        .expect("device key")
        .to_string();
    let mut group = c.benchmark_group("did_parse");
    group.bench_function("human", |b| {
        b.iter(|| {
            black_box(TenzroDid::parse(black_box(&human)).expect("parse"));
        });
    });
    group.bench_function("machine_delegated", |b| {
        b.iter(|| {
            black_box(TenzroDid::parse(black_box(&machine_under)).expect("parse"));
        });
    });
    group.bench_function("machine_autonomous", |b| {
        b.iter(|| {
            black_box(TenzroDid::parse(black_box(&autonomous)).expect("parse"));
        });
    });
    group.finish();
}

fn bench_did_generate(c: &mut Criterion) {
    let mut group = c.benchmark_group("did_generate");
    group.bench_function("human_from_passkey", |b| {
        b.iter(|| {
            black_box(TenzroDid::from_passkey(black_box(&[0x11u8; 65])));
        });
    });
    group.bench_function("autonomous_machine_from_device_key", |b| {
        b.iter(|| {
            let _ = black_box(TenzroDid::from_device_key(&[0x5Au8; 65]));
        });
    });
    group.finish();
}

/// Build a `(registry, machine_did_string)` pair by going through the registry's
/// real async registration path. The default `IdentityRegistry::new()` uses the
/// `DefaultWalletBinder`, which does an in-process wallet provision — slow
/// but a one-time cost outside the benched inner loop.
fn build_seeded_registry() -> (IdentityRegistry, String) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    rt.block_on(async {
        let registry = IdentityRegistry::new();
        let binding = tenzro_identity::WalletBinding {
            wallet_id: "bench-wallet".to_string(),
            address: tenzro_types::primitives::Address::new([0xab; 32]),
            public_key: vec![0xab; 32],
            pq_verifying_key: vec![0xab; 1952],
        };
        let identity = registry
            .register_autonomous_machine_with_binding(
                TenzroDid::from_device_key(&[0xab; 32]).expect("device key"),
                binding,
                vec!["payment".to_string()],
                std::collections::HashMap::new(),
            )
            .await
            .expect("register autonomous machine")
            .identity;
        let machine_did_string = identity.did.to_string();
        (registry, machine_did_string)
    })
}

fn bench_registry_resolve(c: &mut Criterion) {
    let (registry, did) = build_seeded_registry();
    let mut group = c.benchmark_group("registry_resolve");
    group.bench_function("hit_machine_did", |b| {
        b.iter(|| {
            let id = registry.resolve(black_box(&did)).expect("resolve");
            black_box(id);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_did_parse,
    bench_did_generate,
    bench_registry_resolve,
);
criterion_main!(benches);
