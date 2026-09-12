//! Criterion benchmarks for the tenzro-identity hot path.
//!
//! - `TenzroDid::parse` — every RPC that takes a DID string runs this once.
//! - `TenzroDid::new_human / new_machine` — UUID v4;
//!   `from_hardware_root` — SHA-256 over the platform root
//!   generation cost on the registration path.
//! - `IdentityRegistry::resolve` — DashMap lookup, the per-RPC hot path.
//! - `IdentityRegistry::enforce_operation` — runs on every binder-mediated
//!   payment.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use tenzro_identity::{IdentityRegistry, TenzroDid};

fn bench_did_parse(c: &mut Criterion) {
    let human = TenzroDid::new_human().to_string();
    let machine_under = TenzroDid::new_machine("controller-uuid-stub").to_string();
    let autonomous = TenzroDid::from_hardware_root(&[0x5Au8; 32])
        .expect("non-zero root")
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
    group.bench_function("human_new", |b| {
        b.iter(|| {
            black_box(TenzroDid::new_human());
        });
    });
    group.bench_function("autonomous_machine_from_hardware_root", |b| {
        b.iter(|| {
            black_box(TenzroDid::from_hardware_root(&[0x5Au8; 32]));
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
        let identity = registry
            .register_autonomous_machine(
                vec![0xab; 32],
                vec!["payment".to_string()],
                tenzro_identity::identity::MachineAnchor::hardware_rooted("ab".repeat(32), vec!["tpm:ek".to_string()]),
            )
            .await
            .expect("register autonomous machine");
        let machine_did_string = identity.did.to_string();
        // Patch the delegation scope so `enforce_operation` accepts a "payment"
        // call with a small value. We do this through the registry's public
        // update API.
        registry
            .update_delegation_scope(
                &machine_did_string,
                tenzro_identity::DelegationScope::unrestricted()
                    .with_max_transaction_value(1_000_000_000)
                    .with_allowed_operations(vec!["payment".to_string()]),
            )
            .expect("update delegation scope");
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

fn bench_enforce_operation(c: &mut Criterion) {
    let (registry, did) = build_seeded_registry();
    let mut group = c.benchmark_group("enforce_operation");
    group.bench_function("payment_within_scope", |b| {
        b.iter(|| {
            registry
                .enforce_operation(black_box(&did), black_box("payment"), black_box(Some(100)))
                .expect("within scope");
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_did_parse,
    bench_did_generate,
    bench_registry_resolve,
    bench_enforce_operation,
);
criterion_main!(benches);
