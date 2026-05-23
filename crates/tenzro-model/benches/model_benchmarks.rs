//! Criterion benchmarks for tenzro-model hot paths.
//!
//! - `PricingEngine::calculate_cost` — runs on every paid inference response
//!   to compute the per-token cost the router charges back to the requester.
//! - `PricingEngine::calculate_price` — dynamic per-request price for routing
//!   decisions; consulted before dispatching to a provider.
//! - `ProviderManager::record_success` — write path on every completed
//!   inference; touches reputation + metrics + (optionally) RocksDB.
//! - `ProviderManager::get_reputation` — read path on every routing decision
//!   under `RoutingStrategy::Reputation` / `Cortex` / `Weighted`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use tenzro_model::{PricingEngine, ProviderManager};
use tenzro_types::model::{InferenceMetadata, InferenceProvider, PricingConfig, PricingModel};
use tenzro_types::primitives::Address;

fn addr(byte: u8) -> Address {
    Address::new([byte; 32])
}

fn pricing_per_token() -> PricingConfig {
    PricingConfig {
        price_per_input_token: 10,
        price_per_output_token: 20,
        minimum_price: 100,
        pricing_model: PricingModel::PerToken,
    }
}

fn metadata_typical() -> InferenceMetadata {
    InferenceMetadata {
        input_tokens: 512,
        output_tokens: 256,
        latency_ms: 850,
        model_version: None,
        finish_reason: None,
    }
}

fn bench_calculate_cost(c: &mut Criterion) {
    let engine = PricingEngine::new();
    let pricing = pricing_per_token();
    let metadata = metadata_typical();
    let mut group = c.benchmark_group("pricing_calculate_cost");
    group.bench_function("per_token_512in_256out", |b| {
        b.iter(|| {
            let cost = engine
                .calculate_cost(black_box(&pricing), black_box(&metadata))
                .expect("calculate_cost");
            black_box(cost);
        });
    });
    group.finish();
}

fn bench_calculate_price(c: &mut Criterion) {
    let engine = PricingEngine::new();
    let pricing = pricing_per_token();
    let mut group = c.benchmark_group("pricing_calculate_price");
    group.bench_function("dynamic_7b_50pct_load_no_market", |b| {
        b.iter(|| {
            let p = engine.calculate_price(
                black_box("qwen3-7b"),
                black_box("provider-1"),
                black_box(&pricing),
                black_box(7.0),
                black_box(0.5),
            );
            black_box(p);
        });
    });
    // Pre-populate market history to exercise the blending branch.
    for _ in 0..200 {
        engine.update_market_price("qwen3-7b".to_string(), 1500);
    }
    group.bench_function("dynamic_7b_50pct_load_with_market", |b| {
        b.iter(|| {
            let p = engine.calculate_price(
                black_box("qwen3-7b"),
                black_box("provider-1"),
                black_box(&pricing),
                black_box(7.0),
                black_box(0.5),
            );
            black_box(p);
        });
    });
    group.finish();
}

fn seeded_provider_manager() -> (ProviderManager, Address) {
    let manager = ProviderManager::new();
    let address = addr(0x42);
    let provider = InferenceProvider::new(address, "bench-provider".to_string());
    manager
        .register_provider(provider, /* has_tee */ false)
        .expect("register_provider");
    (manager, address)
}

fn bench_record_success(c: &mut Criterion) {
    let (manager, address) = seeded_provider_manager();
    let mut group = c.benchmark_group("provider_manager_record_success");
    group.bench_function("in_memory", |b| {
        b.iter(|| {
            manager.record_success(black_box(&address), black_box(75));
        });
    });
    group.finish();
}

fn bench_get_reputation(c: &mut Criterion) {
    let (manager, address) = seeded_provider_manager();
    // Bump reputation a few times so the read path returns a non-zero value.
    for _ in 0..50 {
        manager.record_success(&address, 75);
    }
    let unknown = addr(0x99);
    let mut group = c.benchmark_group("provider_manager_get_reputation");
    group.bench_function("hit", |b| {
        b.iter(|| {
            let r = manager.get_reputation(black_box(&address));
            black_box(r);
        });
    });
    group.bench_function("miss", |b| {
        b.iter(|| {
            let r = manager.get_reputation(black_box(&unknown));
            black_box(r);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_calculate_cost,
    bench_calculate_price,
    bench_record_success,
    bench_get_reputation,
);
criterion_main!(benches);
