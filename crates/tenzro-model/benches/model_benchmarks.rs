//! Criterion benchmarks for tenzro-model hot paths.
//!
//! - `PriceContext::charge_wei` — runs on every paid inference response to
//!   price the call's meter on its provider's card.
//! - `ProviderManager::record_success` — write path on every completed
//!   inference; touches reputation + metrics + (optionally) RocksDB.
//! - `ProviderManager::get_reputation` — read path on every routing decision
//!   under `RoutingStrategy::HighestReputation` / `WeightedScore`.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use tenzro_model::{PriceContext, ProviderManager};
use tenzro_types::meter::unit;
use tenzro_types::model::{BillableUnits, InferenceProvider};
use tenzro_types::price_card::{Denom, Rate, RateCard};
use tenzro_types::primitives::Address;

fn addr(byte: u8) -> Address {
    Address::new([byte; 32])
}

fn card() -> RateCard {
    RateCard {
        denom: Denom::NanoUsd,
        lines: [
            (unit::INPUT_TOKENS, 200_000_000u128, 6u8),
            (unit::OUTPUT_TOKENS, 1_000_000_000, 6),
            (unit::CACHED_READ_TOKENS, 20_000_000, 6),
            (unit::CACHED_WRITE_TOKENS, 250_000_000, 6),
            (unit::REASONING_LOOPS, 1_000, 0),
            (unit::IMAGE_TOKENS, 200_000_000, 6),
            (unit::AUDIO_MS, 100_000, 3),
            (unit::VIDEO_MS, 400_000, 3),
            (unit::PIXEL_STEPS, 1, 6),
        ]
        .into_iter()
        .map(|(k, p, e)| (k.to_string(), Rate::per(p, e)))
        .collect(),
        min_charge: 0,
    }
}

/// A video job carries every dimension at once, including the u128 denoising
/// term, so the widest meter is measured too.
fn video_units() -> BillableUnits {
    BillableUnits::tokens(512, 256)
        .with_cache(2_048, 512)
        .with_reasoning_loops(4)
        .with_image_tokens(729)
        .with_audio_ms(9_500)
        .with_video_ms(30_000)
        .with_pixel_steps(1_920 * 1_080 * 30 * 720)
}

fn bench_charge(c: &mut Criterion) {
    let ctx = PriceContext::genesis(500_000_000);
    let card = card();
    let typical = BillableUnits::tokens(512, 256);
    let video = video_units();
    let mut group = c.benchmark_group("pricing_charge_wei");
    group.bench_function("tokens_512in_256out", |b| {
        b.iter(|| {
            black_box(
                ctx.charge_wei(black_box(&card), black_box(&typical))
                    .unwrap(),
            )
        });
    });
    group.bench_function("all_dimensions_video_job", |b| {
        b.iter(|| black_box(ctx.charge_wei(black_box(&card), black_box(&video)).unwrap()));
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
    bench_charge,
    bench_record_success,
    bench_get_reputation,
);
criterion_main!(benches);
