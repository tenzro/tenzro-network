//! Criterion benchmarks for tenzro-token hot paths.
//!
//! - `TnzoToken::transfer` — in-memory balance update plus ERC-7265 circuit
//!   breaker check; runs on every TNZO native transfer.
//! - `TnzoToken::balance_of` — read path; runs on every JSON-RPC `eth_getBalance`.
//! - `adaptive_burn::compute_recommendation` — pure governance-dial transfer
//!   function. Read RPCs call this per query.

use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};

use tenzro_token::TnzoToken;
use tenzro_token::adaptive_burn::{
    BurnBreakdown, EmissionBreakdown, SupplyMetricsSnapshot, SupplyTargets, compute_recommendation,
};
use tenzro_types::primitives::{Address, BlockHeight, Timestamp};

fn addr(byte: u8) -> Address {
    Address::new([byte; 32])
}

fn seeded_token() -> TnzoToken {
    let token = TnzoToken::new();
    let treasury = addr(0xFE);
    token.set_treasury_address(treasury);
    token
        .mint(&addr(0x01), 1_000_000_000u128, &treasury)
        .expect("mint sender");
    token
}

fn bench_balance_of(c: &mut Criterion) {
    let token = seeded_token();
    let sender = addr(0x01);
    let unknown = addr(0x99);
    let mut group = c.benchmark_group("tnzo_balance_of");
    group.bench_function("hit", |b| {
        b.iter(|| {
            let v = token.balance_of(black_box(&sender));
            black_box(v);
        });
    });
    group.bench_function("miss", |b| {
        b.iter(|| {
            let v = token.balance_of(black_box(&unknown));
            black_box(v);
        });
    });
    group.finish();
}

fn bench_transfer(c: &mut Criterion) {
    let mut group = c.benchmark_group("tnzo_transfer");
    group.bench_function("1_tnzo_known_recipient", |b| {
        b.iter_batched(
            || {
                let token = seeded_token();
                let sender = addr(0x01);
                let recipient = addr(0x02);
                (token, sender, recipient)
            },
            |(token, sender, recipient)| {
                token
                    .transfer(black_box(&sender), black_box(&recipient), black_box(1))
                    .expect("transfer");
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_adaptive_burn_recommendation(c: &mut Criterion) {
    let targets = SupplyTargets::default();
    let metrics = SupplyMetricsSnapshot {
        block_height: BlockHeight::new(1_000_000),
        captured_at: Timestamp::now(),
        circulating_supply: 1_000_000_000u128 * 10u128.pow(18),
        epoch_supply_delta: 0,
        rolling_window_supply_delta_bps: 150,
        burn_breakdown: BurnBreakdown {
            base_fee: 1_000,
            local_fee: 500,
            paymaster: 200,
            slash: 100,
        },
        emission_breakdown: EmissionBreakdown {
            staking_rewards: 5_000,
            treasury_emissions: 2_000,
        },
    };
    let mut group = c.benchmark_group("adaptive_burn");
    group.bench_function("compute_recommendation_inside_band", |b| {
        b.iter(|| {
            let rec = compute_recommendation(black_box(&metrics), black_box(&targets));
            black_box(rec);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_balance_of,
    bench_transfer,
    bench_adaptive_burn_recommendation,
);
criterion_main!(benches);
