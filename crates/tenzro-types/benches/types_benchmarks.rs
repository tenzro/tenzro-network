//! Criterion benches for tenzro-types hot paths. Bounds are pinned in
//! `tools/bench-gate/thresholds.toml`.

use criterion::{Criterion, criterion_group, criterion_main};
use tenzro_types::intent_7683::{CrossChainOrder, compute_order_id};
use tenzro_types::primitives::{Address, Hash};

/// ERC-7683 `compute_order_id` over a canonical preimage. Bound is
/// `≤ 5 µs` per the BENCHMARKS reference (SHA-256 ~0.2 µs on the
/// 200-byte preimage + ~3 µs serde overhead).
fn bench_compute_order_id(c: &mut Criterion) {
    let order = CrossChainOrder {
        settlement_contract: Address::new([0x42; 32]),
        swapper: Address::new([0x11; 32]),
        nonce: 1234567890,
        origin_chain_id: 1,
        fill_deadline: 1_700_000_000,
        order_data_type: Hash::new([0x77; 32]),
        order_data: vec![0u8; 128],
    };

    c.bench_function("compute_order_id", |b| {
        b.iter(|| {
            let _ = compute_order_id(&order);
        })
    });
}

criterion_group!(benches, bench_compute_order_id);
criterion_main!(benches);
