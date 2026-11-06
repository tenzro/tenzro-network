//! Criterion benchmarks for tenzro-wallet hot paths.
//!
//! - `NonceManager::next_nonce` + `allocate_nonce` — the contended path on
//!   high-throughput senders.
//! - Argon2id-backed `Keystore::store_record` — bounded by the KDF (64MB / 3
//!   iter / parallelism 4), so this is the dominant onboarding latency.

use std::time::Duration;

use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};

use tenzro_types::primitives::Address;
use tenzro_wallet::keystore::WalletRecord;
use tenzro_wallet::{Keystore, NonceManager};

fn bench_nonce_manager(c: &mut Criterion) {
    let mgr = NonceManager::new();
    let addr = Address::new([0x01u8; 32]);
    let mut group = c.benchmark_group("nonce_manager");
    group.bench_function("next_nonce_single_address", |b| {
        b.iter(|| {
            let n = mgr.next_nonce(black_box(&addr));
            black_box(n);
        });
    });
    group.finish();
}

fn bench_keystore_store_record(c: &mut Criterion) {
    // Argon2id KDF is the dominant cost. Use a unique tmp dir per call.
    let tmp_root = std::env::temp_dir().join(format!(
        "tenzro-wallet-bench-keystore-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    std::fs::create_dir_all(&tmp_root).expect("mkdir");
    let wallet_id = tenzro_wallet::WalletId::new();
    let record = WalletRecord {
        public_key: {
            use tenzro_crypto::HybridSigner;
            tenzro_crypto::composite::testing::TestHybridSigner::p256_only(1)
                .public_key()
                .clone()
        },
    };

    let mut group = c.benchmark_group("keystore_store_record");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));
    let mut i: u64 = 0;
    group.bench_function("argon2id_64MB_3iter_p4", |b| {
        b.iter_batched(
            || {
                i = i.wrapping_add(1);
                let dir = tmp_root.join(i.to_string());
                std::fs::create_dir_all(&dir).expect("mkdir");
                Keystore::new(dir).expect("open keystore")
            },
            |mut ks| {
                ks.store_record(&wallet_id, &record, "correct horse battery staple")
                    .expect("store record");
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_nonce_manager, bench_keystore_store_record,);
criterion_main!(benches);
