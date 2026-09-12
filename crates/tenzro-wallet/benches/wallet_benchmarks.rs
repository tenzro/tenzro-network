//! Criterion benchmarks for tenzro-wallet hot paths.
//!
//! - `user_op_hash` — the EIP-712 v0.8 digest every UserOperation signing flow
//!   must compute on the client side.
//! - `NonceManager::next_nonce` + `allocate_nonce` — the contended path on
//!   high-throughput senders.
//! - Wallet provisioning — ML-DSA-65 + BLS12-381 generate. The classical key is
//!   not minted here: it lives in a passkey or secure element and only its
//!   public half reaches this crate.
//! - Argon2id-backed `Keystore::store_secrets` — bounded by the KDF (64MB / 3
//!   iter / parallelism 4), so this is the dominant onboarding latency.

use std::time::Duration;

use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};

use tenzro_types::primitives::Address;
use tenzro_wallet::keystore::WalletSecrets;
use tenzro_wallet::{Keystore, NonceManager, UserOp, UserOpBuilder, user_op_hash};

fn sample_user_op() -> UserOp {
    UserOpBuilder::new()
        .sender(vec![0x11u8; 20])
        .nonce(7)
        .call_data(vec![0xaa; 256])
        .build()
        .expect("build user op")
}

fn bench_user_op_hash(c: &mut Criterion) {
    let op = sample_user_op();
    let entry_point = vec![0x42u8; 20];
    let chain_id: u64 = 1337;
    let mut group = c.benchmark_group("user_op_hash");
    group.bench_function("eip712_v0_8", |b| {
        b.iter(|| {
            let h = user_op_hash(black_box(&op), black_box(chain_id), black_box(&entry_point));
            black_box(h);
        });
    });
    group.finish();
}

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

fn bench_wallet_provision(c: &mut Criterion) {
    let mut group = c.benchmark_group("wallet_provision");
    // Provisioning no longer generates a classical key — that one lives in a
    // passkey or secure element and only its public half reaches this crate.
    // What is left to measure is the ML-DSA-65 + BLS12-381 legs, which have no
    // hardware backing on any current platform and so are minted here.
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));
    group.bench_function("mldsa65_plus_bls", |b| {
        b.iter(|| {
            let pq = tenzro_crypto::pq::MlDsaSigningKey::generate();
            let bls = tenzro_crypto::bls::BlsKeyPair::generate().expect("bls keygen");
            black_box((pq, bls));
        });
    });
    group.finish();
}

fn bench_keystore_store_secrets(c: &mut Criterion) {
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
    let secrets = WalletSecrets {
        pq_seed: vec![7u8; 32],
        bls_key: vec![9u8; 32],
        classical_public_key: vec![1u8; 32],
    };

    let mut group = c.benchmark_group("keystore_store_secrets");
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
                ks.store_secrets(&wallet_id, &secrets, "correct horse battery staple")
                    .expect("store secrets");
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_user_op_hash,
    bench_nonce_manager,
    bench_wallet_provision,
    bench_keystore_store_secrets,
);
criterion_main!(benches);
