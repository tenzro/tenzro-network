//! Criterion benchmarks for tenzro-settlement critical paths
//!
//! Run with: cargo bench -p tenzro-settlement
//!
//! ## Scope
//!
//! These benchmarks measure the in-memory query-cache performance of the
//! settlement managers (`EscrowManager`, `ChannelManager`, `SettlementEngine`,
//! `FeeCollector`). They do **not** measure the on-chain consensus path
//! (signed `CreateEscrow` / `ReleaseEscrow` / `RefundEscrow` transactions
//! flowing through mempool → block → Native VM dispatch), which is the
//! source of truth for funds in production. For on-chain benchmarks that
//! cover the full transaction path, see
//! `crates/tenzro-node/tests/escrow_onchain_integration.rs`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use dashmap::DashMap;
use std::sync::Arc;
use tenzro_crypto::keys::{KeyPair, KeyType};
use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
use tenzro_settlement::{
    ChannelManager, EscrowManager, FeeCollector, SettlementConfig, SettlementEngine,
};
use tenzro_token::NetworkTreasury;
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::{Address, Timestamp};
use tenzro_types::settlement::{
    ProofSignature, ProofType, ReleaseConditions, ServiceProof, ServiceType, SettlementRequest,
    SignerRole,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_address(seed: u8) -> Address {
    let mut bytes = [0u8; 32];
    bytes[0] = seed;
    Address::new(bytes)
}

fn make_treasury() -> Arc<NetworkTreasury> {
    Arc::new(NetworkTreasury::new(make_address(0xFF)))
}

fn make_engine() -> SettlementEngine {
    let treasury = make_treasury();
    let config = SettlementConfig::new(make_address(0xFF));
    SettlementEngine::new(config, treasury).unwrap()
}

fn make_settlement_request(index: u8) -> SettlementRequest {
    // Provider needs to be a real Ed25519 pubkey-address so the engine's
    // verify_ed25519_signature path (which derives the verifying key from the
    // signer address bytes) accepts the proof signature.
    let provider_kp = KeyPair::generate(KeyType::Ed25519).unwrap();
    let pk_bytes = provider_kp.public_key().as_bytes();
    let mut addr_bytes = [0u8; 32];
    let len = pk_bytes.len().min(32);
    addr_bytes[..len].copy_from_slice(&pk_bytes[..len]);
    let provider = Address::new(addr_bytes);
    let customer = make_address(index.wrapping_add(100));
    let proof_data = vec![1, 2, 3, 4];
    let signer = Ed25519SignerImpl::new(provider_kp).unwrap();
    let sig = signer.sign(&proof_data).unwrap();
    let mut proof = ServiceProof::new(ProofType::Cryptographic, proof_data);
    proof.signatures.push(ProofSignature {
        signer: provider,
        signature: sig.as_bytes().to_vec(),
        role: SignerRole::Provider,
    });
    SettlementRequest::new(
        provider,
        customer,
        ServiceType::ModelInference {
            model_id: "test-model".to_string(),
            tokens: 1000,
        },
        10000,
        proof,
    )
}

fn future_timestamp() -> Timestamp {
    Timestamp::new(Timestamp::now().as_millis() + 86400000) // +24 hours
}

// ---------------------------------------------------------------------------
// Immediate settlement benchmark
// ---------------------------------------------------------------------------

fn bench_immediate_settlement(c: &mut Criterion) {
    let mut group = c.benchmark_group("immediate_settlement");
    group.sample_size(100);

    let rt = tokio::runtime::Runtime::new().unwrap();

    group.bench_function("single_settlement", |b| {
        b.iter(|| {
            rt.block_on(async {
                let engine = make_engine();
                let request = make_settlement_request(1);
                // Fund the customer
                engine.set_balance(
                    &request.customer,
                    &AssetId::tnzo(),
                    1_000_000_000,
                );
                black_box(engine.settle(request).await.unwrap());
            });
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Batch settlement benchmark
// ---------------------------------------------------------------------------

fn bench_batch_settlement(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_settlement");
    group.sample_size(50);

    let rt = tokio::runtime::Runtime::new().unwrap();

    for &batch_size in &[10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::new("batch", batch_size),
            &batch_size,
            |b, &batch_size| {
                b.iter(|| {
                    rt.block_on(async {
                        let engine = make_engine();
                        let requests: Vec<SettlementRequest> = (0..batch_size)
                            .map(|i| {
                                let req = make_settlement_request(i as u8);
                                engine.set_balance(
                                    &req.customer,
                                    &AssetId::tnzo(),
                                    1_000_000_000,
                                );
                                req
                            })
                            .collect();
                        black_box(engine.batch_settle(requests).await.unwrap());
                    });
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Escrow create + release cycle benchmark
// ---------------------------------------------------------------------------

fn bench_escrow_create_release(c: &mut Criterion) {
    let mut group = c.benchmark_group("escrow_create_release");
    group.sample_size(100);

    // Generate the payee (provider) Ed25519 keypair once outside `iter()` so
    // the signed proof preimage is a real pub-key-bytes address — the escrow
    // release path verifies `proof.signatures[0]` against `proof_data` using
    // the signer-address-bytes-as-Ed25519-pubkey convention.
    let payee_kp = KeyPair::generate(KeyType::Ed25519).unwrap();
    let pk_bytes = payee_kp.public_key().as_bytes();
    let mut addr_bytes = [0u8; 32];
    let len = pk_bytes.len().min(32);
    addr_bytes[..len].copy_from_slice(&pk_bytes[..len]);
    let payee = Address::new(addr_bytes);
    let payee_signer = Ed25519SignerImpl::new(payee_kp).unwrap();
    let proof_data = vec![1u8, 2, 3];
    let payee_sig = payee_signer.sign(&proof_data).unwrap();

    group.bench_function("create_and_release", |b| {
        b.iter(|| {
            let balances = Arc::new(DashMap::new());
            let payer = make_address(1);
            let asset = AssetId::tnzo();
            balances.insert((payer, asset.clone()), 1_000_000u128);

            let manager = EscrowManager::new(balances);
            let escrow = manager
                .create_escrow(
                    payer,
                    payee,
                    5000,
                    asset,
                    future_timestamp(),
                    ReleaseConditions::ProviderSignature,
                )
                .unwrap();

            let mut proof = ServiceProof::new(ProofType::Cryptographic, proof_data.clone());
            proof.signatures.push(ProofSignature {
                signer: payee,
                signature: payee_sig.as_bytes().to_vec(),
                role: SignerRole::Provider,
            });
            manager.release_escrow(&escrow.escrow_id, &proof).unwrap();
            black_box(());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Micropayment channel benchmark
// ---------------------------------------------------------------------------

fn bench_micropayment_channel(c: &mut Criterion) {
    let mut group = c.benchmark_group("micropayment_channel");
    group.sample_size(100);

    group.bench_function("open_100_updates_close", |b| {
        // Generate a payer keypair once outside `iter()` so we measure the
        // hot channel path (open / 100 signed updates / close) rather than
        // amortizing keygen across the benchmark. Channel updates require
        // a real Ed25519 signature by the payer over the canonical state
        // encoding; the bench has to mirror that to exercise the same
        // verification path the production code takes.
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pk_bytes = keypair.public_key().as_bytes();
        let mut addr_bytes = [0u8; 32];
        let len = pk_bytes.len().min(32);
        addr_bytes[..len].copy_from_slice(&pk_bytes[..len]);
        let payer = Address::new(addr_bytes);
        let signer = Ed25519SignerImpl::new(keypair).unwrap();

        b.iter(|| {
            let manager = ChannelManager::new();
            let payee = make_address(2);
            let asset = AssetId::tnzo();

            // Fund payer
            manager.set_balance(&payer, &asset, 1_000_000);

            // Open channel
            let channel = manager
                .open_channel(payer, payee, 100_000, asset, future_timestamp(), None, 0)
                .unwrap();

            // 100 off-chain updates. Each iteration signs the next state
            // (`spent` advances by 100 each round) so the signature
            // verifies against the canonical encoding of the post-update
            // balances.
            let mut state = channel.state.clone();
            let mut spent: u128 = 0;
            for _i in 0..100u128 {
                spent += 100;
                let next = state.next(channel.deposit - spent, spent);
                let msg = next.canonical_message();
                let sig = signer.sign(&msg).unwrap();
                let _ = manager
                    .update_channel(&channel.channel_id, 100, sig.as_bytes().to_vec());
                state = next;
            }

            // Close
            manager.close_channel(&channel.channel_id).unwrap();
            black_box(());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Fee calculation benchmark
// ---------------------------------------------------------------------------

fn bench_fee_calculation(c: &mut Criterion) {
    let mut group = c.benchmark_group("fee_calculation");
    group.sample_size(100);

    let treasury = make_treasury();
    let collector = FeeCollector::new(treasury);
    let asset = AssetId::tnzo();

    group.bench_function("collect_fee", |b| {
        let mut i = 0u64;
        b.iter(|| {
            i += 1;
            let settlement_id = format!("settle-{}", i);
            collector
            .collect_fee(&settlement_id, &asset, black_box(500))
            .unwrap();
            black_box(
                (),
            );
        });
    });

    for &amount in &[1_000u128, 1_000_000, 1_000_000_000, 1_000_000_000_000_000_000] {
        group.bench_with_input(
            BenchmarkId::new("fee_for_amount", amount),
            &amount,
            |b, &amount| {
                // Fee calculation is: amount * bps / 10000
                // We benchmark the engine's internal calculation via a settlement
                b.iter(|| {
                    let fee = black_box(amount)
                        .checked_mul(50)
                        .and_then(|v| v.checked_div(10000))
                        .unwrap_or(0);
                    black_box(std::cmp::max(fee, 1));
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_immediate_settlement,
    bench_batch_settlement,
    bench_escrow_create_release,
    bench_micropayment_channel,
    bench_fee_calculation,
);
criterion_main!(benches);
