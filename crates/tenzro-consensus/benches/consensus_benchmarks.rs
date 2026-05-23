//! Criterion benchmarks for tenzro-consensus critical paths
//!
//! Run with: cargo bench -p tenzro-consensus

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::Arc;
use tenzro_consensus::leader_reputation::LeaderReputation;
use tenzro_consensus::validator::{EquivocationDetector, ValidatorInfo, ValidatorSet};
use tenzro_consensus::voter::{bls_payload_for_vote, Vote, VoteCollector, VoteType};
use tenzro_consensus::{ConsensusConfig, EpochManager, Mempool};
use tenzro_crypto::bls::{BlsKeyPair, BlsSignature};
use tenzro_crypto::composite::{CompositePublicKey, CompositeSignature, HybridSigner, InMemoryHybridSigner};
use tenzro_crypto::keys::{KeyPair, KeyType};
use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_crypto::signatures::Ed25519SignerImpl;
use tenzro_types::primitives::{Address, BlockHeight, ChainId, Hash, Nonce};
use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};
use tenzro_types::Signature;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct TestValidator {
    info: ValidatorInfo,
    signer: InMemoryHybridSigner,
    bls: BlsKeyPair,
}

fn create_test_validator(stake: u128) -> TestValidator {
    let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
    let crypto_addr = keypair.address();
    let mut addr_bytes = [0u8; 32];
    addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
    let address = Address::new(addr_bytes);
    let pq = MlDsaSigningKey::generate();
    let pq_vk = pq.verifying_key_bytes().to_vec();
    let bls = BlsKeyPair::generate().unwrap();
    let info = ValidatorInfo::new(
        address,
        keypair.public_key().clone(),
        pq_vk,
        bls.public_key().to_bytes().to_vec(),
        stake,
    );
    let classical = Ed25519SignerImpl::new(keypair).unwrap();
    let signer = InMemoryHybridSigner::new(Box::new(classical), pq);
    TestValidator { info, signer, bls }
}

fn create_validator_set(n: usize) -> (Vec<TestValidator>, Arc<ValidatorSet>) {
    let validators: Vec<TestValidator> = (0..n)
        .map(|i| create_test_validator((i as u128 + 1) * 1000))
        .collect();
    let infos: Vec<ValidatorInfo> = validators.iter().map(|v| v.info.clone()).collect();
    let set = Arc::new(ValidatorSet::new(1, infos).unwrap());
    (validators, set)
}

fn create_signed_vote(
    view: u64,
    height: BlockHeight,
    block_hash: Hash,
    voter: Address,
    vote_type: VoteType,
    validator: &TestValidator,
) -> Vote {
    let placeholder_sig = CompositeSignature::new(Vec::new(), Vec::new());
    let pk = validator.signer.public_key().clone();
    let placeholder_bls = placeholder_bls_sig();
    let mut vote = Vote::new(
        view,
        height,
        block_hash,
        voter,
        placeholder_sig,
        pk,
        placeholder_bls,
        vote_type,
        0,
    );
    let payload = vote.signing_payload();
    let sig = validator.signer.sign(&payload).unwrap();
    vote.signature = sig;
    let bls_payload = bls_payload_for_vote(&vote);
    vote.bls_signature = validator.bls.sign(&bls_payload);
    vote
}

fn placeholder_bls_sig() -> BlsSignature {
    BlsKeyPair::generate().unwrap().sign(b"__bench_placeholder__")
}

fn create_test_tx(nonce: u64) -> SignedTransaction {
    let pq_key = MlDsaSigningKey::generate();
    let tx = Transaction::new(
        ChainId::from(1u64),
        Address::default(),
        Address::default(),
        Nonce::from(nonce),
        TransactionType::Transfer { amount: 1000 },
        21000,
        100,
        pq_key.verifying_key_bytes().to_vec(),
    );
    let pq_sig = pq_key.sign(tx.hash().as_bytes()).to_vec();
    SignedTransaction::new(tx, Signature::default(), pq_sig)
}

fn create_plain_validators(count: usize) -> Vec<ValidatorInfo> {
    (0..count)
        .map(|i| {
            let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
            let mut addr_bytes = [0u8; 32];
            addr_bytes[0] = i as u8;
            let pq = MlDsaSigningKey::generate();
            let bls = BlsKeyPair::generate().unwrap();
            ValidatorInfo::new(
                Address::new(addr_bytes),
                keypair.public_key().clone(),
                pq.verifying_key_bytes().to_vec(),
                bls.public_key().to_bytes().to_vec(),
                1000,
            )
        })
        .collect()
}

fn placeholder_composite_pk() -> CompositePublicKey {
    let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
    let pq = MlDsaSigningKey::generate();
    CompositePublicKey::new(
        kp.public_key().clone(),
        pq.verifying_key_bytes().to_vec(),
    )
}

fn placeholder_composite_sig() -> CompositeSignature {
    CompositeSignature::new(vec![0u8; 64], vec![0u8; 3309])
}

// ---------------------------------------------------------------------------
// Vote collection benchmarks
// ---------------------------------------------------------------------------

fn bench_vote_collection(c: &mut Criterion) {
    let mut group = c.benchmark_group("vote_collection");
    group.sample_size(100);

    for &n in &[10, 50, 100] {
        group.bench_with_input(BenchmarkId::new("add_votes", n), &n, |b, &n| {
            let (validators, set) = create_validator_set(n);
            let threshold = set.quorum_threshold();

            b.iter(|| {
                let collector = VoteCollector::new(set.clone());
                let count = std::cmp::min(threshold.saturating_sub(1), n);
                for v in validators.iter().take(count) {
                    let vote = create_signed_vote(
                        1,
                        BlockHeight::from(10),
                        Hash::default(),
                        v.info.address,
                        VoteType::Prepare,
                        v,
                    );
                    let _ = black_box(collector.add_vote(vote));
                }
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Vote signature verification benchmark
// ---------------------------------------------------------------------------

fn bench_vote_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("vote_verification");
    group.sample_size(100);

    let (validators, set) = create_validator_set(10);

    let vote = create_signed_vote(
        1,
        BlockHeight::from(10),
        Hash::default(),
        validators[0].info.address,
        VoteType::Prepare,
        &validators[0],
    );

    group.bench_function("single_vote_verify_and_add", |b| {
        b.iter(|| {
            let collector = VoteCollector::new(set.clone());
            let _ = black_box(collector.add_vote(vote.clone()));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// QC formation benchmarks
// ---------------------------------------------------------------------------

fn bench_qc_formation(c: &mut Criterion) {
    let mut group = c.benchmark_group("qc_formation");
    group.sample_size(100);

    for &n in &[4, 10, 50] {
        group.bench_with_input(BenchmarkId::new("form_qc", n), &n, |b, &n| {
            let (validators, set) = create_validator_set(n);
            let threshold = set.quorum_threshold();

            // Pre-sign all votes needed for quorum
            let votes: Vec<Vote> = (0..threshold)
                .map(|i| {
                    create_signed_vote(
                        1,
                        BlockHeight::from(10),
                        Hash::default(),
                        validators[i].info.address,
                        VoteType::Prepare,
                        &validators[i],
                    )
                })
                .collect();

            b.iter(|| {
                let collector = VoteCollector::new(set.clone());
                let mut result = None;
                for vote in &votes {
                    result = black_box(collector.add_vote(vote.clone()).unwrap());
                }
                black_box(result)
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Leader selection benchmarks
// ---------------------------------------------------------------------------

fn bench_leader_selection(c: &mut Criterion) {
    let mut group = c.benchmark_group("leader_selection");
    group.sample_size(100);

    let (_, set) = create_validator_set(100);

    group.bench_function("round_robin", |b| {
        let mut view = 0u64;
        b.iter(|| {
            view = view.wrapping_add(1);
            black_box(set.select_leader_round_robin(black_box(view)).unwrap());
        });
    });

    // Aptos LeaderReputation selector — stake-weighted seeded draw with
    // observed-behaviour multipliers. Cold cache (no proposer/voter history
    // recorded), so this measures the seeding + draw cost.
    group.bench_function("reputation", |b| {
        let reputation = LeaderReputation::new(set.len());
        let mut round = 0u64;
        let prev_block_id = Hash::default();
        b.iter(|| {
            round = round.wrapping_add(1);
            black_box(
                reputation
                    .select_leader(black_box(round), 0, &prev_block_id, &set)
                    .unwrap(),
            );
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Equivocation detection benchmarks
// ---------------------------------------------------------------------------

fn bench_equivocation_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("equivocation_detection");
    group.sample_size(100);

    let validator = create_test_validator(1000);

    let placeholder_pk = placeholder_composite_pk();
    let placeholder_sig = placeholder_composite_sig();
    let placeholder_bls = placeholder_bls_sig();

    group.bench_function("clean_check", |b| {
        b.iter(|| {
            let detector = EquivocationDetector::new();
            let vote = Vote::new(
                1,
                BlockHeight::from(10),
                Hash::default(),
                validator.info.address,
                placeholder_sig.clone(),
                placeholder_pk.clone(),
                placeholder_bls.clone(),
                VoteType::Prepare,
                0,
            );
            black_box(detector.check_vote(&vote).unwrap());
        });
    });

    group.bench_function("with_equivocation", |b| {
        b.iter(|| {
            let detector = EquivocationDetector::new();
            let vote1 = Vote::new(
                1,
                BlockHeight::from(10),
                Hash::default(),
                validator.info.address,
                placeholder_sig.clone(),
                placeholder_pk.clone(),
                placeholder_bls.clone(),
                VoteType::Prepare,
                0,
            );
            let _ = detector.check_vote(&vote1);

            let mut different_hash_bytes = [0u8; 32];
            different_hash_bytes[0] = 0xFF;
            let vote2 = Vote::new(
                1,
                BlockHeight::from(10),
                Hash::new(different_hash_bytes),
                validator.info.address,
                placeholder_sig.clone(),
                placeholder_pk.clone(),
                placeholder_bls.clone(),
                VoteType::Prepare,
                0,
            );
            let _ = black_box(detector.check_vote(&vote2));
        });
    });

    group.bench_function("check_after_100_votes", |b| {
        let detector = EquivocationDetector::new();
        for view in 0..100u64 {
            let mut addr_bytes = [0u8; 32];
            addr_bytes[..8].copy_from_slice(&view.to_le_bytes());
            let addr = Address::new(addr_bytes);
            let vote = Vote::new(
                view,
                BlockHeight::from(10),
                Hash::default(),
                addr,
                placeholder_sig.clone(),
                placeholder_pk.clone(),
                placeholder_bls.clone(),
                VoteType::Prepare,
                0,
            );
            let _ = detector.check_vote(&vote);
        }

        b.iter(|| {
            let vote = Vote::new(
                200,
                BlockHeight::from(10),
                Hash::default(),
                validator.info.address,
                placeholder_sig.clone(),
                placeholder_pk.clone(),
                placeholder_bls.clone(),
                VoteType::Prepare,
                0,
            );
            let _ = black_box(detector.check_vote(&vote));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Mempool benchmarks
// ---------------------------------------------------------------------------

fn bench_mempool(c: &mut Criterion) {
    let mut group = c.benchmark_group("mempool");
    group.sample_size(100);
    let config = Arc::new(ConsensusConfig::default());

    group.bench_function("add_transaction", |b| {
        let mempool = Mempool::new(config.clone());
        let mut nonce = 0u64;
        b.iter(|| {
            let tx = create_test_tx(nonce);
            nonce += 1;
            let _ = black_box(mempool.add_transaction(tx));
        });
    });

    group.bench_function("select_transactions_100", |b| {
        let mempool = Mempool::new(config.clone());
        for i in 0..1000u64 {
            let _ = mempool.add_transaction(create_test_tx(i));
        }
        b.iter(|| {
            black_box(mempool.select_transactions(black_box(100), black_box(30_000_000)));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Epoch manager benchmarks
// ---------------------------------------------------------------------------

fn bench_epoch_manager(c: &mut Criterion) {
    let mut group = c.benchmark_group("epoch_manager");
    group.sample_size(100);

    group.bench_function("create_epoch_manager", |b| {
        b.iter(|| {
            let validators = create_plain_validators(10);
            black_box(EpochManager::new(validators, 100).unwrap());
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_vote_collection,
    bench_vote_verification,
    bench_qc_formation,
    bench_leader_selection,
    bench_equivocation_detection,
    bench_mempool,
    bench_epoch_manager,
);
criterion_main!(benches);
