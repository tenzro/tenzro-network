//! Criterion benchmarks for tenzro-payments critical paths
//!
//! Run with: cargo bench -p tenzro-payments

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::sync::Arc;
use tenzro_payments::ChallengeStore;
use tenzro_payments::gateway::TenzroPaymentGateway;
use tenzro_payments::mpp::{MppChallenge, MppPaymentServer};
use tenzro_payments::traits::{PaymentGateway, PaymentProtocol};
use tenzro_payments::types::{PaymentChallenge, PaymentCredential};

/// Stands in for the node's reader of the keys accounts enrolled in chain
/// state; here no account has enrolled an ML-DSA-65 key.
struct NoneEnrolled;

impl tenzro_payments::EnrolledKeys for NoneEnrolled {
    fn enrolled_pq_key(&self, _p256_xy: &[u8]) -> tenzro_payments::Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

fn keys() -> Arc<dyn tenzro_payments::EnrolledKeys> {
    Arc::new(NoneEnrolled)
}

const PAYEE: &str = "0909090909090909090909090909090909090909";

fn signer() -> tenzro_crypto::composite::testing::TestHybridSigner {
    static SEED: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(1);
    tenzro_crypto::composite::testing::TestHybridSigner::hybrid(
        SEED.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    )
}

fn stamped(mut challenge: PaymentChallenge) -> PaymentChallenge {
    challenge.extra.insert(
        tenzro_payments::payer_auth::CHAIN_ID_KEY.to_string(),
        serde_json::json!(1337u64),
    );
    challenge
}

fn bench_mpp_challenge_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("mpp_challenge_creation");
    group.sample_size(100);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server: Arc<dyn PaymentProtocol> = Arc::new(MppPaymentServer::new(keys()));

    group.bench_function("create_challenge", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(
                    server
                        .create_challenge(
                            black_box("/api/inference"),
                            black_box(1000),
                            black_box("TNZO"),
                            black_box(PAYEE),
                        )
                        .await
                        .unwrap(),
                );
            });
        });
    });
    group.finish();
}

fn bench_mpp_credential_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("mpp_credential_verification");
    group.sample_size(50);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = MppPaymentServer::new(keys());
    let challenge = stamped(
        rt.block_on(server.create_challenge("/api/inference", 1000, "TNZO", PAYEE))
            .unwrap(),
    );
    let credential = rt
        .block_on(server.create_credential(&challenge, "", &signer()))
        .unwrap();

    group.bench_function("verify_signed_credential", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(
                    server
                        .verify_credential(black_box(&challenge), black_box(&credential))
                        .await
                        .unwrap(),
                );
            });
        });
    });
    group.finish();
}

fn bench_credential_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("credential_parsing");
    group.sample_size(100);

    let credential = PaymentCredential {
        credential_id: uuid::Uuid::new_v4().to_string(),
        challenge_id: "test-challenge-id".to_string(),
        protocol: "mpp".to_string(),
        payer_did: String::new(),
        payer_address: "ab".repeat(20),
        amount: 1000,
        asset: "TNZO".to_string(),
        signature: None,
        extra: std::collections::HashMap::new(),
    };
    let json = serde_json::to_string(&credential).unwrap();
    let base64_encoded =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, json.as_bytes());

    group.bench_function("parse_from_json", |b| {
        b.iter(|| {
            black_box(serde_json::from_str::<PaymentCredential>(black_box(&json)).unwrap());
        });
    });
    group.bench_function("parse_from_header", |b| {
        b.iter(|| {
            black_box(
                tenzro_payments::middleware::credential_from_headers(|name| {
                    (name == "Payment-Credential").then_some(base64_encoded.as_str())
                })
                .unwrap()
                .unwrap(),
            );
        });
    });

    let challenge = MppChallenge::new("/api/inference", 1000, "TNZO", PAYEE);
    let challenge_json = serde_json::to_string(&challenge).unwrap();
    group.bench_function("parse_mpp_challenge", |b| {
        b.iter(|| {
            black_box(serde_json::from_str::<MppChallenge>(black_box(&challenge_json)).unwrap());
        });
    });
    group.finish();
}

fn bench_payment_gateway_routing(c: &mut Criterion) {
    let mut group = c.benchmark_group("payment_gateway_routing");
    group.sample_size(100);
    let rt = tokio::runtime::Runtime::new().unwrap();

    let gateway = TenzroPaymentGateway::new(1337, keys());
    gateway.register_protocol(Arc::new(
        MppPaymentServer::new(keys()).with_challenge_store(gateway.challenge_store()),
    ));

    group.bench_function("route_challenge_creation", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(
                    gateway
                        .create_challenge(
                            black_box("mpp"),
                            black_box("/api/inference"),
                            black_box(1000),
                            black_box("TNZO"),
                            black_box(PAYEE),
                        )
                        .await
                        .unwrap(),
                );
            });
        });
    });

    group.bench_function("challenge_store_operations", |b| {
        let store = ChallengeStore::new();
        let mut i = 0u64;
        b.iter(|| {
            i += 1;
            let challenge = PaymentChallenge {
                challenge_id: format!("ch-{}", i),
                protocol: "mpp".to_string(),
                resource: "/api/inference".to_string(),
                amount: 1000,
                asset: "TNZO".to_string(),
                recipient: PAYEE.to_string(),
                chain: "tenzro".to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
                extra: std::collections::HashMap::new(),
            };
            store.store(&challenge).unwrap();
            let _ = black_box(store.get(&challenge.challenge_id));
            store.consume(&challenge.challenge_id);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_mpp_challenge_creation,
    bench_mpp_credential_verification,
    bench_credential_parsing,
    bench_payment_gateway_routing,
);
criterion_main!(benches);
