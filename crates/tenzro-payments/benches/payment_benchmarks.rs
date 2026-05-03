//! Criterion benchmarks for tenzro-payments critical paths
//!
//! Run with: cargo bench -p tenzro-payments

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::sync::Arc;

use tenzro_payments::mpp::{MppChallenge, MppCredential, MppPaymentServer};
use tenzro_payments::traits::{PaymentGateway, PaymentProtocol};
use tenzro_payments::types::{PaymentChallenge, PaymentCredential};
use tenzro_payments::gateway::TenzroPaymentGateway;
use tenzro_payments::ChallengeStore;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_mpp_challenge() -> MppChallenge {
    MppChallenge::new("/api/inference", 1000, "USDC", "did:tenzro:human:recipient-1")
}

fn _make_mpp_credential(challenge_id: &str) -> MppCredential {
    MppCredential::new(
        challenge_id,
        "did:tenzro:human:payer-1",
        "0xaabbccdd",
        1000,
        "USDC",
    )
}

// ---------------------------------------------------------------------------
// MPP challenge creation benchmark
// ---------------------------------------------------------------------------

fn bench_mpp_challenge_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("mpp_challenge_creation");
    group.sample_size(100);

    let rt = tokio::runtime::Runtime::new().unwrap();

    let server = MppPaymentServer::new("did:tenzro:human:recipient-1");
    let server: Arc<dyn PaymentProtocol> = Arc::new(server);

    group.bench_function("create_challenge", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(
                    server
                        .create_challenge(
                            black_box("/api/inference"),
                            black_box(1000),
                            black_box("USDC"),
                            black_box("did:tenzro:human:recipient-1"),
                        )
                        .await
                        .unwrap(),
                );
            });
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// MPP credential verification benchmark
// ---------------------------------------------------------------------------

fn bench_mpp_credential_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("mpp_credential_verification");
    group.sample_size(100);

    let rt = tokio::runtime::Runtime::new().unwrap();

    let server = MppPaymentServer::new("did:tenzro:human:recipient-1");
    let server: Arc<dyn PaymentProtocol> = Arc::new(server);

    // Pre-create a challenge
    let challenge = rt.block_on(async {
        server
            .create_challenge("/api/inference", 1000, "USDC", "did:tenzro:human:recipient-1")
            .await
            .unwrap()
    });

    // Create a credential for it
    let credential = PaymentCredential {
        credential_id: uuid::Uuid::new_v4().to_string(),
        challenge_id: challenge.challenge_id.clone(),
        protocol: "mpp".to_string(),
        payer_did: "did:tenzro:human:payer-1".to_string(),
        payer_address: "0xaabbccdd".to_string(),
        amount: 1000,
        asset: "USDC".to_string(),
        signature: vec![0u8; 64], // unsigned for benchmark
        pq_signature: vec![0u8; 3309],
        pq_public_key: vec![0u8; 1952],
        extra: std::collections::HashMap::new(),
    };

    group.bench_function("verify_credential", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Verification will fail due to no real signature, but we benchmark the path
                let _ = black_box(
                    server
                        .verify_credential(black_box(&challenge), black_box(&credential))
                        .await,
                );
            });
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// x402 payload creation benchmark
// ---------------------------------------------------------------------------

fn bench_x402_payload_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("x402_payload_creation");
    group.sample_size(100);

    use tenzro_payments::x402::X402PaymentPayload;

    group.bench_function("create_payload", |b| {
        b.iter(|| {
            black_box(X402PaymentPayload::new(
                black_box("base"),
                black_box("USDC"),
                black_box("1000"),
                black_box("0xaabbccdd"),
                black_box("0xdeadbeef"),
            ));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Credential parsing benchmark
// ---------------------------------------------------------------------------

fn bench_credential_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("credential_parsing");
    group.sample_size(100);

    // Serialize a credential to JSON (simulating header parsing)
    let credential = PaymentCredential {
        credential_id: uuid::Uuid::new_v4().to_string(),
        challenge_id: "test-challenge-id".to_string(),
        protocol: "mpp".to_string(),
        payer_did: "did:tenzro:human:payer-1".to_string(),
        payer_address: "0xaabbccdd".to_string(),
        amount: 1000,
        asset: "USDC".to_string(),
        signature: vec![0u8; 64],
        pq_signature: vec![0u8; 3309],
        pq_public_key: vec![0u8; 1952],
        extra: std::collections::HashMap::new(),
    };

    let json = serde_json::to_string(&credential).unwrap();
    let base64_encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        json.as_bytes(),
    );

    group.bench_function("parse_from_json", |b| {
        b.iter(|| {
            black_box(serde_json::from_str::<PaymentCredential>(black_box(&json)).unwrap());
        });
    });

    group.bench_function("parse_from_base64", |b| {
        b.iter(|| {
            let decoded = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                black_box(&base64_encoded),
            )
            .unwrap();
            black_box(serde_json::from_slice::<PaymentCredential>(&decoded).unwrap());
        });
    });

    // Also benchmark MppChallenge serialization roundtrip
    let challenge = make_mpp_challenge();
    let challenge_json = serde_json::to_string(&challenge).unwrap();

    group.bench_function("parse_mpp_challenge", |b| {
        b.iter(|| {
            black_box(serde_json::from_str::<MppChallenge>(black_box(&challenge_json)).unwrap());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Payment gateway routing benchmark
// ---------------------------------------------------------------------------

fn bench_payment_gateway_routing(c: &mut Criterion) {
    let mut group = c.benchmark_group("payment_gateway_routing");
    group.sample_size(100);

    let rt = tokio::runtime::Runtime::new().unwrap();

    // Set up gateway with MPP protocol
    let gateway = TenzroPaymentGateway::new();
    let mpp_server = Arc::new(
        MppPaymentServer::new("did:tenzro:human:recipient-1")
            .with_challenge_store(gateway.challenge_store()),
    );
    gateway.register_protocol(mpp_server);

    group.bench_function("route_challenge_creation", |b| {
        b.iter(|| {
            rt.block_on(async {
                let _ = black_box(
                    gateway
                        .create_challenge(
                            black_box("mpp"),
                            black_box("/api/inference"),
                            black_box(1000),
                            black_box("USDC"),
                            black_box("did:tenzro:human:recipient-1"),
                        )
                        .await,
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
                asset: "USDC".to_string(),
                recipient: "did:tenzro:human:recipient-1".to_string(),
                chain: "tempo".to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(5),
                extra: std::collections::HashMap::new(),
            };
            store.store(&challenge);
            let _ = black_box(store.get(&challenge.challenge_id));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_mpp_challenge_creation,
    bench_mpp_credential_verification,
    bench_x402_payload_creation,
    bench_credential_parsing,
    bench_payment_gateway_routing,
);
criterion_main!(benches);
