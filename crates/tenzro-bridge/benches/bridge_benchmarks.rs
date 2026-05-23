//! Criterion benchmarks for tenzro-bridge hot paths.
//!
//! The synchronous hot path on every bridge message is:
//! - `TenzroMessage::new` → `compute_hash` (SHA-256 over chain ids + nonce + payload)
//! - `TenzroMessage::sign` (Ed25519 / Secp256k1 over the 32-byte hash)
//! - `TenzroMessage::verify_signature` (counterpart on the inbound side)
//! - `encode` / `decode` (JSON wire framing)
//!
//! These run on every outbound LayerZero / CCIP / deBridge / Canton message,
//! so any regression here multiplies across all bridge fan-out.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use tenzro_bridge::message_format::{MessageType, TenzroMessage};
use tenzro_crypto::KeyPair;
use tenzro_crypto::keys::KeyType;

const PAYLOAD_SIZE: usize = 256;
const SRC_CHAIN: u64 = 1337;
const DST_CHAIN: u64 = 137;

fn sample_message() -> TenzroMessage {
    TenzroMessage::new(
        MessageType::TokenTransfer,
        SRC_CHAIN,
        DST_CHAIN,
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        vec![0xab; PAYLOAD_SIZE],
        42,
    )
}

fn signed_message() -> TenzroMessage {
    let mut msg = sample_message();
    let keypair = KeyPair::generate(KeyType::Ed25519).expect("ed25519 keypair");
    msg.sign(keypair).expect("sign");
    msg
}

fn bench_new_message(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_format");
    group.bench_function("new_token_transfer_256b_payload", |b| {
        b.iter(|| {
            let m = TenzroMessage::new(
                black_box(MessageType::TokenTransfer),
                black_box(SRC_CHAIN),
                black_box(DST_CHAIN),
                black_box("0x1111111111111111111111111111111111111111"),
                black_box("0x2222222222222222222222222222222222222222"),
                black_box(vec![0xab; PAYLOAD_SIZE]),
                black_box(42),
            );
            black_box(m);
        });
    });
    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_format_sign");
    group.bench_function("ed25519", |b| {
        b.iter_with_setup(
            || {
                (
                    sample_message(),
                    KeyPair::generate(KeyType::Ed25519).expect("ed25519 keypair"),
                )
            },
            |(mut msg, kp)| {
                msg.sign(kp).expect("sign");
                black_box(msg);
            },
        );
    });
    group.bench_function("secp256k1", |b| {
        b.iter_with_setup(
            || {
                (
                    sample_message(),
                    KeyPair::generate(KeyType::Secp256k1).expect("secp keypair"),
                )
            },
            |(mut msg, kp)| {
                msg.sign(kp).expect("sign");
                black_box(msg);
            },
        );
    });
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let msg = signed_message();
    let mut group = c.benchmark_group("message_format_verify");
    group.bench_function("ed25519", |b| {
        b.iter(|| {
            let ok = msg.verify_signature().expect("verify");
            black_box(ok);
        });
    });
    group.finish();
}

fn bench_encode_decode(c: &mut Criterion) {
    let msg = signed_message();
    let bytes = msg.encode().expect("encode");
    let mut group = c.benchmark_group("message_format_codec");
    group.bench_function("encode_json", |b| {
        b.iter(|| {
            let b = msg.encode().expect("encode");
            black_box(b);
        });
    });
    group.bench_function("decode_json", |b| {
        b.iter(|| {
            let m = TenzroMessage::decode(black_box(&bytes)).expect("decode");
            black_box(m);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_new_message,
    bench_sign,
    bench_verify,
    bench_encode_decode,
);
criterion_main!(benches);
