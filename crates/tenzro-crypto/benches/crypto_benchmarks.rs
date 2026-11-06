//! Criterion benchmarks for tenzro-crypto critical paths
//!
//! Run with: cargo bench -p tenzro-crypto

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use tenzro_crypto::encryption::{self, SymmetricKey};
use tenzro_crypto::hash;
use tenzro_crypto::keys::{KeyPair, KeyType};
use tenzro_crypto::signatures::{self, Ed25519SignerImpl, Secp256k1SignerImpl, Signer};

fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation");

    group.bench_function("ed25519_keygen", |b| {
        b.iter(|| {
            black_box(KeyPair::generate(KeyType::Ed25519).unwrap());
        });
    });

    group.bench_function("secp256k1_keygen", |b| {
        b.iter(|| {
            black_box(KeyPair::generate(KeyType::Secp256k1).unwrap());
        });
    });

    group.finish();
}

fn bench_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing");
    let message = b"Tenzro Network transaction data for benchmark testing";

    let ed25519_signer = Ed25519SignerImpl::generate().unwrap();
    let secp256k1_signer = Secp256k1SignerImpl::generate().unwrap();

    group.bench_function("ed25519_sign", |b| {
        b.iter(|| {
            black_box(ed25519_signer.sign(black_box(message)).unwrap());
        });
    });

    group.bench_function("secp256k1_sign", |b| {
        b.iter(|| {
            black_box(secp256k1_signer.sign(black_box(message)).unwrap());
        });
    });

    group.finish();
}

fn bench_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification");
    let message = b"Tenzro Network transaction data for benchmark testing";

    let ed25519_signer = Ed25519SignerImpl::generate().unwrap();
    let ed25519_sig = ed25519_signer.sign(message).unwrap();
    let ed25519_pubkey = ed25519_signer.public_key().clone();

    let secp256k1_signer = Secp256k1SignerImpl::generate().unwrap();
    let secp256k1_sig = secp256k1_signer.sign(message).unwrap();
    let secp256k1_pubkey = secp256k1_signer.public_key().clone();

    group.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            signatures::verify(
                black_box(&ed25519_pubkey),
                black_box(message),
                black_box(&ed25519_sig),
            )
            .unwrap();
        });
    });

    group.bench_function("secp256k1_verify", |b| {
        b.iter(|| {
            signatures::verify(
                black_box(&secp256k1_pubkey),
                black_box(message),
                black_box(&secp256k1_sig),
            )
            .unwrap();
        });
    });

    group.finish();
}

fn bench_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");

    for size in [32, 256, 1024, 4096].iter() {
        let data = vec![0xABu8; *size];

        group.bench_with_input(BenchmarkId::new("sha256", size), size, |b, _| {
            b.iter(|| {
                black_box(hash::sha256(black_box(&data)));
            });
        });

        group.bench_with_input(BenchmarkId::new("keccak256", size), size, |b, _| {
            b.iter(|| {
                black_box(hash::keccak256(black_box(&data)));
            });
        });
    }

    group.finish();
}

fn bench_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("encryption");
    let key = SymmetricKey::generate();
    let plaintext = vec![0xABu8; 1024];

    group.bench_function("aes256gcm_encrypt_1kb", |b| {
        b.iter(|| {
            black_box(encryption::encrypt_aes(
                black_box(&key),
                black_box(&plaintext),
            ))
            .unwrap();
        });
    });

    let ciphertext = encryption::encrypt_aes(&key, &plaintext).unwrap();

    group.bench_function("aes256gcm_decrypt_1kb", |b| {
        b.iter(|| {
            black_box(encryption::decrypt_aes(
                black_box(&key),
                black_box(&ciphertext),
            ))
            .unwrap();
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_signing,
    bench_verification,
    bench_hashing,
    bench_encryption,
);
criterion_main!(benches);
