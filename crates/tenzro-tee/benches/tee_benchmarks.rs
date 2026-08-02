//! Criterion benches for the TEE keystore hot paths. Bounds are pinned in
//! `tools/bench-gate/thresholds.toml`.

use criterion::{Criterion, criterion_group, criterion_main};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF-SHA256 derive + Ed25519 keypair-from-seed. Matches the
/// `EnclaveKeystore::keygen` Ed25519 path's two hot steps. Bound is
/// `≤ 10 µs` per the BENCHMARKS reference (3 µs HKDF + ~50 µs Ed25519
/// keypair on M-class).
fn bench_hkdf_keygen(c: &mut Criterion) {
    let ikm = [0u8; 32];
    let salt = b"tenzro/tee/keygen-bench/v1";
    let info = b"ed25519";

    c.bench_function("hkdf_derive_ed25519_seed", |b| {
        b.iter(|| {
            let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
            let mut okm = [0u8; 32];
            hk.expand(info, &mut okm).unwrap();
            let _ = SigningKey::from_bytes(&okm);
        })
    });
}

criterion_group!(benches, bench_hkdf_keygen);
criterion_main!(benches);
