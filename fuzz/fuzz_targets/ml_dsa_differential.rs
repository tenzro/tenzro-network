#![no_main]
//! The two ML-DSA-65 verifiers (RustCrypto `ml-dsa` and `libcrux-ml-dsa`)
//! give the same verdict on every input.
//!
//! An input is a key seed, a message and a context to sign under, then edits
//! to the key and signature and the context to verify under. Starting from a
//! real signature keeps most inputs near the accept/refuse boundary, where a
//! decoding or norm-check difference between the implementations shows up;
//! a fully random signature is refused by both on its first check. The
//! target panics when the verdicts differ.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tenzro_crypto::pq::{MlDsaSigningKey, libcrux_ml_dsa_verify, rustcrypto_ml_dsa_verify};

/// Contexts a signature is made under: `sign` takes protocol constants.
const CONTEXTS: [&[u8]; 3] = [b"", b"tenzro/finality/vote", &[0x5a; 255]];

#[derive(Arbitrary, Debug)]
struct Input {
    seed: [u8; 32],
    msg: Vec<u8>,
    sign_ctx: u8,
    /// The context the verifiers are asked about; the signing one if absent.
    verify_ctx: Option<Vec<u8>>,
    /// `(offset, xor)` edits to the signature.
    sig_edits: Vec<(u16, u8)>,
    /// `(offset, xor)` edits to the public key.
    key_edits: Vec<(u16, u8)>,
    /// A length to cut or pad the signature to.
    sig_len: Option<u16>,
}

fn apply(bytes: &mut [u8], edits: &[(u16, u8)]) {
    if bytes.is_empty() {
        return;
    }
    for &(at, x) in edits.iter().take(16) {
        let i = usize::from(at) % bytes.len();
        bytes[i] ^= x;
    }
}

fuzz_target!(|input: Input| {
    let key = MlDsaSigningKey::from_seed(&input.seed).expect("32-byte seed");
    let sign_ctx = CONTEXTS[usize::from(input.sign_ctx) % CONTEXTS.len()];
    let mut sig = key.sign(sign_ctx, &input.msg);
    let mut vk = key.verifying_key_bytes().to_vec();
    apply(&mut sig, &input.sig_edits);
    apply(&mut vk, &input.key_edits);
    if let Some(len) = input.sig_len {
        sig.resize(usize::from(len), 0);
    }
    let ctx = input.verify_ctx.as_deref().unwrap_or(sign_ctx);
    let rustcrypto = rustcrypto_ml_dsa_verify(&vk, ctx, &input.msg, &sig).is_ok();
    let libcrux = libcrux_ml_dsa_verify(&vk, ctx, &input.msg, &sig).is_ok();
    assert_eq!(
        rustcrypto, libcrux,
        "ML-DSA-65 verifiers disagree: RustCrypto {rustcrypto}, libcrux {libcrux}"
    );
    if input.sig_edits.is_empty() && input.key_edits.is_empty() && input.sig_len.is_none()
        && input.verify_ctx.is_none()
    {
        assert!(rustcrypto, "an untouched signature is refused");
    }
});
