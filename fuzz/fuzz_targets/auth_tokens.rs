//! Fuzzes what a client presents to the node's authorization layer: access
//! tokens, DPoP proofs, JWK thumbprint input and WebAuthn registration data.
//!
//! The first byte picks the decoder; the property is that none of them
//! panics, and no token is accepted (the fuzzer holds no signing key).

#![no_main]

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use tenzro_auth::{AuthEngine, AuthEngineConfig, DpopProof, DpopValidation, TokenSigner};

struct VerifyOnly([u8; 64]);

impl TokenSigner for VerifyOnly {
    fn public_key(&self) -> [u8; 64] {
        self.0
    }

    fn sign_prehash(&self, _prehash: &[u8; 32]) -> Result<[u8; 64], String> {
        Err("verification only".into())
    }
}

fn engine() -> &'static AuthEngine {
    static ENGINE: OnceLock<AuthEngine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let pair = tenzro_crypto::P256KeyPair::from_secret_bytes(&[9; 32]).expect("scalar");
        let mut xy = [0u8; 64];
        xy.copy_from_slice(&pair.public_key_sec1()[1..]);
        AuthEngine::new(
            AuthEngineConfig::new("did:tenzro:node:fuzz", "https://rpc.fuzz"),
            Arc::new(tenzro_storage::MemoryStore::new()),
            Arc::new(VerifyOnly(xy)),
        )
        .expect("engine")
    })
}

const NOW: i64 = 1_790_000_000;

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    match which % 4 {
        0 => {
            let Ok(text) = std::str::from_utf8(rest) else {
                return;
            };
            if let Ok((proof, input, sig)) = DpopProof::parse_with_signed_input(text) {
                let _ = proof.verify("POST", "https://rpc.fuzz/", NOW, &input, &sig);
            }
            let _ = DpopProof::compute_jkt(text);
            let _ = tenzro_auth::peek_unverified_jti(text);
        }
        1 => {
            let Ok(text) = std::str::from_utf8(rest) else {
                return;
            };
            let (token, dpop) = text.split_once('\n').unwrap_or((text, ""));
            assert!(engine().validate_jwt(token, None).is_err());
            if let Ok((proof, input, sig)) = DpopProof::parse_with_signed_input(dpop) {
                let ctx = DpopValidation {
                    proof: &proof,
                    expected_htm: "POST",
                    expected_htu: "https://rpc.fuzz/",
                    now_unix: NOW,
                    signed_input: &input,
                    signature: &sig,
                };
                assert!(engine().validate_jwt(token, Some(ctx)).is_err());
            }
        }
        2 => {
            let _ = tenzro_auth::read_authenticator_data(rest);
        }
        _ => {
            let _ = tenzro_auth::parse_attestation(rest, &[0; 32], &[], NOW as u64);
        }
    }
});
