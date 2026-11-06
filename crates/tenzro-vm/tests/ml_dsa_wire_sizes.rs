//! ML-DSA objects at their real FIPS 204 sizes cross the wire.
//!
//! The 256-byte limits `MAX_SIGNATURE_BYTES` and `MAX_PUBLIC_KEY_BYTES` bound
//! `tenzro_types::Signature` (the classical signature and its key). ML-DSA
//! keys and signatures travel in other types, which carry no such limit; this
//! test fixes that with values of the real sizes: ML-DSA-65 key 1952 and
//! signature 3309 bytes, ML-DSA-87 key 2592 and signature 4627 bytes, the
//! non-default scheme's leg tagged with two more bytes.

use tenzro_types::account_signature::{ClassicalProof, CompositeSignature};
use tenzro_types::signature_scheme::SignatureScheme;

const ML_DSA_65: (usize, usize) = (1952, 3309);
const ML_DSA_87: (usize, usize) = (2592, 4627);

fn scheme_sizes(scheme: SignatureScheme) -> (usize, usize) {
    (
        scheme.ml_dsa_public_key_len(),
        scheme.ml_dsa_signature_len(),
    )
}

#[test]
fn the_schemes_carry_the_fips_204_sizes() {
    assert_eq!(scheme_sizes(SignatureScheme::MlDsa65P256), ML_DSA_65);
    assert_eq!(scheme_sizes(SignatureScheme::MlDsa87P384), ML_DSA_87);
    assert_eq!(ML_DSA_65.0, tenzro_crypto::pq::ML_DSA_65_VK_LEN);
    assert_eq!(ML_DSA_65.1, tenzro_crypto::pq::ML_DSA_65_SIG_LEN);
}

#[test]
fn a_leg_of_either_scheme_splits_back_into_its_scheme_and_bare_bytes() {
    for scheme in SignatureScheme::ALL {
        let (key_len, sig_len) = scheme_sizes(scheme);
        let key = vec![0x5a; key_len];
        let sig = vec![0xa5; sig_len];

        let tagged_key = scheme.tag(&key);
        let tagged_sig = scheme.tag(&sig);
        let extra = if scheme == SignatureScheme::default() {
            0
        } else {
            2
        };
        assert_eq!(tagged_key.len(), key_len + extra);
        assert_eq!(tagged_sig.len(), sig_len + extra);
        assert!(tagged_key.len() > 256 && tagged_sig.len() > 256);

        assert_eq!(
            SignatureScheme::split_public_key(&tagged_key),
            Some((scheme, key.as_slice()))
        );
        assert_eq!(
            SignatureScheme::split_signature(&tagged_sig),
            Some((scheme, sig.as_slice()))
        );
    }
}

#[test]
fn a_hybrid_signature_of_either_scheme_round_trips_in_both_encodings() {
    for scheme in SignatureScheme::ALL {
        let pq = scheme.tag(&vec![0xa5; scheme.ml_dsa_signature_len()]);
        let sig = CompositeSignature::hybrid(
            ClassicalProof::Raw {
                signature: vec![0x11; 64],
            },
            pq.clone(),
        );

        // Binary: inside a block or a consensus vertex.
        let bin = bincode::serialize(&sig).unwrap();
        let back: CompositeSignature = bincode::deserialize(&bin).unwrap();
        assert_eq!(back, sig);
        assert_eq!(back.pq.as_deref(), Some(pq.as_slice()));

        // Text: over RPC.
        let json = serde_json::to_string(&sig).unwrap();
        let back: CompositeSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sig);
    }
}
