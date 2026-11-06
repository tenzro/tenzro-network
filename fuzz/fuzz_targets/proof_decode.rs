//! Fuzzes the proof and certificate bytes a node takes from peers and light
//! clients: finality journals, compact certificates and the claims, ML-DSA
//! keys and signatures inside them, proof envelopes of every system (alone
//! and as legs of a diverse statement), and Groth16 finality seals.
//!
//! The first byte picks the decoder. None of them may panic; a journal or a
//! claim that decodes re-encodes to exactly the input, so one statement has
//! one encoding; and no fuzzed proof, set of legs or seal verifies.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tenzro_cert_stark::compact::{Claim, CompactProof};
use tenzro_cert_stark::mldsa;
use tenzro_finality::step::{FinalityJournal, FinalityStep};
use tenzro_zk::Proof;

fn proofs(bytes: &[u8]) -> Vec<Proof> {
    if let Ok(p) = serde_json::from_slice::<Vec<Proof>>(bytes) {
        return p;
    }
    if let Ok(p) = serde_json::from_slice::<Proof>(bytes) {
        return vec![p];
    }
    bincode::deserialize::<Vec<Proof>>(bytes).unwrap_or_default()
}

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    match which % 6 {
        0 => {
            if let Some(j) = FinalityJournal::decode(rest) {
                assert_eq!(j.encode(), rest, "a finality journal has one encoding");
            }
            let _ = bincode::deserialize::<FinalityStep>(rest);
        }
        1 => {
            if let Some(c) = Claim::decode(rest) {
                assert_eq!(c.encode(), rest, "a claim has one encoding");
            }
        }
        2 => {
            let _ = CompactProof::decode(rest);
        }
        3 => {
            let _ = mldsa::PublicKey::decode(rest);
            let _ = mldsa::Signature::decode(rest);
        }
        4 => {
            let legs = proofs(rest);
            for leg in legs.iter().take(4) {
                assert!(tenzro_zk::verify_proof_envelope(leg).is_err(), "a fuzzed proof verified");
            }
            if !legs.is_empty() && legs.len() <= 4 {
                assert!(tenzro_zk::verify_k_of_n(&legs, 1).is_err(), "fuzzed legs verified");
            }
        }
        _ => {
            let (image, rest) = rest.split_at(rest.len().min(32));
            let mut id = [0u8; 32];
            id[..image.len()].copy_from_slice(image);
            let (seal, journal) = rest.split_at(rest.len().min(tenzro_zk::finality_proof::SEAL_LEN));
            assert!(
                tenzro_zk::finality_proof::verify(&id, journal, seal).is_err(),
                "a fuzzed seal verified"
            );
        }
    }
});
