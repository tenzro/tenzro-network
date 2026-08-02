//! Byte-encoding helpers for Plonky3 proofs and KoalaBear public inputs.
//!
//! Bridges the typed `p3_uni_stark::Proof<TenzroStarkConfig>` and
//! `Vec<KoalaBear>` produced by [`super::Plonky3Prover`] / the AIR helpers
//! to the byte-oriented [`crate::proof::Proof`] envelope used across
//! storage, RPC, MCP, and on-chain commitment-attestation paths.
//!
//! Plonky3 proofs are serialized via `bincode` (configurable, version-pinned
//! by `p3-uni-stark`'s git rev). KoalaBear public inputs are serialized as
//! 4-byte little-endian field elements — fixed-width, no length prefix
//! needed because the consumer already knows `NUM_*_PUBLIC_VALUES` from
//! the AIR module.

use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use p3_uni_stark::Proof as P3Proof;

use super::config::TenzroStarkConfig;
use crate::error::{Result, ZkError};

/// Serialize a Plonky3 proof to bytes via `bincode`.
pub fn encode_proof(proof: &P3Proof<TenzroStarkConfig>) -> Result<Vec<u8>> {
    bincode::serialize(proof).map_err(|e| ZkError::SerializationError(e.to_string()))
}

/// Deserialize a Plonky3 proof from bytes.
pub fn decode_proof(bytes: &[u8]) -> Result<P3Proof<TenzroStarkConfig>> {
    bincode::deserialize(bytes).map_err(|e| ZkError::SerializationError(e.to_string()))
}

/// Encode a single KoalaBear element as 4 little-endian bytes.
pub fn encode_kb(x: KoalaBear) -> [u8; 4] {
    x.as_canonical_u32().to_le_bytes()
}

/// Decode a single KoalaBear element from 4 little-endian bytes.
pub fn decode_kb(bytes: &[u8]) -> Result<KoalaBear> {
    if bytes.len() != 4 {
        return Err(ZkError::SerializationError(format!(
            "expected 4 bytes for KoalaBear, got {}",
            bytes.len()
        )));
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(bytes);
    let raw = u32::from_le_bytes(buf);
    // KoalaBear modulus = 2^31 - 2^24 + 1 ≈ 2.13e9.
    Ok(KoalaBear::from_u64(raw as u64))
}

/// Encode a KoalaBear public-input vector as a `Vec<Vec<u8>>` for the
/// [`crate::proof::Proof::public_inputs`] field — one 4-byte chunk per
/// element so storage layers can keep treating each public input as an
/// opaque blob.
pub fn encode_public_inputs(pis: &[KoalaBear]) -> Vec<Vec<u8>> {
    pis.iter().map(|x| encode_kb(*x).to_vec()).collect()
}

/// Decode a `Vec<Vec<u8>>` of 4-byte little-endian chunks back into KoalaBear
/// public inputs.
pub fn decode_public_inputs(blobs: &[Vec<u8>]) -> Result<Vec<KoalaBear>> {
    blobs.iter().map(|b| decode_kb(b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::airs::inference::{
        InferenceAir, generate_inference_trace, inference_public_inputs,
    };
    use crate::plonky3::{Plonky3Prover, Plonky3Verifier};

    #[test]
    fn kb_roundtrip() {
        let x = KoalaBear::from_u64(123456789);
        let bytes = encode_kb(x);
        let y = decode_kb(&bytes).unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn public_inputs_roundtrip() {
        let pis: Vec<KoalaBear> = (0..8).map(|i| KoalaBear::from_u64(i * 7 + 11)).collect();
        let blobs = encode_public_inputs(&pis);
        assert_eq!(blobs.len(), pis.len());
        assert!(blobs.iter().all(|b| b.len() == 4));
        let decoded = decode_public_inputs(&blobs).unwrap();
        assert_eq!(decoded, pis);
    }

    #[test]
    fn proof_roundtrip_through_envelope() {
        let model = KoalaBear::from_u64(3);
        let input = KoalaBear::from_u64(5);
        let output = KoalaBear::from_u64(15);

        let trace = generate_inference_trace(model, input, output, 1 << 3);
        let pis = inference_public_inputs(model, input, output);

        let prover = Plonky3Prover::<InferenceAir>::new();
        let proof = prover.prove_air(&InferenceAir, trace, &pis);

        let bytes = encode_proof(&proof).expect("encode");
        let decoded = decode_proof(&bytes).expect("decode");

        let verifier = Plonky3Verifier::<InferenceAir>::new();
        verifier
            .verify_air(&InferenceAir, &decoded, &pis)
            .expect("decoded proof must verify");
    }
}
