//! Plonky3 STARK proving for Tenzro Network.
//!
//! Transparent-setup STARK system over the [`KoalaBear`] field. No trusted
//! setup, post-quantum-conjectured soundness (assuming Poseidon2 + FRI hold
//! up), and ~64–128KB proofs that verify in ~5–20ms on commodity hardware.
//!
//! # Module layout
//!
//! - [`config`] — pinned [`TenzroStarkConfig`] (field, hashes, FRI params).
//! - [`prover`] — [`Plonky3Prover`] wrapper around `p3_uni_stark::prove`.
//! - [`verifier`] — [`Plonky3Verifier`] wrapper around `p3_uni_stark::verify`.
//! - [`poseidon2_hash`] — native off-circuit Poseidon2 hashing. Used to commit
//!   to witness values that an AIR will re-derive in-circuit.
//!
//! Circuit definitions (the actual AIRs) live in [`crate::circuits`] — this
//! module hosts only the proving infrastructure they share.
//!
//! [`KoalaBear`]: p3_koala_bear::KoalaBear
//! [`TenzroStarkConfig`]: config::TenzroStarkConfig
//! [`Plonky3Prover`]: prover::Plonky3Prover
//! [`Plonky3Verifier`]: verifier::Plonky3Verifier

pub mod config;
pub mod envelope;
pub mod poseidon2_hash;
pub mod prover;
pub mod verifier;
pub mod verify_envelope;

pub use config::{TenzroStarkConfig, Val, build_testnet_config};
pub use envelope::{
    decode_kb, decode_proof, decode_public_inputs, encode_kb, encode_proof, encode_public_inputs,
};
pub use poseidon2_hash::{DIGEST_LEN, hash_many, hash_one, hash_pair};
pub use prover::Plonky3Prover;
pub use verifier::{Plonky3VerificationError, Plonky3Verifier};
pub use verify_envelope::{VerifyEnvelopeError, verify_proof_envelope};
