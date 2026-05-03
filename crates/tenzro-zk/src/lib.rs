//! Zero-knowledge proof system for Tenzro Network.
//!
//! This crate provides a Plonky3-based STARK proving system for the Tenzro
//! Ledger. Proofs are generated over the [`KoalaBear`] field, hashed with
//! Poseidon2, and committed via FRI — no trusted setup, post-quantum-conjectured
//! soundness. Circuits are expressed as [`p3_air::Air`] AIRs.
//!
//! # Examples
//!
//! ```ignore
//! use tenzro_zk::{
//!     circuits::airs::InferenceAir,
//!     plonky3::{Plonky3Prover, Plonky3Verifier},
//! };
//!
//! // Build the AIR + execution trace from witness data, then prove and
//! // verify with the pinned testnet STARK config (set up internally).
//! let prover: Plonky3Prover<InferenceAir> = Plonky3Prover::new();
//! let verifier: Plonky3Verifier<InferenceAir> = Plonky3Verifier::new();
//! ```
//!
//! [`KoalaBear`]: p3_koala_bear::KoalaBear

pub mod circuits;
pub mod error;
pub mod plonky3;
pub mod proof;
pub mod tee_integration;

// Re-export commonly used types
pub use error::{Result, ZkError};
pub use proof::{Proof, ProofMetadata, ProofType, TeeZkProof};

// Re-export Plonky3 stack
pub use plonky3::{
    Plonky3Prover, Plonky3VerificationError, Plonky3Verifier, TenzroStarkConfig, Val,
    VerifyEnvelopeError, build_testnet_config, verify_proof_envelope,
};

// Re-export Plonky3 AIRs
pub use circuits::{
    InferenceAir, IdentityAir, SettlementAir,
    NUM_INFERENCE_COLS, NUM_INFERENCE_PUBLIC_VALUES,
    NUM_IDENTITY_COLS, NUM_IDENTITY_PUBLIC_VALUES,
    NUM_SETTLEMENT_COLS, NUM_SETTLEMENT_PUBLIC_VALUES,
    generate_inference_trace, inference_public_inputs,
    generate_identity_trace, identity_public_inputs,
    generate_settlement_trace, settlement_public_inputs,
};

// Re-export KoalaBear field type and trait for downstream witness builders.
pub use p3_field::PrimeCharacteristicRing;
pub use p3_koala_bear::KoalaBear;

// Re-export TEE integration helpers.
pub use tee_integration::{
    extract_tee_public_key, generate_tee_zk_proof, get_expected_measurement,
    sign_tee_zk_proof, verify_tee_zk_proof, verify_tee_zk_signature,
};
