//! Zero-knowledge proofs for Tenzro Network.
//!
//! # Statements
//!
//! Tenzro proves hash-preimage statements (see [`circuits::preimage`]):
//! knowledge of a 32-byte witness whose SHA3-256 under a per-circuit domain
//! label equals a public digest, bound to a 32-byte public context. The
//! `identity` circuit proves knowledge of the secret behind an identity key
//! commitment; the `settlement` circuit proves knowledge of the service result
//! a customer committed to before paying. The hash is evaluated in-circuit
//! with the Keccak-f[1600] AIR, so the witness is bound to the digest by the
//! constraints themselves.
//!
//! # Proof systems
//!
//! Every statement can be proven in three systems from two independent
//! implementations. Two Plonky3 STARK configurations differ in field,
//! extension, hash and FRI rate ([`plonky3::config`]); both use a hiding PCS
//! and are pinned at no less than 128 bits of proven (Johnson-regime)
//! soundness ([`plonky3::soundness`]). [`halo2`] proves the same statement
//! with a separately written PLONKish circuit over the Pasta curves.
//! [`diverse`] accepts a statement once proofs in `k` distinct systems, from
//! at least two implementations, verify.
//!
//! # TEE-bound proofs
//!
//! [`tee_integration`] bundles a proof with an attestation whose signed report
//! data commits to that exact proof.
//!
//! # Example
//!
//! ```ignore
//! use tenzro_zk::{Circuit, ProofSystem, prove, verify_proof_envelope};
//!
//! let proof = prove(ProofSystem::KoalaBearSha256Fri, Circuit::Settlement, &witness, &binding)?;
//! verify_proof_envelope(&proof)?;
//! ```

#![forbid(unsafe_code)]

pub mod circuits;
pub mod diverse;
pub mod error;
pub mod finality_proof;
pub mod halo2;
pub mod handover_chain;
pub mod plonky3;
pub mod proof;
pub mod tee_integration;

pub use circuits::{Circuit, PreimageAir};
pub use diverse::{
    DIVERSE_THRESHOLD, DiverseError, DiverseVerdict, statement_commitment, verify_k_of_n,
};
pub use error::{Result, ZkError};
pub use finality_proof::{TeeFinalityProof, verify_tee_finality_proof};
pub use plonky3::{VerifyEnvelopeError, prove, verify_proof_envelope};
pub use proof::{Implementation, Proof, ProofSystem, TeeZkProof};
pub use tee_integration::{bind_tee_attestation, verify_tee_zk_proof};
