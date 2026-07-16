//! TEE (Trusted Execution Environment) abstraction layer for Tenzro Network.
//!
//! This crate provides a unified interface for working with different TEE technologies:
//! - Intel TDX (Trust Domain Extensions)
//! - AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging)
//! - AWS Nitro Enclaves
//!
//! The abstraction allows Tenzro Network to leverage confidential computing across
//! different hardware platforms while maintaining a consistent API.

pub mod attestation;
pub mod certs;
pub mod detection;
pub mod enclave_crypto;
pub mod enclave_keystore;
pub mod error;
pub mod registry;
pub mod sealed_agent_keypair;
pub mod sealed_secp256k1;
pub mod traits;

#[cfg(feature = "intel-tdx")]
pub mod intel_tdx;

#[cfg(feature = "amd-sev-snp")]
pub mod amd_sev_snp;

#[cfg(feature = "aws-nitro")]
pub mod aws_nitro;

#[cfg(feature = "nvidia-gpu")]
pub mod nvidia_gpu;

#[cfg(feature = "intel-tiber")]
pub mod intel_tiber;

// Re-export commonly used items
pub use error::{TeeError, Result};
pub use traits::TeeProvider;
pub use detection::detect_tee;
pub use registry::TeeRegistry;
pub use attestation::{AttestationVerifier, ParsedCertificate, parse_x509_certificate, verify_certificate_signature};
pub use sealed_agent_keypair::{
    attest_agent_key, pack_user_data_for_vendor, rotate_agent_key, seal_agent_keypair,
    AgentKeyAttestationPacket, AgentKeyHandle, SealedAgentHybridSignature,
};
pub use sealed_secp256k1::SealedSecp256k1Key;

// Re-export vendor implementations
#[cfg(feature = "intel-tdx")]
pub use intel_tdx::IntelTdxProvider;

#[cfg(feature = "amd-sev-snp")]
pub use amd_sev_snp::AmdSevSnpProvider;

#[cfg(feature = "aws-nitro")]
pub use aws_nitro::AwsNitroProvider;

#[cfg(feature = "nvidia-gpu")]
pub use nvidia_gpu::NvidiaGpuProvider;

#[cfg(feature = "intel-tiber")]
pub use intel_tiber::{
    claims_to_attestation_result, AttestRequest as TiberAttestRequest, IntelTiberClient,
    TiberClaims, TiberJwksPin, TokenSigningAlg as TiberTokenSigningAlg,
    VerifierNonce as TiberVerifierNonce, ATTEST_PATH as TIBER_ATTEST_PATH,
    NONCE_PATH as TIBER_NONCE_PATH, TIBER_API_URL_EU, TIBER_API_URL_US,
};

// Re-export types from tenzro-types
pub use tenzro_types::tee::*;
