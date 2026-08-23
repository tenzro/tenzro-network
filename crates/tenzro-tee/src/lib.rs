//! TEE (Trusted Execution Environment) abstraction layer for Tenzro Network.
//!
//! This crate provides a unified interface for working with different TEE technologies:
//! - Intel TDX (Trust Domain Extensions)
//! - AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging)
//! - AWS Nitro Enclaves
//! - NVIDIA GPU Confidential Computing (Hopper / Blackwell), as an extension of a
//!   CPU confidential VM rather than a standalone trust boundary
//!
//! The abstraction allows Tenzro Network to leverage confidential computing across
//! different hardware platforms while maintaining a consistent API.
//!
//! NVIDIA GPU CC differs from the three CPU technologies in one structural way: it
//! does not establish a trust boundary on its own. The confidential VM is created by
//! SEV-SNP or TDX; the GPU is then admitted to that VM over an SPDM-authenticated
//! PCIe link with VRAM protection. Attestation is therefore composite — a CPU quote
//! and a GPU evidence report bound together by a shared nonce. See [`nvidia_gpu`].

pub mod attestation;
pub mod certs;
pub mod detection;
pub mod enclave_crypto;
pub mod enclave_keystore;
pub mod error;
pub mod hardware_identity;
pub mod platform_root;
pub mod tpm_derive;
pub mod registry;
pub mod sealed_agent_keypair;
pub mod sealed_secp256k1;
pub mod tpm_seal;
pub mod traits;

#[cfg(feature = "intel-tdx")]
pub mod intel_tdx;

#[cfg(feature = "amd-sev-snp")]
pub mod amd_sev_snp;

#[cfg(feature = "aws-nitro")]
pub mod aws_nitro;

#[cfg(feature = "nvidia-gpu")]
pub mod nvidia_gpu;

/// Runtime NVML bindings used to collect NVIDIA Confidential Computing evidence.
///
/// Bound with `dlopen` at first use so the same binary runs on hosts without an
/// NVIDIA driver.
#[cfg(all(target_os = "linux", feature = "nvidia-gpu"))]
pub mod nvml;

#[cfg(feature = "intel-tiber")]
pub mod intel_tiber;

/// Length of the nonce carried into an NVIDIA GPU Confidential Computing
/// attestation report.
///
/// Fixed by the driver ABI (`NVML_CC_GPU_CEC_NONCE_SIZE`). The same value is
/// used for the CPU quote when the two are bound together, so that a verifier
/// can see both legs answer the same challenge.
pub const NVIDIA_CC_NONCE_LEN: usize = 32;

// Re-export commonly used items
pub use attestation::{
    AttestationVerifier, ParsedCertificate, parse_x509_certificate, verify_certificate_signature,
};
pub use detection::detect_tee;
pub use error::{Result, TeeError};
pub use hardware_identity::HardwareIdentity;
pub use platform_root::{derive_platform_key, platform_root_available, platform_root_ikm};
pub use registry::TeeRegistry;
pub use sealed_agent_keypair::{
    AGENT_KEY_PACKET_LEN, AgentKeyAttestationPacket, AgentKeyHandle, SealedAgentHybridSignature,
    attest_agent_key, pack_user_data_for_vendor, rotate_agent_key, seal_agent_keypair,
    verify_agent_key_binding,
};
pub use sealed_secp256k1::SealedSecp256k1Key;
pub use traits::TeeProvider;

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
    ATTEST_PATH as TIBER_ATTEST_PATH, AttestRequest as TiberAttestRequest, IntelTiberClient,
    NONCE_PATH as TIBER_NONCE_PATH, TIBER_API_URL_EU, TIBER_API_URL_US, TiberClaims, TiberJwksPin,
    TokenSigningAlg as TiberTokenSigningAlg, VerifierNonce as TiberVerifierNonce,
    claims_to_attestation_result,
};

// Re-export types from tenzro-types
pub use tenzro_types::tee::*;
