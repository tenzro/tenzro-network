//! The confidential-execution boundary, and the evidence that it held.
//!
//! # What this crate is for
//!
//! Running a workload where the operator of the machine cannot read it, and
//! proving to a remote party that this is what actually happened. Concretely,
//! the workloads are:
//!
//! - **Secure inference** — a model, a prompt, or both, that the host running
//!   them must not be able to see.
//! - **Zero-knowledge proving** — where a proof is generated inside the
//!   boundary so the prover's witness never leaves it. The proof system is
//!   `tenzro-zk`; this crate is only the enclosure it can run in.
//! - **Attestation** — the quote or evidence report that lets a client decide
//!   whether to believe any of the above. Without it the other three are
//!   assertions, so it is not a separate feature but the thing that makes them
//!   worth anything.
//!
//! Vendors covered: Intel TDX, AMD SEV-SNP, AWS Nitro Enclaves, and NVIDIA GPU
//! Confidential Computing on Hopper / Blackwell.
//!
//! NVIDIA GPU CC differs from the three CPU technologies in one structural way:
//! it does not establish a trust boundary on its own. The confidential VM is
//! created by SEV-SNP or TDX; the GPU is then admitted to that VM over an
//! SPDM-authenticated PCIe link with VRAM protection. Attestation is therefore
//! composite — a CPU quote and a GPU evidence report bound together by a shared
//! nonce. See [`nvidia_gpu`].
//!
//! # What this crate is not for
//!
//! **Key custody, and above all not node ownership.** Nothing in the identity
//! model roots trust here, and nothing should start to.
//!
//! A node's authority comes from one of exactly three places: its own TPM 2.0,
//! a human's WebAuthn passkey, or another TPM-rooted machine the same operator
//! owns and has named as its controller. All three are the operator's own
//! hardware or their own credential. An enclave root would not be: it would put
//! node ownership behind a silicon vendor's attestation service, which is a
//! custodian by another name and the opposite of what the network is.
//!
//! The distinction is not a preference, it is what the technologies do. **A TEE
//! attests that a *workload* ran unmodified on trusted silicon. A TPM or a
//! secure element attests that a *machine* holds a key nobody can copy.** Those
//! answer different questions, and a system that treats them as interchangeable
//! will eventually make a claim about one while holding evidence of the other.
//!
//! # The hardware-root modules that still live here
//!
//! [`hardware_identity`] and [`tpm_attest`] are machine-root code, not
//! confidential compute: they read and attest the machine's hardware
//! identity. Keys that sign on a machine's behalf go through
//! `tenzro_device_key::signer`, which holds them in the TPM or Secure Enclave,
//! and keys the hardware cannot hold are derived on demand through
//! `tenzro_device_key::derive`.
//!
//! Nothing in this crate derives a key from a TEE measurement. A measurement
//! is printed in every report and identical for every instance of an image,
//! so a key computed from it is a key anyone can compute.

// --- Confidential execution: the boundary, and the evidence it held. --------

pub mod certs;
pub mod detection;
pub mod error;
pub mod measurements;
pub mod registry;
pub mod report_data;
pub mod traits;
pub mod verify;
pub mod x509;

// --- Hardware roots. --------------------------------------------------------
//
// Not confidential compute, and not TEEs. A TPM and a secure element attest
// that a machine holds a key nobody can copy; a TEE attests that a workload ran
// unmodified. See the crate docs.

pub mod hardware_identity;
pub mod identity_evidence;
pub mod nvidia_device;
pub mod nvidia_rim;
pub mod ocsp;
pub mod tpm_attest;

// --- Confidential compute built on the verifiers. ------------------------

pub mod confidential_job;
pub mod key_release;

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
pub use detection::detect_tee;
pub use error::{Result, TeeError};
pub use hardware_identity::HardwareIdentity;
pub use registry::TeeRegistry;
pub use traits::TeeProvider;
pub use verify::{VerifiedAttestation, VerifyPolicy, configure_nvidia_jwks, verify_report};

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
