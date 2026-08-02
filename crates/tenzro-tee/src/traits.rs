//! Core TEE abstraction traits for Tenzro Network.

use crate::error::Result;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tenzro_types::tee::*;

/// Domain separator for the enclave-response binding. Distinct from every other
/// SHA-256 domain in the workspace so a binding can never be replayed as some
/// other commitment.
const ENCLAVE_RESPONSE_DOMAIN: &[u8] = b"tenzro/tee/enclave-response";

/// Commitment binding an enclave response to the request that produced it.
///
/// This is the value a provider puts in the `user_data` of the attestation
/// report it attaches to an [`EnclaveResponse`]. Because `user_data` is covered
/// by the hardware signature over the report, a relying party that verifies the
/// report and recomputes this commitment learns that *this exact output* was
/// produced inside an enclave with *that exact measurement* — rather than
/// merely that some enclave existed somewhere.
///
/// The request id and operation are bound alongside the data so a response
/// cannot be lifted from one request and presented as the answer to another.
/// Every field is length-prefixed so no two distinct triples can collide by
/// shifting bytes across a boundary.
pub fn enclave_response_binding(request_id: &uuid::Uuid, operation: &str, data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(ENCLAVE_RESPONSE_DOMAIN);
    for field in [request_id.as_bytes().as_slice(), operation.as_bytes(), data] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().to_vec()
}

/// Core trait for TEE (Trusted Execution Environment) providers.
///
/// This trait abstracts over different TEE implementations (Intel TDX, AMD SEV-SNP, AWS Nitro)
/// to provide a unified interface for confidential computing operations in Tenzro Network.
#[async_trait]
pub trait TeeProvider: Send + Sync {
    /// Returns the TEE vendor for this provider.
    fn vendor(&self) -> TeeVendor;

    /// Checks if the TEE hardware is available and functional.
    ///
    /// # Returns
    /// - `Ok(true)` if TEE is available and ready
    /// - `Ok(false)` if TEE is not available
    /// - `Err(_)` if there was an error checking availability
    async fn is_available(&self) -> Result<bool>;

    /// Generates an attestation report for the given user data.
    ///
    /// The attestation report cryptographically proves that the code is running
    /// inside a genuine TEE with specific security properties.
    ///
    /// # Arguments
    /// - `user_data`: Application-specific data to include in the attestation
    ///
    /// # Returns
    /// An attestation report that can be verified by other parties
    async fn generate_attestation(&self, user_data: &[u8]) -> Result<AttestationReport>;

    /// Verifies an attestation report.
    ///
    /// # Arguments
    /// - `report`: The attestation report to verify
    ///
    /// # Returns
    /// Detailed verification results including TCB version and measurements
    async fn verify_attestation(&self, report: &AttestationReport) -> Result<AttestationResult>;

    /// Runs `request` inside the enclave boundary and, when asked, binds the
    /// result to that boundary.
    ///
    /// # What this does and does not mean
    ///
    /// Tenzro's model is that the **whole node process already runs inside a
    /// confidential VM** — the TD, the SEV-SNP guest, the Nitro enclave. There
    /// is no separate per-workload enclave to dispatch into, so this call is
    /// not a context switch and must not be read as one. Its job is narrower
    /// and it is worth stating plainly:
    ///
    /// > Everything the node computes is already inside the boundary. This
    /// > call is how a caller gets *evidence* of that for one specific result.
    ///
    /// With `request.include_attestation` set, the provider generates a live
    /// attestation report whose `user_data` is
    /// [`enclave_response_binding`]`(id, operation, data)`. Because `user_data`
    /// is covered by the hardware signature over the report, a relying party
    /// that verifies the report and recomputes the binding learns that this
    /// exact output came from an enclave with that exact measurement.
    ///
    /// With the flag clear, no report is generated and `attestation` is `None`
    /// — attestation costs a hardware round-trip, so a caller that does not
    /// need evidence should not pay for it.
    ///
    /// # Errors
    ///
    /// Fails closed. If the provider is unavailable, or if attestation was
    /// requested and the hardware could not produce a report, this returns an
    /// error rather than a response with `attestation: None` — a caller that
    /// asked to be able to prove where a result came from must never be handed
    /// one it cannot prove.
    async fn execute_in_enclave(&self, request: EnclaveRequest) -> Result<EnclaveResponse>;

    /// Generates a cryptographic key inside the enclave.
    ///
    /// The key never leaves the secure environment and all operations
    /// using it are performed inside the TEE.
    ///
    /// # Arguments
    /// - `params`: Key generation parameters
    ///
    /// # Returns
    /// A handle to the generated key
    async fn enclave_keygen(&self, params: KeyGenParams) -> Result<EnclaveKeyHandle>;

    /// Signs data using a key stored in the enclave.
    ///
    /// # Arguments
    /// - `key`: Handle to the signing key
    /// - `data`: Data to sign
    ///
    /// # Returns
    /// The signature
    async fn enclave_sign(&self, key: &EnclaveKeyHandle, data: &[u8]) -> Result<Vec<u8>>;

    /// Encrypts data using a key stored in the enclave.
    ///
    /// # Arguments
    /// - `key`: Handle to the encryption key
    /// - `plaintext`: Data to encrypt
    ///
    /// # Returns
    /// The ciphertext
    async fn enclave_encrypt(&self, key: &EnclaveKeyHandle, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypts data using a key stored in the enclave.
    ///
    /// # Arguments
    /// - `key`: Handle to the decryption key
    /// - `ciphertext`: Data to decrypt
    ///
    /// # Returns
    /// The plaintext
    async fn enclave_decrypt(&self, key: &EnclaveKeyHandle, ciphertext: &[u8]) -> Result<Vec<u8>>;
}
