//! Core TEE abstraction traits for Tenzro Network.

use async_trait::async_trait;
use tenzro_types::tee::*;
use crate::error::Result;

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

    /// Executes a request inside the secure enclave.
    ///
    /// # Arguments
    /// - `request`: The enclave operation to perform
    ///
    /// # Returns
    /// The response from the enclave, potentially with attestation
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
