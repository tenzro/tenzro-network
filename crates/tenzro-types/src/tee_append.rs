
/// A measurement extracted from a TEE attestation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Measurement {
    /// Index of the measurement register (e.g., PCR index, RTMR index)
    pub index: u32,
    /// Hash algorithm used (e.g., "SHA384", "SHA256")
    pub algorithm: String,
    /// The measurement value (hash bytes)
    pub value: Vec<u8>,
}

/// Request to execute an operation inside a TEE enclave
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveRequest {
    /// Unique request ID
    pub id: uuid::Uuid,
    /// The operation to perform
    pub operation: String,
    /// Operation parameters
    pub params: Vec<u8>,
    /// Whether to include attestation in response
    pub include_attestation: bool,
}

impl EnclaveRequest {
    /// Creates a new enclave request
    pub fn new(operation: String, params: Vec<u8>) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            operation,
            params,
            include_attestation: false,
        }
    }
}

/// Response from a TEE enclave operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveResponse {
    /// ID of the request this responds to
    pub request_id: uuid::Uuid,
    /// Whether the operation succeeded
    pub success: bool,
    /// Response data
    pub data: Vec<u8>,
    /// Error message if operation failed
    pub error: Option<String>,
    /// Optional attestation proving the response came from a TEE
    pub attestation: Option<AttestationReport>,
}

/// Parameters for generating a key inside a TEE enclave
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyGenParams {
    /// Cryptographic algorithm to use
    pub algorithm: KeyAlgorithm,
    /// Purpose of the key
    pub purpose: KeyPurpose,
    /// Whether the key can be exported
    pub exportable: bool,
    /// Additional algorithm-specific parameters
    pub params: std::collections::HashMap<String, String>,
}

/// Cryptographic algorithms supported for enclave key generation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    /// Ed25519 signature algorithm
    Ed25519,
    /// ECDSA with secp256k1 curve
    Secp256k1,
    /// AES-256-GCM encryption
    Aes256Gcm,
}

/// Purpose of a cryptographic key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyPurpose {
    /// For signing operations
    Signing,
    /// For encryption/decryption
    Encryption,
    /// For key agreement/derivation
    KeyAgreement,
}

/// Handle to a cryptographic key stored inside a TEE enclave
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveKeyHandle {
    /// Unique key ID
    pub id: uuid::Uuid,
    /// Algorithm of the key
    pub algorithm: KeyAlgorithm,
    /// Public key (if applicable), None for symmetric keys
    pub public_key: Option<Vec<u8>>,
    /// Timestamp when key was created
    pub created_at: Timestamp,
    /// Optional attestation proving the key was generated in a TEE
    pub attestation: Option<AttestationReport>,
}
