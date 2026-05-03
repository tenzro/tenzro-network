//! Trusted Execution Environment (TEE) types for Tenzro Network
//!
//! This module defines types for TEE attestation, provider management,
//! and secure computation on the network.

use crate::primitives::{Address, Timestamp};
use serde::{Deserialize, Serialize};

/// Supported TEE vendors on Tenzro Network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub enum TeeVendor {
    /// Intel SGX (Software Guard Extensions)
    IntelSGX,
    /// Intel TDX (Trust Domain Extensions)
    IntelTdx,
    /// AMD SEV (Secure Encrypted Virtualization)
    AMDSEV,
    /// AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging)
    AmdSevSnp,
    /// ARM TrustZone
    ARMTrustZone,
    /// AWS Nitro Enclaves
    AWSNitro,
    /// AWS Nitro (alternative naming)
    AwsNitro,
    /// NVIDIA GPU Confidential Computing (H100/H200/Blackwell)
    NvidiaGpu,
    /// Generic/Other TEE implementation
    #[default]
    Generic,
}

impl TeeVendor {
    /// Returns the vendor name as a string
    pub fn as_str(&self) -> &str {
        match self {
            Self::IntelSGX => "Intel SGX",
            Self::IntelTdx => "Intel TDX",
            Self::AMDSEV => "AMD SEV",
            Self::AmdSevSnp => "AMD SEV-SNP",
            Self::ARMTrustZone => "ARM TrustZone",
            Self::AWSNitro => "AWS Nitro",
            Self::AwsNitro => "AWS Nitro",
            Self::NvidiaGpu => "NVIDIA GPU CC",
            Self::Generic => "Generic",
        }
    }
}

/// A TEE attestation report
///
/// Contains cryptographic evidence that code is running in a trusted
/// execution environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AttestationReport {
    /// Report ID
    pub id: uuid::Uuid,
    /// TEE vendor
    pub vendor: TeeVendor,
    /// Application-specific user data included in the report
    pub user_data: Vec<u8>,
    /// Raw attestation data
    pub attestation_data: Vec<u8>,
    /// Certificate chain for verification
    pub certificates: Vec<Vec<u8>>,
    /// Report timestamp
    pub timestamp: Timestamp,
    /// Additional vendor-specific metadata
    pub metadata: std::collections::HashMap<String, String>,
    /// Quote/evidence from the TEE    #[serde(default)]
    pub quote: Vec<u8>,
    /// Measurement/hash of the running code    #[serde(default)]
    pub measurement: Vec<u8>,
    /// Report signature    #[serde(default)]
    pub signature: Vec<u8>,
    /// Additional vendor-specific data    #[serde(default)]
    pub vendor_data: Vec<u8>,
}

impl Default for AttestationReport {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::nil(),
            vendor: TeeVendor::default(),
            user_data: Vec::new(),
            attestation_data: Vec::new(),
            certificates: Vec::new(),
            timestamp: Timestamp::default(),
            metadata: std::collections::HashMap::new(),
            quote: Vec::new(),
            measurement: Vec::new(),
            signature: Vec::new(),
            vendor_data: Vec::new(),
        }
    }
}

impl AttestationReport {
    /// Creates a new attestation report
    pub fn new(
        vendor: TeeVendor,
        attestation_data: Vec<u8>,
        quote: Vec<u8>,
        measurement: Vec<u8>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            vendor,
            user_data: Vec::new(),
            attestation_data,
            certificates: Vec::new(),
            timestamp: Timestamp::now(),
            metadata: std::collections::HashMap::new(),
            quote,
            measurement,
            signature: Vec::new(),
            vendor_data: Vec::new(),
        }
    }

    /// Adds a signature to the report
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }

    /// Adds vendor-specific data
    pub fn with_vendor_data(mut self, data: Vec<u8>) -> Self {
        self.vendor_data = data;
        self
    }
}

/// A measurement from a TEE attestation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Measurement {
    /// Index of the measurement register (e.g., PCR index, RTMR index)
    #[serde(default)]
    pub index: u32,
    /// Hash algorithm used (e.g., "SHA384", "SHA256")
    #[serde(default)]
    pub algorithm: String,
    /// Measurement value (hash)
    #[serde(default)]
    pub value: Vec<u8>,
    /// Measurement type/register    #[serde(default)]
    pub register: String,
    /// Measurement description    #[serde(default)]
    pub description: Option<String>,
}

/// Result of attestation verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationResult {
    /// Whether the attestation is valid
    #[serde(default)]
    pub valid: bool,
    /// Verification timestamp
    #[serde(default)]
    pub verified_at: Timestamp,
    /// TEE vendor
    #[serde(default)]
    pub vendor: TeeVendor,
    /// TCB (Trusted Computing Base) version string
    #[serde(default)]
    pub tcb_version: String,
    /// Measurements extracted from the attestation
    #[serde(default)]
    pub measurements: Vec<Measurement>,
    /// Whether the certificate chain is valid
    #[serde(default)]
    pub cert_chain_valid: bool,
    /// Additional verification details
    #[serde(default)]
    pub details: std::collections::HashMap<String, String>,
    /// Code measurement that was verified    #[serde(default)]
    pub verified_measurement: Vec<u8>,
    /// Error message if verification failed    #[serde(default)]
    pub error: Option<String>,
    /// Additional verification metadata    #[serde(default)]
    pub metadata: AttestationMetadata,
}

impl Default for AttestationResult {
    fn default() -> Self {
        Self {
            valid: false,
            verified_at: Timestamp::now(),
            vendor: TeeVendor::Generic,
            tcb_version: String::new(),
            measurements: Vec::new(),
            cert_chain_valid: false,
            details: std::collections::HashMap::new(),
            verified_measurement: Vec::new(),
            error: None,
            metadata: AttestationMetadata::default(),
        }
    }
}

impl AttestationResult {
    /// Creates a successful attestation result
    pub fn success(vendor: TeeVendor, measurement: Vec<u8>) -> Self {
        Self {
            valid: true,
            verified_at: Timestamp::now(),
            vendor,
            tcb_version: String::new(),
            measurements: Vec::new(),
            cert_chain_valid: true,
            details: std::collections::HashMap::new(),
            verified_measurement: measurement,
            error: None,
            metadata: AttestationMetadata::default(),
        }
    }

    /// Creates a failed attestation result
    pub fn failure(vendor: TeeVendor, error: String) -> Self {
        Self {
            valid: false,
            verified_at: Timestamp::now(),
            vendor,
            tcb_version: String::new(),
            measurements: Vec::new(),
            cert_chain_valid: false,
            details: std::collections::HashMap::new(),
            verified_measurement: Vec::new(),
            error: Some(error),
            metadata: AttestationMetadata::default(),
        }
    }
}

/// Additional metadata for attestation verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AttestationMetadata {
    /// TEE firmware version
    pub firmware_version: Option<String>,
    /// Security patch level
    pub security_patch_level: Option<String>,
    /// Debug mode enabled
    pub debug_mode: bool,
    /// Production environment
    pub production: bool,
}

/// TEE provider capacity information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeCapacity {
    /// Maximum concurrent jobs
    pub max_concurrent_jobs: u32,
    /// Current active jobs
    pub active_jobs: u32,
    /// Maximum concurrent operations
    pub max_operations: u32,
    /// Current active operations
    pub current_operations: u32,
    /// Total memory available (bytes)
    pub total_memory: u64,
    /// Available memory (bytes)
    pub available_memory: u64,
    /// Total CPU cores
    pub total_cpu_cores: u32,
    /// Available CPU cores
    pub available_cpu_cores: u32,
    /// Supported TEE vendors
    pub supported_vendors: Vec<TeeVendor>,
}

impl TeeCapacity {
    /// Creates a new TEE capacity
    pub fn new(max_concurrent_jobs: u32, total_memory: u64, total_cpu_cores: u32) -> Self {
        Self {
            max_concurrent_jobs,
            active_jobs: 0,
            max_operations: max_concurrent_jobs,
            current_operations: 0,
            total_memory,
            available_memory: total_memory,
            total_cpu_cores,
            available_cpu_cores: total_cpu_cores,
            supported_vendors: Vec::new(),
        }
    }

    /// Checks if capacity is available for a new job
    pub fn has_capacity(&self) -> bool {
        self.active_jobs < self.max_concurrent_jobs
            && self.available_memory > 0
            && self.available_cpu_cores > 0
    }

    /// Returns the utilization percentage (0-100)
    pub fn utilization(&self) -> u8 {
        if self.max_concurrent_jobs == 0 {
            0
        } else {
            ((self.active_jobs as f64 / self.max_concurrent_jobs as f64) * 100.0) as u8
        }
    }
}

/// Information about a TEE provider
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeProviderInfo {
    /// Provider ID
    pub id: uuid::Uuid,
    /// TEE vendor
    pub vendor: TeeVendor,
    /// Provider's network address
    pub address: String,
    /// Provider's public key
    pub public_key: Vec<u8>,
    /// Provider's attestation report
    pub attestation: AttestationReport,
    /// Registration timestamp
    pub registered_at: Timestamp,
    /// Last heartbeat timestamp
    pub last_heartbeat: Timestamp,
    /// Provider capacity
    pub capacity: TeeCapacity,
    /// Provider status
    pub status: TeeProviderStatus,
    /// Attestation verification result    #[serde(default)]
    pub attestation_result: Option<AttestationResult>,
    /// Pricing configuration    #[serde(default)]
    pub pricing: TeeProviderPricing,
    /// Provider reputation    #[serde(default)]
    pub reputation: u64,
    /// Total jobs completed    #[serde(default)]
    pub total_jobs_completed: u64,
    /// Last attestation update    #[serde(default)]
    pub last_attestation_update: Timestamp,
}

impl TeeProviderInfo {
    /// Creates a new TEE provider info
    pub fn new(address: Address, attestation: AttestationReport, capacity: TeeCapacity) -> Self {
        let now = Timestamp::now();
        Self {
            id: uuid::Uuid::new_v4(),
            vendor: attestation.vendor,
            address: address.to_base58(),
            public_key: Vec::new(),
            attestation,
            registered_at: now,
            last_heartbeat: now,
            capacity,
            status: TeeProviderStatus::Pending,
            attestation_result: None,
            pricing: TeeProviderPricing::default(),
            reputation: 0,
            total_jobs_completed: 0,
            last_attestation_update: now,
        }
    }

    /// Checks if the provider is active and has capacity
    pub fn is_available(&self) -> bool {
        self.status == TeeProviderStatus::Active && self.capacity.has_capacity()
    }
}

/// TEE provider pricing configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeProviderPricing {
    /// Price per compute unit (in smallest TNZO unit)
    pub price_per_compute_unit: u64,
    /// Price per memory GB-hour (in smallest TNZO unit)
    pub price_per_memory_gb_hour: u64,
    /// Minimum job price (in smallest TNZO unit)
    pub minimum_job_price: u64,
}

impl Default for TeeProviderPricing {
    fn default() -> Self {
        Self {
            price_per_compute_unit: 1000,
            price_per_memory_gb_hour: 5000,
            minimum_job_price: 100,
        }
    }
}

/// TEE provider operational status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TeeProviderStatus {
    /// Registration pending verification
    Pending,
    /// Active and accepting jobs
    Active,
    /// Temporarily inactive
    Inactive,
    /// Draining existing jobs, not accepting new ones
    Draining,
    /// Offline (no recent heartbeat)
    Offline,
    /// Untrusted (failed attestation verification)
    Untrusted,
    /// Suspended due to violations
    Suspended,
    /// Attestation expired, needs renewal
    AttestationExpired,
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
