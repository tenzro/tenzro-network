//! Cross-VM token types and decimal conversion utilities
//!
//! Provides types for representing tokens across EVM, SVM, and DAML VMs,
//! including safe decimal conversion between native 18-decimal and SPL 9-decimal.

use serde::{Deserialize, Serialize};
use std::fmt;

/// VM types for token addressing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenVmType {
    /// Native Tenzro L1 token (18 decimals)
    Native,
    /// EVM ERC-20 representation (configurable decimals, typically 18)
    Evm,
    /// SVM SPL token representation (9 decimals max due to u64 constraint)
    Svm,
    /// DAML CIP-56 token representation (arbitrary precision Decimal)
    Daml,
    /// Tempo L1 TIP-20 stablecoin representation (Stripe + Paradigm chain, EIP-155 EVM)
    TempoTip20,
}

impl fmt::Display for TokenVmType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenVmType::Native => write!(f, "native"),
            TokenVmType::Evm => write!(f, "evm"),
            TokenVmType::Svm => write!(f, "svm"),
            TokenVmType::Daml => write!(f, "daml"),
            TokenVmType::TempoTip20 => write!(f, "tempo-tip20"),
        }
    }
}

/// Cross-VM address mapping for a token
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VmAddresses {
    /// ERC-20 contract address (20 bytes) on EVM
    pub evm: Option<[u8; 20]>,
    /// SPL mint address (32 bytes) on SVM
    pub svm: Option<[u8; 32]>,
    /// DAML template identifier on Canton
    pub daml_template_id: Option<String>,
    /// Native token address (for TNZO only)
    pub native: Option<[u8; 32]>,
    /// Tempo L1 TIP-20 contract address (20 bytes, EIP-155 EVM at chain_id 42431)
    pub tempo: Option<[u8; 20]>,
}

impl VmAddresses {
    /// Returns true if the token has an address on the given VM
    pub fn has_vm(&self, vm: TokenVmType) -> bool {
        match vm {
            TokenVmType::Native => self.native.is_some(),
            TokenVmType::Evm => self.evm.is_some(),
            TokenVmType::Svm => self.svm.is_some(),
            TokenVmType::Daml => self.daml_template_id.is_some(),
            TokenVmType::TempoTip20 => self.tempo.is_some(),
        }
    }

    /// Returns the Tempo TIP-20 address as a hex string (0x-prefixed)
    pub fn tempo_hex(&self) -> Option<String> {
        self.tempo.map(|addr| format!("0x{}", hex::encode(addr)))
    }

    /// Returns the EVM address as a hex string (0x-prefixed)
    pub fn evm_hex(&self) -> Option<String> {
        self.evm.map(|addr| format!("0x{}", hex::encode(addr)))
    }

    /// Returns the SVM mint as a hex string
    pub fn svm_hex(&self) -> Option<String> {
        self.svm.map(hex::encode)
    }
}

/// Token permissions flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPermissions {
    /// Whether new tokens can be minted after creation
    pub mintable: bool,
    /// Whether tokens can be burned by holders
    pub burnable: bool,
    /// Whether transfers can be paused by the creator
    pub pausable: bool,
    /// Whether individual accounts can be frozen
    pub freezable: bool,
    /// Whether the token is currently paused
    pub paused: bool,
}

impl Default for TokenPermissions {
    fn default() -> Self {
        Self {
            mintable: false,
            burnable: true,
            pausable: false,
            freezable: false,
            paused: false,
        }
    }
}

/// Token metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenMetadata {
    /// Token description
    pub description: Option<String>,
    /// Token icon URI
    pub icon_uri: Option<String>,
    /// Token website
    pub website: Option<String>,
    /// Additional key-value metadata
    pub extra: std::collections::HashMap<String, String>,
}

/// Unique token identifier (32 bytes, SHA-256 of creator + nonce)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenId(pub [u8; 32]);

impl TokenId {
    /// Creates a new TokenId from a byte array
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Computes a TokenId from creator address and nonce
    pub fn compute(creator: &[u8], nonce: u64) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"tenzro-token-id:");
        hasher.update(creator);
        hasher.update(nonce.to_le_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Returns the token ID as hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The well-known token ID for TNZO (all zeros except first byte = 0x01)
    pub fn tnzo() -> Self {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x01;
        Self(bytes)
    }
}

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Token type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    /// Native L1 token (TNZO)
    Native,
    /// User-created ERC-20 on EVM
    Erc20,
    /// User-created SPL token on SVM
    Spl,
    /// Enterprise CIP-56 token on Canton/DAML
    Cip56,
    /// Cross-VM token (exists on multiple VMs via pointer contracts)
    CrossVm,
}

/// Full token definition stored in the registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenDefinition {
    /// Unique token identifier
    pub token_id: TokenId,
    /// Human-readable name
    pub name: String,
    /// Trading symbol
    pub symbol: String,
    /// Decimal places (18 for EVM, 9 for SPL)
    pub decimals: u8,
    /// Total supply in native (18-decimal) units
    pub total_supply: u128,
    /// Maximum supply (None = unlimited if mintable)
    pub max_supply: Option<u128>,
    /// Creator address (32 bytes)
    pub creator: [u8; 32],
    /// Token type
    pub token_type: TokenType,
    /// Cross-VM address mapping
    pub vm_addresses: VmAddresses,
    /// Permission flags
    pub permissions: TokenPermissions,
    /// Creation timestamp (Unix seconds)
    pub created_at: u64,
    /// Token metadata
    pub metadata: TokenMetadata,
}

/// Decimal conversion constants
pub const NATIVE_DECIMALS: u8 = 18;
pub const SPL_DECIMALS: u8 = 9;
pub const NATIVE_UNIT: u128 = 1_000_000_000_000_000_000; // 10^18
pub const SPL_UNIT: u64 = 1_000_000_000; // 10^9
pub const DECIMAL_SHIFT: u128 = 1_000_000_000; // 10^9 (difference between 18 and 9)

/// Converts a native 18-decimal amount to SPL 9-decimal amount.
/// Truncates (does not round) to prevent inflation from rounding errors.
///
/// # Returns
/// `None` if the result exceeds u64::MAX (overflow)
pub fn native_to_spl(native_amount: u128) -> Option<u64> {
    let spl_amount = native_amount / DECIMAL_SHIFT;
    if spl_amount > u64::MAX as u128 {
        None
    } else {
        Some(spl_amount as u64)
    }
}

/// Converts an SPL 9-decimal amount to native 18-decimal amount.
/// This is lossless since we're scaling up.
pub fn spl_to_native(spl_amount: u64) -> u128 {
    (spl_amount as u128) * DECIMAL_SHIFT
}

/// Computes the truncation dust lost when converting native -> SPL -> native
pub fn truncation_dust(native_amount: u128) -> u128 {
    native_amount % DECIMAL_SHIFT
}

/// Cross-VM transfer request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossVmTransfer {
    /// Token being transferred
    pub token_id: TokenId,
    /// Source VM
    pub from_vm: TokenVmType,
    /// Destination VM
    pub to_vm: TokenVmType,
    /// Sender address (variable length)
    pub from_address: Vec<u8>,
    /// Recipient address (variable length)
    pub to_address: Vec<u8>,
    /// Amount in native (18-decimal) units
    pub amount: u128,
    /// Nonce for replay protection
    pub nonce: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_to_spl_conversion() {
        // 1 TNZO = 10^18 native = 10^9 SPL
        assert_eq!(native_to_spl(NATIVE_UNIT), Some(SPL_UNIT));

        // 0.5 TNZO
        let half_tnzo = NATIVE_UNIT / 2;
        assert_eq!(native_to_spl(half_tnzo), Some(SPL_UNIT / 2));

        // Very small amount (less than 1 SPL unit)
        assert_eq!(native_to_spl(999_999_999), Some(0)); // truncated to 0

        // Exact boundary: 1 SPL lamport = 10^9 native
        assert_eq!(native_to_spl(DECIMAL_SHIFT), Some(1));
    }

    #[test]
    fn test_spl_to_native_conversion() {
        assert_eq!(spl_to_native(SPL_UNIT), NATIVE_UNIT);
        assert_eq!(spl_to_native(1), DECIMAL_SHIFT);
        assert_eq!(spl_to_native(0), 0);
    }

    #[test]
    fn test_roundtrip_conversion() {
        let original = 12_345_678_901_234_567_890u128; // ~12.3 TNZO
        let spl = native_to_spl(original).unwrap();
        let back = spl_to_native(spl);
        let dust = truncation_dust(original);

        // Roundtrip loses the dust
        assert_eq!(back + dust, original);
        // Dust is always less than DECIMAL_SHIFT
        assert!(dust < DECIMAL_SHIFT);
    }

    #[test]
    fn test_spl_overflow_protection() {
        // u64::MAX * DECIMAL_SHIFT would exceed u64 capacity
        let huge = u128::MAX;
        assert_eq!(native_to_spl(huge), None);
    }

    #[test]
    fn test_token_id_computation() {
        let creator = [42u8; 32];
        let id1 = TokenId::compute(&creator, 0);
        let id2 = TokenId::compute(&creator, 1);
        assert_ne!(id1, id2); // Different nonces produce different IDs
    }

    #[test]
    fn test_token_id_tnzo() {
        let tnzo = TokenId::tnzo();
        assert_eq!(tnzo.0[0], 0x01);
        assert!(tnzo.0[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_vm_addresses_has_vm() {
        let mut addrs = VmAddresses::default();
        assert!(!addrs.has_vm(TokenVmType::Evm));
        addrs.evm = Some([0u8; 20]);
        assert!(addrs.has_vm(TokenVmType::Evm));
    }

    #[test]
    fn test_token_permissions_default() {
        let perms = TokenPermissions::default();
        assert!(!perms.mintable);
        assert!(perms.burnable);
        assert!(!perms.pausable);
        assert!(!perms.freezable);
        assert!(!perms.paused);
    }
}
