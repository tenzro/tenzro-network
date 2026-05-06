//! ERC-4337 Account Abstraction for Tenzro Network (EntryPoint v0.8)
//!
//! This module implements the ERC-4337 standard (EntryPoint v0.8) for account abstraction,
//! enabling smart contract wallets with advanced features for AI agents and users on
//! Tenzro Network.
//!
//! # Overview
//!
//! Account abstraction separates the concept of an account from a private key, allowing
//! smart contracts to act as accounts. This enables:
//!
//! - **Gasless Transactions**: Paymasters can sponsor gas fees for users
//! - **Social Recovery**: Multi-signature recovery mechanisms without seed phrases
//! - **Session Keys**: Temporary keys with limited permissions for AI agents
//! - **Batched Operations**: Execute multiple operations in a single transaction
//! - **Spending Limits**: Programmable spending controls per token/time period
//! - **Custom Validation Logic**: Flexible signature schemes and authentication
//!
//! # Architecture
//!
//! The implementation follows the ERC-4337 EntryPoint v0.8 specification with these
//! core components:
//!
//! - **UserOperation**: A pseudo-transaction with split factory/paymaster fields (v0.8)
//! - **PackedUserOperation**: Wire-format with combined fields for calldata efficiency
//! - **EntryPoint**: The singleton contract that processes UserOperations (with EIP-712 hashing)
//! - **Account Factory**: Creates deterministic smart contract wallets
//! - **Paymaster**: Optional contract that sponsors gas fees
//! - **Bundler**: Off-chain service that bundles UserOps into transactions
//!
//! # v0.8 Changes from v0.6
//!
//! - `init_code` split into `factory` + `factory_data`
//! - `paymaster_and_data` split into `paymaster` + `paymaster_verification_gas_limit`
//!   + `paymaster_post_op_gas_limit` + `paymaster_data`
//! - UserOperation hash uses EIP-712 typed data hashing with keccak256
//! - EntryPoint carries `chain_id` for EIP-712 domain separator
//! - Gas penalty waived when unused gas is below 40,000
//!
//! # AI Agent Integration
//!
//! Tenzro Network's account abstraction is designed for AI agents:
//!
//! - Session keys allow AI agents to operate with limited permissions
//! - Spending limits prevent runaway costs from AI operations
//! - Social recovery enables human oversight and intervention
//! - Batching optimizes multi-step AI workflows
//!
//! # Example
//!
//! ```rust,no_run
//! use tenzro_vm::account_abstraction::{EntryPoint, AccountFactory, UserOperation, AccountModule};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create entry point with chain ID for EIP-712
//! let entry_point = EntryPoint::new(vec![0x01; 20]).with_chain_id(1337);
//!
//! // Create account factory
//! let factory = AccountFactory::new(vec![0x02; 20]);
//!
//! // Deploy a smart account for an AI agent
//! let owner = vec![0x03; 20];
//! let mut account = factory.create_account(owner.clone(), 1);
//!
//! // Add session key module for AI agent
//! account.modules.push(AccountModule::SessionKey {
//!     key: vec![0x04; 20],
//!     expires_at: 1735689600, // Expires in 24 hours
//!     permissions: vec!["transfer".to_string(), "approve".to_string()],
//! });
//!
//! // Add spending limit for safety
//! account.modules.push(AccountModule::SpendingLimit {
//!     token: vec![0x05; 20],
//!     limit: 1000_000_000_000_000_000, // 1 token with 18 decimals
//!     period_seconds: 86400, // Daily limit
//! });
//!
//! // Create and validate a user operation (v0.8 split fields)
//! let user_op = UserOperation {
//!     sender: account.address.clone(),
//!     nonce: entry_point.get_nonce(&account.address),
//!     factory: vec![],
//!     factory_data: vec![],
//!     call_data: vec![0x42; 32],
//!     call_gas_limit: 100_000,
//!     verification_gas_limit: 50_000,
//!     pre_verification_gas: 21_000,
//!     max_fee_per_gas: 1_000_000_000,
//!     max_priority_fee_per_gas: 1_000_000,
//!     paymaster: vec![],
//!     paymaster_verification_gas_limit: 0,
//!     paymaster_post_op_gas_limit: 0,
//!     paymaster_data: vec![],
//!     signature: vec![0x05; 65],
//! };
//!
//! entry_point.validate_user_op(&user_op)?;
//!
//! // Process bundle of operations
//! let receipts = entry_point.handle_ops(vec![user_op]);
//! # Ok(())
//! # }
//! ```

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use tracing::info;

use tenzro_crypto::hash::keccak256;

use crate::error::VmError;
use crate::traits::VmState;

/// Gas penalty threshold for v0.8: if unused gas is below this value, no penalty applies.
const GAS_PENALTY_THRESHOLD: u64 = 40_000;

/// Error types for account abstraction operations
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
pub enum AccountAbstractionError {
    /// Invalid user operation
    #[error("Invalid user operation: {0}")]
    InvalidUserOp(String),

    /// Insufficient balance for operation
    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u128, available: u128 },

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Invalid nonce
    #[error("Invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },

    /// Paymaster error
    #[error("Paymaster error: {0}")]
    PaymasterError(String),

    /// Factory error
    #[error("Factory error: {0}")]
    FactoryError(String),

    /// Simulation failed
    #[error("Simulation failed: {0}")]
    SimulationFailed(String),

    /// Bundle error
    #[error("Bundle error: {0}")]
    BundleError(String),
}

/// ERC-4337 User Operation (EntryPoint v0.8)
///
/// A UserOperation is a pseudo-transaction that represents the user's intent.
/// It is sent to the bundler off-chain, which then bundles multiple UserOps
/// into a single transaction to the EntryPoint contract.
///
/// In v0.8, the `init_code` field from v0.6 is split into `factory` + `factory_data`,
/// and `paymaster_and_data` is split into `paymaster` + `paymaster_verification_gas_limit`
/// + `paymaster_post_op_gas_limit` + `paymaster_data`. The hash uses EIP-712 typed data
///   hashing with keccak256.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserOperation {
    /// The account making the operation
    pub sender: Vec<u8>,

    /// Anti-replay parameter; also used as the salt for first-time account creation
    pub nonce: u64,

    /// The factory address for deploying the account (empty if account already deployed).
    /// In v0.6 this was combined with factory_data as `init_code`.
    pub factory: Vec<u8>,

    /// Calldata passed to the factory for account deployment (empty if no deployment).
    /// In v0.6 this was combined with factory address as `init_code`.
    pub factory_data: Vec<u8>,

    /// The data to pass to the sender during the main execution call
    pub call_data: Vec<u8>,

    /// The amount of gas to allocate for the main execution call
    pub call_gas_limit: u64,

    /// The amount of gas to allocate for the verification step
    pub verification_gas_limit: u64,

    /// Extra gas to pay the bundler (independent of callGasLimit and verificationGasLimit)
    pub pre_verification_gas: u64,

    /// Maximum fee per gas (similar to EIP-1559 max_fee_per_gas)
    pub max_fee_per_gas: u128,

    /// Maximum priority fee per gas (similar to EIP-1559 max_priority_fee_per_gas)
    pub max_priority_fee_per_gas: u128,

    /// Address of the paymaster sponsoring the transaction (empty if self-sponsored).
    /// In v0.6 this was combined with gas limits and data as `paymaster_and_data`.
    pub paymaster: Vec<u8>,

    /// Gas limit for paymaster verification (v0.8 field, was embedded in paymaster_and_data in v0.6)
    pub paymaster_verification_gas_limit: u64,

    /// Gas limit for paymaster postOp (v0.8 field, was embedded in paymaster_and_data in v0.6)
    pub paymaster_post_op_gas_limit: u64,

    /// Extra data for the paymaster (v0.8 field, was embedded in paymaster_and_data in v0.6)
    pub paymaster_data: Vec<u8>,

    /// Signature over the entire UserOperation (except signature itself)
    pub signature: Vec<u8>,
}

/// EIP-712 type hash for UserOperation v0.8
///
/// keccak256("UserOperation(address sender,uint256 nonce,address factory,bytes factoryData,bytes callData,uint256 callGasLimit,uint256 verificationGasLimit,uint256 preVerificationGas,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,address paymaster,uint256 paymasterVerificationGasLimit,uint256 paymasterPostOpGasLimit,bytes paymasterData)")
fn user_operation_type_hash() -> [u8; 32] {
    let type_string = "UserOperation(address sender,uint256 nonce,address factory,bytes factoryData,bytes callData,uint256 callGasLimit,uint256 verificationGasLimit,uint256 preVerificationGas,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,address paymaster,uint256 paymasterVerificationGasLimit,uint256 paymasterPostOpGasLimit,bytes paymasterData)";
    let hash = keccak256(type_string.as_bytes());
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

/// EIP-712 domain separator for EntryPoint v0.8
///
/// keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
fn eip712_domain_separator(chain_id: u64, entry_point_address: &[u8]) -> [u8; 32] {
    let domain_type_hash = {
        let h = keccak256(
            b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        let mut buf = [0u8; 32];
        buf.copy_from_slice(h.as_bytes());
        buf
    };

    let name_hash = {
        let h = keccak256(b"EntryPoint");
        let mut buf = [0u8; 32];
        buf.copy_from_slice(h.as_bytes());
        buf
    };

    let version_hash = {
        let h = keccak256(b"0.8");
        let mut buf = [0u8; 32];
        buf.copy_from_slice(h.as_bytes());
        buf
    };

    // Encode chain_id as uint256 (32 bytes, big-endian)
    let mut chain_id_bytes = [0u8; 32];
    chain_id_bytes[24..32].copy_from_slice(&chain_id.to_be_bytes());

    // Encode address as bytes32 (left-padded with zeros)
    let mut address_bytes = [0u8; 32];
    let addr_len = entry_point_address.len().min(20);
    address_bytes[32 - addr_len..32].copy_from_slice(&entry_point_address[..addr_len]);

    // domain_separator = keccak256(domain_type_hash || name_hash || version_hash || chain_id || address)
    let mut data = Vec::with_capacity(160);
    data.extend_from_slice(&domain_type_hash);
    data.extend_from_slice(&name_hash);
    data.extend_from_slice(&version_hash);
    data.extend_from_slice(&chain_id_bytes);
    data.extend_from_slice(&address_bytes);

    let h = keccak256(&data);
    let mut result = [0u8; 32];
    result.copy_from_slice(h.as_bytes());
    result
}

/// Encode a byte slice as its keccak256 hash (for EIP-712 `bytes` encoding)
fn keccak256_bytes(data: &[u8]) -> [u8; 32] {
    let h = keccak256(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(h.as_bytes());
    result
}

/// Encode a u64 as a 32-byte big-endian uint256
fn encode_u64_as_uint256(val: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[24..32].copy_from_slice(&val.to_be_bytes());
    buf
}

/// Encode a u128 as a 32-byte big-endian uint256
fn encode_u128_as_uint256(val: u128) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[16..32].copy_from_slice(&val.to_be_bytes());
    buf
}

/// Encode an address (Vec<u8>) as a 32-byte left-padded bytes32
fn encode_address(addr: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let len = addr.len().min(20);
    if len > 0 {
        buf[32 - len..32].copy_from_slice(&addr[..len]);
    }
    buf
}

impl UserOperation {
    /// Calculate the EIP-712 struct hash of this UserOperation.
    ///
    /// This is `keccak256(typeHash || encoded_fields...)` where each field is
    /// ABI-encoded per EIP-712 rules: addresses as bytes32, dynamic bytes as
    /// their keccak256 hash, integers as uint256.
    fn struct_hash(&self) -> [u8; 32] {
        let type_hash = user_operation_type_hash();

        // Build the encoded data: type_hash || field1 || field2 || ...
        // Each field is 32 bytes per EIP-712 encoding.
        let mut data = Vec::with_capacity(32 * 15); // type_hash + 14 fields
        data.extend_from_slice(&type_hash);
        data.extend_from_slice(&encode_address(&self.sender));
        data.extend_from_slice(&encode_u64_as_uint256(self.nonce));
        data.extend_from_slice(&encode_address(&self.factory));
        data.extend_from_slice(&keccak256_bytes(&self.factory_data));
        data.extend_from_slice(&keccak256_bytes(&self.call_data));
        data.extend_from_slice(&encode_u64_as_uint256(self.call_gas_limit));
        data.extend_from_slice(&encode_u64_as_uint256(self.verification_gas_limit));
        data.extend_from_slice(&encode_u64_as_uint256(self.pre_verification_gas));
        data.extend_from_slice(&encode_u128_as_uint256(self.max_fee_per_gas));
        data.extend_from_slice(&encode_u128_as_uint256(self.max_priority_fee_per_gas));
        data.extend_from_slice(&encode_address(&self.paymaster));
        data.extend_from_slice(&encode_u64_as_uint256(self.paymaster_verification_gas_limit));
        data.extend_from_slice(&encode_u64_as_uint256(self.paymaster_post_op_gas_limit));
        data.extend_from_slice(&keccak256_bytes(&self.paymaster_data));

        let h = keccak256(&data);
        let mut result = [0u8; 32];
        result.copy_from_slice(h.as_bytes());
        result
    }

    /// Calculate the EIP-712 hash of this UserOperation for signing.
    ///
    /// Returns `keccak256("\x19\x01" || domainSeparator || structHash)`.
    /// The domain separator is computed from the EntryPoint address and chain ID.
    pub fn hash(&self, chain_id: u64, entry_point_address: &[u8]) -> Vec<u8> {
        let domain_sep = eip712_domain_separator(chain_id, entry_point_address);
        let struct_hash = self.struct_hash();

        let mut data = Vec::with_capacity(66);
        data.push(0x19);
        data.push(0x01);
        data.extend_from_slice(&domain_sep);
        data.extend_from_slice(&struct_hash);

        keccak256(&data).as_bytes().to_vec()
    }

    /// Calculate total gas limit for this operation.
    ///
    /// In v0.8, this includes paymaster gas limits when a paymaster is present.
    pub fn total_gas_limit(&self) -> u64 {
        let mut total = self.call_gas_limit
            .saturating_add(self.verification_gas_limit)
            .saturating_add(self.pre_verification_gas);

        if self.has_paymaster() {
            total = total
                .saturating_add(self.paymaster_verification_gas_limit)
                .saturating_add(self.paymaster_post_op_gas_limit);
        }

        total
    }

    /// Calculate maximum gas cost for this operation
    pub fn max_gas_cost(&self) -> u128 {
        self.total_gas_limit() as u128 * self.max_fee_per_gas
    }

    /// Check if this operation has a paymaster
    pub fn has_paymaster(&self) -> bool {
        !self.paymaster.is_empty()
    }

    /// Check if this is an account creation operation
    pub fn is_account_creation(&self) -> bool {
        !self.factory.is_empty()
    }

    /// Convert this UserOperation to a [`PackedUserOperation`] for on-chain calldata
    /// efficiency. The packed format combines factory + factory_data into `init_code`
    /// and paymaster fields into `paymaster_and_data`, matching the v0.6 wire format.
    pub fn to_packed(&self) -> PackedUserOperation {
        let init_code = if self.factory.is_empty() {
            vec![]
        } else {
            let mut ic = self.factory.clone();
            ic.extend_from_slice(&self.factory_data);
            ic
        };

        let paymaster_and_data = if self.paymaster.is_empty() {
            vec![]
        } else {
            let mut pd = self.paymaster.clone();
            pd.extend_from_slice(&self.paymaster_verification_gas_limit.to_be_bytes());
            pd.extend_from_slice(&self.paymaster_post_op_gas_limit.to_be_bytes());
            pd.extend_from_slice(&self.paymaster_data);
            pd
        };

        PackedUserOperation {
            sender: self.sender.clone(),
            nonce: self.nonce,
            init_code,
            call_data: self.call_data.clone(),
            call_gas_limit: self.call_gas_limit,
            verification_gas_limit: self.verification_gas_limit,
            pre_verification_gas: self.pre_verification_gas,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            paymaster_and_data,
            signature: self.signature.clone(),
        }
    }
}

/// Packed (v0.6-style) UserOperation for on-chain calldata efficiency.
///
/// This struct uses the combined `init_code` and `paymaster_and_data` fields
/// from v0.6, which is more compact on-chain. Use [`PackedUserOperation::to_user_op`]
/// to convert to the structured [`UserOperation`] for validation and hashing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PackedUserOperation {
    /// The account making the operation
    pub sender: Vec<u8>,

    /// Anti-replay parameter
    pub nonce: u64,

    /// Combined factory address (first 20 bytes) + factory calldata
    pub init_code: Vec<u8>,

    /// The data to pass to the sender during the main execution call
    pub call_data: Vec<u8>,

    /// The amount of gas to allocate for the main execution call
    pub call_gas_limit: u64,

    /// The amount of gas to allocate for the verification step
    pub verification_gas_limit: u64,

    /// Extra gas to pay the bundler
    pub pre_verification_gas: u64,

    /// Maximum fee per gas
    pub max_fee_per_gas: u128,

    /// Maximum priority fee per gas
    pub max_priority_fee_per_gas: u128,

    /// Combined paymaster address (20 bytes) + verification gas limit (8 bytes)
    /// + post-op gas limit (8 bytes) + paymaster data
    pub paymaster_and_data: Vec<u8>,

    /// Signature over the UserOperation
    pub signature: Vec<u8>,
}

impl PackedUserOperation {
    /// Unpack into a structured [`UserOperation`] (v0.8 format).
    ///
    /// - `init_code`: first 20 bytes = factory address, remainder = factory_data
    /// - `paymaster_and_data`: first 20 bytes = paymaster address, next 8 bytes =
    ///   paymaster_verification_gas_limit (big-endian u64), next 8 bytes =
    ///   paymaster_post_op_gas_limit (big-endian u64), remainder = paymaster_data
    pub fn to_user_op(&self) -> UserOperation {
        let (factory, factory_data) = if self.init_code.len() >= 20 {
            (self.init_code[..20].to_vec(), self.init_code[20..].to_vec())
        } else {
            (vec![], vec![])
        };

        let (paymaster, pm_ver_gas, pm_post_gas, paymaster_data) =
            if self.paymaster_and_data.len() >= 36 {
                let pm = self.paymaster_and_data[..20].to_vec();
                let ver_gas = u64::from_be_bytes(
                    self.paymaster_and_data[20..28].try_into().unwrap_or([0u8; 8]),
                );
                let post_gas = u64::from_be_bytes(
                    self.paymaster_and_data[28..36].try_into().unwrap_or([0u8; 8]),
                );
                let data = self.paymaster_and_data[36..].to_vec();
                (pm, ver_gas, post_gas, data)
            } else {
                (vec![], 0, 0, vec![])
            };

        UserOperation {
            sender: self.sender.clone(),
            nonce: self.nonce,
            factory,
            factory_data,
            call_data: self.call_data.clone(),
            call_gas_limit: self.call_gas_limit,
            verification_gas_limit: self.verification_gas_limit,
            pre_verification_gas: self.pre_verification_gas,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            paymaster,
            paymaster_verification_gas_limit: pm_ver_gas,
            paymaster_post_op_gas_limit: pm_post_gas,
            paymaster_data,
            signature: self.signature.clone(),
        }
    }
}

/// Result of simulating a UserOperation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    /// Whether the operation is valid
    pub valid: bool,

    /// Gas used in the pre-operation phase
    pub pre_op_gas: u64,

    /// Amount paid for the operation
    pub paid: u128,

    /// Validation data (implementation-specific)
    pub validation_data: Vec<u8>,
}

/// Receipt for a processed UserOperation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOpReceipt {
    /// Hash of the UserOperation
    pub user_op_hash: Vec<u8>,

    /// Whether the operation succeeded
    pub success: bool,

    /// Actual gas used
    pub gas_used: u64,

    /// Actual gas cost paid
    pub actual_gas_cost: u128,

    /// Logs emitted during execution
    pub logs: Vec<Vec<u8>>,
}

/// The ERC-4337 EntryPoint contract (v0.8)
///
/// The EntryPoint is a singleton contract that processes UserOperations.
/// All UserOps go through the EntryPoint, which handles validation, execution,
/// and payment. In v0.8, the EntryPoint carries a `chain_id` for EIP-712
/// domain separator computation and uses the 40,000 gas penalty threshold.
#[derive(Debug)]
pub struct EntryPoint {
    /// EntryPoint contract address
    pub address: Vec<u8>,

    /// Chain ID for EIP-712 domain separator
    pub chain_id: u64,

    /// Supported account factory addresses
    pub supported_account_factories: Vec<Vec<u8>>,

    /// Nonces for each account
    pub nonces: DashMap<Vec<u8>, u64>,

    /// Deposits for each account (for gas payment)
    pub deposits: DashMap<Vec<u8>, u128>,

    /// Total operations processed
    pub total_ops_processed: AtomicU64,
}

impl EntryPoint {
    /// Create a new EntryPoint with default chain_id (1337)
    pub fn new(address: Vec<u8>) -> Self {
        Self {
            address,
            chain_id: 1337,
            supported_account_factories: Vec::new(),
            nonces: DashMap::new(),
            deposits: DashMap::new(),
            total_ops_processed: AtomicU64::new(0),
        }
    }

    /// Set the chain ID for EIP-712 domain separator (builder pattern)
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// Add a supported account factory
    pub fn add_factory(&mut self, factory_address: Vec<u8>) {
        if !self.supported_account_factories.contains(&factory_address) {
            self.supported_account_factories.push(factory_address);
        }
    }

    /// Get the current nonce for an account
    pub fn get_nonce(&self, sender: &[u8]) -> u64 {
        self.nonces
            .get(sender)
            .map(|n| *n)
            .unwrap_or(0)
    }

    /// Increment and return the next nonce for an account
    fn increment_nonce(&self, sender: &[u8]) -> u64 {
        let mut entry = self.nonces.entry(sender.to_vec()).or_insert(0);
        let current = *entry;
        *entry += 1;
        current
    }

    /// Deposit funds for an account
    pub fn deposit_to(&self, account: Vec<u8>, amount: u128) {
        self.deposits
            .entry(account)
            .and_modify(|balance| *balance = balance.saturating_add(amount))
            .or_insert(amount);
    }

    /// Get the deposit balance for an account
    pub fn get_deposit(&self, account: &[u8]) -> u128 {
        self.deposits
            .get(account)
            .map(|d| *d)
            .unwrap_or(0)
    }

    /// Deduct from an account's deposit
    fn deduct_deposit(&self, account: &[u8], amount: u128) -> Result<(), AccountAbstractionError> {
        let mut entry = self.deposits.entry(account.to_vec()).or_insert(0);
        if *entry < amount {
            return Err(AccountAbstractionError::InsufficientBalance {
                required: amount,
                available: *entry,
            });
        }
        *entry = entry.saturating_sub(amount);
        Ok(())
    }

    /// Validate a UserOperation
    ///
    /// Checks:
    /// - Account exists or can be created
    /// - Nonce is correct
    /// - Signature is valid
    /// - Sufficient balance/deposit for gas
    /// - Paymaster approval (if applicable)
    pub fn validate_user_op(&self, op: &UserOperation) -> Result<(), AccountAbstractionError> {
        // Validate nonce
        let expected_nonce = self.get_nonce(&op.sender);
        if op.nonce != expected_nonce {
            return Err(AccountAbstractionError::InvalidNonce {
                expected: expected_nonce,
                got: op.nonce,
            });
        }

        // Validate gas limits
        if op.call_gas_limit == 0 {
            return Err(AccountAbstractionError::InvalidUserOp(
                "call_gas_limit must be greater than 0".to_string(),
            ));
        }

        if op.verification_gas_limit == 0 {
            return Err(AccountAbstractionError::InvalidUserOp(
                "verification_gas_limit must be greater than 0".to_string(),
            ));
        }

        // Validate signature (simplified - in production, this would verify actual cryptographic signature)
        if op.signature.is_empty() {
            return Err(AccountAbstractionError::InvalidSignature);
        }

        // Validate sufficient balance
        let max_cost = op.max_gas_cost();
        if !op.has_paymaster() {
            let deposit = self.get_deposit(&op.sender);
            if deposit < max_cost {
                return Err(AccountAbstractionError::InsufficientBalance {
                    required: max_cost,
                    available: deposit,
                });
            }
        }

        // Validate account creation (v0.8: factory field must be a valid address)
        if op.is_account_creation()
            && op.factory.len() < 20 {
                return Err(AccountAbstractionError::InvalidUserOp(
                    "factory must be a valid 20-byte address".to_string(),
                ));
            }

        Ok(())
    }

    /// Simulate a UserOperation without state changes
    pub fn simulate_user_op(
        &self,
        op: &UserOperation,
    ) -> Result<SimulationResult, AccountAbstractionError> {
        // Validate first
        self.validate_user_op(op)?;

        // Simulate gas usage (simplified)
        let pre_op_gas = op.verification_gas_limit + op.pre_verification_gas;
        let paid = op.max_fee_per_gas * (pre_op_gas as u128);

        Ok(SimulationResult {
            valid: true,
            pre_op_gas,
            paid,
            validation_data: op.hash(self.chain_id, &self.address),
        })
    }

    /// Handle a bundle of UserOperations
    ///
    /// This is the main entry point for processing operations.
    /// It validates, executes, and settles payment for each operation.
    pub fn handle_ops(&self, ops: Vec<UserOperation>) -> Vec<UserOpReceipt> {
        let mut receipts = Vec::new();

        for op in ops {
            let receipt = self.handle_single_op(op);
            receipts.push(receipt);
        }

        receipts
    }

    /// Handle a single UserOperation
    fn handle_single_op(&self, op: UserOperation) -> UserOpReceipt {
        let op_hash = op.hash(self.chain_id, &self.address);

        // Phase 1: Validation
        let validation_result = self.validate_user_op(&op);
        if let Err(e) = validation_result {
            tracing::error!("UserOp validation failed: {}", e);
            return UserOpReceipt {
                user_op_hash: op_hash,
                success: false,
                gas_used: 0,
                actual_gas_cost: 0,
                logs: vec![format!("Validation failed: {}", e).into_bytes()],
            };
        }

        // Phase 2: Execution (simplified - would call actual contract code)
        let execution_gas = op.call_gas_limit;
        let verification_gas = op.verification_gas_limit;
        let mut total_gas = execution_gas
            .saturating_add(verification_gas)
            .saturating_add(op.pre_verification_gas);

        // v0.8: include paymaster gas limits when a paymaster is present
        if op.has_paymaster() {
            total_gas = total_gas
                .saturating_add(op.paymaster_verification_gas_limit)
                .saturating_add(op.paymaster_post_op_gas_limit);
        }

        // Phase 3: Payment
        // v0.8 gas penalty: if unused gas is below GAS_PENALTY_THRESHOLD (40,000),
        // no gas penalty is applied — the user is charged only for gas actually used.
        let gas_limit = op.total_gas_limit();
        let unused_gas = gas_limit.saturating_sub(total_gas);
        let chargeable_gas = if unused_gas < GAS_PENALTY_THRESHOLD {
            // No penalty: charge only actual gas used
            total_gas
        } else {
            // Charge the full gas limit (penalty for large unused gas)
            gas_limit
        };

        let actual_gas_price = op.max_fee_per_gas; // Simplified: use max fee
        let actual_gas_cost = (chargeable_gas as u128) * actual_gas_price;

        let payment_result = if op.has_paymaster() {
            // Paymaster pays
            Ok(())
        } else {
            // Account pays from deposit
            self.deduct_deposit(&op.sender, actual_gas_cost)
        };

        let success = payment_result.is_ok();

        if success {
            // Increment nonce on success
            self.increment_nonce(&op.sender);
            self.total_ops_processed.fetch_add(1, Ordering::Relaxed);
        }

        UserOpReceipt {
            user_op_hash: op_hash,
            success,
            gas_used: total_gas,
            actual_gas_cost,
            logs: vec![b"UserOp executed".to_vec()],
        }
    }

    /// Get statistics about the EntryPoint
    pub fn get_stats(&self) -> EntryPointStats {
        EntryPointStats {
            total_ops_processed: self.total_ops_processed.load(Ordering::Relaxed),
            total_accounts: self.nonces.len(),
            total_deposited: self.deposits.iter().map(|entry| *entry.value()).sum(),
        }
    }
}

/// Statistics about EntryPoint activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPointStats {
    pub total_ops_processed: u64,
    pub total_accounts: usize,
    pub total_deposited: u128,
}

/// Account Factory for creating smart contract wallets
///
/// The factory creates deterministic addresses for accounts based on
/// the owner and salt, allowing counterfactual deployment.
#[derive(Debug)]
pub struct AccountFactory {
    /// Factory contract address
    pub factory_address: Vec<u8>,

    /// Deployed accounts
    pub deployed_accounts: DashMap<Vec<u8>, SmartAccount>,
}

impl AccountFactory {
    /// Create a new AccountFactory
    pub fn new(factory_address: Vec<u8>) -> Self {
        Self {
            factory_address,
            deployed_accounts: DashMap::new(),
        }
    }

    /// Create a new smart account
    ///
    /// The account is created deterministically based on owner and salt.
    pub fn create_account(&self, owner: Vec<u8>, salt: u64) -> SmartAccount {
        let address = self.get_address(&owner, salt);

        let account = SmartAccount {
            address: address.clone(),
            owner,
            factory: self.factory_address.clone(),
            nonce: 0,
            is_deployed: true,
            modules: Vec::new(),
        };

        self.deployed_accounts.insert(address, account.clone());
        account
    }

    /// Get the counterfactual address for an account
    ///
    /// This computes the deterministic address without deploying the account.
    pub fn get_address(&self, owner: &[u8], salt: u64) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.factory_address);
        hasher.update(owner);
        hasher.update(salt.to_le_bytes());
        let hash = hasher.finalize();

        // Take first 20 bytes as address (Ethereum-style)
        hash[..20].to_vec()
    }

    /// Get an account by address
    pub fn get_account(&self, address: &[u8]) -> Option<SmartAccount> {
        self.deployed_accounts.get(address).map(|acc| acc.clone())
    }

    /// Get all deployed accounts
    pub fn get_all_accounts(&self) -> Vec<SmartAccount> {
        self.deployed_accounts
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get the number of deployed accounts
    pub fn account_count(&self) -> usize {
        self.deployed_accounts.len()
    }
}

/// A smart contract wallet account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartAccount {
    /// Account address
    pub address: Vec<u8>,

    /// Owner of the account
    pub owner: Vec<u8>,

    /// Factory that created this account
    pub factory: Vec<u8>,

    /// Current nonce
    pub nonce: u64,

    /// Whether the account is deployed on-chain
    pub is_deployed: bool,

    /// Installed modules
    pub modules: Vec<AccountModule>,
}

impl SmartAccount {
    /// Add a module to the account
    pub fn add_module(&mut self, module: AccountModule) {
        self.modules.push(module);
    }

    /// Remove a module from the account
    pub fn remove_module(&mut self, index: usize) -> Option<AccountModule> {
        if index < self.modules.len() {
            Some(self.modules.remove(index))
        } else {
            None
        }
    }

    /// Check if account has a specific module type
    pub fn has_module_type(&self, module_type: &str) -> bool {
        self.modules.iter().any(|m| matches!((module_type, m),
            ("social_recovery", AccountModule::SocialRecovery { .. })
            | ("session_key", AccountModule::SessionKey { .. })
            | ("spending_limit", AccountModule::SpendingLimit { .. })
            | ("batching", AccountModule::Batching)
        ))
    }

    /// Get session keys that are currently valid
    pub fn get_valid_session_keys(&self, current_time: u64) -> Vec<Vec<u8>> {
        self.modules
            .iter()
            .filter_map(|m| {
                if let AccountModule::SessionKey { key, expires_at, .. } = m
                    && *expires_at > current_time
                {
                    return Some(key.clone());
                }
                None
            })
            .collect()
    }
}

/// Account modules that extend smart account functionality
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AccountModule {
    /// Social recovery module
    ///
    /// Allows designated guardians to recover the account if the owner
    /// loses access. Requires a threshold of guardians to approve recovery.
    SocialRecovery {
        /// Guardian addresses
        guardians: Vec<Vec<u8>>,
        /// Number of guardians required for recovery
        threshold: u32,
    },

    /// Session key module
    ///
    /// Allows temporary keys with limited permissions, ideal for AI agents
    /// that need to operate autonomously within constraints.
    SessionKey {
        /// Session key address
        key: Vec<u8>,
        /// Expiration timestamp
        expires_at: u64,
        /// Allowed operations
        permissions: Vec<String>,
    },

    /// Spending limit module
    ///
    /// Enforces spending limits per token over a time period, providing
    /// safety controls for AI agents and preventing unauthorized drains.
    SpendingLimit {
        /// Token address
        token: Vec<u8>,
        /// Maximum amount per period
        limit: u128,
        /// Period duration in seconds
        period_seconds: u64,
    },

    /// Batching module
    ///
    /// Allows multiple operations to be executed atomically in a single
    /// transaction, optimizing gas costs and ensuring all-or-nothing execution.
    Batching,
}

/// Paymaster for sponsoring gas fees
///
/// A Paymaster is a contract that agrees to pay for UserOperations,
/// enabling gasless transactions for users and AI agents.
#[derive(Debug, Clone)]
pub struct Paymaster {
    /// Paymaster address
    pub address: Vec<u8>,

    /// Current balance
    pub balance: u128,

    /// Number of operations sponsored
    pub sponsored_ops: u64,
}

impl Paymaster {
    /// Create a new Paymaster
    pub fn new(address: Vec<u8>, initial_balance: u128) -> Self {
        Self {
            address,
            balance: initial_balance,
            sponsored_ops: 0,
        }
    }

    /// Validate that this paymaster will sponsor an operation.
    ///
    /// In v0.8, the paymaster address is a separate field (not embedded in paymaster_and_data).
    pub fn validate_paymaster_op(
        &self,
        op: &UserOperation,
    ) -> Result<bool, AccountAbstractionError> {
        // Check if paymaster is specified in the operation (v0.8: separate field)
        if op.paymaster.len() < 20 {
            return Err(AccountAbstractionError::PaymasterError(
                "Invalid paymaster address".to_string(),
            ));
        }

        // Verify paymaster address matches
        let paymaster_address = &op.paymaster[..20];
        if paymaster_address != self.address {
            return Err(AccountAbstractionError::PaymasterError(
                "Paymaster address mismatch".to_string(),
            ));
        }

        // Check if paymaster has sufficient balance
        let max_cost = op.max_gas_cost();
        if self.balance < max_cost {
            return Err(AccountAbstractionError::PaymasterError(format!(
                "Insufficient paymaster balance: required {}, available {}",
                max_cost, self.balance
            )));
        }

        Ok(true)
    }

    /// Sponsor gas for an operation
    pub fn sponsor_gas(&mut self, gas_cost: u128) -> Result<(), AccountAbstractionError> {
        if self.balance < gas_cost {
            return Err(AccountAbstractionError::PaymasterError(format!(
                "Insufficient balance: required {}, available {}",
                gas_cost, self.balance
            )));
        }

        self.balance = self.balance.saturating_sub(gas_cost);
        self.sponsored_ops += 1;
        Ok(())
    }

    /// Add funds to the paymaster
    pub fn add_funds(&mut self, amount: u128) {
        self.balance = self.balance.saturating_add(amount);
    }

    /// Get remaining balance
    pub fn get_balance(&self) -> u128 {
        self.balance
    }
}

/// Configuration for bundler operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundlerConfig {
    /// Maximum number of operations per bundle
    pub max_bundle_size: usize,

    /// Minimum priority fee to accept
    pub min_priority_fee: u128,

    /// Maximum operations in mempool
    pub mempool_capacity: usize,
}

impl Default for BundlerConfig {
    fn default() -> Self {
        Self {
            max_bundle_size: 100,
            min_priority_fee: 1_000_000, // 1 Gwei
            mempool_capacity: 10_000,
        }
    }
}

// ---------------------------------------------------------------------------
// EIP-7702: EOA Code Delegation (SET_CODE_TX_TYPE = 0x04)
// ---------------------------------------------------------------------------

/// EIP-7702 transaction type identifier
pub const EIP_7702_TX_TYPE: u8 = 0x04;

/// EIP-7702 authorization magic byte (domain separator). Per EIP-7702 §4 the
/// signing preimage is `keccak256(MAGIC || rlp([chain_id, address, nonce]))`.
pub const EIP_7702_MAGIC: u8 = 0x05;

/// EIP-7702 delegation designator prefix. When an EOA's code slot contains
/// `0xef 0x01 0x00 || address20` the EVM treats calls to that EOA as if they
/// ran `address20`'s code.
pub const EIP_7702_DESIGNATOR_PREFIX: [u8; 3] = [0xef, 0x01, 0x00];

/// Full length of the delegation designator (3 prefix bytes + 20-byte address).
pub const EIP_7702_DESIGNATOR_LEN: usize = 23;

/// EIP-7702 authorization: EOA delegates to contract code for one transaction
///
/// This allows an externally-owned account (EOA) to temporarily adopt the code
/// of a smart contract for the duration of a single transaction, enabling
/// advanced account abstraction features without permanent deployment.
///
/// The `signature` field is a 65-byte secp256k1 signature encoded as
/// `r(32) || s(32) || y_parity(1)` where `y_parity` is `0` or `1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip7702Authorization {
    /// Chain ID this authorization is valid for
    pub chain_id: u64,
    /// Contract address whose code the EOA temporarily adopts (20 bytes)
    pub delegate_address: Vec<u8>,
    /// Authorization nonce (prevents replay)
    pub nonce: u64,
    /// secp256k1 signature: r(32) || s(32) || y_parity(1)
    pub signature: Vec<u8>,
}

impl Eip7702Authorization {
    /// Build the EIP-7702 signing preimage:
    /// `MAGIC(0x05) || rlp([chain_id, delegate_address, nonce])`.
    ///
    /// Per the spec, `chain_id == 0` is a wildcard that allows the
    /// authorization to be included on any chain.
    pub fn signing_data(&self) -> Vec<u8> {
        use rlp::RlpStream;
        let mut stream = RlpStream::new_list(3);
        stream.append(&self.chain_id);
        stream.append(&self.delegate_address.as_slice());
        stream.append(&self.nonce);
        let rlp_bytes = stream.out();

        let mut out = Vec::with_capacity(1 + rlp_bytes.len());
        out.push(EIP_7702_MAGIC);
        out.extend_from_slice(&rlp_bytes);
        out
    }

    /// keccak256 of [`signing_data`], i.e. the message digest the authorizer
    /// signs with secp256k1.
    pub fn signing_hash(&self) -> [u8; 32] {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(self.signing_data());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

/// Recover the authorizing EOA address from an EIP-7702 authorization
/// signature via secp256k1 ecrecover, exactly matching Ethereum's execution-
/// layer behaviour.
///
/// The signature must be 65 bytes: `r(32) || s(32) || y_parity(1)` with
/// `y_parity ∈ {0, 1}`. The Ethereum address is the last 20 bytes of
/// `keccak256(uncompressed_pubkey)`.
fn recover_eoa_from_7702_signature(auth: &Eip7702Authorization) -> Result<Vec<u8>, VmError> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use sha3::{Digest, Keccak256};

    if auth.signature.len() != 65 {
        return Err(VmError::InvalidSignature);
    }
    if auth.delegate_address.len() != 20 {
        return Err(VmError::InvalidTransaction(
            "EIP-7702: delegate_address must be 20 bytes".into(),
        ));
    }

    let y_parity = auth.signature[64];
    if y_parity > 1 {
        return Err(VmError::InvalidSignature);
    }
    let recovery_id = RecoveryId::try_from(y_parity).map_err(|_| VmError::InvalidSignature)?;

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&auth.signature[..64]);
    let signature = Signature::from_bytes(&sig_bytes.into())
        .map_err(|_| VmError::InvalidSignature)?;

    let hash = auth.signing_hash();
    let recovered = VerifyingKey::recover_from_prehash(&hash, &signature, recovery_id)
        .map_err(|_| VmError::InvalidSignature)?;

    // Ethereum address = keccak256(uncompressed_pubkey[1..])[12..32]
    let encoded = recovered.to_encoded_point(false);
    let pubkey_no_prefix = &encoded.as_bytes()[1..];
    let mut hasher = Keccak256::new();
    hasher.update(pubkey_no_prefix);
    let digest = hasher.finalize();
    Ok(digest[12..32].to_vec())
}

/// Build the 23-byte EIP-7702 delegation designator for a given target
/// address: `0xef 0x01 0x00 || address20`.
pub fn build_7702_designator(delegate_address: &[u8]) -> Result<Vec<u8>, VmError> {
    if delegate_address.len() != 20 {
        return Err(VmError::InvalidTransaction(
            "EIP-7702: delegate_address must be 20 bytes".into(),
        ));
    }
    let mut out = Vec::with_capacity(EIP_7702_DESIGNATOR_LEN);
    out.extend_from_slice(&EIP_7702_DESIGNATOR_PREFIX);
    out.extend_from_slice(delegate_address);
    Ok(out)
}

/// If `code` is a valid EIP-7702 designator, return the 20-byte delegate
/// address it points to. Otherwise return `None`.
pub fn parse_7702_designator(code: &[u8]) -> Option<Vec<u8>> {
    if code.len() == EIP_7702_DESIGNATOR_LEN && code[..3] == EIP_7702_DESIGNATOR_PREFIX {
        Some(code[3..].to_vec())
    } else {
        None
    }
}

/// Process an EIP-7702 authorization list before transaction execution.
///
/// For each authorization, verifies the signature, checks the nonce, and
/// temporarily sets the EOA's code to the delegate contract's code. Returns
/// the list of upgraded EOA addresses so the caller can clean up after
/// execution completes.
pub fn process_7702_authorizations(
    authorizations: &[Eip7702Authorization],
    expected_chain_id: u64,
    state: &mut dyn VmState,
) -> Result<Vec<Vec<u8>>, VmError> {
    let mut upgraded_eoas = Vec::new();
    let mut seen_eoas: HashSet<Vec<u8>> = HashSet::new();

    for auth in authorizations {
        // Validate chain ID
        if auth.chain_id != expected_chain_id {
            return Err(VmError::InvalidTransaction(format!(
                "EIP-7702: authorization chain_id {} does not match expected {}",
                auth.chain_id, expected_chain_id
            )));
        }

        // Recover EOA address from signature (secp256k1 ecrecover over
        // keccak256(MAGIC || rlp([chain_id, address, nonce])))
        let eoa_address = recover_eoa_from_7702_signature(auth)?;

        // Prevent duplicate authorizations for the same EOA
        if seen_eoas.contains(&eoa_address) {
            return Err(VmError::InvalidTransaction(format!(
                "EIP-7702: duplicate authorization for EOA 0x{}",
                hex::encode(&eoa_address)
            )));
        }

        // Verify nonce matches the EOA's current nonce
        let current_nonce = state.get_nonce(&eoa_address);
        if auth.nonce != current_nonce {
            return Err(VmError::InvalidNonce {
                expected: current_nonce,
                got: auth.nonce,
            });
        }

        // Per EIP-7702 the EOA's code slot is set to the 23-byte designator
        // `0xef 0x01 0x00 || delegate_address`, NOT the delegate's bytecode.
        // The EVM detects this prefix and routes calls to `delegate_address`,
        // so upgrades to the delegate are picked up automatically.
        let designator = build_7702_designator(&auth.delegate_address)?;
        state.set_code(&eoa_address, designator);
        seen_eoas.insert(eoa_address.clone());
        upgraded_eoas.push(eoa_address.clone());
        info!(
            "EIP-7702: EOA 0x{} delegated to 0x{} via designator",
            hex::encode(&eoa_address),
            hex::encode(&auth.delegate_address)
        );
    }

    Ok(upgraded_eoas)
}

/// Clean up EIP-7702 code delegation after transaction execution.
///
/// Removes the temporarily injected code from each upgraded EOA, restoring
/// them to their original empty-code state.
pub fn cleanup_7702_authorizations(
    upgraded_eoas: &[Vec<u8>],
    state: &mut dyn VmState,
) {
    for eoa in upgraded_eoas {
        state.set_code(eoa, vec![]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_point_creation() {
        let entry_point = EntryPoint::new(vec![0x01; 20]);
        assert_eq!(entry_point.address, vec![0x01; 20]);
        assert_eq!(entry_point.get_nonce(&[0x02; 20]), 0);
    }

    #[test]
    fn test_deposit_and_balance() {
        let entry_point = EntryPoint::new(vec![0x01; 20]);
        let account = vec![0x02; 20];

        assert_eq!(entry_point.get_deposit(&account), 0);

        entry_point.deposit_to(account.clone(), 1_000_000_000);
        assert_eq!(entry_point.get_deposit(&account), 1_000_000_000);

        entry_point.deposit_to(account.clone(), 500_000_000);
        assert_eq!(entry_point.get_deposit(&account), 1_500_000_000);
    }

    #[test]
    fn test_account_factory() {
        let factory = AccountFactory::new(vec![0x01; 20]);
        let owner = vec![0x02; 20];
        let salt = 12345u64;

        // Get counterfactual address
        let address1 = factory.get_address(&owner, salt);
        let address2 = factory.get_address(&owner, salt);
        assert_eq!(address1, address2, "Addresses should be deterministic");

        // Different salt should give different address
        let address3 = factory.get_address(&owner, salt + 1);
        assert_ne!(address1, address3, "Different salts should give different addresses");

        // Create account
        let account = factory.create_account(owner.clone(), salt);
        assert_eq!(account.address, address1);
        assert_eq!(account.owner, owner);
        assert_eq!(account.factory, vec![0x01; 20]);
        assert!(account.is_deployed);
    }

    /// Helper to create a default v0.8 UserOperation for tests
    fn test_user_op(sender: Vec<u8>, nonce: u64) -> UserOperation {
        UserOperation {
            sender,
            nonce,
            factory: vec![],
            factory_data: vec![],
            call_data: vec![0x42; 32],
            call_gas_limit: 100_000,
            verification_gas_limit: 50_000,
            pre_verification_gas: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000,
            paymaster: vec![],
            paymaster_verification_gas_limit: 0,
            paymaster_post_op_gas_limit: 0,
            paymaster_data: vec![],
            signature: vec![0x05; 65],
        }
    }

    #[test]
    fn test_user_operation_validation() {
        let entry_point = EntryPoint::new(vec![0x01; 20]);
        let sender = vec![0x02; 20];

        // Deposit funds
        entry_point.deposit_to(sender.clone(), 10_000_000_000_000_000);

        let user_op = test_user_op(sender.clone(), 0);

        // Should validate successfully
        assert!(entry_point.validate_user_op(&user_op).is_ok());

        // Invalid nonce should fail
        let mut invalid_op = user_op.clone();
        invalid_op.nonce = 5;
        assert!(entry_point.validate_user_op(&invalid_op).is_err());

        // Missing signature should fail
        let mut invalid_op = user_op.clone();
        invalid_op.signature = vec![];
        assert!(entry_point.validate_user_op(&invalid_op).is_err());

        // Zero gas limit should fail
        let mut invalid_op = user_op.clone();
        invalid_op.call_gas_limit = 0;
        assert!(entry_point.validate_user_op(&invalid_op).is_err());
    }

    #[test]
    fn test_handle_ops() {
        let entry_point = EntryPoint::new(vec![0x01; 20]);
        let sender = vec![0x02; 20];

        // Deposit sufficient funds
        entry_point.deposit_to(sender.clone(), 100_000_000_000_000_000);

        let user_op = test_user_op(sender.clone(), 0);

        let receipts = entry_point.handle_ops(vec![user_op]);
        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].success);
        assert_eq!(receipts[0].gas_used, 171_000);

        // Nonce should be incremented
        assert_eq!(entry_point.get_nonce(&sender), 1);

        // Total ops should be incremented
        assert_eq!(entry_point.total_ops_processed.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_paymaster_validation() {
        let paymaster = Paymaster::new(vec![0x03; 20], 10_000_000_000_000_000);
        let sender = vec![0x02; 20];

        let mut user_op = test_user_op(sender.clone(), 0);
        // v0.8: set paymaster fields separately
        user_op.paymaster = vec![0x03; 20];
        user_op.paymaster_verification_gas_limit = 30_000;
        user_op.paymaster_post_op_gas_limit = 20_000;

        // Should validate successfully
        assert!(paymaster.validate_paymaster_op(&user_op).is_ok());

        // Wrong paymaster address should fail
        user_op.paymaster = vec![0x04; 20];
        assert!(paymaster.validate_paymaster_op(&user_op).is_err());

        // Insufficient paymaster address should fail
        user_op.paymaster = vec![0x03; 10];
        assert!(paymaster.validate_paymaster_op(&user_op).is_err());
    }

    #[test]
    fn test_paymaster_gas_sponsorship() {
        let mut paymaster = Paymaster::new(vec![0x03; 20], 10_000_000_000_000_000);

        assert_eq!(paymaster.sponsored_ops, 0);
        assert_eq!(paymaster.balance, 10_000_000_000_000_000);

        // Sponsor gas
        let gas_cost = 1_000_000_000_000_000;
        assert!(paymaster.sponsor_gas(gas_cost).is_ok());
        assert_eq!(paymaster.balance, 9_000_000_000_000_000);
        assert_eq!(paymaster.sponsored_ops, 1);

        // Sponsor more gas
        assert!(paymaster.sponsor_gas(gas_cost).is_ok());
        assert_eq!(paymaster.balance, 8_000_000_000_000_000);
        assert_eq!(paymaster.sponsored_ops, 2);

        // Insufficient balance should fail
        let large_cost = 20_000_000_000_000_000;
        assert!(paymaster.sponsor_gas(large_cost).is_err());
        assert_eq!(paymaster.sponsored_ops, 2); // Should not increment on failure
    }

    #[test]
    fn test_smart_account_modules() {
        let factory = AccountFactory::new(vec![0x01; 20]);
        let owner = vec![0x02; 20];
        let mut account = factory.create_account(owner, 1);

        assert_eq!(account.modules.len(), 0);

        // Add session key module
        account.add_module(AccountModule::SessionKey {
            key: vec![0x03; 20],
            expires_at: 1735689600,
            permissions: vec!["transfer".to_string(), "approve".to_string()],
        });
        assert_eq!(account.modules.len(), 1);
        assert!(account.has_module_type("session_key"));

        // Add social recovery module
        account.add_module(AccountModule::SocialRecovery {
            guardians: vec![vec![0x04; 20], vec![0x05; 20], vec![0x06; 20]],
            threshold: 2,
        });
        assert_eq!(account.modules.len(), 2);
        assert!(account.has_module_type("social_recovery"));

        // Add spending limit module
        account.add_module(AccountModule::SpendingLimit {
            token: vec![0x07; 20],
            limit: 1_000_000_000_000_000_000,
            period_seconds: 86400,
        });
        assert_eq!(account.modules.len(), 3);
        assert!(account.has_module_type("spending_limit"));

        // Add batching module
        account.add_module(AccountModule::Batching);
        assert_eq!(account.modules.len(), 4);
        assert!(account.has_module_type("batching"));

        // Remove a module
        let removed = account.remove_module(0);
        assert!(removed.is_some());
        assert_eq!(account.modules.len(), 3);
    }

    #[test]
    fn test_session_key_expiration() {
        let factory = AccountFactory::new(vec![0x01; 20]);
        let owner = vec![0x02; 20];
        let mut account = factory.create_account(owner, 1);

        // Add expired session key
        account.add_module(AccountModule::SessionKey {
            key: vec![0x03; 20],
            expires_at: 1000,
            permissions: vec!["transfer".to_string()],
        });

        // Add valid session key
        account.add_module(AccountModule::SessionKey {
            key: vec![0x04; 20],
            expires_at: 2000,
            permissions: vec!["approve".to_string()],
        });

        // Add another valid session key
        account.add_module(AccountModule::SessionKey {
            key: vec![0x05; 20],
            expires_at: 3000,
            permissions: vec!["mint".to_string()],
        });

        // Check valid keys at time 1500
        let valid_keys = account.get_valid_session_keys(1500);
        assert_eq!(valid_keys.len(), 2);
        assert!(valid_keys.contains(&vec![0x04; 20]));
        assert!(valid_keys.contains(&vec![0x05; 20]));

        // Check valid keys at time 2500
        let valid_keys = account.get_valid_session_keys(2500);
        assert_eq!(valid_keys.len(), 1);
        assert!(valid_keys.contains(&vec![0x05; 20]));

        // Check valid keys at time 3500 (all expired)
        let valid_keys = account.get_valid_session_keys(3500);
        assert_eq!(valid_keys.len(), 0);
    }

    #[test]
    fn test_social_recovery_module() {
        let factory = AccountFactory::new(vec![0x01; 20]);
        let owner = vec![0x02; 20];
        let mut account = factory.create_account(owner, 1);

        // Add social recovery with 3 guardians, 2 required
        let guardians = vec![vec![0x03; 20], vec![0x04; 20], vec![0x05; 20]];
        account.add_module(AccountModule::SocialRecovery {
            guardians: guardians.clone(),
            threshold: 2,
        });

        // Verify module was added
        assert!(account.has_module_type("social_recovery"));

        // Extract and verify the module
        if let AccountModule::SocialRecovery {
            guardians: g,
            threshold: t,
        } = &account.modules[0]
        {
            assert_eq!(g.len(), 3);
            assert_eq!(*t, 2);
            assert_eq!(g, &guardians);
        } else {
            panic!("Expected SocialRecovery module");
        }
    }

    #[test]
    fn test_spending_limit_module() {
        let factory = AccountFactory::new(vec![0x01; 20]);
        let owner = vec![0x02; 20];
        let mut account = factory.create_account(owner, 1);

        // Add spending limit: 100 tokens per day
        let token = vec![0x03; 20];
        let limit = 100_000_000_000_000_000_000; // 100 tokens with 18 decimals
        let period = 86400u64; // 24 hours

        account.add_module(AccountModule::SpendingLimit {
            token: token.clone(),
            limit,
            period_seconds: period,
        });

        // Verify module was added
        assert!(account.has_module_type("spending_limit"));

        // Extract and verify the module
        if let AccountModule::SpendingLimit {
            token: t,
            limit: l,
            period_seconds: p,
        } = &account.modules[0]
        {
            assert_eq!(t, &token);
            assert_eq!(*l, limit);
            assert_eq!(*p, period);
        } else {
            panic!("Expected SpendingLimit module");
        }
    }

    #[test]
    fn test_user_operation_hash() {
        let chain_id = 1337u64;
        let entry_point_addr = vec![0xAA; 20];

        let user_op = UserOperation {
            sender: vec![0x01; 20],
            nonce: 42,
            factory: vec![0x02; 20],
            factory_data: vec![0x02; 12],
            call_data: vec![0x03; 64],
            call_gas_limit: 100_000,
            verification_gas_limit: 50_000,
            pre_verification_gas: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000,
            paymaster: vec![0x04; 20],
            paymaster_verification_gas_limit: 30_000,
            paymaster_post_op_gas_limit: 20_000,
            paymaster_data: vec![],
            signature: vec![0x05; 65],
        };

        let hash1 = user_op.hash(chain_id, &entry_point_addr);
        let hash2 = user_op.hash(chain_id, &entry_point_addr);

        // Hash should be deterministic
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // Keccak-256 produces 32 bytes

        // Different operation should produce different hash
        let mut user_op2 = user_op.clone();
        user_op2.nonce = 43;
        let hash3 = user_op2.hash(chain_id, &entry_point_addr);
        assert_ne!(hash1, hash3);

        // Different chain_id should produce different hash
        let hash4 = user_op.hash(1, &entry_point_addr);
        assert_ne!(hash1, hash4);

        // Different entry_point address should produce different hash
        let hash5 = user_op.hash(chain_id, &[0xBB; 20]);
        assert_ne!(hash1, hash5);
    }

    #[test]
    fn test_user_operation_helpers() {
        let mut user_op = UserOperation {
            sender: vec![0x01; 20],
            nonce: 0,
            factory: vec![0x02; 20],
            factory_data: vec![0x02; 12],
            call_data: vec![0x03; 64],
            call_gas_limit: 100_000,
            verification_gas_limit: 50_000,
            pre_verification_gas: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000,
            paymaster: vec![0x04; 20],
            paymaster_verification_gas_limit: 30_000,
            paymaster_post_op_gas_limit: 20_000,
            paymaster_data: vec![],
            signature: vec![0x05; 65],
        };

        // Test total gas limit (v0.8: includes paymaster gas limits when paymaster present)
        // 100_000 + 50_000 + 21_000 + 30_000 + 20_000 = 221_000
        assert_eq!(user_op.total_gas_limit(), 221_000);

        // Test max gas cost
        assert_eq!(user_op.max_gas_cost(), 221_000_000_000_000);

        // Test has paymaster
        assert!(user_op.has_paymaster());

        // Test is account creation
        assert!(user_op.is_account_creation());

        // Test without paymaster
        let mut user_op2 = user_op.clone();
        user_op2.paymaster = vec![];
        assert!(!user_op2.has_paymaster());
        // Without paymaster, total gas excludes paymaster gas limits
        assert_eq!(user_op2.total_gas_limit(), 171_000);

        // Test without factory
        user_op.factory = vec![];
        assert!(!user_op.is_account_creation());
    }

    #[test]
    fn test_simulate_user_op() {
        let entry_point = EntryPoint::new(vec![0x01; 20]);
        let sender = vec![0x02; 20];

        // Deposit funds
        entry_point.deposit_to(sender.clone(), 10_000_000_000_000_000);

        let user_op = test_user_op(sender.clone(), 0);

        let result = entry_point.simulate_user_op(&user_op);
        assert!(result.is_ok());

        let sim = result.unwrap();
        assert!(sim.valid);
        assert_eq!(sim.pre_op_gas, 71_000);
        assert_eq!(sim.paid, 71_000_000_000_000);
    }

    #[test]
    fn test_bundler_config_default() {
        let config = BundlerConfig::default();
        assert_eq!(config.max_bundle_size, 100);
        assert_eq!(config.min_priority_fee, 1_000_000);
        assert_eq!(config.mempool_capacity, 10_000);
    }

    #[test]
    fn test_entry_point_stats() {
        let entry_point = EntryPoint::new(vec![0x01; 20]);
        let sender1 = vec![0x02; 20];
        let sender2 = vec![0x03; 20];

        // Add deposits
        entry_point.deposit_to(sender1.clone(), 5_000_000_000_000_000);
        entry_point.deposit_to(sender2.clone(), 3_000_000_000_000_000);

        // Process operations
        let user_op1 = test_user_op(sender1.clone(), 0);
        let user_op2 = test_user_op(sender2.clone(), 0);

        entry_point.handle_ops(vec![user_op1, user_op2]);

        let stats = entry_point.get_stats();
        assert_eq!(stats.total_ops_processed, 2);
        assert_eq!(stats.total_accounts, 2);
        // Total deposited minus gas costs
        assert!(stats.total_deposited < 8_000_000_000_000_000);
    }

    #[test]
    fn test_multiple_account_creation() {
        let factory = AccountFactory::new(vec![0x01; 20]);

        // Create multiple accounts with different owners and salts
        let account1 = factory.create_account(vec![0x02; 20], 1);
        let account2 = factory.create_account(vec![0x03; 20], 1);
        let account3 = factory.create_account(vec![0x02; 20], 2);

        // All addresses should be different
        assert_ne!(account1.address, account2.address);
        assert_ne!(account1.address, account3.address);
        assert_ne!(account2.address, account3.address);

        // Verify factory count
        assert_eq!(factory.account_count(), 3);

        // Verify we can retrieve accounts
        assert!(factory.get_account(&account1.address).is_some());
        assert!(factory.get_account(&account2.address).is_some());
        assert!(factory.get_account(&account3.address).is_some());

        // Get all accounts
        let all_accounts = factory.get_all_accounts();
        assert_eq!(all_accounts.len(), 3);
    }

    // -----------------------------------------------------------------------
    // v0.8 specific tests: PackedUserOperation, EIP-712 hashing, gas penalty
    // -----------------------------------------------------------------------

    #[test]
    fn test_packed_user_operation_roundtrip() {
        let user_op = UserOperation {
            sender: vec![0x01; 20],
            nonce: 42,
            factory: vec![0x02; 20],
            factory_data: vec![0xAA, 0xBB, 0xCC],
            call_data: vec![0x03; 64],
            call_gas_limit: 100_000,
            verification_gas_limit: 50_000,
            pre_verification_gas: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000,
            paymaster: vec![0x04; 20],
            paymaster_verification_gas_limit: 30_000,
            paymaster_post_op_gas_limit: 20_000,
            paymaster_data: vec![0xDD, 0xEE],
            signature: vec![0x05; 65],
        };

        let packed = user_op.to_packed();

        // Verify packed init_code = factory || factory_data
        assert_eq!(&packed.init_code[..20], &vec![0x02; 20][..]);
        assert_eq!(&packed.init_code[20..], &[0xAA, 0xBB, 0xCC]);

        // Verify packed paymaster_and_data = paymaster || ver_gas(8) || post_gas(8) || data
        assert_eq!(&packed.paymaster_and_data[..20], &vec![0x04; 20][..]);
        assert_eq!(
            u64::from_be_bytes(packed.paymaster_and_data[20..28].try_into().unwrap()),
            30_000
        );
        assert_eq!(
            u64::from_be_bytes(packed.paymaster_and_data[28..36].try_into().unwrap()),
            20_000
        );
        assert_eq!(&packed.paymaster_and_data[36..], &[0xDD, 0xEE]);

        // Roundtrip: packed -> user_op should match original
        let restored = packed.to_user_op();
        assert_eq!(restored.sender, user_op.sender);
        assert_eq!(restored.nonce, user_op.nonce);
        assert_eq!(restored.factory, user_op.factory);
        assert_eq!(restored.factory_data, user_op.factory_data);
        assert_eq!(restored.call_data, user_op.call_data);
        assert_eq!(restored.paymaster, user_op.paymaster);
        assert_eq!(restored.paymaster_verification_gas_limit, user_op.paymaster_verification_gas_limit);
        assert_eq!(restored.paymaster_post_op_gas_limit, user_op.paymaster_post_op_gas_limit);
        assert_eq!(restored.paymaster_data, user_op.paymaster_data);
    }

    #[test]
    fn test_packed_user_operation_empty_fields() {
        // No factory, no paymaster
        let user_op = test_user_op(vec![0x01; 20], 0);
        let packed = user_op.to_packed();

        assert!(packed.init_code.is_empty());
        assert!(packed.paymaster_and_data.is_empty());

        let restored = packed.to_user_op();
        assert!(restored.factory.is_empty());
        assert!(restored.factory_data.is_empty());
        assert!(restored.paymaster.is_empty());
        assert_eq!(restored.paymaster_verification_gas_limit, 0);
        assert_eq!(restored.paymaster_post_op_gas_limit, 0);
        assert!(restored.paymaster_data.is_empty());
    }

    #[test]
    fn test_eip712_hash_is_keccak256() {
        let user_op = test_user_op(vec![0x01; 20], 0);
        let hash = user_op.hash(1337, &[0xAA; 20]);

        // EIP-712 hash should be 32 bytes (keccak256 output)
        assert_eq!(hash.len(), 32);

        // Signature field should NOT affect the hash (excluded per ERC-4337)
        let mut user_op2 = user_op.clone();
        user_op2.signature = vec![0xFF; 130]; // different signature
        let hash2 = user_op2.hash(1337, &[0xAA; 20]);
        assert_eq!(hash, hash2, "Signature should not affect the EIP-712 hash");
    }

    #[test]
    fn test_entry_point_chain_id() {
        let ep = EntryPoint::new(vec![0x01; 20]);
        assert_eq!(ep.chain_id, 1337); // default

        let ep2 = EntryPoint::new(vec![0x01; 20]).with_chain_id(42161);
        assert_eq!(ep2.chain_id, 42161);
    }

    #[test]
    fn test_gas_penalty_threshold_below() {
        // When unused gas < 40,000, only actual gas is charged (no penalty)
        let entry_point = EntryPoint::new(vec![0x01; 20]);
        let sender = vec![0x02; 20];

        // Deposit a large amount
        entry_point.deposit_to(sender.clone(), 1_000_000_000_000_000_000);

        // total_gas_limit = 100_000 + 50_000 + 21_000 = 171_000
        // gas_used (in handle_single_op) = same 171_000 (simplified)
        // unused = 0, which is < 40,000 => no penalty, charge only actual gas
        let user_op = test_user_op(sender.clone(), 0);

        let receipts = entry_point.handle_ops(vec![user_op]);
        assert!(receipts[0].success);
        // actual_gas_cost should be gas_used * max_fee_per_gas
        // gas_used = 171_000, unused = 0 < 40_000 => chargeable = 171_000
        assert_eq!(receipts[0].actual_gas_cost, 171_000 * 1_000_000_000);
    }

    // -----------------------------------------------------------------------
    // EIP-7702 tests
    // -----------------------------------------------------------------------

    use crate::state_adapter::StateAdapter;
    use k256::ecdsa::SigningKey;

    /// Deterministic secp256k1 signing key derived from a single byte seed.
    /// Keeps tests hermetic (no thread_rng dep).
    fn test_signing_key(seed: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        // Simple key schedule — must be a valid scalar (non-zero, < curve order).
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8).wrapping_add(1);
        }
        SigningKey::from_bytes(&bytes.into()).expect("valid secp256k1 scalar")
    }

    /// Produce a real secp256k1 signature over an authorization's EIP-7702
    /// signing hash and return `(signature, expected_eoa_address)`.
    fn sign_7702_auth(
        sk: &SigningKey,
        chain_id: u64,
        delegate: &[u8],
        nonce: u64,
    ) -> (Vec<u8>, Vec<u8>) {
        use sha3::{Digest, Keccak256};

        let auth = Eip7702Authorization {
            chain_id,
            delegate_address: delegate.to_vec(),
            nonce,
            signature: vec![],
        };
        let hash = auth.signing_hash();

        let (sig, rid) = sk.sign_prehash_recoverable(&hash).expect("sign");
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&sig.to_bytes());
        out.push(rid.to_byte());

        // Expected Ethereum address: keccak256(uncompressed_pubkey[1..])[12..32]
        let vk = sk.verifying_key();
        let encoded = vk.to_encoded_point(false);
        let pk_no_prefix = &encoded.as_bytes()[1..];
        let mut hasher = Keccak256::new();
        hasher.update(pk_no_prefix);
        let digest = hasher.finalize();
        let expected = digest[12..32].to_vec();

        (out, expected)
    }

    #[test]
    fn test_eip7702_process_and_cleanup() {
        let mut state = StateAdapter::new();
        let delegate_addr = vec![0xDE; 20];
        // Delegate bytecode does not need to be set — EIP-7702 writes a
        // designator that points at the delegate, not the bytecode itself.
        state.set_code(&delegate_addr, vec![0x60, 0x00, 0xFD]);

        let sk = test_signing_key(7);
        let (signature, expected_eoa) = sign_7702_auth(&sk, 1337, &delegate_addr, 0);

        let auth = Eip7702Authorization {
            chain_id: 1337,
            delegate_address: delegate_addr.clone(),
            nonce: 0,
            signature,
        };

        let upgraded = process_7702_authorizations(&[auth], 1337, &mut state).unwrap();
        assert_eq!(upgraded.len(), 1);
        let eoa = &upgraded[0];
        assert_eq!(eoa, &expected_eoa, "ecrecover must return signer's address");

        // Code slot holds the 23-byte designator, not the delegate's bytecode.
        let code = state.get_code(eoa).expect("code");
        assert_eq!(code.len(), EIP_7702_DESIGNATOR_LEN);
        assert_eq!(&code[..3], &EIP_7702_DESIGNATOR_PREFIX);
        assert_eq!(&code[3..], delegate_addr.as_slice());
        assert_eq!(parse_7702_designator(&code), Some(delegate_addr.clone()));

        cleanup_7702_authorizations(&upgraded, &mut state);
        assert_eq!(state.get_code(eoa), Some(vec![]));
    }

    #[test]
    fn test_eip7702_rejects_wrong_chain_id() {
        let mut state = StateAdapter::new();
        let sk = test_signing_key(9);
        let delegate = vec![0xDE; 20];
        let (signature, _) = sign_7702_auth(&sk, 9999, &delegate, 0);

        let auth = Eip7702Authorization {
            chain_id: 9999,
            delegate_address: delegate,
            nonce: 0,
            signature,
        };

        let err = process_7702_authorizations(&[auth], 1337, &mut state).unwrap_err();
        assert!(err.to_string().contains("chain_id"));
    }

    #[test]
    fn test_eip7702_rejects_empty_signature() {
        let mut state = StateAdapter::new();
        let auth = Eip7702Authorization {
            chain_id: 1337,
            delegate_address: vec![0xDE; 20],
            nonce: 0,
            signature: vec![],
        };
        assert!(process_7702_authorizations(&[auth], 1337, &mut state).is_err());
    }

    #[test]
    fn test_eip7702_rejects_malformed_signature_length() {
        let mut state = StateAdapter::new();
        let auth = Eip7702Authorization {
            chain_id: 1337,
            delegate_address: vec![0xDE; 20],
            nonce: 0,
            signature: vec![0x01; 64], // should be 65 bytes (r||s||y_parity)
        };
        assert!(process_7702_authorizations(&[auth], 1337, &mut state).is_err());
    }

    #[test]
    fn test_eip7702_rejects_duplicate_eoa() {
        let mut state = StateAdapter::new();
        let delegate = vec![0xDE; 20];
        let sk = test_signing_key(11);
        let (signature, _) = sign_7702_auth(&sk, 1337, &delegate, 0);

        // Identical authorizations recover the same EOA.
        let auth1 = Eip7702Authorization {
            chain_id: 1337,
            delegate_address: delegate.clone(),
            nonce: 0,
            signature,
        };
        let auth2 = auth1.clone();

        let err = process_7702_authorizations(&[auth1, auth2], 1337, &mut state).unwrap_err();
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn test_eip7702_rejects_wrong_nonce() {
        let mut state = StateAdapter::new();
        let delegate = vec![0xDE; 20];
        let sk = test_signing_key(13);

        // Authorization says nonce=5, but EOA's on-chain nonce is still 0.
        let (signature, _) = sign_7702_auth(&sk, 1337, &delegate, 5);
        let auth = Eip7702Authorization {
            chain_id: 1337,
            delegate_address: delegate,
            nonce: 5,
            signature,
        };

        let err = process_7702_authorizations(&[auth], 1337, &mut state).unwrap_err();
        match err {
            VmError::InvalidNonce { .. } => {}
            other => panic!("expected InvalidNonce, got {:?}", other),
        }
    }

    #[test]
    fn test_eip7702_signing_preimage_has_magic_and_rlp() {
        let auth = Eip7702Authorization {
            chain_id: 1337,
            delegate_address: vec![0xDE; 20],
            nonce: 0,
            signature: vec![],
        };
        let preimage = auth.signing_data();
        assert_eq!(preimage[0], EIP_7702_MAGIC, "first byte must be MAGIC=0x05");

        // Body must RLP-decode to [chain_id, address, nonce].
        let rlp_body = rlp::Rlp::new(&preimage[1..]);
        assert!(rlp_body.is_list());
        assert_eq!(rlp_body.item_count().unwrap(), 3);
        let chain_id: u64 = rlp_body.val_at(0).unwrap();
        let addr: Vec<u8> = rlp_body.val_at(1).unwrap();
        let nonce: u64 = rlp_body.val_at(2).unwrap();
        assert_eq!(chain_id, 1337);
        assert_eq!(addr, vec![0xDE; 20]);
        assert_eq!(nonce, 0);
    }

    #[test]
    fn test_eip7702_designator_roundtrip() {
        let delegate = vec![0xAB; 20];
        let designator = build_7702_designator(&delegate).unwrap();
        assert_eq!(designator.len(), 23);
        assert_eq!(&designator[..3], &[0xef, 0x01, 0x00]);
        assert_eq!(parse_7702_designator(&designator), Some(delegate));
        // Non-designator code is not detected.
        assert_eq!(parse_7702_designator(&[0x60, 0x00]), None);
        assert_eq!(parse_7702_designator(&[0xef, 0x01, 0x00, 0x01]), None);
    }
}
