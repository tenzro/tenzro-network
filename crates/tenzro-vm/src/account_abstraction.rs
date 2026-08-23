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
//! use tenzro_vm::account_abstraction::{
//!     AccountFactory, AccountModule, EntryPoint, Nonce, UserOperation,
//! };
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
//!     // `get_nonce` is 2-D per EIP-4337 v0.8 and takes a 192-bit key;
//!     // `get_nonce_default_key` is the key=0 ordered stream, and `Nonce`
//!     // packs it into the 32-byte `(key << 64) | seq` field.
//!     nonce: Nonce::from_seq(entry_point.get_nonce_default_key(&account.address))
//!         .to_bytes(),
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
//! // Process bundle of operations (async — handle_ops dispatches to the VM runtime
//! // when one is attached via `with_runtime`).
//! // let receipts = entry_point.handle_ops(vec![user_op]).await;
//! # Ok(())
//! # }
//! ```

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use tracing::info;

use tenzro_crypto::hash::keccak256;
use tenzro_storage::{CF_AGENTS, KvStore};

use crate::error::VmError;
use crate::runtime::MultiVmRuntime;
use crate::state_adapter::StateAdapter;
use crate::traits::{VmState, VmType};
use crate::types::VmTransaction;

/// Persistence prefix for per-sender, per-key AA nonces in `CF_AGENTS`.
/// Layout: `aa/nonce/{20-byte sender hex}/{24-byte key hex}` ->
/// 8-byte big-endian u64 sequence (next-expected seq).
///
/// EIP-4337 v0.8 wire nonce is a `uint256` packed as
/// `(uint192 key << 64) | uint64 seq`. The EntryPoint enforces strict
/// monotonic `seq` per `(sender, key)` pair — different keys are
/// independent and may execute in any order. Studio uses one key per
/// session so parallel offline signing doesn't stomp seq.
const AA_NONCE_PREFIX: &str = "aa/nonce/";

/// Gas penalty threshold for v0.8: if unused gas is below this value, no penalty applies.
const GAS_PENALTY_THRESHOLD: u64 = 40_000;

/// 2-D nonce per EIP-4337 v0.8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce {
    /// 24-byte (192-bit) key, big-endian.
    pub key: [u8; 24],
    /// 8-byte (64-bit) sequence portion.
    pub seq: u64,
}

impl Nonce {
    /// A nonce with `key = 0` and the given `seq` — the default-key
    /// ordered stream every legacy wallet uses.
    pub const fn from_seq(seq: u64) -> Self {
        Self {
            key: [0u8; 24],
            seq,
        }
    }

    /// Pack `(key, seq)` into the 32-byte big-endian uint256 the wire
    /// expects: `[key[0..24] ‖ seq.to_be_bytes()]`.
    pub fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..24].copy_from_slice(&self.key);
        out[24..].copy_from_slice(&self.seq.to_be_bytes());
        out
    }

    /// Unpack a 32-byte big-endian uint256 into `(key, seq)`.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut key = [0u8; 24];
        key.copy_from_slice(&bytes[..24]);
        let mut seq_buf = [0u8; 8];
        seq_buf.copy_from_slice(&bytes[24..]);
        Self {
            key,
            seq: u64::from_be_bytes(seq_buf),
        }
    }

    /// Hex form of the key portion (48 chars) for storage paths.
    pub fn key_hex(&self) -> String {
        hex::encode(self.key)
    }
}

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

    /// Invalid nonce — strict monotonic seq enforced per `(sender, key)`.
    #[error("Invalid nonce: expected seq {expected}, got seq {got} (key 0x{key_hex})")]
    InvalidNonce {
        expected: u64,
        got: u64,
        key_hex: String,
    },

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

    /// Anti-replay parameter — 32-byte big-endian uint256 per EIP-4337
    /// v0.8, packed `(uint192 key << 64) | uint64 seq`. Use [`Nonce`]
    /// helpers to read the key/seq fields; storage of the raw bytes
    /// keeps EIP-712 encoding a direct copy.
    pub nonce: [u8; 32],

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
        // Nonce is already the 32-byte big-endian uint256 (2-D packed).
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&encode_address(&self.factory));
        data.extend_from_slice(&keccak256_bytes(&self.factory_data));
        data.extend_from_slice(&keccak256_bytes(&self.call_data));
        data.extend_from_slice(&encode_u64_as_uint256(self.call_gas_limit));
        data.extend_from_slice(&encode_u64_as_uint256(self.verification_gas_limit));
        data.extend_from_slice(&encode_u64_as_uint256(self.pre_verification_gas));
        data.extend_from_slice(&encode_u128_as_uint256(self.max_fee_per_gas));
        data.extend_from_slice(&encode_u128_as_uint256(self.max_priority_fee_per_gas));
        data.extend_from_slice(&encode_address(&self.paymaster));
        data.extend_from_slice(&encode_u64_as_uint256(
            self.paymaster_verification_gas_limit,
        ));
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
        let mut total = self
            .call_gas_limit
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

    /// Anti-replay parameter — 32-byte big-endian uint256 per EIP-4337
    /// v0.8, packed `(uint192 key << 64) | uint64 seq`.
    pub nonce: [u8; 32],

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
                    self.paymaster_and_data[20..28]
                        .try_into()
                        .unwrap_or([0u8; 8]),
                );
                let post_gas = u64::from_be_bytes(
                    self.paymaster_and_data[28..36]
                        .try_into()
                        .unwrap_or([0u8; 8]),
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
///
/// Gas accounting collapses to the EVM balance: the smart account's EVM
/// balance is debited for `gas_used * gas_price` after a successful UserOp,
/// rather than maintaining a separate per-account deposit pool. The legacy
/// `deposit_to` / `get_deposit` / EntryPoint-side balance tracking has been
/// removed — the account balance held in `VmState` is the single source of
/// truth for whether a UserOp can pay for itself.
///
/// `Debug` is implemented manually because `Arc<MultiVmRuntime>` and
/// `Arc<dyn KvStore>` don't implement `Debug` themselves.
pub struct EntryPoint {
    /// EntryPoint contract address
    pub address: Vec<u8>,

    /// Chain ID for EIP-712 domain separator
    pub chain_id: u64,

    /// Supported account factory addresses
    pub supported_account_factories: Vec<Vec<u8>>,

    /// 2-D nonces keyed by `(sender, nonce_key)`. EIP-4337 v0.8: each
    /// `(sender, key)` pair owns its own strict-monotonic `seq`. The
    /// stored `u64` is the **next expected** seq under that pair.
    /// Persisted to `CF_AGENTS` under
    /// `aa/nonce/{sender_hex}/{key_hex}` when `storage` is set;
    /// hydrated via `hydrate_nonces()`.
    pub nonces: DashMap<(Vec<u8>, [u8; 24]), u64>,

    /// Total operations processed
    pub total_ops_processed: AtomicU64,

    /// ERC-7579 validator registry. `validate_user_op` routes to the sender's
    /// installed validators in priority order.
    ///
    /// Optional only in construction order — an `EntryPoint` without one
    /// cannot verify any signature, so it refuses every UserOperation rather
    /// than admitting them unchecked. The node always attaches one.
    pub validator_registry: Option<Arc<crate::aa_validators::ValidatorRegistry>>,

    /// Optional VM runtime used to actually execute UserOp `call_data` against
    /// the smart account. When unset, `handle_single_op` falls back to a
    /// no-op execution path that only validates and charges gas — useful for
    /// unit tests that don't need real EVM execution.
    pub runtime: Option<Arc<MultiVmRuntime>>,

    /// Optional persistent storage backend for nonces and receipts. When
    /// set, `handle_single_op` writes the post-execution nonce through to
    /// `CF_AGENTS` and indexes the receipt under `aa/receipt/{op_hash_hex}`.
    pub storage: Option<Arc<dyn KvStore>>,

    /// Receipts indexed by UserOp hash. Populated on every `handle_single_op`
    /// call. Bounded by caller (the bundler / RPC layer is responsible for
    /// pruning old entries); the EntryPoint itself does not evict.
    pub receipts: DashMap<Vec<u8>, UserOpReceipt>,

    /// Optional TNZO bootstrap paymaster. Sponsors the **one-shot**
    /// first UserOp of a newly-spawned autonomous TEE-resident agent.
    /// Only fires when the incoming UserOp's paymaster address matches
    /// the bootstrap paymaster's address AND `op.factory` is non-empty
    /// (bootstrap signal). Detailed gating lives in the paymaster itself
    /// (TEE attestation freshness, ERC-8004 registration, one-shot
    /// consumption ledger). Unset = legacy "paymaster-sponsored ops
    /// skip sender debit, no paymaster debit either" behaviour.
    pub bootstrap_paymaster:
        Option<Arc<RwLock<crate::aa_bootstrap_paymaster::TnzoBootstrapPaymaster>>>,
}

impl std::fmt::Debug for EntryPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryPoint")
            .field("address", &self.address)
            .field("chain_id", &self.chain_id)
            .field(
                "supported_account_factories",
                &self.supported_account_factories,
            )
            .field("nonces", &self.nonces)
            .field("total_ops_processed", &self.total_ops_processed)
            .field("validator_registry", &self.validator_registry.is_some())
            .field("runtime", &self.runtime.is_some())
            .field("storage", &self.storage.is_some())
            .field("receipts_len", &self.receipts.len())
            .field("bootstrap_paymaster", &self.bootstrap_paymaster.is_some())
            .finish()
    }
}

impl EntryPoint {
    /// Create a new EntryPoint with default chain_id (1337)
    pub fn new(address: Vec<u8>) -> Self {
        Self {
            address,
            chain_id: 1337,
            supported_account_factories: Vec::new(),
            nonces: DashMap::new(),
            total_ops_processed: AtomicU64::new(0),
            validator_registry: None,
            runtime: None,
            storage: None,
            receipts: DashMap::new(),
            bootstrap_paymaster: None,
        }
    }

    /// Attach the TNZO bootstrap paymaster (builder pattern). When set,
    /// `handle_single_op` routes paymaster-sponsored UserOps whose
    /// `op.paymaster` address matches the bootstrap paymaster through
    /// `TnzoBootstrapPaymaster::sponsor` — which atomically debits the
    /// paymaster's balance and records the sender as consumed (one-shot).
    /// Other paymaster addresses fall through to the legacy "skip
    /// sender debit, no paymaster debit" behaviour and can be wired by
    /// the bundler in a follow-up.
    pub fn with_bootstrap_paymaster(
        mut self,
        paymaster: Arc<RwLock<crate::aa_bootstrap_paymaster::TnzoBootstrapPaymaster>>,
    ) -> Self {
        self.bootstrap_paymaster = Some(paymaster);
        self
    }

    /// Attach an ERC-7579 validator registry (builder pattern). Once set,
    /// signature validation is delegated to the installed validator modules
    /// for the sender account. See `crate::aa_validators` for the trait and
    /// reference modules.
    pub fn with_validator_registry(
        mut self,
        registry: Arc<crate::aa_validators::ValidatorRegistry>,
    ) -> Self {
        self.validator_registry = Some(registry);
        self
    }

    /// Set the chain ID for EIP-712 domain separator (builder pattern)
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// Attach the multi-VM runtime that will execute UserOp `call_data`.
    /// When set, `handle_single_op` synthesizes a `VmTransaction` from the
    /// UserOp and runs it through `MultiVmRuntime::execute_transaction`.
    /// Without this, the EntryPoint only validates and charges gas.
    pub fn with_runtime(mut self, runtime: Arc<MultiVmRuntime>) -> Self {
        self.runtime = Some(runtime);
        self
    }

    /// Attach a persistent storage backend. Nonces are written through to
    /// `CF_AGENTS` under the `aa/nonce/` prefix on every successful UserOp;
    /// receipts are also persisted under `aa/receipt/`. The caller should
    /// invoke `hydrate_nonces()` after construction to restore in-memory
    /// state from storage.
    pub fn with_storage(mut self, storage: Arc<dyn KvStore>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Restore the in-memory 2-D nonce table from storage. Walks all
    /// keys under `aa/nonce/` in `CF_AGENTS`, parses the
    /// `{sender_hex}/{key_hex}` path, and reads the 8-byte big-endian
    /// next-seq value. No-op when storage isn't attached.
    pub fn hydrate_nonces(&self) -> Result<usize, AccountAbstractionError> {
        let Some(storage) = self.storage.as_ref() else {
            return Ok(0);
        };
        let prefix = AA_NONCE_PREFIX.as_bytes();
        let keys = storage
            .get_keys_with_prefix(CF_AGENTS, prefix)
            .map_err(|e| {
                AccountAbstractionError::InvalidUserOp(format!(
                    "hydrate_nonces: list keys failed: {e}"
                ))
            })?;
        let mut count = 0usize;
        for storage_key in keys {
            // storage_key = "aa/nonce/{sender_hex}/{key_hex}"
            let suffix = match std::str::from_utf8(&storage_key[prefix.len()..]) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut parts = suffix.splitn(2, '/');
            let sender_hex = match parts.next() {
                Some(s) => s,
                None => continue,
            };
            let key_hex = match parts.next() {
                Some(s) => s,
                None => continue, // legacy 1-D row — skip
            };
            let sender = match hex::decode(sender_hex) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let key_bytes = match hex::decode(key_hex) {
                Ok(v) if v.len() == 24 => {
                    let mut arr = [0u8; 24];
                    arr.copy_from_slice(&v);
                    arr
                }
                _ => continue,
            };
            let value = match storage.get(CF_AGENTS, &storage_key) {
                Ok(Some(v)) => v,
                _ => continue,
            };
            if value.len() != 8 {
                continue;
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&value);
            let seq = u64::from_be_bytes(buf);
            self.nonces.insert((sender, key_bytes), seq);
            count += 1;
        }
        Ok(count)
    }

    /// Persist the next-expected seq under `(sender, key)`. No-op when
    /// storage isn't attached. Errors logged but don't fail the UserOp
    /// — in-memory state still reflects the increment.
    fn persist_nonce(&self, sender: &[u8], nonce_key: &[u8; 24], seq: u64) {
        let Some(storage) = self.storage.as_ref() else {
            return;
        };
        let storage_key = format!(
            "{}{}/{}",
            AA_NONCE_PREFIX,
            hex::encode(sender),
            hex::encode(nonce_key),
        );
        if let Err(e) = storage.put(CF_AGENTS, storage_key.as_bytes(), &seq.to_be_bytes()) {
            tracing::warn!(
                sender = %hex::encode(sender),
                key = %hex::encode(nonce_key),
                seq,
                error = %e,
                "failed to persist AA nonce"
            );
        }
    }

    /// Persist a receipt to storage under `aa/receipt/{op_hash_hex}`. No-op
    /// when storage is not attached.
    fn persist_receipt(&self, receipt: &UserOpReceipt) {
        let Some(storage) = self.storage.as_ref() else {
            return;
        };
        let key = format!("aa/receipt/{}", hex::encode(&receipt.user_op_hash));
        let value = match serde_json::to_vec(receipt) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "failed to serialize AA receipt");
                return;
            }
        };
        if let Err(e) = storage.put(CF_AGENTS, key.as_bytes(), &value) {
            tracing::warn!(error = %e, "failed to persist AA receipt");
        }
    }

    /// Look up a previously processed UserOp receipt by hash. Checks the
    /// in-memory cache first, then storage if attached.
    pub fn get_receipt(&self, op_hash: &[u8]) -> Option<UserOpReceipt> {
        if let Some(r) = self.receipts.get(op_hash) {
            return Some(r.clone());
        }
        let storage = self.storage.as_ref()?;
        let key = format!("aa/receipt/{}", hex::encode(op_hash));
        let bytes = storage.get(CF_AGENTS, key.as_bytes()).ok().flatten()?;
        serde_json::from_slice::<UserOpReceipt>(&bytes).ok()
    }

    /// Add a supported account factory
    pub fn add_factory(&mut self, factory_address: Vec<u8>) {
        if !self.supported_account_factories.contains(&factory_address) {
            self.supported_account_factories.push(factory_address);
        }
    }

    /// Get the next-expected seq under `(sender, key)`. Returns `0`
    /// when never used. EIP-4337 `getNonce(sender, key)` equivalent:
    /// callers pack `(key, seq)` via [`Nonce`] for the on-chain shape.
    pub fn get_nonce(&self, sender: &[u8], key: &[u8; 24]) -> u64 {
        self.nonces
            .get(&(sender.to_vec(), *key))
            .map(|n| *n)
            .unwrap_or(0)
    }

    /// Default-key convenience: `get_nonce(sender, &[0u8; 24])`. The
    /// pattern most ordered-stream wallets use. Tests that pre-date
    /// the 2-D migration land here.
    pub fn get_nonce_default_key(&self, sender: &[u8]) -> u64 {
        self.get_nonce(sender, &[0u8; 24])
    }

    /// Increment and return the **previous** seq under `(sender, key)`.
    /// Stored value advances to `seq + 1`.
    fn increment_nonce(&self, sender: &[u8], key: &[u8; 24]) -> u64 {
        let mut entry = self.nonces.entry((sender.to_vec(), *key)).or_insert(0);
        let current = *entry;
        *entry += 1;
        current
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
        // Validate 2-D nonce: unpack, look up next expected seq under
        // (sender, key), require strict equality. Different keys are
        // independent — a UserOp under key A doesn't affect seq under
        // key B.
        let op_nonce = Nonce::from_bytes(op.nonce);
        let expected_seq = self.get_nonce(&op.sender, &op_nonce.key);
        if op_nonce.seq != expected_seq {
            return Err(AccountAbstractionError::InvalidNonce {
                expected: expected_seq,
                got: op_nonce.seq,
                key_hex: op_nonce.key_hex(),
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

        // Validate the signature through the sender's installed ERC-7579
        // validator modules (the first non-failure validator wins).
        //
        // There is no fallback. The previous one accepted any non-empty
        // signature for an account with no installed validator, which is not
        // a signature check -- `signature = [0x00]` passed it. An account
        // whose signature semantics nothing owns cannot have its signature
        // verified, so its operations are refused rather than admitted.
        if let Some(registry) = self.validator_registry.as_ref() {
            // Compute the canonical UserOp hash bound to this EntryPoint
            // (chain_id + address). 32-byte preimage matches what the on-chain
            // EntryPoint passes to `IValidator::validateUserOp`.
            let mut op_hash = [0u8; 32];
            let h = op.hash(self.chain_id, &self.address);
            let take = h.len().min(32);
            op_hash[..take].copy_from_slice(&h[..take]);

            // Account has at least one installed validator → strict route.
            if !registry.list_for_account(&op.sender).is_empty() {
                let result = registry
                    .validate_user_op(op, &op_hash)
                    .map_err(|e| AccountAbstractionError::InvalidUserOp(e.to_string()))?;
                if result.is_failure() {
                    return Err(AccountAbstractionError::InvalidSignature);
                }
                // The validator module owns the signature semantics; nothing
                // further to check here.
            } else {
                return Err(AccountAbstractionError::InvalidUserOp(
                    "sender has no installed ERC-7579 validator module, so its                      signature cannot be verified; install one before submitting                      UserOperations"
                        .to_string(),
                ));
            }
        } else {
            return Err(AccountAbstractionError::InvalidUserOp(
                "EntryPoint has no validator registry attached, so UserOperation                  signatures cannot be verified"
                    .to_string(),
            ));
        }

        // Balance sufficiency is verified at execution time against the
        // smart-account's EVM balance in `VmState` (the single source of
        // truth post-Phase B Thread 3c). The legacy EntryPoint-side deposit
        // check has been removed because account balance lives in the
        // unified `VmState`, not in a parallel deposit pool.

        // Validate account creation (v0.8: factory field must be a valid address)
        if op.is_account_creation() && op.factory.len() < 20 {
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

    /// Handle a bundle of UserOperations.
    ///
    /// This is the main entry point for processing operations. It validates,
    /// executes, and settles payment for each operation in order. Async
    /// because each call dispatches to `MultiVmRuntime::execute_transaction`,
    /// which is itself async. UserOps within a bundle execute sequentially —
    /// each UserOp's nonce increment must be visible to the next.
    pub async fn handle_ops(&self, ops: Vec<UserOperation>) -> Vec<UserOpReceipt> {
        let mut receipts = Vec::with_capacity(ops.len());
        for op in ops {
            let receipt = self.handle_single_op(op).await;
            receipts.push(receipt);
        }
        receipts
    }

    /// Handle a single UserOperation: validate → execute → charge gas.
    ///
    /// Execution flow:
    /// 1. Validate the UserOp (nonce, signature via validator registry, gas limits).
    /// 2. Synthesize a `VmTransaction` with `to = sender` (smart-account self-call)
    ///    and `data = call_data`, dispatch through `MultiVmRuntime` if attached.
    ///    Without a runtime, treat execution as a no-op success — useful for
    ///    unit tests of the validation/accounting pipeline.
    /// 3. Apply v0.8 gas penalty: if unused gas < 40,000, charge actual gas;
    ///    otherwise charge the full limit.
    /// 4. Debit `gas_used * gas_price` from the smart account's EVM balance
    ///    (no separate deposit pool). Paymaster-sponsored ops skip the debit
    ///    on the sender's side; the paymaster integration lands in a follow-up.
    /// 5. On success, increment + persist nonce, persist receipt.
    pub async fn handle_single_op(&self, op: UserOperation) -> UserOpReceipt {
        let op_hash = op.hash(self.chain_id, &self.address);

        // Phase 1: Validation. Failures short-circuit with a failure receipt
        // and DO NOT increment the nonce — replay protection only kicks in
        // for accepted UserOps.
        if let Err(e) = self.validate_user_op(&op) {
            tracing::error!("UserOp validation failed: {}", e);
            let receipt = UserOpReceipt {
                user_op_hash: op_hash.clone(),
                success: false,
                gas_used: 0,
                actual_gas_cost: 0,
                logs: vec![format!("Validation failed: {}", e).into_bytes()],
            };
            self.receipts.insert(op_hash.clone(), receipt.clone());
            self.persist_receipt(&receipt);
            return receipt;
        }

        // Phase 2: Execution. Build a synthetic VmTransaction targeting the
        // smart account itself; the account's contract code is responsible
        // for unpacking call_data into the actual operation (transfer, call,
        // batch, etc.). The signature on the inner VmTransaction is None
        // because admission has already verified the UserOp signature via
        // the validator registry — `MultiVmRuntime::execute_transaction`
        // accepts unsigned txs from internal sources (line 248-253 of
        // runtime.rs).
        let (exec_success, exec_gas_used, exec_logs) = match self.runtime.as_ref() {
            Some(runtime) => {
                // Decode the canonical Safe / Biconomy Nexus / ZeroDev Kernel
                // `execute(address to, uint256 value, bytes data)` selector
                // (0xb61d27f6). When present, dispatch the sub-call directly
                // (smart-account-as-router pattern). When absent, fall back
                // to the legacy self-call shape (smart-account-as-target)
                // so callers wiring raw bytecode keep working.
                let (sub_to, sub_value, sub_data) = decode_execute_calldata(&op.call_data)
                    .unwrap_or_else(|| (op.sender.clone(), 0u128, op.call_data.clone()));

                let tx = VmTransaction {
                    from: op.sender.clone(),
                    to: Some(sub_to),
                    value: sub_value,
                    data: sub_data,
                    gas_limit: op.call_gas_limit,
                    gas_price: op.max_fee_per_gas,
                    // Inner-tx counter is EOA-style u64; pass the seq
                    // portion of the outer UserOp's 2-D nonce.
                    nonce: Nonce::from_bytes(op.nonce).seq,
                    vm_type: VmType::Evm,
                    chain_id: self.chain_id,
                    signature: None,
                    public_key: None,
                    signing_digest: None,
                    // ERC-4337 EntryPoint executes user operations within
                    // a parent block context; the caller must supply the
                    // block timestamp via `with_block_timestamp_ms` when
                    // it actually goes through native VM time-dependent
                    // handlers. Left as None here because EntryPoint-
                    // driven sub-execution is not currently routed through
                    // native VM escrow/expiry paths.
                    block_timestamp_ms: None,
                };

                let mut state = match self.storage.as_ref() {
                    Some(s) => StateAdapter::with_storage(s.clone()),
                    None => StateAdapter::new(),
                };

                match runtime.execute_transaction(&tx, &mut state).await {
                    Ok(result) => {
                        let logs: Vec<Vec<u8>> =
                            result.logs.iter().map(|l| l.data.clone()).collect();
                        (result.success, result.gas_used, logs)
                    }
                    Err(e) => {
                        tracing::warn!(
                            sender = %hex::encode(&op.sender),
                            error = %e,
                            "UserOp execution failed"
                        );
                        (
                            false,
                            0u64,
                            vec![format!("Execution failed: {}", e).into_bytes()],
                        )
                    }
                }
            }
            None => {
                // No runtime attached — accounting-only path. Charge as if
                // the call ran to completion at the verification + pre +
                // call gas limits.
                let mut total_gas = op
                    .call_gas_limit
                    .saturating_add(op.verification_gas_limit)
                    .saturating_add(op.pre_verification_gas);
                if op.has_paymaster() {
                    total_gas = total_gas
                        .saturating_add(op.paymaster_verification_gas_limit)
                        .saturating_add(op.paymaster_post_op_gas_limit);
                }
                (
                    true,
                    total_gas,
                    vec![b"UserOp executed (no runtime)".to_vec()],
                )
            }
        };

        // Phase 3: Gas accounting with v0.8 penalty rule. When the unused
        // gas is below GAS_PENALTY_THRESHOLD (40,000), the user pays only
        // for actual gas consumed; otherwise they pay the full limit as
        // a penalty for over-reserving.
        let gas_limit = op.total_gas_limit();
        let unused_gas = gas_limit.saturating_sub(exec_gas_used);
        let chargeable_gas = if unused_gas < GAS_PENALTY_THRESHOLD {
            exec_gas_used
        } else {
            gas_limit
        };

        let actual_gas_price = op.max_fee_per_gas;
        let actual_gas_cost = (chargeable_gas as u128).saturating_mul(actual_gas_price);

        // Phase 4: Payment. Debit the smart account's EVM balance unless a
        // paymaster is sponsoring.
        //
        // Three branches:
        //   (a) No paymaster (`op.paymaster` empty) → debit the sender's
        //       balance for `actual_gas_cost`. Standard 4337 self-pay.
        //   (b) Paymaster is the configured bootstrap paymaster
        //       (`op.paymaster[..20] == bootstrap.address`) → dispatch
        //       `TnzoBootstrapPaymaster::sponsor(op)`. The paymaster's
        //       internal gating (TEE attestation freshness, ERC-8004
        //       registration, one-shot consumption ledger) is the
        //       authority; failures here translate into `success = false`.
        //   (c) Paymaster is some other address (operator-supplied
        //       app-level paymaster) → legacy behaviour: skip the sender
        //       debit. The bundler is responsible for the operator's
        //       paymaster integration; the EntryPoint does not double-
        //       debit. This branch is unchanged.
        let mut success = exec_success;
        if success {
            if !op.has_paymaster() {
                // Branch (a): self-pay.
                if let Some(runtime) = self.runtime.as_ref() {
                    let mut state = match self.storage.as_ref() {
                        Some(s) => StateAdapter::with_storage(s.clone()),
                        None => StateAdapter::new(),
                    };
                    let _ = runtime; // state created independently; runtime owns no state
                    let current_balance = state.get_balance(&op.sender);
                    if current_balance < actual_gas_cost {
                        tracing::warn!(
                            sender = %hex::encode(&op.sender),
                            required = actual_gas_cost,
                            available = current_balance,
                            "UserOp post-execution balance check failed"
                        );
                        success = false;
                    } else {
                        state.set_balance(&op.sender, current_balance - actual_gas_cost);
                        if let Err(e) = state.commit() {
                            tracing::error!(error = %e, "AA balance commit failed");
                            success = false;
                        }
                    }
                }
            } else if let Some(bootstrap) = self.bootstrap_paymaster.as_ref() {
                // Branch (b): bootstrap-paymaster-sponsored ops, when the
                // declared paymaster address matches the configured
                // bootstrap paymaster.
                let paymaster_addr_matches = {
                    let guard = bootstrap.read();
                    op.paymaster.len() >= 20 && op.paymaster[..20] == guard.address()[..20]
                };
                if paymaster_addr_matches {
                    let sponsor_result = bootstrap.write().sponsor(&op);
                    if let Err(e) = sponsor_result {
                        tracing::warn!(
                            sender = %hex::encode(&op.sender),
                            error = %e,
                            "Bootstrap paymaster refused sponsorship"
                        );
                        success = false;
                    } else {
                        info!(
                            sender = %hex::encode(&op.sender),
                            paymaster = %hex::encode(&op.paymaster[..20]),
                            gas_cost = actual_gas_cost,
                            "Bootstrap paymaster sponsored UserOp"
                        );
                    }
                }
                // else: branch (c) — non-bootstrap paymaster, legacy
                // skip-sender-debit behaviour (no-op here).
            }
            // else: no bootstrap paymaster configured AND op uses a
            // paymaster → branch (c) legacy behaviour.
        }

        if success {
            // Replay protection: increment + persist seq only under
            // THIS op's (sender, key). Failed ops leave seq intact so
            // the user retries with the same (key, seq).
            let op_key = Nonce::from_bytes(op.nonce).key;
            self.increment_nonce(&op.sender, &op_key);
            let next_seq = self.get_nonce(&op.sender, &op_key);
            self.persist_nonce(&op.sender, &op_key, next_seq);
            self.total_ops_processed.fetch_add(1, Ordering::Relaxed);
        }

        let receipt = UserOpReceipt {
            user_op_hash: op_hash.clone(),
            success,
            gas_used: exec_gas_used,
            actual_gas_cost,
            logs: exec_logs,
        };
        self.receipts.insert(op_hash, receipt.clone());
        self.persist_receipt(&receipt);
        receipt
    }

    /// Get statistics about the EntryPoint
    pub fn get_stats(&self) -> EntryPointStats {
        EntryPointStats {
            total_ops_processed: self.total_ops_processed.load(Ordering::Relaxed),
            total_accounts: self.nonces.len(),
        }
    }
}

/// Statistics about EntryPoint activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPointStats {
    pub total_ops_processed: u64,
    pub total_accounts: usize,
}

/// Account Factory for creating smart contract wallets
///
/// The factory creates deterministic addresses for accounts based on
/// the owner and salt, allowing counterfactual deployment.
pub struct AccountFactory {
    /// Factory contract address
    pub factory_address: Vec<u8>,

    /// Deployed accounts
    pub deployed_accounts: DashMap<Vec<u8>, SmartAccount>,

    /// Optional persistent storage. When present every `create_account` /
    /// `update_account` writes through to `CF_AGENTS` under the
    /// `smart_account/<addr>` prefix, and the constructor hydrates
    /// `deployed_accounts` from the same prefix. Production constructor
    /// `with_storage()` always wires this; tests use `new()` for the
    /// in-memory-only path.
    storage: Option<std::sync::Arc<dyn tenzro_storage::KvStore>>,
}

impl std::fmt::Debug for AccountFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountFactory")
            .field("factory_address", &self.factory_address)
            .field("deployed_accounts", &self.deployed_accounts)
            .field("storage", &self.storage.as_ref().map(|_| "<KvStore>"))
            .finish()
    }
}

impl AccountFactory {
    /// Storage-key prefix for smart-account records in CF_AGENTS.
    /// `smart_account/<20-byte-address>`.
    const PERSIST_PREFIX: &'static [u8] = b"smart_account/";

    /// Compute the on-disk key for an account.
    pub fn persist_key(address: &[u8]) -> Vec<u8> {
        let mut k = Self::PERSIST_PREFIX.to_vec();
        k.extend_from_slice(address);
        k
    }

    /// Create a new AccountFactory (in-memory only).
    pub fn new(factory_address: Vec<u8>) -> Self {
        Self {
            factory_address,
            deployed_accounts: DashMap::new(),
            storage: None,
        }
    }

    /// Construct a persistent factory backed by `storage`. Hydrates
    /// `deployed_accounts` from `CF_AGENTS / smart_account/*` on
    /// construction. Every subsequent `create_account` /
    /// `update_account` writes through to the same column family.
    /// **Production constructor** — call instead of `new` whenever the
    /// node owns a `KvStore`.
    pub fn with_storage(
        factory_address: Vec<u8>,
        storage: std::sync::Arc<dyn tenzro_storage::KvStore>,
    ) -> Self {
        let factory = Self {
            factory_address,
            deployed_accounts: DashMap::new(),
            storage: Some(storage),
        };
        factory.hydrate();
        factory
    }

    fn hydrate(&self) {
        let Some(ref storage) = self.storage else {
            return;
        };
        let prefix = Self::PERSIST_PREFIX;
        let entries = match storage.scan_prefix(tenzro_storage::CF_AGENTS, prefix) {
            Ok(e) => e,
            Err(_) => return,
        };
        for (key, value) in entries {
            if key.len() <= prefix.len() {
                continue;
            }
            let addr = key[prefix.len()..].to_vec();
            if let Ok(account) = bincode::deserialize::<SmartAccount>(&value) {
                self.deployed_accounts.insert(addr, account);
            }
        }
    }

    fn persist(&self, account: &SmartAccount) {
        if let Some(ref storage) = self.storage
            && let Ok(bytes) = bincode::serialize(account)
        {
            let _ = storage.put(
                tenzro_storage::CF_AGENTS,
                &Self::persist_key(&account.address),
                &bytes,
            );
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
            validator_modules: std::collections::BTreeMap::new(),
        };

        self.persist(&account);
        self.deployed_accounts.insert(address, account.clone());
        account
    }

    /// Persist an updated smart account (validator install, nonce bump,
    /// social-recovery rotation, etc.). Use this instead of writing to
    /// `deployed_accounts` directly so the on-disk state stays in sync.
    pub fn update_account(&self, account: SmartAccount) {
        self.persist(&account);
        self.deployed_accounts
            .insert(account.address.clone(), account);
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

    /// Legacy in-account module enum (`AccountModule::SocialRecovery` /
    /// `SessionKey` / `SpendingLimit` / `Batching`). Retained for the
    /// non-modular smart-account path; ERC-7579 modular accounts use
    /// [`Self::validator_modules`] instead.
    pub modules: Vec<AccountModule>,

    /// ERC-7579 installed validator modules, keyed by 20-byte module address.
    /// Mirrors the on-chain account state set by `installModule(uint256 typeId,
    /// address module, bytes initData)`. The associated `ValidatorRegistry`
    /// holds the live `Arc<dyn IValidator>` instance — this map records the
    /// `(typeId, address, initData, priority)` triple so the account can
    /// re-issue installs to fresh registries (e.g. on rehydration) and answer
    /// `isModuleInstalled`.
    #[serde(default)]
    pub validator_modules:
        std::collections::BTreeMap<[u8; 20], crate::erc7579::ValidatorModuleConfig>,
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
        self.modules.iter().any(|m| {
            matches!(
                (module_type, m),
                ("social_recovery", AccountModule::SocialRecovery { .. })
                    | ("session_key", AccountModule::SessionKey { .. })
                    | ("spending_limit", AccountModule::SpendingLimit { .. })
                    | ("batching", AccountModule::Batching)
            )
        })
    }

    /// Get session keys that are currently valid
    pub fn get_valid_session_keys(&self, current_time: u64) -> Vec<Vec<u8>> {
        self.modules
            .iter()
            .filter_map(|m| {
                if let AccountModule::SessionKey {
                    key, expires_at, ..
                } = m
                    && *expires_at > current_time
                {
                    return Some(key.clone());
                }
                None
            })
            .collect()
    }

    // ---------------------------------------------------------------------
    // ERC-7579 modular validator installation
    // ---------------------------------------------------------------------

    /// Install an ERC-7579 validator module record on this account.
    ///
    /// The actual `Arc<dyn IValidator>` lives in the
    /// [`crate::aa_validators::ValidatorRegistry`]; this method just records
    /// the on-account `(typeId, address, initData, priority)` triple per
    /// ERC-7579 §3.2.
    ///
    /// `owner_authorized` enforces the custody invariant from
    /// `feedback_custody_enforce_at_signing_time`: pre-recovery (i.e. before
    /// any `SocialRecoveryValidator` is installed), only the root key may
    /// install validators. After recovery is installed, callers must instead
    /// use [`Self::install_validator_module_with_recovery`] with proof from
    /// the recovery quorum.
    pub fn install_validator_module(
        &mut self,
        config: crate::erc7579::ValidatorModuleConfig,
        owner_authorized: bool,
    ) -> Result<(), crate::aa_validators::ValidatorError> {
        if !owner_authorized {
            return Err(crate::aa_validators::ValidatorError::InvalidInput(
                "install_validator_module: owner key required pre-recovery; \
                 use install_validator_module_with_recovery once a SocialRecovery \
                 validator is installed"
                    .into(),
            ));
        }
        self.validator_modules.insert(config.module_address, config);
        Ok(())
    }

    /// Install an ERC-7579 validator module on a recovery-protected account.
    ///
    /// `recovery_authorized = true` represents proof that the recovery quorum
    /// has signed off on the install (the caller — typically the
    /// `SocialRecoveryValidator` itself — is responsible for verifying the
    /// guardian quorum signature before invoking this method). The boolean
    /// gate is the account-side enforcement; the cryptographic check lives in
    /// the validator module.
    pub fn install_validator_module_with_recovery(
        &mut self,
        config: crate::erc7579::ValidatorModuleConfig,
        recovery_authorized: bool,
    ) -> Result<(), crate::aa_validators::ValidatorError> {
        if !recovery_authorized {
            return Err(crate::aa_validators::ValidatorError::InvalidInput(
                "install_validator_module_with_recovery: recovery quorum \
                 authorisation required"
                    .into(),
            ));
        }
        self.validator_modules.insert(config.module_address, config);
        Ok(())
    }

    /// Uninstall an ERC-7579 validator module record. Returns `true` iff a
    /// module was previously installed at `module_address`.
    pub fn uninstall_validator_module(&mut self, module_address: &[u8; 20]) -> bool {
        self.validator_modules.remove(module_address).is_some()
    }

    /// `true` iff an ERC-7579 validator module is installed at
    /// `module_address` on this account.
    pub fn is_validator_installed(&self, module_address: &[u8; 20]) -> bool {
        self.validator_modules.contains_key(module_address)
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
    ///
    /// NOTE: The TEE-attestation-gated bootstrap paymaster for
    /// autonomous-agent first-transactions is a dedicated primitive
    /// living in [`crate::aa_bootstrap_paymaster::TnzoBootstrapPaymaster`].
    /// That one carries an `AgentRegistryLookup`, an
    /// `AttestationVerifier`, and a per-bootstrap-attempt nonce ledger
    /// so the same authorization cannot be sponsored twice. Use it
    /// for the agent-bootstrap path; use this basic Paymaster only for
    /// application-level gas sponsorship where the policy is
    /// "I have balance, I sponsor."
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
pub fn recover_eoa_from_7702_signature(auth: &Eip7702Authorization) -> Result<Vec<u8>, VmError> {
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
    let signature =
        Signature::from_bytes(&sig_bytes.into()).map_err(|_| VmError::InvalidSignature)?;

    let hash = auth.signing_hash();
    let recovered = VerifyingKey::recover_from_prehash(&hash, &signature, recovery_id)
        .map_err(|_| VmError::InvalidSignature)?;

    // Ethereum address = keccak256(uncompressed_pubkey[1..])[12..32]
    let encoded = recovered.to_sec1_point(false);
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
/// **persistently** writes the 23-byte designator into the EOA's code slot.
///
/// Per EIP-7702 the delegation **survives the transaction** — the EOA stays
/// delegated until a subsequent tx submits a fresh authorization (including
/// one delegating to `address(0)` to clear it). This matches mainnet semantics
/// post-Pectra. Callers MUST NOT roll the code slot back at end-of-tx.
///
/// Per the spec, the EOA's nonce is also incremented as part of consuming the
/// authorization (EIP-7702 §3) so a single authorization cannot be replayed.
/// Returns the list of EOAs that were delegated.
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

        // Per EIP-7702 §3: increment the EOA's nonce so the authorization
        // (which embeds the old nonce) cannot be replayed.
        state.set_nonce(&eoa_address, current_nonce.saturating_add(1));

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

/// Canonical Safe / Biconomy Nexus / ZeroDev Kernel selector for
/// `execute(address to, uint256 value, bytes data)` — same wire format
/// every major smart-account stack uses, so a UserOp built by an external
/// tool (Biconomy SDK, Pimlico bundler, web wallet) is dispatched here.
pub const EXECUTE_SELECTOR: [u8; 4] = [0xb6, 0x1d, 0x27, 0xf6];

/// Encode `execute(address,uint256,bytes)` calldata.
///
/// The inverse of [`decode_execute_calldata`], and the shape any client
/// building a UserOperation has to produce for the EntryPoint to route
/// the call anywhere other than back at the sender. Layout is documented
/// on the decoder.
pub fn encode_execute_calldata(to: &[u8; 20], value: u128, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(132 + data.len().div_ceil(32) * 32);
    out.extend_from_slice(&EXECUTE_SELECTOR);
    // slot 1: to (32 bytes, left-padded)
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(to);
    // slot 2: value (32 bytes BE)
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&value.to_be_bytes());
    // slot 3: offset = 0x60 (96)
    let mut off = [0u8; 32];
    off[31] = 0x60;
    out.extend_from_slice(&off);
    // slot 4: length
    let mut len = [0u8; 32];
    len[16..].copy_from_slice(&(data.len() as u128).to_be_bytes());
    out.extend_from_slice(&len);
    // data + zero-pad to 32
    out.extend_from_slice(data);
    let pad = (32 - data.len() % 32) % 32;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// Decode `execute(address,uint256,bytes)` calldata into `(to, value, data)`.
///
/// ABI layout (all big-endian, 32-byte slots):
///   [0..4]      selector 0xb61d27f6
///   [4..36]     to (left-padded to 32, low 20 bytes are the address)
///   [36..68]    value (uint256; low 128 bits are the VmTransaction.value)
///   [68..100]   offset of `data` (always 0x60 for this layout)
///   [100..132]  length of `data`
///   [132..]     `data` bytes
///
/// Returns `None` when the calldata doesn't match (the caller falls back
/// to the legacy self-call shape).
fn decode_execute_calldata(call_data: &[u8]) -> Option<(Vec<u8>, u128, Vec<u8>)> {
    if call_data.len() < 132 {
        return None;
    }
    if call_data[0..4] != EXECUTE_SELECTOR {
        return None;
    }

    // to: low 20 bytes of slot 0
    let to = call_data[16..36].to_vec();

    // value: uint256 → u128. Reject the call if the high 128 bits are
    // non-zero so we never silently truncate.
    if call_data[36..52].iter().any(|b| *b != 0) {
        return None;
    }
    let mut v_bytes = [0u8; 16];
    v_bytes.copy_from_slice(&call_data[52..68]);
    let value = u128::from_be_bytes(v_bytes);

    // offset must be 0x60 for the canonical single-call layout.
    let mut off_bytes = [0u8; 32];
    off_bytes.copy_from_slice(&call_data[68..100]);
    let offset = u128::from_be_bytes(off_bytes[16..32].try_into().ok()?);
    if offset != 0x60 {
        return None;
    }

    // length of `data`
    let mut len_bytes = [0u8; 32];
    len_bytes.copy_from_slice(&call_data[100..132]);
    let data_len = u128::from_be_bytes(len_bytes[16..32].try_into().ok()?) as usize;

    let data_start: usize = 132;
    let data_end = data_start.checked_add(data_len)?;
    if call_data.len() < data_end {
        return None;
    }
    let data = call_data[data_start..data_end].to_vec();

    Some((to, value, data))
}

#[cfg(test)]
mod tests {

    /// An `EntryPoint` whose `senders` can actually be validated.
    ///
    /// Validation routes through installed ERC-7579 validator modules and has
    /// no fallback, so a test that is not about signatures still needs one.
    /// `NoOpValidator` accepts any non-empty signature — the same rule the
    /// removed length-only fallback applied — except that it is installed
    /// deliberately here rather than applying to every account everywhere.
    fn entry_point_with_validators(ep_address: Vec<u8>, senders: &[&[u8]]) -> EntryPoint {
        use crate::aa_validators::{
            ModuleAttestation, ModuleType, NoOpValidator, ValidatorRegistry,
        };
        let registry = ValidatorRegistry::new();
        let module_addr = [0x7Au8; 20];
        registry.attestations().attest(ModuleAttestation {
            module_address: module_addr,
            module_type: ModuleType::Validator,
            registry: *registry.trusted_registry(),
            attester: [0xAA; 20],
            attestation_data: b"test".to_vec(),
            revoked: false,
        });
        for sender in senders {
            registry
                .install(
                    sender.to_vec(),
                    ModuleType::Validator,
                    std::sync::Arc::new(NoOpValidator::new(module_addr)),
                    100,
                    vec![],
                )
                .expect("install NoOpValidator for test sender");
        }
        EntryPoint::new(ep_address).with_validator_registry(std::sync::Arc::new(registry))
    }
    use super::*;

    #[test]
    fn test_entry_point_creation() {
        let entry_point = EntryPoint::new(vec![0x01; 20]);
        assert_eq!(entry_point.address, vec![0x01; 20]);
        assert_eq!(entry_point.get_nonce_default_key(&[0x02; 20]), 0);
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
        assert_ne!(
            address1, address3,
            "Different salts should give different addresses"
        );

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
            nonce: Nonce::from_seq(nonce).to_bytes(),
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
        let sender = vec![0x02; 20];
        let entry_point = entry_point_with_validators(vec![0x01; 20], &[&sender]);

        let user_op = test_user_op(sender.clone(), 0);

        // Should validate successfully — balance check happens at execution
        // time in `handle_single_op`, not in `validate_user_op`.
        assert!(entry_point.validate_user_op(&user_op).is_ok());

        // Invalid nonce should fail
        let mut invalid_op = user_op.clone();
        invalid_op.nonce = Nonce::from_seq(5).to_bytes();
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

    #[tokio::test]
    async fn test_handle_ops_no_runtime() {
        // Without a VM runtime attached, handle_ops follows the
        // accounting-only path: validates, charges gas at the full call/
        // verification/pre-verification limit, increments nonce.
        let sender = vec![0x02; 20];
        let entry_point = entry_point_with_validators(vec![0x01; 20], &[&sender]);

        let user_op = test_user_op(sender.clone(), 0);

        let receipts = entry_point.handle_ops(vec![user_op]).await;
        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].success);
        assert_eq!(receipts[0].gas_used, 171_000);

        // Nonce should be incremented
        assert_eq!(entry_point.get_nonce_default_key(&sender), 1);

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
            nonce: Nonce::from_seq(42).to_bytes(),
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
        user_op2.nonce = Nonce::from_seq(43).to_bytes();
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
            nonce: Nonce::from_seq(0).to_bytes(),
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
        let sender = vec![0x02; 20];
        let entry_point = entry_point_with_validators(vec![0x01; 20], &[&sender]);

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

    #[tokio::test]
    async fn test_entry_point_stats() {
        let sender1 = vec![0x02; 20];
        let sender2 = vec![0x03; 20];
        let entry_point = entry_point_with_validators(vec![0x01; 20], &[&sender1, &sender2]);

        // Process operations on the no-runtime accounting path
        let user_op1 = test_user_op(sender1.clone(), 0);
        let user_op2 = test_user_op(sender2.clone(), 0);

        entry_point.handle_ops(vec![user_op1, user_op2]).await;

        let stats = entry_point.get_stats();
        assert_eq!(stats.total_ops_processed, 2);
        assert_eq!(stats.total_accounts, 2);
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
            nonce: Nonce::from_seq(42).to_bytes(),
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
        assert_eq!(
            restored.paymaster_verification_gas_limit,
            user_op.paymaster_verification_gas_limit
        );
        assert_eq!(
            restored.paymaster_post_op_gas_limit,
            user_op.paymaster_post_op_gas_limit
        );
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

    #[tokio::test]
    async fn test_gas_penalty_threshold_below() {
        // When unused gas < 40,000, only actual gas is charged (no penalty).
        // No-runtime path so the gas-used equals the full reserved limit.
        let sender = vec![0x02; 20];
        let entry_point = entry_point_with_validators(vec![0x01; 20], &[&sender]);

        // total_gas_limit = 100_000 + 50_000 + 21_000 = 171_000
        // gas_used = same 171_000 (no-runtime path), unused = 0 < 40_000
        let user_op = test_user_op(sender.clone(), 0);

        let receipts = entry_point.handle_ops(vec![user_op]).await;
        assert!(receipts[0].success);
        // actual_gas_cost = gas_used * max_fee_per_gas = 171_000 * 1e9
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
        let encoded = vk.to_sec1_point(false);
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

        // Per EIP-7702 the designator is persistent — not rolled back at
        // end-of-tx — and the EOA's nonce was incremented as part of consuming
        // the authorization, blocking replay.
        assert_eq!(state.get_nonce(eoa), 1);
        assert_eq!(state.get_code(eoa), Some(code));
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

    /// Proves that `AccountFactory::with_storage()` survives a restart:
    /// 1. Build factory A backed by an in-memory `KvStore`, create + mutate
    ///    accounts, drop the factory.
    /// 2. Build factory B against the same store; verify all accounts
    ///    (including the mutated module config) hydrated back exactly.
    #[test]
    fn account_factory_hydrates_after_restart() {
        use std::sync::Arc;
        let store: Arc<dyn tenzro_storage::KvStore> = Arc::new(tenzro_storage::MemoryStore::new());

        // Factory A — create two accounts and install a validator on the first.
        let factory_addr = vec![0xAB; 20];
        {
            let factory = AccountFactory::with_storage(factory_addr.clone(), store.clone());
            let _acc1 = factory.create_account(b"owner-1".to_vec(), 0);
            let _acc2 = factory.create_account(b"owner-2".to_vec(), 7);
            let mut mutated = factory
                .get_account(&factory.get_address(b"owner-1", 0))
                .unwrap();
            let cfg = crate::erc7579::ValidatorModuleConfig {
                type_id: 1,
                module_address: [0xCD; 20],
                init_data: vec![1, 2, 3, 4],
                priority: 0,
            };
            mutated
                .install_validator_module(cfg.clone(), /* owner_authorized = */ true)
                .unwrap();
            factory.update_account(mutated);
        }

        // Factory B — same store, fresh map.
        let factory = AccountFactory::with_storage(factory_addr.clone(), store.clone());
        assert_eq!(factory.account_count(), 2, "both accounts must hydrate");
        let acc1_addr = factory.get_address(b"owner-1", 0);
        let restored = factory.get_account(&acc1_addr).expect("acc1 hydrated");
        assert_eq!(restored.owner, b"owner-1");
        assert!(
            restored.is_validator_installed(&[0xCD; 20]),
            "installed validator must survive restart"
        );

        let acc2_addr = factory.get_address(b"owner-2", 7);
        let restored2 = factory.get_account(&acc2_addr).expect("acc2 hydrated");
        assert_eq!(restored2.owner, b"owner-2");
        assert!(restored2.validator_modules.is_empty());
    }

    #[test]
    fn test_decode_execute_roundtrip() {
        let to = [0xAB; 20];
        let value = 12345u128;
        let inner = b"hello world inner call data";
        let encoded = encode_execute_calldata(&to, value, inner);
        let (decoded_to, decoded_value, decoded_data) =
            decode_execute_calldata(&encoded).expect("must decode");
        assert_eq!(decoded_to.as_slice(), &to[..]);
        assert_eq!(decoded_value, value);
        assert_eq!(decoded_data, inner);
    }

    #[test]
    fn test_decode_execute_rejects_wrong_selector() {
        let mut encoded = encode_execute_calldata(&[0x11; 20], 0, b"x");
        encoded[0] = 0xff;
        assert!(decode_execute_calldata(&encoded).is_none());
    }

    #[test]
    fn test_decode_execute_rejects_oversize_value() {
        let mut encoded = encode_execute_calldata(&[0x22; 20], 0, b"x");
        // set high byte of value slot non-zero → must reject (no silent truncation)
        encoded[36] = 0x01;
        assert!(decode_execute_calldata(&encoded).is_none());
    }

    #[test]
    fn test_decode_execute_rejects_short_calldata() {
        let too_short = vec![0xb6, 0x1d, 0x27, 0xf6, 0x00];
        assert!(decode_execute_calldata(&too_short).is_none());
    }

    /// EntryPoint integration: a bootstrap-paymaster-sponsored UserOp whose
    /// declared paymaster address matches the configured bootstrap paymaster
    /// must route through `TnzoBootstrapPaymaster::sponsor`, debit the
    /// paymaster's balance, and consume the sender's one-shot slot.
    #[tokio::test]
    async fn entrypoint_dispatches_to_bootstrap_paymaster() {
        use crate::aa_bootstrap_paymaster::TnzoBootstrapPaymaster;
        use crate::aa_tee_bound_validator::{InMemoryTeeKeyOracle, TeeBoundAccountKey};
        use std::collections::HashMap;
        use tenzro_tee::AttestationVerifier;
        use tenzro_types::Timestamp;
        use tenzro_types::tee::{AttestationReport, TeeVendor};

        /// Permissive ERC-8004 registry — every sender is "registered".
        struct PermissiveRegistry;
        impl crate::aa_bootstrap_paymaster::AgentRegistryLookup for PermissiveRegistry {
            fn is_registered(&self, _: &[u8]) -> bool {
                true
            }
        }

        fn attestation_for(
            vendor: TeeVendor,
            measurement: Vec<u8>,
            enclave_pubkey: &[u8; 32],
        ) -> AttestationReport {
            let attestation_data = serde_json::to_vec(&serde_json::json!({
                "tdx_tcb_svn": "03000600000000000000000000000000",
            }))
            .unwrap();
            let mut metadata = HashMap::new();
            metadata.insert("simulated".to_string(), "true".to_string());
            AttestationReport {
                id: Default::default(),
                vendor,
                user_data: enclave_pubkey.to_vec(),
                attestation_data,
                certificates: vec![],
                timestamp: Timestamp::now(),
                metadata,
                quote: vec![0x01; 32],
                measurement,
                signature: vec![],
                vendor_data: vec![],
            }
        }

        let paymaster_addr = vec![0xAA; 20];
        let sender = vec![0x05; 20];
        let pubkey = [0x77; 32];
        let measurement = b"enclave-image-v1".to_vec();

        // Wire the bootstrap-paymaster dependencies.
        let oracle = Arc::new(InMemoryTeeKeyOracle::new());
        oracle.enroll(
            sender.clone(),
            TeeBoundAccountKey::new(TeeVendor::IntelTdx, &measurement, pubkey),
        );

        let mut verifier = AttestationVerifier::new();
        verifier.set_strict_cert_validation(false);

        let initial_balance: u128 = 10u128.pow(20); // 100 TNZO
        let bootstrap = TnzoBootstrapPaymaster::new(
            paymaster_addr.clone(),
            initial_balance,
            oracle,
            Arc::new(PermissiveRegistry),
            Arc::new(verifier),
        );
        let bootstrap_handle = Arc::new(RwLock::new(bootstrap));

        // EntryPoint wired to the paymaster and no runtime, so the test stays
        // on the validation-only path and exercises paymaster-debit semantics
        // in isolation. A validator module is installed for the sender because
        // validation has no fallback — without one the op is refused before
        // the paymaster is ever consulted.
        let entry_point = entry_point_with_validators(vec![0xEE; 20], &[&sender])
            .with_chain_id(1337)
            .with_bootstrap_paymaster(bootstrap_handle.clone());

        // Build a bootstrap-shaped UserOp: non-empty factory + paymaster
        // address matches the bootstrap paymaster + paymaster_data carries
        // the encoded attestation that binds the sender's enclave key.
        let attestation = attestation_for(TeeVendor::IntelTdx, measurement, &pubkey);
        let paymaster_data = bincode::serialize(&attestation).unwrap();

        let op = UserOperation {
            sender: sender.clone(),
            nonce: Nonce::from_seq(0).to_bytes(),
            factory: vec![0xFA; 20],
            factory_data: vec![],
            call_data: vec![],
            call_gas_limit: 200_000,
            verification_gas_limit: 100_000,
            pre_verification_gas: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            paymaster: paymaster_addr.clone(),
            paymaster_verification_gas_limit: 50_000,
            paymaster_post_op_gas_limit: 30_000,
            paymaster_data,
            signature: vec![0u8; 65],
        };

        let receipt = entry_point.handle_single_op(op.clone()).await;
        assert!(
            receipt.success,
            "EntryPoint should succeed with bootstrap-paymaster sponsorship; logs={:?}",
            receipt
                .logs
                .iter()
                .map(|l| String::from_utf8_lossy(l).into_owned())
                .collect::<Vec<_>>()
        );

        // Paymaster balance must have moved.
        {
            let pm_after = bootstrap_handle.read();
            assert!(
                pm_after.balance() < initial_balance,
                "bootstrap paymaster must have debited some gas (balance: {} → {})",
                initial_balance,
                pm_after.balance()
            );
            assert_eq!(pm_after.sponsored_ops(), 1);
            assert!(
                pm_after.has_consumed(&sender),
                "one-shot consumption ledger must record the sender"
            );
        }

        // Second attempt for the same sender must fail (one-shot exhausted).
        let mut op2 = op;
        op2.nonce = Nonce::from_seq(1).to_bytes();
        let receipt2 = entry_point.handle_single_op(op2).await;
        // The op may still "succeed" at the execution layer (no-op runtime)
        // but the paymaster must have refused — meaning the receipt records
        // success = false because Phase 4 explicitly sets it on refusal.
        assert!(
            !receipt2.success,
            "second op for same sender must be rejected by bootstrap paymaster"
        );
        assert_eq!(bootstrap_handle.read().sponsored_ops(), 1);
    }
}
