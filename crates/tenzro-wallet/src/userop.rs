//! Client-side ERC-4337 v0.8 UserOperation builder + EIP-712 hashing.
//!
//! This is the **self-custodial** path: the wallet (running on the user's
//! device — desktop, mobile, or CLI) builds a `UserOp`, computes its EIP-712
//! hash, signs that hash with a device-bound key (Secure Enclave / TPM /
//! StrongBox / passkey / FROST share), packs the signature, and submits the
//! finished op to the node via `eth_sendUserOperation`. The node never sees
//! the signing key.
//!
//! ## Wire compatibility
//!
//! The `UserOp` struct here is wire-identical to `tenzro_vm::account_abstraction::UserOperation`
//! and the EIP-712 hash matches `UserOperation::hash()` byte-for-byte. We keep
//! a parallel definition (rather than depending on `tenzro-vm`) so the wallet
//! stays small enough to ship into the desktop / mobile binary without
//! dragging in the EVM runtime, revm, BLS, Plonky3, etc.
//!
//! The `userop_hash_matches_tenzro_vm` integration test in `tests/userop_hash.rs`
//! cross-checks the hash against `tenzro-vm` to guarantee they cannot drift.
//!
//! ## EIP-712 domain (v0.8)
//!
//! Per ERC-4337 v0.8: `name = "EntryPoint"`, `version = "0.8"`, `chainId` and
//! `verifyingContract = entryPoint.address` come from the caller.
//!
//! ## Public surface
//!
//! - [`UserOp`] — the operation, serializable to the JSON shape the node
//!   accepts at `eth_sendUserOperation`.
//! - [`UserOpBuilder`] — fluent builder, default 21k pre-verification gas.
//! - [`user_op_hash`] / [`UserOp::eip712_hash`] — the 32-byte digest signers
//!   need.
//! - [`UserOp::with_signature`] — installs a packed signature without
//!   recomputing the hash.
//! - [`encode_user_op_json`] — the JSON the node expects (hex-encoded byte
//!   fields, 0x-prefixed integers).

use serde::{Deserialize, Serialize};
use tenzro_crypto::keccak256;

use crate::error::{Result, WalletError};

/// ERC-4337 v0.8 UserOperation — wire-identical to the node's
/// `tenzro_vm::account_abstraction::UserOperation`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserOp {
    pub sender: Vec<u8>,
    pub nonce: u64,
    pub factory: Vec<u8>,
    pub factory_data: Vec<u8>,
    pub call_data: Vec<u8>,
    pub call_gas_limit: u64,
    pub verification_gas_limit: u64,
    pub pre_verification_gas: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub paymaster: Vec<u8>,
    pub paymaster_verification_gas_limit: u64,
    pub paymaster_post_op_gas_limit: u64,
    pub paymaster_data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl UserOp {
    /// Compute the 32-byte EIP-712 v0.8 digest the signing key signs over.
    pub fn eip712_hash(&self, chain_id: u64, entry_point: &[u8]) -> [u8; 32] {
        user_op_hash(self, chain_id, entry_point)
    }

    /// Install the packed signature and return the finished op.
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }

    /// Serialize the op to the JSON object shape the node accepts at
    /// `eth_sendUserOperation`. Byte fields are emitted as `0x`-prefixed
    /// lowercase hex; integer fields as `0x`-prefixed hex (EVM convention).
    pub fn to_rpc_json(&self) -> serde_json::Value {
        serde_json::json!({
            "sender": hex0x(&self.sender),
            "nonce": format!("0x{:x}", self.nonce),
            "factory": hex0x(&self.factory),
            "factoryData": hex0x(&self.factory_data),
            "callData": hex0x(&self.call_data),
            "callGasLimit": format!("0x{:x}", self.call_gas_limit),
            "verificationGasLimit": format!("0x{:x}", self.verification_gas_limit),
            "preVerificationGas": format!("0x{:x}", self.pre_verification_gas),
            "maxFeePerGas": format!("0x{:x}", self.max_fee_per_gas),
            "maxPriorityFeePerGas": format!("0x{:x}", self.max_priority_fee_per_gas),
            "paymaster": hex0x(&self.paymaster),
            "paymasterVerificationGasLimit": format!("0x{:x}", self.paymaster_verification_gas_limit),
            "paymasterPostOpGasLimit": format!("0x{:x}", self.paymaster_post_op_gas_limit),
            "paymasterData": hex0x(&self.paymaster_data),
            "signature": hex0x(&self.signature),
        })
    }
}

fn hex0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// Standalone EIP-712 v0.8 hash function. Identical bytes to
/// `tenzro_vm::account_abstraction::UserOperation::hash`.
pub fn user_op_hash(op: &UserOp, chain_id: u64, entry_point: &[u8]) -> [u8; 32] {
    let domain = eip712_domain_separator(chain_id, entry_point);
    let struct_hash = user_op_struct_hash(op);

    let mut data = Vec::with_capacity(66);
    data.push(0x19);
    data.push(0x01);
    data.extend_from_slice(&domain);
    data.extend_from_slice(&struct_hash);

    let h = keccak256(&data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// keccak256("UserOperation(address sender,uint256 nonce,address factory,bytes factoryData,bytes callData,uint256 callGasLimit,uint256 verificationGasLimit,uint256 preVerificationGas,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,address paymaster,uint256 paymasterVerificationGasLimit,uint256 paymasterPostOpGasLimit,bytes paymasterData)")
fn user_operation_type_hash() -> [u8; 32] {
    let s = "UserOperation(address sender,uint256 nonce,address factory,bytes factoryData,bytes callData,uint256 callGasLimit,uint256 verificationGasLimit,uint256 preVerificationGas,uint256 maxFeePerGas,uint256 maxPriorityFeePerGas,address paymaster,uint256 paymasterVerificationGasLimit,uint256 paymasterPostOpGasLimit,bytes paymasterData)";
    let h = keccak256(s.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

fn eip712_domain_separator(chain_id: u64, entry_point: &[u8]) -> [u8; 32] {
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

    let mut chain_id_bytes = [0u8; 32];
    chain_id_bytes[24..32].copy_from_slice(&chain_id.to_be_bytes());

    let mut address_bytes = [0u8; 32];
    let n = entry_point.len().min(20);
    address_bytes[32 - n..32].copy_from_slice(&entry_point[..n]);

    let mut data = Vec::with_capacity(160);
    data.extend_from_slice(&domain_type_hash);
    data.extend_from_slice(&name_hash);
    data.extend_from_slice(&version_hash);
    data.extend_from_slice(&chain_id_bytes);
    data.extend_from_slice(&address_bytes);

    let h = keccak256(&data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

fn user_op_struct_hash(op: &UserOp) -> [u8; 32] {
    let type_hash = user_operation_type_hash();

    let mut data = Vec::with_capacity(32 * 15);
    data.extend_from_slice(&type_hash);
    data.extend_from_slice(&encode_address(&op.sender));
    data.extend_from_slice(&encode_u64_as_uint256(op.nonce));
    data.extend_from_slice(&encode_address(&op.factory));
    data.extend_from_slice(&keccak256_of(&op.factory_data));
    data.extend_from_slice(&keccak256_of(&op.call_data));
    data.extend_from_slice(&encode_u64_as_uint256(op.call_gas_limit));
    data.extend_from_slice(&encode_u64_as_uint256(op.verification_gas_limit));
    data.extend_from_slice(&encode_u64_as_uint256(op.pre_verification_gas));
    data.extend_from_slice(&encode_u128_as_uint256(op.max_fee_per_gas));
    data.extend_from_slice(&encode_u128_as_uint256(op.max_priority_fee_per_gas));
    data.extend_from_slice(&encode_address(&op.paymaster));
    data.extend_from_slice(&encode_u64_as_uint256(op.paymaster_verification_gas_limit));
    data.extend_from_slice(&encode_u64_as_uint256(op.paymaster_post_op_gas_limit));
    data.extend_from_slice(&keccak256_of(&op.paymaster_data));

    let h = keccak256(&data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

fn keccak256_of(b: &[u8]) -> [u8; 32] {
    let h = keccak256(b);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

fn encode_u64_as_uint256(v: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[24..32].copy_from_slice(&v.to_be_bytes());
    buf
}

fn encode_u128_as_uint256(v: u128) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[16..32].copy_from_slice(&v.to_be_bytes());
    buf
}

fn encode_address(addr: &[u8]) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let n = addr.len().min(20);
    if n > 0 {
        buf[32 - n..32].copy_from_slice(&addr[..n]);
    }
    buf
}

/// Fluent builder for [`UserOp`]. Sane defaults: 21k pre-verification gas,
/// 100k call gas, 50k verification gas, no paymaster, no factory. The caller
/// must set `sender`, `nonce`, `call_data`, and (eventually) `signature`.
#[derive(Debug, Clone)]
pub struct UserOpBuilder {
    op: UserOp,
}

impl Default for UserOpBuilder {
    fn default() -> Self {
        Self {
            op: UserOp {
                sender: vec![],
                nonce: 0,
                factory: vec![],
                factory_data: vec![],
                call_data: vec![],
                call_gas_limit: 100_000,
                verification_gas_limit: 50_000,
                pre_verification_gas: 21_000,
                max_fee_per_gas: 1_000_000_000,
                max_priority_fee_per_gas: 1_000_000,
                paymaster: vec![],
                paymaster_verification_gas_limit: 0,
                paymaster_post_op_gas_limit: 0,
                paymaster_data: vec![],
                signature: vec![],
            },
        }
    }
}

impl UserOpBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sender(mut self, addr: impl Into<Vec<u8>>) -> Self {
        self.op.sender = addr.into();
        self
    }
    pub fn nonce(mut self, n: u64) -> Self {
        self.op.nonce = n;
        self
    }
    pub fn factory(mut self, addr: impl Into<Vec<u8>>, data: impl Into<Vec<u8>>) -> Self {
        self.op.factory = addr.into();
        self.op.factory_data = data.into();
        self
    }
    pub fn call_data(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.op.call_data = data.into();
        self
    }
    pub fn call_gas_limit(mut self, g: u64) -> Self {
        self.op.call_gas_limit = g;
        self
    }
    pub fn verification_gas_limit(mut self, g: u64) -> Self {
        self.op.verification_gas_limit = g;
        self
    }
    pub fn pre_verification_gas(mut self, g: u64) -> Self {
        self.op.pre_verification_gas = g;
        self
    }
    pub fn max_fee_per_gas(mut self, f: u128) -> Self {
        self.op.max_fee_per_gas = f;
        self
    }
    pub fn max_priority_fee_per_gas(mut self, f: u128) -> Self {
        self.op.max_priority_fee_per_gas = f;
        self
    }
    pub fn paymaster(
        mut self,
        addr: impl Into<Vec<u8>>,
        verification_gas: u64,
        post_op_gas: u64,
        data: impl Into<Vec<u8>>,
    ) -> Self {
        self.op.paymaster = addr.into();
        self.op.paymaster_verification_gas_limit = verification_gas;
        self.op.paymaster_post_op_gas_limit = post_op_gas;
        self.op.paymaster_data = data.into();
        self
    }

    /// Validate basic invariants and return the constructed (unsigned) op.
    pub fn build(self) -> Result<UserOp> {
        if self.op.sender.is_empty() {
            return Err(WalletError::TransactionValidationFailed(
                "user_op_builder: sender missing".into(),
            ));
        }
        if self.op.call_data.is_empty() && self.op.factory.is_empty() {
            return Err(WalletError::TransactionValidationFailed(
                "user_op_builder: either call_data or factory must be set".into(),
            ));
        }
        Ok(self.op)
    }
}

/// Encode a single ERC-7579 module signature into the packed envelope the
/// validator registry expects. The envelope is:
///
/// ```text
///   validator_address (20 bytes) || module_signature_bytes
/// ```
///
/// `tenzro_vm::aa_validator_registry::ValidatorRegistry::validate_user_op`
/// splits on the leading 20 bytes to route to the installed module. Plain
/// owner-key signatures (no validator routing) are submitted as the raw
/// 64-byte `r ‖ s` or 65-byte `r ‖ s ‖ v` with no envelope.
pub fn pack_validator_signature(validator_addr: &[u8], module_signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + module_signature.len());
    let n = validator_addr.len().min(20);
    // Left-pad if caller passed fewer than 20 bytes (uncommon but defensive).
    if n < 20 {
        out.extend(std::iter::repeat(0u8).take(20 - n));
    }
    out.extend_from_slice(&validator_addr[..n]);
    out.extend_from_slice(module_signature);
    out
}

/// JSON-RPC params shape for `eth_sendUserOperation([userOp, entryPoint])`.
pub fn encode_user_op_json(op: &UserOp, entry_point: &[u8]) -> serde_json::Value {
    serde_json::json!([op.to_rpc_json(), format!("0x{}", hex::encode(entry_point))])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_op() -> UserOp {
        UserOpBuilder::new()
            .sender(vec![0x11; 20])
            .nonce(7)
            .call_data(vec![0x42; 32])
            .build()
            .unwrap()
    }

    #[test]
    fn builder_rejects_empty_sender() {
        let err = UserOpBuilder::new()
            .call_data(vec![0x01])
            .build()
            .unwrap_err();
        assert!(matches!(err, WalletError::TransactionValidationFailed(_)));
    }

    #[test]
    fn builder_rejects_empty_call_data_and_factory() {
        let err = UserOpBuilder::new()
            .sender(vec![0x11; 20])
            .build()
            .unwrap_err();
        assert!(matches!(err, WalletError::TransactionValidationFailed(_)));
    }

    #[test]
    fn builder_accepts_factory_only() {
        let op = UserOpBuilder::new()
            .sender(vec![0x11; 20])
            .factory(vec![0x22; 20], vec![0x01])
            .build()
            .unwrap();
        assert!(op.call_data.is_empty());
        assert!(!op.factory.is_empty());
    }

    #[test]
    fn hash_is_32_bytes_and_deterministic() {
        let op = sample_op();
        let ep = vec![0xee; 20];
        let h1 = op.eip712_hash(1337, &ep);
        let h2 = op.eip712_hash(1337, &ep);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn hash_changes_with_chain_id() {
        let op = sample_op();
        let ep = vec![0xee; 20];
        assert_ne!(op.eip712_hash(1, &ep), op.eip712_hash(2, &ep));
    }

    #[test]
    fn hash_changes_with_entry_point() {
        let op = sample_op();
        assert_ne!(
            op.eip712_hash(1337, &vec![0xaa; 20]),
            op.eip712_hash(1337, &vec![0xbb; 20])
        );
    }

    #[test]
    fn signature_is_excluded_from_hash() {
        let mut a = sample_op();
        let mut b = sample_op();
        a.signature = vec![0x01; 65];
        b.signature = vec![0x02; 65];
        let ep = vec![0xee; 20];
        // EIP-712 schema excludes `signature` — different signatures must hash identically.
        assert_eq!(a.eip712_hash(1337, &ep), b.eip712_hash(1337, &ep));
    }

    #[test]
    fn pack_validator_signature_layout() {
        let validator = vec![0xaa; 20];
        let inner = vec![0x12, 0x34];
        let packed = pack_validator_signature(&validator, &inner);
        assert_eq!(packed.len(), 22);
        assert_eq!(&packed[..20], validator.as_slice());
        assert_eq!(&packed[20..], inner.as_slice());
    }

    #[test]
    fn pack_validator_signature_left_pads_short_addr() {
        let validator = vec![0xaa; 4];
        let packed = pack_validator_signature(&validator, &[0x55]);
        assert_eq!(packed.len(), 21);
        assert_eq!(&packed[..16], &[0u8; 16]);
        assert_eq!(&packed[16..20], validator.as_slice());
        assert_eq!(packed[20], 0x55);
    }

    #[test]
    fn to_rpc_json_emits_hex_strings() {
        let op = sample_op();
        let j = op.to_rpc_json();
        assert_eq!(j["sender"].as_str().unwrap(), "0x1111111111111111111111111111111111111111");
        assert_eq!(j["nonce"].as_str().unwrap(), "0x7");
        assert!(j["callData"].as_str().unwrap().starts_with("0x"));
    }

    #[test]
    fn encode_user_op_json_wraps_array() {
        let op = sample_op();
        let ep = vec![0xee; 20];
        let v = encode_user_op_json(&op, &ep);
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(
            arr[1].as_str().unwrap(),
            "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );
    }
}
