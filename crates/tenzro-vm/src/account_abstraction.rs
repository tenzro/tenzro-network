//! ERC-4337 and EIP-7702 encodings for EVM compatibility.
//!
//! Tenzro accounts are native: a passkey account's keystore lives in
//! consensus state and its transactions are verified by every validator.
//! This module does not execute user operations. It holds the byte-exact
//! encodings that EVM contracts and Ethereum tooling compute, so the same
//! values come out on Tenzro as on Ethereum:
//!
//! - the ERC-4337 `PackedUserOperation` layout and the user operation hash
//!   that EntryPoint v0.9 computes (EIP-712 domain `ERC4337`, version `1`),
//!   including the paymaster signature suffix that is left out of the hash
//!   and the EIP-7702 init code whose hash is replaced by the delegate;
//! - the validation data an account or paymaster returns, with the block
//!   number range flag of v0.9;
//! - EIP-7702 authorizations and delegation designators.
//!
//! An EntryPoint contract deployed in the EVM runs in consensus like any
//! other contract. There is no user operation mempool or bundler in the node.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The 256-bit integer an EIP-7702 authorization's chain id is.
pub use revm::primitives::U256;
use revm::primitives::{Address, Authorization, RecoveredAuthority, RecoveredAuthorization};
use tenzro_crypto::hash::keccak256;

use crate::error::VmError;

/// EntryPoint v0.9 address on every chain that deploys it.
pub const ENTRY_POINT_V09: [u8; 20] = [
    0x43, 0x37, 0x09, 0x00, 0x9b, 0x83, 0x30, 0xfd, 0xa3, 0x23, 0x11, 0xdf, 0x1c, 0x2a, 0xfa, 0x40,
    0x2e, 0xd8, 0xd0, 0x09,
];

/// SenderCreator deployed by EntryPoint v0.9.
pub const SENDER_CREATOR_V09: [u8; 20] = [
    0x0a, 0x63, 0x0a, 0x99, 0xdf, 0x90, 0x8a, 0x81, 0x11, 0x5a, 0x30, 0x22, 0x92, 0x7b, 0xe8, 0x2f,
    0x92, 0x99, 0x98, 0x7e,
];

/// EIP-712 domain name of the EntryPoint.
pub const EIP712_DOMAIN_NAME: &str = "ERC4337";

/// EIP-712 domain version of the EntryPoint.
pub const EIP712_DOMAIN_VERSION: &str = "1";

/// The EIP-712 type of the hashed user operation.
pub const PACKED_USEROP_TYPE: &str = "PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)";

/// `factory` value that marks an EIP-7702 account: the 20 bytes `0x7702`
/// followed by zeros.
pub const INITCODE_EIP7702_MARKER: [u8; 20] = {
    let mut a = [0u8; 20];
    a[0] = 0x77;
    a[1] = 0x02;
    a
};

/// Last 8 bytes of a `paymasterAndData` that carries a paymaster signature:
/// `keccak256("PaymasterSignature")[..8]`.
pub const PAYMASTER_SIG_MAGIC: [u8; 8] = [0x22, 0xe3, 0x25, 0xa2, 0x97, 0x43, 0x96, 0x56];

/// Offset of the paymaster data in `paymasterAndData` (address, then two
/// 16-byte gas limits).
pub const PAYMASTER_DATA_OFFSET: usize = 52;

/// Length of the paymaster signature suffix: a 2-byte length and the magic.
const PAYMASTER_SUFFIX_LEN: usize = 2 + PAYMASTER_SIG_MAGIC.len();

/// Top bit of `validAfter` and `validUntil`: when set in both, the range is
/// block numbers rather than timestamps.
pub const VALIDITY_BLOCK_RANGE_FLAG: u64 = 0x8000_0000_0000;

/// The rest of a 48-bit validity bound.
pub const VALIDITY_BLOCK_RANGE_MASK: u64 = 0x7fff_ffff_ffff;

/// 2-D nonce: a 192-bit key and a 64-bit sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce {
    /// 24-byte (192-bit) key, big-endian.
    pub key: [u8; 24],
    /// 8-byte (64-bit) sequence portion.
    pub seq: u64,
}

impl Nonce {
    /// A nonce with `key = 0` and the given `seq`.
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
}

/// Why a user operation cannot be encoded or decoded.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AccountAbstractionError {
    /// The operation is malformed.
    #[error("Invalid user operation: {0}")]
    InvalidUserOp(String),
}

/// An ERC-4337 user operation with its packed fields split out.
///
/// [`UserOperation::to_packed`] gives the `PackedUserOperation` an
/// EntryPoint receives, and [`UserOperation::hash`] the hash it computes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct UserOperation {
    /// The account making the operation (20 bytes).
    pub sender: Vec<u8>,
    /// `(uint192 key << 64) | uint64 seq`, big-endian; see [`Nonce`].
    pub nonce: [u8; 32],
    /// Factory that deploys the account, [`INITCODE_EIP7702_MARKER`] for an
    /// EIP-7702 account, or empty.
    pub factory: Vec<u8>,
    /// Data for the factory, or the EIP-7702 initialization call data.
    pub factory_data: Vec<u8>,
    /// The call the account executes.
    pub call_data: Vec<u8>,
    /// Gas for the execution call.
    pub call_gas_limit: u64,
    /// Gas for validation.
    pub verification_gas_limit: u64,
    /// Gas paid to the submitter beyond the two limits.
    pub pre_verification_gas: u64,
    /// EIP-1559 max fee per gas.
    pub max_fee_per_gas: u128,
    /// EIP-1559 max priority fee per gas.
    pub max_priority_fee_per_gas: u128,
    /// Paymaster address, or empty.
    pub paymaster: Vec<u8>,
    /// Gas for the paymaster's validation.
    pub paymaster_verification_gas_limit: u64,
    /// Gas for the paymaster's `postOp`.
    pub paymaster_post_op_gas_limit: u64,
    /// Data for the paymaster, covered by the account's signature.
    pub paymaster_data: Vec<u8>,
    /// The paymaster's own signature, appended after the account signs and
    /// not covered by the hash (EntryPoint v0.9).
    #[serde(default)]
    pub paymaster_signature: Vec<u8>,
    /// The account's signature.
    pub signature: Vec<u8>,
}

/// The `PackedUserOperation` struct as EntryPoint v0.9 takes it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PackedUserOperation {
    /// The account making the operation.
    pub sender: Vec<u8>,
    /// 2-D nonce, big-endian uint256.
    pub nonce: [u8; 32],
    /// `factory ‖ factoryData`, or empty.
    pub init_code: Vec<u8>,
    /// The call the account executes.
    pub call_data: Vec<u8>,
    /// `verificationGasLimit (16 bytes) ‖ callGasLimit (16 bytes)`.
    pub account_gas_limits: [u8; 32],
    /// Gas paid to the submitter beyond the two limits.
    pub pre_verification_gas: u64,
    /// `maxPriorityFeePerGas (16 bytes) ‖ maxFeePerGas (16 bytes)`.
    pub gas_fees: [u8; 32],
    /// `paymaster ‖ verificationGas (16) ‖ postOpGas (16) ‖ data`, then
    /// `‖ paymasterSignature ‖ len (2) ‖ PAYMASTER_SIG_MAGIC` when the
    /// paymaster signs.
    pub paymaster_and_data: Vec<u8>,
    /// The account's signature.
    pub signature: Vec<u8>,
}

fn word_u128_pair(hi: u128, lo: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&hi.to_be_bytes());
    out[16..].copy_from_slice(&lo.to_be_bytes());
    out
}

fn split_u128_pair(word: &[u8; 32]) -> (u128, u128) {
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&word[..16]);
    lo.copy_from_slice(&word[16..]);
    (u128::from_be_bytes(hi), u128::from_be_bytes(lo))
}

fn to_u64(v: u128, what: &str) -> Result<u64, AccountAbstractionError> {
    u64::try_from(v)
        .map_err(|_| AccountAbstractionError::InvalidUserOp(format!("{what} exceeds 64 bits")))
}

fn k256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(keccak256(data).as_bytes());
    out
}

fn address_word(addr: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let n = addr.len().min(20);
    out[32 - n..].copy_from_slice(&addr[..n]);
    out
}

fn u64_word(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// The EIP-712 domain separator of an EntryPoint at `entry_point` on
/// `chain_id`.
pub fn domain_separator(chain_id: u64, entry_point: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(160);
    data.extend_from_slice(&k256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    ));
    data.extend_from_slice(&k256(EIP712_DOMAIN_NAME.as_bytes()));
    data.extend_from_slice(&k256(EIP712_DOMAIN_VERSION.as_bytes()));
    data.extend_from_slice(&u64_word(chain_id));
    data.extend_from_slice(&address_word(entry_point));
    k256(&data)
}

/// Length of the paymaster signature in `paymaster_and_data`, 0 when it has
/// none. A length reaching back into the paymaster's fixed fields is refused,
/// as the EntryPoint refuses it.
pub fn paymaster_signature_len(
    paymaster_and_data: &[u8],
) -> Result<usize, AccountAbstractionError> {
    let n = paymaster_and_data.len();
    if n < PAYMASTER_DATA_OFFSET + PAYMASTER_SUFFIX_LEN
        || paymaster_and_data[n - 8..] != PAYMASTER_SIG_MAGIC
    {
        return Ok(0);
    }
    let len = u16::from_be_bytes([paymaster_and_data[n - 10], paymaster_and_data[n - 9]]) as usize;
    if len > n - PAYMASTER_DATA_OFFSET - PAYMASTER_SUFFIX_LEN {
        return Err(AccountAbstractionError::InvalidUserOp(
            "paymaster signature length reaches into the paymaster fields".into(),
        ));
    }
    Ok(len)
}

impl PackedUserOperation {
    /// Whether `init_code` marks an EIP-7702 account.
    pub fn is_eip7702(&self) -> bool {
        self.init_code.len() >= 2 && {
            let mut start = [0u8; 20];
            let n = self.init_code.len().min(20);
            start[..n].copy_from_slice(&self.init_code[..n]);
            start == INITCODE_EIP7702_MARKER
        }
    }

    /// The user operation hash EntryPoint v0.9 computes:
    /// `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`.
    ///
    /// For an EIP-7702 account the init code hash is
    /// `keccak256(delegate ‖ initCode[20..])`, where `delegate` is the
    /// address the sender's delegation designator names; pass it as
    /// `eip7702_delegate`. The paymaster signature suffix is left out of the
    /// hashed `paymasterAndData` (the magic stays in).
    pub fn hash(
        &self,
        chain_id: u64,
        entry_point: &[u8],
        eip7702_delegate: Option<&[u8; 20]>,
    ) -> Result<[u8; 32], AccountAbstractionError> {
        let init_code_hash = if self.is_eip7702() {
            let delegate = eip7702_delegate.ok_or_else(|| {
                AccountAbstractionError::InvalidUserOp(
                    "EIP-7702 init code: the sender's delegate is needed for the hash".into(),
                )
            })?;
            let mut pre = delegate.to_vec();
            if self.init_code.len() > 20 {
                pre.extend_from_slice(&self.init_code[20..]);
            }
            k256(&pre)
        } else {
            k256(&self.init_code)
        };
        let sig_len = paymaster_signature_len(&self.paymaster_and_data)?;
        let paymaster_hash = if sig_len > 0 {
            let keep = self.paymaster_and_data.len() - sig_len - PAYMASTER_SUFFIX_LEN;
            let mut pre = self.paymaster_and_data[..keep].to_vec();
            pre.extend_from_slice(&PAYMASTER_SIG_MAGIC);
            k256(&pre)
        } else {
            k256(&self.paymaster_and_data)
        };
        let mut s = Vec::with_capacity(32 * 9);
        s.extend_from_slice(&k256(PACKED_USEROP_TYPE.as_bytes()));
        s.extend_from_slice(&address_word(&self.sender));
        s.extend_from_slice(&self.nonce);
        s.extend_from_slice(&init_code_hash);
        s.extend_from_slice(&k256(&self.call_data));
        s.extend_from_slice(&self.account_gas_limits);
        s.extend_from_slice(&u64_word(self.pre_verification_gas));
        s.extend_from_slice(&self.gas_fees);
        s.extend_from_slice(&paymaster_hash);
        let struct_hash = k256(&s);
        let mut d = Vec::with_capacity(66);
        d.extend_from_slice(&[0x19, 0x01]);
        d.extend_from_slice(&domain_separator(chain_id, entry_point));
        d.extend_from_slice(&struct_hash);
        Ok(k256(&d))
    }

    /// Split the packed fields out.
    pub fn to_user_op(&self) -> Result<UserOperation, AccountAbstractionError> {
        let (factory, factory_data) = match self.init_code.len() {
            0 => (vec![], vec![]),
            n if n >= 20 => (self.init_code[..20].to_vec(), self.init_code[20..].to_vec()),
            _ if self.is_eip7702() => (INITCODE_EIP7702_MARKER.to_vec(), vec![]),
            _ => {
                return Err(AccountAbstractionError::InvalidUserOp(
                    "initCode shorter than 20 bytes".into(),
                ));
            }
        };
        let (verification, call) = split_u128_pair(&self.account_gas_limits);
        let (priority, max_fee) = split_u128_pair(&self.gas_fees);
        let pd = &self.paymaster_and_data;
        let mut op = UserOperation {
            sender: self.sender.clone(),
            nonce: self.nonce,
            factory,
            factory_data,
            call_data: self.call_data.clone(),
            call_gas_limit: to_u64(call, "callGasLimit")?,
            verification_gas_limit: to_u64(verification, "verificationGasLimit")?,
            pre_verification_gas: self.pre_verification_gas,
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: priority,
            signature: self.signature.clone(),
            ..UserOperation::default()
        };
        if !pd.is_empty() {
            if pd.len() < PAYMASTER_DATA_OFFSET {
                return Err(AccountAbstractionError::InvalidUserOp(
                    "paymasterAndData shorter than 52 bytes".into(),
                ));
            }
            let sig_len = paymaster_signature_len(pd)?;
            let data_end = if sig_len > 0 {
                pd.len() - sig_len - PAYMASTER_SUFFIX_LEN
            } else {
                pd.len()
            };
            let mut gas = [0u8; 32];
            gas.copy_from_slice(&pd[20..52]);
            let (pv, pp) = split_u128_pair(&gas);
            op.paymaster = pd[..20].to_vec();
            op.paymaster_verification_gas_limit = to_u64(pv, "paymasterVerificationGasLimit")?;
            op.paymaster_post_op_gas_limit = to_u64(pp, "paymasterPostOpGasLimit")?;
            op.paymaster_data = pd[PAYMASTER_DATA_OFFSET..data_end].to_vec();
            op.paymaster_signature = pd[data_end..data_end + sig_len].to_vec();
        }
        Ok(op)
    }
}

impl UserOperation {
    /// The packed form an EntryPoint receives.
    pub fn to_packed(&self) -> PackedUserOperation {
        let mut init_code = self.factory.clone();
        init_code.extend_from_slice(&self.factory_data);
        let mut paymaster_and_data = Vec::new();
        if !self.paymaster.is_empty() {
            paymaster_and_data.extend_from_slice(&self.paymaster);
            paymaster_and_data.extend_from_slice(&word_u128_pair(
                self.paymaster_verification_gas_limit as u128,
                self.paymaster_post_op_gas_limit as u128,
            ));
            paymaster_and_data.extend_from_slice(&self.paymaster_data);
            if !self.paymaster_signature.is_empty() {
                paymaster_and_data.extend_from_slice(&self.paymaster_signature);
                paymaster_and_data
                    .extend_from_slice(&(self.paymaster_signature.len() as u16).to_be_bytes());
                paymaster_and_data.extend_from_slice(&PAYMASTER_SIG_MAGIC);
            }
        }
        PackedUserOperation {
            sender: self.sender.clone(),
            nonce: self.nonce,
            init_code,
            call_data: self.call_data.clone(),
            account_gas_limits: word_u128_pair(
                self.verification_gas_limit as u128,
                self.call_gas_limit as u128,
            ),
            pre_verification_gas: self.pre_verification_gas,
            gas_fees: word_u128_pair(self.max_priority_fee_per_gas, self.max_fee_per_gas),
            paymaster_and_data,
            signature: self.signature.clone(),
        }
    }

    /// The user operation hash EntryPoint v0.9 computes; see
    /// [`PackedUserOperation::hash`].
    pub fn hash(
        &self,
        chain_id: u64,
        entry_point: &[u8],
        eip7702_delegate: Option<&[u8; 20]>,
    ) -> Result<[u8; 32], AccountAbstractionError> {
        self.to_packed()
            .hash(chain_id, entry_point, eip7702_delegate)
    }
}

/// The validation data an account's `validateUserOp` or a paymaster's
/// `validatePaymasterUserOp` returns, unpacked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidityRange {
    /// `address(0)`: valid; `address(1)`: signature failure; otherwise an
    /// aggregator.
    pub aggregator: [u8; 20],
    /// First instant (exclusive) the operation is valid after.
    pub valid_after: u64,
    /// Last instant it is valid at; 0 on the wire means no limit.
    pub valid_until: u64,
    /// Whether the bounds are block numbers rather than timestamps.
    pub block_range: bool,
}

impl ValidityRange {
    /// Unpack `aggregator (20) | validUntil (6) << 160 | validAfter (6) << 208`.
    pub fn parse(validation_data: &[u8; 32]) -> Self {
        let mut aggregator = [0u8; 20];
        aggregator.copy_from_slice(&validation_data[12..32]);
        let read48 = |b: &[u8]| b.iter().fold(0u64, |acc, x| (acc << 8) | *x as u64);
        let valid_after = read48(&validation_data[0..6]);
        let mut valid_until = read48(&validation_data[6..12]);
        if valid_until == 0 {
            valid_until = 0xffff_ffff_ffff;
        }
        let block_range =
            valid_after >= VALIDITY_BLOCK_RANGE_FLAG && valid_until >= VALIDITY_BLOCK_RANGE_FLAG;
        if block_range {
            Self {
                aggregator,
                valid_after: valid_after & VALIDITY_BLOCK_RANGE_MASK,
                valid_until: valid_until & VALIDITY_BLOCK_RANGE_MASK,
                block_range,
            }
        } else {
            Self {
                aggregator,
                valid_after,
                valid_until,
                block_range,
            }
        }
    }

    /// Whether the operation is out of its range at this block.
    pub fn out_of_range(&self, block_number: u64, block_timestamp_secs: u64) -> bool {
        let now = if self.block_range {
            block_number
        } else {
            block_timestamp_secs
        };
        now > self.valid_until || now <= self.valid_after
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

/// EIP-7702 authorization: an EOA sets its code to a delegation designator
/// naming a contract, and calls to the EOA run that contract's code until
/// another authorization changes or clears it.
///
/// The `signature` field is a 65-byte secp256k1 signature encoded as
/// `r(32) || s(32) || y_parity(1)` where `y_parity` is `0` or `1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip7702Authorization {
    /// Chain ID this authorization is valid for (0: every chain). A
    /// 256-bit integer, as signed.
    pub chain_id: U256,
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
        let chain_id = self.chain_id.to_be_bytes_trimmed_vec();
        stream.append(&chain_id.as_slice());
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
    if auth.signature.len() != 65 {
        return Err(VmError::InvalidSignature);
    }
    if auth.delegate_address.len() != 20 {
        return Err(VmError::InvalidTransaction(
            "EIP-7702: delegate_address must be 20 bytes".into(),
        ));
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&auth.signature[..32]);
    s.copy_from_slice(&auth.signature[32..64]);
    crate::external_tx::ecrecover(&auth.signing_hash(), &r, &s, auth.signature[64])
        .map(|a| a.to_vec())
}

impl Eip7702Authorization {
    /// The authorization as the EVM applies it, with its authority
    /// recovered. One whose signature does not recover (malformed, `s` in
    /// the upper half of the curve order, `y_parity` above 1) carries no
    /// authority, so execution skips it (EIP-7702) while the transaction
    /// still runs.
    pub fn recovered(&self) -> RecoveredAuthorization {
        let mut address = [0u8; 20];
        if self.delegate_address.len() == 20 {
            address.copy_from_slice(&self.delegate_address);
        }
        let authority = match recover_eoa_from_7702_signature(self) {
            Ok(a) => RecoveredAuthority::Valid(Address::from_slice(&a)),
            Err(_) => RecoveredAuthority::Invalid,
        };
        RecoveredAuthorization::new_unchecked(
            Authorization {
                chain_id: self.chain_id,
                address: Address::from(address),
                nonce: self.nonce,
            },
            authority,
        )
    }
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

/// The 20-byte EVM address of a ledger account: a 32-byte account that is a
/// 20-byte address followed by twelve zero bytes is that address.
pub fn evm_address_20(account: &[u8]) -> &[u8] {
    match account.len() {
        32 if account[20..].iter().all(|b| *b == 0) => &account[..20],
        _ => account,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> UserOperation {
        UserOperation {
            sender: vec![0x11; 20],
            nonce: Nonce {
                key: [0x01; 24],
                seq: 7,
            }
            .to_bytes(),
            factory: vec![0x22; 20],
            factory_data: vec![0xaa, 0xbb],
            call_data: vec![0xe9, 0xae, 0x5c, 0x53],
            call_gas_limit: 100_000,
            verification_gas_limit: 50_000,
            pre_verification_gas: 21_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000,
            paymaster: vec![0x33; 20],
            paymaster_verification_gas_limit: 40_000,
            paymaster_post_op_gas_limit: 10_000,
            paymaster_data: vec![0x01, 0x02, 0x03],
            paymaster_signature: vec![0x44; 65],
            signature: vec![0x55; 65],
        }
    }

    #[test]
    fn nonce_roundtrip() {
        let n = Nonce {
            key: [0x09; 24],
            seq: 42,
        };
        assert_eq!(Nonce::from_bytes(n.to_bytes()), n);
    }

    #[test]
    fn packed_roundtrip_keeps_every_field() {
        let op = sample();
        let packed = op.to_packed();
        assert_eq!(packed.init_code.len(), 22);
        assert_eq!(packed.paymaster_and_data.len(), 52 + 3 + 65 + 10);
        assert_eq!(packed.to_user_op().unwrap(), op);
    }

    #[test]
    fn paymaster_signature_is_not_hashed() {
        let a = sample();
        let mut b = sample();
        b.paymaster_signature = vec![0x66; 70];
        assert_eq!(
            a.hash(1, &ENTRY_POINT_V09, None),
            b.hash(1, &ENTRY_POINT_V09, None)
        );
        let mut c = sample();
        c.paymaster_data.push(0);
        assert_ne!(
            a.hash(1, &ENTRY_POINT_V09, None),
            c.hash(1, &ENTRY_POINT_V09, None)
        );
    }

    #[test]
    fn eip7702_init_code_needs_the_delegate() {
        let mut op = sample();
        op.factory = INITCODE_EIP7702_MARKER.to_vec();
        op.factory_data.clear();
        assert!(op.hash(1, &ENTRY_POINT_V09, None).is_err());
        let h1 = op.hash(1, &ENTRY_POINT_V09, Some(&[0x77; 20])).unwrap();
        let h2 = op.hash(1, &ENTRY_POINT_V09, Some(&[0x78; 20])).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn short_paymaster_data_is_refused() {
        let mut p = sample().to_packed();
        p.paymaster_and_data.truncate(40);
        assert!(p.to_user_op().is_err());
    }

    #[test]
    fn validity_range_by_time_and_by_block() {
        let mut w = [0u8; 32];
        w[0..6].copy_from_slice(&[0, 0, 0, 0, 0, 10]);
        w[6..12].copy_from_slice(&[0, 0, 0, 0, 0, 20]);
        let r = ValidityRange::parse(&w);
        assert!(!r.block_range);
        assert!(r.out_of_range(0, 10));
        assert!(!r.out_of_range(0, 11));
        assert!(r.out_of_range(0, 21));
        w[0] = 0x80;
        w[6] = 0x80;
        let r = ValidityRange::parse(&w);
        assert!(r.block_range);
        assert_eq!((r.valid_after, r.valid_until), (10, 20));
        assert!(!r.out_of_range(15, 0));
        assert!(r.out_of_range(21, 15));
        let r = ValidityRange::parse(&[0u8; 32]);
        assert!(!r.out_of_range(u64::MAX >> 20, 1_900_000_000));
    }

    #[test]
    fn test_eip7702_signing_preimage_has_magic_and_rlp() {
        let auth = Eip7702Authorization {
            chain_id: U256::from(1337u64),
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
