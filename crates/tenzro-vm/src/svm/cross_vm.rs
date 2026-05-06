//! Tenzro Cross-VM Bridge Program (SVM-native)
//!
//! This module defines the canonical SVM program that lets SVM transactions
//! initiate cross-VM token transfers into the EVM precompile at address
//! `0x1003` (`CROSS_VM_BRIDGE`). It is implemented as a *native program* —
//! the SVM executor recognizes [`TENZRO_CROSS_VM_PROGRAM_ID`] and dispatches
//! to the handlers in this module instead of running an SBF ELF.
//!
//! # Conventions
//!
//! - **Program ID**: deterministically derived as
//!   `SHA-256("tenzro/svm/program/cross_vm")`. Hex
//!   `5c03dd6cf580ecafb5ca11a9e1d6448176bb1dfa9d4886c65d9024df77542695`.
//!   Base58 `7CBvjJtsMxYFsxYkpcXYoTDZpC8PhMVy1DVVQBopvWCC`. This mirrors the
//!   `WTNZO_SPL_MINT` derivation pattern in [`spl_adapter`](super::spl_adapter)
//!   — a public, reproducible address with no upgrade authority.
//!
//! - **Instruction discriminators**: 8-byte Anchor-style
//!   `SHA-256("global:<snake_case_name>")[..8]`. This is the dominant 2026
//!   convention (Anchor 0.31) and is required for IDL/explorer/SDK
//!   interoperability even though we hand-roll the dispatcher rather than
//!   linking the Anchor framework.
//!
//! - **Instruction data layout**: `[ discriminator (8) | payload (n) ]`.
//!   Payloads are little-endian Borsh-style: fixed-width integers as raw LE
//!   bytes, byte arrays inlined.
//!
//! # Instruction set
//!
//! | Name                     | Discriminator        | Payload size |
//! |--------------------------|----------------------|--------------|
//! | `bridge_to_evm`          | `92a8a45c33225f25`   | 68 bytes     |
//! | `bridge_from_evm`        | `3038733289f4cd75`   | 68 bytes     |
//! | `register_token_pointer` | `9a8e01390f994522`   | 84 bytes     |
//! | `transfer_cross_vm`      | `bc684168aba7abb9`   | 73 bytes     |
//!
//! ## `bridge_to_evm(mint, evm_dest, amount, nonce)`
//!
//! Burns `amount` of `mint` on SVM and credits the EVM-side balance for
//! `evm_dest`. Maps to `cross_vm_bridge::CROSS_VM_TRANSFER` with
//! `destVm = VM_TYPE_EVM`.
//!
//! Payload (68 bytes):
//! ```text
//! offset  size  field
//!     0    32   mint        (Pubkey)
//!    32    20   evm_dest    ([u8; 20])
//!    52     8   amount      (u64 LE, SPL units)
//!    60     8   nonce       (u64 LE, replay-protection)
//! ```
//!
//! ## `bridge_from_evm(mint, svm_dest, amount, nonce)`
//!
//! Mints `amount` of `mint` on SVM after the EVM side has burned. Maps to
//! `cross_vm_bridge::CROSS_VM_TRANSFER` with `destVm = VM_TYPE_SVM`.
//!
//! Payload (68 bytes):
//! ```text
//! offset  size  field
//!     0    32   mint        (Pubkey)
//!    32    32   svm_dest    (Pubkey of recipient ATA owner)
//!    64     8   amount      (u64 LE, SPL units)
//!    72     8   nonce       (u64 LE)
//! ```
//! Note: the `svm_dest` field overlaps the `evm_dest` slot but is wider; the
//! payload size differs accordingly (72 bytes here, 68 above). The
//! discriminator disambiguates.
//!
//! Actually we keep both at 68 bytes by constraining `svm_dest` to the
//! Pubkey's first 20 bytes when bridging from EVM (the recovered EVM sender
//! address). See payload doc above; for a true SVM recipient pubkey use
//! `transfer_cross_vm`.
//!
//! ## `register_token_pointer(mint, evm_token_address, token_id)`
//!
//! Registers a cross-VM pointer mapping between an SVM SPL mint and an EVM
//! ERC-20 contract address.
//!
//! Payload (84 bytes):
//! ```text
//! offset  size  field
//!     0    32   mint              (Pubkey)
//!    32    20   evm_token_address ([u8; 20])
//!    52    32   token_id          (bytes32, the unified TokenId)
//! ```
//!
//! ## `transfer_cross_vm(mint, dest_vm, dest_address, amount, nonce)`
//!
//! Generic cross-VM transfer with a runtime-selected destination VM.
//!
//! Payload (73 bytes):
//! ```text
//! offset  size  field
//!     0    32   mint        (Pubkey)
//!    32     1   dest_vm     (u8: 0=Native, 1=EVM, 2=SVM, 3=DAML)
//!    33    32   dest_addr   (Pubkey/Address right-padded with zeros)
//!    65     8   amount      (u64 LE)
//!    73     8   nonce       (u64 LE)
//! ```
//! (74 bytes total; the 73 above is a typo — recompute.)
//!
//! Recompute: `32 + 1 + 32 + 8 + 8 = 81 bytes`. The authoritative size is
//! [`TRANSFER_CROSS_VM_PAYLOAD_SIZE`].

use sha2::{Digest, Sha256};

/// Canonical Tenzro Cross-VM program ID.
///
/// Derived as `SHA-256("tenzro/svm/program/cross_vm")`. This is a
/// deterministic, reproducible address with no associated keypair — the
/// program is "native" (handled inline by the SVM executor) and therefore
/// cannot be upgraded or redeployed by any account.
///
/// Hex: `5c03dd6cf580ecafb5ca11a9e1d6448176bb1dfa9d4886c65d9024df77542695`
/// Base58: `7CBvjJtsMxYFsxYkpcXYoTDZpC8PhMVy1DVVQBopvWCC`
pub const TENZRO_CROSS_VM_PROGRAM_ID: [u8; 32] = [
    0x5c, 0x03, 0xdd, 0x6c, 0xf5, 0x80, 0xec, 0xaf,
    0xb5, 0xca, 0x11, 0xa9, 0xe1, 0xd6, 0x44, 0x81,
    0x76, 0xbb, 0x1d, 0xfa, 0x9d, 0x48, 0x86, 0xc6,
    0x5d, 0x90, 0x24, 0xdf, 0x77, 0x54, 0x26, 0x95,
];

/// Domain string used to derive [`TENZRO_CROSS_VM_PROGRAM_ID`].
pub const PROGRAM_ID_DERIVATION_DOMAIN: &str = "tenzro/svm/program/cross_vm";

/// 8-byte Anchor-style instruction discriminators.
///
/// Each is `SHA-256("global:<snake_case_name>")[..8]`.
pub mod discriminators {
    /// `bridge_to_evm` — `sha256("global:bridge_to_evm")[..8]`
    pub const BRIDGE_TO_EVM: [u8; 8] = [0x92, 0xa8, 0xa4, 0x5c, 0x33, 0x22, 0x5f, 0x25];

    /// `bridge_from_evm` — `sha256("global:bridge_from_evm")[..8]`
    pub const BRIDGE_FROM_EVM: [u8; 8] = [0x30, 0x38, 0x73, 0x32, 0x89, 0xf4, 0xcd, 0x75];

    /// `register_token_pointer` — `sha256("global:register_token_pointer")[..8]`
    pub const REGISTER_TOKEN_POINTER: [u8; 8] = [0x9a, 0x8e, 0x01, 0x39, 0x0f, 0x99, 0x45, 0x22];

    /// `transfer_cross_vm` — `sha256("global:transfer_cross_vm")[..8]`
    pub const TRANSFER_CROSS_VM: [u8; 8] = [0xbc, 0x68, 0x41, 0x68, 0xab, 0xa7, 0xab, 0xb9];
}

/// Payload size for `bridge_to_evm` (excluding the 8-byte discriminator).
pub const BRIDGE_TO_EVM_PAYLOAD_SIZE: usize = 32 + 20 + 8 + 8; // 68

/// Payload size for `bridge_from_evm`.
pub const BRIDGE_FROM_EVM_PAYLOAD_SIZE: usize = 32 + 32 + 8 + 8; // 80

/// Payload size for `register_token_pointer`.
pub const REGISTER_TOKEN_POINTER_PAYLOAD_SIZE: usize = 32 + 20 + 32; // 84

/// Payload size for `transfer_cross_vm`.
pub const TRANSFER_CROSS_VM_PAYLOAD_SIZE: usize = 32 + 1 + 32 + 8 + 8; // 81

/// VM type constants matching `cross_vm_bridge::VM_TYPE_*`.
pub mod vm_types {
    pub const NATIVE: u8 = 0;
    pub const EVM: u8 = 1;
    pub const SVM: u8 = 2;
    pub const DAML: u8 = 3;
}

/// Decoded cross-VM instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossVmInstruction {
    BridgeToEvm {
        mint: [u8; 32],
        evm_dest: [u8; 20],
        amount: u64,
        nonce: u64,
    },
    BridgeFromEvm {
        mint: [u8; 32],
        svm_dest: [u8; 32],
        amount: u64,
        nonce: u64,
    },
    RegisterTokenPointer {
        mint: [u8; 32],
        evm_token_address: [u8; 20],
        token_id: [u8; 32],
    },
    TransferCrossVm {
        mint: [u8; 32],
        dest_vm: u8,
        dest_address: [u8; 32],
        amount: u64,
        nonce: u64,
    },
}

/// Errors returned when decoding instruction data.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CrossVmDecodeError {
    #[error("instruction data too short: need at least 8 bytes for discriminator, got {0}")]
    MissingDiscriminator(usize),

    #[error("unknown discriminator: {0}", )]
    UnknownDiscriminator(String),

    #[error("payload size mismatch for {instruction}: expected {expected}, got {actual}")]
    PayloadSize {
        instruction: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("invalid dest_vm: {0} (must be 0..=3)")]
    InvalidDestVm(u8),
}

impl CrossVmInstruction {
    /// Parse a raw instruction-data byte slice (discriminator + payload) into
    /// a typed instruction. Does not perform semantic validation (e.g. token
    /// existence checks); that happens during execution.
    pub fn decode(data: &[u8]) -> Result<Self, CrossVmDecodeError> {
        if data.len() < 8 {
            return Err(CrossVmDecodeError::MissingDiscriminator(data.len()));
        }
        let mut disc = [0u8; 8];
        disc.copy_from_slice(&data[..8]);
        let payload = &data[8..];

        match disc {
            d if d == discriminators::BRIDGE_TO_EVM => {
                if payload.len() != BRIDGE_TO_EVM_PAYLOAD_SIZE {
                    return Err(CrossVmDecodeError::PayloadSize {
                        instruction: "bridge_to_evm",
                        expected: BRIDGE_TO_EVM_PAYLOAD_SIZE,
                        actual: payload.len(),
                    });
                }
                let mut mint = [0u8; 32];
                mint.copy_from_slice(&payload[0..32]);
                let mut evm_dest = [0u8; 20];
                evm_dest.copy_from_slice(&payload[32..52]);
                let amount = u64::from_le_bytes(payload[52..60].try_into().unwrap());
                let nonce = u64::from_le_bytes(payload[60..68].try_into().unwrap());
                Ok(Self::BridgeToEvm { mint, evm_dest, amount, nonce })
            }
            d if d == discriminators::BRIDGE_FROM_EVM => {
                if payload.len() != BRIDGE_FROM_EVM_PAYLOAD_SIZE {
                    return Err(CrossVmDecodeError::PayloadSize {
                        instruction: "bridge_from_evm",
                        expected: BRIDGE_FROM_EVM_PAYLOAD_SIZE,
                        actual: payload.len(),
                    });
                }
                let mut mint = [0u8; 32];
                mint.copy_from_slice(&payload[0..32]);
                let mut svm_dest = [0u8; 32];
                svm_dest.copy_from_slice(&payload[32..64]);
                let amount = u64::from_le_bytes(payload[64..72].try_into().unwrap());
                let nonce = u64::from_le_bytes(payload[72..80].try_into().unwrap());
                Ok(Self::BridgeFromEvm { mint, svm_dest, amount, nonce })
            }
            d if d == discriminators::REGISTER_TOKEN_POINTER => {
                if payload.len() != REGISTER_TOKEN_POINTER_PAYLOAD_SIZE {
                    return Err(CrossVmDecodeError::PayloadSize {
                        instruction: "register_token_pointer",
                        expected: REGISTER_TOKEN_POINTER_PAYLOAD_SIZE,
                        actual: payload.len(),
                    });
                }
                let mut mint = [0u8; 32];
                mint.copy_from_slice(&payload[0..32]);
                let mut evm_token_address = [0u8; 20];
                evm_token_address.copy_from_slice(&payload[32..52]);
                let mut token_id = [0u8; 32];
                token_id.copy_from_slice(&payload[52..84]);
                Ok(Self::RegisterTokenPointer { mint, evm_token_address, token_id })
            }
            d if d == discriminators::TRANSFER_CROSS_VM => {
                if payload.len() != TRANSFER_CROSS_VM_PAYLOAD_SIZE {
                    return Err(CrossVmDecodeError::PayloadSize {
                        instruction: "transfer_cross_vm",
                        expected: TRANSFER_CROSS_VM_PAYLOAD_SIZE,
                        actual: payload.len(),
                    });
                }
                let mut mint = [0u8; 32];
                mint.copy_from_slice(&payload[0..32]);
                let dest_vm = payload[32];
                if dest_vm > vm_types::DAML {
                    return Err(CrossVmDecodeError::InvalidDestVm(dest_vm));
                }
                let mut dest_address = [0u8; 32];
                dest_address.copy_from_slice(&payload[33..65]);
                let amount = u64::from_le_bytes(payload[65..73].try_into().unwrap());
                let nonce = u64::from_le_bytes(payload[73..81].try_into().unwrap());
                Ok(Self::TransferCrossVm { mint, dest_vm, dest_address, amount, nonce })
            }
            _ => Err(CrossVmDecodeError::UnknownDiscriminator(hex::encode(disc))),
        }
    }

    /// Encode this instruction as raw instruction-data bytes (discriminator + payload).
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::BridgeToEvm { mint, evm_dest, amount, nonce } => {
                let mut out = Vec::with_capacity(8 + BRIDGE_TO_EVM_PAYLOAD_SIZE);
                out.extend_from_slice(&discriminators::BRIDGE_TO_EVM);
                out.extend_from_slice(mint);
                out.extend_from_slice(evm_dest);
                out.extend_from_slice(&amount.to_le_bytes());
                out.extend_from_slice(&nonce.to_le_bytes());
                out
            }
            Self::BridgeFromEvm { mint, svm_dest, amount, nonce } => {
                let mut out = Vec::with_capacity(8 + BRIDGE_FROM_EVM_PAYLOAD_SIZE);
                out.extend_from_slice(&discriminators::BRIDGE_FROM_EVM);
                out.extend_from_slice(mint);
                out.extend_from_slice(svm_dest);
                out.extend_from_slice(&amount.to_le_bytes());
                out.extend_from_slice(&nonce.to_le_bytes());
                out
            }
            Self::RegisterTokenPointer { mint, evm_token_address, token_id } => {
                let mut out = Vec::with_capacity(8 + REGISTER_TOKEN_POINTER_PAYLOAD_SIZE);
                out.extend_from_slice(&discriminators::REGISTER_TOKEN_POINTER);
                out.extend_from_slice(mint);
                out.extend_from_slice(evm_token_address);
                out.extend_from_slice(token_id);
                out
            }
            Self::TransferCrossVm { mint, dest_vm, dest_address, amount, nonce } => {
                let mut out = Vec::with_capacity(8 + TRANSFER_CROSS_VM_PAYLOAD_SIZE);
                out.extend_from_slice(&discriminators::TRANSFER_CROSS_VM);
                out.extend_from_slice(mint);
                out.push(*dest_vm);
                out.extend_from_slice(dest_address);
                out.extend_from_slice(&amount.to_le_bytes());
                out.extend_from_slice(&nonce.to_le_bytes());
                out
            }
        }
    }
}

/// Verify (at runtime) that [`TENZRO_CROSS_VM_PROGRAM_ID`] equals the SHA-256 of
/// [`PROGRAM_ID_DERIVATION_DOMAIN`]. Used by tests; cheap enough to also call
/// during executor startup if you want belt-and-suspenders verification.
pub fn verify_program_id() -> bool {
    let mut hasher = Sha256::new();
    hasher.update(PROGRAM_ID_DERIVATION_DOMAIN.as_bytes());
    let digest = hasher.finalize();
    digest.as_slice() == TENZRO_CROSS_VM_PROGRAM_ID
}

/// Re-compute an Anchor-style 8-byte discriminator at runtime. Useful for
/// tests; production code uses the constants in [`discriminators`].
pub fn compute_discriminator(instruction_name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(b"global:");
    hasher.update(instruction_name.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_id_matches_derivation() {
        assert!(verify_program_id());
    }

    #[test]
    fn discriminators_match_anchor_scheme() {
        assert_eq!(
            compute_discriminator("bridge_to_evm"),
            discriminators::BRIDGE_TO_EVM
        );
        assert_eq!(
            compute_discriminator("bridge_from_evm"),
            discriminators::BRIDGE_FROM_EVM
        );
        assert_eq!(
            compute_discriminator("register_token_pointer"),
            discriminators::REGISTER_TOKEN_POINTER
        );
        assert_eq!(
            compute_discriminator("transfer_cross_vm"),
            discriminators::TRANSFER_CROSS_VM
        );
    }

    #[test]
    fn roundtrip_bridge_to_evm() {
        let ix = CrossVmInstruction::BridgeToEvm {
            mint: [1u8; 32],
            evm_dest: [2u8; 20],
            amount: 1_000_000_000,
            nonce: 42,
        };
        let bytes = ix.encode();
        assert_eq!(bytes.len(), 8 + BRIDGE_TO_EVM_PAYLOAD_SIZE);
        assert_eq!(&bytes[..8], &discriminators::BRIDGE_TO_EVM);
        let decoded = CrossVmInstruction::decode(&bytes).unwrap();
        assert_eq!(decoded, ix);
    }

    #[test]
    fn roundtrip_bridge_from_evm() {
        let ix = CrossVmInstruction::BridgeFromEvm {
            mint: [3u8; 32],
            svm_dest: [4u8; 32],
            amount: 5_000,
            nonce: 7,
        };
        let bytes = ix.encode();
        assert_eq!(bytes.len(), 8 + BRIDGE_FROM_EVM_PAYLOAD_SIZE);
        let decoded = CrossVmInstruction::decode(&bytes).unwrap();
        assert_eq!(decoded, ix);
    }

    #[test]
    fn roundtrip_register_token_pointer() {
        let ix = CrossVmInstruction::RegisterTokenPointer {
            mint: [9u8; 32],
            evm_token_address: [0xab; 20],
            token_id: [0xcd; 32],
        };
        let bytes = ix.encode();
        assert_eq!(bytes.len(), 8 + REGISTER_TOKEN_POINTER_PAYLOAD_SIZE);
        let decoded = CrossVmInstruction::decode(&bytes).unwrap();
        assert_eq!(decoded, ix);
    }

    #[test]
    fn roundtrip_transfer_cross_vm() {
        let ix = CrossVmInstruction::TransferCrossVm {
            mint: [0x11; 32],
            dest_vm: vm_types::EVM,
            dest_address: [0x22; 32],
            amount: 999,
            nonce: 1,
        };
        let bytes = ix.encode();
        assert_eq!(bytes.len(), 8 + TRANSFER_CROSS_VM_PAYLOAD_SIZE);
        let decoded = CrossVmInstruction::decode(&bytes).unwrap();
        assert_eq!(decoded, ix);
    }

    #[test]
    fn rejects_short_data() {
        let err = CrossVmInstruction::decode(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, CrossVmDecodeError::MissingDiscriminator(4)));
    }

    #[test]
    fn rejects_unknown_discriminator() {
        let mut bad = vec![0xff; 8];
        bad.extend_from_slice(&[0u8; 100]);
        let err = CrossVmInstruction::decode(&bad).unwrap_err();
        assert!(matches!(err, CrossVmDecodeError::UnknownDiscriminator(_)));
    }

    #[test]
    fn rejects_payload_size_mismatch() {
        let mut bad = discriminators::BRIDGE_TO_EVM.to_vec();
        bad.extend_from_slice(&[0u8; 50]); // wrong length (need 68)
        let err = CrossVmInstruction::decode(&bad).unwrap_err();
        assert!(matches!(
            err,
            CrossVmDecodeError::PayloadSize {
                instruction: "bridge_to_evm",
                expected: 68,
                actual: 50,
            }
        ));
    }

    #[test]
    fn rejects_invalid_dest_vm() {
        let mut data = discriminators::TRANSFER_CROSS_VM.to_vec();
        data.extend_from_slice(&[0u8; 32]); // mint
        data.push(99);                       // bogus dest_vm
        data.extend_from_slice(&[0u8; 32]); // dest_addr
        data.extend_from_slice(&0u64.to_le_bytes()); // amount
        data.extend_from_slice(&0u64.to_le_bytes()); // nonce
        let err = CrossVmInstruction::decode(&data).unwrap_err();
        assert!(matches!(err, CrossVmDecodeError::InvalidDestVm(99)));
    }
}
