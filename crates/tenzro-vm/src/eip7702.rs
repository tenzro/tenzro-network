//! EIP-7702 delegation registry — protocol-level state for Pectra Type-4
//! authorizations.
//!
//! The stateless 7702 primitives (signing-hash computation, designator
//! build/parse, signature recovery, `Eip7702Authorization` type) live in
//! [`crate::account_abstraction`]. This module adds the **stateful** half:
//! a process-wide registry that records the active delegation pointer per
//! authority and exposes install / resolve / revoke against it.
//!
//! The EVM executor consults [`DelegationRegistry::resolve_target`] when
//! it encounters a call whose target's code begins with the EIP-7702
//! designator prefix `0xef0100`. The registry holds the structured
//! pointer so the executor can use the target's code in the authority's
//! storage context per the EIP.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::account_abstraction::{
    build_7702_designator, parse_7702_designator, Eip7702Authorization,
};
use crate::error::VmError;
use tenzro_types::primitives::Address;

/// Errors that can arise when applying a 7702 authorization.
#[derive(Debug, Error)]
pub enum DelegationError {
    /// The signature could not be recovered or the recovered authority is
    /// the zero address.
    #[error("invalid authorization signature")]
    InvalidSignature,

    /// The authorization's chain_id does not match the current chain.
    #[error("chain_id mismatch: authorization for {auth}, current chain {current}")]
    ChainIdMismatch {
        /// Chain id named in the authorization.
        auth: u64,
        /// Current chain id.
        current: u64,
    },

    /// The authorization's nonce does not match the authority's expected nonce.
    #[error("nonce mismatch: authorization {auth}, account {account}")]
    NonceMismatch {
        /// Nonce named in the authorization.
        auth: u64,
        /// Account's current nonce.
        account: u64,
    },

    /// The recovered authority does not match the declared authority.
    #[error("recovered authority {recovered} does not match declared authority {declared}")]
    AuthorityMismatch {
        /// Authority recovered from the signature, lowercase hex.
        recovered: String,
        /// Authority the caller declared, lowercase hex.
        declared: String,
    },

    /// The authorization's `delegate_address` is not 20 bytes.
    #[error("delegate_address must be 20 bytes")]
    InvalidDelegateAddress,

    /// Underlying VM error from one of the stateless 7702 helpers.
    #[error("vm: {0}")]
    Vm(String),
}

impl From<VmError> for DelegationError {
    fn from(err: VmError) -> Self {
        DelegationError::Vm(err.to_string())
    }
}

/// In-memory per-account delegation pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationPointer {
    /// Contract whose code is borrowed when this account is called. Stored
    /// as a 20-byte EVM address.
    pub target: [u8; 20],
    /// Chain id from the authorization (`0` = any chain).
    pub chain_id: u64,
    /// Authority nonce at install time (sanity / replay record).
    pub authority_nonce: u64,
}

impl DelegationPointer {
    /// Synthesize the 23-byte designator per EIP-7702.
    pub fn designator_bytes(&self) -> Vec<u8> {
        // `build_7702_designator` returns a Result but the only failure
        // mode is delegate_address length != 20, which can't happen for
        // a stored pointer.
        build_7702_designator(&self.target).unwrap_or_else(|_| {
            let mut out = Vec::with_capacity(23);
            out.extend_from_slice(&[0xef, 0x01, 0x00]);
            out.extend_from_slice(&self.target);
            out
        })
    }
}

/// Returns `true` iff `code` is a 23-byte 7702 designator (`0xef0100 || 20 bytes`).
pub fn is_delegation_designator(code: &[u8]) -> bool {
    parse_7702_designator(code).is_some()
}

/// Extract the delegation target from a 23-byte designator. Returns `None`
/// if `code` is not a valid 7702 designator.
pub fn extract_delegation_target(code: &[u8]) -> Option<[u8; 20]> {
    let raw = parse_7702_designator(code)?;
    if raw.len() != 20 {
        return None;
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&raw);
    Some(out)
}

/// Process-wide registry of active 7702 delegations.
#[derive(Debug, Default)]
pub struct DelegationRegistry {
    inner: RwLock<HashMap<[u8; 20], DelegationPointer>>,
}

impl DelegationRegistry {
    /// Build an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a signed authorization tuple on behalf of `expected_authority`.
    ///
    /// `current_chain_id` is the chain id of the executing block;
    /// authorizations with `chain_id == 0` are accepted on any chain per
    /// the EIP. `current_nonce` is the authority's pre-call nonce.
    pub fn install(
        &self,
        auth: &Eip7702Authorization,
        expected_authority: [u8; 20],
        current_chain_id: u64,
        current_nonce: u64,
    ) -> Result<DelegationPointer, DelegationError> {
        if auth.chain_id != 0 && auth.chain_id != current_chain_id {
            return Err(DelegationError::ChainIdMismatch {
                auth: auth.chain_id,
                current: current_chain_id,
            });
        }
        if auth.nonce != current_nonce {
            return Err(DelegationError::NonceMismatch {
                auth: auth.nonce,
                account: current_nonce,
            });
        }
        if auth.delegate_address.len() != 20 {
            return Err(DelegationError::InvalidDelegateAddress);
        }

        let recovered = crate::account_abstraction::recover_eoa_from_7702_signature(auth)
            .map_err(|_| DelegationError::InvalidSignature)?;
        if recovered.len() != 20 {
            return Err(DelegationError::InvalidSignature);
        }
        if recovered.as_slice() != expected_authority.as_slice() {
            return Err(DelegationError::AuthorityMismatch {
                recovered: hex::encode(&recovered),
                declared: hex::encode(expected_authority),
            });
        }

        let mut target = [0u8; 20];
        target.copy_from_slice(&auth.delegate_address);

        let pointer = DelegationPointer {
            target,
            chain_id: auth.chain_id,
            authority_nonce: auth.nonce,
        };

        // Per EIP-7702 §"clear delegation": delegating to the zero address
        // revokes any active delegation rather than installing a new one.
        if target == [0u8; 20] {
            self.inner.write().remove(&expected_authority);
        } else {
            self.inner
                .write()
                .insert(expected_authority, pointer.clone());
        }
        Ok(pointer)
    }

    /// Returns the active delegation pointer for `account`, if any.
    pub fn resolve_target(&self, account: &[u8; 20]) -> Option<DelegationPointer> {
        self.inner.read().get(account).cloned()
    }

    /// Returns `true` iff `account` currently has an active delegation.
    pub fn is_delegated(&self, account: &[u8; 20]) -> bool {
        self.inner.read().contains_key(account)
    }

    /// Revoke any active delegation for `account` without requiring a
    /// signed authorization. Used during account self-destruct, social
    /// recovery, and explicit operator override paths.
    pub fn revoke(&self, account: &[u8; 20]) -> bool {
        self.inner.write().remove(account).is_some()
    }

    /// Number of active delegations.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Returns `true` iff the registry has no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

/// Convert a Tenzro 32-byte `Address` (last 20 bytes = EVM address) into
/// the 20-byte EVM array used by [`DelegationRegistry`].
pub fn address_to_evm20(address: &Address) -> [u8; 20] {
    let bytes = address.as_bytes();
    let slice = if bytes.len() >= 20 {
        &bytes[bytes.len() - 20..]
    } else {
        bytes
    };
    let mut out = [0u8; 20];
    let dst_start = 20 - slice.len();
    out[dst_start..].copy_from_slice(slice);
    out
}

/// Shareable handle around a [`DelegationRegistry`].
pub type SharedDelegationRegistry = Arc<DelegationRegistry>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn designator_roundtrip() {
        let target = [0x42u8; 20];
        let pointer = DelegationPointer {
            target,
            chain_id: 1,
            authority_nonce: 7,
        };
        let bytes = pointer.designator_bytes();
        assert_eq!(bytes.len(), 23);
        assert!(is_delegation_designator(&bytes));
        assert_eq!(extract_delegation_target(&bytes), Some(target));
    }

    #[test]
    fn non_designator_rejected() {
        assert!(!is_delegation_designator(&[0xef, 0x01, 0x00]));
        assert!(extract_delegation_target(&[0xef, 0x01, 0x01]).is_none());
    }

    #[test]
    fn registry_revoke() {
        let registry = DelegationRegistry::new();
        let authority = [1u8; 20];
        registry.inner.write().insert(
            authority,
            DelegationPointer {
                target: [2u8; 20],
                chain_id: 0,
                authority_nonce: 0,
            },
        );
        assert!(registry.is_delegated(&authority));
        assert!(registry.revoke(&authority));
        assert!(!registry.is_delegated(&authority));
        assert!(!registry.revoke(&authority));
    }
}
