//! Which identity a wallet belongs to, and what roots it.
//!
//! # The rule
//!
//! **A wallet may not exist without an identity.** Not "should not" — the type
//! system does not let you name one: [`WalletIdentity`] is a required parameter
//! of wallet provisioning and has no `Default`, no empty variant, and no
//! constructor that omits the key.
//!
//! # Two identity classes, two roots
//!
//! | Identity | Who holds the key | Root |
//! |---|---|---|
//! | [`WalletIdentity::Human`] | a person | passkey (WebAuthn) |
//! | [`WalletIdentity::Machine`] | a node | TPM 2.0 or Apple Secure Enclave |
//!
//! These are not interchangeable and the distinction is recorded rather than
//! inferred. A machine wallet is rooted in hardware that can prove possession
//! of a non-exportable key; a human wallet is rooted in an authenticator the
//! person carries. Anything deciding what a wallet may do needs to know which,
//! and asking "does it have a TPM?" of a passkey wallet is a category error.
//!
//! # What is NOT here
//!
//! No custodial option. The service never generates a signing secret: under
//! both classes the private half lives with the identity holder — in the
//! authenticator or in the secure element — and the wallet carries only the
//! public half. A wallet the service could sign for alone is a wallet the
//! service can be compelled to sign for.

use tenzro_crypto::PublicKey;

use crate::error::{Result, WalletError};

/// The identity a wallet belongs to.
///
/// Constructed through [`Self::human`] or [`Self::machine`], both of which
/// require the identity's public key. There is deliberately no way to build one
/// without it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalletIdentity {
    /// A person, rooted in a passkey (WebAuthn authenticator).
    Human {
        /// The WebAuthn credential this identity authenticates with.
        credential_id: Vec<u8>,
        /// Public half of the passkey. The private half never leaves the
        /// authenticator.
        public_key: PublicKey,
    },
    /// A machine, rooted in a TPM 2.0 or Apple Secure Enclave key.
    Machine {
        /// Stable machine identifier this wallet is bound to.
        machine_id: String,
        /// Public half of the device key. The private half cannot be exported
        /// from the secure element.
        public_key: PublicKey,
    },
}

impl WalletIdentity {
    /// A human identity rooted in a passkey.
    ///
    /// `credential_id` is rejected when empty: a passkey wallet that cannot
    /// name its credential cannot ever be authenticated, so it would be a
    /// wallet nobody can open.
    pub fn human(credential_id: Vec<u8>, public_key: PublicKey) -> Result<Self> {
        if credential_id.is_empty() {
            return Err(WalletError::InvalidKeyMaterial(
                "a human wallet needs a passkey credential id".to_string(),
            ));
        }
        Ok(Self::Human {
            credential_id,
            public_key,
        })
    }

    /// A machine identity rooted in a TPM or Secure Enclave key.
    pub fn machine(machine_id: impl Into<String>, public_key: PublicKey) -> Result<Self> {
        let machine_id = machine_id.into();
        if machine_id.trim().is_empty() {
            return Err(WalletError::InvalidKeyMaterial(
                "a machine wallet needs a machine id".to_string(),
            ));
        }
        Ok(Self::Machine {
            machine_id,
            public_key,
        })
    }

    /// The public key this wallet's signatures verify against.
    pub fn public_key(&self) -> &PublicKey {
        match self {
            Self::Human { public_key, .. } | Self::Machine { public_key, .. } => public_key,
        }
    }

    /// Whether the signing key is held in a secure element rather than an
    /// authenticator. Recorded, not inferred — see the module docs.
    pub fn is_machine(&self) -> bool {
        matches!(self, Self::Machine { .. })
    }

    /// Stable label for logs and records.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Human { .. } => "human:passkey",
            Self::Machine { .. } => "machine:secure-element",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::KeyType;

    fn pk() -> PublicKey {
        PublicKey::new(KeyType::Ed25519, vec![7u8; 32])
    }

    #[test]
    fn a_human_wallet_needs_a_credential() {
        assert!(WalletIdentity::human(Vec::new(), pk()).is_err());
        assert!(WalletIdentity::human(vec![1, 2, 3], pk()).is_ok());
    }

    #[test]
    fn a_machine_wallet_needs_a_machine_id() {
        assert!(WalletIdentity::machine("   ", pk()).is_err());
        assert!(WalletIdentity::machine("node-1", pk()).is_ok());
    }

    /// The two classes must stay distinguishable: deciding what a wallet may do
    /// depends on which root it has, and inferring it would be a guess.
    #[test]
    fn the_two_classes_are_distinguishable() {
        let h = WalletIdentity::human(vec![1], pk()).unwrap();
        let m = WalletIdentity::machine("node-1", pk()).unwrap();
        assert!(!h.is_machine());
        assert!(m.is_machine());
        assert_ne!(h.kind(), m.kind());
    }

    #[test]
    fn both_expose_the_verifying_key() {
        let h = WalletIdentity::human(vec![1], pk()).unwrap();
        assert_eq!(h.public_key(), &pk());
    }
}
