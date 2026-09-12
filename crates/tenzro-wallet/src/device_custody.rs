//! Local custody: a wallet whose keys live in this machine's secure element.
//!
//! # Why this exists
//!
//! Tenzro's original custody model was threshold MPC — a wallet held key
//! shares and signed by coordinating rounds across them. That has been
//! superseded by **permissionless key management controlled locally**: passkeys
//! for human identity, a TPM or Secure Enclave for machine identity.
//!
//! This module is the wallet-side half of that. It is deliberately built on the
//! two seams the crate already has rather than a third custody shape:
//!
//! * [`Wallet::new_watch_only`] — a wallet holding **no** signing secrets, whose
//!   address and public keys mirror a key the node cannot read. That is exactly
//!   the shape of a device-key wallet: the private half never leaves the
//!   enclave, so the node genuinely cannot hold it.
//! * [`HybridSigner`] — the async signing seam, already written to accommodate
//!   "a TEE call or a device round-trip".
//!
//! So a device-custody wallet is not a new kind of wallet. It is a watch-only
//! wallet bound to a signer that happens to be hardware.
//!
//! # What is NOT solved here
//!
//! The classical leg is P-256 from the Secure Enclave; the PQ leg is ML-DSA-65
//! held by [`tenzro_device_key::PqCompanion`], whose seed is sealed into a
//! multi-recipient envelope so hardware death is survivable. Both legs are
//! mandatory, matching [`HybridSignatureBytes`] — there is no classical-only
//! path here either.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::{Result, WalletError};
use crate::signing::{HybridSignatureBytes, HybridSigner};

/// A signer whose classical leg is a hardware key that cannot be exported.
///
/// The private half never enters process memory: signing is a round-trip into
/// the secure element. That is the property MPC was originally reaching for,
/// obtained from hardware instead of from a threshold.
pub struct DeviceCustodySigner {
    classical_pk: Vec<u8>,
    pq_vk: Vec<u8>,
    backend: Arc<dyn DeviceBackend>,
}

/// The hardware operations device custody needs.
///
/// A trait rather than a concrete type so the same wallet shape works over a
/// Secure Enclave, a TPM, or a test double — and so `tenzro-wallet` does not
/// take a hard dependency on any one platform.
#[async_trait]
pub trait DeviceBackend: Send + Sync {
    /// Raw classical public key this backend signs under.
    fn classical_public_key(&self) -> Vec<u8>;

    /// ML-DSA-65 verifying key (1952 bytes) of the PQ companion.
    fn pq_verifying_key(&self) -> Vec<u8>;

    /// Sign `message` with the hardware classical key.
    async fn sign_classical(&self, message: &[u8]) -> Result<Vec<u8>>;

    /// Sign `message` with the PQ companion key.
    async fn sign_pq(&self, message: &[u8]) -> Result<Vec<u8>>;
}

impl DeviceCustodySigner {
    /// Bind a signer to a hardware backend.
    ///
    /// The key lengths are checked here rather than at first signature, because
    /// a wrong-length verifying key produces a wallet whose address is derived
    /// from one key and whose signatures verify against another — a mismatch
    /// that would surface only when a transaction is rejected.
    pub fn new(backend: Arc<dyn DeviceBackend>) -> Result<Self> {
        let classical_pk = backend.classical_public_key();
        let pq_vk = backend.pq_verifying_key();
        if pq_vk.len() != 1952 {
            return Err(WalletError::InvalidKeyMaterial(format!(
                "ML-DSA-65 verifying key must be 1952 bytes, got {}",
                pq_vk.len()
            )));
        }
        if classical_pk.is_empty() {
            return Err(WalletError::InvalidKeyMaterial(
                "device backend returned an empty classical public key".to_string(),
            ));
        }
        Ok(Self {
            classical_pk,
            pq_vk,
            backend,
        })
    }
}

#[async_trait]
impl HybridSigner for DeviceCustodySigner {
    fn classical_public_key(&self) -> Vec<u8> {
        self.classical_pk.clone()
    }

    fn pq_verifying_key(&self) -> Vec<u8> {
        self.pq_vk.clone()
    }

    async fn sign_hybrid(&self, message: &[u8]) -> Result<HybridSignatureBytes> {
        // Both legs sign the same bytes, as HybridSignatureBytes requires.
        let classical = self.backend.sign_classical(message).await?;
        let pq = self.backend.sign_pq(message).await?;
        Ok(HybridSignatureBytes::new(classical, pq))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stub {
        pq_len: usize,
        classical_len: usize,
    }

    #[async_trait]
    impl DeviceBackend for Stub {
        fn classical_public_key(&self) -> Vec<u8> {
            vec![7u8; self.classical_len]
        }
        fn pq_verifying_key(&self) -> Vec<u8> {
            vec![9u8; self.pq_len]
        }
        async fn sign_classical(&self, m: &[u8]) -> Result<Vec<u8>> {
            Ok(m.to_vec())
        }
        async fn sign_pq(&self, m: &[u8]) -> Result<Vec<u8>> {
            Ok(m.to_vec())
        }
    }

    /// A wrong-length PQ key must be refused at binding time, not at the first
    /// signature — otherwise the wallet's address and its signatures disagree
    /// and that only surfaces when a transaction is rejected.
    #[test]
    fn wrong_length_pq_key_is_refused_at_construction() {
        let s = DeviceCustodySigner::new(Arc::new(Stub {
            pq_len: 32,
            classical_len: 32,
        }));
        assert!(s.is_err());
    }

    #[test]
    fn empty_classical_key_is_refused() {
        let s = DeviceCustodySigner::new(Arc::new(Stub {
            pq_len: 1952,
            classical_len: 0,
        }));
        assert!(s.is_err());
    }

    #[tokio::test]
    async fn both_legs_sign_the_same_bytes() {
        let s = DeviceCustodySigner::new(Arc::new(Stub {
            pq_len: 1952,
            classical_len: 32,
        }))
        .expect("valid backend");
        let sig = s.sign_hybrid(b"payload").await.expect("sign");
        assert_eq!(sig.classical, b"payload");
        assert_eq!(sig.pq, b"payload");
    }
}
