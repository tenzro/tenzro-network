//! [`DeviceBackend`] over the Apple Secure Enclave.
//!
//! Concrete counterpart to [`crate::device_custody`]: the classical leg is a
//! P-256 key that never leaves the enclave, the PQ leg is the ML-DSA-65
//! companion whose seed is sealed into a multi-recipient envelope.
//!
//! # Why the PQ seed is not enclave-only
//!
//! ML-DSA-65 has no hardware backing on current Apple silicon, so its seed has
//! to live somewhere. Sealing it to the enclave *alone* would mean a dead logic
//! board destroys the wallet, and the ML-DSA verifying key is enrolled as a
//! permanent identity — losing the seed strands the account rather than costing
//! a cache. [`PqCompanion`] therefore seals into an envelope addressed to the
//! enclave **and** a recovery recipient the operator holds.
//!
//! The classical P-256 key has the opposite property on purpose: it genuinely
//! cannot be recovered, because it genuinely never leaves the enclave. Losing
//! the machine means re-enrolling that leg, not recovering it.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::device_custody::DeviceBackend;
use crate::error::{Result, WalletError};

use tenzro_device_key::PqCompanion;
use tenzro_device_key::envelope::Recipient;

/// Secure Enclave backend for a device-custody wallet.
pub struct SecureEnclaveBackend {
    label: String,
    classical_pk: Vec<u8>,
    companion: PqCompanion,
}

impl SecureEnclaveBackend {
    /// Enrol a new wallet key on this machine.
    ///
    /// `recovery` is required and is not generated here: the operator has to
    /// keep the matching code. One minted internally and discarded would look
    /// like redundancy while providing none.
    pub fn enrol(
        label: impl Into<String>,
        pq_ciphertext_path: impl Into<PathBuf>,
        recovery: &Recipient,
    ) -> Result<Self> {
        let label = label.into();
        // `false`: a wallet key on a node must be usable without a human to
        // answer a Touch ID prompt. An interactive wallet should pass `true`.
        tenzro_device_key::backend_se::create_with_presence(&label, false)
            .map_err(|e| WalletError::InvalidKeyMaterial(format!("create device key: {e}")))?;
        let companion = PqCompanion::enrol(label.clone(), pq_ciphertext_path, recovery)
            .map_err(|e| WalletError::InvalidKeyMaterial(format!("enrol pq companion: {e}")))?;
        Self::bind(label, companion)
    }

    /// Reopen an already-enrolled wallet key.
    pub fn open(label: impl Into<String>, pq_ciphertext_path: impl Into<PathBuf>) -> Result<Self> {
        let label = label.into();
        let companion = PqCompanion::open(label.clone(), pq_ciphertext_path)
            .map_err(|e| WalletError::InvalidKeyMaterial(format!("open pq companion: {e}")))?;
        Self::bind(label, companion)
    }

    fn bind(label: String, companion: PqCompanion) -> Result<Self> {
        let ident = tenzro_device_key::backend_se::identity(&label)
            .map_err(|e| WalletError::InvalidKeyMaterial(format!("device identity: {e}")))?;
        // The SIGNING key is the device's identity; the agreement key is a
        // subordinate credential. Binding the wallet to the wrong one would
        // produce an address nothing can sign for.
        Ok(Self {
            label,
            classical_pk: ident.signing.to_vec(),
            companion,
        })
    }
}

#[async_trait]
impl DeviceBackend for SecureEnclaveBackend {
    fn classical_public_key(&self) -> Vec<u8> {
        self.classical_pk.clone()
    }

    fn pq_verifying_key(&self) -> Vec<u8> {
        self.companion.verifying_key_bytes().to_vec()
    }

    async fn sign_classical(&self, message: &[u8]) -> Result<Vec<u8>> {
        // The enclave signs a 32-byte prehash, so hash here rather than making
        // every caller remember to. Verified elsewhere as standard ECDSA over
        // SHA-256, so any ordinary verifier accepts it.
        let digest: [u8; 32] = Sha256::digest(message).into();
        let key = tenzro_device_key::backend_se::open(&self.label)
            .map_err(|e| WalletError::InvalidKeyMaterial(format!("open device key: {e}")))?;
        let sig = key
            .sign_prehash(&digest)
            .map_err(|e| WalletError::InvalidKeyMaterial(format!("device sign: {e}")))?;
        Ok(sig.to_vec())
    }

    async fn sign_pq(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.companion.sign(message))
    }
}

/// Convenience: a hybrid signer backed by this machine's Secure Enclave.
pub fn signer(backend: SecureEnclaveBackend) -> Result<crate::device_custody::DeviceCustodySigner> {
    crate::device_custody::DeviceCustodySigner::new(Arc::new(backend))
}
