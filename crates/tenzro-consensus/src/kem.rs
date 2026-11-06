//! ML-KEM-768 for the channel handshake and sealed endpoints:
//! [`tenzro_crypto::ml_kem768`], with its refusals reported as channel
//! errors.

use tenzro_crypto::ml_kem768 as imp;

use crate::error::{ConsensusError, Result};

pub(crate) use tenzro_crypto::ml_kem768::{ML_KEM_768_CT_LEN, ML_KEM_768_EK_LEN, ML_KEM_SS_LEN};

fn channel(e: tenzro_crypto::CryptoError) -> ConsensusError {
    ConsensusError::Channel(e.to_string())
}

/// A handshake's ephemeral ML-KEM-768 decapsulation key.
pub(crate) struct EphemeralKem(imp::EphemeralKem);

impl EphemeralKem {
    /// A fresh key pair from the OS random source.
    pub(crate) fn generate() -> Self {
        Self(imp::EphemeralKem::generate())
    }

    /// The encapsulation key, sent to the peer.
    pub(crate) fn encapsulation_key(&self) -> &[u8] {
        self.0.encapsulation_key()
    }

    /// The shared secret a peer's ciphertext carries.
    pub(crate) fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; ML_KEM_SS_LEN]> {
        self.0.decapsulate(ciphertext).map_err(channel)
    }
}

/// Encapsulates a fresh shared secret to `encapsulation_key`: the ciphertext
/// for the peer, and the secret.
pub(crate) fn encapsulate(encapsulation_key: &[u8]) -> Result<(Vec<u8>, [u8; ML_KEM_SS_LEN])> {
    imp::encapsulate(encapsulation_key).map_err(channel)
}
