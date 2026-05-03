//! Persistent Ed25519 signer for Cortex workers.
//!
//! In prior iterations the Cortex worker signed receipts with an ephemeral
//! `Ed25519SignerImpl::generate()` — meaning the `worker_did` and public
//! key in receipts changed on every node restart. Auditors verifying
//! historical receipts against a `worker_did` hash would see signatures
//! from keys that no longer existed.
//!
//! [`PersistentCortexSigner`] loads a 32-byte Ed25519 secret from disk
//! (or generates and persists a fresh one on first launch). The key file
//! is written with owner-read-only permissions on Unix.

use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use tenzro_crypto::{
    keys::{KeyPair, KeyType},
    signatures::{Ed25519SignerImpl, Signature, Signer},
};

use crate::error::{CortexError, Result};

/// Ed25519 secret key size in bytes.
const ED25519_SECRET_SIZE: usize = 32;

/// Persistent signer that loads-or-generates an Ed25519 key file.
///
/// Wraps an [`Ed25519SignerImpl`] so it plugs into the existing
/// [`Signer`] trait used by [`crate::worker::CortexWorker`].
pub struct PersistentCortexSigner {
    inner: Ed25519SignerImpl,
    key_path: PathBuf,
}

impl PersistentCortexSigner {
    /// Load an Ed25519 signer from `key_path`, or generate + persist
    /// a new one if the file is missing.
    ///
    /// The key file format is the raw 32-byte Ed25519 secret, written
    /// with mode 0o600 on Unix.
    pub fn load_or_generate(key_path: impl Into<PathBuf>) -> Result<Self> {
        let key_path = key_path.into();

        if key_path.exists() {
            let bytes = std::fs::read(&key_path)
                .map_err(|e| CortexError::Crypto(format!("read key file: {e}")))?;
            if bytes.len() != ED25519_SECRET_SIZE {
                return Err(CortexError::Crypto(format!(
                    "invalid key file at {}: expected {} bytes, got {}",
                    key_path.display(),
                    ED25519_SECRET_SIZE,
                    bytes.len()
                )));
            }
            let keypair = KeyPair::from_bytes(KeyType::Ed25519, &bytes)
                .map_err(|e| CortexError::Crypto(format!("decode key: {e}")))?;
            let inner = Ed25519SignerImpl::new(keypair)
                .map_err(|e| CortexError::Crypto(format!("build signer: {e}")))?;
            return Ok(Self { inner, key_path });
        }

        // Generate a fresh Ed25519 keypair, persist its 32-byte secret,
        // then build the signer. We go through `KeyPair` rather than
        // `Ed25519SignerImpl::generate()` so we retain access to the
        // secret bytes for disk serialization.
        let keypair = KeyPair::generate(KeyType::Ed25519)
            .map_err(|e| CortexError::Crypto(format!("generate key: {e}")))?;
        let secret_bytes = keypair.to_bytes();
        persist_key(&key_path, &secret_bytes)?;
        let inner = Ed25519SignerImpl::new(keypair)
            .map_err(|e| CortexError::Crypto(format!("build signer: {e}")))?;
        Ok(Self { inner, key_path })
    }

    /// Path to the persisted key file.
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    /// Borrow the underlying [`Ed25519SignerImpl`].
    pub fn inner(&self) -> &Ed25519SignerImpl {
        &self.inner
    }

    /// Wrap this persistent signer into an `Arc<dyn Signer + Send + Sync>`
    /// for use with [`crate::worker::CortexWorker::new`].
    pub fn into_arc(self) -> Arc<dyn Signer + Send + Sync> {
        Arc::new(self)
    }
}

impl Signer for PersistentCortexSigner {
    fn sign(&self, message: &[u8]) -> tenzro_crypto::error::Result<Signature> {
        self.inner.sign(message)
    }

    fn public_key(&self) -> &tenzro_crypto::keys::PublicKey {
        self.inner.public_key()
    }
}

/// Persist raw key bytes to disk with tight permissions.
fn persist_key(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CortexError::Crypto(format!("create key dir: {e}")))?;
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(path)
        .map_err(|e| CortexError::Crypto(format!("create key file: {e}")))?;
    file.write_all(bytes)
        .map_err(|e| CortexError::Crypto(format!("write key file: {e}")))?;
    file.sync_all()
        .map_err(|e| CortexError::Crypto(format!("fsync key file: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_or_generate_creates_key() {
        let tmp = std::env::temp_dir().join(format!(
            "cortex-signer-test-{}",
            uuid::Uuid::new_v4()
        ));
        let path = tmp.join("cortex-worker.key");
        let s1 = PersistentCortexSigner::load_or_generate(&path).unwrap();
        assert!(path.exists());
        let pk1 = s1.public_key().as_bytes().to_vec();

        // Reload → same key.
        let s2 = PersistentCortexSigner::load_or_generate(&path).unwrap();
        assert_eq!(pk1, s2.public_key().as_bytes());

        // Signatures should be deterministic (Ed25519).
        let msg = b"cortex receipt preimage";
        let sig1 = s1.sign(msg).unwrap();
        let sig2 = s2.sign(msg).unwrap();
        assert_eq!(sig1.as_bytes(), sig2.as_bytes());

        // Cleanup.
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
