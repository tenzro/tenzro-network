//! Encrypted local storage for identity-bound wallets.
//!
//! Each wallet is one file, `<id>.json`, holding the wallet's public record
//! sealed with the holder's password via Argon2id-derived AES-256-GCM. A
//! wallet holds no secret: the classical key is in the holder's hardware and
//! the post-quantum key, when there is one, is the holder's own. Sealing the
//! record keeps which keys a holder uses off the disk in the clear.

use crate::error::{Result, WalletError};
use crate::wallet::WalletId;
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tenzro_crypto::encryption::SymmetricKey;

/// Persisted wallet bundle: the wallet record, AES-256-GCM-sealed under an
/// Argon2id-derived key.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedWalletBundle {
    /// Wallet ID this bundle belongs to.
    wallet_id: WalletId,
    /// Salt for the Argon2id KDF.
    salt: [u8; 32],
    /// Encrypted record (JSON-serialized then sealed).
    encrypted_record: Vec<u8>,
}

/// In-memory cache entry: the decrypted record.
#[derive(Clone)]
struct CacheEntry {
    record: WalletRecord,
}

/// The public keys a wallet is rebuilt from.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WalletRecord {
    /// The hardware public keys. The private halves live in the secure
    /// element and cannot be exported.
    pub public_key: tenzro_crypto::CompositePublicKey,
}

/// Keystore for the sealed wallet records.
pub struct Keystore {
    storage_path: PathBuf,
    cache: HashMap<WalletId, CacheEntry>,
}

impl Keystore {
    /// Create a new keystore at the specified path.
    pub fn new<P: AsRef<Path>>(storage_path: P) -> Result<Self> {
        let storage_path = storage_path.as_ref().to_path_buf();
        if !storage_path.exists() {
            std::fs::create_dir_all(&storage_path)?;
        }
        Ok(Self {
            storage_path,
            cache: HashMap::new(),
        })
    }
    /// Seal a wallet's record with the holder's password.
    pub fn store_record(
        &mut self,
        wallet_id: &WalletId,
        record: &WalletRecord,
        password: &str,
    ) -> Result<()> {
        let salt = Self::generate_salt();
        let encryption_key = Self::derive_key(password, &salt)?;

        let json = serde_json::to_vec(record)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        let encrypted_record = encryption_key
            .encrypt(&json)
            .map_err(|e| WalletError::KeystoreError(format!("encrypt record: {e}")))?;

        let stored = EncryptedWalletBundle {
            wallet_id: wallet_id.clone(),
            salt,
            encrypted_record,
        };
        let path = self.get_keystore_path(wallet_id);
        let bytes = serde_json::to_vec_pretty(&stored)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        std::fs::write(&path, bytes)?;
        self.cache.insert(
            wallet_id.clone(),
            CacheEntry {
                record: record.clone(),
            },
        );
        Ok(())
    }

    /// Unseal a wallet's record.
    pub fn load_record(&mut self, wallet_id: &WalletId, password: &str) -> Result<WalletRecord> {
        if let Some(entry) = self.cache.get(wallet_id) {
            return Ok(entry.record.clone());
        }
        let path = self.get_keystore_path(wallet_id);
        if !path.exists() {
            return Err(WalletError::WalletNotFound(wallet_id.to_string()));
        }
        let bytes = std::fs::read(&path)?;
        let stored: EncryptedWalletBundle = serde_json::from_slice(&bytes)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        let encryption_key = Self::derive_key(password, &stored.salt)?;
        let json = encryption_key
            .decrypt(&stored.encrypted_record)
            .map_err(|_| WalletError::KeystoreError("Invalid password".to_string()))?;
        let record: WalletRecord = serde_json::from_slice(&json)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        self.cache.insert(
            wallet_id.clone(),
            CacheEntry {
                record: record.clone(),
            },
        );
        Ok(record)
    }

    /// Check if a wallet exists in the keystore.
    pub fn has_wallet(&self, wallet_id: &WalletId) -> bool {
        self.get_keystore_path(wallet_id).exists()
    }

    /// Delete a wallet's sealed record.
    pub fn delete_wallet(&mut self, wallet_id: &WalletId) -> Result<()> {
        let file_path = self.get_keystore_path(wallet_id);
        if file_path.exists() {
            std::fs::remove_file(&file_path)?;
        }

        self.cache.remove(wallet_id);
        Ok(())
    }

    /// List all wallet IDs in the keystore.
    pub fn list_wallets(&self) -> Result<Vec<WalletId>> {
        let mut wallet_ids = Vec::new();

        // A keystore that has never persisted a wallet has no storage dir yet
        // (created lazily on first write). Treat that as "no wallets" rather
        // than an I/O error so callers can distinguish empty from broken.
        if !self.storage_path.exists() {
            return Ok(wallet_ids);
        }

        for entry in std::fs::read_dir(&self.storage_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            {
                wallet_ids.push(WalletId::from_string(stem.to_string()));
            }
        }

        Ok(wallet_ids)
    }

    /// Re-seal a wallet's record under a new password.
    pub fn change_password(
        &mut self,
        wallet_id: &WalletId,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        self.cache.remove(wallet_id);
        let record = self.load_record(wallet_id, old_password)?;
        self.store_record(wallet_id, &record, new_password)
    }

    /// Clear the in-memory cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Get the file path for a wallet's keystore bundle.
    fn get_keystore_path(&self, wallet_id: &WalletId) -> PathBuf {
        self.storage_path
            .join(format!("{}.json", wallet_id.as_str()))
    }

    /// Generate a random salt.
    fn generate_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Derive an encryption key from a password and salt using Argon2id.
    fn derive_key(password: &str, salt: &[u8; 32]) -> Result<SymmetricKey> {
        let params = Params::new(
            65536,    // memory cost in 1 KiB blocks = 64 MB
            3,        // time cost (iterations)
            4,        // parallelism
            Some(32), // output length (32 bytes for AES-256)
        )
        .map_err(|e| {
            WalletError::KeystoreError(format!("Failed to create Argon2 params: {}", e))
        })?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key_bytes = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
            .map_err(|e| {
                WalletError::KeystoreError(format!("Argon2 key derivation failed: {}", e))
            })?;

        SymmetricKey::from_bytes(&key_bytes).map_err(|e| WalletError::KeystoreError(e.to_string()))
    }
}

impl Drop for Keystore {
    fn drop(&mut self) {
        self.cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn record(tag: u8) -> WalletRecord {
        use tenzro_crypto::HybridSigner;
        WalletRecord {
            public_key: tenzro_crypto::composite::testing::TestHybridSigner::hybrid(tag)
                .public_key()
                .clone(),
        }
    }

    #[test]
    fn test_keystore_store() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();
        let wallet_id = WalletId::new();

        keystore
            .store_record(&wallet_id, &record(1), "test-password-123")
            .unwrap();

        assert!(keystore.has_wallet(&wallet_id));
    }

    /// The whole point of the keystore: what goes in under a password comes
    /// back out intact under the same password.
    #[test]
    fn test_keystore_round_trip() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();
        let wallet_id = WalletId::new();
        let original = record(7);

        keystore
            .store_record(&wallet_id, &original, "correct horse")
            .unwrap();

        // Drop the cache so this genuinely exercises decrypt-from-disk rather
        // than handing back the in-memory copy.
        let mut fresh = Keystore::new(temp_dir.path()).unwrap();
        let loaded = fresh.load_record(&wallet_id, "correct horse").unwrap();

        assert_eq!(loaded, original);
    }

    #[test]
    fn test_keystore_wrong_password_is_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();
        let wallet_id = WalletId::new();

        keystore
            .store_record(&wallet_id, &record(3), "right-password")
            .unwrap();

        let mut fresh = Keystore::new(temp_dir.path()).unwrap();
        assert!(fresh.load_record(&wallet_id, "wrong-password").is_err());
    }

    #[test]
    fn test_list_wallets() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();
        let wallet1 = WalletId::new();
        let wallet2 = WalletId::new();

        keystore
            .store_record(&wallet1, &record(1), "password1")
            .unwrap();
        keystore
            .store_record(&wallet2, &record(2), "password2")
            .unwrap();

        let wallet_ids = keystore.list_wallets().unwrap();
        assert_eq!(wallet_ids.len(), 2);
        assert!(wallet_ids.contains(&wallet1));
        assert!(wallet_ids.contains(&wallet2));
    }

    #[test]
    fn test_delete_wallet() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();
        let wallet_id = WalletId::new();

        keystore
            .store_record(&wallet_id, &record(4), "password")
            .unwrap();

        assert!(keystore.has_wallet(&wallet_id));
        keystore.delete_wallet(&wallet_id).unwrap();
        assert!(!keystore.has_wallet(&wallet_id));
    }

    /// After a password change the old one must stop working — a change that
    /// leaves the previous password valid is not a change.
    #[test]
    fn test_change_password() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();
        let wallet_id = WalletId::new();
        let original = record(5);

        keystore
            .store_record(&wallet_id, &original, "old-password")
            .unwrap();
        keystore
            .change_password(&wallet_id, "old-password", "new-password")
            .unwrap();

        let mut fresh = Keystore::new(temp_dir.path()).unwrap();
        let loaded = fresh.load_record(&wallet_id, "new-password").unwrap();
        assert_eq!(loaded, original);

        let mut fresh2 = Keystore::new(temp_dir.path()).unwrap();
        assert!(fresh2.load_record(&wallet_id, "old-password").is_err());
    }
}
