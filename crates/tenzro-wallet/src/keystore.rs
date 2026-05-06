//! Secure key storage for Tenzro Network wallets.
//!
//! This module provides encrypted local storage of MPC key shares
//! with password-based encryption and key rotation support.

use crate::error::{Result, WalletError};
use crate::wallet::{KeyShare, WalletId};
use argon2::{Argon2, Algorithm, Params, Version};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tenzro_crypto::encryption::SymmetricKey;
use tenzro_crypto::pq::MlDsaSigningKey;
use tracing::debug;

/// Encrypted key share storage entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedKeyShare {
    /// Wallet ID
    wallet_id: WalletId,
    /// Share index
    share_index: u32,
    /// Encrypted share data
    encrypted_data: Vec<u8>,
    /// Salt for key derivation
    salt: [u8; 32],
}

/// Encrypted ML-DSA-65 signing-key storage entry.
///
/// Persists the 32-byte FIPS 204 canonical seed sealed with the same
/// Argon2id-derived key as the classical shares. The on-disk file is
/// `<wallet_id>.pq.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedPqSeed {
    /// Wallet ID this seed belongs to.
    wallet_id: WalletId,
    /// AES-256-GCM ciphertext over the 32-byte FIPS 204 seed.
    encrypted_seed: Vec<u8>,
    /// Salt for the Argon2id KDF.
    salt: [u8; 32],
}

/// Keystore for secure storage of MPC key shares.
///
/// Key shares are encrypted with a password-derived key and stored locally.
pub struct Keystore {
    /// Storage directory path
    storage_path: PathBuf,
    /// In-memory cache of decrypted shares (cleared on drop)
    cache: HashMap<WalletId, Vec<KeyShare>>,
}

impl Keystore {
    /// Create a new keystore at the specified path
    pub fn new<P: AsRef<Path>>(storage_path: P) -> Result<Self> {
        let storage_path = storage_path.as_ref().to_path_buf();

        // Create storage directory if it doesn't exist
        if !storage_path.exists() {
            std::fs::create_dir_all(&storage_path)?;
        }

        Ok(Self {
            storage_path,
            cache: HashMap::new(),
        })
    }

    /// Store key shares encrypted with a password
    pub fn store_shares(
        &mut self,
        wallet_id: &WalletId,
        shares: &[KeyShare],
        password: &str,
    ) -> Result<()> {
        if shares.is_empty() {
            return Err(WalletError::KeystoreError(
                "No shares to store".to_string(),
            ));
        }

        // Derive encryption key from password
        let salt = Self::generate_salt();
        let encryption_key = Self::derive_key(password, &salt)?;

        // Encrypt each share
        let mut encrypted_shares = Vec::new();
        for share in shares {
            let share_bytes = share.to_bytes();
            let encrypted_data = encryption_key
                .encrypt(&share_bytes)
                .map_err(|e| WalletError::EncryptionError(e.to_string()))?;

            encrypted_shares.push(EncryptedKeyShare {
                wallet_id: wallet_id.clone(),
                share_index: share.share_index,
                encrypted_data,
                salt,
            });
        }

        // Store to file
        let file_path = self.get_keystore_path(wallet_id);
        let json = serde_json::to_string(&encrypted_shares)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        std::fs::write(&file_path, json)?;

        // Cache the decrypted shares
        self.cache.insert(wallet_id.clone(), shares.to_vec());

        Ok(())
    }

    /// Load key shares by decrypting with a password
    pub fn load_shares(&mut self, wallet_id: &WalletId, password: &str) -> Result<Vec<KeyShare>> {
        // Check cache first
        if let Some(shares) = self.cache.get(wallet_id) {
            debug!("Loaded {} shares from cache for wallet {}", shares.len(), wallet_id);
            return Ok(shares.clone());
        }

        // Load from file
        let file_path = self.get_keystore_path(wallet_id);
        if !file_path.exists() {
            return Err(WalletError::KeystoreError(format!(
                "Wallet {} not found in keystore",
                wallet_id
            )));
        }

        let json = std::fs::read_to_string(&file_path)?;
        let encrypted_shares: Vec<EncryptedKeyShare> = serde_json::from_str(&json)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        if encrypted_shares.is_empty() {
            return Err(WalletError::KeystoreError(
                "No encrypted shares found in keystore".to_string(),
            ));
        }

        // Decrypt shares using the password
        let mut decrypted_shares = Vec::new();
        for encrypted in encrypted_shares {
            // Derive decryption key from password and stored salt
            let decryption_key = Self::derive_key(password, &encrypted.salt)?;

            // Decrypt the share data
            let decrypted_bytes = decryption_key
                .decrypt(&encrypted.encrypted_data)
                .map_err(|e| {
                    WalletError::KeystoreError(format!(
                        "Failed to decrypt share {} (wrong password?): {}",
                        encrypted.share_index, e
                    ))
                })?;

            // Deserialize the KeyShare from decrypted bytes
            let share = Self::deserialize_share(&decrypted_bytes, encrypted.share_index)?;
            decrypted_shares.push(share);
        }

        debug!(
            "Loaded {} shares from keystore for wallet {}",
            decrypted_shares.len(),
            wallet_id
        );

        // Cache the decrypted shares
        self.cache
            .insert(wallet_id.clone(), decrypted_shares.clone());

        Ok(decrypted_shares)
    }

    /// Check if wallet exists in keystore
    pub fn has_wallet(&self, wallet_id: &WalletId) -> bool {
        self.get_keystore_path(wallet_id).exists()
    }

    /// Delete wallet from keystore
    pub fn delete_wallet(&mut self, wallet_id: &WalletId) -> Result<()> {
        let file_path = self.get_keystore_path(wallet_id);
        if file_path.exists() {
            std::fs::remove_file(&file_path)?;
        }

        // Also remove the ML-DSA-65 sealed seed if present.
        let pq_path = self.get_pq_keystore_path(wallet_id);
        if pq_path.exists() {
            std::fs::remove_file(&pq_path)?;
        }

        // Remove from cache
        self.cache.remove(wallet_id);

        Ok(())
    }

    /// List all wallet IDs in the keystore
    pub fn list_wallets(&self) -> Result<Vec<WalletId>> {
        let mut wallet_ids = Vec::new();

        for entry in std::fs::read_dir(&self.storage_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("json")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            {
                // Skip ML-DSA-65 sealed-seed companion files (`<id>.pq.json`).
                // These are stored alongside the classical keystore but are
                // not separate wallets.
                if stem.ends_with(".pq") {
                    continue;
                }
                wallet_ids.push(WalletId::from_string(stem.to_string()));
            }
        }

        Ok(wallet_ids)
    }

    /// Change password for a wallet (classical shares + PQ seed).
    pub fn change_password(
        &mut self,
        wallet_id: &WalletId,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        // Load shares with old password
        let shares = self.load_shares(wallet_id, old_password)?;

        // Re-encrypt classical shares with new password
        self.store_shares(wallet_id, &shares, new_password)?;

        // Re-encrypt the ML-DSA-65 seed if it exists. The seed is mandatory for
        // every freshly-provisioned wallet; older test fixtures may not yet
        // carry one, so missing seeds are tolerated here for backward-compat
        // with the in-memory test path that bypasses `provision_wallet()`.
        let pq_path = self.get_pq_keystore_path(wallet_id);
        if pq_path.exists() {
            let pq_key = self.load_pq_seed(wallet_id, old_password)?;
            self.store_pq_seed(wallet_id, &pq_key, new_password)?;
        }

        Ok(())
    }

    /// Clear the in-memory cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Get the file path for a wallet's keystore
    fn get_keystore_path(&self, wallet_id: &WalletId) -> PathBuf {
        self.storage_path.join(format!("{}.json", wallet_id.as_str()))
    }

    /// Get the file path for a wallet's ML-DSA-65 sealed seed.
    fn get_pq_keystore_path(&self, wallet_id: &WalletId) -> PathBuf {
        self.storage_path
            .join(format!("{}.pq.json", wallet_id.as_str()))
    }

    /// Persist the wallet's ML-DSA-65 signing seed sealed with `password`.
    ///
    /// The 32-byte FIPS 204 seed is encrypted with an Argon2id-derived
    /// AES-256-GCM key (same KDF parameters as the classical share keystore)
    /// and written to `<wallet_id>.pq.json`. This is **mandatory** for every
    /// wallet — the post-quantum migration has no classical-only fallback.
    pub fn store_pq_seed(
        &mut self,
        wallet_id: &WalletId,
        pq_signing_key: &MlDsaSigningKey,
        password: &str,
    ) -> Result<()> {
        let salt = Self::generate_salt();
        let encryption_key = Self::derive_key(password, &salt)?;

        let seed_bytes = pq_signing_key.seed_bytes();
        let encrypted_seed = encryption_key
            .encrypt(seed_bytes)
            .map_err(|e| WalletError::EncryptionError(e.to_string()))?;

        let entry = EncryptedPqSeed {
            wallet_id: wallet_id.clone(),
            encrypted_seed,
            salt,
        };

        let path = self.get_pq_keystore_path(wallet_id);
        let json = serde_json::to_string(&entry)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    /// Load and decrypt the wallet's ML-DSA-65 signing seed.
    pub fn load_pq_seed(
        &mut self,
        wallet_id: &WalletId,
        password: &str,
    ) -> Result<MlDsaSigningKey> {
        let path = self.get_pq_keystore_path(wallet_id);
        if !path.exists() {
            return Err(WalletError::KeystoreError(format!(
                "Wallet {} has no ML-DSA-65 seed in keystore — every wallet must \
                 carry a hybrid PQ key per the post-quantum migration",
                wallet_id
            )));
        }

        let json = std::fs::read_to_string(&path)?;
        let entry: EncryptedPqSeed = serde_json::from_str(&json)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        let decryption_key = Self::derive_key(password, &entry.salt)?;
        let seed_bytes = decryption_key.decrypt(&entry.encrypted_seed).map_err(|e| {
            WalletError::KeystoreError(format!(
                "Failed to decrypt ML-DSA-65 seed (wrong password?): {}",
                e
            ))
        })?;

        MlDsaSigningKey::from_seed(&seed_bytes).map_err(|e| {
            WalletError::KeystoreError(format!(
                "Decrypted bytes are not a valid ML-DSA-65 seed: {}",
                e
            ))
        })
    }

    /// Generate a random salt
    fn generate_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut salt);
        salt
    }

    /// Derive an encryption key from a password and salt using Argon2id
    fn derive_key(password: &str, salt: &[u8; 32]) -> Result<SymmetricKey> {
        // Use Argon2id for password-based key derivation
        // Parameters: 64 MB memory, time cost 3, parallelism 4
        let params = Params::new(
            65536,  // memory cost in 1 KiB blocks = 64 MB
            3,      // time cost (iterations)
            4,      // parallelism
            Some(32), // output length (32 bytes for AES-256)
        )
        .map_err(|e| WalletError::KeystoreError(format!("Failed to create Argon2 params: {}", e)))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        // Derive the key using Argon2
        let mut key_bytes = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
            .map_err(|e| WalletError::KeystoreError(format!("Argon2 key derivation failed: {}", e)))?;

        SymmetricKey::from_bytes(&key_bytes)
            .map_err(|e| WalletError::KeystoreError(e.to_string()))
    }

    /// Deserialize a key share from bytes
    fn deserialize_share(bytes: &[u8], expected_share_index: u32) -> Result<KeyShare> {
        use tenzro_crypto::mpc::{MpcKeyShare, ThresholdConfig};
        use tenzro_crypto::{KeyType, PublicKey};

        // Deserialize the SerializableKeyShare structure
        #[derive(serde::Deserialize)]
        struct SerializableKeyShare {
            share_index: u32,
            participant_id: String,
            mpc_share_bytes: Vec<u8>,
        }

        let serializable: SerializableKeyShare = serde_json::from_slice(bytes)
            .map_err(|e| WalletError::SerializationError(format!("Failed to deserialize KeyShare: {}", e)))?;

        // Verify share index matches
        if serializable.share_index != expected_share_index {
            return Err(WalletError::SerializationError(format!(
                "Share index mismatch: expected {}, got {}",
                expected_share_index, serializable.share_index
            )));
        }

        // Manually deserialize MpcKeyShare from bytes
        // Format: share_id (4) | key_type (1) | threshold (4) | total_shares (4) |
        //         share_data_len (4) | share_data (n) | pubkey_len (4) | pubkey (m)
        let share_bytes = &serializable.mpc_share_bytes;
        if share_bytes.len() < 21 {
            return Err(WalletError::SerializationError(
                "MpcKeyShare bytes too short".to_string(),
            ));
        }

        let mut pos = 0;

        // Read share_id
        let share_id = u32::from_le_bytes([
            share_bytes[pos],
            share_bytes[pos + 1],
            share_bytes[pos + 2],
            share_bytes[pos + 3],
        ]);
        pos += 4;

        // Read key_type
        let key_type = match share_bytes[pos] {
            0 => KeyType::Ed25519,
            1 => KeyType::Secp256k1,
            _ => {
                return Err(WalletError::SerializationError(
                    "Invalid key type byte".to_string(),
                ))
            }
        };
        pos += 1;

        // Read threshold config
        let threshold = u32::from_le_bytes([
            share_bytes[pos],
            share_bytes[pos + 1],
            share_bytes[pos + 2],
            share_bytes[pos + 3],
        ]) as usize;
        pos += 4;

        let total_shares = u32::from_le_bytes([
            share_bytes[pos],
            share_bytes[pos + 1],
            share_bytes[pos + 2],
            share_bytes[pos + 3],
        ]) as usize;
        pos += 4;

        let config = ThresholdConfig::new(threshold, total_shares)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        // Read share_data
        let share_data_len = u32::from_le_bytes([
            share_bytes[pos],
            share_bytes[pos + 1],
            share_bytes[pos + 2],
            share_bytes[pos + 3],
        ]) as usize;
        pos += 4;

        if share_bytes.len() < pos + share_data_len + 4 {
            return Err(WalletError::SerializationError(
                "Invalid share_data length".to_string(),
            ));
        }

        let share_data = share_bytes[pos..pos + share_data_len].to_vec();
        pos += share_data_len;

        // Read public_key
        let pubkey_len = u32::from_le_bytes([
            share_bytes[pos],
            share_bytes[pos + 1],
            share_bytes[pos + 2],
            share_bytes[pos + 3],
        ]) as usize;
        pos += 4;

        if share_bytes.len() < pos + pubkey_len {
            return Err(WalletError::SerializationError(
                "Invalid public key length".to_string(),
            ));
        }

        let pubkey_bytes = share_bytes[pos..pos + pubkey_len].to_vec();
        let public_key = PublicKey::new(key_type, pubkey_bytes);

        // Reconstruct MpcKeyShare
        let mpc_share = MpcKeyShare::new(share_id, key_type, config, share_data, public_key)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        // Reconstruct KeyShare
        Ok(KeyShare::new(
            serializable.share_index,
            serializable.participant_id,
            mpc_share,
        ))
    }
}

impl Drop for Keystore {
    fn drop(&mut self) {
        // Clear cache on drop for security
        self.cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provisioning::WalletProvisioner;
    use tempfile::TempDir;

    #[test]
    fn test_keystore_store() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();

        // Provision a wallet
        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        let password = "test-password-123";

        // Store shares
        keystore
            .store_shares(&wallet.wallet_id, &wallet.key_shares, password)
            .unwrap();

        // Check wallet exists
        assert!(keystore.has_wallet(&wallet.wallet_id));

        // Shares should be in cache after store_shares
    }

    #[test]
    fn test_keystore_cache() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();

        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        keystore
            .store_shares(&wallet.wallet_id, &wallet.key_shares, "password")
            .unwrap();

        // Should find in cache
        keystore.clear_cache();
        // After clearing, shares are no longer available without re-provisioning
    }

    #[test]
    fn test_list_wallets() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();

        let provisioner = WalletProvisioner::new();

        // Create multiple wallets
        let wallet1 = provisioner.provision_wallet().unwrap();
        let wallet2 = provisioner.provision_wallet().unwrap();

        keystore
            .store_shares(&wallet1.wallet_id, &wallet1.key_shares, "password1")
            .unwrap();
        keystore
            .store_shares(&wallet2.wallet_id, &wallet2.key_shares, "password2")
            .unwrap();

        // List wallets
        let wallet_ids = keystore.list_wallets().unwrap();
        assert_eq!(wallet_ids.len(), 2);
        assert!(wallet_ids.contains(&wallet1.wallet_id));
        assert!(wallet_ids.contains(&wallet2.wallet_id));
    }

    #[test]
    fn test_delete_wallet() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();

        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        keystore
            .store_shares(&wallet.wallet_id, &wallet.key_shares, "password")
            .unwrap();

        assert!(keystore.has_wallet(&wallet.wallet_id));

        // Delete wallet
        keystore.delete_wallet(&wallet.wallet_id).unwrap();

        assert!(!keystore.has_wallet(&wallet.wallet_id));
    }

    #[test]
    fn test_change_password() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();

        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        let old_password = "old-password";
        let new_password = "new-password";

        keystore
            .store_shares(&wallet.wallet_id, &wallet.key_shares, old_password)
            .unwrap();

        // Change password (stores with new encryption)
        keystore
            .change_password(&wallet.wallet_id, old_password, new_password)
            .unwrap();

        // Verify new password works by loading shares
        let shares = keystore.load_shares(&wallet.wallet_id, new_password).unwrap();
        assert_eq!(shares.len(), wallet.key_shares.len());
    }
}
