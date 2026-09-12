//! Encrypted local storage for identity-bound wallets.
//!
//! Each wallet is sealed with the user's password via Argon2id-derived
//! AES-256-GCM. Three on-disk artifacts per wallet:
//!
//!   * `<id>.json` — the wallet's local secret material, each item encrypted
//!     independently.
//!   * `<id>.pq.json` — the wallet's mandatory ML-DSA-65 sealed seed.
//!
//! The sealed material is required at unlock time so the wallet can
//! reconstruct enough state to re-derive the wallet and
//! aggregation. It is encrypted under the same Argon2id-derived key as the
//! shares — not because it carries secrets but to make the unlock atomic
//! (one password derivation per wallet).

use crate::error::{Result, WalletError};
use crate::wallet::WalletId;
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tenzro_crypto::bls::{BlsKeyPair, BlsSecretKey};
use tenzro_crypto::encryption::SymmetricKey;
use tenzro_crypto::pq::MlDsaSigningKey;

/// Persisted wallet bundle: the local secret material, AES-256-GCM-sealed
/// under an Argon2id-derived key.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedWalletBundle {
    /// Wallet ID this bundle belongs to.
    wallet_id: WalletId,
    /// Salt for the Argon2id KDF (shared by all sealed payloads in the bundle).
    salt: [u8; 32],
    /// Encrypted local secret bundle (JSON-serialized then sealed).
    encrypted_secrets: Vec<u8>,
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

/// Encrypted BLS12-381 signing-key storage entry.
///
/// Persists the 32-byte secret-key scalar sealed with the same Argon2id-
/// derived key as the classical shares. The on-disk file is
/// `<wallet_id>.bls.json`. The corresponding 48-byte G1-compressed public
/// key is bound to the wallet's identity at registration so the chain knows
/// which BLS pubkey to verify the validator's HotStuff-2 votes against.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedBlsSeed {
    /// Wallet ID this seed belongs to.
    wallet_id: WalletId,
    /// AES-256-GCM ciphertext over the 32-byte BLS12-381 secret key bytes.
    encrypted_seed: Vec<u8>,
    /// Salt for the Argon2id KDF.
    salt: [u8; 32],
}

/// In-memory cache entry — the decrypted secret bundle needed to rebuild a
/// working wallet.
#[derive(Clone)]
struct CacheEntry {
    secrets: WalletSecrets,
}

/// A wallet's local secret material.
///
/// Replaces the former threshold `PublicKeyPackage` + per-signer shares. Custody is
/// no longer a quorum reconstructed at signing time: the classical key lives in
/// hardware and never appears here at all, so this holds only the two keys that
/// have no hardware backing.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct WalletSecrets {
    /// ML-DSA-65 (FIPS-204) signing seed.
    pub pq_seed: Vec<u8>,
    /// BLS12-381 signing key bytes.
    pub bls_key: Vec<u8>,
    /// The device key's public half, recorded so a wallet can be rebuilt
    /// without the hardware being present. The private half never appears
    /// here — it lives in the secure element and cannot be exported.
    #[serde(default)]
    pub classical_public_key: Vec<u8>,
}

/// Keystore for secure storage of a wallet's local secrets.
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
    /// Seal a wallet's local secrets with the user's password.
    ///
    /// Replaces the former `store_shares`. There are no shares to distribute:
    /// the classical key lives in hardware and never reaches this keystore, so
    /// only the ML-DSA and BLS material is sealed here.
    pub fn store_secrets(
        &mut self,
        wallet_id: &WalletId,
        secrets: &WalletSecrets,
        password: &str,
    ) -> Result<()> {
        let salt = Self::generate_salt();
        let encryption_key = Self::derive_key(password, &salt)?;

        let json = serde_json::to_vec(secrets)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        let encrypted_secrets = encryption_key
            .encrypt(&json)
            .map_err(|e| WalletError::KeystoreError(format!("encrypt secrets: {e}")))?;

        let stored = EncryptedWalletBundle {
            wallet_id: wallet_id.clone(),
            salt,
            encrypted_secrets,
        };
        let path = self.get_keystore_path(wallet_id);
        let bytes = serde_json::to_vec_pretty(&stored)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        std::fs::write(&path, bytes)?;
        self.cache.insert(
            wallet_id.clone(),
            CacheEntry {
                secrets: secrets.clone(),
            },
        );
        Ok(())
    }

    /// Unseal a wallet's local secrets.
    pub fn load_secrets(&mut self, wallet_id: &WalletId, password: &str) -> Result<WalletSecrets> {
        if let Some(entry) = self.cache.get(wallet_id) {
            return Ok(entry.secrets.clone());
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
            .decrypt(&stored.encrypted_secrets)
            .map_err(|_| WalletError::KeystoreError("Invalid password".to_string()))?;
        let secrets: WalletSecrets = serde_json::from_slice(&json)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        self.cache.insert(
            wallet_id.clone(),
            CacheEntry {
                secrets: secrets.clone(),
            },
        );
        Ok(secrets)
    }

    /// Check if a wallet exists in the keystore.
    pub fn has_wallet(&self, wallet_id: &WalletId) -> bool {
        self.get_keystore_path(wallet_id).exists()
    }

    /// Delete a wallet (classical bundle + ML-DSA-65 sealed seed).
    pub fn delete_wallet(&mut self, wallet_id: &WalletId) -> Result<()> {
        let file_path = self.get_keystore_path(wallet_id);
        if file_path.exists() {
            std::fs::remove_file(&file_path)?;
        }

        let pq_path = self.get_pq_keystore_path(wallet_id);
        if pq_path.exists() {
            std::fs::remove_file(&pq_path)?;
        }

        let bls_path = self.get_bls_keystore_path(wallet_id);
        if bls_path.exists() {
            std::fs::remove_file(&bls_path)?;
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
                // Skip ML-DSA-65 sealed-seed companion files (`<id>.pq.json`)
                // and BLS12-381 sealed-seed companion files (`<id>.bls.json`).
                if stem.ends_with(".pq") || stem.ends_with(".bls") {
                    continue;
                }
                wallet_ids.push(WalletId::from_string(stem.to_string()));
            }
        }

        Ok(wallet_ids)
    }

    /// Change password for a wallet (PQ seed + BLS seed).
    pub fn change_password(
        &mut self,
        wallet_id: &WalletId,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        let secrets = self.load_secrets(wallet_id, old_password)?;
        self.store_secrets(wallet_id, &secrets, new_password)?;

        let pq_path = self.get_pq_keystore_path(wallet_id);
        if pq_path.exists() {
            let pq_key = self.load_pq_seed(wallet_id, old_password)?;
            self.store_pq_seed(wallet_id, &pq_key, new_password)?;
        }

        let bls_path = self.get_bls_keystore_path(wallet_id);
        if bls_path.exists() {
            let bls_key = self.load_bls_seed(wallet_id, old_password)?;
            self.store_bls_seed(wallet_id, &bls_key, new_password)?;
        }

        Ok(())
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

    /// Get the file path for a wallet's ML-DSA-65 sealed seed.
    fn get_pq_keystore_path(&self, wallet_id: &WalletId) -> PathBuf {
        self.storage_path
            .join(format!("{}.pq.json", wallet_id.as_str()))
    }

    /// Get the file path for a wallet's BLS12-381 sealed seed.
    fn get_bls_keystore_path(&self, wallet_id: &WalletId) -> PathBuf {
        self.storage_path
            .join(format!("{}.bls.json", wallet_id.as_str()))
    }

    /// Persist the wallet's ML-DSA-65 signing seed sealed with `password`.
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

    /// Persist the wallet's BLS12-381 secret-key scalar sealed with `password`.
    pub fn store_bls_seed(
        &mut self,
        wallet_id: &WalletId,
        bls_signing_key: &BlsKeyPair,
        password: &str,
    ) -> Result<()> {
        let salt = Self::generate_salt();
        let encryption_key = Self::derive_key(password, &salt)?;

        let seed_bytes = bls_signing_key.secret_key().to_bytes();
        let encrypted_seed = encryption_key
            .encrypt(&seed_bytes)
            .map_err(|e| WalletError::EncryptionError(e.to_string()))?;

        let entry = EncryptedBlsSeed {
            wallet_id: wallet_id.clone(),
            encrypted_seed,
            salt,
        };

        let path = self.get_bls_keystore_path(wallet_id);
        let json = serde_json::to_string(&entry)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    /// Load and decrypt the wallet's BLS12-381 keypair.
    pub fn load_bls_seed(&mut self, wallet_id: &WalletId, password: &str) -> Result<BlsKeyPair> {
        let path = self.get_bls_keystore_path(wallet_id);
        if !path.exists() {
            return Err(WalletError::KeystoreError(format!(
                "Wallet {} has no BLS12-381 seed in keystore — every wallet must \
                 carry a BLS key for HotStuff-2 vote aggregation",
                wallet_id
            )));
        }

        let json = std::fs::read_to_string(&path)?;
        let entry: EncryptedBlsSeed = serde_json::from_str(&json)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        let decryption_key = Self::derive_key(password, &entry.salt)?;
        let seed_bytes = decryption_key.decrypt(&entry.encrypted_seed).map_err(|e| {
            WalletError::KeystoreError(format!(
                "Failed to decrypt BLS12-381 seed (wrong password?): {}",
                e
            ))
        })?;

        let secret = BlsSecretKey::from_bytes(&seed_bytes).map_err(|e| {
            WalletError::KeystoreError(format!(
                "Decrypted bytes are not a valid BLS12-381 secret key: {}",
                e
            ))
        })?;
        Ok(BlsKeyPair::from_secret_key(secret))
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

    /// Read the three encrypted keystore files for `wallet_id` as raw bytes,
    /// without decrypting them.
    ///
    /// Returned map keys are the on-disk filenames (`<id>.json`,
    /// `<id>.pq.json`, `<id>.bls.json`); values are the verbatim ciphertext
    /// blobs as written by `store_secrets` / `store_pq_seed` / `store_bls_seed`.
    ///
    /// Used by the identity CAR export (C.6) so users can move their wallet
    /// across machines without ever decrypting their key material in transit —
    /// the recipient supplies the password locally at import time. All three
    /// files are required; if any of them is missing the call errors out
    /// rather than silently producing an incomplete bundle.
    pub fn export_encrypted_wallet_files(
        &self,
        wallet_id: &WalletId,
    ) -> Result<HashMap<String, Vec<u8>>> {
        let mut out = HashMap::with_capacity(3);
        for path in [
            self.get_keystore_path(wallet_id),
            self.get_pq_keystore_path(wallet_id),
            self.get_bls_keystore_path(wallet_id),
        ] {
            if !path.exists() {
                return Err(WalletError::KeystoreError(format!(
                    "Wallet {} is missing keystore file {} — cannot export an \
                     incomplete bundle",
                    wallet_id,
                    path.display()
                )));
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| {
                    WalletError::KeystoreError(format!(
                        "Keystore path {} has no valid file name",
                        path.display()
                    ))
                })?
                .to_string();
            let bytes = std::fs::read(&path)?;
            out.insert(name, bytes);
        }
        Ok(out)
    }

    /// Write encrypted keystore files into this keystore, byte-for-byte.
    ///
    /// `files` is the map returned by `export_encrypted_wallet_files` on the
    /// source machine. Filenames are validated to match the
    /// `<wallet_id>.json` / `<wallet_id>.pq.json` / `<wallet_id>.bls.json`
    /// scheme before writing, so a malicious bundle cannot drop arbitrary
    /// files into the keystore directory or overwrite siblings.
    ///
    /// Refuses to overwrite an existing wallet of the same ID — callers must
    /// `delete_wallet` first if they really mean to clobber.
    pub fn import_encrypted_wallet_files(
        &mut self,
        wallet_id: &WalletId,
        files: &HashMap<String, Vec<u8>>,
    ) -> Result<()> {
        let id = wallet_id.as_str();
        let expected = [
            format!("{}.json", id),
            format!("{}.pq.json", id),
            format!("{}.bls.json", id),
        ];

        for name in &expected {
            if !files.contains_key(name) {
                return Err(WalletError::KeystoreError(format!(
                    "Bundle for {} is missing expected file {}",
                    id, name
                )));
            }
            let target = self.storage_path.join(name);
            if target.exists() {
                return Err(WalletError::KeystoreError(format!(
                    "Refusing to overwrite existing keystore file {} — delete \
                     the wallet first if you really mean to import over it",
                    target.display()
                )));
            }
        }

        for (name, bytes) in files {
            if !expected.iter().any(|e| e == name) {
                return Err(WalletError::KeystoreError(format!(
                    "Bundle contains unexpected file name {} (expected one of \
                     {:?}) — refusing to write outside the wallet's own files",
                    name, expected
                )));
            }
            let target = self.storage_path.join(name);
            std::fs::write(&target, bytes)?;
        }

        Ok(())
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

    /// Secrets for a wallet whose classical key lives in hardware — only the
    /// public half is ever recorded here.
    fn secrets(tag: u8) -> WalletSecrets {
        WalletSecrets {
            pq_seed: vec![tag; 32],
            bls_key: vec![tag.wrapping_add(1); 32],
            classical_public_key: vec![tag.wrapping_add(2); 32],
        }
    }

    #[test]
    fn test_keystore_store() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();
        let wallet_id = WalletId::new();

        keystore
            .store_secrets(&wallet_id, &secrets(1), "test-password-123")
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
        let original = secrets(7);

        keystore
            .store_secrets(&wallet_id, &original, "correct horse")
            .unwrap();

        // Drop the cache so this genuinely exercises decrypt-from-disk rather
        // than handing back the in-memory copy.
        let mut fresh = Keystore::new(temp_dir.path()).unwrap();
        let loaded = fresh.load_secrets(&wallet_id, "correct horse").unwrap();

        assert_eq!(loaded.pq_seed, original.pq_seed);
        assert_eq!(loaded.bls_key, original.bls_key);
        assert_eq!(loaded.classical_public_key, original.classical_public_key);
    }

    #[test]
    fn test_keystore_wrong_password_is_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();
        let wallet_id = WalletId::new();

        keystore
            .store_secrets(&wallet_id, &secrets(3), "right-password")
            .unwrap();

        let mut fresh = Keystore::new(temp_dir.path()).unwrap();
        assert!(fresh.load_secrets(&wallet_id, "wrong-password").is_err());
    }

    #[test]
    fn test_list_wallets() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();
        let wallet1 = WalletId::new();
        let wallet2 = WalletId::new();

        keystore
            .store_secrets(&wallet1, &secrets(1), "password1")
            .unwrap();
        keystore
            .store_secrets(&wallet2, &secrets(2), "password2")
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
            .store_secrets(&wallet_id, &secrets(4), "password")
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
        let original = secrets(5);

        keystore
            .store_secrets(&wallet_id, &original, "old-password")
            .unwrap();
        keystore
            .change_password(&wallet_id, "old-password", "new-password")
            .unwrap();

        let mut fresh = Keystore::new(temp_dir.path()).unwrap();
        let loaded = fresh.load_secrets(&wallet_id, "new-password").unwrap();
        assert_eq!(loaded.pq_seed, original.pq_seed);

        let mut fresh2 = Keystore::new(temp_dir.path()).unwrap();
        assert!(fresh2.load_secrets(&wallet_id, "old-password").is_err());
    }

    /// Export/import moves a wallet between machines. The ciphertext is opaque
    /// to the transfer, so the password must still open it on the far side.
    ///
    /// A bundle is all three files or nothing: `export_encrypted_wallet_files`
    /// refuses to emit a partial one and `import_encrypted_wallet_files`
    /// refuses to accept one, so the wallet must be fully stored first.
    #[test]
    fn test_export_import_encrypted_wallet_files_round_trip() {
        let src_dir = TempDir::new().unwrap();
        let mut src = Keystore::new(src_dir.path()).unwrap();
        let wallet_id = WalletId::new();
        let original = secrets(9);
        let pq = MlDsaSigningKey::generate();
        let bls = BlsKeyPair::generate().unwrap();

        src.store_secrets(&wallet_id, &original, "transfer-password")
            .unwrap();
        src.store_pq_seed(&wallet_id, &pq, "transfer-password")
            .unwrap();
        src.store_bls_seed(&wallet_id, &bls, "transfer-password")
            .unwrap();

        let files = src.export_encrypted_wallet_files(&wallet_id).unwrap();
        assert_eq!(files.len(), 3, "bundle is all three files or nothing");

        let dst_dir = TempDir::new().unwrap();
        let mut dst = Keystore::new(dst_dir.path()).unwrap();
        dst.import_encrypted_wallet_files(&wallet_id, &files)
            .unwrap();

        let loaded = dst.load_secrets(&wallet_id, "transfer-password").unwrap();
        assert_eq!(loaded.pq_seed, original.pq_seed);
        assert_eq!(loaded.classical_public_key, original.classical_public_key);
    }
}
