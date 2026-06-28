//! Encrypted local storage for FROST-Ed25519 threshold wallets.
//!
//! Each wallet is sealed with the user's password via Argon2id-derived
//! AES-256-GCM. Three on-disk artifacts per wallet:
//!
//!   * `<id>.json` — the FROST `PublicKeyPackage` (non-secret) plus every
//!     held `KeyShare`, each encrypted independently.
//!   * `<id>.pq.json` — the wallet's mandatory ML-DSA-65 sealed seed.
//!
//! The `PublicKeyPackage` is required at unlock time so the wallet can
//! reconstruct enough state to coordinate FROST round-2 signing and
//! aggregation. It is encrypted under the same Argon2id-derived key as the
//! shares — not because it carries secrets but to make the unlock atomic
//! (one password derivation per wallet).

use crate::error::{Result, WalletError};
use crate::wallet::{KeyShare, WalletId};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tenzro_crypto::bls::{BlsKeyPair, BlsSecretKey};
use tenzro_crypto::encryption::SymmetricKey;
use tenzro_crypto::frost::PublicKeyPackage;
use tenzro_crypto::pq::MlDsaSigningKey;
use tracing::debug;

/// Persisted wallet bundle. The shares (and the pubkey package) are each
/// AES-256-GCM-sealed under the same Argon2id-derived key.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedWalletBundle {
    /// Wallet ID this bundle belongs to.
    wallet_id: WalletId,
    /// Salt for the Argon2id KDF (shared by all sealed payloads in the bundle).
    salt: [u8; 32],
    /// Encrypted FROST `PublicKeyPackage` (JSON-serialized then sealed).
    encrypted_pubkey_package: Vec<u8>,
    /// Encrypted key shares.
    encrypted_shares: Vec<EncryptedKeyShare>,
}

/// One sealed FROST key share.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedKeyShare {
    /// 1-based FROST signer index.
    signer_index: u16,
    /// AES-256-GCM ciphertext over the share's serialized bytes.
    encrypted_data: Vec<u8>,
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

/// In-memory cache entry — both the shares and the pubkey package needed to
/// rebuild a working wallet.
#[derive(Clone)]
struct CacheEntry {
    pubkey_package: PublicKeyPackage,
    shares: Vec<KeyShare>,
}

/// Keystore for secure storage of FROST wallets.
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

    /// Store a wallet's FROST shares + public-key package, sealed with the
    /// user's password.
    pub fn store_shares(
        &mut self,
        wallet_id: &WalletId,
        pubkey_package: &PublicKeyPackage,
        shares: &[KeyShare],
        password: &str,
    ) -> Result<()> {
        if shares.is_empty() {
            return Err(WalletError::KeystoreError(
                "No shares to store".to_string(),
            ));
        }

        let salt = Self::generate_salt();
        let encryption_key = Self::derive_key(password, &salt)?;

        // Seal the public-key package.
        let pubkey_json = serde_json::to_vec(pubkey_package)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        let encrypted_pubkey_package = encryption_key
            .encrypt(&pubkey_json)
            .map_err(|e| WalletError::EncryptionError(e.to_string()))?;

        // Seal each share independently.
        let mut encrypted_shares = Vec::with_capacity(shares.len());
        for share in shares {
            let share_bytes = share.to_bytes();
            let encrypted_data = encryption_key
                .encrypt(&share_bytes)
                .map_err(|e| WalletError::EncryptionError(e.to_string()))?;
            encrypted_shares.push(EncryptedKeyShare {
                signer_index: share.signer_index.0,
                encrypted_data,
            });
        }

        let bundle = EncryptedWalletBundle {
            wallet_id: wallet_id.clone(),
            salt,
            encrypted_pubkey_package,
            encrypted_shares,
        };

        let file_path = self.get_keystore_path(wallet_id);
        let json = serde_json::to_string(&bundle)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;
        std::fs::write(&file_path, json)?;

        self.cache.insert(
            wallet_id.clone(),
            CacheEntry {
                pubkey_package: pubkey_package.clone(),
                shares: shares.to_vec(),
            },
        );

        Ok(())
    }

    /// Load and decrypt a wallet bundle: returns the FROST public-key
    /// package and every held key share.
    pub fn load_shares(
        &mut self,
        wallet_id: &WalletId,
        password: &str,
    ) -> Result<(PublicKeyPackage, Vec<KeyShare>)> {
        if let Some(entry) = self.cache.get(wallet_id) {
            debug!(
                "Loaded wallet {} from cache ({} shares)",
                wallet_id,
                entry.shares.len()
            );
            return Ok((entry.pubkey_package.clone(), entry.shares.clone()));
        }

        let file_path = self.get_keystore_path(wallet_id);
        if !file_path.exists() {
            return Err(WalletError::KeystoreError(format!(
                "Wallet {} not found in keystore",
                wallet_id
            )));
        }

        let json = std::fs::read_to_string(&file_path)?;
        let bundle: EncryptedWalletBundle = serde_json::from_str(&json)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        if bundle.encrypted_shares.is_empty() {
            return Err(WalletError::KeystoreError(
                "No encrypted shares found in keystore".to_string(),
            ));
        }

        let decryption_key = Self::derive_key(password, &bundle.salt)?;

        // Decrypt the public-key package.
        let pubkey_json = decryption_key
            .decrypt(&bundle.encrypted_pubkey_package)
            .map_err(|e| {
                WalletError::KeystoreError(format!(
                    "Failed to decrypt FROST public-key package (wrong password?): {}",
                    e
                ))
            })?;
        let pubkey_package: PublicKeyPackage = serde_json::from_slice(&pubkey_json)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        // Decrypt each share.
        let mut decrypted_shares = Vec::with_capacity(bundle.encrypted_shares.len());
        for encrypted in bundle.encrypted_shares {
            let decrypted_bytes = decryption_key
                .decrypt(&encrypted.encrypted_data)
                .map_err(|e| {
                    WalletError::KeystoreError(format!(
                        "Failed to decrypt share {} (wrong password?): {}",
                        encrypted.signer_index, e
                    ))
                })?;
            let share = KeyShare::from_bytes(&decrypted_bytes)?;
            if share.signer_index.0 != encrypted.signer_index {
                return Err(WalletError::SerializationError(format!(
                    "Signer index mismatch on disk: envelope says {}, payload says {}",
                    encrypted.signer_index, share.signer_index.0
                )));
            }
            decrypted_shares.push(share);
        }

        debug!(
            "Loaded wallet {} from keystore ({} shares, threshold {})",
            wallet_id,
            decrypted_shares.len(),
            pubkey_package.threshold,
        );

        self.cache.insert(
            wallet_id.clone(),
            CacheEntry {
                pubkey_package: pubkey_package.clone(),
                shares: decrypted_shares.clone(),
            },
        );

        Ok((pubkey_package, decrypted_shares))
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

    /// Change password for a wallet (FROST bundle + PQ seed + BLS seed).
    pub fn change_password(
        &mut self,
        wallet_id: &WalletId,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        let (pubkey_package, shares) = self.load_shares(wallet_id, old_password)?;
        self.store_shares(wallet_id, &pubkey_package, &shares, new_password)?;

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
    pub fn load_bls_seed(
        &mut self,
        wallet_id: &WalletId,
        password: &str,
    ) -> Result<BlsKeyPair> {
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

        SymmetricKey::from_bytes(&key_bytes)
            .map_err(|e| WalletError::KeystoreError(e.to_string()))
    }

    /// Read the three encrypted keystore files for `wallet_id` as raw bytes,
    /// without decrypting them.
    ///
    /// Returned map keys are the on-disk filenames (`<id>.json`,
    /// `<id>.pq.json`, `<id>.bls.json`); values are the verbatim ciphertext
    /// blobs as written by `store_shares` / `store_pq_seed` / `store_bls_seed`.
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
    use crate::provisioning::WalletProvisioner;
    use tempfile::TempDir;

    #[test]
    fn test_keystore_store() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();

        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();
        let pubkey_package = wallet.frost_pubkey_package().unwrap().clone();

        let password = "test-password-123";

        keystore
            .store_shares(&wallet.wallet_id, &pubkey_package, &wallet.key_shares, password)
            .unwrap();

        assert!(keystore.has_wallet(&wallet.wallet_id));
    }

    #[test]
    fn test_keystore_round_trip_signs_after_unlock() {
        use crate::mpc_signing::MpcSigner;
        use crate::wallet::MpcWallet;
        use tenzro_types::primitives::Address;

        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();

        let provisioner = WalletProvisioner::new();
        let original = provisioner.provision_wallet().unwrap();
        let pubkey_package = original.frost_pubkey_package().unwrap().clone();
        let pq_key = original.pq_signing_key().unwrap().clone();
        let bls_key = original.bls_signing_key().unwrap().clone();
        let original_pk = original.public_key.clone();
        let wallet_id = original.wallet_id.clone();
        let address = original.address;
        let key_shares = original.key_shares.clone();

        keystore
            .store_shares(&wallet_id, &pubkey_package, &key_shares, "pw")
            .unwrap();
        keystore.store_pq_seed(&wallet_id, &pq_key, "pw").unwrap();
        keystore.store_bls_seed(&wallet_id, &bls_key, "pw").unwrap();
        keystore.clear_cache();
        drop(original);

        let (loaded_pkg, loaded_shares) = keystore.load_shares(&wallet_id, "pw").unwrap();
        let loaded_pq = keystore.load_pq_seed(&wallet_id, "pw").unwrap();
        let loaded_bls = keystore.load_bls_seed(&wallet_id, "pw").unwrap();
        assert_eq!(loaded_shares.len(), 3);
        assert_eq!(loaded_pkg.threshold, 2);
        assert_eq!(loaded_pkg.total, 3);

        // Make sure the rehydrated wallet can produce a valid signature.
        let _ = address;
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(loaded_pkg.group_public_key.as_public_key().to_address().as_bytes());
        let rehydrated_address = Address::new(addr_bytes);

        let restored = MpcWallet::new(
            wallet_id.clone(),
            rehydrated_address,
            loaded_shares,
            loaded_pkg,
            loaded_pq,
            loaded_bls,
        )
        .unwrap();

        let sig = MpcSigner::sign(&restored, b"keystore round-trip").unwrap();
        tenzro_crypto::signatures::verify(&original_pk, b"keystore round-trip", &sig).unwrap();
    }

    #[test]
    fn test_list_wallets() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();

        let provisioner = WalletProvisioner::new();
        let wallet1 = provisioner.provision_wallet().unwrap();
        let wallet2 = provisioner.provision_wallet().unwrap();

        keystore
            .store_shares(
                &wallet1.wallet_id,
                wallet1.frost_pubkey_package().unwrap(),
                &wallet1.key_shares,
                "password1",
            )
            .unwrap();
        keystore
            .store_shares(
                &wallet2.wallet_id,
                wallet2.frost_pubkey_package().unwrap(),
                &wallet2.key_shares,
                "password2",
            )
            .unwrap();

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
            .store_shares(
                &wallet.wallet_id,
                wallet.frost_pubkey_package().unwrap(),
                &wallet.key_shares,
                "password",
            )
            .unwrap();

        assert!(keystore.has_wallet(&wallet.wallet_id));
        keystore.delete_wallet(&wallet.wallet_id).unwrap();
        assert!(!keystore.has_wallet(&wallet.wallet_id));
    }

    #[test]
    fn test_export_import_encrypted_wallet_files_round_trip() {
        use crate::mpc_signing::MpcSigner;
        use crate::wallet::MpcWallet;
        use tenzro_types::primitives::Address;

        // Source keystore: provision + persist a wallet.
        let src_dir = TempDir::new().unwrap();
        let mut src = Keystore::new(src_dir.path()).unwrap();
        let provisioner = WalletProvisioner::new();
        let original = provisioner.provision_wallet().unwrap();
        let pubkey_package = original.frost_pubkey_package().unwrap().clone();
        let pq_key = original.pq_signing_key().unwrap().clone();
        let bls_key = original.bls_signing_key().unwrap().clone();
        let wallet_id = original.wallet_id.clone();
        let original_pk = original.public_key.clone();

        src.store_shares(&wallet_id, &pubkey_package, &original.key_shares, "pw")
            .unwrap();
        src.store_pq_seed(&wallet_id, &pq_key, "pw").unwrap();
        src.store_bls_seed(&wallet_id, &bls_key, "pw").unwrap();
        drop(original);

        let bundle = src.export_encrypted_wallet_files(&wallet_id).unwrap();
        assert_eq!(bundle.len(), 3);
        assert!(bundle.contains_key(&format!("{}.json", wallet_id.as_str())));
        assert!(bundle.contains_key(&format!("{}.pq.json", wallet_id.as_str())));
        assert!(bundle.contains_key(&format!("{}.bls.json", wallet_id.as_str())));

        // Destination keystore: import the bundle.
        let dst_dir = TempDir::new().unwrap();
        let mut dst = Keystore::new(dst_dir.path()).unwrap();
        dst.import_encrypted_wallet_files(&wallet_id, &bundle).unwrap();

        // Importing twice must refuse — we don't silently overwrite.
        let dup = dst.import_encrypted_wallet_files(&wallet_id, &bundle);
        assert!(dup.is_err(), "duplicate import must error");

        // Rehydrate from the imported files and sign — proves bytes are intact.
        let (loaded_pkg, loaded_shares) = dst.load_shares(&wallet_id, "pw").unwrap();
        let loaded_pq = dst.load_pq_seed(&wallet_id, "pw").unwrap();
        let loaded_bls = dst.load_bls_seed(&wallet_id, "pw").unwrap();

        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(
            loaded_pkg
                .group_public_key
                .as_public_key()
                .to_address()
                .as_bytes(),
        );
        let restored = MpcWallet::new(
            wallet_id,
            Address::new(addr_bytes),
            loaded_shares,
            loaded_pkg,
            loaded_pq,
            loaded_bls,
        )
        .unwrap();

        let sig = MpcSigner::sign(&restored, b"car export round-trip").unwrap();
        tenzro_crypto::signatures::verify(&original_pk, b"car export round-trip", &sig)
            .unwrap();
    }

    #[test]
    fn test_change_password() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = Keystore::new(temp_dir.path()).unwrap();

        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();
        let pq_key = wallet.pq_signing_key().unwrap().clone();
        let bls_key = wallet.bls_signing_key().unwrap().clone();

        keystore
            .store_shares(
                &wallet.wallet_id,
                wallet.frost_pubkey_package().unwrap(),
                &wallet.key_shares,
                "old-password",
            )
            .unwrap();
        keystore
            .store_pq_seed(&wallet.wallet_id, &pq_key, "old-password")
            .unwrap();
        keystore
            .store_bls_seed(&wallet.wallet_id, &bls_key, "old-password")
            .unwrap();

        keystore
            .change_password(&wallet.wallet_id, "old-password", "new-password")
            .unwrap();
        keystore.clear_cache();

        let (_, shares) = keystore
            .load_shares(&wallet.wallet_id, "new-password")
            .unwrap();
        assert_eq!(shares.len(), wallet.key_shares.len());
    }
}
