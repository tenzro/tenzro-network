//! Local self-custody hybrid keystore for the Tenzro CLI.
//!
//! A self-custody node runner holds its own signing keys and never surrenders
//! them to a node. This module seals an Ed25519 + ML-DSA-65 hybrid keypair on
//! disk under an Argon2id-derived AES-256-GCM key (same KDF hardening as the
//! `tenzro-wallet` keystore) and signs both legs of a transaction locally, then
//! submits it via `eth_sendRawTransaction`.
//!
//! The server-custodial path (`tenzro_signAndSendTransaction`) remains the
//! default for runners without local keys; this is the opt-in local-key path
//! for runners who bring their own custody.

use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tenzro_crypto::encryption::SymmetricKey;
use tenzro_crypto::{
    signatures::{Ed25519SignerImpl, Signer},
    KeyPair, KeyType, MlDsaSigningKey, PublicKey, SecretKey,
};

/// On-disk sealed hybrid keystore. Both seeds are AES-256-GCM ciphertext under
/// the Argon2id-derived key; the salt is shared by both payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealedHybridKey {
    /// Argon2id salt for the KDF (shared by both sealed seeds).
    salt: Vec<u8>,
    /// AES-256-GCM ciphertext of the 32-byte Ed25519 secret scalar.
    encrypted_ed25519_seed: Vec<u8>,
    /// AES-256-GCM ciphertext of the 32-byte ML-DSA-65 seed.
    encrypted_ml_dsa_seed: Vec<u8>,
    /// Ed25519 public key (32 bytes) — held in the clear so the CLI can show
    /// the account address and populate `from` without a password prompt.
    ed25519_public_key: Vec<u8>,
    /// ML-DSA-65 verifying key (1952 bytes) — held in the clear for `pq_public_key`.
    ml_dsa_verifying_key: Vec<u8>,
}

/// An unlocked local hybrid signer: an Ed25519 signer plus an ML-DSA-65 seed.
/// Signs both legs over the same message so the node's hybrid verifier accepts.
pub struct LocalHybridSigner {
    ed25519: Ed25519SignerImpl,
    ed25519_public_key: Vec<u8>,
    ml_dsa: MlDsaSigningKey,
}

impl LocalHybridSigner {
    /// Raw 32-byte Ed25519 public key. This IS the account address on the
    /// native convention — the node's `eth_sendRawTransaction` verifier accepts
    /// a raw 32-byte pubkey placed in `from` (`matches_pubkey`).
    pub fn ed25519_public_key(&self) -> &[u8] {
        &self.ed25519_public_key
    }

    /// ML-DSA-65 verifying key bytes (1952) for the mandatory `pq_public_key`.
    pub fn ml_dsa_verifying_key(&self) -> &[u8] {
        self.ml_dsa.verifying_key_bytes()
    }

    /// Hex-encoded raw Ed25519 pubkey, used as the `from` address (64 hex chars,
    /// no `0x` prefix — the node strips an optional prefix either way).
    pub fn from_address_hex(&self) -> String {
        format!("0x{}", hex::encode(&self.ed25519_public_key))
    }

    /// Sign `message` with both legs. Returns `(ed25519_sig_64, ml_dsa_sig_3309)`.
    pub fn sign_hybrid(&self, message: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let classical = self
            .ed25519
            .sign(message)
            .map_err(|e| anyhow!("Ed25519 signing failed: {}", e))?;
        let pq = self.ml_dsa.sign(message);
        Ok((classical.to_bytes(), pq))
    }
}

/// Path to the CLI's sealed hybrid key: `~/.tenzro/hybrid_key.json`.
pub fn hybrid_key_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".tenzro").join("hybrid_key.json")
}

/// `true` iff a local self-custody hybrid key exists on disk.
pub fn has_local_key() -> bool {
    hybrid_key_path().exists()
}

/// Generate a fresh Ed25519 + ML-DSA-65 hybrid keypair and seal it under
/// `password`. Overwrites any existing local key. Returns the raw Ed25519
/// public key (the account address) as hex.
pub fn create_local_key(password: &str) -> Result<String> {
    let ed_keypair = KeyPair::generate(KeyType::Ed25519)
        .map_err(|e| anyhow!("Ed25519 keygen failed: {}", e))?;
    let ml_dsa = MlDsaSigningKey::generate();
    persist(
        password,
        ed_keypair.secret_key().as_bytes(),
        ed_keypair.public_key().as_bytes(),
        ml_dsa.seed_bytes(),
        ml_dsa.verifying_key_bytes(),
    )?;
    Ok(format!("0x{}", hex::encode(ed_keypair.public_key().as_bytes())))
}

/// Import an existing Ed25519 secret key (32-byte hex) into a local self-custody
/// keystore, deriving a fresh ML-DSA-65 leg. Returns the account address hex.
pub fn import_local_key(ed25519_secret_hex: &str, password: &str) -> Result<String> {
    let clean = ed25519_secret_hex.strip_prefix("0x").unwrap_or(ed25519_secret_hex);
    let secret_bytes = hex::decode(clean).map_err(|e| anyhow!("invalid secret key hex: {}", e))?;
    if secret_bytes.len() != 32 {
        return Err(anyhow!(
            "Ed25519 secret key must be 32 bytes, got {}",
            secret_bytes.len()
        ));
    }
    let secret = SecretKey::new(KeyType::Ed25519, secret_bytes);
    let ed_keypair =
        KeyPair::from_secret_key(secret).map_err(|e| anyhow!("invalid Ed25519 secret: {}", e))?;
    let ml_dsa = MlDsaSigningKey::generate();
    persist(
        password,
        ed_keypair.secret_key().as_bytes(),
        ed_keypair.public_key().as_bytes(),
        ml_dsa.seed_bytes(),
        ml_dsa.verifying_key_bytes(),
    )?;
    Ok(format!("0x{}", hex::encode(ed_keypair.public_key().as_bytes())))
}

/// Unlock the local hybrid key with `password`, returning a signer.
pub fn unlock_local_key(password: &str) -> Result<LocalHybridSigner> {
    let path = hybrid_key_path();
    let json = std::fs::read_to_string(&path)
        .map_err(|_| anyhow!("no local self-custody key at {}", path.display()))?;
    let sealed: SealedHybridKey =
        serde_json::from_str(&json).map_err(|e| anyhow!("corrupt hybrid keystore: {}", e))?;

    let salt: [u8; 32] = sealed
        .salt
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("corrupt hybrid keystore: salt must be 32 bytes"))?;
    let key = derive_key(password, &salt)?;

    let ed_seed = key
        .decrypt(&sealed.encrypted_ed25519_seed)
        .map_err(|_| anyhow!("failed to decrypt Ed25519 seed (wrong password?)"))?;
    let ml_seed = key
        .decrypt(&sealed.encrypted_ml_dsa_seed)
        .map_err(|_| anyhow!("failed to decrypt ML-DSA-65 seed (wrong password?)"))?;

    let secret = SecretKey::new(KeyType::Ed25519, ed_seed);
    let ed_keypair =
        KeyPair::from_secret_key(secret).map_err(|e| anyhow!("invalid Ed25519 seed: {}", e))?;
    let ml_dsa =
        MlDsaSigningKey::from_seed(&ml_seed).map_err(|e| anyhow!("invalid ML-DSA-65 seed: {}", e))?;

    // Cross-check the sealed public keys against the reconstructed private keys
    // so a tampered clear-text pubkey field cannot mislead `from`. Snapshot the
    // Ed25519 pubkey bytes before the keypair is moved into the signer.
    let ed_public_key = ed_keypair.public_key().as_bytes().to_vec();
    if ed_public_key != sealed.ed25519_public_key {
        return Err(anyhow!("hybrid keystore integrity: Ed25519 public key mismatch"));
    }
    if ml_dsa.verifying_key_bytes() != sealed.ml_dsa_verifying_key.as_slice() {
        return Err(anyhow!("hybrid keystore integrity: ML-DSA-65 verifying key mismatch"));
    }

    let ed25519 = Ed25519SignerImpl::new(ed_keypair)
        .map_err(|e| anyhow!("Ed25519 signer init failed: {}", e))?;

    Ok(LocalHybridSigner {
        ed25519,
        ed25519_public_key: ed_public_key,
        ml_dsa,
    })
}

/// Public account address (raw Ed25519 pubkey hex) without unlocking. Reads the
/// clear-text pubkey field, so no password is needed to display the address.
pub fn local_address() -> Option<String> {
    let json = std::fs::read_to_string(hybrid_key_path()).ok()?;
    let sealed: SealedHybridKey = serde_json::from_str(&json).ok()?;
    Some(format!("0x{}", hex::encode(&sealed.ed25519_public_key)))
}

fn persist(
    password: &str,
    ed_seed: &[u8],
    ed_public_key: &[u8],
    ml_seed: &[u8],
    ml_verifying_key: &[u8],
) -> Result<()> {
    let salt = generate_salt();
    let key = derive_key(password, &salt)?;
    let encrypted_ed25519_seed = key
        .encrypt(ed_seed)
        .map_err(|e| anyhow!("seal Ed25519 seed: {}", e))?;
    let encrypted_ml_dsa_seed = key
        .encrypt(ml_seed)
        .map_err(|e| anyhow!("seal ML-DSA-65 seed: {}", e))?;

    let sealed = SealedHybridKey {
        salt: salt.to_vec(),
        encrypted_ed25519_seed,
        encrypted_ml_dsa_seed,
        ed25519_public_key: ed_public_key.to_vec(),
        ml_dsa_verifying_key: ml_verifying_key.to_vec(),
    };

    let path = hybrid_key_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(&sealed)?;
    std::fs::write(&path, json)?;
    Ok(())
}

fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

/// Argon2id KDF — identical parameters to the `tenzro-wallet` keystore
/// (64 MB memory, 3 iterations, parallelism 4, 32-byte output).
fn derive_key(password: &str, salt: &[u8; 32]) -> Result<SymmetricKey> {
    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| anyhow!("Argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| anyhow!("Argon2 KDF: {}", e))?;
    SymmetricKey::from_bytes(&key_bytes).map_err(|e| anyhow!("symmetric key: {}", e))
}

/// Confirm a `PublicKey` from raw Ed25519 bytes derives the same address the
/// node will (used only to validate imported keys ahead of a send).
pub fn ed25519_public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey> {
    if bytes.len() != 32 {
        return Err(anyhow!("Ed25519 public key must be 32 bytes"));
    }
    Ok(PublicKey::new(KeyType::Ed25519, bytes.to_vec()))
}
