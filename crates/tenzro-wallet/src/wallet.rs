//! Identity-bound wallet types for Tenzro Network.
//!
//! Each wallet holds:
//!   * the identity's classical public key (the private half lives in the
//!     holder's hardware — a passkey for a human, a TPM 2.0 / Secure Enclave
//!     for a machine — and never enters this process),
//!   * a mandatory ML-DSA-65 signing key for the post-quantum hybrid leg,
//!   * a BLS12-381 signing key.
//!
//! Signing is Ed25519 by the identity key. The signature is a standard
//! 64-byte Ed25519 signature that verifies under the identity's verifying key
//! using `tenzro_crypto::signatures::verify`.

use crate::error::{Result, WalletError};
use serde::{Deserialize, Serialize};
use tenzro_crypto::bls::BlsKeyPair;
use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_crypto::{KeyType, PublicKey};
use tenzro_types::AssetId;
use tenzro_types::primitives::{Address, Timestamp};
use uuid::Uuid;

/// Unique identifier for a wallet in Tenzro Network.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WalletId(pub String);

impl WalletId {
    /// Generate a new random wallet ID
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Create from string
    pub fn from_string(id: String) -> Self {
        Self(id)
    }

    /// Get the ID as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for WalletId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for WalletId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for WalletId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

/// An identity-bound wallet.
///
/// The classical key is held by this machine's secure element and never
/// appears here; the wallet carries its public half plus a mandatory ML-DSA-65
/// hybrid post-quantum signing key.
#[derive(Clone, Serialize, Deserialize)]
pub struct Wallet {
    /// Unique wallet identifier.
    pub wallet_id: WalletId,
    /// Wallet's address on the network (derived from the identity public key).
    pub address: Address,
    /// The device key's public half — the single verifying key the chain sees.
    /// Serialized: it is public, and without it a wallet cannot be rebuilt from
    /// storage without the hardware being present.
    pub public_key: PublicKey,
    /// List of supported assets.
    pub supported_assets: Vec<AssetId>,
    /// Wallet creation timestamp.
    pub created_at: Timestamp,
    /// Last used timestamp.
    pub last_used: Option<Timestamp>,
    /// Optional wallet label.
    pub label: Option<String>,
    /// ML-DSA-65 signing key (FIPS 204) for the post-quantum leg of the
    /// hybrid signature. Mandatory — every wallet carries one.
    #[serde(skip)]
    pub pq_signing_key: Option<MlDsaSigningKey>,
    /// ML-DSA-65 verifying key bytes (FIPS 204, exactly 1952 bytes).
    pub pq_verifying_key: Vec<u8>,
    /// BLS12-381 signing key (`min_pk` scheme) for HotStuff-2 vote
    /// aggregation. Mandatory — every wallet carries one. Lives alongside
    /// the ML-DSA-65 and BLS seeds in the keystore. The
    /// corresponding 48-byte G1-compressed public key is bound to the
    /// identity at registration.
    #[serde(skip)]
    pub bls_signing_key: Option<BlsKeyPair>,
    /// BLS12-381 G1-compressed verifying key (exactly 48 bytes).
    pub bls_verifying_key: Vec<u8>,
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("wallet_id", &self.wallet_id)
            .field("address", &self.address)
            .field("public_key", &self.public_key)
            .field("supported_assets", &self.supported_assets)
            .field("created_at", &self.created_at)
            .field("last_used", &self.last_used)
            .field("label", &self.label)
            .field(
                "pq_signing_key",
                &format_args!(
                    "{}",
                    if self.pq_signing_key.is_some() {
                        "<loaded>"
                    } else {
                        "<not loaded>"
                    }
                ),
            )
            .field(
                "pq_verifying_key",
                &format_args!("<{} bytes>", self.pq_verifying_key.len()),
            )
            .field(
                "bls_signing_key",
                &format_args!(
                    "{}",
                    if self.bls_signing_key.is_some() {
                        "<loaded>"
                    } else {
                        "<not loaded>"
                    }
                ),
            )
            .field(
                "bls_verifying_key",
                &format_args!("<{} bytes>", self.bls_verifying_key.len()),
            )
            .finish()
    }
}

impl Wallet {
    /// Create a wallet whose classical key is held locally, in this machine's
    /// secure element.
    ///
    /// This replaces the former threshold constructor. Custody is no
    /// longer a quorum of shares reconstructed at signing time — the private
    /// half never leaves the hardware, so there is nothing to reconstruct and
    /// nothing to distribute. `pq_signing_key` and `bls_signing_key` remain
    /// mandatory; there is no classical-only fallback.
    ///
    /// `classical_public_key` is the public half of the device key. Signing
    /// goes through a [`crate::signing::HybridSigner`] — see
    /// [`crate::device_custody`] — because this type deliberately cannot hold
    /// the classical secret.
    pub fn new(
        wallet_id: WalletId,
        address: Address,
        classical_public_key: PublicKey,
        pq_signing_key: MlDsaSigningKey,
        bls_signing_key: BlsKeyPair,
    ) -> Result<Self> {
        let supported_assets = vec![
            AssetId::tnzo(),
            AssetId::from("USDT"),
            AssetId::from("USDC"),
        ];

        let pq_verifying_key = pq_signing_key.verifying_key_bytes().to_vec();
        let bls_verifying_key = bls_signing_key.public_key().to_bytes().to_vec();

        Ok(Self {
            wallet_id,
            address,
            public_key: classical_public_key,
            supported_assets,
            created_at: Timestamp::now(),
            last_used: None,
            label: None,
            pq_signing_key: Some(pq_signing_key),
            pq_verifying_key,
            bls_signing_key: Some(bls_signing_key),
            bls_verifying_key,
        })
    }

    /// Create a watch-only wallet that holds no signing secrets.
    ///
    /// The classical public key, ML-DSA-65 verifying key, and BLS12-381
    /// verifying key are supplied directly; the wallet cannot sign on its
    /// own (`pq_signing_key` / `bls_signing_key`
    /// `bls_signing_key` all `None`). Signatures for this wallet must
    /// come from an external [`crate::signing::HybridSigner`] bound via
    /// `TenzroWalletService::set_hybrid_signer`.
    ///
    /// This is the autonomous-machine custody shape: the address and public
    /// keys mirror a TEE-sealed agent key the node cannot read, so no secret
    /// is ever reconstructed in node memory.
    ///
    /// The address is derived from `classical_public_key` exactly as the
    /// signing path expects (`PublicKey::to_address` widened to 32 bytes).
    pub fn new_watch_only(
        wallet_id: WalletId,
        classical_public_key: PublicKey,
        pq_verifying_key: Vec<u8>,
        bls_verifying_key: Vec<u8>,
    ) -> Result<Self> {
        if pq_verifying_key.len() != 1952 {
            return Err(WalletError::InvalidKeyMaterial(format!(
                "ML-DSA-65 verifying key must be 1952 bytes, got {}",
                pq_verifying_key.len()
            )));
        }
        if bls_verifying_key.len() != 48 {
            return Err(WalletError::InvalidKeyMaterial(format!(
                "BLS12-381 verifying key must be 48 bytes, got {}",
                bls_verifying_key.len()
            )));
        }

        let crypto_addr = classical_public_key.to_address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = Address::new(addr_bytes);

        let supported_assets = vec![
            AssetId::tnzo(),
            AssetId::from("USDT"),
            AssetId::from("USDC"),
        ];

        Ok(Self {
            wallet_id,
            address,
            public_key: classical_public_key,
            supported_assets,
            created_at: Timestamp::now(),
            last_used: None,
            label: None,
            pq_signing_key: None,
            pq_verifying_key,
            bls_signing_key: None,
            bls_verifying_key,
        })
    }

    /// Whether this wallet holds no signing secrets (watch-only). Such a
    /// wallet must sign through an external
    /// [`crate::signing::HybridSigner`].
    pub fn is_watch_only(&self) -> bool {
        self.pq_signing_key.is_none()
    }

    /// Borrow the post-quantum (ML-DSA-65) signing key.
    pub fn pq_signing_key(&self) -> Result<&MlDsaSigningKey> {
        self.pq_signing_key.as_ref().ok_or_else(|| {
            WalletError::SignatureFailed(
                "ML-DSA-65 signing key not loaded — keystore must decrypt the wallet first"
                    .to_string(),
            )
        })
    }

    /// 1952-byte ML-DSA-65 verifying key bytes (FIPS 204).
    pub fn pq_verifying_key_bytes(&self) -> Vec<u8> {
        self.pq_verifying_key.clone()
    }

    /// Borrow the BLS12-381 signing key.
    pub fn bls_signing_key(&self) -> Result<&BlsKeyPair> {
        self.bls_signing_key.as_ref().ok_or_else(|| {
            WalletError::SignatureFailed(
                "BLS12-381 signing key not loaded — keystore must decrypt the wallet first"
                    .to_string(),
            )
        })
    }

    /// 48-byte BLS12-381 G1-compressed verifying key bytes (`min_pk` scheme).
    pub fn bls_verifying_key_bytes(&self) -> &[u8] {
        &self.bls_verifying_key
    }

    /// Get the wallet ID.
    pub fn id(&self) -> &WalletId {
        &self.wallet_id
    }

    /// Get the wallet address.
    pub fn address(&self) -> Address {
        self.address
    }

    /// The identity key is Ed25519.
    pub fn key_type(&self) -> KeyType {
        KeyType::Ed25519
    }

    /// Check if an asset is supported.
    pub fn supports_asset(&self, asset_id: &AssetId) -> bool {
        self.supported_assets.contains(asset_id)
    }

    /// Add support for a new asset.
    pub fn add_supported_asset(&mut self, asset_id: AssetId) {
        if !self.supported_assets.contains(&asset_id) {
            self.supported_assets.push(asset_id);
        }
    }

    /// Remove asset support.
    pub fn remove_supported_asset(&mut self, asset_id: &AssetId) {
        self.supported_assets.retain(|a| a != asset_id);
    }

    /// Set the wallet label.
    pub fn set_label(&mut self, label: String) {
        self.label = Some(label);
    }

    /// Update last used timestamp.
    pub fn update_last_used(&mut self) {
        self.last_used = Some(Timestamp::now());
    }

    /// Serialize wallet metadata to JSON (excludes secret material).
    pub fn to_metadata_json(&self) -> Result<String> {
        serde_json::to_string(&self).map_err(|e| WalletError::SerializationError(e.to_string()))
    }

    /// Deserialize wallet metadata from JSON.
    pub fn from_metadata_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| WalletError::SerializationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::PublicKey;

    /// Build a locally-custodied wallet. There is no dealer and no share
    /// distribution any more: the classical key is held by hardware, so the
    /// test supplies its public half directly.
    fn build_wallet() -> Wallet {
        let signing = tenzro_crypto::KeyPair::generate(tenzro_crypto::KeyType::Ed25519).unwrap();
        let group_pk: PublicKey = signing.public_key().clone();
        let crypto_addr = group_pk.to_address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = Address::new(addr_bytes);

        Wallet::new(
            WalletId::new(),
            address,
            group_pk,
            MlDsaSigningKey::generate(),
            BlsKeyPair::generate().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn test_wallet_id_generation() {
        let id1 = WalletId::new();
        let id2 = WalletId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_mpc_wallet_creation() {
        let wallet = build_wallet();
        // A locally-held key is trivially its own quorum.
        assert_eq!(wallet.pq_verifying_key_bytes().len(), 1952);
    }

    #[test]
    fn test_wallet_asset_management() {
        let mut wallet = build_wallet();

        assert!(wallet.supports_asset(&AssetId::tnzo()));
        assert!(wallet.supports_asset(&AssetId::from("USDT")));

        let new_asset = AssetId::from("ETH");
        wallet.add_supported_asset(new_asset.clone());
        assert!(wallet.supports_asset(&new_asset));

        wallet.remove_supported_asset(&new_asset);
        assert!(!wallet.supports_asset(&new_asset));
    }

    #[test]
    fn test_wallet_metadata_serialization() {
        let wallet = build_wallet();

        let json = wallet.to_metadata_json().unwrap();
        let restored = Wallet::from_metadata_json(&json).unwrap();

        assert_eq!(wallet.wallet_id, restored.wallet_id);
        assert_eq!(wallet.address, restored.address);
    }
}
