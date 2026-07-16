//! FROST-Ed25519 threshold wallet types for Tenzro Network.
//!
//! Each wallet holds:
//!   * the shared FROST [`PublicKeyPackage`] (group public key + per-signer
//!     verifying shares),
//!   * one [`KeyShare`] per signer this process holds,
//!   * a mandatory ML-DSA-65 signing key for the post-quantum hybrid leg.
//!
//! Signing is RFC 9591 FROST-Ed25519. The aggregated signature is a standard
//! 64-byte Ed25519 signature that verifies under the group's verifying key
//! using `tenzro_crypto::signatures::verify`.

use crate::error::{Result, WalletError};
use serde::{Deserialize, Serialize};
use tenzro_crypto::bls::BlsKeyPair;
use tenzro_crypto::frost::{PublicKeyPackage, SecretShare, SignerIndex};
use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_crypto::{KeyType, PublicKey};
use tenzro_types::primitives::{Address, Timestamp};
use tenzro_types::AssetId;
use uuid::Uuid;
use zeroize::Zeroize;

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

/// One signer's share of a FROST-Ed25519 threshold key.
///
/// `signer_index` is the FROST identifier (1..=n). `participant_id` is a
/// human-readable label for ops/audit. The actual secret material lives in
/// `secret_share`, whose `Debug` impl redacts the bytes. Serde derives are
/// retained because the keystore writes through to its own AES-256-GCM
/// envelope — this type is never serialized in the clear at the wallet API
/// boundary; `MpcWallet` skips its `key_shares` field on serialize.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyShare {
    /// FROST signer index (1..=n).
    pub signer_index: SignerIndex,
    /// Identifier of the participant holding this share.
    pub participant_id: String,
    /// FROST secret share (sensitive — never log; redacted in `Debug`).
    pub secret_share: SecretShare,
}

impl KeyShare {
    /// Create a new key share.
    pub fn new(
        signer_index: SignerIndex,
        participant_id: String,
        secret_share: SecretShare,
    ) -> Self {
        Self {
            signer_index,
            participant_id,
            secret_share,
        }
    }

    /// 1-based signer index.
    pub fn share_index(&self) -> u16 {
        self.signer_index.0
    }

    /// FROST is Ed25519-only (RFC 9591).
    pub fn key_type(&self) -> KeyType {
        KeyType::Ed25519
    }

    /// Export to bytes for storage. The keystore wraps the result in its
    /// AES-256-GCM envelope before writing to disk.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Restore from bytes (the persisted blob carries the secret share).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| WalletError::SerializationError(e.to_string()))
    }
}

impl std::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyShare")
            .field("signer_index", &self.signer_index.0)
            .field("participant_id", &self.participant_id)
            .field("secret_share", &"<redacted>")
            .finish()
    }
}

/// A FROST-Ed25519 threshold wallet.
///
/// Auto-provisioned without seed phrases. Holds the group's
/// [`PublicKeyPackage`], the local signers' key shares, and a mandatory
/// ML-DSA-65 hybrid post-quantum signing key.
#[derive(Clone, Serialize, Deserialize)]
pub struct MpcWallet {
    /// Unique wallet identifier.
    pub wallet_id: WalletId,
    /// Wallet's address on the network (derived from the FROST group key).
    pub address: Address,
    /// FROST threshold (`t`).
    pub threshold: u16,
    /// Total number of FROST signers (`n`).
    pub total_shares: u16,
    /// Key shares held by this wallet instance.
    #[serde(skip)]
    pub key_shares: Vec<KeyShare>,
    /// Group public key — the single Ed25519 verifying key the chain sees.
    pub public_key: PublicKey,
    /// Full FROST public-key package (group key + per-signer verifying
    /// shares). Required for round-2 signing and aggregation.
    #[serde(skip)]
    pub frost_pubkey_package: Option<PublicKeyPackage>,
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
    /// the FROST shares and ML-DSA-65 seed in the keystore. The
    /// corresponding 48-byte G1-compressed public key is bound to the
    /// identity at registration.
    #[serde(skip)]
    pub bls_signing_key: Option<BlsKeyPair>,
    /// BLS12-381 G1-compressed verifying key (exactly 48 bytes).
    pub bls_verifying_key: Vec<u8>,
}

impl std::fmt::Debug for MpcWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MpcWallet")
            .field("wallet_id", &self.wallet_id)
            .field("address", &self.address)
            .field("threshold", &self.threshold)
            .field("total_shares", &self.total_shares)
            .field(
                "key_shares",
                &format_args!("<{} share(s) redacted>", self.key_shares.len()),
            )
            .field("public_key", &self.public_key)
            .field(
                "frost_pubkey_package",
                &format_args!(
                    "{}",
                    if self.frost_pubkey_package.is_some() {
                        "<loaded>"
                    } else {
                        "<not loaded>"
                    }
                ),
            )
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

impl MpcWallet {
    /// Create a new FROST threshold wallet.
    ///
    /// `pq_signing_key` and `bls_signing_key` are both mandatory and bound
    /// directly into the wallet alongside the FROST shares. There is no
    /// classical-only fallback.
    pub fn new(
        wallet_id: WalletId,
        address: Address,
        key_shares: Vec<KeyShare>,
        frost_pubkey_package: PublicKeyPackage,
        pq_signing_key: MlDsaSigningKey,
        bls_signing_key: BlsKeyPair,
    ) -> Result<Self> {
        if key_shares.is_empty() {
            return Err(WalletError::InvalidKeyShare(
                "Must have at least one key share".to_string(),
            ));
        }

        let supported_assets = vec![
            AssetId::tnzo(),
            AssetId::from("USDT"),
            AssetId::from("USDC"),
        ];

        let pq_verifying_key = pq_signing_key.verifying_key_bytes().to_vec();
        let bls_verifying_key = bls_signing_key.public_key().to_bytes().to_vec();
        let public_key = frost_pubkey_package.group_public_key.as_public_key();
        let threshold = frost_pubkey_package.threshold;
        let total_shares = frost_pubkey_package.total;

        Ok(Self {
            wallet_id,
            address,
            threshold,
            total_shares,
            key_shares,
            public_key,
            frost_pubkey_package: Some(frost_pubkey_package),
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
    /// own (`key_shares` empty, `pq_signing_key` / `bls_signing_key` /
    /// `frost_pubkey_package` all `None`). Signatures for this wallet must
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
            return Err(WalletError::InvalidKeyShare(format!(
                "ML-DSA-65 verifying key must be 1952 bytes, got {}",
                pq_verifying_key.len()
            )));
        }
        if bls_verifying_key.len() != 48 {
            return Err(WalletError::InvalidKeyShare(format!(
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
            threshold: 0,
            total_shares: 0,
            key_shares: Vec::new(),
            public_key: classical_public_key,
            frost_pubkey_package: None,
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
        self.key_shares.is_empty()
            && self.pq_signing_key.is_none()
            && self.frost_pubkey_package.is_none()
    }

    /// FROST public-key package — required for round-2 signing and
    /// aggregation. Returns an error when the wallet was rehydrated from
    /// metadata-only storage and the keystore has not yet decrypted it.
    pub fn frost_pubkey_package(&self) -> Result<&PublicKeyPackage> {
        self.frost_pubkey_package.as_ref().ok_or_else(|| {
            WalletError::SignatureFailed(
                "FROST public-key package not loaded — keystore must decrypt the wallet first"
                    .to_string(),
            )
        })
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

    /// FROST is Ed25519-only.
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

    /// Number of key shares held by this wallet.
    pub fn share_count(&self) -> usize {
        self.key_shares.len()
    }

    /// Whether we hold enough shares to meet the FROST threshold.
    pub fn can_sign(&self) -> bool {
        self.key_shares.len() >= self.threshold as usize
    }

    /// Reference to held key shares.
    pub fn key_shares(&self) -> &[KeyShare] {
        &self.key_shares
    }

    /// Add a key share to the wallet.
    ///
    /// Rejects duplicates by signer index. The cryptographic binding to the
    /// group key is enforced by FROST aggregation, not by per-share metadata
    /// (each FROST share has only its own verifying share, not the group
    /// pubkey).
    pub fn add_key_share(&mut self, share: KeyShare) -> Result<()> {
        if self
            .key_shares
            .iter()
            .any(|s| s.signer_index == share.signer_index)
        {
            return Err(WalletError::InvalidKeyShare(format!(
                "Share with signer index {} already exists",
                share.signer_index.0
            )));
        }

        self.key_shares.push(share);
        Ok(())
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

impl Drop for MpcWallet {
    fn drop(&mut self) {
        for share in &mut self.key_shares {
            share.participant_id.zeroize();
        }
        self.key_shares.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::frost::keygen_with_trusted_dealer;

    fn build_wallet(t: u16, n: u16) -> MpcWallet {
        let (pubkey_pkg, secret_shares) = keygen_with_trusted_dealer(t, n).unwrap();

        let key_shares: Vec<KeyShare> = secret_shares
            .into_iter()
            .map(|s| {
                let participant = format!("participant_{}", s.index.0);
                KeyShare::new(s.index, participant, s)
            })
            .collect();

        let group_pk = pubkey_pkg.group_public_key.as_public_key();
        let crypto_addr = group_pk.to_address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = Address::new(addr_bytes);

        MpcWallet::new(
            WalletId::new(),
            address,
            key_shares,
            pubkey_pkg,
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
        let wallet = build_wallet(2, 3);
        assert_eq!(wallet.threshold, 2);
        assert_eq!(wallet.total_shares, 3);
        assert_eq!(wallet.share_count(), 3);
        assert!(wallet.can_sign());
        assert_eq!(wallet.pq_verifying_key_bytes().len(), 1952);
    }

    #[test]
    fn test_wallet_asset_management() {
        let mut wallet = build_wallet(2, 3);

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
        let wallet = build_wallet(2, 3);

        let json = wallet.to_metadata_json().unwrap();
        let restored = MpcWallet::from_metadata_json(&json).unwrap();

        assert_eq!(wallet.wallet_id, restored.wallet_id);
        assert_eq!(wallet.address, restored.address);
        assert_eq!(wallet.threshold, restored.threshold);
        assert_eq!(wallet.total_shares, restored.total_shares);
    }

    #[test]
    fn test_add_key_share_rejects_duplicate_signer_index() {
        let mut wallet = build_wallet(2, 3);
        let dup = wallet.key_shares[0].clone();
        let err = wallet.add_key_share(dup).unwrap_err();
        assert!(matches!(err, WalletError::InvalidKeyShare(_)));
    }
}
