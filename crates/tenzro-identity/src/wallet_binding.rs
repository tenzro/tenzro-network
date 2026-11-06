//! Wallet binding for the Tenzro Decentralized Identity Protocol
//!
//! Provisions identity-bound wallets for new identities and binds
//! wallet addresses to identity DIDs.

use crate::error::{IdentityError, Result};
use std::sync::Arc;
use tenzro_types::primitives::Address;
use tenzro_wallet::{TenzroWalletService, WalletService};
use tracing::info;

/// Wallet provisioning result
pub struct WalletBinding {
    /// The wallet ID
    pub wallet_id: String,
    /// The wallet address
    pub address: Address,
    /// The wallet's P-256 public key, `x || y` (64 bytes): the passkey or
    /// TPM / Secure Enclave key the identity authenticates with.
    pub public_key: Vec<u8>,
    /// The wallet's hardware ML-DSA-65 verifying key (1952 bytes), or empty
    /// when the hardware has none enrolled.
    pub pq_verifying_key: Vec<u8>,
}

/// Binds identity-bound wallets to TDIP identities
///
/// Handles auto-provisioning of permissionless wallets when new identities
/// are registered, ensuring every identity has a wallet for on-chain operations.
///
/// The binder holds an `Arc<TenzroWalletService>` so the registry and the
/// node-level RPC handlers share a single wallet service instance — wallets
/// provisioned during identity registration are immediately resolvable by
/// `WalletService::sign_transaction` against the same `wallet_id`.
pub struct WalletBinder {
    wallet_service: Arc<TenzroWalletService>,
}

impl WalletBinder {
    /// Creates a new wallet binder backed by a fresh in-process wallet service.
    ///
    /// Suitable for tests; production node startup must use
    /// [`Self::from_service`] so the binder shares the node's `WalletService`.
    pub fn new() -> Result<Self> {
        let wallet_service = Arc::new(
            TenzroWalletService::new().map_err(|e| IdentityError::WalletError(e.to_string()))?,
        );
        Ok(Self { wallet_service })
    }

    /// Creates a wallet binder backed by an existing shared wallet service.
    ///
    /// This is the production wiring used by the node: the same
    /// `Arc<TenzroWalletService>` that backs `tenzro_*` RPC handlers is
    /// passed in here, so wallets provisioned via
    /// `IdentityRegistry::register_human_via_binder` are signable by the
    /// auth-mediated `tenzro_signTransaction` / `tenzro_sendRawTransaction`
    /// paths without any wallet-id translation.
    pub fn from_service(wallet_service: Arc<TenzroWalletService>) -> Self {
        Self { wallet_service }
    }

    /// Provisions a wallet for an identity.
    ///
    /// `identity` carries the public key the wallet's signatures verify
    /// against — a passkey for a human, a TPM or Secure Enclave key for a
    /// machine. It is required: a wallet with no identity behind it cannot be
    /// authorised by anyone, so the wallet service has no overload that omits
    /// it. See `tenzro_wallet::WalletIdentity`.
    pub async fn provision_wallet(
        &self,
        did: &str,
        identity: tenzro_wallet::WalletIdentity,
    ) -> Result<WalletBinding> {
        info!(
            "Provisioning {} wallet for identity: {}",
            identity.kind(),
            did
        );

        let wallet = self
            .wallet_service
            .provision_wallet(identity)
            .await
            .map_err(|e| IdentityError::WalletError(e.to_string()))?;

        let mut addr_bytes = [0u8; 32];
        let src = wallet.address.as_bytes();
        let len = src.len().min(32);
        addr_bytes[..len].copy_from_slice(&src[..len]);

        Ok(WalletBinding {
            wallet_id: wallet.wallet_id.to_string(),
            address: Address::new(addr_bytes),
            public_key: wallet.public_key.p256.clone(),
            pq_verifying_key: wallet.public_key.pq.clone().unwrap_or_default(),
        })
    }
}
