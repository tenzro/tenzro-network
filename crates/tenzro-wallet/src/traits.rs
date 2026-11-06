//! Wallet service trait for Tenzro Network.
//!
//! This module defines the core trait that wallet implementations must satisfy.

use crate::balance::Balance;
use crate::contacts::Contact;
use crate::error::Result;
use crate::history::{HistoryFilter, TxRecord};
use crate::identity_binding::WalletIdentity;
use crate::wallet::{Wallet, WalletId};
use async_trait::async_trait;
use tenzro_crypto::CompositeSignature;
use tenzro_types::AssetId;
use tenzro_types::primitives::{Address, Hash, Nonce};
use tenzro_types::transaction::Transaction;

/// Wallet service trait for Tenzro Network.
///
/// This trait defines the complete interface for wallet operations including:
/// - Wallet provisioning (auto-creation)
/// - Balance queries (with on-chain sync)
/// - Transaction building, validation, and signing
/// - Nonce management
/// - Transaction history
/// - Contact management
/// - Asset management
#[async_trait]
pub trait WalletService: Send + Sync {
    // === Wallet Lifecycle ===

    /// Provision a wallet for an identity.
    ///
    /// **A wallet cannot be provisioned without one.** `identity` carries the
    /// public key the wallet's signatures verify against — a passkey for a
    /// human, a TPM or Secure Enclave key for a machine — and there is no
    /// overload that omits it.
    ///
    /// The service never generates that key. A signing secret minted here would
    /// sit in process memory and be custodial, which is precisely the design
    /// this replaced; the private half stays with the identity holder, and the
    /// wallet signs by binding a [`crate::signing::HybridSigner`].
    async fn provision_wallet(&self, identity: WalletIdentity) -> Result<Wallet>;

    /// Get a wallet by its ID.
    async fn get_wallet(&self, wallet_id: &WalletId) -> Result<Option<Wallet>>;

    /// Get all wallets managed by this service.
    async fn list_wallets(&self) -> Result<Vec<WalletId>>;

    /// Delete a wallet (removes from storage).
    async fn delete_wallet(&self, wallet_id: &WalletId) -> Result<()>;

    /// Update wallet label.
    async fn set_wallet_label(&self, wallet_id: &WalletId, label: String) -> Result<()>;

    // === Balance ===

    /// Get the balance for a specific address and asset.
    ///
    /// Returns the full balance including available, locked, and pending amounts.
    async fn get_balance(&self, address: &Address, asset: &AssetId) -> Result<Balance>;

    /// Get the available (spendable) balance for an address and asset.
    async fn available_balance(&self, address: &Address, asset: &AssetId) -> Result<u128>;

    // === Signing ===

    /// Validate `tx` and sign `Transaction::hash()` with the wallet's
    /// hardware signer under the transaction context.
    async fn sign_transaction(
        &self,
        wallet_id: &WalletId,
        tx: &Transaction,
    ) -> Result<CompositeSignature>;

    /// Sign `data` for the protocol named by `context`, producing a composite
    /// signature that verifies only under that context.
    async fn sign_data(
        &self,
        wallet_id: &WalletId,
        context: tenzro_crypto::SignatureContext,
        data: &[u8],
    ) -> Result<CompositeSignature>;

    /// A plain P-256 (ES256) signature over `SHA-256(data)` for external
    /// protocols that verify their own canonical bytes (HTTP message
    /// signatures, JWS). Refuses input that begins with the composite prefix.
    async fn sign_external(&self, wallet_id: &WalletId, data: &[u8]) -> Result<Vec<u8>>;

    // === Nonce ===

    /// Get the next nonce for a wallet's address.
    fn next_nonce(&self, address: &Address) -> Nonce;

    /// Get the current pending nonce without incrementing.
    fn peek_nonce(&self, address: &Address) -> Nonce;

    /// Re-anchor the pending nonce counter against the chain's executed nonce,
    /// allowing `max_inflight` assignments to be outstanding. Callers that can
    /// read chain state do this before assigning, so one rejected transaction
    /// cannot wedge the address for the life of the process.
    fn rebase_nonce(&self, address: &Address, chain_nonce: u64, max_inflight: u64);

    // === History ===

    /// Get transaction history for an address.
    async fn get_history(&self, address: &Address) -> Result<Vec<TxRecord>>;

    /// Get filtered transaction history.
    async fn get_filtered_history(
        &self,
        address: &Address,
        filter: &HistoryFilter,
    ) -> Result<Vec<TxRecord>>;

    /// Get a transaction record by hash.
    async fn get_transaction(&self, tx_hash: &Hash) -> Result<Option<TxRecord>>;

    // === Contacts ===

    /// Add a contact to the address book.
    async fn add_contact(&self, contact: Contact) -> Result<()>;

    /// Get a contact by address.
    async fn get_contact(&self, address: &Address) -> Result<Option<Contact>>;

    /// Resolve a contact name to an address.
    async fn resolve_contact(&self, name: &str) -> Result<Option<Address>>;

    // === Assets ===

    /// Get the list of supported assets.
    async fn supported_assets(&self) -> Vec<AssetId>;

    /// Add asset support to a wallet.
    async fn add_asset_support(&self, wallet_id: &WalletId, asset_id: AssetId) -> Result<()>;

    /// Remove asset support from a wallet.
    async fn remove_asset_support(&self, wallet_id: &WalletId, asset_id: &AssetId) -> Result<()>;

    // === Export/Import ===

    /// Export wallet metadata (for backup).
    async fn export_wallet_metadata(&self, wallet_id: &WalletId) -> Result<String>;

    /// Import wallet metadata (for recovery).
    async fn import_wallet_metadata(&self, metadata: &str) -> Result<WalletId>;
}
