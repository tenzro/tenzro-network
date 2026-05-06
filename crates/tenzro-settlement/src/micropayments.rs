//! Micropayment channels for frequent small payments (e.g., per-token inference billing)

use crate::error::{Result, SettlementError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tenzro_crypto::keys::{KeyType, PublicKey};
use tenzro_crypto::signatures::Signature as CryptoSignature;
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::{Address, Nonce, Timestamp};
use tracing::{debug, info, warn};

/// Trait for persistent channel storage
///
/// Implementations can use databases, files, or other persistent storage.
/// The trait covers both channel records and dispute records — both must
/// survive node restarts since channel disputes have a 24-hour resolution
/// timeout that may straddle a restart.
pub trait ChannelStorage: Send + Sync {
    /// Persists a channel to storage
    fn persist_channel(&self, channel: &MicropaymentChannel) -> Result<()>;

    /// Loads a channel from storage
    fn load_channel(&self, channel_id: &str) -> Result<Option<MicropaymentChannel>>;

    /// Loads all channels from storage
    fn load_all_channels(&self) -> Result<Vec<MicropaymentChannel>>;

    /// Deletes a channel from storage
    fn delete_channel(&self, channel_id: &str) -> Result<()>;

    /// Persists a dispute to storage. Default impl is a no-op so existing
    /// implementations remain source-compatible; backends that care about
    /// dispute durability should override.
    fn persist_dispute(&self, _dispute: &ChannelDispute) -> Result<()> {
        Ok(())
    }

    /// Loads all disputes from storage. Default returns empty.
    fn load_all_disputes(&self) -> Result<Vec<ChannelDispute>> {
        Ok(Vec::new())
    }

    /// Deletes a dispute from storage. Default no-op.
    fn delete_dispute(&self, _dispute_id: &str) -> Result<()> {
        Ok(())
    }
}

/// In-memory channel storage (default, non-persistent)
#[derive(Debug, Default)]
pub struct InMemoryChannelStorage {
    channels: DashMap<String, Vec<u8>>,
    disputes: DashMap<String, Vec<u8>>,
}

impl InMemoryChannelStorage {
    /// Creates a new in-memory storage
    pub fn new() -> Self {
        Self {
            channels: DashMap::new(),
            disputes: DashMap::new(),
        }
    }
}

impl ChannelStorage for InMemoryChannelStorage {
    fn persist_channel(&self, channel: &MicropaymentChannel) -> Result<()> {
        let serialized = serde_json::to_vec(channel).map_err(|e| {
            SettlementError::StorageError(format!("Failed to serialize channel: {}", e))
        })?;

        self.channels
            .insert(channel.channel_id.clone(), serialized);
        Ok(())
    }

    fn load_channel(&self, channel_id: &str) -> Result<Option<MicropaymentChannel>> {
        if let Some(entry) = self.channels.get(channel_id) {
            let channel = serde_json::from_slice(entry.value()).map_err(|e| {
                SettlementError::StorageError(format!("Failed to deserialize channel: {}", e))
            })?;
            Ok(Some(channel))
        } else {
            Ok(None)
        }
    }

    fn load_all_channels(&self) -> Result<Vec<MicropaymentChannel>> {
        let mut channels = Vec::new();
        for entry in self.channels.iter() {
            let channel = serde_json::from_slice(entry.value()).map_err(|e| {
                SettlementError::StorageError(format!("Failed to deserialize channel: {}", e))
            })?;
            channels.push(channel);
        }
        Ok(channels)
    }

    fn delete_channel(&self, channel_id: &str) -> Result<()> {
        self.channels.remove(channel_id);
        Ok(())
    }

    fn persist_dispute(&self, dispute: &ChannelDispute) -> Result<()> {
        let serialized = serde_json::to_vec(dispute).map_err(|e| {
            SettlementError::StorageError(format!("Failed to serialize dispute: {}", e))
        })?;
        self.disputes
            .insert(dispute.dispute_id.clone(), serialized);
        Ok(())
    }

    fn load_all_disputes(&self) -> Result<Vec<ChannelDispute>> {
        let mut disputes = Vec::new();
        for entry in self.disputes.iter() {
            let dispute = serde_json::from_slice(entry.value()).map_err(|e| {
                SettlementError::StorageError(format!("Failed to deserialize dispute: {}", e))
            })?;
            disputes.push(dispute);
        }
        Ok(disputes)
    }

    fn delete_dispute(&self, dispute_id: &str) -> Result<()> {
        self.disputes.remove(dispute_id);
        Ok(())
    }
}

/// RocksDB-backed channel storage.
///
/// Persists channels and disputes to `CF_CHANNELS` under the prefixes:
/// - `channel:<channel_id>` — full [`MicropaymentChannel`] record (JSON)
/// - `dispute:<dispute_id>` — full [`ChannelDispute`] record (JSON)
///
/// All writes go through [`KvStore::write_batch_sync`] for atomic, fsync'd
/// durability. Hydration scans both prefixes on construction.
pub struct RocksDbChannelStorage {
    storage: Arc<dyn tenzro_storage::KvStore>,
}

impl std::fmt::Debug for RocksDbChannelStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RocksDbChannelStorage")
            .field("storage", &"<dyn KvStore>")
            .finish()
    }
}

impl RocksDbChannelStorage {
    /// Channel record key prefix
    const CHANNEL_PREFIX: &'static [u8] = b"channel:";
    /// Dispute record key prefix
    const DISPUTE_PREFIX: &'static [u8] = b"dispute:";

    /// Creates a new RocksDB-backed channel storage adapter.
    pub fn new(storage: Arc<dyn tenzro_storage::KvStore>) -> Self {
        Self { storage }
    }

    fn channel_key(channel_id: &str) -> Vec<u8> {
        [Self::CHANNEL_PREFIX, channel_id.as_bytes()].concat()
    }

    fn dispute_key(dispute_id: &str) -> Vec<u8> {
        [Self::DISPUTE_PREFIX, dispute_id.as_bytes()].concat()
    }
}

impl ChannelStorage for RocksDbChannelStorage {
    fn persist_channel(&self, channel: &MicropaymentChannel) -> Result<()> {
        let value = serde_json::to_vec(channel).map_err(|e| {
            SettlementError::StorageError(format!("Failed to serialize channel: {}", e))
        })?;
        self.storage
            .write_batch_sync(vec![tenzro_storage::WriteOp::Put {
                cf: tenzro_storage::CF_CHANNELS.to_string(),
                key: Self::channel_key(&channel.channel_id),
                value,
            }])
            .map_err(|e| SettlementError::StorageError(e.to_string()))
    }

    fn load_channel(&self, channel_id: &str) -> Result<Option<MicropaymentChannel>> {
        match self
            .storage
            .get(tenzro_storage::CF_CHANNELS, &Self::channel_key(channel_id))
            .map_err(|e| SettlementError::StorageError(e.to_string()))?
        {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| SettlementError::StorageError(format!("decode channel: {}", e))),
            None => Ok(None),
        }
    }

    fn load_all_channels(&self) -> Result<Vec<MicropaymentChannel>> {
        let keys = self
            .storage
            .get_keys_with_prefix(tenzro_storage::CF_CHANNELS, Self::CHANNEL_PREFIX)
            .map_err(|e| SettlementError::StorageError(e.to_string()))?;

        let mut channels = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(bytes) = self
                .storage
                .get(tenzro_storage::CF_CHANNELS, &key)
                .map_err(|e| SettlementError::StorageError(e.to_string()))?
            {
                match serde_json::from_slice::<MicropaymentChannel>(&bytes) {
                    Ok(c) => channels.push(c),
                    Err(e) => warn!("skip undecodable channel record: {}", e),
                }
            }
        }
        Ok(channels)
    }

    fn delete_channel(&self, channel_id: &str) -> Result<()> {
        self.storage
            .write_batch_sync(vec![tenzro_storage::WriteOp::Delete {
                cf: tenzro_storage::CF_CHANNELS.to_string(),
                key: Self::channel_key(channel_id),
            }])
            .map_err(|e| SettlementError::StorageError(e.to_string()))
    }

    fn persist_dispute(&self, dispute: &ChannelDispute) -> Result<()> {
        let value = serde_json::to_vec(dispute).map_err(|e| {
            SettlementError::StorageError(format!("Failed to serialize dispute: {}", e))
        })?;
        self.storage
            .write_batch_sync(vec![tenzro_storage::WriteOp::Put {
                cf: tenzro_storage::CF_CHANNELS.to_string(),
                key: Self::dispute_key(&dispute.dispute_id),
                value,
            }])
            .map_err(|e| SettlementError::StorageError(e.to_string()))
    }

    fn load_all_disputes(&self) -> Result<Vec<ChannelDispute>> {
        let keys = self
            .storage
            .get_keys_with_prefix(tenzro_storage::CF_CHANNELS, Self::DISPUTE_PREFIX)
            .map_err(|e| SettlementError::StorageError(e.to_string()))?;

        let mut disputes = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(bytes) = self
                .storage
                .get(tenzro_storage::CF_CHANNELS, &key)
                .map_err(|e| SettlementError::StorageError(e.to_string()))?
            {
                match serde_json::from_slice::<ChannelDispute>(&bytes) {
                    Ok(d) => disputes.push(d),
                    Err(e) => warn!("skip undecodable dispute record: {}", e),
                }
            }
        }
        Ok(disputes)
    }

    fn delete_dispute(&self, dispute_id: &str) -> Result<()> {
        self.storage
            .write_batch_sync(vec![tenzro_storage::WriteOp::Delete {
                cf: tenzro_storage::CF_CHANNELS.to_string(),
                key: Self::dispute_key(dispute_id),
            }])
            .map_err(|e| SettlementError::StorageError(e.to_string()))
    }
}

/// Status of a micropayment channel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelStatus {
    /// Channel is open and accepting payments
    Open,
    /// Channel close has been initiated (challenge period)
    Closing,
    /// Channel is closed
    Closed,
    /// Channel was force-closed due to dispute
    ForceClosed,
}

/// Status of a channel dispute
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisputeStatus {
    /// Dispute has been opened
    Opened,
    /// Other party has responded to the dispute
    Responded,
    /// Dispute has been resolved
    Resolved,
    /// Dispute timed out without response
    TimedOut,
}

/// A dispute over a micropayment channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelDispute {
    /// Unique dispute identifier
    pub dispute_id: String,
    /// Channel being disputed
    pub channel_id: String,
    /// Address of the party that opened the dispute
    pub challenger: Address,
    /// Evidence provided by challenger
    pub challenger_evidence: Vec<u8>,
    /// Evidence provided by responder (if any)
    pub responder_evidence: Option<Vec<u8>>,
    /// Current dispute status
    pub status: DisputeStatus,
    /// Timestamp when dispute was opened
    pub opened_at: Timestamp,
    /// Timestamp when dispute expires (auto-resolve in favor of challenger)
    pub timeout_at: Timestamp,
    /// Timestamp when dispute was resolved
    pub resolved_at: Option<Timestamp>,
    /// Resolution outcome (if resolved)
    pub resolution: Option<String>,
}

/// State of a micropayment channel
///
/// This represents the current state that can be updated off-chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelState {
    /// State nonce (increments with each update)
    pub nonce: Nonce,
    /// Payer's remaining balance
    pub payer_balance: u128,
    /// Payee's accumulated balance
    pub payee_balance: u128,
    /// Signature over this state (simplified - would be actual cryptographic signature)
    pub signature: Vec<u8>,
}

impl ChannelState {
    /// Creates a new channel state
    pub fn new(payer_balance: u128, payee_balance: u128) -> Self {
        Self {
            nonce: Nonce::initial(),
            payer_balance,
            payee_balance,
            signature: Vec::new(),
        }
    }

    /// Creates the next state with updated balances
    pub fn next(&self, payer_balance: u128, payee_balance: u128) -> Self {
        Self {
            nonce: self.nonce.next(),
            payer_balance,
            payee_balance,
            signature: Vec::new(),
        }
    }

    /// Signs the state (simplified — stores raw signature bytes)
    pub fn sign(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }

    /// Verifies the signature is non-empty (basic check)
    ///
    /// For full cryptographic verification, use `verify_signature_with_key()`
    /// which verifies against a specific signer's Ed25519 public key.
    pub fn verify_signature(&self) -> bool {
        !self.signature.is_empty()
    }

    /// Verifies the signature cryptographically against a signer's public key
    ///
    /// The message signed is the canonical state encoding:
    /// `nonce || payer_balance || payee_balance`
    pub fn verify_signature_with_key(&self, signer: &Address) -> bool {
        if self.signature.is_empty() {
            return false;
        }

        let message = self.canonical_message();
        let pk_bytes = signer.as_bytes().to_vec();
        let public_key = PublicKey::new(KeyType::Ed25519, pk_bytes);
        let signature = CryptoSignature::new(KeyType::Ed25519, self.signature.clone());

        tenzro_crypto::signatures::verify(&public_key, &message, &signature).is_ok()
    }

    /// Returns the canonical message bytes for signing
    ///
    /// Format: `nonce (8 bytes LE) || payer_balance (16 bytes LE) || payee_balance (16 bytes LE)`
    pub fn canonical_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(40);
        msg.extend_from_slice(&self.nonce.0.to_le_bytes());
        msg.extend_from_slice(&self.payer_balance.to_le_bytes());
        msg.extend_from_slice(&self.payee_balance.to_le_bytes());
        msg
    }
}

/// A micropayment channel for frequent small payments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicropaymentChannel {
    /// Unique channel identifier
    pub channel_id: String,
    /// Payer address
    pub payer: Address,
    /// Payee address (service provider)
    pub payee: Address,
    /// Total deposit in channel
    pub deposit: u128,
    /// Amount already spent
    pub spent: u128,
    /// Current channel state
    pub state: ChannelState,
    /// Asset type
    pub asset_id: AssetId,
    /// Channel expiration time
    pub expires_at: Timestamp,
    /// Current status
    pub status: ChannelStatus,
    /// Timestamp when channel was opened
    pub opened_at: Timestamp,
    /// Timestamp when close was initiated
    pub close_initiated_at: Option<Timestamp>,
    /// Timestamp when channel was closed
    pub closed_at: Option<Timestamp>,
    /// Challenge period duration in milliseconds
    pub challenge_period_ms: i64,
}

impl MicropaymentChannel {
    /// Creates a new micropayment channel
    pub fn new(
        payer: Address,
        payee: Address,
        deposit: u128,
        asset_id: AssetId,
        expires_at: Timestamp,
        challenge_period_ms: i64,
    ) -> Self {
        let state = ChannelState::new(deposit, 0);

        Self {
            channel_id: uuid::Uuid::new_v4().to_string(),
            payer,
            payee,
            deposit,
            spent: 0,
            state,
            asset_id,
            expires_at,
            status: ChannelStatus::Open,
            opened_at: Timestamp::now(),
            close_initiated_at: None,
            closed_at: None,
            challenge_period_ms,
        }
    }

    /// Remaining balance in channel
    pub fn remaining_balance(&self) -> u128 {
        self.deposit.saturating_sub(self.spent)
    }

    /// Checks if channel has expired
    pub fn is_expired(&self) -> bool {
        Timestamp::now() > self.expires_at
    }

    /// Checks if challenge period has elapsed
    pub fn challenge_period_elapsed(&self) -> bool {
        if let Some(close_time) = self.close_initiated_at {
            let elapsed = Timestamp::now().as_millis() - close_time.as_millis();
            elapsed >= self.challenge_period_ms
        } else {
            false
        }
    }
}

/// Micropayment channel manager
pub struct ChannelManager {
    /// Active channels (in-memory cache)
    channels: DashMap<String, MicropaymentChannel>,
    /// Channels by payer
    channels_by_payer: DashMap<Address, Vec<String>>,
    /// Channels by payee
    channels_by_payee: DashMap<Address, Vec<String>>,
    /// Account balances (simplified)
    balances: DashMap<(Address, AssetId), u128>,
    /// Default challenge period (24 hours)
    default_challenge_period_ms: i64,
    /// Persistent storage backend
    storage: Arc<dyn ChannelStorage>,
    /// Active disputes by dispute ID
    disputes: DashMap<String, ChannelDispute>,
    /// Disputes by channel ID
    disputes_by_channel: DashMap<String, Vec<String>>,
    /// Default dispute timeout (24 hours)
    default_dispute_timeout_ms: i64,
}

impl std::fmt::Debug for ChannelManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelManager")
            .field("channels", &self.channels)
            .field("channels_by_payer", &self.channels_by_payer)
            .field("channels_by_payee", &self.channels_by_payee)
            .field("balances", &self.balances)
            .field("default_challenge_period_ms", &self.default_challenge_period_ms)
            .field("storage", &"<dyn ChannelStorage>")
            .field("disputes", &self.disputes)
            .field("disputes_by_channel", &self.disputes_by_channel)
            .field("default_dispute_timeout_ms", &self.default_dispute_timeout_ms)
            .finish()
    }
}

impl ChannelManager {
    /// Creates a new channel manager with in-memory storage
    pub fn new() -> Self {
        Self::with_storage(Arc::new(InMemoryChannelStorage::new()))
    }

    /// Creates a new channel manager with custom storage backend
    pub fn with_storage(storage: Arc<dyn ChannelStorage>) -> Self {
        let manager = Self {
            channels: DashMap::new(),
            channels_by_payer: DashMap::new(),
            channels_by_payee: DashMap::new(),
            balances: DashMap::new(),
            default_challenge_period_ms: 86400000, // 24 hours
            storage,
            disputes: DashMap::new(),
            disputes_by_channel: DashMap::new(),
            default_dispute_timeout_ms: 86400000, // 24 hours
        };

        // Load existing channels from storage
        if let Err(e) = manager.load_from_storage() {
            warn!("Failed to load channels from storage: {}", e);
        }

        manager
    }

    /// Loads all channels and disputes from persistent storage into memory.
    ///
    /// Disputes are rehydrated alongside channels because a 24-hour timeout
    /// can straddle a node restart — losing dispute state would silently
    /// strand parties that opened a dispute pre-restart.
    fn load_from_storage(&self) -> Result<()> {
        let channels = self.storage.load_all_channels()?;

        for channel in channels {
            let channel_id = channel.channel_id.clone();

            // Store in memory
            self.channels.insert(channel_id.clone(), channel.clone());

            // Index by payer
            self.channels_by_payer
                .entry(channel.payer)
                .or_default()
                .push(channel_id.clone());

            // Index by payee
            self.channels_by_payee
                .entry(channel.payee)
                .or_default()
                .push(channel_id);
        }

        // Rehydrate disputes + rebuild the per-channel dispute index.
        let disputes = self.storage.load_all_disputes()?;
        for dispute in disputes {
            let dispute_id = dispute.dispute_id.clone();
            let channel_id = dispute.channel_id.clone();

            self.disputes.insert(dispute_id.clone(), dispute);
            self.disputes_by_channel
                .entry(channel_id)
                .or_default()
                .push(dispute_id);
        }

        info!(
            "Loaded {} channels and {} disputes from storage",
            self.channels.len(),
            self.disputes.len()
        );
        Ok(())
    }

    /// Persists a channel to storage
    fn persist_channel(&self, channel: &MicropaymentChannel) -> Result<()> {
        self.storage.persist_channel(channel)?;
        debug!("Persisted channel {} to storage", channel.channel_id);
        Ok(())
    }

    /// Deletes a channel from storage
    fn delete_channel_from_storage(&self, channel_id: &str) -> Result<()> {
        self.storage.delete_channel(channel_id)?;
        debug!("Deleted channel {} from storage", channel_id);
        Ok(())
    }

    /// Sets balance for testing
    pub fn set_balance(&self, address: &Address, asset_id: &AssetId, amount: u128) {
        self.balances.insert((*address, asset_id.clone()), amount);
    }

    /// Gets balance
    pub fn get_balance(&self, address: &Address, asset_id: &AssetId) -> u128 {
        self.balances
            .get(&(*address, asset_id.clone()))
            .map(|e| *e.value())
            .unwrap_or(0)
    }

    /// Opens a new micropayment channel with initial deposit
    pub fn open_channel(
        &self,
        payer: Address,
        payee: Address,
        deposit: u128,
        asset_id: AssetId,
        expires_at: Timestamp,
    ) -> Result<MicropaymentChannel> {
        if deposit == 0 {
            return Err(SettlementError::InvalidAmount(
                "Deposit must be greater than zero".to_string(),
            ));
        }

        // Check payer balance
        let key = (payer, asset_id.clone());
        let balance = self.balances.get(&key).map(|e| *e.value()).unwrap_or(0);

        if balance < deposit {
            return Err(SettlementError::InsufficientFunds {
                required: deposit,
                available: balance,
            });
        }

        // Lock deposit
        let mut entry = self.balances.entry(key).or_insert(0);
        *entry = entry.checked_sub(deposit).ok_or_else(|| {
            SettlementError::ArithmeticOverflow("Deposit deduction overflow".to_string())
        })?;
        drop(entry);

        // Create channel
        let channel = MicropaymentChannel::new(
            payer,
            payee,
            deposit,
            asset_id,
            expires_at,
            self.default_challenge_period_ms,
        );

        let channel_id = channel.channel_id.clone();

        // Persist channel to storage
        self.persist_channel(&channel)?;

        // Store channel in memory
        self.channels.insert(channel_id.clone(), channel.clone());

        // Index by payer
        self.channels_by_payer
            .entry(payer)
            .or_default()
            .push(channel_id.clone());

        // Index by payee
        self.channels_by_payee
            .entry(payee)
            .or_default()
            .push(channel_id.clone());

        info!(
            "Opened channel {} with deposit {} from {} to {}",
            channel.channel_id, deposit, payer, payee
        );

        Ok(channel)
    }

    /// Updates channel state (off-chain payment)
    ///
    /// This increments the payment without on-chain settlement
    pub fn update_channel(
        &self,
        channel_id: &str,
        payment_amount: u128,
        signature: Vec<u8>,
    ) -> Result<ChannelState> {
        let mut channel_entry = self
            .channels
            .get_mut(channel_id)
            .ok_or_else(|| SettlementError::ChannelNotFound(channel_id.to_string()))?;

        let channel = channel_entry.value_mut();

        // Check channel status
        if channel.status != ChannelStatus::Open {
            return Err(SettlementError::ChannelClosed(channel_id.to_string()));
        }

        // Check if expired
        if channel.is_expired() {
            return Err(SettlementError::ChannelClosed(
                "Channel has expired".to_string(),
            ));
        }

        // Calculate new balances
        let new_spent = channel
            .spent
            .checked_add(payment_amount)
            .ok_or_else(|| SettlementError::ArithmeticOverflow("Spent overflow".to_string()))?;

        if new_spent > channel.deposit {
            return Err(SettlementError::InsufficientFunds {
                required: new_spent,
                available: channel.deposit,
            });
        }

        let new_payer_balance = channel.deposit.saturating_sub(new_spent);
        let new_payee_balance = new_spent;

        // Create new state
        let mut new_state = channel.state.next(new_payer_balance, new_payee_balance);
        new_state.sign(signature);

        // Verify the signature is the payer's Ed25519 signature over the
        // canonical state encoding (`nonce || payer_balance ||
        // payee_balance`). The previous non-empty check was a stub that
        // accepted any byte string; with payer-key verification, only the
        // funder of the channel can authorize a debit against their own
        // balance, which is the channel-update invariant.
        if !new_state.verify_signature_with_key(&channel.payer) {
            return Err(SettlementError::InvalidSignature(
                "channel update signature failed verification against payer key"
                    .to_string(),
            ));
        }

        // Update channel
        channel.state = new_state.clone();
        channel.spent = new_spent;

        // Persist updated state
        let updated_channel = channel.clone();
        drop(channel_entry); // Release lock before persisting
        self.persist_channel(&updated_channel)?;

        debug!(
            "Updated channel {} state: spent={}, remaining={}",
            channel_id,
            new_spent,
            updated_channel.remaining_balance()
        );

        Ok(new_state)
    }

    /// Initiates cooperative channel close
    pub fn close_channel(&self, channel_id: &str) -> Result<()> {
        let mut channel_entry = self
            .channels
            .get_mut(channel_id)
            .ok_or_else(|| SettlementError::ChannelNotFound(channel_id.to_string()))?;

        let channel = channel_entry.value_mut();

        if channel.status != ChannelStatus::Open {
            return Err(SettlementError::ChannelClosed(
                "Channel already closing or closed".to_string(),
            ));
        }

        // Start challenge period
        channel.status = ChannelStatus::Closing;
        channel.close_initiated_at = Some(Timestamp::now());

        // Persist updated state
        let updated_channel = channel.clone();
        drop(channel_entry); // Release lock before persisting
        self.persist_channel(&updated_channel)?;

        info!("Initiated close for channel {}", channel_id);

        Ok(())
    }

    /// Finalizes channel close after challenge period
    pub fn finalize_close(&self, channel_id: &str) -> Result<()> {
        let mut channel_entry = self
            .channels
            .get_mut(channel_id)
            .ok_or_else(|| SettlementError::ChannelNotFound(channel_id.to_string()))?;

        let channel = channel_entry.value_mut();

        if channel.status != ChannelStatus::Closing {
            return Err(SettlementError::InvalidChannelState(
                "Channel not in closing state".to_string(),
            ));
        }

        // Check if challenge period elapsed
        if !channel.challenge_period_elapsed() {
            return Err(SettlementError::InvalidChannelState(
                "Challenge period not yet elapsed".to_string(),
            ));
        }

        // Settle final balances
        let payer_key = (channel.payer, channel.asset_id.clone());
        let payee_key = (channel.payee, channel.asset_id.clone());

        // Return remaining balance to payer
        if channel.state.payer_balance > 0 {
            let mut payer_entry = self.balances.entry(payer_key).or_insert(0);
            *payer_entry = payer_entry
                .checked_add(channel.state.payer_balance)
                .ok_or_else(|| {
                    SettlementError::ArithmeticOverflow("Payer refund overflow".to_string())
                })?;
        }

        // Pay accumulated balance to payee
        if channel.state.payee_balance > 0 {
            let mut payee_entry = self.balances.entry(payee_key).or_insert(0);
            *payee_entry = payee_entry
                .checked_add(channel.state.payee_balance)
                .ok_or_else(|| {
                    SettlementError::ArithmeticOverflow("Payee payment overflow".to_string())
                })?;
        }

        // Update channel status
        channel.status = ChannelStatus::Closed;
        channel.closed_at = Some(Timestamp::now());

        // Persist final state then delete from storage (channel is closed)
        let updated_channel = channel.clone();
        let channel_id_owned = channel_id.to_string();
        drop(channel_entry); // Release lock before storage operations

        self.persist_channel(&updated_channel)?;
        self.delete_channel_from_storage(&channel_id_owned)?;

        info!(
            "Finalized close for channel {}: payer={}, payee={}",
            channel_id_owned,
            updated_channel.state.payer_balance,
            updated_channel.state.payee_balance
        );

        Ok(())
    }

    /// Challenges a channel close with a newer state
    ///
    /// The challenge state must have a higher nonce and a valid signature
    /// from either the payer or payee.
    pub fn challenge_close(&self, channel_id: &str, new_state: ChannelState) -> Result<()> {
        let mut channel_entry = self
            .channels
            .get_mut(channel_id)
            .ok_or_else(|| SettlementError::ChannelNotFound(channel_id.to_string()))?;

        let channel = channel_entry.value_mut();

        if channel.status != ChannelStatus::Closing {
            return Err(SettlementError::InvalidChannelState(
                "Channel not in closing state".to_string(),
            ));
        }

        // Verify new state is newer
        if new_state.nonce.0 <= channel.state.nonce.0 {
            return Err(SettlementError::InvalidChannelState(
                "Challenge state not newer than current state".to_string(),
            ));
        }

        // Verify signature cryptographically — must be signed by payer or payee
        let payer_valid = new_state.verify_signature_with_key(&channel.payer);
        let payee_valid = new_state.verify_signature_with_key(&channel.payee);

        if !payer_valid && !payee_valid {
            return Err(SettlementError::InvalidSignature(
                "Challenge state must be signed by payer or payee".to_string(),
            ));
        }

        // Update to new state
        channel.state = new_state;

        // Persist updated state
        let updated_channel = channel.clone();
        drop(channel_entry); // Release lock before persisting
        self.persist_channel(&updated_channel)?;

        warn!("Channel {} close challenged with newer state", channel_id);

        Ok(())
    }

    /// Force closes a channel after timeout
    pub fn force_close(&self, channel_id: &str) -> Result<()> {
        let mut channel_entry = self
            .channels
            .get_mut(channel_id)
            .ok_or_else(|| SettlementError::ChannelNotFound(channel_id.to_string()))?;

        let channel = channel_entry.value_mut();

        if channel.status == ChannelStatus::Closed
            || channel.status == ChannelStatus::ForceClosed
        {
            return Err(SettlementError::ChannelClosed(
                "Channel already closed".to_string(),
            ));
        }

        // Force close settles with current state
        let payer_key = (channel.payer, channel.asset_id.clone());
        let payee_key = (channel.payee, channel.asset_id.clone());

        // Return remaining balance to payer
        if channel.state.payer_balance > 0 {
            let mut payer_entry = self.balances.entry(payer_key).or_insert(0);
            *payer_entry = payer_entry
                .checked_add(channel.state.payer_balance)
                .ok_or_else(|| {
                    SettlementError::ArithmeticOverflow("Payer refund overflow".to_string())
                })?;
        }

        // Pay accumulated balance to payee
        if channel.state.payee_balance > 0 {
            let mut payee_entry = self.balances.entry(payee_key).or_insert(0);
            *payee_entry = payee_entry
                .checked_add(channel.state.payee_balance)
                .ok_or_else(|| {
                    SettlementError::ArithmeticOverflow("Payee payment overflow".to_string())
                })?;
        }

        channel.status = ChannelStatus::ForceClosed;
        channel.closed_at = Some(Timestamp::now());

        // Persist final state
        let updated_channel = channel.clone();
        let channel_id_owned = channel_id.to_string();
        drop(channel_entry); // Release lock before persisting
        self.persist_channel(&updated_channel)?;

        warn!("Force closed channel {}", channel_id_owned);

        Ok(())
    }

    /// Gets a channel by ID
    pub fn get_channel(&self, channel_id: &str) -> Result<MicropaymentChannel> {
        self.channels
            .get(channel_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| SettlementError::ChannelNotFound(channel_id.to_string()))
    }

    /// Gets all channels for a payer
    pub fn get_channels_by_payer(&self, payer: &Address) -> Vec<MicropaymentChannel> {
        if let Some(channel_ids) = self.channels_by_payer.get(payer) {
            channel_ids
                .iter()
                .filter_map(|id| self.channels.get(id).map(|c| c.value().clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Gets all channels for a payee
    pub fn get_channels_by_payee(&self, payee: &Address) -> Vec<MicropaymentChannel> {
        if let Some(channel_ids) = self.channels_by_payee.get(payee) {
            channel_ids
                .iter()
                .filter_map(|id| self.channels.get(id).map(|c| c.value().clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Opens a dispute for a channel
    ///
    /// Either party can open a dispute if they believe the other party is
    /// attempting to close the channel with an invalid state.
    pub fn open_dispute(
        &self,
        channel_id: &str,
        challenger: Address,
        evidence: Vec<u8>,
    ) -> Result<ChannelDispute> {
        // Verify channel exists
        let channel = self.get_channel(channel_id)?;

        // Check if channel is in a disputable state
        if channel.status != ChannelStatus::Open && channel.status != ChannelStatus::Closing {
            return Err(SettlementError::InvalidChannelState(
                "Channel must be open or closing to dispute".to_string(),
            ));
        }

        // Verify challenger is a party to the channel
        if challenger != channel.payer && challenger != channel.payee {
            return Err(SettlementError::Unauthorized(
                "Only channel parties can open disputes".to_string(),
            ));
        }

        // Check if there's already an open dispute for this channel
        if let Some(dispute_ids) = self.disputes_by_channel.get(channel_id) {
            for dispute_id in dispute_ids.value() {
                if let Some(dispute) = self.disputes.get(dispute_id)
                    && (dispute.status == DisputeStatus::Opened
                        || dispute.status == DisputeStatus::Responded)
                {
                    return Err(SettlementError::InvalidChannelState(
                        "Channel already has an open dispute".to_string(),
                    ));
                }
            }
        }

        // Create dispute
        let timeout_at = Timestamp::new(
            Timestamp::now().as_millis() + self.default_dispute_timeout_ms,
        );

        let dispute = ChannelDispute {
            dispute_id: uuid::Uuid::new_v4().to_string(),
            channel_id: channel_id.to_string(),
            challenger,
            challenger_evidence: evidence,
            responder_evidence: None,
            status: DisputeStatus::Opened,
            opened_at: Timestamp::now(),
            timeout_at,
            resolved_at: None,
            resolution: None,
        };

        // Persist before exposing in-memory — if storage fails, the dispute
        // never appears to other code paths.
        self.storage.persist_dispute(&dispute)?;

        // Store dispute
        self.disputes
            .insert(dispute.dispute_id.clone(), dispute.clone());

        // Index by channel
        self.disputes_by_channel
            .entry(channel_id.to_string())
            .or_default()
            .push(dispute.dispute_id.clone());

        info!(
            "Opened dispute {} for channel {} by {}",
            dispute.dispute_id, channel_id, challenger
        );

        Ok(dispute)
    }

    /// Responds to a dispute with counter-evidence
    pub fn respond_to_dispute(
        &self,
        dispute_id: &str,
        responder: Address,
        evidence: Vec<u8>,
    ) -> Result<()> {
        let mut dispute_entry = self
            .disputes
            .get_mut(dispute_id)
            .ok_or_else(|| SettlementError::Internal("Dispute not found".to_string()))?;

        let dispute = dispute_entry.value_mut();

        // Check dispute status
        if dispute.status != DisputeStatus::Opened {
            return Err(SettlementError::InvalidChannelState(
                "Dispute is not open for response".to_string(),
            ));
        }

        // Get channel to verify responder
        let channel = self.get_channel(&dispute.channel_id)?;

        // Verify responder is the other party (not the challenger)
        if responder == dispute.challenger {
            return Err(SettlementError::Unauthorized(
                "Challenger cannot respond to their own dispute".to_string(),
            ));
        }

        if responder != channel.payer && responder != channel.payee {
            return Err(SettlementError::Unauthorized(
                "Only channel parties can respond to disputes".to_string(),
            ));
        }

        // Update dispute
        dispute.responder_evidence = Some(evidence);
        dispute.status = DisputeStatus::Responded;

        // Persist mutation before releasing the in-memory lock.
        let snapshot = dispute.clone();
        drop(dispute_entry);
        self.storage.persist_dispute(&snapshot)?;

        info!(
            "Dispute {} responded to by {}",
            dispute_id, responder
        );

        Ok(())
    }

    /// Resolves a dispute
    ///
    /// This can be called by either party to request resolution, or automatically
    /// after the timeout period. The resolution logic should be implemented based
    /// on the evidence provided by both parties.
    pub fn resolve_dispute(
        &self,
        dispute_id: &str,
        resolution: String,
    ) -> Result<()> {
        let mut dispute_entry = self
            .disputes
            .get_mut(dispute_id)
            .ok_or_else(|| SettlementError::Internal("Dispute not found".to_string()))?;

        let dispute = dispute_entry.value_mut();

        // Check dispute status
        if dispute.status == DisputeStatus::Resolved
            || dispute.status == DisputeStatus::TimedOut
        {
            return Err(SettlementError::InvalidChannelState(
                "Dispute already resolved".to_string(),
            ));
        }

        // Mark as resolved
        dispute.status = DisputeStatus::Resolved;
        dispute.resolved_at = Some(Timestamp::now());
        dispute.resolution = Some(resolution.clone());

        // Persist resolution before releasing the lock.
        let snapshot = dispute.clone();
        drop(dispute_entry);
        self.storage.persist_dispute(&snapshot)?;

        info!(
            "Dispute {} resolved: {}",
            dispute_id, resolution
        );

        Ok(())
    }

    /// Checks for timed out disputes and auto-resolves them in favor of challenger
    pub fn check_dispute_timeouts(&self) -> usize {
        let now = Timestamp::now();
        // Mutate in-memory first, collect snapshots, then persist outside the
        // iter_mut loop — holding a DashMap iter_mut guard across a storage
        // call risks deadlocks / re-entry.
        let mut to_persist: Vec<ChannelDispute> = Vec::new();

        for mut entry in self.disputes.iter_mut() {
            let dispute = entry.value_mut();

            if (dispute.status == DisputeStatus::Opened
                || dispute.status == DisputeStatus::Responded)
                && now > dispute.timeout_at
            {
                // Auto-resolve in favor of challenger
                dispute.status = DisputeStatus::TimedOut;
                dispute.resolved_at = Some(now);
                dispute.resolution = Some(format!(
                    "Auto-resolved in favor of challenger {} due to timeout",
                    dispute.challenger
                ));

                warn!(
                    "Dispute {} timed out, resolved in favor of challenger",
                    dispute.dispute_id
                );

                to_persist.push(dispute.clone());
            }
        }

        let resolved_count = to_persist.len();
        for snapshot in to_persist {
            if let Err(e) = self.storage.persist_dispute(&snapshot) {
                warn!(
                    "Failed to persist auto-resolved dispute {}: {}",
                    snapshot.dispute_id, e
                );
            }
        }

        if resolved_count > 0 {
            info!(
                "Auto-resolved {} timed out disputes",
                resolved_count
            );
        }

        resolved_count
    }

    /// Gets a dispute by ID
    pub fn get_dispute(&self, dispute_id: &str) -> Result<ChannelDispute> {
        self.disputes
            .get(dispute_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| SettlementError::Internal("Dispute not found".to_string()))
    }

    /// Gets all disputes for a channel
    pub fn get_disputes_for_channel(&self, channel_id: &str) -> Vec<ChannelDispute> {
        if let Some(dispute_ids) = self.disputes_by_channel.get(channel_id) {
            dispute_ids
                .iter()
                .filter_map(|id| self.disputes.get(id).map(|d| d.value().clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Returns channel statistics
    pub fn stats(&self) -> ChannelStats {
        let total_channels = self.channels.len();
        let mut open = 0;
        let mut closing = 0;
        let mut closed = 0;
        let mut force_closed = 0;

        for entry in self.channels.iter() {
            match entry.value().status {
                ChannelStatus::Open => open += 1,
                ChannelStatus::Closing => closing += 1,
                ChannelStatus::Closed => closed += 1,
                ChannelStatus::ForceClosed => force_closed += 1,
            }
        }

        ChannelStats {
            total_channels,
            open,
            closing,
            closed,
            force_closed,
        }
    }
}

impl Default for ChannelManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Channel statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelStats {
    /// Total number of channels
    pub total_channels: usize,
    /// Number of open channels
    pub open: usize,
    /// Number of closing channels
    pub closing: usize,
    /// Number of closed channels
    pub closed: usize,
    /// Number of force-closed channels
    pub force_closed: usize,
}

// ---------------------------------------------------------------------------
// Nanopayment Batcher (Circle USDC Nanopayments pattern)
// ---------------------------------------------------------------------------

/// A single nanopayment entry pending batch settlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NanopaymentEntry {
    /// Sender address
    pub from: Address,
    /// Recipient address
    pub to: Address,
    /// Amount in smallest token units
    pub amount: u128,
    /// Optional memo / reference
    pub memo: Option<String>,
    /// Timestamp when the transfer was submitted
    pub timestamp: u64,
}

/// Result of a nanopayment batch settlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NanopaymentBatchResult {
    /// Unique batch identifier
    pub batch_id: String,
    /// Number of entries that were netted
    pub entries_count: usize,
    /// Sum of all individual transfer amounts
    pub total_amount: u128,
    /// Netted transfers (from, to, net_amount) — the minimal settlement set
    pub net_transfers: Vec<(Address, Address, u128)>,
    /// Timestamp when the batch was settled
    pub settled_at: u64,
}

/// Accumulates micro-transfers and settles them in batches, following the
/// Circle USDC Nanopayments pattern for gasless micro-transfers.
///
/// Opposing flows between the same pair of addresses are netted so only the
/// net difference is settled on-chain, dramatically reducing the number of
/// settlement transactions.
pub struct NanopaymentBatcher {
    /// Pending micro-transfers
    pending: parking_lot::RwLock<Vec<NanopaymentEntry>>,
    /// Minimum batch size before auto-settlement
    min_batch_size: usize,
    /// Maximum delay before forced settlement (seconds)
    max_delay_seconds: u64,
    /// Last batch timestamp
    last_batch_at: parking_lot::RwLock<u64>,
    /// Total batches settled
    total_batched: parking_lot::Mutex<u64>,
    /// Minimum transfer amount (e.g., 1 unit = 0.000000000000000001 TNZO)
    min_amount: u128,
}

impl NanopaymentBatcher {
    /// Create a new batcher with the given thresholds.
    pub fn new(min_batch_size: usize, max_delay_seconds: u64, min_amount: u128) -> Self {
        let now = Timestamp::now().as_millis() as u64 / 1000;
        Self {
            pending: parking_lot::RwLock::new(Vec::new()),
            min_batch_size,
            max_delay_seconds,
            last_batch_at: parking_lot::RwLock::new(now),
            total_batched: parking_lot::Mutex::new(0),
            min_amount,
        }
    }

    /// Create a batcher with sensible defaults: batch at 100 entries or 60 seconds,
    /// minimum transfer of 1 unit.
    pub fn with_defaults() -> Self {
        Self::new(100, 60, 1)
    }

    /// Submit a nanopayment. If the pending queue reaches `min_batch_size`,
    /// the batch is flushed automatically and the result is returned.
    pub fn submit(
        &self,
        from: Address,
        to: Address,
        amount: u128,
        memo: Option<String>,
    ) -> Result<Option<NanopaymentBatchResult>> {
        if amount < self.min_amount {
            return Err(SettlementError::InvalidAmount(format!(
                "Nanopayment amount {} is below minimum {}",
                amount, self.min_amount
            )));
        }
        if from == to {
            return Err(SettlementError::InvalidAmount(
                "Sender and recipient must be different".to_string(),
            ));
        }

        let now = Timestamp::now().as_millis() as u64 / 1000;
        let entry = NanopaymentEntry {
            from,
            to,
            amount,
            memo,
            timestamp: now,
        };

        let should_flush;
        {
            let mut pending = self.pending.write();
            pending.push(entry);
            should_flush = pending.len() >= self.min_batch_size;
        }

        if should_flush {
            return self.flush().map(Some);
        }

        // Check time-based flush
        let last = *self.last_batch_at.read();
        if now.saturating_sub(last) >= self.max_delay_seconds {
            let pending_len = self.pending.read().len();
            if pending_len > 0 {
                return self.flush().map(Some);
            }
        }

        Ok(None)
    }

    /// Flush all pending entries: net opposing flows and produce a minimal
    /// settlement set.
    pub fn flush(&self) -> Result<NanopaymentBatchResult> {
        let entries = {
            let mut pending = self.pending.write();
            std::mem::take(&mut *pending)
        };

        if entries.is_empty() {
            return Err(SettlementError::InvalidAmount(
                "No pending nanopayments to flush".to_string(),
            ));
        }

        let entries_count = entries.len();
        let total_amount: u128 = entries.iter().map(|e| e.amount).sum();
        let net_transfers = Self::netting(&entries);

        let now = Timestamp::now().as_millis() as u64 / 1000;
        *self.last_batch_at.write() = now;
        *self.total_batched.lock() += 1;

        let batch_id = uuid::Uuid::new_v4().to_string();

        info!(
            "Nanopayment batch {}: {} entries netted to {} transfers, total_amount={}",
            batch_id,
            entries_count,
            net_transfers.len(),
            total_amount,
        );

        Ok(NanopaymentBatchResult {
            batch_id,
            entries_count,
            total_amount,
            net_transfers,
            settled_at: now,
        })
    }

    /// Net opposing payment flows to produce the minimal settlement set.
    ///
    /// If A sends 100 to B and B sends 40 to A, only A->B 60 is settled.
    /// All flows between the same (ordered) pair are aggregated first, then
    /// opposing directions are netted.
    pub fn netting(entries: &[NanopaymentEntry]) -> Vec<(Address, Address, u128)> {
        use std::collections::HashMap;

        // Aggregate flows: (from, to) -> total_amount
        let mut flows: HashMap<(Address, Address), u128> = HashMap::new();
        for entry in entries {
            *flows.entry((entry.from, entry.to)).or_insert(0) += entry.amount;
        }

        // Net opposing flows
        let mut netted: HashMap<(Address, Address), u128> = HashMap::new();
        let mut processed: HashSet<(Address, Address)> = HashSet::new();

        for (&(a, b), &amount_ab) in &flows {
            if processed.contains(&(a, b)) || processed.contains(&(b, a)) {
                continue;
            }
            processed.insert((a, b));
            processed.insert((b, a));

            let amount_ba = flows.get(&(b, a)).copied().unwrap_or(0);

            if amount_ab > amount_ba {
                let net = amount_ab - amount_ba;
                if net > 0 {
                    netted.insert((a, b), net);
                }
            } else if amount_ba > amount_ab {
                let net = amount_ba - amount_ab;
                if net > 0 {
                    netted.insert((b, a), net);
                }
            }
            // If equal, they cancel out completely — no settlement needed
        }

        netted.into_iter().map(|((a, b), amt)| (a, b, amt)).collect()
    }

    /// Number of pending (unflushed) entries.
    pub fn pending_count(&self) -> usize {
        self.pending.read().len()
    }

    /// Total number of batches settled since creation.
    pub fn total_batches(&self) -> u64 {
        *self.total_batched.lock()
    }
}

impl std::fmt::Debug for NanopaymentBatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NanopaymentBatcher")
            .field("pending_count", &self.pending.read().len())
            .field("min_batch_size", &self.min_batch_size)
            .field("max_delay_seconds", &self.max_delay_seconds)
            .field("total_batched", &*self.total_batched.lock())
            .field("min_amount", &self.min_amount)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::keys::{KeyPair, KeyType};
    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

    /// Helper: generate an Ed25519 keypair, return (Address, KeyPair)
    fn make_channel_keypair() -> (Address, KeyPair) {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pk_bytes = keypair.public_key().as_bytes();
        let mut addr_bytes = [0u8; 32];
        let len = pk_bytes.len().min(32);
        addr_bytes[..len].copy_from_slice(&pk_bytes[..len]);
        (Address::new(addr_bytes), keypair)
    }

    #[test]
    fn test_channel_opening() {
        let manager = ChannelManager::new();
        let payer = Address::new([1u8; 32]);
        let payee = Address::new([2u8; 32]);
        let asset_id = AssetId::tnzo();

        // Set payer balance
        manager.set_balance(&payer, &asset_id, 10000);

        let expires_at = Timestamp::now().as_millis() + 86400000; // 24 hours
        let channel = manager
            .open_channel(payer, payee, 5000, asset_id.clone(), Timestamp::new(expires_at))
            .unwrap();

        assert_eq!(channel.deposit, 5000);
        assert_eq!(channel.spent, 0);
        assert_eq!(channel.status, ChannelStatus::Open);

        // Verify payer balance was deducted
        assert_eq!(manager.get_balance(&payer, &asset_id), 5000);
    }

    #[test]
    fn test_channel_update() {
        // Phase D hardened the channel-update path so that the signature
        // must be a real Ed25519 signature by the channel's payer over the
        // canonical state encoding (`nonce || payer_balance ||
        // payee_balance`). Use `make_channel_keypair` to derive a payer
        // whose `Address` matches the public-key bytes the verifier
        // expects.
        let (payer, payer_keypair) = make_channel_keypair();
        let payee = Address::new([2u8; 32]);
        let asset_id = AssetId::tnzo();

        let manager = ChannelManager::new();
        manager.set_balance(&payer, &asset_id, 10000);

        let expires_at = Timestamp::now().as_millis() + 86400000;
        let channel = manager
            .open_channel(payer, payee, 5000, asset_id, Timestamp::new(expires_at))
            .unwrap();

        // Build the canonical message for the *next* state (matches the
        // arithmetic inside `update_channel`: spent=1000 → payer=4000,
        // payee=1000) and sign it with the payer's key.
        let next_state = channel.state.next(4000, 1000);
        let message = next_state.canonical_message();
        let signer = Ed25519SignerImpl::new(payer_keypair).unwrap();
        let crypto_sig = signer.sign(&message).unwrap();

        let state = manager
            .update_channel(&channel.channel_id, 1000, crypto_sig.as_bytes().to_vec())
            .unwrap();

        assert_eq!(state.payee_balance, 1000);
        assert_eq!(state.payer_balance, 4000);
    }

    #[test]
    fn test_channel_update_rejects_bogus_signature() {
        // Stub bytes used to pass under the legacy non-empty check.
        // After Phase D they must fail with `InvalidSignature` because
        // they do not verify against the payer's Ed25519 key.
        let (payer, _payer_keypair) = make_channel_keypair();
        let payee = Address::new([2u8; 32]);
        let asset_id = AssetId::tnzo();

        let manager = ChannelManager::new();
        manager.set_balance(&payer, &asset_id, 10000);

        let expires_at = Timestamp::now().as_millis() + 86400000;
        let channel = manager
            .open_channel(payer, payee, 5000, asset_id, Timestamp::new(expires_at))
            .unwrap();

        let bogus = vec![0xAA; 64]; // 64 bytes = Ed25519 sig length, but garbage
        let err = manager
            .update_channel(&channel.channel_id, 1000, bogus)
            .unwrap_err();
        assert!(matches!(err, SettlementError::InvalidSignature(_)));
    }

    #[test]
    fn test_channel_state_real_signature_verification() {
        let (payer_addr, payer_keypair) = make_channel_keypair();

        // Create a channel state
        let state = ChannelState::new(5000, 0);
        let next_state = state.next(4000, 1000);

        // Sign the canonical message with the payer's key
        let message = next_state.canonical_message();
        let signer = Ed25519SignerImpl::new(payer_keypair).unwrap();
        let crypto_sig = signer.sign(&message).unwrap();

        let mut signed_state = next_state;
        signed_state.sign(crypto_sig.as_bytes().to_vec());

        // Verify with the correct key — should pass
        assert!(
            signed_state.verify_signature_with_key(&payer_addr),
            "Valid signature should verify"
        );

        // Verify with a wrong key — should fail
        let wrong_addr = Address::new([0xFFu8; 32]);
        assert!(
            !signed_state.verify_signature_with_key(&wrong_addr),
            "Wrong key should not verify"
        );
    }

    #[test]
    fn test_channel_state_empty_signature_fails() {
        let state = ChannelState::new(5000, 0);
        let payer = Address::new([1u8; 32]);

        assert!(!state.verify_signature(), "Empty signature should fail basic check");
        assert!(!state.verify_signature_with_key(&payer), "Empty signature should fail crypto check");
    }

    // -----------------------------------------------------------------------
    // NanopaymentBatcher tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_nanopayment_netting_basic() {
        let a = Address::new([1u8; 32]);
        let b = Address::new([2u8; 32]);

        let entries = vec![
            NanopaymentEntry { from: a, to: b, amount: 100, memo: None, timestamp: 1 },
            NanopaymentEntry { from: b, to: a, amount: 40, memo: None, timestamp: 2 },
        ];

        let net = NanopaymentBatcher::netting(&entries);
        assert_eq!(net.len(), 1);
        let (from, to, amt) = &net[0];
        assert_eq!(*from, a);
        assert_eq!(*to, b);
        assert_eq!(*amt, 60);
    }

    #[test]
    fn test_nanopayment_netting_cancel_out() {
        let a = Address::new([1u8; 32]);
        let b = Address::new([2u8; 32]);

        let entries = vec![
            NanopaymentEntry { from: a, to: b, amount: 50, memo: None, timestamp: 1 },
            NanopaymentEntry { from: b, to: a, amount: 50, memo: None, timestamp: 2 },
        ];

        let net = NanopaymentBatcher::netting(&entries);
        assert!(net.is_empty(), "Equal opposing flows should cancel out");
    }

    #[test]
    fn test_nanopayment_netting_multiple_pairs() {
        let a = Address::new([1u8; 32]);
        let b = Address::new([2u8; 32]);
        let c = Address::new([3u8; 32]);

        let entries = vec![
            NanopaymentEntry { from: a, to: b, amount: 100, memo: None, timestamp: 1 },
            NanopaymentEntry { from: a, to: c, amount: 200, memo: None, timestamp: 2 },
            NanopaymentEntry { from: b, to: a, amount: 30, memo: None, timestamp: 3 },
        ];

        let net = NanopaymentBatcher::netting(&entries);
        assert_eq!(net.len(), 2);

        // Find the A->B and A->C transfers (order not guaranteed)
        let ab = net.iter().find(|(f, t, _)| *f == a && *t == b);
        let ac = net.iter().find(|(f, t, _)| *f == a && *t == c);

        assert_eq!(ab.unwrap().2, 70); // 100 - 30
        assert_eq!(ac.unwrap().2, 200);
    }

    #[test]
    fn test_nanopayment_submit_and_flush() {
        let batcher = NanopaymentBatcher::new(10, 3600, 1);
        let a = Address::new([1u8; 32]);
        let b = Address::new([2u8; 32]);

        for _ in 0..5 {
            let result = batcher.submit(a, b, 10, None).unwrap();
            assert!(result.is_none(), "Should not auto-flush below threshold");
        }
        assert_eq!(batcher.pending_count(), 5);

        let batch = batcher.flush().unwrap();
        assert_eq!(batch.entries_count, 5);
        assert_eq!(batch.total_amount, 50);
        assert_eq!(batch.net_transfers.len(), 1);
        assert_eq!(batch.net_transfers[0].2, 50);
        assert_eq!(batcher.pending_count(), 0);
        assert_eq!(batcher.total_batches(), 1);
    }

    #[test]
    fn test_nanopayment_auto_flush_on_threshold() {
        let batcher = NanopaymentBatcher::new(3, 3600, 1);
        let a = Address::new([1u8; 32]);
        let b = Address::new([2u8; 32]);

        batcher.submit(a, b, 10, None).unwrap();
        batcher.submit(a, b, 20, None).unwrap();

        // Third submit should trigger auto-flush
        let result = batcher.submit(a, b, 30, None).unwrap();
        assert!(result.is_some());
        let batch = result.unwrap();
        assert_eq!(batch.entries_count, 3);
        assert_eq!(batch.total_amount, 60);
        assert_eq!(batcher.pending_count(), 0);
    }

    #[test]
    fn test_nanopayment_rejects_below_minimum() {
        let batcher = NanopaymentBatcher::new(10, 60, 100);
        let a = Address::new([1u8; 32]);
        let b = Address::new([2u8; 32]);

        let result = batcher.submit(a, b, 50, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_nanopayment_rejects_self_transfer() {
        let batcher = NanopaymentBatcher::new(10, 60, 1);
        let a = Address::new([1u8; 32]);

        let result = batcher.submit(a, a, 100, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_nanopayment_flush_empty_errors() {
        let batcher = NanopaymentBatcher::with_defaults();
        let result = batcher.flush();
        assert!(result.is_err());
    }
}
