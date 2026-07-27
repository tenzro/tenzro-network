//! TNZO token management
//!
//! This module implements the TNZO governance/utility token with 18-decimal precision.

use crate::error::{Result, TokenError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tenzro_types::primitives::Address;
use tenzro_types::asset::AssetId;
use tenzro_storage::kv::{KvStore, CF_ACCOUNTS};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Decimals for TNZO token (18 decimal places)
pub const TNZO_DECIMALS: u8 = 18;

/// Default circuit breaker: max 10% of total supply per window
const CIRCUIT_BREAKER_MAX_OUTFLOW_PERCENT: u128 = 10;
/// Default circuit breaker window: 1 hour (3600 seconds)
const CIRCUIT_BREAKER_WINDOW_SECS: u64 = 3600;
/// Default cooldown after trip: 30 minutes (1800 seconds)
const CIRCUIT_BREAKER_COOLDOWN_SECS: u64 = 1800;

/// One TNZO token in smallest unit (10^18)
pub const ONE_TNZO: u128 = 1_000_000_000_000_000_000;

/// Maximum supply of TNZO (1 billion tokens)
pub const MAX_SUPPLY: u128 = 1_000_000_000 * ONE_TNZO;

// ---------------------------------------------------------------------------
// Circuit Breaker — ERC-7265 pattern for outflow rate limiting
// ---------------------------------------------------------------------------

/// Circuit breaker for monitoring and limiting token outflow rates.
///
/// Implements the ERC-7265 pattern: tracks cumulative outflow within a sliding
/// time window and automatically trips (pauses transfers) when the outflow
/// exceeds a configurable threshold. After a cooldown period, the breaker
/// automatically resets and transfers resume.
pub struct CircuitBreaker {
    /// Maximum outflow per window (in smallest TNZO units)
    max_outflow_per_window: u128,
    /// Window duration in seconds
    window_seconds: u64,
    /// Current window outflow
    current_outflow: parking_lot::RwLock<u128>,
    /// Window start timestamp (Unix seconds)
    window_start: parking_lot::RwLock<u64>,
    /// Whether circuit breaker is tripped
    tripped: parking_lot::RwLock<bool>,
    /// Cooldown period after trip (seconds)
    cooldown_seconds: u64,
    /// Trip timestamp (Unix seconds)
    tripped_at: parking_lot::RwLock<Option<u64>>,
}

impl CircuitBreaker {
    /// Creates a new circuit breaker with the given parameters.
    ///
    /// # Arguments
    /// * `max_outflow_per_window` - Maximum cumulative outflow before tripping
    /// * `window_seconds` - Duration of the monitoring window
    /// * `cooldown_seconds` - How long the breaker stays tripped before auto-reset
    pub fn new(max_outflow_per_window: u128, window_seconds: u64, cooldown_seconds: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            max_outflow_per_window,
            window_seconds,
            current_outflow: parking_lot::RwLock::new(0),
            window_start: parking_lot::RwLock::new(now),
            tripped: parking_lot::RwLock::new(false),
            cooldown_seconds,
            tripped_at: parking_lot::RwLock::new(None),
        }
    }

    /// Creates a default circuit breaker: 10% of MAX_SUPPLY per 1-hour window,
    /// 30-minute cooldown.
    pub fn default_for_tnzo() -> Self {
        let max_outflow = MAX_SUPPLY / 100 * CIRCUIT_BREAKER_MAX_OUTFLOW_PERCENT;
        Self::new(max_outflow, CIRCUIT_BREAKER_WINDOW_SECS, CIRCUIT_BREAKER_COOLDOWN_SECS)
    }

    /// Returns the current Unix timestamp in seconds.
    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Checks whether the circuit breaker is currently tripped.
    /// Also handles auto-reset after the cooldown period.
    pub fn is_tripped(&self) -> bool {
        let tripped = *self.tripped.read();
        if !tripped {
            return false;
        }

        // Check if cooldown has elapsed
        if let Some(trip_time) = *self.tripped_at.read() {
            let now = Self::now_secs();
            if now >= trip_time + self.cooldown_seconds {
                // Auto-reset after cooldown
                self.reset_internal();
                return false;
            }
        }

        true
    }

    /// Checks whether adding `amount` to the current window outflow would
    /// exceed the maximum. Returns Ok(()) if the transfer is allowed, or
    /// an error if the circuit breaker would trip.
    ///
    /// This method also handles window rotation: if the current window has
    /// expired, it starts a new window before checking.
    pub fn check_outflow(&self, amount: u128) -> Result<()> {
        if self.is_tripped() {
            let remaining = self.tripped_at.read()
                .map(|t| {
                    let elapsed = Self::now_secs().saturating_sub(t);
                    self.cooldown_seconds.saturating_sub(elapsed)
                })
                .unwrap_or(self.cooldown_seconds);

            return Err(TokenError::Unauthorized {
                reason: format!(
                    "Circuit breaker tripped: outflow limit exceeded. \
                     Auto-reset in {} seconds.",
                    remaining
                ),
            });
        }

        let now = Self::now_secs();
        let mut window_start = self.window_start.write();
        let mut current_outflow = self.current_outflow.write();

        // Rotate window if expired
        if now >= *window_start + self.window_seconds {
            *window_start = now;
            *current_outflow = 0;
        }

        // Check if the new outflow would exceed the limit
        let new_outflow = current_outflow
            .checked_add(amount)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "circuit breaker outflow check".to_string(),
            })?;

        if new_outflow > self.max_outflow_per_window {
            // Trip the breaker
            drop(window_start);
            drop(current_outflow);
            self.trip();
            return Err(TokenError::Unauthorized {
                reason: format!(
                    "Circuit breaker tripped: transfer of {} would exceed \
                     window limit of {} ({} already used). \
                     Cooldown: {} seconds.",
                    amount,
                    self.max_outflow_per_window,
                    new_outflow - amount,
                    self.cooldown_seconds,
                ),
            });
        }

        Ok(())
    }

    /// Records a successful outflow of `amount` in the current window.
    pub fn record_outflow(&self, amount: u128) {
        let mut current_outflow = self.current_outflow.write();
        *current_outflow = current_outflow.saturating_add(amount);
    }

    /// Manually resets the circuit breaker (for authorized callers).
    pub fn reset(&self) {
        self.reset_internal();
        info!("Circuit breaker manually reset");
    }

    /// Internal reset helper.
    fn reset_internal(&self) {
        *self.tripped.write() = false;
        *self.tripped_at.write() = None;
        *self.current_outflow.write() = 0;
        *self.window_start.write() = Self::now_secs();
    }

    /// Trips the circuit breaker.
    fn trip(&self) {
        *self.tripped.write() = true;
        *self.tripped_at.write() = Some(Self::now_secs());
        warn!(
            "Circuit breaker TRIPPED: outflow limit of {} exceeded in {}-second window. \
             Transfers paused for {} seconds.",
            self.max_outflow_per_window,
            self.window_seconds,
            self.cooldown_seconds,
        );
    }

    /// Returns the current outflow in the active window.
    pub fn current_outflow(&self) -> u128 {
        *self.current_outflow.read()
    }

    /// Returns the maximum outflow per window.
    pub fn max_outflow(&self) -> u128 {
        self.max_outflow_per_window
    }
}

impl std::fmt::Debug for CircuitBreaker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircuitBreaker")
            .field("max_outflow_per_window", &self.max_outflow_per_window)
            .field("window_seconds", &self.window_seconds)
            .field("cooldown_seconds", &self.cooldown_seconds)
            .field("tripped", &*self.tripped.read())
            .field("current_outflow", &*self.current_outflow.read())
            .finish()
    }
}

/// Storage backend trait for TNZO token balances
pub trait StorageBackend: Send + Sync {
    /// Gets the balance of an address
    fn get_balance(&self, address: &Address) -> Result<Option<u128>>;

    /// Sets the balance of an address
    fn set_balance(&self, address: &Address, balance: u128) -> Result<()>;

    /// Gets the total supply
    fn get_total_supply(&self) -> Result<u128>;

    /// Sets the total supply
    fn set_total_supply(&self, supply: u128) -> Result<()>;
}

/// RocksDB-backed storage backend
pub struct RocksDbBackend {
    store: Arc<dyn KvStore>,
}

impl RocksDbBackend {
    /// Creates a new RocksDB backend
    pub fn new(store: Arc<dyn KvStore>) -> Self {
        Self { store }
    }

    /// Creates the key for a balance entry
    fn balance_key(address: &Address) -> Vec<u8> {
        let mut key = b"balance:".to_vec();
        key.extend_from_slice(address.as_bytes());
        key
    }

    /// Key for total supply
    fn supply_key() -> Vec<u8> {
        b"total_supply".to_vec()
    }
}

impl StorageBackend for RocksDbBackend {
    fn get_balance(&self, address: &Address) -> Result<Option<u128>> {
        let key = Self::balance_key(address);
        match self.store.get(CF_ACCOUNTS, &key)? {
            Some(bytes) => {
                if bytes.len() == 16 {
                    let array: [u8; 16] = bytes.try_into().unwrap();
                    Ok(Some(u128::from_le_bytes(array)))
                } else {
                    warn!("Invalid balance bytes length for {}: {}", address, bytes.len());
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    fn set_balance(&self, address: &Address, balance: u128) -> Result<()> {
        let key = Self::balance_key(address);
        let value = balance.to_le_bytes();
        self.store.put(CF_ACCOUNTS, &key, &value)?;
        Ok(())
    }

    fn get_total_supply(&self) -> Result<u128> {
        let key = Self::supply_key();
        match self.store.get(CF_ACCOUNTS, &key)? {
            Some(bytes) => {
                if bytes.len() == 16 {
                    let array: [u8; 16] = bytes.try_into().unwrap();
                    Ok(u128::from_le_bytes(array))
                } else {
                    warn!("Invalid supply bytes length: {}", bytes.len());
                    Ok(0)
                }
            }
            None => Ok(0),
        }
    }

    fn set_total_supply(&self, supply: u128) -> Result<()> {
        let key = Self::supply_key();
        let value = supply.to_le_bytes();
        self.store.put(CF_ACCOUNTS, &key, &value)?;
        Ok(())
    }
}

/// TNZO token manager
///
/// Manages TNZO token balances, transfers, minting, and burning.
/// Uses `u128` for amounts to properly handle 18-decimal precision.
/// Balances are cached in memory and persisted to storage backend.
pub struct TnzoToken {
    /// Asset ID for TNZO token
    pub asset_id: AssetId,
    /// Account balances cache (Address -> Balance)
    balances: DashMap<Address, u128>,
    /// Total supply in circulation
    total_supply: parking_lot::RwLock<u128>,
    /// Total burned amount
    total_burned: parking_lot::RwLock<u128>,
    /// Treasury address (only authorized to mint)
    treasury_address: parking_lot::RwLock<Option<Address>>,
    /// Optional storage backend for persistence
    storage: Option<Arc<dyn StorageBackend>>,
    /// Circuit breaker for outflow monitoring (ERC-7265 pattern)
    circuit_breaker: CircuitBreaker,
}

impl std::fmt::Debug for TnzoToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TnzoToken")
            .field("asset_id", &self.asset_id)
            .field("total_supply", &self.total_supply)
            .field("total_burned", &self.total_burned)
            .field("treasury_address", &self.treasury_address)
            .field("storage", &self.storage.as_ref().map(|_| "Some(...)"))
            .field("circuit_breaker", &self.circuit_breaker)
            .finish()
    }
}

impl TnzoToken {
    /// Creates a new TNZO token instance without storage backend (in-memory only)
    pub fn new() -> Self {
        Self {
            asset_id: AssetId::tnzo(),
            balances: DashMap::new(),
            total_supply: parking_lot::RwLock::new(0),
            total_burned: parking_lot::RwLock::new(0),
            treasury_address: parking_lot::RwLock::new(None),
            storage: None,
            circuit_breaker: CircuitBreaker::default_for_tnzo(),
        }
    }

    /// Creates a new TNZO token instance with storage backend
    pub fn with_storage(storage: Arc<dyn StorageBackend>) -> Result<Self> {
        // Load total supply from storage
        let total_supply = storage.get_total_supply()?;

        Ok(Self {
            asset_id: AssetId::tnzo(),
            balances: DashMap::new(),
            total_supply: parking_lot::RwLock::new(total_supply),
            total_burned: parking_lot::RwLock::new(0),
            treasury_address: parking_lot::RwLock::new(None),
            storage: Some(storage),
            circuit_breaker: CircuitBreaker::default_for_tnzo(),
        })
    }

    /// Sets the treasury address (only address authorized to mint)
    pub fn set_treasury_address(&self, address: Address) {
        *self.treasury_address.write() = Some(address);
        info!("Treasury address set to: {}", address);
    }

    /// Returns the treasury address, if set
    pub fn treasury_address_ref(&self) -> Option<Address> {
        *self.treasury_address.read()
    }

    /// Returns the balance of an address.
    ///
    /// When a storage backend is configured, reads always go to storage
    /// (CF_ACCOUNTS). The in-memory `balances` map is only used as a fallback
    /// for stand-alone token instances that have no storage attached
    /// (e.g. unit tests). RocksDB has its own block cache underneath, so
    /// re-reading on every call is cheap.
    ///
    /// Why not cache in `self.balances` after a storage read? The VM's
    /// `StateAdapter::commit` writes balance updates directly to CF_ACCOUNTS
    /// (using the same `tnzo_balance_key` encoding) and does NOT invalidate
    /// `TnzoToken::balances`. Caching here would let stale values shadow
    /// post-VM-execution balances — exactly the bug that made
    /// `eth_sendRawTransaction` Transfers appear to land successfully but
    /// not move balances on the read side.
    pub fn balance_of(&self, address: &Address) -> u128 {
        // Storage is the canonical source of truth when configured.
        if let Some(storage) = &self.storage {
            return match storage.get_balance(address) {
                Ok(Some(balance)) => balance,
                Ok(None) => 0,
                Err(e) => {
                    warn!("Failed to load balance from storage: {}", e);
                    0
                }
            };
        }

        // Storage-less mode: rely on the in-memory map (test/dev only).
        self.balances.get(address).map(|v| *v).unwrap_or(0)
    }

    /// Persists a balance to storage if backend exists
    fn persist_balance(&self, address: &Address, balance: u128) -> Result<()> {
        if let Some(storage) = &self.storage {
            storage.set_balance(address, balance)?;
        }
        Ok(())
    }

    /// Persists total supply to storage if backend exists
    fn persist_supply(&self, supply: u128) -> Result<()> {
        if let Some(storage) = &self.storage {
            storage.set_total_supply(supply)?;
        }
        Ok(())
    }

    /// Transfers tokens from one address to another.
    ///
    /// The transfer is subject to the ERC-7265 circuit breaker: if cumulative
    /// outflow within the current window would exceed the configured limit,
    /// the breaker trips and the transfer is rejected.
    ///
    /// # Arguments
    ///
    /// * `from` - Source address
    /// * `to` - Destination address
    /// * `amount` - Amount to transfer (in smallest unit)
    pub fn transfer(&self, from: &Address, to: &Address, amount: u128) -> Result<()> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount("Amount must be greater than zero".to_string()));
        }

        // ERC-7265 circuit breaker check
        self.circuit_breaker.check_outflow(amount)?;

        let from_balance = self.balance_of(from);
        if from_balance < amount {
            return Err(TokenError::InsufficientBalance {
                required: amount,
                available: from_balance,
            });
        }

        // Use checked_sub for sender
        let new_from_balance = from_balance.checked_sub(amount)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "transfer subtraction".to_string(),
            })?;

        // Use checked_add for recipient
        let to_balance = self.balance_of(to);
        let new_to_balance = to_balance.checked_add(amount)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "transfer addition".to_string(),
            })?;

        // Update balances in cache
        self.balances.insert(*from, new_from_balance);
        self.balances.insert(*to, new_to_balance);

        // Persist to storage
        self.persist_balance(from, new_from_balance)?;
        self.persist_balance(to, new_to_balance)?;

        // Record outflow in circuit breaker
        self.circuit_breaker.record_outflow(amount);

        debug!("Transferred {} TNZO from {} to {}", amount, from, to);
        Ok(())
    }

    /// Mints new tokens (only callable by treasury)
    ///
    /// # Arguments
    ///
    /// * `to` - Address to mint tokens to
    /// * `amount` - Amount to mint
    /// * `caller` - Address calling the mint function (must be treasury)
    pub fn mint(&self, to: &Address, amount: u128, caller: &Address) -> Result<()> {
        // Check authorization
        let treasury = self.treasury_address.read();
        if treasury.as_ref() != Some(caller) {
            return Err(TokenError::Unauthorized {
                reason: "Only treasury can mint tokens".to_string(),
            });
        }

        if amount == 0 {
            return Err(TokenError::InvalidAmount("Amount must be greater than zero".to_string()));
        }

        // Check max supply
        let current_supply = *self.total_supply.read();
        let new_supply = current_supply.checked_add(amount)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "mint supply increase".to_string(),
            })?;

        if new_supply > MAX_SUPPLY {
            return Err(TokenError::InvalidAmount(
                format!("Minting would exceed max supply: {} > {}", new_supply, MAX_SUPPLY)
            ));
        }

        // Update balance
        let current_balance = self.balance_of(to);
        let new_balance = current_balance.checked_add(amount)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "mint balance increase".to_string(),
            })?;
        self.balances.insert(*to, new_balance);

        // Update total supply
        *self.total_supply.write() = new_supply;

        // Persist to storage
        self.persist_balance(to, new_balance)?;
        self.persist_supply(new_supply)?;

        info!("Minted {} TNZO to {}", amount, to);
        Ok(())
    }

    /// Burns tokens from an address
    ///
    /// # Arguments
    ///
    /// * `from` - Address to burn tokens from
    /// * `amount` - Amount to burn
    pub fn burn(&self, from: &Address, amount: u128) -> Result<()> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount("Amount must be greater than zero".to_string()));
        }

        let balance = self.balance_of(from);
        if balance < amount {
            return Err(TokenError::InsufficientBalance {
                required: amount,
                available: balance,
            });
        }

        // Use checked_sub for balance
        let new_balance = balance.checked_sub(amount)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "burn balance decrease".to_string(),
            })?;
        self.balances.insert(*from, new_balance);

        // Update total supply with checked_sub
        let mut supply = self.total_supply.write();
        *supply = supply.checked_sub(amount)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "burn supply decrease".to_string(),
            })?;
        let new_supply = *supply;
        drop(supply);

        // Update burned with checked_add
        let mut burned = self.total_burned.write();
        *burned = burned.checked_add(amount)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "burn total increase".to_string(),
            })?;

        // Persist to storage
        self.persist_balance(from, new_balance)?;
        self.persist_supply(new_supply)?;

        info!("Burned {} TNZO from {}", amount, from);
        Ok(())
    }

    /// Books gas fees the executor has already debited from payers.
    ///
    /// The VM subtracts `gas_price * gas_used` from the sender's balance and
    /// credits nobody, so without this call the TNZO leaves circulation
    /// without leaving `total_supply` — the books drift by exactly the gas
    /// collected on every block. This settles that gap:
    ///
    /// * `to_treasury` is credited to `treasury` with **no** mint, because the
    ///   tokens already exist and are already out of the payer's balance.
    /// * `burned` decrements `total_supply` and increments `total_burned`
    ///   without touching any balance, for the same reason.
    ///
    /// The split between the two comes from the fee market's adaptive burn
    /// dial, which is the authoritative basis for the movement.
    pub fn settle_collected_fees(
        &self,
        treasury: &Address,
        to_treasury: u128,
        burned: u128,
    ) -> Result<()> {
        if to_treasury == 0 && burned == 0 {
            return Ok(());
        }

        if to_treasury > 0 {
            let balance = self.balance_of(treasury);
            let new_balance =
                balance
                    .checked_add(to_treasury)
                    .ok_or_else(|| TokenError::ArithmeticOverflow {
                        operation: "fee treasury credit".to_string(),
                    })?;
            self.balances.insert(*treasury, new_balance);
            self.persist_balance(treasury, new_balance)?;
        }

        if burned > 0 {
            let mut supply = self.total_supply.write();
            *supply = supply
                .checked_sub(burned)
                .ok_or_else(|| TokenError::ArithmeticOverflow {
                    operation: "fee burn supply decrease".to_string(),
                })?;
            let new_supply = *supply;
            drop(supply);

            let mut total_burned = self.total_burned.write();
            *total_burned =
                total_burned
                    .checked_add(burned)
                    .ok_or_else(|| TokenError::ArithmeticOverflow {
                        operation: "fee burn total increase".to_string(),
                    })?;
            drop(total_burned);

            self.persist_supply(new_supply)?;
        }

        debug!(
            "Settled collected fees: {} to treasury {}, {} burned",
            to_treasury, treasury, burned
        );
        Ok(())
    }

    /// Returns the total supply of TNZO
    pub fn total_supply(&self) -> u128 {
        *self.total_supply.read()
    }

    /// Returns the circulating supply (total supply - burned)
    pub fn circulating_supply(&self) -> u128 {
        self.total_supply()
    }

    /// Returns the total amount burned
    pub fn total_burned(&self) -> u128 {
        *self.total_burned.read()
    }

    /// Returns token statistics
    pub fn stats(&self) -> TokenStats {
        TokenStats {
            total_supply: self.total_supply(),
            circulating_supply: self.circulating_supply(),
            total_burned: self.total_burned(),
            total_accounts: self.balances.len() as u64,
        }
    }

    /// Returns a reference to the circuit breaker.
    pub fn circuit_breaker(&self) -> &CircuitBreaker {
        &self.circuit_breaker
    }

    /// Returns all balances (for debugging/testing)
    pub fn get_all_balances(&self) -> Vec<(Address, u128)> {
        self.balances
            .iter()
            .map(|entry| (*entry.key(), *entry.value()))
            .collect()
    }
}

impl Default for TnzoToken {
    fn default() -> Self {
        Self::new()
    }
}

/// TNZO token statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStats {
    /// Total supply of TNZO
    pub total_supply: u128,
    /// Circulating supply
    pub circulating_supply: u128,
    /// Total burned
    pub total_burned: u128,
    /// Total number of accounts with balance
    pub total_accounts: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_creation() {
        let token = TnzoToken::new();
        assert_eq!(token.total_supply(), 0);
        assert_eq!(token.total_burned(), 0);
    }

    #[test]
    fn test_transfer() {
        let token = TnzoToken::new();
        let from = Address::new([1u8; 32]);
        let to = Address::new([2u8; 32]);

        // Setup: Give initial balance to 'from'
        token.balances.insert(from, 1000 * ONE_TNZO);

        // Transfer
        token.transfer(&from, &to, 100 * ONE_TNZO).unwrap();

        assert_eq!(token.balance_of(&from), 900 * ONE_TNZO);
        assert_eq!(token.balance_of(&to), 100 * ONE_TNZO);
    }

    #[test]
    fn test_mint() {
        let token = TnzoToken::new();
        let treasury = Address::new([1u8; 32]);
        let recipient = Address::new([2u8; 32]);

        token.set_treasury_address(treasury);
        token.mint(&recipient, 1000 * ONE_TNZO, &treasury).unwrap();

        assert_eq!(token.balance_of(&recipient), 1000 * ONE_TNZO);
        assert_eq!(token.total_supply(), 1000 * ONE_TNZO);
    }

    #[test]
    fn test_burn() {
        let token = TnzoToken::new();
        let address = Address::new([1u8; 32]);

        // Setup: Give initial balance
        token.balances.insert(address, 1000 * ONE_TNZO);
        *token.total_supply.write() = 1000 * ONE_TNZO;

        // Burn
        token.burn(&address, 100 * ONE_TNZO).unwrap();

        assert_eq!(token.balance_of(&address), 900 * ONE_TNZO);
        assert_eq!(token.total_supply(), 900 * ONE_TNZO);
        assert_eq!(token.total_burned(), 100 * ONE_TNZO);
    }

    // -----------------------------------------------------------------------
    // Circuit breaker tests (ERC-7265)
    // -----------------------------------------------------------------------

    #[test]
    fn test_circuit_breaker_allows_normal_transfer() {
        // Small max to make testing easy: 1000 TNZO window
        let cb = CircuitBreaker::new(1000 * ONE_TNZO, 3600, 1800);
        assert!(!cb.is_tripped());
        assert!(cb.check_outflow(500 * ONE_TNZO).is_ok());
        cb.record_outflow(500 * ONE_TNZO);
        assert_eq!(cb.current_outflow(), 500 * ONE_TNZO);
    }

    #[test]
    fn test_circuit_breaker_trips_on_excess() {
        let cb = CircuitBreaker::new(1000 * ONE_TNZO, 3600, 1800);
        cb.record_outflow(900 * ONE_TNZO);
        // This should trip the breaker
        let result = cb.check_outflow(200 * ONE_TNZO);
        assert!(result.is_err());
        assert!(cb.is_tripped());
    }

    #[test]
    fn test_circuit_breaker_blocks_after_trip() {
        let cb = CircuitBreaker::new(1000 * ONE_TNZO, 3600, 1800);
        cb.record_outflow(900 * ONE_TNZO);
        let _ = cb.check_outflow(200 * ONE_TNZO); // trips
        assert!(cb.is_tripped());

        // Even small transfers should be blocked
        let result = cb.check_outflow(1);
        assert!(result.is_err());
    }

    #[test]
    fn test_circuit_breaker_manual_reset() {
        let cb = CircuitBreaker::new(1000 * ONE_TNZO, 3600, 1800);
        cb.record_outflow(900 * ONE_TNZO);
        let _ = cb.check_outflow(200 * ONE_TNZO); // trips
        assert!(cb.is_tripped());

        cb.reset();
        assert!(!cb.is_tripped());
        assert_eq!(cb.current_outflow(), 0);
        assert!(cb.check_outflow(500 * ONE_TNZO).is_ok());
    }

    #[test]
    fn test_circuit_breaker_wired_into_transfer() {
        let token = TnzoToken::new();
        let from = Address::new([1u8; 32]);
        let to = Address::new([2u8; 32]);

        // Give a huge balance
        token.balances.insert(from, MAX_SUPPLY);
        *token.total_supply.write() = MAX_SUPPLY;

        // The default breaker allows 10% of MAX_SUPPLY per window
        let limit = MAX_SUPPLY / 100 * CIRCUIT_BREAKER_MAX_OUTFLOW_PERCENT;

        // Transfer just under the limit should succeed
        let small_amount = limit / 2;
        assert!(token.transfer(&from, &to, small_amount).is_ok());

        // Another transfer that exceeds the remaining window should fail
        let over_amount = limit;
        let result = token.transfer(&from, &to, over_amount);
        assert!(result.is_err());
        assert!(token.circuit_breaker().is_tripped());

        // Reset and transfers should work again
        token.circuit_breaker().reset();
        assert!(token.transfer(&from, &to, small_amount).is_ok());
    }

    #[test]
    fn test_treasury_address_ref() {
        let token = TnzoToken::new();
        assert!(token.treasury_address_ref().is_none());

        let treasury = Address::new([0xFF; 32]);
        token.set_treasury_address(treasury);
        assert_eq!(token.treasury_address_ref(), Some(treasury));
    }

    /// Regression test for the bug where `eth_sendRawTransaction` Transfer
    /// txs landed in CF_ACCOUNTS via `StateAdapter::commit` but `balance_of`
    /// returned a stale 0 because of an in-memory cache shadowing fresh
    /// storage reads.
    ///
    /// Scenario: storage backend mutated externally (mimicking the VM's
    /// direct CF_ACCOUNTS write). `balance_of` must reflect the new value
    /// on the next call — no stale cache.
    #[test]
    fn test_balance_of_reflects_external_storage_writes() {
        use std::sync::Mutex as StdMutex;

        struct MockBackend {
            balances: StdMutex<std::collections::HashMap<Address, u128>>,
            supply: StdMutex<u128>,
        }
        impl StorageBackend for MockBackend {
            fn get_balance(&self, address: &Address) -> Result<Option<u128>> {
                Ok(self.balances.lock().unwrap().get(address).copied())
            }
            fn set_balance(&self, address: &Address, balance: u128) -> Result<()> {
                self.balances.lock().unwrap().insert(*address, balance);
                Ok(())
            }
            fn get_total_supply(&self) -> Result<u128> {
                Ok(*self.supply.lock().unwrap())
            }
            fn set_total_supply(&self, s: u128) -> Result<()> {
                *self.supply.lock().unwrap() = s;
                Ok(())
            }
        }

        let backend = Arc::new(MockBackend {
            balances: StdMutex::new(Default::default()),
            supply: StdMutex::new(0),
        });

        let token = TnzoToken::with_storage(backend.clone() as Arc<dyn StorageBackend>).unwrap();
        let recipient = Address::new([0xAB; 32]);

        // First read: balance is zero (cache miss → storage miss).
        assert_eq!(token.balance_of(&recipient), 0);

        // External writer (the VM) mutates storage directly, bypassing
        // TnzoToken::transfer. Pre-fix, balance_of would still return 0.
        backend.balances.lock().unwrap().insert(recipient, 5_000 * ONE_TNZO);

        // Post-fix: read goes back to storage, sees the new value.
        assert_eq!(token.balance_of(&recipient), 5_000 * ONE_TNZO);

        // Subsequent external mutation must also be visible.
        backend.balances.lock().unwrap().insert(recipient, 1_000 * ONE_TNZO);
        assert_eq!(token.balance_of(&recipient), 1_000 * ONE_TNZO);
    }
}
