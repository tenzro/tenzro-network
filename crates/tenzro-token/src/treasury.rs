//! Network treasury management
//!
//! This module implements the network treasury that accumulates fees from settlements,
//! transactions, and bridge operations in multiple assets (stablecoins + crypto).
//!
//! It holds no withdrawal authority. The treasury is the keyless
//! `network_treasury_address` in consensus state; only an enacted governance
//! proposal moves its funds.

use crate::error::{Result, TokenError};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tenzro_storage::kv::{CF_METADATA, KvStore};
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::Address;
use tracing::{debug, info, warn};

/// Fee distribution configuration
///
/// Defines how network fees are split between treasury, burn, and staker rewards.
/// All values are in basis points (bps) and must sum to 10000 (100%).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeDistributionConfig {
    /// Percentage of fees going to treasury (basis points)
    pub treasury_share_bps: u32,
    /// Percentage of fees to burn (basis points)
    pub burn_share_bps: u32,
    /// Percentage of fees going to stakers (basis points)
    pub staker_share_bps: u32,
}

impl Default for FeeDistributionConfig {
    fn default() -> Self {
        Self {
            treasury_share_bps: 4000, // 40%
            burn_share_bps: 3000,     // 30%
            staker_share_bps: 3000,   // 30%
        }
    }
}

impl FeeDistributionConfig {
    /// Validates that the configuration is correct
    pub fn validate(&self) -> Result<()> {
        let total = self
            .treasury_share_bps
            .saturating_add(self.burn_share_bps)
            .saturating_add(self.staker_share_bps);

        if total != 10000 {
            return Err(TokenError::InvalidConfig(format!(
                "Fee distribution must sum to 10000 bps, got {}",
                total
            )));
        }

        Ok(())
    }

    /// Calculates the distribution amounts for a given fee
    pub fn calculate_distribution(&self, total_fee: u128) -> FeeDistribution {
        let treasury_amount = total_fee * (self.treasury_share_bps as u128) / 10000;
        let burn_amount = total_fee * (self.burn_share_bps as u128) / 10000;
        let staker_amount = total_fee * (self.staker_share_bps as u128) / 10000;

        FeeDistribution {
            treasury_amount,
            burn_amount,
            staker_amount,
        }
    }
}

/// Calculated fee distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeDistribution {
    /// Amount going to treasury
    pub treasury_amount: u128,
    /// Amount to burn
    pub burn_amount: u128,
    /// Amount for stakers
    pub staker_amount: u128,
}

/// RocksDB-backed storage for treasury state
pub struct TreasuryStorageBackend {
    store: Arc<dyn KvStore>,
}

impl TreasuryStorageBackend {
    /// Creates a new treasury storage backend
    pub fn new(store: Arc<dyn KvStore>) -> Self {
        Self { store }
    }

    fn balance_key(asset_id: &AssetId) -> Vec<u8> {
        let mut key = b"treasury:balance:".to_vec();
        key.extend_from_slice(asset_id.as_str().as_bytes());
        key
    }

    fn collected_key(asset_id: &AssetId) -> Vec<u8> {
        let mut key = b"treasury:collected:".to_vec();
        key.extend_from_slice(asset_id.as_str().as_bytes());
        key
    }

    fn distributed_key(asset_id: &AssetId) -> Vec<u8> {
        let mut key = b"treasury:distributed:".to_vec();
        key.extend_from_slice(asset_id.as_str().as_bytes());
        key
    }

    fn get_u128(&self, key: &[u8]) -> Result<u128> {
        match self.store.get(CF_METADATA, key)? {
            Some(bytes) if bytes.len() == 16 => {
                let array: [u8; 16] = bytes.try_into().unwrap();
                Ok(u128::from_le_bytes(array))
            }
            Some(bytes) => {
                warn!("Invalid treasury bytes length: {}", bytes.len());
                Ok(0)
            }
            None => Ok(0),
        }
    }

    fn set_u128(&self, key: &[u8], value: u128) -> Result<()> {
        self.store.put(CF_METADATA, key, &value.to_le_bytes())?;
        Ok(())
    }

    /// Persists a treasury balance for an asset
    pub fn persist_balance(&self, asset_id: &AssetId, balance: u128) -> Result<()> {
        self.set_u128(&Self::balance_key(asset_id), balance)
    }

    /// Persists total collected for an asset
    pub fn persist_collected(&self, asset_id: &AssetId, collected: u128) -> Result<()> {
        self.set_u128(&Self::collected_key(asset_id), collected)
    }

    /// Persists total distributed for an asset
    pub fn persist_distributed(&self, asset_id: &AssetId, distributed: u128) -> Result<()> {
        self.set_u128(&Self::distributed_key(asset_id), distributed)
    }

    /// Loads a treasury balance for an asset
    pub fn load_balance(&self, asset_id: &AssetId) -> Result<u128> {
        self.get_u128(&Self::balance_key(asset_id))
    }

    /// Loads total collected for an asset
    pub fn load_collected(&self, asset_id: &AssetId) -> Result<u128> {
        self.get_u128(&Self::collected_key(asset_id))
    }

    /// Loads total distributed for an asset
    pub fn load_distributed(&self, asset_id: &AssetId) -> Result<u128> {
        self.get_u128(&Self::distributed_key(asset_id))
    }
}

/// Network treasury
///
/// Manages multi-asset treasury accumulating network fees and supporting
/// treasury-based operations.
pub struct NetworkTreasury {
    /// Treasury address
    pub treasury_address: Address,
    /// Multi-asset balances (AssetId -> Balance)
    balances: RwLock<HashMap<AssetId, u128>>,
    /// Total fees collected per asset
    total_fees_collected: RwLock<HashMap<AssetId, u128>>,
    /// Total distributed per asset
    total_distributed: RwLock<HashMap<AssetId, u128>>,
    /// Fee distribution configuration
    distribution_config: RwLock<FeeDistributionConfig>,
    /// Optional storage backend for persistence
    storage: Option<Arc<TreasuryStorageBackend>>,
}

impl std::fmt::Debug for NetworkTreasury {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkTreasury")
            .field("treasury_address", &self.treasury_address)
            .field("storage", &self.storage.as_ref().map(|_| "Some(...)"))
            .finish()
    }
}

impl NetworkTreasury {
    /// Creates a new network treasury (in-memory only)
    pub fn new(treasury_address: Address) -> Self {
        Self {
            treasury_address,
            balances: RwLock::new(HashMap::new()),
            total_fees_collected: RwLock::new(HashMap::new()),
            total_distributed: RwLock::new(HashMap::new()),
            distribution_config: RwLock::new(FeeDistributionConfig::default()),
            storage: None,
        }
    }

    /// Creates a new network treasury with persistent storage
    pub fn with_storage(treasury_address: Address, storage: Arc<TreasuryStorageBackend>) -> Self {
        Self {
            treasury_address,
            balances: RwLock::new(HashMap::new()),
            total_fees_collected: RwLock::new(HashMap::new()),
            total_distributed: RwLock::new(HashMap::new()),
            distribution_config: RwLock::new(FeeDistributionConfig::default()),
            storage: Some(storage),
        }
    }

    /// Persists balance, collected, and distributed for an asset to storage
    fn persist_asset_state(
        &self,
        asset_id: &AssetId,
        balance: u128,
        collected: u128,
        distributed: u128,
    ) {
        if let Some(storage) = &self.storage {
            if let Err(e) = storage.persist_balance(asset_id, balance) {
                warn!("Failed to persist treasury balance: {}", e);
            }
            if let Err(e) = storage.persist_collected(asset_id, collected) {
                warn!("Failed to persist treasury collected: {}", e);
            }
            if let Err(e) = storage.persist_distributed(asset_id, distributed) {
                warn!("Failed to persist treasury distributed: {}", e);
            }
        }
    }

    /// Deposits a fee into the treasury
    ///
    /// # Arguments
    ///
    /// * `asset_id` - Asset being deposited
    /// * `amount` - Amount to deposit
    pub fn deposit_fee(&self, asset_id: &AssetId, amount: u128) -> Result<()> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount(
                "Amount must be greater than zero".to_string(),
            ));
        }

        // Update balance
        let mut balances = self.balances.write();
        let current = balances.get(asset_id).copied().unwrap_or(0);
        let new_balance =
            current
                .checked_add(amount)
                .ok_or_else(|| TokenError::ArithmeticOverflow {
                    operation: "treasury deposit".to_string(),
                })?;
        balances.insert(asset_id.clone(), new_balance);
        drop(balances);

        // Update total collected
        let mut total_collected = self.total_fees_collected.write();
        let current_total = total_collected.get(asset_id).copied().unwrap_or(0);
        let new_total =
            current_total
                .checked_add(amount)
                .ok_or_else(|| TokenError::ArithmeticOverflow {
                    operation: "treasury total fees collected".to_string(),
                })?;
        total_collected.insert(asset_id.clone(), new_total);
        let distributed = self
            .total_distributed
            .read()
            .get(asset_id)
            .copied()
            .unwrap_or(0);
        drop(total_collected);

        // Persist to storage
        self.persist_asset_state(asset_id, new_balance, new_total, distributed);

        info!("Deposited {} of {} to treasury", amount, asset_id.as_str());
        Ok(())
    }

    /// Returns the balance for a specific asset
    pub fn balance(&self, asset_id: &AssetId) -> u128 {
        self.balances.read().get(asset_id).copied().unwrap_or(0)
    }

    /// Returns the total value across all assets (in TNZO equivalent)
    ///
    /// Note: This is a simplified version. In production, you'd use an oracle
    /// or price feed to convert different assets to TNZO equivalent.
    pub fn total_value(&self) -> u128 {
        let balances = self.balances.read();
        balances.values().sum()
    }

    /// Processes a network fee according to the distribution config
    ///
    /// # Arguments
    ///
    /// * `asset_id` - Asset of the fee
    /// * `total_fee` - Total fee amount
    ///
    /// Returns the calculated distribution
    pub fn process_network_fee(
        &self,
        asset_id: &AssetId,
        total_fee: u128,
    ) -> Result<FeeDistribution> {
        let config = self.distribution_config.read();
        config.validate()?;

        let distribution = config.calculate_distribution(total_fee);

        // Deposit treasury share
        self.deposit_fee(asset_id, distribution.treasury_amount)?;

        debug!(
            "Processed fee: treasury={}, burn={}, stakers={}",
            distribution.treasury_amount, distribution.burn_amount, distribution.staker_amount
        );

        Ok(distribution)
    }

    /// Updates the fee distribution configuration
    pub fn update_distribution_config(&self, config: FeeDistributionConfig) -> Result<()> {
        config.validate()?;
        *self.distribution_config.write() = config;
        info!("Updated fee distribution config");
        Ok(())
    }

    /// Audits the treasury's supply invariant
    ///
    /// Verifies that: total_collected = current_balance + total_distributed
    ///
    /// # Arguments
    ///
    /// * `asset_id` - Asset to audit
    ///
    /// Returns `Ok(())` if the invariant holds, or an error with details if it doesn't.
    pub fn audit_supply(&self, asset_id: &AssetId) -> Result<()> {
        let balances = self.balances.read();
        let total_collected = self.total_fees_collected.read();
        let total_distributed = self.total_distributed.read();

        let current_balance = balances.get(asset_id).copied().unwrap_or(0);
        let collected = total_collected.get(asset_id).copied().unwrap_or(0);
        let distributed = total_distributed.get(asset_id).copied().unwrap_or(0);

        // Invariant: collected = balance + distributed
        // Or equivalently: balance = collected - distributed
        let expected_balance =
            collected
                .checked_sub(distributed)
                .ok_or_else(|| TokenError::TreasuryError {
                    message: format!(
                        "Distributed ({}) exceeds collected ({}) for {}",
                        distributed,
                        collected,
                        asset_id.as_str()
                    ),
                })?;

        if current_balance != expected_balance {
            return Err(TokenError::TreasuryError {
                message: format!(
                    "Supply invariant violation for {}: balance {} != expected {} (collected {} - distributed {})",
                    asset_id.as_str(),
                    current_balance,
                    expected_balance,
                    collected,
                    distributed
                ),
            });
        }

        debug!(
            "Supply audit passed for {}: balance={}, collected={}, distributed={}",
            asset_id.as_str(),
            current_balance,
            collected,
            distributed
        );
        Ok(())
    }

    /// Audits all assets in the treasury
    ///
    /// Returns the list of assets that failed the audit.
    pub fn audit_all_supplies(&self) -> Vec<(AssetId, String)> {
        let balances = self.balances.read();
        let mut failures = Vec::new();

        for asset_id in balances.keys() {
            if let Err(e) = self.audit_supply(asset_id) {
                failures.push((asset_id.clone(), e.to_string()));
            }
        }

        if !failures.is_empty() {
            warn!("Treasury audit found {} violations", failures.len());
        } else {
            info!("Treasury audit passed for all {} assets", balances.len());
        }

        failures
    }

    /// Returns treasury statistics
    pub fn stats(&self) -> TreasuryStats {
        let balances = self.balances.read().clone();
        let total_collected = self.total_fees_collected.read().clone();
        let total_distributed = self.total_distributed.read().clone();

        TreasuryStats {
            treasury_address: self.treasury_address,
            balances,
            total_fees_collected: total_collected,
            total_distributed,
            total_value: self.total_value(),
        }
    }
}

/// Treasury statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryStats {
    /// Treasury address
    pub treasury_address: Address,
    /// Current balances per asset
    pub balances: HashMap<AssetId, u128>,
    /// Total fees collected per asset
    pub total_fees_collected: HashMap<AssetId, u128>,
    /// Total distributed per asset
    pub total_distributed: HashMap<AssetId, u128>,
    /// Total value (in TNZO equivalent)
    pub total_value: u128,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_distribution_config() {
        let config = FeeDistributionConfig::default();
        assert!(config.validate().is_ok());

        let distribution = config.calculate_distribution(10000);
        assert_eq!(distribution.treasury_amount, 4000);
        assert_eq!(distribution.burn_amount, 3000);
        assert_eq!(distribution.staker_amount, 3000);
    }

    #[test]
    fn test_treasury_deposit() {
        let treasury = NetworkTreasury::new(Address::new([1u8; 32]));
        let asset_id = AssetId::tnzo();

        treasury.deposit_fee(&asset_id, 1000).unwrap();
        assert_eq!(treasury.balance(&asset_id), 1000);
    }

    #[test]
    fn test_supply_audit_passes() {
        let treasury = NetworkTreasury::new(Address::new([1u8; 32]));
        let asset_id = AssetId::tnzo();

        // Deposit 1000
        treasury.deposit_fee(&asset_id, 1000).unwrap();

        // Audit should pass
        assert!(treasury.audit_supply(&asset_id).is_ok());

        // A second deposit keeps the invariant.
        treasury.deposit_fee(&asset_id, 400).unwrap();
        assert!(treasury.audit_supply(&asset_id).is_ok());
    }

    #[test]
    fn test_supply_audit_detects_violation() {
        let treasury = NetworkTreasury::new(Address::new([1u8; 32]));
        let asset_id = AssetId::tnzo();

        // Deposit 1000
        treasury.deposit_fee(&asset_id, 1000).unwrap();

        // Manually corrupt the distributed counter (simulate a bug)
        {
            let mut distributed = treasury.total_distributed.write();
            distributed.insert(asset_id.clone(), 1500); // Exceeds collected
        }

        // Audit should fail
        assert!(treasury.audit_supply(&asset_id).is_err());
    }

    #[test]
    fn test_audit_all_supplies() {
        let treasury = NetworkTreasury::new(Address::new([1u8; 32]));
        let asset1 = AssetId::tnzo();
        let asset2 = AssetId::usd_stablecoin();

        // Deposit to both assets
        treasury.deposit_fee(&asset1, 1000).unwrap();
        treasury.deposit_fee(&asset2, 2000).unwrap();

        // All audits should pass
        let failures = treasury.audit_all_supplies();
        assert_eq!(failures.len(), 0);

        // Corrupt one asset
        {
            let mut distributed = treasury.total_distributed.write();
            distributed.insert(asset1.clone(), 1500);
        }

        // Should detect exactly one failure
        let failures = treasury.audit_all_supplies();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].0, asset1);
    }
}
