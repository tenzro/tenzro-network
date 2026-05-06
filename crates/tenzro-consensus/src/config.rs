//! Consensus configuration

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for the consensus engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Target block time in milliseconds (default: 400ms)
    pub block_time_ms: u64,

    /// Maximum block size in bytes (default: 2MB)
    pub max_block_size: usize,

    /// Maximum transactions per block (default: 10000)
    pub max_transactions_per_block: usize,

    /// Maximum gas per block (default: 30M)
    pub max_gas_per_block: u64,

    /// View timeout in milliseconds (default: 2000ms)
    pub view_timeout_ms: u64,

    /// Minimum validator count (default: 4)
    pub min_validators: usize,

    /// Byzantine fault tolerance threshold (default: 2f+1 where f = (n-1)/3)
    pub bft_threshold: BftThreshold,

    /// Enable TEE attestation priority (default: true)
    pub enable_tee_priority: bool,

    /// Epoch duration in blocks (default: 10000)
    pub epoch_duration: u64,

    /// Mempool size limit in bytes (default: 100MB)
    pub mempool_size_limit: usize,

    /// Maximum number of transactions in mempool (default: 10000)
    pub mempool_max_transactions: usize,

    /// Minimum gas price (in wei) accepted by the mempool, before lane
    /// fee-floor multipliers are applied. Set to 0 to disable the static
    /// floor entirely (mainnet should drive this off live EIP-1559 base fee).
    /// Default: 1 Gwei (1e9 wei). Spec 2 lane fee-floor multipliers
    /// (`fee_floor_mult(lane)`) scale this value at admission time so the
    /// effective floor for a Verified-lane controller is `1.0 × mempool_min_gas_price`,
    /// Delegated `1.5×`, and Open `4.0×` (per `AdmissionConfig::Default`).
    pub mempool_min_gas_price: u64,

    /// Transaction TTL in seconds (default: 600)
    pub transaction_ttl_seconds: u64,

    /// Enable optimistic responsiveness (default: true)
    pub optimistic_responsiveness: bool,

    /// Leader rotation strategy
    pub leader_rotation: LeaderRotation,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            block_time_ms: 400,
            max_block_size: 2 * 1024 * 1024, // 2MB
            max_transactions_per_block: 10_000,
            max_gas_per_block: 30_000_000,
            view_timeout_ms: 2000,
            min_validators: 4,
            bft_threshold: BftThreshold::TwoThirdsPlusOne,
            enable_tee_priority: true,
            epoch_duration: 10_000,
            mempool_size_limit: 100 * 1024 * 1024, // 100MB
            mempool_max_transactions: 10_000,
            mempool_min_gas_price: 1_000_000_000, // 1 Gwei
            transaction_ttl_seconds: 600,
            optimistic_responsiveness: true,
            leader_rotation: LeaderRotation::RoundRobin,
        }
    }
}

impl ConsensusConfig {
    /// Creates a new consensus configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the block time
    pub fn with_block_time(mut self, block_time_ms: u64) -> Self {
        self.block_time_ms = block_time_ms;
        self
    }

    /// Sets the max block size
    pub fn with_max_block_size(mut self, max_block_size: usize) -> Self {
        self.max_block_size = max_block_size;
        self
    }

    /// Sets the view timeout
    pub fn with_view_timeout(mut self, view_timeout_ms: u64) -> Self {
        self.view_timeout_ms = view_timeout_ms;
        self
    }

    /// Returns the block time as a Duration
    pub fn block_time(&self) -> Duration {
        Duration::from_millis(self.block_time_ms)
    }

    /// Returns the view timeout as a Duration
    pub fn view_timeout(&self) -> Duration {
        Duration::from_millis(self.view_timeout_ms)
    }

    /// Returns the transaction TTL as a Duration
    pub fn transaction_ttl(&self) -> Duration {
        Duration::from_secs(self.transaction_ttl_seconds)
    }

    /// Calculates the quorum threshold for the given validator count
    pub fn quorum_threshold(&self, validator_count: usize) -> usize {
        self.bft_threshold.calculate(validator_count)
    }
}

/// BFT threshold calculation strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BftThreshold {
    /// 2f+1 where f = (n-1)/3 (classic BFT)
    TwoThirdsPlusOne,
    /// Simple majority (n/2 + 1)
    SimpleMajority,
}

impl BftThreshold {
    /// Calculate the threshold for the given validator count
    pub fn calculate(&self, validator_count: usize) -> usize {
        match self {
            BftThreshold::TwoThirdsPlusOne => {
                // 2f+1 where f = (n-1)/3
                // This tolerates f Byzantine faults
                let f = (validator_count.saturating_sub(1)) / 3;
                2 * f + 1
            }
            BftThreshold::SimpleMajority => validator_count / 2 + 1,
        }
    }
}

/// Leader rotation strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaderRotation {
    /// Round-robin rotation based on view number
    RoundRobin,
    /// Weighted rotation based on stake
    StakeWeighted,
    /// Random rotation (using VRF)
    Random,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ConsensusConfig::default();
        assert_eq!(config.block_time_ms, 400);
        assert_eq!(config.max_block_size, 2 * 1024 * 1024);
        assert_eq!(config.view_timeout_ms, 2000);
    }

    #[test]
    fn test_bft_threshold() {
        let threshold = BftThreshold::TwoThirdsPlusOne;

        // With 4 validators: f=1, need 3 votes
        assert_eq!(threshold.calculate(4), 3);

        // With 7 validators: f=2, need 5 votes
        assert_eq!(threshold.calculate(7), 5);

        // With 10 validators: f=3, need 7 votes
        assert_eq!(threshold.calculate(10), 7);
    }

    #[test]
    fn test_config_builder() {
        let config = ConsensusConfig::new()
            .with_block_time(500)
            .with_max_block_size(3 * 1024 * 1024)
            .with_view_timeout(3000);

        assert_eq!(config.block_time_ms, 500);
        assert_eq!(config.max_block_size, 3 * 1024 * 1024);
        assert_eq!(config.view_timeout_ms, 3000);
    }
}
