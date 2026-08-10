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

    /// View timeout in milliseconds — **bootstrap seed only**.
    ///
    /// This value seeds `ViewChangeTimer::base_timeout` at engine
    /// construction. After the first successful view, the adaptive
    /// tuner (`ViewChangeTimer::record_observed_view_latency`)
    /// retunes the base timeout to track the cluster's actually-
    /// observed quorum-formation latency.
    ///
    /// **Why this is a seed, not a default**: the validator set is
    /// open. A validator on residential WiFi joining a cluster of
    /// datacenter peers cannot share a static default with a
    /// single-region testnet. The adaptive algorithm tracks an EWMA
    /// of observed view-to-QC latency and sets `base_timeout =
    /// safety_multiplier × ewma`, clamped to `[base_floor,
    /// base_ceiling]`. The seed only matters until the cluster has
    /// produced a few successful views — after that, this value is
    /// overwritten.
    ///
    /// **Seed choice**: 1000ms is a reasonable midpoint. Lower seeds
    /// (e.g. 200ms) cause noisy view-change storms during bootstrap
    /// when no peer has spoken yet; higher seeds (e.g. 5000ms) waste
    /// wall-clock on the first few views before adaptation kicks in.
    /// Operators rarely need to tune this.
    pub view_timeout_ms: u64,

    /// Minimum validator count (default: 4)
    pub min_validators: usize,

    /// Byzantine fault tolerance threshold (default: 2f+1 where f = (n-1)/3)
    pub bft_threshold: BftThreshold,

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

    /// Maximum number of pending transactions a single sender address may
    /// hold in the mempool at once (default: 64). Bounds the damage one
    /// account can do to shared mempool capacity and doubles as the
    /// admissible nonce look-ahead: a tx whose nonce exceeds
    /// `account_nonce + mempool_max_per_sender` is rejected as
    /// unexecutable-for-now spam.
    pub mempool_max_per_sender: usize,

    /// Transaction TTL in seconds (default: 600)
    pub transaction_ttl_seconds: u64,

    /// Enable optimistic responsiveness (default: true)
    pub optimistic_responsiveness: bool,

    /// Proposer election strategy.
    ///
    /// Default is [`ProposerElectionKind::Reputation`] (reputation-weighted proposer election),
    /// which prevents the chain from stalling when a single validator becomes
    /// unresponsive. [`ProposerElectionKind::RoundRobin`] is retained for
    /// tests and replay benchmarks.
    pub proposer_election: ProposerElectionKind,

    /// Heartbeat interval for empty-block suppression, in milliseconds.
    ///
    /// When the mempool is empty the leader does NOT mint a block on every
    /// pacemaker beat — doing so accreted ~216k empty headers/day of
    /// monotonic, never-pruned SST on an idle chain. Instead the leader
    /// proposes only when it has transactions to commit OR when this
    /// interval has elapsed since the last finalized block, whichever comes
    /// first. The heartbeat block keeps the chain tip fresh (timestamps,
    /// state-root continuity) and gives non-leaders a positive liveness
    /// signal so they can distinguish "idle" from "dead leader" without
    /// waiting on the view-change timer.
    ///
    /// This follows the standard `create_empty_blocks = false` +
    /// `create_empty_blocks_interval` pattern. Set to 0 to disable suppression and
    /// restore always-on block production (every beat mints a block).
    ///
    /// Default: 600000ms (10 min) — activity-driven production with only a
    /// rare liveness heartbeat. Real (transaction-bearing) blocks are always
    /// produced immediately; a fully idle chain mints at most ~144 keepalive
    /// headers/day (vs ~2,880 at 30s / ~17,280 at 5s). The heartbeat is
    /// decoupled from liveness — followers detect a dead leader via the
    /// view-change timer, not this interval — so a long interval only trades a
    /// staler idle-tip timestamp for far fewer empty headers, which is the
    /// intended policy: don't accumulate millions of empty blocks on an idle
    /// network. Set to 0 to disable suppression (mint every beat — dev only).
    pub empty_block_heartbeat_ms: u64,

    /// Floor on the adaptive view-change base timeout, in milliseconds.
    ///
    /// The pacemaker self-tunes its base timeout to `safety_multiplier ×
    /// EWMA(observed quorum latency)`, clamped to this floor. The floor
    /// exists because the EWMA measures only *successful* rounds, so on a
    /// wide-area fleet it converges to the median quorum latency and gives
    /// no headroom for the tail — a single round slower than `2 × median`
    /// (WAN jitter, GC pause, a momentarily slow peer) then trips a
    /// spurious timeout. Each spurious timeout advances the view without
    /// finalizing, which on this chain produced ~2 views per height and a
    /// stream of recovery blocks that defeated empty-block suppression.
    ///
    /// 200ms (the previous hard-coded value) is far below realistic
    /// cross-region quorum latency: inter-continent RTT alone is
    /// 150–250ms, and a quorum needs a full proposal→vote round trip. For
    /// a multi-continent validator set the floor must exceed the tail of
    /// that round trip, not its median.
    ///
    /// Default: 1000ms — comfortably above observed cross-region quorum
    /// latency (~100–400ms tail) so views stop timing out spuriously,
    /// while still letting the adaptive tuner raise the timeout further
    /// under genuine load. A single-region or LAN cluster can lower this.
    pub adaptive_timeout_floor_ms: u64,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            block_time_ms: 400,
            max_block_size: 2 * 1024 * 1024, // 2MB
            max_transactions_per_block: 10_000,
            max_gas_per_block: 30_000_000,
            view_timeout_ms: 1000,
            min_validators: 4,
            bft_threshold: BftThreshold::TwoThirdsPlusOne,
            epoch_duration: 10_000,
            mempool_size_limit: 100 * 1024 * 1024, // 100MB
            mempool_max_transactions: 10_000,
            mempool_min_gas_price: 1_000_000_000, // 1 Gwei
            mempool_max_per_sender: 64,
            transaction_ttl_seconds: 600,
            optimistic_responsiveness: true,
            proposer_election: ProposerElectionKind::Reputation,
            empty_block_heartbeat_ms: 600_000,
            adaptive_timeout_floor_ms: 1000,
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

    /// Sets the proposer election strategy.
    pub fn with_proposer_election(mut self, kind: ProposerElectionKind) -> Self {
        self.proposer_election = kind;
        self
    }

    /// Sets the empty-block heartbeat interval (0 disables suppression).
    pub fn with_empty_block_heartbeat(mut self, heartbeat_ms: u64) -> Self {
        self.empty_block_heartbeat_ms = heartbeat_ms;
        self
    }

    /// Returns the empty-block heartbeat interval as a Duration.
    pub fn empty_block_heartbeat(&self) -> Duration {
        Duration::from_millis(self.empty_block_heartbeat_ms)
    }

    /// Whether empty-block suppression is active (heartbeat > 0).
    pub fn suppress_empty_blocks(&self) -> bool {
        self.empty_block_heartbeat_ms > 0
    }

    /// Sets the adaptive view-timeout floor.
    pub fn with_adaptive_timeout_floor(mut self, floor_ms: u64) -> Self {
        self.adaptive_timeout_floor_ms = floor_ms;
        self
    }

    /// Returns the adaptive view-timeout floor as a Duration.
    pub fn adaptive_timeout_floor(&self) -> Duration {
        Duration::from_millis(self.adaptive_timeout_floor_ms)
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

/// Proposer election strategy.
///
/// Renamed from `LeaderRotation` to avoid colliding with the
/// `ProposerElection` *trait* in `validator.rs`. The "Kind" suffix marks
/// this as the configuration discriminator: the engine resolves it to a
/// concrete `Box<dyn ProposerElection>` at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposerElectionKind {
    /// Naïve `view % N` round-robin. Tests and very small validator sets only.
    RoundRobin,
    /// Reputation-weighted proposer election: stake-weighted seeded draw with
    /// observed-behaviour multipliers. Default and recommended for production.
    Reputation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ConsensusConfig::default();
        assert_eq!(config.block_time_ms, 400);
        assert_eq!(config.max_block_size, 2 * 1024 * 1024);
        assert_eq!(config.view_timeout_ms, 1000);
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
