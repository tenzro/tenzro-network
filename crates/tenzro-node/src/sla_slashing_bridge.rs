//! Bridge between the SLA fault detector (lives in `tenzro-model`) and the
//! compute-bond slashing primitives (lives in `tenzro-token`).
//!
//! Mirrors [`crate::node::StakingSlashingCallback`]: the trait
//! ([`tenzro_model::ProviderSlashingCallback`]) lives in the upstream crate
//! so `tenzro-model` stays free of node-level cross-crate refs; this is the
//! only place that holds both the [`ComputeBondManager`] handle and the
//! current block-height source.
//!
//! Why a bridge: the upstream trait is async (mirroring
//! `tenzro_consensus::SlashingCallback`'s shape so wiring is symmetric across
//! validator and provider slashing paths), while the bond manager methods are
//! synchronous in-memory updates with synchronous RocksDB write-through. The
//! bridge owns the async boundary and the type translation between
//! `tenzro_token::Result` and `tenzro_model::Result`.
//!
//! ## Block height
//!
//! `ComputeBondManager::slash` requires a block height for the audit-trail
//! event. We accept an `Arc<dyn Fn() -> u64 + Send + Sync>` so the bridge
//! reads the current finalized height at slash-time without holding a
//! consensus engine reference. The node wires this from the
//! [`tenzro_consensus::FinalityTracker`].

use async_trait::async_trait;
use std::sync::Arc;
use tenzro_model::{ModelError, ProviderSlashingCallback, Result as ModelResult};
use tenzro_token::ComputeBondManager;
use tracing::{info, warn};

/// Closure type returning the latest finalized block height. Used to stamp
/// `Slashed` events on the bond audit trail.
pub type BlockHeightFn = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Adapter implementing [`ProviderSlashingCallback`] in terms of a
/// [`ComputeBondManager`] handle.
pub struct ComputeBondSlashingBridge {
    bonds: Arc<ComputeBondManager>,
    /// Resolves the current finalized block height. Called once per `slash`.
    block_height_fn: BlockHeightFn,
}

impl ComputeBondSlashingBridge {
    /// Construct a new bridge. `block_height_fn` should return the latest
    /// finalized height; an early-startup fallback of `0` is acceptable.
    pub fn new(bonds: Arc<ComputeBondManager>, block_height_fn: BlockHeightFn) -> Self {
        Self {
            bonds,
            block_height_fn,
        }
    }
}

#[async_trait]
impl ProviderSlashingCallback for ComputeBondSlashingBridge {
    async fn record_probe_miss(&self, provider_did: &str) -> ModelResult<u32> {
        self.bonds
            .record_failure(provider_did)
            .map_err(|e| ModelError::Other(format!("compute_bond.record_failure: {e}")))
    }

    async fn reset_failure_count(&self, provider_did: &str) -> ModelResult<()> {
        self.bonds
            .reset_failure_count(provider_did)
            .map_err(|e| ModelError::Other(format!("compute_bond.reset_failure_count: {e}")))
    }

    async fn slash_provider_bond(
        &self,
        provider_did: &str,
        amount: u128,
        reason: &str,
    ) -> ModelResult<()> {
        let height = (self.block_height_fn)();
        match self.bonds.slash(provider_did, amount, reason, height) {
            Ok(snapshot) => {
                info!(
                    provider = %provider_did,
                    amount,
                    remaining = snapshot.amount,
                    reason,
                    height,
                    terminal = matches!(snapshot.status, tenzro_token::ComputeBondStatus::Slashed),
                    "Provider compute bond slashed via SLA fault detector"
                );
                Ok(())
            }
            Err(e) => {
                warn!(
                    provider = %provider_did,
                    amount,
                    reason,
                    error = %e,
                    "Compute bond slash failed"
                );
                Err(ModelError::Other(format!("compute_bond.slash: {e}")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_token::{ComputeBondManager, DEFAULT_COMPUTE_BOND_MIN};
    use tenzro_types::primitives::Address;

    fn block_fn(h: u64) -> BlockHeightFn {
        Arc::new(move || h)
    }

    fn provider_addr() -> Address {
        Address::new([0xAB; 32])
    }

    #[tokio::test]
    async fn record_failure_propagates() {
        let bonds = Arc::new(ComputeBondManager::new());
        // Need an Active bond for the failure counter to live on. Stake the
        // default minimum and verify the counter increments via the bridge.
        bonds
            .post(
                "did:tenzro:provider:p1",
                provider_addr(),
                DEFAULT_COMPUTE_BOND_MIN,
                100,
            )
            .expect("post bond");
        let bridge = ComputeBondSlashingBridge::new(bonds.clone(), block_fn(101));
        let n = bridge
            .record_probe_miss("did:tenzro:provider:p1")
            .await
            .expect("record");
        assert_eq!(n, 1);
        let n = bridge
            .record_probe_miss("did:tenzro:provider:p1")
            .await
            .expect("record");
        assert_eq!(n, 2);
    }

    #[tokio::test]
    async fn reset_clears_counter() {
        let bonds = Arc::new(ComputeBondManager::new());
        bonds
            .post(
                "did:tenzro:provider:p1",
                provider_addr(),
                DEFAULT_COMPUTE_BOND_MIN,
                100,
            )
            .expect("post bond");
        let bridge = ComputeBondSlashingBridge::new(bonds.clone(), block_fn(101));
        bridge
            .record_probe_miss("did:tenzro:provider:p1")
            .await
            .unwrap();
        bridge
            .reset_failure_count("did:tenzro:provider:p1")
            .await
            .unwrap();
        let bond = bonds.get("did:tenzro:provider:p1").unwrap();
        assert_eq!(bond.failure_count, 0);
    }

    #[tokio::test]
    async fn slash_debits_bond_and_logs_height() {
        let bonds = Arc::new(ComputeBondManager::new());
        let stake = DEFAULT_COMPUTE_BOND_MIN;
        bonds
            .post("did:tenzro:provider:p1", provider_addr(), stake, 100)
            .expect("post bond");
        let bridge = ComputeBondSlashingBridge::new(bonds.clone(), block_fn(202));
        bridge
            .slash_provider_bond("did:tenzro:provider:p1", 1_000, "sla:probe_timeout")
            .await
            .expect("slash");
        let bond = bonds.get("did:tenzro:provider:p1").unwrap();
        assert_eq!(bond.amount, stake - 1_000);
        assert_eq!(bond.last_modified_block, 202);
    }

    #[tokio::test]
    async fn slash_unknown_bond_returns_error() {
        let bonds = Arc::new(ComputeBondManager::new());
        let bridge = ComputeBondSlashingBridge::new(bonds, block_fn(0));
        let err = bridge
            .slash_provider_bond("did:tenzro:provider:ghost", 1, "sla:probe_timeout")
            .await
            .expect_err("must fail on unknown DID");
        assert!(matches!(err, ModelError::Other(_)));
    }
}
