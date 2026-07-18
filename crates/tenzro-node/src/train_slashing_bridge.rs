//! Bridge between the Tenzro Train syncer's slash-and-evict hook (lives in
//! `tenzro-training`) and the compute-bond slashing primitive (lives in
//! `tenzro-token`).
//!
//! Mirrors [`crate::sla_slashing_bridge::ComputeBondSlashingBridge`]: the trait
//! ([`tenzro_training::TrainerSlashingCallback`]) lives in the upstream crate so
//! `tenzro-training` stays free of node-level cross-crate refs; this is the only
//! place that holds both the [`ComputeBondManager`] handle and the finalized
//! block-height source.
//!
//! ## Terminal slash
//!
//! Unlike the SLA path (which debits a fixed per-miss amount so a flaky provider
//! bleeds its bond down gradually), a rejected training contribution is a
//! spec-deviation or an out-of-band gradient — the trainer is evicted for the
//! remainder of the run with no rehabilitation. So
//! the bridge slashes the entire remaining bond: `ComputeBondManager::slash`
//! caps the applied amount at the bond balance, so passing `u128::MAX` zeroes
//! the bond and flips its status to `Slashed` in one call.

use async_trait::async_trait;
use std::sync::Arc;
use tenzro_token::ComputeBondManager;
use tenzro_training::{EvictionReason, TrainerSlashingCallback};
use tracing::{info, warn};

/// Closure returning the latest finalized block height. Used to stamp the
/// `Slashed` event on the bond audit trail. Shared shape with the SLA bridge.
pub type BlockHeightFn = Arc<dyn Fn() -> u64 + Send + Sync>;

/// Adapter implementing [`TrainerSlashingCallback`] in terms of a
/// [`ComputeBondManager`] handle.
pub struct TrainerComputeBondSlashingBridge {
    bonds: Arc<ComputeBondManager>,
    /// Resolves the current finalized block height. Called once per slash.
    block_height_fn: BlockHeightFn,
}

impl TrainerComputeBondSlashingBridge {
    pub fn new(bonds: Arc<ComputeBondManager>, block_height_fn: BlockHeightFn) -> Self {
        Self { bonds, block_height_fn }
    }
}

#[async_trait]
impl TrainerSlashingCallback for TrainerComputeBondSlashingBridge {
    async fn slash_and_evict(&self, task_id: &str, trainer_did: &str, reason: EvictionReason) {
        let height = (self.block_height_fn)();
        // Full slash — eviction is terminal for the run. `slash` caps at the
        // bond balance, so u128::MAX zeroes it and marks it Slashed.
        match self.bonds.slash(trainer_did, u128::MAX, reason.tag(), height) {
            Ok(snapshot) => {
                info!(
                    task = %task_id,
                    trainer = %trainer_did,
                    reason = reason.tag(),
                    remaining = snapshot.amount,
                    height,
                    "Trainer compute bond slashed + evicted from training run"
                );
            }
            Err(e) => {
                // Fail-open on the bond debit: the syncer has already removed
                // the DID from the active set, so an evicted trainer stays
                // evicted even if it never posted a bond (Open-tier) or the
                // bond is already in a terminal state.
                warn!(
                    task = %task_id,
                    trainer = %trainer_did,
                    reason = reason.tag(),
                    error = %e,
                    "Trainer eviction proceeded but compute-bond slash failed"
                );
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

    #[tokio::test]
    async fn slash_zeroes_bond_and_marks_slashed() {
        let bonds = Arc::new(ComputeBondManager::new());
        bonds
            .post(
                "did:tenzro:machine:t1",
                Address::new([0x11; 32]),
                DEFAULT_COMPUTE_BOND_MIN,
                100,
            )
            .expect("post bond");
        let bridge = TrainerComputeBondSlashingBridge::new(bonds.clone(), block_fn(202));
        bridge
            .slash_and_evict("run-1", "did:tenzro:machine:t1", EvictionReason::AcceptRejected)
            .await;
        let bond = bonds.get("did:tenzro:machine:t1").unwrap();
        assert_eq!(bond.amount, 0);
        assert_eq!(bond.last_modified_block, 202);
        assert_eq!(bond.status, tenzro_token::ComputeBondStatus::Slashed);
    }

    #[tokio::test]
    async fn slash_unbonded_trainer_is_noop() {
        // Open-tier trainer that never posted a bond — eviction still stands,
        // the slash just no-ops with a logged warning.
        let bonds = Arc::new(ComputeBondManager::new());
        let bridge = TrainerComputeBondSlashingBridge::new(bonds, block_fn(0));
        bridge
            .slash_and_evict(
                "run-1",
                "did:tenzro:machine:ghost",
                EvictionReason::NormBudgetExceeded,
            )
            .await;
    }
}
