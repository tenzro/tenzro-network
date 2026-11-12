//! Applies network policy decided by on-chain governance, and proposes the
//! burn-dial changes the supply metrics call for.
//!
//! A `PolicyUpdate` proposal enacts in the VM, which records the change in
//! consensus state and logs a [`PolicyEnactedLog`]. Every node re-executes
//! the same block, so every node applies the same change here, to the
//! subsystem it names: the economic policy, or the burn dial and its supply
//! targets. A protocol upgrade enacts once enough validator machines have
//! quoted its binary, and activates at the height consensus scheduled: a node
//! running any other binary stops executing blocks from that height.
//!
//! The burn dial's [`AutoProposalGenerator`] drafts changes; a validator
//! submits each draft as a governance proposal signed by its own key, and
//! nothing changes until the network votes it through.

use std::sync::Arc;

use tenzro_token::EconomicPolicyManager;
use tenzro_token::adaptive_burn::{AutoProposalGenerator, BurnRateConfigManager, PolicyDraft};
use tenzro_types::TransactionType;
use tenzro_types::token::PolicyUpdate;
use tenzro_vm::governance::{
    PolicyEnactedLog, PolicyTrack, ProposalAction, UpgradeActivation, policy_kind,
};
use tenzro_vm::native::{
    POLICY_ENACTED_TOPIC, PROTOCOL_VERSION_TOPIC, ProtocolVersionRecord, UPGRADE_SCHEDULED_TOPIC,
    read_policy, read_protocol_version, read_upgrade_activation,
};
use tenzro_vm::protocol_range::{ProtocolMismatch, ProtocolRange};
use tenzro_vm::traits::VmState;
use tracing::{info, warn};

/// Gas limit of a governance proposal transaction.
const PROPOSE_GAS: u64 = 100_000;

/// The subsystems a policy change can name.
pub struct PolicyApplier {
    economic_policy: Arc<EconomicPolicyManager>,
    burn_rate: Option<Arc<BurnRateConfigManager>>,
    /// The protocol upgrade consensus scheduled last.
    upgrade: std::sync::RwLock<Option<UpgradeActivation>>,
    /// The chain's protocol version as consensus state holds it; `None` for
    /// a chain whose genesis recorded none, which is not range-checked.
    protocol: std::sync::RwLock<Option<ProtocolVersionRecord>>,
    /// Hex SHA-256 of the binary this node runs.
    own_code_hash: Option<String>,
    /// The protocol versions this binary can execute.
    supported: ProtocolRange,
}

impl PolicyApplier {
    pub fn new(
        economic_policy: Arc<EconomicPolicyManager>,
        burn_rate: Option<Arc<BurnRateConfigManager>>,
        own_code_hash: Option<String>,
    ) -> Self {
        Self {
            economic_policy,
            burn_rate,
            upgrade: std::sync::RwLock::new(None),
            protocol: std::sync::RwLock::new(None),
            own_code_hash,
            supported: ProtocolRange::this_binary(),
        }
    }

    /// Override the protocol versions this node can execute.
    pub fn with_supported_protocols(mut self, supported: ProtocolRange) -> Self {
        self.supported = supported;
        self
    }

    /// The protocol version `height` runs at, as consensus state holds it.
    pub fn protocol_version_at(&self, height: u64) -> Option<u32> {
        self.protocol
            .read()
            .ok()
            .and_then(|p| p.as_ref().map(|r| r.at(height)))
    }

    /// The mismatch between the chain's protocol version at `height` and the
    /// versions this binary supports, if there is one.
    pub fn protocol_mismatch_at(&self, height: u64) -> Option<ProtocolMismatch> {
        self.supported
            .check(self.protocol_version_at(height)?)
            .err()
    }

    /// Why this node must stop executing the block at `height`, in plain
    /// words, if it must: an upgrade names another binary, or the chain's
    /// protocol version is outside what this binary supports.
    pub fn stop_reason(&self, height: u64) -> Option<String> {
        if let Some(upgrade) = self.superseded_at(height) {
            return Some(format!(
                "protocol upgrade {} (binary {}) activated at height {}; this node runs another binary \
                 and stops executing blocks until it is replaced",
                upgrade.version, upgrade.code_hash, upgrade.activation_height
            ));
        }
        self.protocol_mismatch_at(height).map(|m| m.to_string())
    }

    /// Startup check against the next height to execute: refuses to start a
    /// node whose binary does not support the chain's protocol version.
    pub fn startup_check(&self, next_height: u64) -> Result<(), ProtocolMismatch> {
        match self.protocol_mismatch_at(next_height) {
            Some(m) => Err(m),
            None => Ok(()),
        }
    }

    /// The protocol upgrade consensus scheduled last, if any.
    pub fn scheduled_upgrade(&self) -> Option<UpgradeActivation> {
        self.upgrade.read().ok().and_then(|u| u.clone())
    }

    /// Whether this node runs the binary whose hex SHA-256 is `code_hash`.
    pub fn runs_binary(&self, code_hash: &str) -> bool {
        self.own_code_hash.as_deref() == Some(code_hash)
    }

    /// The upgrade that retires this binary at `height`: one scheduled to
    /// activate at or below it whose code hash is not this binary's. A node
    /// that cannot hash its own binary is retired by any activation.
    pub fn superseded_at(&self, height: u64) -> Option<UpgradeActivation> {
        let upgrade = self.scheduled_upgrade()?;
        let current = self.own_code_hash.as_deref() == Some(upgrade.code_hash.as_str());
        (height >= upgrade.activation_height && !current).then_some(upgrade)
    }

    fn note_upgrade(&self, activation: UpgradeActivation) {
        info!(
            proposal_id = %activation.proposal_id,
            version = %activation.version,
            code_hash = %activation.code_hash,
            activation_height = activation.activation_height,
            runs_it = self.own_code_hash.as_deref() == Some(activation.code_hash.as_str()),
            "Protocol upgrade scheduled"
        );
        if let Ok(mut slot) = self.upgrade.write() {
            *slot = Some(activation);
        }
    }

    /// Apply every policy change logged in `logs`.
    pub fn reflect_logs(&self, logs: &[tenzro_vm::Log]) {
        for log in logs {
            let topic = log.topics.first().map(|t| t.as_slice());
            if topic == Some(UPGRADE_SCHEDULED_TOPIC) {
                match serde_json::from_slice::<UpgradeActivation>(&log.data) {
                    Ok(activation) => self.note_upgrade(activation),
                    Err(e) => warn!("Malformed upgrade activation log, skipping: {e}"),
                }
                continue;
            }
            if topic == Some(PROTOCOL_VERSION_TOPIC) {
                match serde_json::from_slice::<ProtocolVersionRecord>(&log.data) {
                    Ok(record) => {
                        if let Ok(mut slot) = self.protocol.write() {
                            *slot = Some(record);
                        }
                    }
                    Err(e) => warn!("Malformed protocol version log, skipping: {e}"),
                }
                continue;
            }
            if topic != Some(POLICY_ENACTED_TOPIC) {
                continue;
            }
            match serde_json::from_slice::<PolicyEnactedLog>(&log.data) {
                Ok(record) => {
                    if let Err(e) = self.apply(&record) {
                        warn!(
                            proposal_id = %record.proposal_id,
                            kind = policy_kind(&record.update),
                            "consensus enacted a policy change this node could not apply: {e}"
                        );
                    }
                }
                Err(e) => warn!("Malformed policy log, skipping: {e}"),
            }
        }
    }

    /// Bring the settings consensus holds as absolute values (economic
    /// policy, burn dial, supply targets) up to date at startup, so a node
    /// that joined from a state snapshot runs the policy the network voted
    /// for rather than its genesis defaults. Changes keyed per record arrive
    /// only with the blocks that carry them.
    pub fn hydrate(&self, state: &dyn VmState) {
        for kind in ["economic_policy", "adaptive_burn_config", "supply_targets"] {
            if let Some(record) = read_policy(state, kind)
                && let Err(e) = self.apply(&record)
            {
                warn!(kind, "could not apply the enacted policy at startup: {e}");
            }
        }
        if let Ok(mut slot) = self.protocol.write() {
            *slot = read_protocol_version(state);
        }
        if let Some(activation) = read_upgrade_activation(state) {
            self.note_upgrade(activation);
        }
    }

    /// Apply one enacted change.
    pub fn apply(&self, record: &PolicyEnactedLog) -> Result<(), String> {
        let id = &record.proposal_id;
        match &record.update {
            PolicyUpdate::ProtocolUpgrade { version, code_hash } => {
                info!(
                    proposal_id = %id,
                    version = %version,
                    code_hash = %hex::encode(code_hash),
                    "Governance enacted a protocol upgrade"
                );
            }
            PolicyUpdate::EconomicPolicyUpdate { policy } => {
                self.economic_policy
                    .apply(*policy)
                    .map_err(|e| e.to_string())?;
                info!(proposal_id = %id, "Governance applied a new economic policy");
            }
            PolicyUpdate::AdaptiveBurnConfigUpdate {
                base_fee_burn_bps,
                local_fee_burn_bps,
            } => {
                let burn_rate = self.burn_rate()?;
                burn_rate
                    .apply_config(tenzro_token::adaptive_burn::BurnRateConfig {
                        base_fee_burn_bps: *base_fee_burn_bps,
                        local_fee_burn_bps: *local_fee_burn_bps,
                    })
                    .map_err(|e| e.to_string())?;
                info!(proposal_id = %id, "Governance applied a burn-dial change");
            }
            PolicyUpdate::SupplyTargetsUpdate {
                epoch_neutral_band_bps,
                rolling_window_epochs,
                inflation_alarm_bps,
                deflation_alarm_bps,
                target_annual_supply_bps,
                gain_bps_per_pct,
                magnitude_cap_normal_bps,
                magnitude_cap_alarm_bps,
                auto_proposal_min_magnitude_bps,
                alarm_fast_track_enabled,
            } => {
                let burn_rate = self.burn_rate()?;
                // The update carries the parametric knobs; the enabled flag
                // is left as it is.
                let enabled = burn_rate.targets().enabled;
                burn_rate
                    .apply_targets(tenzro_token::adaptive_burn::SupplyTargets {
                        enabled,
                        epoch_neutral_band_bps: *epoch_neutral_band_bps,
                        rolling_window_epochs: *rolling_window_epochs,
                        inflation_alarm_bps: *inflation_alarm_bps,
                        deflation_alarm_bps: *deflation_alarm_bps,
                        target_annual_supply_bps: *target_annual_supply_bps,
                        gain_bps_per_pct: *gain_bps_per_pct,
                        magnitude_cap_normal_bps: *magnitude_cap_normal_bps,
                        magnitude_cap_alarm_bps: *magnitude_cap_alarm_bps,
                        auto_proposal_min_magnitude_bps: *auto_proposal_min_magnitude_bps,
                        alarm_fast_track_enabled: *alarm_fast_track_enabled,
                    })
                    .map_err(|e| e.to_string())?;
                info!(proposal_id = %id, "Governance applied new supply targets");
            }
            // Consensus state; nothing for the event loop to mirror.
            PolicyUpdate::TpmEndorsementRootsSet { .. } => {
                info!(proposal_id = %id, "Governance replaced the TPM endorsement roots");
            }
            PolicyUpdate::GpuDeviceRootsSet { .. } => {
                info!(proposal_id = %id, "Governance replaced the GPU device roots");
            }
            PolicyUpdate::GpuReferenceValuesSet { .. } => {
                info!(proposal_id = %id, "Governance replaced the GPU reference values");
            }
            PolicyUpdate::BridgeCircuitSet {
                adapter,
                source_chain,
                mode,
                ..
            } => {
                info!(proposal_id = %id, adapter = adapter.as_str(), %source_chain, mode = mode.as_str(),
                    "Governance set a bridge route's mode");
            }
            PolicyUpdate::BridgeMintLimitsSet { .. } => {
                info!(proposal_id = %id, "Governance replaced the bridge mint limits");
            }
            PolicyUpdate::BridgeOutflowLimitsSet { .. } => {
                info!(proposal_id = %id, "Governance replaced the bridge outflow limits");
            }
            PolicyUpdate::FinalityProgramSet { image_id } => {
                info!(proposal_id = %id, image_id = %hex::encode(image_id),
                    "Governance set the finality program");
            }
            PolicyUpdate::HandoverProgramSet { image_id } => {
                info!(proposal_id = %id, image_id = %hex::encode(image_id),
                    "Governance set the handover program");
            }
        }
        Ok(())
    }

    fn burn_rate(&self) -> Result<&Arc<BurnRateConfigManager>, String> {
        self.burn_rate
            .as_ref()
            .ok_or_else(|| "this node runs no burn dial".to_string())
    }
}

/// SHA-256 of the file at `path`, read in blocks.
pub fn binary_hash(path: &std::path::Path) -> std::io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

/// Hex SHA-256 of the binary this process runs.
pub fn own_code_hash() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    match binary_hash(&exe) {
        Ok(h) => Some(hex::encode(h)),
        Err(e) => {
            warn!(path = %exe.display(), "cannot hash this node's own binary: {e}");
            None
        }
    }
}

/// Where an operator stages the binary a protocol upgrade names, inside the
/// node's data directory, before signalling readiness for it.
pub fn staged_binary_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("upgrade").join("staged")
}

/// The governance proposal transaction for `draft`.
pub fn proposal_transaction(draft: PolicyDraft) -> Result<TransactionType, String> {
    let action = ProposalAction::PolicyUpdate {
        update: draft.update,
        memo: draft.memo,
        track: if draft.expedited {
            PolicyTrack::Expedited
        } else {
            PolicyTrack::Standard
        },
    };
    action.validate().map_err(|e| e.to_string())?;
    let proposal = serde_json::to_vec(&action).map_err(|e| e.to_string())?;
    Ok(TransactionType::GovernancePropose { proposal })
}

/// Run the burn dial's proposal generator on a validator: each draft goes to
/// the network as a governance proposal from this validator's own account.
pub fn spawn_burn_proposer(
    burn_rate: Arc<BurnRateConfigManager>,
    submitter: Arc<crate::payment_rails::LedgerSubmitter>,
) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PolicyDraft>();
    Arc::new(AutoProposalGenerator::new(burn_rate, tx)).spawn();
    tokio::spawn(async move {
        while let Some(draft) = rx.recv().await {
            let tx_type = match proposal_transaction(draft) {
                Ok(t) => t,
                Err(e) => {
                    warn!("burn-dial draft is not a valid proposal: {e}");
                    continue;
                }
            };
            let from = submitter.address();
            match submitter.submit_with_gas(from, tx_type, PROPOSE_GAS).await {
                Ok(hash) => info!(tx_hash = %hash, "Submitted a burn-dial proposal"),
                Err(e) => warn!("burn-dial proposal not admitted: {e}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_vm::Log;

    fn applier() -> (PolicyApplier, Arc<BurnRateConfigManager>) {
        let burn = Arc::new(BurnRateConfigManager::new());
        (
            PolicyApplier::new(
                Arc::new(EconomicPolicyManager::new()),
                Some(burn.clone()),
                Some("aa".repeat(32)),
            ),
            burn,
        )
    }

    fn scheduled(code_hash: &str, activation_height: u64) -> Log {
        let activation = UpgradeActivation {
            proposal_id: "ab".repeat(32),
            version: "2".into(),
            code_hash: code_hash.into(),
            readiness_met_height: activation_height - 10,
            activation_height,
        };
        Log::new(
            vec![0; 20],
            vec![UPGRADE_SCHEDULED_TOPIC.to_vec()],
            serde_json::to_vec(&activation).unwrap(),
        )
    }

    #[test]
    fn a_scheduled_upgrade_retires_another_binary_at_its_height_only() {
        let (applier, _) = applier();
        applier.reflect_logs(&[scheduled(&"bb".repeat(32), 100)]);
        assert_eq!(applier.scheduled_upgrade().unwrap().activation_height, 100);
        assert!(
            applier.superseded_at(99).is_none(),
            "not before the activation height"
        );
        assert!(
            applier.superseded_at(100).is_some(),
            "this node runs another binary"
        );

        applier.reflect_logs(&[scheduled(&"aa".repeat(32), 200)]);
        assert!(
            applier.superseded_at(500).is_none(),
            "this node runs the upgraded binary"
        );
    }

    // ---- The protocol version range ----

    fn version_log(version: u32, next: Option<(u32, u64)>) -> Log {
        let record = ProtocolVersionRecord {
            version,
            next: next.map(|(version, activation_height)| {
                tenzro_vm::native::PendingProtocolVersion {
                    version,
                    activation_height,
                }
            }),
        };
        Log::new(
            vec![0; 20],
            vec![PROTOCOL_VERSION_TOPIC.to_vec()],
            serde_json::to_vec(&record).unwrap(),
        )
    }

    #[test]
    fn a_binary_outside_the_protocol_range_stops_at_the_activation_height_with_a_clear_message() {
        let (applier, _) = applier();
        let node = applier.with_supported_protocols(ProtocolRange { min: 2, max: 2 });
        // The chain runs 2 and a scheduled upgrade raises it to 3 at 100.
        node.reflect_logs(&[version_log(2, Some((3, 100)))]);
        assert_eq!(node.protocol_version_at(99), Some(2));
        assert_eq!(node.protocol_version_at(100), Some(3));
        assert!(node.stop_reason(99).is_none(), "in range before activation");
        assert!(node.startup_check(99).is_ok());

        let reason = node.stop_reason(100).expect("out of range at activation");
        assert!(reason.contains("protocol version mismatch"), "{reason}");
        assert!(reason.contains("protocol version 3"), "{reason}");
        assert!(reason.contains("2 to 2"), "{reason}");
        assert!(reason.contains("Stopping"), "{reason}");
        assert!(node.stop_reason(10_000).is_some());

        // Started after the activation, the node refuses to start at all.
        let err = node.startup_check(100).unwrap_err().to_string();
        assert!(err.contains("protocol version 3"), "{err}");

        // A binary that has the newer range goes on.
        let upgraded = PolicyApplier::new(Arc::new(EconomicPolicyManager::new()), None, None)
            .with_supported_protocols(ProtocolRange { min: 2, max: 3 });
        upgraded.reflect_logs(&[version_log(2, Some((3, 100)))]);
        assert!(upgraded.stop_reason(100).is_none());
    }

    #[test]
    fn a_chain_below_the_binarys_minimum_refuses_too_and_no_record_means_no_check() {
        let node = PolicyApplier::new(Arc::new(EconomicPolicyManager::new()), None, None)
            .with_supported_protocols(ProtocolRange { min: 2, max: 4 });
        assert!(
            node.stop_reason(1).is_none() && node.startup_check(1).is_ok(),
            "a chain that records no version is not range-checked"
        );
        node.reflect_logs(&[version_log(1, None)]);
        let err = node.startup_check(1).unwrap_err().to_string();
        assert!(err.contains("protocol version 1"), "{err}");
        assert!(err.contains("older than this binary supports"), "{err}");
    }

    #[test]
    fn hydrating_from_state_reads_the_recorded_version() {
        let mut state = tenzro_vm::StateAdapter::new();
        state.set_storage(
            &tenzro_vm::native::SYSTEM_ADDRESS,
            tenzro_vm::native::PROTOCOL_VERSION_KEY.as_bytes(),
            tenzro_vm::native::genesis_protocol_version(5).unwrap(),
        );
        let (applier, _) = applier();
        let node = applier.with_supported_protocols(ProtocolRange { min: 2, max: 4 });
        node.hydrate(&state);
        assert_eq!(node.protocol_version_at(0), Some(5));
        assert!(node.startup_check(1).is_err());
    }

    fn log(update: PolicyUpdate) -> Log {
        let record = PolicyEnactedLog {
            proposal_id: "ab".repeat(32),
            update,
        };
        Log::new(
            vec![0; 20],
            vec![POLICY_ENACTED_TOPIC.to_vec()],
            serde_json::to_vec(&record).unwrap(),
        )
    }

    #[test]
    fn an_enacted_burn_change_reaches_the_dial() {
        let (applier, burn) = applier();
        applier.reflect_logs(&[log(PolicyUpdate::AdaptiveBurnConfigUpdate {
            base_fee_burn_bps: 7_000,
            local_fee_burn_bps: 9_000,
        })]);
        let c = burn.config();
        assert_eq!((c.base_fee_burn_bps, c.local_fee_burn_bps), (7_000, 9_000));
    }

    #[test]
    fn other_logs_and_a_missing_subsystem_change_nothing() {
        let (applier, burn) = applier();
        let before = burn.config();
        let unrelated = Log::new(vec![0; 20], vec![b"Other".to_vec()], b"{}".to_vec());
        applier.reflect_logs(&[
            unrelated,
            log(PolicyUpdate::TpmEndorsementRootsSet { roots_pem: vec![] }),
        ]);
        assert_eq!(burn.config(), before);
    }

    #[test]
    fn a_draft_becomes_a_governance_proposal_and_a_bad_one_does_not() {
        let good = PolicyDraft {
            update: PolicyUpdate::AdaptiveBurnConfigUpdate {
                base_fee_burn_bps: 9_000,
                local_fee_burn_bps: 10_000,
            },
            memo: "alarm".into(),
            expedited: true,
        };
        let TransactionType::GovernancePropose { proposal } = proposal_transaction(good).unwrap()
        else {
            panic!("not a proposal");
        };
        let action: ProposalAction = serde_json::from_slice(&proposal).unwrap();
        assert_eq!(
            action.track(),
            tenzro_vm::governance::ProposalTrack::Expedited
        );

        let bad = PolicyDraft {
            update: PolicyUpdate::ProtocolUpgrade {
                version: "2".into(),
                code_hash: vec![1; 32],
            },
            memo: "x".into(),
            expedited: true,
        };
        assert!(proposal_transaction(bad).is_err());
    }
}
