//! Core Tenzro Network node implementation

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use tenzro_agent::{AgentRuntime, SwarmManager};
use tenzro_bridge::BridgeRouter;
use tenzro_bridge::chainlink_ccip::{ChainlinkCcipAdapter, CcipConfig, FeeToken};
use tenzro_bridge::debridge::{DeBridgeAdapter, DeBridgeConfig};
use tenzro_bridge::layerzero::{LayerZeroAdapter, LayerZeroConfig};
use tenzro_bridge::lifi::{LiFiAdapter, LiFiConfig};
use tenzro_bridge::wormhole::{GuardianSet, WormholeAdapter, WormholeConfig};
use tenzro_bridge::hyperlane::{HyperlaneAdapter, HyperlaneConfig, HyperlaneValidatorSet};
use tenzro_bridge::axelar::{AxelarAdapter, AxelarConfig, AxelarValidatorSet};
use tenzro_bridge::babylon::{BabylonAdapter, BabylonConfig};
use tenzro_bridge::tnzo_cct::{TnzoCctBridge, TnzoCctRegistry};
use tenzro_bridge::evm_signer::{EvmSignerConfig, EvmTransactionSigner};
use tenzro_consensus::{
    open_default_file_store, ConsensusEngine, ConsensusOutMessage, EquivocationEvidence,
    EpochManager, HotStuff2Engine, SlashingCallback, ValidatorInfo,
};
use tenzro_crypto::{KeyPair, KeyType};
use tenzro_identity::IdentityRegistry;
use tenzro_model::{
    AudioRuntime, DetectionRuntime, ExternalEngine, ExternalEngineKind, HfDownloader,
    InferenceRouter, ModelRegistry, ModelRuntime, MtpKind, ProviderManager, SegmentationRuntime,
    TextEmbeddingRuntime, TextSegmentationRuntime, TimeseriesRuntime, VideoRuntime, VisionRuntime,
};
use tenzro_network::{MessagePayload, NetworkMessage, NetworkService, TenzroNetworkService};
use tenzro_payments::gateway::TenzroPaymentGateway;
use tenzro_payments::mpp::server::MppPaymentServer;
use tenzro_payments::traits::PaymentGateway as PaymentGatewayTrait;
use tenzro_payments::x402::server::X402PaymentServer;
use tenzro_settlement::{
    BatchProcessor, ChannelManager, EscrowManager, FeeCollector, RocksDbChannelStorage,
    SettlementConfig, SettlementEngine, Spec4FillRegistry,
};
use tenzro_storage::{KvStore, RocksDbStore, StorageConfig, CF_MODELS, CF_SKILLS, CF_TOOLS, CF_AGENT_TEMPLATES, CF_MODEL_SERVICES};
use tenzro_tee::{detect_tee, TeeProvider, TeeRegistry};
use tenzro_token::{TnzoToken, StakingManager, GovernanceEngine, NetworkTreasury, TokenRegistry};
use tenzro_types::constants::{CORRELATED_SLASH_BPS, DOUBLE_SIGN_SLASH_BPS};
use tenzro_types::{primitives::Address, RoleSet};
use tenzro_types::block::Block;
use tenzro_types::model::{ModelServiceInstance, ModelLocation, ModelVisibility, ServiceStatus};
use tenzro_vm::{eip1559::FeeMarket, MultiVmRuntime, VmConfig};
use tenzro_wallet::TenzroWalletService;

use crate::config::NodeConfig;
use crate::error::{NodeError, Result};
use crate::event_loop::{EventLoop, NodeBlockProvider, NodeEvent, NodeStateRootProvider};
use crate::health::HealthMonitor;
use crate::metrics::MetricsCollector;

use dashmap::DashMap;
use sha2::{Digest, Sha256};

/// Views retained in the co-offender window used to tell an isolated fault
/// apart from a correlated one.
const CORRELATION_WINDOW_VIEWS: u64 = 16;

/// Bridges the consensus layer's `SlashingCallback` trait to the token layer's `StakingManager`.
///
/// When the consensus engine detects equivocation (a validator voting for conflicting blocks
/// in the same view), it invokes this callback to slash the misbehaving validator's stake.
///
/// The rate depends on how the fault presents. An isolated first offence is
/// charged [`DOUBLE_SIGN_SLASH_BPS`]; a repeat offence by the same validator,
/// or a fault landing in the same window as another validator's, is charged
/// [`CORRELATED_SLASH_BPS`]. A lone operator whose node double-signs once
/// because of a botched failover therefore pays a fraction of what a
/// coordinated set pays.
pub struct StakingSlashingCallback {
    staking: Arc<StakingManager>,
    /// Epoch manager handle. When wired, slashed validators are also dropped
    /// from the next epoch's pending-validator queue so that a punished node
    /// cannot be promoted in the rotation that immediately follows the slash.
    epoch_manager: Option<Arc<EpochManager>>,
    /// Permissionless validator registry. When wired, slashed validators are
    /// also `jail()`ed in the registry so their status flips to `Jailed` and
    /// they cannot be re-promoted by the next epoch transition until the
    /// jail period elapses.
    validator_registry: Option<Arc<tenzro_token::validator_registry::ValidatorRegistry>>,
    /// Offences seen in the last [`CORRELATION_WINDOW_VIEWS`] views, keyed by
    /// view. A second distinct validator faulting inside the window is what
    /// makes an offence correlated rather than isolated.
    recent_offences: DashMap<u64, Vec<Address>>,
}

impl StakingSlashingCallback {
    pub fn new(staking: Arc<StakingManager>) -> Self {
        Self {
            staking,
            epoch_manager: None,
            validator_registry: None,
            recent_offences: DashMap::new(),
        }
    }

    /// Attach an epoch manager so slashed validators are dropped from the
    /// next epoch's pending-validator queue.
    pub fn with_epoch_manager(mut self, epoch_manager: Arc<EpochManager>) -> Self {
        self.epoch_manager = Some(epoch_manager);
        self
    }

    /// Attach the permissionless validator registry so slashed validators are
    /// also flipped to `Jailed` status in the registry.
    pub fn with_validator_registry(
        mut self,
        registry: Arc<tenzro_token::validator_registry::ValidatorRegistry>,
    ) -> Self {
        self.validator_registry = Some(registry);
        self
    }
}

impl StakingSlashingCallback {
    /// Slash a validator that co-signed a ZK commitment whose fraud proof was
    /// upheld. Routes through the shared consensus-offence path (rate-scaled
    /// stake burn + pending-queue drop + registry jail), identical treatment to
    /// equivocation. `height` is the finalized height the fraud was resolved at.
    pub fn report_zk_fraud(&self, validator: &Address, height: u64, reason: String) {
        self.slash_for_consensus_offence(validator, height, reason);
    }

    /// Record the offence and report whether it is correlated with another.
    ///
    /// An offence is correlated when the same validator has been slashed
    /// before, or when a different validator also faulted within
    /// [`CORRELATION_WINDOW_VIEWS`] of this one.
    fn is_correlated(&self, validator: &Address, view: u64) -> bool {
        let floor = view.saturating_sub(CORRELATION_WINDOW_VIEWS);
        self.recent_offences.retain(|seen_view, _| *seen_view >= floor);

        let co_offender = self
            .recent_offences
            .iter()
            .any(|entry| entry.value().iter().any(|other| other != validator));

        self.recent_offences
            .entry(view)
            .or_default()
            .push(*validator);

        let repeat = self
            .staking
            .get_stake(validator)
            .is_some_and(|info| !info.slashing_history.is_empty());

        co_offender || repeat
    }

    /// Shared slash path for consensus offences: burn the rate the offence
    /// earns, drop the validator from the next-epoch pending queue, and jail
    /// them in the permissionless registry.
    fn slash_for_consensus_offence(&self, validator: &Address, view: u64, reason: String) {
        let rate_bps = if self.is_correlated(validator, view) {
            CORRELATED_SLASH_BPS
        } else {
            DOUBLE_SIGN_SLASH_BPS
        };

        let slash_amount = self.staking.get_stake(validator)
            .map(|info| info.amount * rate_bps as u128 / 10_000)
            .unwrap_or(0);

        if slash_amount == 0 {
            tracing::warn!(
                validator = %validator,
                view = view,
                "Consensus offence detected but validator has no stake to slash"
            );
            return;
        }

        match self.staking.slash(validator, slash_amount, reason, Address::default()) {
            Ok(()) => {
                tracing::warn!(
                    validator = %validator,
                    view = view,
                    slash_amount = slash_amount,
                    rate_bps = rate_bps,
                    "Slashed validator for consensus offence"
                );

                // Drop the slashed validator from the next epoch's pending
                // queue if we have an epoch manager handle. Idempotent: a
                // non-pending address is just retained-out as a no-op.
                if let Some(em) = self.epoch_manager.as_ref() {
                    em.remove_pending_validator(validator);
                    tracing::info!(
                        validator = %validator,
                        view = view,
                        "Removed slashed validator from next-epoch pending queue"
                    );

                    // Flip the registry entry to `Jailed` so the next epoch
                    // transition refuses to re-promote them. The current epoch
                    // number drives the jail-until window inside the registry.
                    if let Some(registry) = self.validator_registry.as_ref() {
                        let current_epoch = em.current_epoch().number;
                        match registry.jail(validator, current_epoch) {
                            Ok(()) => {
                                tracing::info!(
                                    validator = %validator,
                                    view = view,
                                    epoch = current_epoch,
                                    "Jailed slashed validator in permissionless registry"
                                );
                            }
                            Err(e) => {
                                // Not fatal: the validator may not be in the
                                // permissionless registry (e.g. genesis-only
                                // validators on early testnet). Slashing already
                                // succeeded; log and move on.
                                tracing::debug!(
                                    validator = %validator,
                                    view = view,
                                    error = %e,
                                    "Could not jail validator in permissionless registry \
                                     (likely genesis-only entry, not registry-tracked)"
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    validator = %validator,
                    view = view,
                    error = %e,
                    "Failed to slash validator for consensus offence"
                );
            }
        }
    }
}

impl SlashingCallback for StakingSlashingCallback {
    fn report_equivocation(
        &self,
        validator: &Address,
        view: u64,
        evidence: &EquivocationEvidence,
    ) {
        let reason = format!(
            "Equivocation in view {}: voted for blocks {} and {}",
            view,
            evidence.vote1.block_hash,
            evidence.vote2.block_hash,
        );
        self.slash_for_consensus_offence(validator, view, reason);
    }

    fn report_proposal_equivocation(
        &self,
        proposer: &Address,
        view: u64,
        evidence: &tenzro_consensus::ProposalEquivocationEvidence,
    ) {
        let reason = format!(
            "Proposal equivocation in view {}: signed blocks {} and {}",
            view,
            evidence.proposal1.block_hash,
            evidence.proposal2.block_hash,
        );
        self.slash_for_consensus_offence(proposer, view, reason);
    }
}

/// Bridges the MPC layer's `MpcSlashingCallback` trait to the token layer's
/// `StakingManager`. Symmetric to [`StakingSlashingCallback`] but driven by
/// admitted MPC abort evidence (see `tenzro_bridge::mpc::abort::admit_evidence`)
/// rather than consensus equivocation.
///
/// By the time `report_abort` is called, the abort packet has already cleared
/// witness-quorum and signature checks — the bridge is the authoritative slash
/// dispatch. A first admitted abort costs [`DOUBLE_SIGN_SLASH_BPS`] of the
/// accused operator's TNZO stake; an operator with a prior slash on record pays
/// [`CORRELATED_SLASH_BPS`], mirroring the equivocation escalation.
///
/// Operator-DID → on-chain Address resolution flows through
/// `IdentityRegistry::resolve(&did).map(|i| i.wallet_address)`. Aborts naming a
/// DID that does not resolve are logged at WARN and dropped (admission cannot
/// see the registry, so a stale/unknown DID is possible).
pub struct MpcAbortSlashingCallback {
    staking: Arc<StakingManager>,
    identity_registry: Arc<IdentityRegistry>,
}

impl MpcAbortSlashingCallback {
    pub fn new(
        staking: Arc<StakingManager>,
        identity_registry: Arc<IdentityRegistry>,
    ) -> Self {
        Self { staking, identity_registry }
    }
}

impl tenzro_bridge::mpc::abort::MpcSlashingCallback for MpcAbortSlashingCallback {
    fn report_abort(&self, evidence: &tenzro_bridge::mpc::abort::MpcAbortEvidence) {
        let accused_did = &evidence.accused_did;

        let operator_address = match self.identity_registry.resolve(accused_did) {
            Ok(identity) => identity.wallet_address,
            Err(e) => {
                tracing::warn!(
                    accused_did = %accused_did,
                    error = %e,
                    "MPC abort evidence references DID that does not resolve in identity registry; dropping"
                );
                return;
            }
        };

        let slash_amount = self
            .staking
            .get_stake(&operator_address)
            .map(|info| {
                let rate_bps = if info.slashing_history.is_empty() {
                    DOUBLE_SIGN_SLASH_BPS
                } else {
                    CORRELATED_SLASH_BPS
                };
                info.amount * rate_bps as u128 / 10_000
            })
            .unwrap_or(0);

        if slash_amount == 0 {
            tracing::warn!(
                accused_did = %accused_did,
                operator = %operator_address,
                category = ?evidence.category,
                "MPC abort admitted but operator has no stake to slash"
            );
            return;
        }

        let reason = format!(
            "MPC identifiable abort: category={:?} severity={:?} context={}",
            evidence.category, evidence.severity, evidence.context,
        );

        match self.staking.slash(&operator_address, slash_amount, reason, Address::default()) {
            Ok(()) => {
                tracing::warn!(
                    accused_did = %accused_did,
                    operator = %operator_address,
                    slash_amount = slash_amount,
                    category = ?evidence.category,
                    "Slashed MPC operator for identifiable abort"
                );
            }
            Err(e) => {
                tracing::error!(
                    accused_did = %accused_did,
                    operator = %operator_address,
                    error = %e,
                    "Failed to slash MPC operator for identifiable abort"
                );
            }
        }
    }
}

/// Bridges the token layer's `ProposalExecutor` trait to the node's actual
/// subsystems. Mirrors `StakingSlashingCallback`: the trait lives in
/// `tenzro-token` so the engine stays free of node-level cross-crate refs;
/// the node-side bridge is the only place that holds the manager handles.
///
/// `GovernanceEngine::execute_proposal` calls `apply_proposal` exactly once
/// after a passed proposal has cleared status checks. The bridge dispatches
/// on `ProposalType` and routes to:
///
/// - `AdaptiveBurnConfigUpdate` → `BurnRateConfigManager::apply_config`
/// - `SupplyTargetsUpdate`      → `BurnRateConfigManager::apply_targets`
/// - `TreasuryGrant`            → `NetworkTreasury::withdraw` (TNZO asset)
/// - `ParameterChange` / `ProtocolUpgrade` / `Custom` → log + accept (these
///   are recorded on-chain but applied externally; e.g. `ProtocolUpgrade`
///   triggers an operator-coordinated rolling restart).
///
/// Returning `Err` from `apply_proposal` leaves the proposal in `Passed` so
/// it can be retried after the operator fixes the underlying cause.
pub struct TenzroProposalExecutor {
    burn_rate: Arc<tenzro_token::adaptive_burn::BurnRateConfigManager>,
    treasury: Arc<NetworkTreasury>,
    /// Caller address used when the executor invokes `NetworkTreasury::withdraw`.
    /// Set to the treasury's own address so the authorization check (which
    /// allows `caller == treasury_address`) passes for governance-driven
    /// transfers. The treasury already enforces its own multisig threshold
    /// internally and rejects withdrawals when `threshold > 1`, so wiring
    /// the executor here doesn't bypass multisig — it just supplies the
    /// authorized caller for the threshold-1 governance path.
    treasury_caller: Address,
    /// Optional SeedAgent earmark manager. When wired, governance
    /// proposals of type `SeedAgentEarmarkUpdate` / `SeedAgentCharterUpsert`
    /// / `SeedAgentStatusSet` (Spec 10) dispatch here. Absent on light
    /// clients that do not initialize the seed-agent subsystem.
    seed_agents: Option<Arc<tenzro_token::seed_agent::SeedAgentEarmarkManager>>,
    /// Optional outbound channel for SeedAgent gossip broadcasts. When
    /// wired, governance-driven mutations (earmark / charter / status
    /// transitions) push a `SeedAgentGossipMessage` onto this channel
    /// after the local mutation succeeds. A separate forwarder task
    /// drains the channel and calls `network.broadcast(...)`. The
    /// channel is unbounded because governance dispatch is rare and
    /// the forwarder always drains in real time.
    seed_agent_broadcast:
        Option<tokio::sync::mpsc::UnboundedSender<tenzro_token::SeedAgentGossipMessage>>,
}

impl TenzroProposalExecutor {
    pub fn new(
        burn_rate: Arc<tenzro_token::adaptive_burn::BurnRateConfigManager>,
        treasury: Arc<NetworkTreasury>,
        treasury_caller: Address,
    ) -> Self {
        Self {
            burn_rate,
            treasury,
            treasury_caller,
            seed_agents: None,
            seed_agent_broadcast: None,
        }
    }

    /// Attach a SeedAgent earmark manager so that the three Spec 10
    /// proposal types are dispatched on `apply_proposal`.
    pub fn with_seed_agents(
        mut self,
        seed_agents: Arc<tenzro_token::seed_agent::SeedAgentEarmarkManager>,
    ) -> Self {
        self.seed_agents = Some(seed_agents);
        self
    }

    /// Attach an outbound channel for SeedAgent gossip broadcasts so that
    /// governance-driven mutations propagate to peers on
    /// `tenzro/seed-agents` after the local mutation succeeds. The
    /// receiver half is owned by a forwarder task spawned in
    /// `init_event_loop` that calls `network.broadcast(...)` for each
    /// message. Sends are non-blocking; channel-closed errors are logged
    /// but do not fail the proposal.
    pub fn with_seed_agent_broadcast(
        mut self,
        tx: tokio::sync::mpsc::UnboundedSender<tenzro_token::SeedAgentGossipMessage>,
    ) -> Self {
        self.seed_agent_broadcast = Some(tx);
        self
    }
}

impl tenzro_token::governance::ProposalExecutor for TenzroProposalExecutor {
    fn apply_proposal(
        &self,
        proposal: &tenzro_types::token::GovernanceProposal,
    ) -> tenzro_token::error::Result<()> {
        use tenzro_types::token::ProposalType;

        match &proposal.proposal_type {
            ProposalType::AdaptiveBurnConfigUpdate {
                base_fee_burn_bps,
                local_fee_burn_bps,
                paymaster_burn_bps,
            } => {
                let new_config = tenzro_token::adaptive_burn::BurnRateConfig {
                    base_fee_burn_bps: *base_fee_burn_bps,
                    local_fee_burn_bps: *local_fee_burn_bps,
                    paymaster_burn_bps: *paymaster_burn_bps,
                };
                self.burn_rate.apply_config(new_config)?;
                info!(
                    proposal_id = %proposal.proposal_id,
                    "Applied AdaptiveBurnConfigUpdate via governance"
                );
                Ok(())
            }
            ProposalType::SupplyTargetsUpdate {
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
                alarm_timelock_hours,
            } => {
                // Preserve the existing `enabled` flag — it's a separate
                // governance-controlled kill switch with its own proposal
                // shape (or operator override). `SupplyTargetsUpdate`
                // proposals only adjust the parametric knobs.
                let current = self.burn_rate.targets();
                let new_targets = tenzro_token::adaptive_burn::SupplyTargets {
                    enabled: current.enabled,
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
                    alarm_timelock_hours: *alarm_timelock_hours,
                };
                self.burn_rate.apply_targets(new_targets)?;
                info!(
                    proposal_id = %proposal.proposal_id,
                    "Applied SupplyTargetsUpdate via governance"
                );
                Ok(())
            }
            ProposalType::TreasuryGrant { recipient, amount } => {
                // Withdraw from the treasury under the authorized governance
                // caller. The recipient receives funds via a follow-up
                // settlement transaction emitted by the treasury's withdraw
                // path; for now we record the grant by debiting the treasury
                // balance. The recipient field is logged for downstream
                // payout reconciliation.
                let asset_id = tenzro_types::AssetId::tnzo();
                self.treasury
                    .withdraw(&asset_id, *amount, &self.treasury_caller)?;
                info!(
                    proposal_id = %proposal.proposal_id,
                    recipient = %recipient,
                    amount = amount,
                    "Applied TreasuryGrant via governance"
                );
                Ok(())
            }
            ProposalType::ParameterChange { parameter, new_value } => {
                // Generic parameter changes are recorded on-chain but the
                // actual subsystem applying them must subscribe to the
                // governance event stream (e.g. fee market params, mempool
                // limits). The status flip to `Executed` here makes the
                // change canonical.
                info!(
                    proposal_id = %proposal.proposal_id,
                    parameter = %parameter,
                    new_value = %new_value,
                    "Applied ParameterChange via governance (consumer-side dispatch)"
                );
                Ok(())
            }
            ProposalType::ProtocolUpgrade { version, code_hash } => {
                // Protocol upgrades are operator-coordinated: the proposal
                // status flip to `Executed` is the on-chain signal; the
                // actual binary swap happens via a rolling restart on the
                // K8s side. Log the version + hash for the operator audit
                // trail.
                info!(
                    proposal_id = %proposal.proposal_id,
                    version = %version,
                    code_hash = ?code_hash,
                    "Applied ProtocolUpgrade via governance (operator rollout follows)"
                );
                Ok(())
            }
            ProposalType::SeedAgentEarmarkUpdate {
                enabled,
                allocation_topup_wei,
                is_initial_seed,
                surplus_burn_bps,
            } => {
                let Some(seed_agents) = &self.seed_agents else {
                    return Err(tenzro_token::error::TokenError::InvalidParameter(
                        "SeedAgentEarmarkUpdate proposal but seed-agent manager not wired"
                            .into(),
                    ));
                };
                if *surplus_burn_bps > 10_000 {
                    return Err(tenzro_token::error::TokenError::InvalidParameter(
                        format!("surplus_burn_bps {} > 10000", surplus_burn_bps),
                    ));
                }
                let mut next = seed_agents.earmark();
                next.enabled = *enabled;
                next.surplus_burn_bps = *surplus_burn_bps;
                next.allocation_remaining_wei = next
                    .allocation_remaining_wei
                    .saturating_add(*allocation_topup_wei);
                if *is_initial_seed {
                    next.initial_allocation_wei = next
                        .initial_allocation_wei
                        .saturating_add(*allocation_topup_wei);
                }
                seed_agents.apply_earmark(next.clone())?;
                info!(
                    proposal_id = %proposal.proposal_id,
                    enabled,
                    allocation_topup_wei,
                    is_initial_seed,
                    surplus_burn_bps,
                    "Applied SeedAgentEarmarkUpdate via governance"
                );
                if let Some(tx) = &self.seed_agent_broadcast
                    && let Err(e) = tx.send(
                        tenzro_token::SeedAgentGossipMessage::EarmarkUpdated(next),
                    )
                {
                    tracing::warn!(
                        proposal_id = %proposal.proposal_id,
                        error = %e,
                        "Failed to enqueue SeedAgent EarmarkUpdated gossip"
                    );
                }
                Ok(())
            }
            ProposalType::SeedAgentCharterUpsert { charter_blob } => {
                let Some(seed_agents) = &self.seed_agents else {
                    return Err(tenzro_token::error::TokenError::InvalidParameter(
                        "SeedAgentCharterUpsert proposal but seed-agent manager not wired"
                            .into(),
                    ));
                };
                let charter: tenzro_token::seed_agent::Charter =
                    bincode::deserialize(charter_blob).map_err(|e| {
                        tenzro_token::error::TokenError::InvalidParameter(format!(
                            "decode charter blob: {}",
                            e
                        ))
                    })?;
                let charter_id = charter.charter_id;
                let name = charter.name.clone();
                let charter_for_gossip = charter.clone();
                seed_agents.upsert_charter(charter)?;
                info!(
                    proposal_id = %proposal.proposal_id,
                    charter_id = ?charter_id,
                    name = %name,
                    "Applied SeedAgentCharterUpsert via governance"
                );
                if let Some(tx) = &self.seed_agent_broadcast
                    && let Err(e) = tx.send(
                        tenzro_token::SeedAgentGossipMessage::CharterUpserted(
                            charter_for_gossip,
                        ),
                    )
                {
                    tracing::warn!(
                        proposal_id = %proposal.proposal_id,
                        charter_id = ?charter_id,
                        error = %e,
                        "Failed to enqueue SeedAgent CharterUpserted gossip"
                    );
                }
                Ok(())
            }
            ProposalType::SeedAgentStatusSet { agent_did, status } => {
                let Some(seed_agents) = &self.seed_agents else {
                    return Err(tenzro_token::error::TokenError::InvalidParameter(
                        "SeedAgentStatusSet proposal but seed-agent manager not wired"
                            .into(),
                    ));
                };
                use tenzro_token::seed_agent::SeedAgentStatus;
                let target = match status.as_str() {
                    "active" => SeedAgentStatus::Active,
                    "paused" => SeedAgentStatus::Paused,
                    "quarantined" => SeedAgentStatus::Quarantined,
                    "terminated" => SeedAgentStatus::Terminated,
                    other => {
                        return Err(tenzro_token::error::TokenError::InvalidParameter(
                            format!("unknown SeedAgent status '{}'", other),
                        ));
                    }
                };
                seed_agents.set_agent_status(agent_did, target)?;
                info!(
                    proposal_id = %proposal.proposal_id,
                    agent_did = %agent_did,
                    status = %status,
                    "Applied SeedAgentStatusSet via governance"
                );
                if let Some(tx) = &self.seed_agent_broadcast
                    && let Err(e) = tx.send(
                        tenzro_token::SeedAgentGossipMessage::AgentStatusChanged {
                            agent_did: agent_did.clone(),
                            status: target,
                        },
                    )
                {
                    tracing::warn!(
                        proposal_id = %proposal.proposal_id,
                        agent_did = %agent_did,
                        error = %e,
                        "Failed to enqueue SeedAgent AgentStatusChanged gossip"
                    );
                }
                Ok(())
            }
            ProposalType::Custom { proposal_data } => {
                info!(
                    proposal_id = %proposal.proposal_id,
                    payload_len = proposal_data.len(),
                    "Applied Custom proposal via governance (opaque payload recorded)"
                );
                Ok(())
            }
        }
    }
}

/// Node-level validator registry that implements the network's ValidatorRegistry trait.
///
/// This registry maintains a mapping of PeerIds to validator status. Validators are
/// registered when the node starts (for the local validator) and when peers identify
/// themselves as validators via the identify protocol. In single-node / testnet mode,
/// the local validator PeerId is automatically registered.
///
/// The registry is designed to be dynamically updated as the validator set changes
/// across epochs.
pub struct NodeValidatorRegistry {
    /// Set of PeerIds known to be active validators
    validator_peers: DashMap<libp2p::PeerId, ()>,
    /// Validator identity Ed25519 public keys seeded from the genesis
    /// validator set. Used as the identity check for peers whose signed
    /// PeerId↔identity binding arrives before (or without) a live consensus
    /// engine — e.g. on non-validator nodes that still gate validator-only
    /// gossip topics.
    genesis_identities: DashMap<Vec<u8>, ()>,
    /// Live epoch manager handle, installed once consensus is initialized.
    /// When present, identity checks consult the CURRENT epoch validator set
    /// so that validators admitted after genesis (stake-based joins) are
    /// recognized and validators rotated out stop being admitted.
    epoch_manager: parking_lot::RwLock<Option<Arc<EpochManager>>>,
    /// Validator-address → PeerId registry for the committee-DA surface.
    /// Populated at the same admission point as `validator_peers`: when a
    /// peer's signed PeerId↔validator-identity binding verifies, the matching
    /// validator's on-chain address is bound to its PeerId so the committee-DA
    /// backend can resolve a committee index (→ address) to the peer to dial.
    /// `None` until the committee-DA subsystem installs it at startup.
    da_peer_registry:
        parking_lot::RwLock<Option<Arc<crate::da_committee_surface::AddressPeerRegistry>>>,
}

impl Default for NodeValidatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeValidatorRegistry {
    /// Creates a new empty validator registry
    pub fn new() -> Self {
        Self {
            validator_peers: DashMap::new(),
            genesis_identities: DashMap::new(),
            epoch_manager: parking_lot::RwLock::new(None),
            da_peer_registry: parking_lot::RwLock::new(None),
        }
    }

    /// Registers a PeerId as a known validator
    pub fn add_validator(&self, peer_id: libp2p::PeerId) {
        self.validator_peers.insert(peer_id, ());
        tracing::info!(peer = %peer_id, "Registered validator peer");
    }

    /// Seeds a validator identity Ed25519 public key (from genesis config).
    pub fn add_identity(&self, ed25519_pubkey: Vec<u8>) {
        self.genesis_identities.insert(ed25519_pubkey, ());
    }

    /// Installs the live epoch manager so identity checks track the current
    /// epoch validator set instead of the static genesis set.
    pub fn set_epoch_manager(&self, epoch_manager: Arc<EpochManager>) {
        *self.epoch_manager.write() = Some(epoch_manager);
    }

    /// Installs the committee-DA address→PeerId registry so verified validator
    /// admissions also record the address↔PeerId binding the committee-DA
    /// surface needs to dial members.
    pub fn set_da_peer_registry(
        &self,
        registry: Arc<crate::da_committee_surface::AddressPeerRegistry>,
    ) {
        *self.da_peer_registry.write() = Some(registry);
    }

    /// Record the `(validator_address, peer_id)` binding for the committee-DA
    /// surface, resolving the address from the current epoch validator set by
    /// matching the admitted Ed25519 pubkey. Using the validator set's own
    /// stored address avoids re-deriving it (and thus avoids any address-
    /// convention mismatch): the committee-DA `CommitteeView` reads the same
    /// `ValidatorInfo.address`, so registry key and lookup key are identical.
    fn record_da_peer(&self, peer_id: &libp2p::PeerId, validator_pubkey: &[u8]) {
        let Some(registry) = self.da_peer_registry.read().as_ref().cloned() else {
            return;
        };
        let Some(epoch_manager) = self.epoch_manager.read().as_ref().cloned() else {
            return;
        };
        let epoch = epoch_manager.current_epoch();
        if let Some(v) = epoch
            .validator_set
            .iter()
            .find(|v| v.is_active() && v.public_key.as_bytes() == validator_pubkey)
        {
            registry.insert(v.address, *peer_id);
        }
    }

    /// Removes a PeerId from the validator set.
    ///
    /// Called by the network layer's `try_remove_validator` (via the
    /// `ValidatorRegistry` trait) when a peer is banned for misbehavior, and
    /// can also be called directly on epoch rotation or governance-driven
    /// validator removal.
    pub fn remove_validator(&self, peer_id: &libp2p::PeerId) {
        if self.validator_peers.remove(peer_id).is_some() {
            tracing::info!(peer = %peer_id, "Removed validator peer");
        }
    }
}

impl tenzro_network::ValidatorRegistry for NodeValidatorRegistry {
    fn is_validator(&self, peer_id: &libp2p::PeerId) -> bool {
        self.validator_peers.contains_key(peer_id)
    }

    fn validator_peer_ids(&self) -> std::collections::HashSet<libp2p::PeerId> {
        self.validator_peers.iter().map(|entry| *entry.key()).collect()
    }

    /// Checks whether an Ed25519 public key belongs to an active validator
    /// identity. Consults the live epoch validator set when consensus is
    /// running (so stake-based joins and rotations are tracked), falling
    /// back to the genesis validator identities otherwise.
    fn is_validator_identity(&self, ed25519_pubkey: &[u8]) -> bool {
        if let Some(epoch_manager) = self.epoch_manager.read().as_ref() {
            let epoch = epoch_manager.current_epoch();
            return epoch
                .validator_set
                .iter()
                .any(|v| v.is_active() && v.public_key.as_bytes() == ed25519_pubkey);
        }
        self.genesis_identities.contains_key(ed25519_pubkey)
    }

    /// Dynamically admit a peer as a validator after the network layer has
    /// verified its signed PeerId↔validator-identity binding. This closes
    /// the "mutual ban" gap where peers that come online after the static
    /// boot-node list was wired would never be admitted to validator topics
    /// (consensus / attestations), resulting in their messages being
    /// rejected and their gossipsub peer-score decaying below the graylist
    /// threshold.
    ///
    /// The network layer only calls this after verifying the binding
    /// signature over the transport-authenticated PeerId AND checking
    /// `is_validator_identity`; the identity membership is re-checked here
    /// as defense in depth.
    fn try_add_validator(&self, peer_id: &libp2p::PeerId, validator_pubkey: &[u8]) {
        if !self.is_validator_identity(validator_pubkey) {
            tracing::warn!(
                peer = %peer_id,
                "Refusing validator admission: pubkey not in active validator set"
            );
            return;
        }
        if !self.validator_peers.contains_key(peer_id) {
            self.validator_peers.insert(*peer_id, ());
            tracing::info!(
                peer = %peer_id,
                "Registered validator peer via verified identity binding"
            );
        }
        self.record_da_peer(peer_id, validator_pubkey);
    }

    /// Remove a peer from the validator set when it has been banned by the
    /// peer manager. Mirrors `try_add_validator` so authorization stays
    /// consistent with peer admission state.
    fn try_remove_validator(&self, peer_id: &libp2p::PeerId) {
        self.remove_validator(peer_id);
    }
}

/// Durable peer-ban store backed by RocksDB (`CF_METADATA`, `peer_ban:` prefix).
///
/// Bans survive node restarts: the peer manager hydrates active bans on
/// startup and re-blocks them at the libp2p transport layer, so a misbehaving
/// peer cannot escape its ban window by waiting for an operator restart.
/// Values are the ban-expiry wall-clock time as 8-byte little-endian Unix
/// seconds (`Instant` is monotonic-only and cannot cross process restarts).
pub struct NodeBanStore {
    storage: Arc<dyn KvStore>,
}

const PEER_BAN_KEY_PREFIX: &str = "peer_ban:";

impl NodeBanStore {
    pub fn new(storage: Arc<dyn KvStore>) -> Self {
        Self { storage }
    }

    fn key(peer_id: &libp2p::PeerId) -> String {
        format!("{}{}", PEER_BAN_KEY_PREFIX, peer_id)
    }
}

impl tenzro_network::BanStore for NodeBanStore {
    fn record_ban(&self, peer_id: &libp2p::PeerId, until_unix_secs: u64) {
        if let Err(e) = self.storage.put(
            tenzro_storage::CF_METADATA,
            Self::key(peer_id).as_bytes(),
            &until_unix_secs.to_le_bytes(),
        ) {
            warn!(peer = %peer_id, "Failed to persist peer ban: {}", e);
        }
    }

    fn remove_ban(&self, peer_id: &libp2p::PeerId) {
        if let Err(e) = self
            .storage
            .delete(tenzro_storage::CF_METADATA, Self::key(peer_id).as_bytes())
        {
            warn!(peer = %peer_id, "Failed to remove persisted peer ban: {}", e);
        }
    }

    fn load_bans(&self) -> Vec<(libp2p::PeerId, u64)> {
        let entries = match self.storage.scan_prefix(
            tenzro_storage::CF_METADATA,
            PEER_BAN_KEY_PREFIX.as_bytes(),
        ) {
            Ok(entries) => entries,
            Err(e) => {
                warn!("Failed to list persisted peer bans: {}", e);
                return Vec::new();
            }
        };
        let mut bans = Vec::new();
        for (key, value) in entries {
            let Ok(key_str) = std::str::from_utf8(&key) else {
                continue;
            };
            let Some(peer_str) = key_str.strip_prefix(PEER_BAN_KEY_PREFIX) else {
                continue;
            };
            let (Ok(peer_id), Ok(until)) = (
                peer_str.parse::<libp2p::PeerId>(),
                <[u8; 8]>::try_from(value.as_slice()).map(u64::from_le_bytes),
            ) else {
                warn!(key = %key_str, "Dropping malformed persisted peer ban");
                let _ = self.storage.delete(tenzro_storage::CF_METADATA, &key);
                continue;
            };
            bans.push((peer_id, until));
        }
        bans
    }
}

/// Gas limit stamped on the system-signed `X402Settle` tx. The privileged VM
/// handler consumes `GAS_X402_SETTLE` (40k); this leaves headroom for the
/// intrinsic/nonce bookkeeping without over-reserving.
const GAS_X402_SETTLE_TX_LIMIT: u64 = 100_000;

/// Gas price for the settle tx. The system address carries no registered DID, so
/// admission lands it in the Open lane, whose fee floor is
/// `mempool_min_gas_price (1 gwei) × open_floor_mult (4.0)` = 4 gwei. The fee is
/// paid back to the treasury from the system account, so it nets to a
/// book-keeping no-op for the operator — same rationale as the faucet.
const X402_SETTLE_GAS_PRICE: u64 = 4_000_000_000;

/// Bridges the payment gateway's `SettlementCallback` to the settlement layer.
///
/// For TNZO-denominated x402/MPP/Visa-TAP settlements, the payer→payee balance
/// move is executed **consensus-mediated** — the callback builds a system-key
/// signed `TransactionType::X402Settle` and submits it through `HotStuff2Engine`,
/// so the transfer lands in a finalized block and executes through
/// `MultiVmRuntime` (privileged `SELECTOR_X402_SETTLE`, payer→payee authorized
/// by on-chain state + a `payment_id` replay guard). The returned string is the
/// real in-block tx hash — settlement is final after the block that carries it.
///
/// The `SettlementEngine` record is audit-only; it never holds balance authority.
///
/// Non-TNZO assets (external chains via Coinbase CDP / EIP-3009 / Permit2) are
/// left to their own settlement paths and only recorded here.
pub struct TnzoSettlementCallback {
    /// HotStuff-2 handle for admitting the signed settlement tx.
    consensus: Arc<HotStuff2Engine>,
    /// Composite (Ed25519 + ML-DSA-65) signer for the system/validator key.
    hybrid_signer: Arc<dyn tenzro_crypto::composite::HybridSigner>,
    /// System address paying gas and authoring the privileged settle tx.
    system_addr: Address,
    /// Read-through to VM execution state for the system-address nonce floor.
    storage: Arc<dyn tenzro_storage::KvStore>,
    /// Genesis chain id stamped into the signed tx.
    chain_id: u64,
    /// Monotonic in-memory nonce counter, floored by the VM-state nonce so
    /// concurrent settlements within the same unfinalized window get distinct
    /// slots. Mirrors the faucet's `wallet_service.next_nonce` discipline.
    next_nonce: Arc<parking_lot::Mutex<u64>>,
    /// Gossip fan-out for the admitted tx. Populated after the event loop
    /// starts (`init_event_loop` runs later than `init_payments`, so this is
    /// injected out-of-band via [`Self::event_sender_slot`]). Absent it, the tx
    /// is still admitted to the local mempool but not gossiped.
    event_sender: Arc<parking_lot::Mutex<Option<mpsc::Sender<NodeEvent>>>>,
    /// Audit-only settlement receipt store (never balance authority).
    settlement_engine: Arc<SettlementEngine>,
    /// Provider-reputation ledger. A successful settle is the ONLY score-up
    /// path (+1, ceiling 1000) — the anti-self-deal invariant that makes
    /// Bazaar reputation ranking meaningful. `None` on nodes without the
    /// AI-infrastructure subsystem; the record is then skipped.
    provider_manager: Option<Arc<tenzro_model::ProviderManager>>,
}

impl TnzoSettlementCallback {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        consensus: Arc<HotStuff2Engine>,
        hybrid_signer: Arc<dyn tenzro_crypto::composite::HybridSigner>,
        system_addr: Address,
        storage: Arc<dyn tenzro_storage::KvStore>,
        chain_id: u64,
        settlement_engine: Arc<SettlementEngine>,
        provider_manager: Option<Arc<tenzro_model::ProviderManager>>,
    ) -> Self {
        Self {
            consensus,
            hybrid_signer,
            system_addr,
            storage,
            chain_id,
            next_nonce: Arc::new(parking_lot::Mutex::new(0)),
            event_sender: Arc::new(parking_lot::Mutex::new(None)),
            settlement_engine,
            provider_manager,
        }
    }

    /// Shared handle for injecting the event-loop sender once the loop has
    /// started. `init_payments` builds the callback before `init_event_loop`
    /// exists, so `start()` clones this slot and fills it after the sender is
    /// available.
    pub fn event_sender_slot(&self) -> Arc<parking_lot::Mutex<Option<mpsc::Sender<NodeEvent>>>> {
        self.event_sender.clone()
    }

    /// Reserve the next nonce for the system address. Takes the VM-state nonce
    /// (the value `MultiVmRuntime` validates against) as the floor and returns
    /// `max(vm_state_nonce, in_memory_counter)`, advancing the counter. The
    /// VM-state read is authoritative across restarts; the in-memory counter
    /// distinguishes concurrent same-window settlements.
    fn reserve_nonce(&self) -> u64 {
        let chain_nonce = {
            let state = tenzro_vm::StateAdapter::with_storage(self.storage.clone());
            use tenzro_vm::traits::VmState as _;
            state.get_nonce(self.system_addr.as_bytes())
        };
        let mut guard = self.next_nonce.lock();
        let reserved = (*guard).max(chain_nonce);
        *guard = reserved + 1;
        reserved
    }
}

#[async_trait::async_trait]
impl tenzro_payments::gateway::SettlementCallback for TnzoSettlementCallback {
    async fn settle_on_chain(
        &self,
        payer: &[u8],
        payee: &[u8],
        amount: u128,
        asset: &str,
        receipt_id: &str,
        app_wallet: Option<&[u8]>,
        margin_bps: u32,
    ) -> std::result::Result<String, tenzro_payments::PaymentError> {
        use tenzro_types::primitives::{ChainId, Nonce, Signature};
        use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};

        // Convert byte slices to 32-byte Address
        let payer_addr = bytes_to_address(payer);
        let payee_addr = bytes_to_address(payee);
        let app_wallet_addr = app_wallet.map(bytes_to_address);

        // TNZO settlements move balance consensus-mediated: a system-key signed
        // `X402Settle` tx that executes through MultiVmRuntime in a finalized
        // block. The returned string is the real in-block tx hash. Non-TNZO
        // assets fall through to audit-only recording (their own settlement
        // path already moved value on the foreign chain).
        let onchain_tx_hash = if asset == "TNZO" || asset == "tnzo" {
            let nonce = self.reserve_nonce();
            let tx = Transaction::new(
                ChainId::from(self.chain_id),
                self.system_addr,
                payee_addr,
                Nonce::from(nonce),
                TransactionType::X402Settle {
                    payer: payer_addr,
                    payee: payee_addr,
                    amount,
                    payment_id: receipt_id.to_string(),
                    app_wallet: app_wallet_addr,
                    margin_bps,
                },
                GAS_X402_SETTLE_TX_LIMIT,
                X402_SETTLE_GAS_PRICE,
                self.hybrid_signer.public_key().pq.clone(),
            );
            let tx_hash = tx.hash();

            let composite = self.hybrid_signer.sign(tx_hash.as_bytes()).map_err(|e| {
                tenzro_payments::PaymentError::SettlementError(format!(
                    "x402 settle signing failed: {}",
                    e
                ))
            })?;
            let classical_pubkey = self.hybrid_signer.public_key().classical.as_bytes().to_vec();
            let signed_tx = SignedTransaction::new(
                tx,
                Signature::new(composite.classical, classical_pubkey),
                composite.pq,
            );
            let in_block_hash = signed_tx.clone().hash();
            let hash_str = format!("{}", in_block_hash);

            // Admit synchronously so fee-floor / rate-limit rejections surface
            // here, then fan the tx out for gossip via LocallyAdmittedTransaction.
            self.consensus
                .submit_transaction(signed_tx.clone())
                .map_err(|e| {
                    tenzro_payments::PaymentError::SettlementError(format!(
                        "x402 settle rejected by consensus mempool: {}",
                        e
                    ))
                })?;

            let sender = self.event_sender.lock().clone();
            if let Some(sender) = sender
                && let Err(e) = sender
                    .send(NodeEvent::LocallyAdmittedTransaction(signed_tx))
                    .await
            {
                warn!(
                    "x402 settle admitted but gossip enqueue failed (tx {}): {}",
                    hash_str, e
                );
            }

            info!(
                "x402 TNZO settlement admitted consensus-mediated: payment_id={}, tx={}, amount={}",
                receipt_id, hash_str, amount
            );
            Some(hash_str)
        } else {
            None
        };

        // Record in the settlement engine for auditing only — never balance
        // authority. A recording failure does not undo the on-chain settle.
        use tenzro_types::settlement::{
            ProofType, ServiceProof, ServiceType, SettlementRequest,
        };
        let proof = ServiceProof::new(ProofType::Cryptographic, receipt_id.as_bytes().to_vec());
        let request = SettlementRequest::new(
            payee_addr,
            payer_addr,
            ServiceType::HttpPayment {
                protocol: asset.to_string(),
                resource: receipt_id.to_string(),
            },
            // SettlementRequest.amount is u64; clamp to u64::MAX for very large values
            amount.min(u64::MAX as u128) as u64,
            proof,
        );

        if let Err(e) = self.settlement_engine.settle(request).await {
            warn!("Settlement engine audit-record failed for {}: {}", receipt_id, e);
        }

        // Settled payment → provider reputation. This is the only score-up
        // path on the ledger; no-op for payees without a provider record.
        if let Some(pm) = &self.provider_manager {
            pm.record_settled_success(&payee_addr, amount);
        }

        // Prefer the real in-block tx hash for TNZO; for external assets the
        // receipt id is the settlement reference.
        Ok(onchain_tx_hash.unwrap_or_else(|| receipt_id.to_string()))
    }
}

/// Helper: convert a variable-length byte slice to a 32-byte `Address`.
/// Left-pads with zeros if shorter, truncates from the right if longer.
fn bytes_to_address(bytes: &[u8]) -> Address {
    let mut buf = [0u8; 32];
    let len = bytes.len().min(32);
    // Right-align the bytes (zero-pad on the left)
    buf[32 - len..].copy_from_slice(&bytes[..len]);
    Address(buf)
}

/// Decode hex-encoded 20-byte EVM-style addresses for inbound bridge
/// verifier sets (LayerZero DVN, CCIP committee + RMN, deBridge DLN).
/// Accepts an optional `0x` prefix. Returns a single error string
/// naming the first malformed entry so the operator can fix their
/// config before retrying.
fn decode_verifier_addresses(hex_addrs: &[String]) -> std::result::Result<Vec<[u8; 20]>, String> {
    let mut out = Vec::with_capacity(hex_addrs.len());
    for (i, raw) in hex_addrs.iter().enumerate() {
        let cleaned = raw.trim_start_matches("0x").trim_start_matches("0X");
        let bytes = hex::decode(cleaned)
            .map_err(|e| format!("address #{i} '{raw}' is not valid hex: {e}"))?;
        if bytes.len() != 20 {
            return Err(format!(
                "address #{i} '{raw}' is {} bytes (expected 20)",
                bytes.len()
            ));
        }
        let mut a = [0u8; 20];
        a.copy_from_slice(&bytes);
        out.push(a);
    }
    Ok(out)
}

/// Build a `ModelInfo` record describing a Cortex recurrent-depth worker so
/// it can be published in the shared `ModelRegistry` catalog. Pricing is
/// mapped from the worker's `CortexPricing` (per-input/per-output tokens, all
/// in wei) and Cortex-specific parameters (`price_per_loop_wei`,
/// `base_request_fee_wei`, tiers, max_loops) are stashed in `metadata` for
/// discovery clients.
pub(crate) fn cortex_model_info(
    model_id: &str,
    worker: &Arc<tenzro_cortex::CortexWorker>,
    arch_label: &str,
) -> tenzro_types::model::ModelInfo {
    use tenzro_types::model::{
        ModalityRates, ModelInfo, ModelModality, ModelParameters, ModelStatus, MoeMetadata,
        MoeRoutingStrategy, PricingConfig, PricingModel,
    };

    let pricing = worker.pricing();
    let family = worker.backend().family();

    let mut metadata = std::collections::HashMap::new();
    metadata.insert("tier".to_string(), "cortex".to_string());
    metadata.insert("arch".to_string(), arch_label.to_string());
    metadata.insert("max_loops".to_string(), family.max_loops.to_string());
    metadata.insert("moe_experts".to_string(), family.moe_experts.to_string());
    metadata.insert(
        "experts_per_token".to_string(),
        family.experts_per_token.to_string(),
    );
    metadata.insert("attn_type".to_string(), family.attn_type.clone());
    metadata.insert(
        "price_per_loop_wei".to_string(),
        pricing.price_per_loop_wei.to_string(),
    );
    metadata.insert(
        "base_request_fee_wei".to_string(),
        pricing.base_request_fee_wei.to_string(),
    );
    metadata.insert("tee_premium_wei".to_string(), pricing.tee_premium_wei.to_string());
    metadata.insert("zk_premium_wei".to_string(), pricing.zk_premium_wei.to_string());
    metadata.insert(
        "worker_did".to_string(),
        worker.worker_did().to_string(),
    );

    let mut info = ModelInfo::new(
        model_id.to_string(),
        format!("Tenzro Cortex — {}", model_id),
        "0.1.0".to_string(),
        ModelModality::Text,
        worker.worker_address(),
    );
    // Cortex workers run behind a sidecar and have no downloadable weights
    // artifact, but the registry rejects zero hashes. Bind a deterministic
    // identity hash over the model id + worker DID instead — nothing fetches
    // Cortex weights through the download manager, so this hash never
    // reaches per-artifact integrity verification.
    info.model_hash = {
        let mut hasher = Sha256::new();
        hasher.update(b"tenzro/model/cortex-identity");
        hasher.update(model_id.as_bytes());
        hasher.update(worker.worker_did().as_bytes());
        tenzro_types::Hash::new(hasher.finalize().into())
    };
    info.description = format!(
        "Recurrent-depth reasoning worker (arch={}, max_loops={}).",
        arch_label, family.max_loops
    );
    info.architecture = arch_label.to_string();
    info.parameters = ModelParameters {
        parameter_count: None,
        context_window: 8192,
        max_output_tokens: 4096,
        input_formats: vec!["text".to_string()],
        output_formats: vec!["text".to_string()],
        capabilities: vec![
            "reasoning".to_string(),
            "recurrent-depth".to_string(),
            "cortex".to_string(),
        ],
        // Text-only, so the geometry descriptor stays at its default and is
        // never consulted.
        ..Default::default()
    };
    info.pricing = PricingConfig {
        price_per_input_token: pricing.price_per_input_token_wei,
        price_per_output_token: pricing.price_per_output_token_wei,
        minimum_price: pricing.base_request_fee_wei,
        pricing_model: PricingModel::PerToken,
        // A reasoning worker charges per recurrent loop, so the catalog quote a
        // caller reads carries the same loop rate the worker settles on. The
        // remaining dimensions are unpriced rather than defaulted: cortex is
        // text-only, and these rates are wei while the defaults are nominal.
        modality_rates: ModalityRates {
            price_per_request: pricing.base_request_fee_wei,
            price_per_reasoning_loop: pricing.price_per_loop_wei,
            ..ModalityRates::unpriced()
        },
    };
    info.status = ModelStatus::Active;
    info.metadata = metadata;
    if family.moe_experts > 0 && family.experts_per_token > 0 {
        let mut moe = MoeMetadata::new(
            family.moe_experts,
            family.experts_per_token as u8,
            MoeRoutingStrategy::TopK,
        );
        if !family.attn_type.is_empty() {
            moe = moe.with_attention_type(family.attn_type.clone());
        }
        info.moe = Some(moe);
    }
    info
}

/// Hardware profile detected from the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProfile {
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub cpu_threads: usize,
    pub total_ram_gb: f64,
    pub gpus: Vec<tenzro_types::hardware::GpuDevice>,
    pub storage_available_gb: f64,
    pub tee_available: bool,
    pub tee_vendor: Option<String>,
    pub os: String,
    pub arch: String,
    pub device_fingerprint: String,
}

/// Provider scheduling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSchedule {
    pub enabled: bool,
    pub start_hour: u8,
    pub end_hour: u8,
    pub timezone: String,
    pub days_of_week: [bool; 7], // Mon-Sun
}

impl Default for ProviderSchedule {
    fn default() -> Self {
        Self {
            enabled: false,
            start_hour: 0,
            end_hour: 24,
            timezone: "UTC".to_string(),
            days_of_week: [true; 7],
        }
    }
}

/// Default storage byte-epoch rate (wei) a freshly-spawned storage provider
/// charges before any operator override or dynamic-pricing switch. 1000 wei per
/// byte-epoch ≈ 0.001 TNZO to store 1 GiB for one epoch.
pub const DEFAULT_STORAGE_RATE_PER_BYTE_EPOCH: u128 = 1_000;

/// Default compute per-epoch rate (wei) a freshly-spawned compute provider
/// charges before any operator override or dynamic-pricing switch.
pub const DEFAULT_COMPUTE_RATE_PER_EPOCH: u128 = 1_000_000_000_000;

/// Interval between provider billing epochs. Each tick streams one epoch's
/// slice of every active storage deal + compute rental this node provides (PoR-
/// / availability-gated), then persists the prepaid ledger. One hour balances
/// settlement latency against the per-epoch pricing granularity.
pub const BILLING_EPOCH_INTERVAL_SECS: u64 = 3_600;

/// Interval between DvP saga expiry sweeps. Each tick compensates and expires
/// every Open/Executing saga past its deadline so a stalled counterparty can
/// not pin escrowed funds indefinitely. Five minutes bounds the worst-case
/// delay between a saga's deadline and its refund without polling escrow state
/// too aggressively.
pub const SAGA_EXPIRY_SWEEP_INTERVAL_SECS: u64 = 300;

/// Interval between app-hosting placement reconciles. Each tick sweeps expired
/// leases and evicts any serving node whose provider announcement has gone stale
/// (dropped off `tenzro/status`), re-letting its replica slot over the surviving
/// candidates. Thirty seconds bounds the failover delay after a host stops
/// announcing without polling the announcement map too aggressively.
pub const PLACEMENT_RECONCILE_INTERVAL_SECS: u64 = 30;

/// Rendezvous (HRW) replica set size for shard self-selection. This is the
/// top-`R` cut a storage-serving node applies when deciding which shards of an
/// announced object it should hold. It matches the default erasure scheme's
/// total shard count (4 data + 2 parity) so a node's expected share of any
/// object is one shard, and the union of every node's self-selected set covers
/// all shards under a converged membership view.
pub const DEFAULT_STORAGE_REPLICAS: usize = 6;

/// Minimum verified free disk (GB) a node must have to advertise the
/// StorageProvider role. Below this there is no point accepting deals — the
/// node could not honor a single redundancy slot. Storage is permissionless
/// but capacity is the one thing it cannot fake, so this is a hard floor.
pub const MIN_STORAGE_PROVIDER_FREE_GB: f64 = 10.0;

/// Minimum verified free disk (GB) a node must have to advertise the
/// CloudProvider role. Sites and function bundles are small next to storage
/// deals, but a machine image is not, so the floor is the same order and set
/// separately to keep the two roles from moving together by accident.
pub const MIN_CLOUD_PROVIDER_FREE_GB: f64 = 10.0;

/// Provider pricing configuration. All prices are wei per token (1 TNZO = 10^18 wei).
/// Wire format: u128 decimal strings (matches the rest of the wei-base-unit RPC contract).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderPricing {
    /// Wei per input token (decimal string)
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub input_price_per_token_wei: u128,
    /// Wei per output token (decimal string)
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub output_price_per_token_wei: u128,
    /// Network-enforced ceiling on input price (decimal string)
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub network_max_input_wei: u128,
    /// Network-enforced ceiling on output price (decimal string)
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub network_max_output_wei: u128,
    /// Rates for every billable unit that is not an input or output token:
    /// cached tokens, reasoning loops, image tokens, audio and video seconds,
    /// denoising pixel-steps, and frames. An operator setting only token prices
    /// omits this and inherits [`default_modality_rates`].
    ///
    /// The fallback is the wei-scale card rather than `ModalityRates::default`:
    /// the token prices above are wei and the type default is nominal, so
    /// inheriting the type default would price a second of audio far under a
    /// single token.
    #[serde(default = "default_modality_rates")]
    pub modality_rates: tenzro_types::model::ModalityRates,
    /// The scheme the rates above are charged under. Decides which of them a
    /// finished call is actually billed on — see [`ProviderPricing::price`].
    ///
    /// An operator who posts rates without naming a scheme is charging for the
    /// work those rates describe, which is [`PricingModel::PerToken`].
    #[serde(default)]
    pub pricing_model: tenzro_types::model::PricingModel,
}

/// Network ceiling on the price of one input token: 0.001 TNZO.
pub const NETWORK_MAX_INPUT_WEI: u128 = 1_000_000_000_000_000;

/// Network ceiling on the price of one output token: 0.002 TNZO.
///
/// Also the ceiling on every other metered unit, so an operator cannot route
/// around the token ceiling by charging per audio second or per frame instead.
pub const NETWORK_MAX_OUTPUT_WEI: u128 = 2_000_000_000_000_000;

impl ProviderPricing {
    /// Holds every rate at or below the network per-unit ceiling and restates
    /// the ceilings themselves, so an operator cannot advertise a rate the
    /// network will not honour.
    ///
    /// Every path that accepts operator-supplied pricing runs this before the
    /// card becomes readable: a rate that escaped it would be quoted to callers
    /// and settled on.
    pub fn clamp_to_network_maximums(&mut self) {
        self.input_price_per_token_wei = self.input_price_per_token_wei.min(NETWORK_MAX_INPUT_WEI);
        self.output_price_per_token_wei = self.output_price_per_token_wei.min(NETWORK_MAX_OUTPUT_WEI);
        self.network_max_input_wei = NETWORK_MAX_INPUT_WEI;
        self.network_max_output_wei = NETWORK_MAX_OUTPUT_WEI;

        // ModalityRates is u64 while the ceiling is u128, so the ceiling is
        // itself capped at u64::MAX before comparison.
        let unit_ceiling = NETWORK_MAX_OUTPUT_WEI.min(u64::MAX as u128) as u64;
        let rates = &mut self.modality_rates;
        rates.price_per_request = rates.price_per_request.min(unit_ceiling);
        rates.price_per_compute_ms = rates.price_per_compute_ms.min(unit_ceiling);
        rates.price_per_cached_read_token = rates.price_per_cached_read_token.min(unit_ceiling);
        rates.price_per_cached_write_token = rates.price_per_cached_write_token.min(unit_ceiling);
        rates.price_per_reasoning_loop = rates.price_per_reasoning_loop.min(unit_ceiling);
        rates.price_per_image_token = rates.price_per_image_token.min(unit_ceiling);
        rates.price_per_audio_second = rates.price_per_audio_second.min(unit_ceiling);
        rates.price_per_video_second = rates.price_per_video_second.min(unit_ceiling);
        rates.price_per_pixel_step = rates.price_per_pixel_step.min(unit_ceiling);
        rates.price_per_frame = rates.price_per_frame.min(unit_ceiling);
    }

    /// Prices one locally-served call under the scheme this card declares.
    ///
    /// [`ProviderPricing::meter`] is the per-unit metering the default scheme
    /// charges on. The other three settle on something else entirely — a flat
    /// charge per call, the measured wall-clock, or the metered cost pulled
    /// toward what the model has recently been settling at — so a card that
    /// declares one of them and is then billed per token would charge a caller
    /// something other than what it advertised.
    ///
    /// `market_average` is the average cost this model's finished calls have
    /// settled at, which is the only demand signal a serving node holds without
    /// asking the network. `None` leaves a dynamic quote at its metered cost
    /// rather than guessing a scale.
    pub fn price(
        &self,
        units: &tenzro_types::model::BillableUnits,
        latency_ms: u64,
        market_average: Option<u128>,
    ) -> u128 {
        use tenzro_types::model::PricingModel;
        let rates = &self.modality_rates;
        match self.pricing_model {
            PricingModel::PerToken => self.meter(units),
            PricingModel::PerRequest => rates.price_per_request as u128,
            PricingModel::PerComputeTime => {
                (latency_ms as u128).saturating_mul(rates.price_per_compute_ms as u128)
            }
            PricingModel::Dynamic => Self::scale_to_market(self.meter(units), market_average),
        }
    }

    /// Pulls a metered cost toward what the model has recently settled at,
    /// bounded to between half and twice the metered figure.
    ///
    /// The bound is what keeps this a price signal rather than an unbounded
    /// multiplier: one outlier settlement in a thin market must not multiply a
    /// caller's bill without limit, and a soft market must not drive the price
    /// to zero. Absent history, the metered cost stands.
    fn scale_to_market(metered: u128, market_average: Option<u128>) -> u128 {
        match market_average {
            Some(average) if average > 0 && metered > 0 => {
                let ratio = (average as f64 / metered as f64).clamp(0.5, 2.0);
                (metered as f64 * ratio) as u128
            }
            _ => metered,
        }
    }

    /// Meters one call across every billable dimension it reported, in wei.
    ///
    /// This is the single place a locally-served call is metered, so a modality
    /// that starts reporting a new unit begins billing for it everywhere at
    /// once. Arithmetic is u128 throughout because the token prices are u128 and
    /// a high-resolution video's pixel-step count exceeds u64.
    ///
    /// Frames are charged only when the call reported no pixel-steps. A
    /// generation's frame count is already a factor of its pixel-steps, so
    /// charging both would bill the same work twice; frames stand alone only for
    /// a call that *consumed* them, as when a video encoder samples a clip.
    pub fn meter(&self, units: &tenzro_types::model::BillableUnits) -> u128 {
        let rates = &self.modality_rates;
        let charge = |quantity: u64, rate: u64| -> u128 {
            (quantity as u128).saturating_mul(rate as u128)
        };

        let frames = if units.pixel_steps == 0 {
            charge(units.frames as u64, rates.price_per_frame)
        } else {
            0
        };

        [
            (units.input_tokens as u128).saturating_mul(self.input_price_per_token_wei),
            (units.output_tokens as u128).saturating_mul(self.output_price_per_token_wei),
            charge(
                units.cached_read_tokens as u64,
                rates.price_per_cached_read_token,
            ),
            charge(
                units.cached_write_tokens as u64,
                rates.price_per_cached_write_token,
            ),
            charge(units.reasoning_loops as u64, rates.price_per_reasoning_loop),
            charge(units.image_tokens as u64, rates.price_per_image_token),
            charge(units.audio_seconds(), rates.price_per_audio_second),
            charge(units.video_seconds(), rates.price_per_video_second),
            units
                .pixel_steps
                .saturating_mul(rates.price_per_pixel_step as u128),
            frames,
        ]
        .into_iter()
        .fold(0u128, |acc, term| acc.saturating_add(term))
    }
}

impl Default for ProviderPricing {
    fn default() -> Self {
        // Defaults: 0.0001 / 0.0002 TNZO per token, max 0.001 / 0.002 TNZO per token.
        Self {
            input_price_per_token_wei: 100_000_000_000_000,  // 1e14 wei = 0.0001 TNZO
            output_price_per_token_wei: 200_000_000_000_000, // 2e14 wei = 0.0002 TNZO
            network_max_input_wei: NETWORK_MAX_INPUT_WEI,
            network_max_output_wei: NETWORK_MAX_OUTPUT_WEI,
            modality_rates: default_modality_rates(),
            pricing_model: tenzro_types::model::PricingModel::PerToken,
        }
    }
}

/// Wei-scale rates for the non-token billable units, in the same order of
/// magnitude as the default token prices (1e14 wei per input token).
///
/// A cached read is a tenth of a fresh input token because the provider skipped
/// the prefill for it; a cache write is priced above a fresh token because the
/// provider pays to retain it. The denoising and base-fee rates match
/// `tenzro_media_gen::pricing`, which meters the same pixel-steps, so a
/// generation quoted by the media runtime and one metered here agree.
///
/// Pixel-steps price frames a provider *generates*; `price_per_frame` prices
/// frames a provider *consumes*, as when sampling a clip for embedding. A
/// request carries one or the other, never both.
///
/// Every rate sits at or below the `network_max_output_wei` per-unit ceiling
/// enforced when an operator sets pricing.
pub fn default_modality_rates() -> tenzro_types::model::ModalityRates {
    tenzro_types::model::ModalityRates {
        price_per_request: 1_000_000_000_000_000,          // 1e15 wei
        price_per_compute_ms: 1_000_000_000,               // 1e9 wei
        price_per_cached_read_token: 10_000_000_000_000,   // 1e13 wei
        price_per_cached_write_token: 300_000_000_000_000, // 3e14 wei
        price_per_reasoning_loop: 1_000_000_000_000_000,   // 1e15 wei
        price_per_image_token: 100_000_000_000_000,        // 1e14 wei
        price_per_audio_second: 500_000_000_000_000,       // 5e14 wei
        price_per_video_second: 1_000_000_000_000_000,     // 1e15 wei
        price_per_pixel_step: 1_000_000_000,               // 1e9 wei
        price_per_frame: 100_000_000_000_000,              // 1e14 wei
    }
}

/// Model download status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDownloadStatus {
    pub model_id: String,
    pub status: String, // "downloading", "completed", "failed", "not_started"
    pub progress_percent: f64,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// User resource tracking (models being used from providers)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResource {
    pub resource_type: String,
    pub resource_id: String,
    pub added_at: u64,
}

/// Transaction history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionHistoryEntry {
    pub tx_hash: String,
    pub from: String,
    pub to: String,
    pub amount: String,
    pub asset: String,
    pub status: String,
    pub timestamp: u64,
    pub tx_type: String,
}

/// A model discovered via gossipsub from a remote provider.
/// Entries expire if not refreshed within `ttl_secs`.
#[derive(Debug, Clone)]
pub struct NetworkModelEntry {
    pub registration: tenzro_network::ModelRegistrationMessage,
    pub last_seen: std::time::Instant,
}

/// An agent discovered via gossipsub from a remote node.
/// Entries expire if not refreshed within `ttl_secs`.
#[derive(Debug, Clone)]
pub struct NetworkAgentEntry {
    pub announcement: tenzro_network::AgentAnnouncementMessage,
    pub last_seen: std::time::Instant,
}

/// A provider discovered via gossipsub from a remote node.
/// Entries expire if not refreshed within `ttl_secs`.
#[derive(Debug, Clone)]
pub struct NetworkProviderEntry {
    pub announcement: tenzro_network::ProviderAnnouncementMessage,
    pub last_seen: std::time::Instant,
}

/// Distill the live provider-announcement map into app-hosting placement
/// candidates. Each entry is kept only if its announcement is still within TTL,
/// carries a bound iroh endpoint, and advertises at least one hosting runtime
/// class; placement's `select` applies the per-request filters (class, TEE,
/// headroom, price ceiling, reachability) on top. Shared by
/// `TenzroNode::hosting_candidates` and the background placement-reconcile tick.
fn distill_hosting_candidates(
    providers: &DashMap<String, NetworkProviderEntry>,
) -> Vec<crate::placement::NodeCandidate> {
    let now = std::time::Instant::now();
    providers
        .iter()
        .filter(|entry| {
            let ttl = std::time::Duration::from_secs(entry.announcement.ttl_secs);
            now.duration_since(entry.last_seen) < ttl
        })
        .filter_map(|entry| {
            let ann = &entry.announcement;
            if ann.iroh_endpoint_id.is_empty()
                || ann.runtime_support.hosting_runtimes.is_empty()
            {
                return None;
            }
            Some(crate::placement::NodeCandidate {
                endpoint_id: ann.iroh_endpoint_id.clone(),
                hosting_runtimes: ann.runtime_support.hosting_runtimes.clone(),
                cpu_cores: ann.hardware.cpu_cores,
                ram_gb: ann.hardware.ram_gb,
                disk_gb: ann.hardware.disk_gb,
                tee_available: ann.hardware.tee_available,
                reachability: ann.network_profile.reachability.clone(),
                region: ann.geography.clone(),
                price_per_hour: ann.runtime_support.hosting_price_per_hour,
            })
        })
        .collect()
}

/// Derive the 32-byte provider wallet address for a plain node that has no
/// identity-registry entry, from its announce signer's Ed25519 public key.
/// Same derivation as the self-custodial wallet in
/// `tenzro_identity::registry` (`sha256(public_key_bytes)`), so a validator
/// with no provisioned identity still advertises a stable, reproducible
/// provider address instead of the zero address.
fn announce_signer_wallet_address(
    signer: &(dyn tenzro_crypto::signatures::Signer + Send + Sync),
) -> Option<Address> {
    let hash = tenzro_crypto::sha256(signer.public_key().as_bytes());
    Address::from_bytes(hash.as_bytes())
}

/// Main Tenzro Network node
pub struct TenzroNode {
    config: NodeConfig,
    pub(crate) state: Arc<RwLock<NodeState>>,

    // Core infrastructure
    storage: Option<Arc<RocksDbStore>>,
    network: Option<Arc<TenzroNetworkService>>,

    // Consensus (validators only)
    consensus: Option<Arc<HotStuff2Engine>>,
    /// Outbound consensus messages (votes, proposals) from HotStuff-2 engine.
    /// Consumed once by `init_event_loop()` and wired into the event loop for
    /// gossipsub broadcast.  `None` when consensus is not running on this node.
    consensus_out_rx: Option<tokio::sync::mpsc::UnboundedReceiver<ConsensusOutMessage>>,
    /// Local validator address (32-byte, derived from the node's Ed25519
    /// keypair). Captured at `init_consensus()` time and used by the inbound
    /// consensus gossipsub bridge to skip self-broadcasts — without this
    /// filter, every validator would re-feed its own proposal/vote back into
    /// the engine on the gossipsub echo, causing duplicate votes and
    /// redundant `on_proposal()` invocations.
    local_validator_address: Option<Address>,

    /// Validator-owned hybrid (Ed25519 + ML-DSA-65) signer, constructed
    /// from the same `validator_key` + `validator_pq_key` that consensus
    /// loads in [`init_consensus`]. Used by webhook-sourced TDIP
    /// revocation paths (e.g. Stripe SPT `granted_token.deactivated`)
    /// that need to sign a `SignedRevocationEntry` before broadcasting
    /// the revocation to the rest of the mesh via the
    /// `RevocationBroadcaster`. `None` on non-validator roles.
    validator_hybrid_signer: Option<Arc<dyn tenzro_crypto::composite::HybridSigner>>,

    /// Committee-DA validator-address → PeerId registry (Task #82). Populated
    /// at validator admission; consumed by the committee-DA surface to dial
    /// committee members. `None` on non-validator roles.
    da_peer_registry: Option<Arc<crate::da_committee_surface::AddressPeerRegistry>>,

    /// The committee-resident Red Stuff DA backend, held concretely so the
    /// possession-challenge RPC surface (`tenzro_daChallenge*`) can reach the
    /// custody store and committee snapshot; coerced to `Arc<dyn DaBackend>`
    /// where a trait object is needed. `None` on non-validator roles or when
    /// committee-DA init fails.
    da_committee_backend: Option<Arc<crate::da_committee::DaCommitteeBackend>>,

    /// JoinHandle for the committee-DA inbound serving loop. Kept alive for the
    /// node's lifetime; dropped on stop.
    da_committee_server_handle: Option<tokio::task::JoinHandle<()>>,

    /// JoinHandle for the database replicated-write inbound serving loop
    /// (`/tenzro/db/replicate`). Applies writes fanned out by remote holders to
    /// this node's copy of a partition. Kept alive for the node's lifetime.
    db_replicate_server_handle: Option<tokio::task::JoinHandle<()>>,

    /// Background possession-challenge driver: periodically audits a random
    /// committee member's custody of a random held blob and scores the result
    /// into the member's rolling availability score. Aborted on stop.
    da_possession_challenger: Option<crate::da_committee::PossessionChallenger>,

    /// Node Ed25519 signer for outbound model + provider gossip
    /// announcements. Byte-shared with the validator identity that derives
    /// this node's `peer_id`, so consumers can bind a signed announcement to
    /// the announcing node and reject spoofed / replayed announcements.
    /// Loaded from `keygen::load_validator_keypair` during startup.
    announce_signer: Option<Arc<dyn tenzro_crypto::signatures::Signer + Send + Sync>>,

    /// Stripe SPT ceiling-resolver cache adapter. Held here so the
    /// SPT-revocation RPC + (future) webhook receive endpoint can
    /// invalidate the cache in lockstep with `IdentityRegistry::revoke`.
    /// `None` when no Stripe API key is configured.
    spt_ceiling_cache: Option<Arc<crate::spt_ceiling_bridge::SptCeilingResolverAdapter>>,

    /// Write-through store for validated AP2 mandate pairs. Populated by
    /// `handle_ap2_validate_mandate_pair` on a successful cross-validation
    /// and read by `tenzro_listMandates` for principal-scoped listing.
    /// `None` until `init_payments` runs with persistent storage.
    mandate_store: Option<Arc<crate::mandate_store::MandateStore>>,

    // Execution layer
    vm_runtime: Option<Arc<MultiVmRuntime>>,

    // Services
    wallet_service: Option<Arc<TenzroWalletService>>,
    token: Option<Arc<TnzoToken>>,
    /// Accounts for the gas the executor debits per transaction. The event
    /// loop settles the fee market's treasury/burn split onto the ledger at
    /// every finalized block and records the movement here.
    fee_processor: Option<Arc<tenzro_token::FeeProcessor>>,
    staking: Option<Arc<StakingManager>>,
    /// AgentBond surety primitive (Agent-Swarm Spec 9). Single source of
    /// truth for bond state across lane resolution, RPC reads, and
    /// post-block scan dispatch from VM-emitted bond logs. Persists to
    /// CF_AGENTS via `BondManager::with_storage`.
    bond_manager: Option<Arc<tenzro_token::bond::BondManager>>,
    /// ComputeBond surety primitive (Phase A #153). Single source of
    /// truth for provider compute-bond state. Consulted by
    /// `handle_register_provider` to enforce minimum-bond admission, read by
    /// the bond RPCs (`tenzro_getComputeBond`, `tenzro_listComputeBonds`,
    /// `tenzro_computeBondParams`), and mutated by the post-block scan over
    /// the `PostComputeBond` / `IncreaseComputeBond` / `WithdrawComputeBond` /
    /// `FinalizeComputeBondWithdrawal` transaction types so the vault
    /// transfer and the bond state change land in the same block. Persists
    /// to CF_PROVIDERS via
    /// `ComputeBondManager::with_storage`.
    compute_bond_manager: Option<Arc<tenzro_token::compute_bond::ComputeBondManager>>,
    /// Verifiable-inference commitment store + challenge lifecycle
    /// (TOPLOC scheme). Stores per-response top-k logit commitments
    /// under `commitment/<hash_hex>` and filed disputes under
    /// `challenge/<uuid>` in CF_CHALLENGES. Consulted by the
    /// `tenzro_*InferenceCommitment` / `tenzro_*InferenceChallenge`
    /// RPC handlers; commitments are written by the chat/inference
    /// handlers when the caller passes `verifiable: true`. `Some`
    /// only when RocksDB storage is available.
    challenge_manager: Option<Arc<crate::inference_challenge::ChallengeManager>>,
    /// SLA fault detector (Phase B Thread 5). Owns the validator's VRF
    /// signing key (byte-shared with the validator's Ed25519 identity per
    /// RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI), issues VRF-stamped probes
    /// to providers, and escalates persistent misses to compute-bond
    /// slashing via [`crate::sla_slashing_bridge::ComputeBondSlashingBridge`].
    /// `Some` only on validator-role nodes (slashing authority requires
    /// consensus participation); `None` on ModelProvider / TeeProvider /
    /// LightClient. The probe scheduler, gossipsub `tenzro/sla` topic, and
    /// `tenzro_sla_*` RPC handlers consult this field.
    sla_manager: Option<Arc<tenzro_model::SlaManager>>,
    /// In-flight SLA probes awaiting provider response. Keyed by
    /// `challenge_nonce` (32 bytes hex-encoded for DashMap key ergonomics).
    /// Populated by `tenzro_slaIssueProbe` immediately before broadcasting
    /// the probe over `tenzro/sla`; drained by the gossipsub subscriber when
    /// a matching `SlaResponse` arrives, or by a periodic timeout sweeper
    /// that scores no-shows as `SlaResult::Missed` past `deadline_ms`.
    /// Empty on non-validator nodes.
    sla_outstanding_probes:
        Arc<DashMap<String, tenzro_model::SlaProbe>>,
    /// In-flight + completed DKLS23 DKG sessions keyed by hex instance id.
    /// Populated by `tenzro_mpcKeygen`, polled by `tenzro_mpcKeygenStatus`.
    /// Orchestration state only — the durable output of a successful run is
    /// the sealed `KeyshareEnvelope` in `CF_MPC_KEYSHARES`.
    mpc_keygen_sessions: Arc<crate::mpc_keygen::KeygenSessionRegistry>,
    /// Workflow runtime — typed mirror of the privileged-VM workflow
    /// selectors (`0x01000040`–`0x0100004B`). Bundles `WorkflowManager`
    /// (workflows / obligations / approvals / lifecycle) and
    /// `PrivacyDomainRegistry`, both hydrated from RocksDB
    /// (CF_SETTLEMENTS + CF_APPROVALS). The post-block scan in
    /// `EventLoop::process_workflow_logs` decodes the 12 typed
    /// `Workflow*` log topics and dispatches into this runtime; RPC /
    /// MCP / A2A read accessors consult it directly.
    workflow_runtime: Option<Arc<crate::workflow_runtime::WorkflowRuntime>>,
    /// Permissionless ValidatorRegistry (Spec — dynamic validator set).
    /// Holds Candidate / PendingActive / Active / PendingExit / Exited /
    /// Jailed entries with EIP-8061-style churn budgeting. The post-block
    /// scan in `EventLoop::process_validator_logs` mirrors VM-emitted
    /// `ValidatorRegister` / `ValidatorExit` / `ValidatorMetadataUpdate`
    /// logs into this registry; the periodic epoch hook in the event
    /// loop calls `compute_epoch_transition()` and feeds the resulting
    /// plan into the consensus `EpochManager`'s pending queues.
    /// Persists to CF_TOKENS via `ValidatorRegistry::with_storage`.
    validator_registry: Option<Arc<tenzro_token::validator_registry::ValidatorRegistry>>,
    /// ERC-7579 modular validator registry for ERC-4337 smart-account UserOps
    /// (Phase B Thread 3 / B.3.5). Distinct from `validator_registry` above
    /// (which tracks consensus validators). This holds per-account
    /// `IValidator` modules — `DelegationScopeValidator`, `WebAuthnValidator`,
    /// `TeeBoundValidator` — and is the AND-combiner consulted by
    /// `EntryPoint::validate_user_op` before bundling. Constructed in
    /// `init_ai_infrastructure` once `identity_registry` and `agent_runtime`
    /// are up so the bound `IdentityScopeOracle` can do a fresh
    /// `IdentityRegistry::resolve(did)` on every validation. In-memory
    /// only; a later revision will rebuild the per-account install set from
    /// on-chain `InstalledModule` logs on restart.
    aa_validator_registry: Option<Arc<tenzro_vm::aa_validators::ValidatorRegistry>>,
    /// ERC-4337 smart-account factory shared across passkey-first enrollment,
    /// guardian recovery, and session-key grants. The factory holds a
    /// `DashMap<Vec<u8>, SmartAccount>` of every account deployed via
    /// `tenzro_enrollPasskey`; the per-account `validator_modules` field is
    /// the source of truth for which ERC-7579 validators (`WebAuthnValidator`,
    /// `SocialRecoveryValidator`, `SessionKeyValidator`, `SpendingLimitValidator`,
    /// `HardwareSignerValidator`) are installed. Persisted to `CF_AGENTS`
    /// under the `smart_account:` prefix via the wrapper layer (see
    /// `passkey_rpc.rs`). The factory address is the canonical Tenzro
    /// AccountFactory precompile address `0x0000…0000400`.
    account_factory: Option<Arc<tenzro_vm::AccountFactory>>,
    /// SocialRecoveryValidator shared by every account that has installed it.
    /// Owned at node level (not per-account) because the validator is
    /// `Arc<dyn IValidator>`-stored in the AccountFactory but the *config* is
    /// per-account inside the validator's own `configs: DashMap` (see
    /// `tenzro_vm::erc7579::SocialRecoveryValidator`). Persists to
    /// `CF_VALIDATOR_MODULES` under `erc7579/social/<account_addr>`.
    social_recovery_validator: Option<Arc<tenzro_vm::SocialRecoveryValidator>>,
    /// SessionKeyValidator — same per-account-config model as
    /// `social_recovery_validator`. Configs persist under
    /// `erc7579/session/<account_addr>`.
    session_key_validator: Option<Arc<tenzro_vm::SessionKeyValidator>>,
    /// SpendingLimitValidator — per-account ceilings (per-tx + rolling-window
    /// daily). Configs persist under `erc7579/spending/<account_addr>`.
    spending_limit_validator: Option<Arc<tenzro_vm::SpendingLimitValidator>>,
    /// WebAuthnValidator — the primary user-facing validator for passkey-first
    /// onboarding. Per-account configs hold the registered WebAuthn public
    /// key (P-256 SEC1) plus the rolling sign-count. Persists to
    /// `CF_VALIDATOR_MODULES / erc7579/webauthn/<account_addr>`.
    webauthn_validator: Option<Arc<tenzro_vm::WebAuthnValidator>>,
    /// Hardware-signer validators (Ledger / Trezor / GridPlus / YubiKey /
    /// Generic). One validator per device-kind module address. Per-account
    /// configs are written through to `CF_VALIDATOR_MODULES /
    /// erc7579/hardware/<module_addr>/<account_addr>` by
    /// `tenzro_addHardwareSigner` and hydrated on startup.
    hardware_signer_validators:
        Option<Vec<Arc<tenzro_vm::erc7579::HardwareSignerValidator>>>,
    /// Pending social-recovery operations indexed by recovery_id. Each entry
    /// holds the target account, the new validator install request, the set
    /// of guardian signatures collected so far, and the `expires_at`
    /// deadline. Persists to `CF_VALIDATOR_MODULES / erc7579/recovery_pending/`
    /// so an interrupted recovery survives node restart.
    recovery_pending: Option<Arc<crate::passkey_rpc::PendingRecoveryStore>>,
    /// Pending browser-mediated passkey auth sessions (CLI → browser →
    /// node), indexed by session_id. The CLI creates a session over RPC,
    /// the node-served `/auth/passkey` page completes the WebAuthn ceremony
    /// and posts the outcome back, the CLI polls until terminal. Persists to
    /// `CF_VALIDATOR_MODULES / erc7579/auth_session/` so sessions survive
    /// node restart.
    passkey_sessions: Option<Arc<crate::passkey_rpc::PasskeySessionStore>>,
    /// Shared `IdentityScopeOracle` consulted by every installed
    /// `DelegationScopeValidator` (Phase B Thread 3 / B.3.5). Held on Node
    /// so #164 (per-machine validator install) can clone the same Arc into
    /// each newly installed validator without re-binding the registry.
    identity_scope_oracle: Option<Arc<crate::delegation_scope_oracle::IdentityScopeOracle>>,
    /// ERC-4337 v0.8 EntryPoint singleton (Phase B Thread 3c / #165). Wired
    /// to `aa_validator_registry` for signature validation and to
    /// `vm_runtime` for actual UserOp execution. Persists nonces +
    /// receipts to `CF_AGENTS` under the `aa/nonce/` and `aa/receipt/`
    /// prefixes. Backed by the same `RocksDbStore` as the rest of the node.
    aa_entry_point: Option<Arc<tenzro_vm::EntryPoint>>,
    /// TEE-key oracle for autonomous-machine custody. Resolves a smart
    /// account to its enrolled `TeeBoundAccountKey` (enclave vendor +
    /// measurement + signing pubkey). Backed by `TeeEnrollmentKvStore`
    /// (CF_VALIDATOR_MODULES under `erc7579/tee_enrollment/`), hydrated on
    /// boot. Consulted by the `TeeBoundValidator` (module 0x1021) and the
    /// `TnzoBootstrapPaymaster`; populated by `tenzro_enrollTeeKey`.
    tee_key_oracle: Option<Arc<tenzro_vm::InMemoryTeeKeyOracle>>,
    /// TEE-bound validator (ERC-7579 module 0x1021) for autonomous-machine
    /// custody. Gates every UserOp on a fresh key-bound TEE attestation
    /// resolved via `tee_key_oracle`. Installed per autonomous-machine smart
    /// account as the single point of signing enforcement.
    tee_bound_validator: Option<Arc<tenzro_vm::TeeBoundValidator>>,
    /// BurnQuota singleton (Agent-Swarm Spec 3). Tracks the
    /// protocol-side TNZO budget the stablecoin paymaster will draw from
    /// once the dual-rail-gas paymaster + oracle + AMM swap loop is in place.
    /// Currently only the read RPC `tenzro_getBurnQuota` is wired;
    /// `try_drain` / `refill` are public on the manager but no caller
    /// invokes them yet. Persists to CF_TOKENS via
    /// `BurnQuotaManager::with_storage`.
    burn_quota_manager: Option<Arc<tenzro_token::burn_quota::BurnQuotaManager>>,
    /// Adaptive burn governance dial (Agent-Swarm Spec 8). Holds the
    /// current `BurnRateConfig`, the `SupplyTargets` thresholds, and the
    /// most recent `SupplyMetricsSnapshot`. Read-only RPCs surface the
    /// recommendation produced by `compute_recommendation`; the
    /// auto-proposal generator and EIP-1559 fee-market consumer land
    /// alongside the governance executor wiring. Persists to
    /// CF_TOKENS via `BurnRateConfigManager::with_storage`.
    burn_rate_manager: Option<Arc<tenzro_token::adaptive_burn::BurnRateConfigManager>>,
    /// SeedAgent treasury earmark manager (Agent-Swarm Spec 10). Owns the
    /// genesis-funded TreasuryEarmark, the catalog of operation Charters
    /// (C1-C6), and the per-DID `SeedAgentRecord` registry that drives the
    /// 12-month bootstrap traffic. Read-only RPCs surface earmark balance,
    /// charter listings, and per-agent status; the off-chain provisioning
    /// daemon, monthly decay enforcement, and governance-executor mutation
    /// paths persist to CF_TOKENS via
    /// `SeedAgentEarmarkManager::with_storage`.
    seed_agent_manager: Option<Arc<tenzro_token::seed_agent::SeedAgentEarmarkManager>>,
    /// Work-gated reward engine. Meters verified work (consensus
    /// participation, settled inference/TEE/RPC traffic, training rounds,
    /// app usage) into per-epoch reward coupons against the declining
    /// minting schedule. Coupons expire unclaimed after
    /// `CLAIM_WINDOW_EPOCHS`; unmatched minting rights are permanently
    /// unminted. Persists to CF_TOKENS via `RewardEngine::with_storage`.
    reward_engine: Option<Arc<tenzro_token::RewardEngine>>,
    /// Vesting schedules (reward / grant / contributor). The claim path
    /// routes the non-liquid portion of reward claims here; grant and
    /// contributor schedules are created through admin-gated RPCs.
    /// Slashing consumes vesting after the junior bond and before owned
    /// stake. Persists to CF_TOKENS via `VestingManager::with_storage`.
    vesting_manager: Option<Arc<tenzro_token::VestingManager>>,
    /// Foundation sponsorship slots (revocable delegated stake for
    /// qualifying operators). Enforces junior bond, adaptive concentration
    /// caps, and the 33% aggregate sponsored-stake ceiling. While a slot is
    /// Active, 100% of the operator's reward claims convert to self-owned
    /// stake until graduation. Persists to CF_TOKENS via
    /// `SponsorshipManager::with_storage`.
    sponsorship_manager: Option<Arc<tenzro_token::SponsorshipManager>>,
    /// Gossip sender created at `init_token_economics` time and consumed by
    /// the SeedAgent provisioning daemon spawned in `start()` after
    /// consensus is initialised. The receiver half is owned by the
    /// forwarder task in `init_token_economics` (drains the channel and
    /// broadcasts each envelope on `tenzro/seed-agents`). `None` when the
    /// node has no `seed_agent_manager` or no network.
    seed_agent_gossip_tx: Option<
        tokio::sync::mpsc::UnboundedSender<tenzro_token::SeedAgentGossipMessage>,
    >,
    /// SeedAgent provisioning daemon (Agent-Swarm Spec 10 Task #42). Owns
    /// the monthly-refill tick loop + charter-sunset pause sweep + gossip
    /// broadcast. Spawned in `start()` after consensus init so the leader
    /// gate (`HotStuff2Engine::is_leader_in_next_views`) is wireable. The
    /// `Arc` is retained so `tenzro_getSeedAgentDaemonStatus` can return
    /// the most recent tick outcome.
    seed_agent_daemon: Option<Arc<tenzro_token::SeedAgentDaemon>>,
    /// Trainer auto-provisioning daemon. Polls active training runs and
    /// supervises a Python reference-trainer subprocess per run. `Arc` is
    /// retained so `tenzro_getTrainerDaemonStatus` can report live counts.
    trainer_daemon: Option<Arc<crate::trainer_daemon::TrainerDaemon>>,
    /// Liquid staking pool (stTNZO). Persists holder balances, validator
    /// delegations, withdrawal requests, and aggregate totals to CF_TOKENS
    /// via `LiquidStakingPool::with_storage`. Surfaced through
    /// `tenzro_liquidStaking*` RPCs and CLI commands.
    liquid_staking_pool: Option<Arc<tenzro_token::LiquidStakingPool>>,
    governance: Option<Arc<GovernanceEngine>>,
    treasury: Option<Arc<NetworkTreasury>>,
    settlement: Option<Arc<SettlementEngine>>,
    channel_manager: Option<Arc<ChannelManager>>,
    escrow_manager: Option<Arc<EscrowManager>>,
    /// ERC-7683 destination-side fill registry (Agent-Swarm Spec 4). The
    /// idempotency guard for `fill(originData)`: refuses to record a second
    /// fill for an `order_id` already filled on this Tenzro replica.
    /// Persisted to `CF_SETTLEMENTS / 7683_dest:<order_id>` so the guard
    /// survives restart. Initialized alongside `escrow_manager` in
    /// `init_settlement` since both share the settlements column family.
    spec4_fill_registry: Option<Arc<Spec4FillRegistry>>,
    /// Kill-switch receipt store (Agent-Swarm Spec 1). Records every
    /// `KillSwitchPause`/`KillSwitchQuarantine`/`KillSwitchTerminate` log
    /// emitted by the VM so that read-RPCs can list receipts by agent or
    /// controller DID. Persisted to CF_SETTLEMENTS.
    kill_switch_store: Option<Arc<tenzro_settlement::KillSwitchStore>>,
    batch_processor: Option<Arc<BatchProcessor>>,
    fee_collector: Option<Arc<FeeCollector>>,

    /// OAuth 2.1 + DPoP + RAR auth engine. Replaces the legacy
    /// `OnboardingKey` flow. See `tenzro_auth::AuthEngine` for the
    /// trust model and storage layout (CF_AUDIT, CF_APPROVALS).
    auth_engine: Option<Arc<tenzro_auth::AuthEngine>>,

    /// Per-client API key manager. Gates access to scoped RPC surfaces
    /// (currently `Canton` — `tenzro_*Canton*` methods). The server-side
    /// Canton credentials live in [`Self::canton_adapters`] and are never
    /// exposed to clients; instead, clients authenticate to Tenzro with
    /// an opaque `tnz_*` API key, and the dispatch path in `rpc.rs`
    /// calls `authorize(plaintext, method)` to gate scoped methods.
    /// Persists `ApiKeyRecord` rows (SHA-256-hashed plaintext) to
    /// `CF_API_KEYS` via [`crate::api_key::ApiKeyManager::new`].
    api_key_manager: Option<Arc<crate::api_key::ApiKeyManager>>,

    /// Permissionless application registry for developer payments.
    /// Developers register apps by signing with their TDIP DID; records
    /// persist to `CF_SETTLEMENTS` under `app:` and hydrate on startup.
    /// Consumed by the settlement-authorization path to verify
    /// developer-signed settlements and apply the declared margin.
    /// `None` until storage is initialized.
    app_registry: Option<Arc<crate::app_registry::AppRegistry>>,

    /// MCP plugin host. Runs operator-curated custom + third-party
    /// MCPs (stdio subprocesses, remote Streamable HTTP, legacy SSE).
    /// Holds the sealed credential vault for operator's upstream API
    /// keys. `None` when storage is unavailable or the operator has
    /// not configured a vault root (no TEE + no master secret).
    mcp_plugin_host: Option<Arc<crate::mcp_plugin_host::McpPluginHost>>,

    /// Workflow executor for agent workflow templates. Drives a
    /// template's saga to completion against the node's RPC handlers.
    /// Hydrates in-flight runs from `CF_SETTLEMENTS` on startup so
    /// workflows survive operator restarts. Constructed lazily on
    /// first use because it needs `Arc<TenzroNode>` self-reference.
    workflow_executor: parking_lot::Mutex<Option<Arc<crate::workflow_executor::WorkflowExecutor>>>,

    /// Per-tenant Canton usage counter. Incremented from the canton
    /// RPC dispatch path so the operator can answer "how many DAML
    /// transactions has the tenzro-labs team submitted this month, and
    /// which methods are they hitting?" Persists `CantonKeyAnalytics`
    /// to `CF_CANTON_ANALYTICS`. `None` when storage isn't wired,
    /// matching the api_key_manager pattern.
    canton_analytics: Option<Arc<crate::canton_analytics::CantonAnalyticsManager>>,

    /// Per-tenant Chainlink/bridge analytics — counters + CU attribution
    /// for `chainlink`-scoped API keys. Same pattern as `canton_analytics`
    /// but for the bridge fee oracle path.
    bridge_analytics: Option<Arc<crate::bridge_analytics::BridgeAnalyticsManager>>,

    /// GCRA rate limiter for `chainlink`-scoped API keys. In-memory only;
    /// counters don't survive restart (rate-limit windows are short-lived).
    /// Defaults: 10 req/sec, burst 100.
    chainlink_rate_limiter: Arc<crate::bridge_analytics::GcraLimiter>,

    /// Stage 2.b: per-tenant upstream OAuth client provisioner. When
    /// `canton.identity_providers.enabled` is true and
    /// `mgmt_url` + M2M client credentials are configured, this is an
    /// `Auth0ManagementClient`; `handle_create_api_key` uses it to
    /// mint a per-tenant client and return the secret to the tenant
    /// once. `None` when Stage 2.b is disabled — devnet flow.
    tenant_idp_provisioner: Option<Arc<dyn tenzro_bridge::tenant_idp::TenantIdpProvisioner>>,

    /// Operator admin token gating per-node mutation RPCs (API-key
    /// issuance/revocation, staking, provider registration). Loaded once
    /// from the `TENZRO_ADMIN_TOKEN` environment variable during
    /// [`Node::start`] and never persisted: it lives only in process
    /// memory, never appears in `NodeConfig`, the TOML config file, or
    /// RocksDB. When `None`, the node is in **fail-closed** mode — every
    /// gated method returns `-32001 Unauthorized` regardless of caller
    /// input. Operators set the env var on the validator service unit
    /// (`Environment="TENZRO_ADMIN_TOKEN=..."`) to unlock the gates.
    ///
    /// Compared via [`crate::api_key::verify_admin_token`] in constant
    /// time to avoid leaking the secret through timing.
    admin_token: Option<String>,

    // AI infrastructure
    model_registry: Option<Arc<ModelRegistry>>,
    /// Governance-anchored transparency log mapping `model_id` to its
    /// canonical weight hash (BLAKE3 peer content-address + SHA-256 integrity
    /// digest + manifest hash). Recording is permissionless first-recorder-
    /// wins; correction flows only through a governance override. Write-through
    /// to CF_MODEL_HASHES, hydrated on boot. Read by the verify-before-load
    /// gate and the `tenzro_getModelHash` / `tenzro_listModelHashes` RPCs;
    /// written at model registration and by `tenzro_recordModelHash` /
    /// `tenzro_overrideModelHash`.
    model_hash_registry: Option<Arc<tenzro_model::ModelHashRegistry>>,
    provider_manager: Option<Arc<ProviderManager>>,
    inference_router: Option<Arc<InferenceRouter>>,
    /// Intent → model discovery-and-dispatch layer. Sits above the inference
    /// router: resolves a `RouteIntent` (use case + budget + quality floor) to
    /// a concrete `model_id`, then hands that to `inference_router` for
    /// provider selection. Reuses `model_registry` + `usage_tracker` +
    /// `inference_router`; the per-DID budget gate adapts the same spending
    /// policy the payment binder enforces. Read by `tenzro_routeIntent` and
    /// `tenzro_chatByIntent`.
    meta_router: Option<Arc<tenzro_model::meta_router::MetaRouter>>,
    /// Usage tracker — recipient of every successful inference's
    /// `UsageRecord`. Persists per-model / per-provider / global stats
    /// to RocksDB CF_MODELS via `UsageTracker::with_storage`. Read by
    /// the `tenzro_listInferenceUsage` RPC.
    usage_tracker: Option<Arc<tenzro_model::UsageTracker>>,
    /// EU AI Act Art. 50(2) provenance store. Populated by the inference
    /// router (writer) and queried by the `tenzro_getProvenance` RPC
    /// (reader). Shared via `Arc` so both producer and consumer see the
    /// same SHA-256-keyed manifest cache.
    provenance_store: Option<Arc<tenzro_model::ProvenanceStore>>,
    /// Provenance signer used when this node serves a model itself — the
    /// `/v1/chat/completions` handler stamps a `tenzro_provenance` manifest
    /// on locally-generated responses with it. Built from the node's
    /// long-term Ed25519 key so the manifest verifies against the
    /// announcement pubkey consumers pinned.
    provenance_signer: Option<tenzro_model::SharedProvenanceSigner>,
    /// Sealed-model manifest store — write-through cache of
    /// `SealedModelManifest` records under the `sealed:` prefix in
    /// CF_MODELS. Written by the seal/install RPC handlers, read by the
    /// get/list handlers and the unseal path.
    sealed_model_store: Option<Arc<tenzro_model::SealedModelStore>>,
    /// This node's X25519 recipient keypair for sealed model shards.
    /// Publishers wrap the per-artifact AES-256-GCM content key to this
    /// key's public half (`x25519-envelope-aes-256-gcm`); the install
    /// path uses the secret half to unwrap. Silent-generated at
    /// `{data_dir}/model_recipient_x25519_key` on first use.
    model_recipient_key: Option<Arc<tenzro_crypto::encryption::X25519KeyPair>>,
    /// Jurisdiction signer used when this node serves a model itself — the
    /// chat handlers stamp a `tenzro_jurisdiction` receipt on locally-
    /// generated responses with it. Built from the same long-term Ed25519
    /// key as the provenance signer so receipts verify against the
    /// announcement pubkey consumers pinned. `None` when the operator
    /// declared no jurisdiction or no node key is available.
    jurisdiction_signer: Option<tenzro_model::SharedJurisdictionSigner>,
    /// This node's operator-declared jurisdiction claim, built once at
    /// startup from `NodeConfig::jurisdiction_country` / `jurisdiction_blocs`
    /// and — when TEE hardware is present — bound to a fresh attestation
    /// report. Rides every provider announcement and every locally-signed
    /// jurisdiction receipt. `None` means this node never satisfies a
    /// jurisdiction pin (fail-closed).
    jurisdiction_claim: Option<tenzro_types::JurisdictionClaim>,
    agent_runtime: Option<Arc<AgentRuntime>>,
    swarm_manager: Option<Arc<SwarmManager>>,

    // Background liveness sweeper — periodically marks silent skills/tools/
    // templates/tasks/sessions/services as Inactive and purges old terminal
    // rows. Held here so its `Drop` aborts the task on node shutdown.
    liveness_sweeper: Option<crate::liveness::LivenessSweeper>,

    // HuggingFace model integration
    pub hf_downloader: Option<Arc<HfDownloader>>,
    pub model_runtime: Option<Arc<ModelRuntime>>,

    // ONNX-backed runtimes (timeseries forecasting, vision encoders).
    // Default-built nodes carry stub runtimes that error cleanly on use;
    // ONNX-built nodes (cargo --features tenzro-model/onnx) get real ORT
    // sessions through the same handles.
    pub timeseries_runtime: Arc<TimeseriesRuntime>,
    pub vision_runtime: Arc<VisionRuntime>,
    pub text_embedding_runtime: Arc<TextEmbeddingRuntime>,
    pub segmentation_runtime: Arc<SegmentationRuntime>,
    pub text_segmentation_runtime: Arc<TextSegmentationRuntime>,
    pub detection_runtime: Arc<DetectionRuntime>,
    pub audio_runtime: Arc<AudioRuntime>,
    pub video_runtime: Arc<VideoRuntime>,

    /// Tenzro Train runtime — protocol layer for decentralized training
    /// (see `tenzro_training::TrainingRuntime`). Wired with write-through
    /// persistence to CF_TRAINING_RUNS / CF_TRAINING_RECEIPTS once storage
    /// is available.
    pub training_runtime: Arc<tenzro_training::TrainingRuntime>,

    /// Tenzro Media Gen runtime — protocol layer for generative-media
    /// inference (see `tenzro_media_gen::MediaGenRuntime`). Wired with
    /// write-through persistence to CF_MEDIA_GEN_RUNS /
    /// CF_MEDIA_GEN_RECEIPTS / CF_MEDIA_GEN_WORKERS once storage is
    /// available, and with an iroh-blobs output store once the resolver is
    /// bound.
    pub media_gen_runtime: Arc<tenzro_media_gen::MediaGenRuntime>,

    /// Concrete handle on the media-gen output store, kept alongside the
    /// `Arc<dyn MediaGenOutputStore>` inside the runtime because the gossip
    /// consumer needs `record_blake3` to learn the iroh-blobs locator for an
    /// output rendered on another node. `None` until the iroh resolver binds.
    pub media_gen_output_store: Option<Arc<tenzro_iroh::IrohMediaGenOutputStore>>,

    /// MoE expert-host runtime — per-expert FFN weights + gating networks
    /// for distributed mixture-of-experts serving. Serves both the local
    /// `tenzro_moe*` RPC surface and the `tenzro/moe` iroh ALPN.
    pub moe_runtime: Arc<tenzro_model::MoeExpertRuntime>,

    /// Shared iroh endpoint resolver (Phase C1, #219). Constructed at node
    /// startup when `NodeConfig::iroh` is `Some`; held here so every
    /// consumer (training `GradientPayloadStore`, storage
    /// `IrohBlobsDaBackend`, direct `tenzro://blob/<hash>` URI fetches)
    /// shares the same endpoint, ALPN, and hash space.
    pub iroh_resolver: Option<Arc<tenzro_iroh::IrohBackedResolver>>,

    /// Deferred A2A JSON-RPC dispatcher over iroh — Phase D2 (#223).
    ///
    /// Registered on the iroh router at bind time (in `init_ai_infrastructure`)
    /// because `iroh::Router::spawn` sets ALPNs once and a second router
    /// would overwrite them. The backing dispatcher (which needs
    /// `Arc<TenzroNode>` for `A2aState`) is installed later from `main.rs`
    /// once `Arc::new(node)` exists. Until that happens, the dispatcher
    /// returns a JSON-RPC `-32603` "dispatcher not yet bound" envelope to
    /// connecting peers.
    pub iroh_a2a_dispatcher: Option<Arc<tenzro_iroh::DeferredJsonRpcDispatcher>>,

    /// Deferred MCP-over-iroh stream handler. Same chicken-and-egg pattern
    /// as `iroh_a2a_dispatcher`: the `tenzro/mcp` ALPN is registered on the
    /// iroh router at bind time backed by an unbound trampoline, then the
    /// real `IrohMcpHandler` (which needs `Arc<TenzroNode>` to construct
    /// `TenzroMcpServer` instances per session) is installed from `main.rs`
    /// after `Arc::new(node)` exists.
    pub iroh_mcp_handler: Option<Arc<tenzro_iroh::DeferredMcpHandler>>,

    /// Deferred inference-over-iroh dispatcher. Same chicken-and-egg pattern
    /// as `iroh_a2a_dispatcher`: the `tenzro/infer` ALPN is registered on the
    /// iroh router at bind time backed by an unbound trampoline, then the
    /// real dispatcher (which needs `Arc<TenzroNode>` to call `handle_chat`)
    /// is installed from `main.rs` after `Arc::new(node)` exists.
    pub iroh_infer_dispatcher: Option<Arc<tenzro_iroh::DeferredJsonRpcDispatcher>>,

    /// Deferred HTTP-forward-over-iroh handler — the app-hosting ingress
    /// data plane. Same chicken-and-egg pattern as `iroh_a2a_dispatcher`:
    /// the `tenzro/http` ALPN is registered on the iroh router at bind time
    /// backed by an unbound trampoline, then the real ingress handler
    /// (which needs `Arc<TenzroNode>` to reach the site registry + app
    /// runtimes) is installed from `main.rs` after `Arc::new(node)` exists.
    pub iroh_http_handler: Option<Arc<tenzro_iroh::DeferredHttpHandler>>,

    // Identity & Payments (TDIP + MPP/x402)
    identity_registry: Option<Arc<IdentityRegistry>>,
    payment_gateway: Option<Arc<TenzroPaymentGateway>>,
    x402_server: Option<Arc<X402PaymentServer>>,

    /// Shared x402 facilitator, exposed as the verify/settle facilitator on
    /// the web API. Built in `init_payments` from the node's supported chains
    /// and settlement engine, and stored here so the web server can mount the
    /// `/facilitator/x402/*` routes for external resource servers that
    /// forward payloads for verification.
    x402_facilitator: Option<Arc<tenzro_payments::x402::X402Facilitator>>,

    /// Shared Visa TAP RFC 9421 verifier, exposed as the recognition
    /// facilitator on the web API. Built in `init_payments` alongside the
    /// gateway-registered [`VisaTapServer`] and stored here so the web server
    /// can mount the `/facilitator/visa-tap/*` recognition routes. `None`
    /// when the `visa-tap` feature is disabled or no identity registry exists.
    #[cfg(feature = "visa-tap")]
    visa_tap_verifier: Option<Arc<tenzro_payments::visa_tap::TapVerifier>>,

    /// Deferred event-loop sender slot for the consensus-mediated x402
    /// settlement callback. `init_payments` builds the callback before the
    /// event loop exists; `start()` fills this slot after `init_event_loop`
    /// so admitted settle txs also gossip. `None` when no callback was wired.
    x402_settle_event_slot: Option<Arc<parking_lot::Mutex<Option<mpsc::Sender<NodeEvent>>>>>,

    /// x402 Bazaar resource catalog — sellers register discoverable paid
    /// resources; buyers query matching listings. RocksDB-backed via
    /// `CF_SETTLEMENTS / bazaar:*`.
    bazaar_catalog: Option<Arc<tenzro_payments::x402::ResourceCatalog>>,

    /// Distributed database registry — the databases this node serves, placed
    /// local / LAN-cluster / network with the same tiering the model and
    /// storage layers use. RocksDB-backed via `CF_DATABASES`.
    database_registry: Option<Arc<tenzro_database::DatabaseRegistry>>,

    /// Live database-engine backends this node serves, keyed by engine id. The
    /// registry above tracks placement; this holds the concrete drivers the
    /// query path dispatches to. Empty until a driver backend is registered.
    db_engine_registry: Arc<crate::db_engine_registry::EngineRegistry>,

    /// Per-database usage counters for the managed-database query path —
    /// queries served, bytes moved, total billed. RocksDB-backed via
    /// `CF_DATABASES / usage/*` once storage is up; in-memory before that.
    db_usage_meter: Arc<tenzro_database::DatabaseUsageMeter>,

    /// Static-site registry — published site manifests mapping URL paths to
    /// iroh blob hashes, served at `/sites/{site_id}`. RocksDB-backed via
    /// `CF_METADATA / site:*` once storage is up; in-memory before that.
    site_registry: Arc<crate::sites::SiteRegistry>,

    /// Dynamic-ingress placement table — `site_id → [serving EndpointId]`.
    /// The edge consults it to decide whether to serve a site locally or
    /// forward the request to a remote serving node over the `tenzro/http`
    /// iroh ALPN. RocksDB-backed via `CF_METADATA / site_placement:*` once
    /// storage is up; in-memory before that.
    ingress_table: Arc<crate::ingress::IngressTable>,

    /// Function-deployment registry — `wasi:http` components served over the
    /// same `tenzro/http` ingress as static sites. Shares the site naming layer
    /// (alias / custom domain → id). RocksDB-backed via `CF_METADATA /
    /// function:*` once storage is up; in-memory before that.
    function_registry: Arc<crate::functions::FunctionRegistry>,

    /// Compiled `wasi:http` component cache for served functions. Present only
    /// when the node is built with the `wasi-skills` feature; a node without it
    /// holds function metadata but answers function requests with 501.
    #[cfg(feature = "wasi-skills")]
    function_components: Arc<crate::functions::FunctionComponentCache>,

    /// Sandbox for caller-supplied WASI 0.2 components, backing the
    /// `code-executor` builtin tool. Present only when the node is built
    /// with the `wasi-skills` feature; without it the tool reports itself
    /// unavailable rather than pretending to execute.
    #[cfg(feature = "wasi-skills")]
    sandboxed_tools: crate::mcp::wasm_tools::SandboxedToolRegistry,

    /// Machine-deployment registry — unmodified long-lived server processes run
    /// in a Firecracker microVM, served over the same `tenzro/http` ingress as
    /// static sites and functions. Shares the site naming layer. RocksDB-backed
    /// via `CF_METADATA / machine:*` once storage is up; in-memory before that.
    machine_registry: Arc<crate::machines::MachineRegistry>,

    /// Firecracker microVM supervisor. Present only when the node is built with
    /// the `firecracker` feature and set during the boot path once the iroh
    /// resolver and sealing key are available. `None` on a node that cannot run
    /// microVMs — it still serves the machine metadata RPCs but answers a machine
    /// request with 501 at ingress.
    #[cfg(feature = "firecracker")]
    machine_supervisor: Option<Arc<crate::machines::MachineSupervisor>>,

    /// App-hosting placement scheduler — decides which nodes serve a deployment,
    /// records the resulting leases (`CF_METADATA / hosting_lease:*`, hydrated on
    /// boot), and re-places on liveness loss / lease expiry by rewriting the
    /// `ingress_table`. In-memory before storage is up.
    placement_scheduler: Arc<crate::placement::PlacementScheduler>,

    /// Spec-2 per-DID admission controller. Wired into the consensus
    /// mempool at startup (`set_admission`); also held here so RPC
    /// handlers (`tenzro_getMempoolLane`, `tenzro_getMempoolStats`) can
    /// consult buckets and stats without going through the engine.
    admission: Option<Arc<tenzro_consensus::admission::AdmissionController>>,

    // Agent Kit (registry-driven agent runtime)
    agent_kit: Option<Arc<tenzro_agent_kit::AgentKit>>,

    // Token registry (unified cross-VM token tracking)
    token_registry: Option<Arc<TokenRegistry>>,

    // Interoperability
    bridge_router: Option<Arc<BridgeRouter>>,

    /// Asset USD price oracle (Chainlink `SYMBOL/USD` feeds). Backs the
    /// read-only `tenzro_getPrice` RPC used by wallet portfolio views.
    /// `None` when `bridge.prices` is unset / disabled.
    price_oracle: Option<Arc<tenzro_bridge::PriceOracle>>,

    /// Canton bridge adapter — exposes the Workflow / Obligation / Approval /
    /// Lifecycle DAML mirror methods used by `tenzro_mirror*` RPCs and the
    /// `consume_daml_events` polling path. Constructed in `init_bridge` from
    /// the node's `CantonConfig` when the Canton subsystem is enabled.
    /// Held here so RPC handlers can reach it directly (the canton mirror
    /// surface is intentionally caller-driven, not hooked into the
    /// post-execute log scan — the choice of which workflows mirror to
    /// which synchronizer is per-workflow operator policy, not a global
    /// node default).
    /// One adapter per Canton network the operator serves. Empty when
    /// the Canton subsystem is disabled or no network is configured.
    canton_adapters: std::collections::BTreeMap<
        crate::config::CantonNetwork,
        Arc<tenzro_bridge::canton::CantonAdapter>,
    >,

    /// TNZO CCT bridge — Chainlink CCT (Cross-Chain Token) helper that wraps
    /// a `ChainlinkCcipAdapter` plus the canonical TNZO pool registry
    /// (Ethereum / Base / Arbitrum / Optimism LockRelease + Solana BurnMint).
    /// Used by `tenzro_cctTransfer` RPCs to build CCT-formatted CCIP messages
    /// for native-TNZO cross-chain delivery without bridge custody risk.
    cct_bridge: Option<Arc<TnzoCctBridge>>,

    /// Hyperlane V3 adapter — local Mailbox-encoding message registry serving
    /// the `tenzro_hyperlane*` RPC namespace. Constructed unconditionally
    /// (pure local state, no network I/O at rest) so dispatch and getMessage
    /// share one outbound map.
    hyperlane_adapter: Arc<HyperlaneAdapter>,

    /// Axelar GMP adapter — local call-contract registry serving the
    /// `tenzro_axelar*` RPC namespace. Constructed unconditionally.
    axelar_adapter: Arc<AxelarAdapter>,

    /// Babylon Bitcoin-staking adapter — finality-provider registry serving
    /// the `tenzro_babylon*` RPC namespace. Constructed unconditionally
    /// against the Babylon testnet LCD endpoints.
    babylon_adapter: Arc<BabylonAdapter>,

    // TEE (optional). The local hardware provider is retained so attestation
    // requests routed to this node (RPC `tenzro_attest`, MCP `attest`, agent
    // workloads requesting confidential execution) can call
    // `provider.generate_attestation(user_data)` instead of returning a stub.
    // Populated by `init_tee()`; consumed by the TEE attestation request path
    // and exposed via `tee_provider()` accessor.
    tee_provider: Option<Box<dyn TeeProvider>>,
    tee_registry: Option<Arc<TeeRegistry>>,

    /// On-chain registry of validator-attested Plonky3 proof commitments.
    ///
    /// Populated by the consensus / settlement / RPC verify paths after they
    /// successfully run the off-EVM Plonky3 verifier; consumed by the
    /// `PRECOMPILE_ZK_VERIFY` precompile in the EVM. See
    /// `tenzro_vm::precompiles::ZkCommitmentRegistry`.
    zk_commitment_registry: Arc<tenzro_vm::precompiles::ZkCommitmentRegistry>,

    /// Quorum-gated attestation store for ZK proof commitments. A commitment is
    /// admitted to [`Self::zk_commitment_registry`] only after `2f+1`
    /// stake-weight of the active validator set has independently re-run
    /// `verify_proof_envelope` and co-signed it, and it remains slashable inside
    /// a fraud-proof window. Present only on nodes that hold a validator BLS key.
    /// See [`tenzro_consensus::ZkQuorumStore`].
    zk_quorum_store: Option<Arc<tenzro_consensus::ZkQuorumStore>>,

    /// EIP-7702 Type-4 delegation registry. Records active authority →
    /// target delegations applied via `tenzro_install7702Delegation`.
    /// The EVM executor consults this through
    /// [`tenzro_vm::eip7702::DelegationRegistry::resolve_target`] when an
    /// account's code field begins with the `0xef0100` designator.
    eip7702_delegation_registry: Arc<tenzro_vm::eip7702::DelegationRegistry>,

    /// Permit2 nonce bitmap. Tracks signed-and-spent permit nonces per
    /// owner so a relayer cannot replay a signature that has already
    /// been used. See [`tenzro_vm::permit2::Permit2NonceBitmap`].
    permit2_nonce_bitmap: Arc<tenzro_vm::permit2::Permit2NonceBitmap>,

    /// Secure-Mint registry. Holds per-token reserve attestations and
    /// enforces `circulating + amount ≤ reserve` on every gated mint.
    /// Tokens without a registered policy are unaffected. See
    /// [`tenzro_vm::secure_mint::SecureMintRegistry`].
    secure_mint_registry: Arc<tenzro_vm::secure_mint::SecureMintRegistry>,

    /// Chainlink Proof-of-Reserve pull adapter. Reads per-asset PoR
    /// aggregators and projects live readings into the reserve-attestation
    /// shape `tenzro_submitReserveAttestation` consumes — the automatic
    /// backing feed for tokenized-equity 1:1 mint (xStocks-class). Feeds are
    /// registered per tokenized asset; the adapter never signs (signing stays
    /// with the attestor identity at the RPC boundary).
    chainlink_por_adapter: Arc<tenzro_bridge::ChainlinkPorAdapter>,

    /// Corporate-action engine for tokenized equities: records splits,
    /// dividends, and other actions that adjust per-share ratios or emit
    /// distribution obligations against a tokenized-equity asset.
    corporate_action_engine: Arc<tenzro_vm::corporate_actions::CorporateActionEngine>,

    /// DvP saga orchestrator. Bundles multiple settlement legs (native /
    /// escrow / channel / external) into an all-or-compensate unit driven
    /// through the node-layer [`NodeLegExecutor`]. Persists to
    /// `CF_SETTLEMENTS` under `saga:` / `saga_creator:` prefixes.
    saga_orchestrator: Arc<tenzro_settlement::SagaOrchestrator>,

    /// Multilateral netting engine. Compresses gross bilateral obligations
    /// into a minimal deterministic instruction set per asset. Persists to
    /// `CF_SETTLEMENTS` under `netting:` prefix.
    netting_manager: Arc<tenzro_settlement::NettingManager>,

    /// Stable-asset registry. Holds per-issuer stable-unit policies
    /// (reserve source, controller config, allowed rails, settlement
    /// destination). Ties each unit to its SecureMint floor on the same
    /// token. See [`tenzro_vm::stable_asset_registry::StableAssetRegistry`].
    stable_asset_registry: Arc<tenzro_vm::stable_asset_registry::StableAssetRegistry>,

    /// Governance-set rate oracle backing stable-unit ↔ token conversion at
    /// settlement. Attached to the payment gateway as a
    /// [`crate::stable_conversion::OracleConversionHook`] so an agent can
    /// spend a stable unit while the payee settles in another asset.
    stable_rate_oracle: Arc<tenzro_vm::stable_rate_oracle::GovernanceSetRateOracle>,

    /// ERC-7943 (uRWA) per-token kill-switch + per-account freeze
    /// registry. The EVM transfer hook consults `check_transfer`
    /// pre-debit so a kill-switched token cannot move and a frozen
    /// balance cannot be transferred. Mutations flow through
    /// `tenzro_urwaSetFrozenTokens` / `tenzro_urwaTriggerKillSwitch` /
    /// `tenzro_urwaClearKillSwitch` / `tenzro_urwaForcedTransfer` —
    /// each admin-gated. Persisted to `CF_TOKENS` under
    /// `urwa_freeze:` and `urwa_kill:` prefixes via
    /// `UrwaRegistry::with_storage`.
    urwa_registry: Arc<tenzro_vm::erc7943::UrwaRegistry>,

    /// ERC-8004 on-chain agent-registry mirror (DID → sequential `agentId`).
    /// Populated during identity init with `NativeErc8004Mirror`, which
    /// dispatches signed EVM transactions to the canonical
    /// `IdentityRegistry` proxy at `addresses::IDENTITY_REGISTRY`.
    /// Settlement-outcome dispatchers read this to resolve a TDIP machine DID
    /// to the `uint256 agentId` allocated at registration time, which keys the
    /// `submitFeedback` row written into the on-chain `ReputationRegistry`.
    erc8004_agent_registry:
        Option<Arc<dyn tenzro_identity::erc8004::OnChainAgentRegistry>>,

    /// Per-node `erc8004-system` secp256k1 signer used by the two
    /// internal writers that have no caller signature: the TDIP
    /// `NativeErc8004Mirror::mirror_register_agent` path (fired from
    /// inside `IdentityRegistry::register_machine_with_fee`) and the
    /// Stripe SPT reputation dispatcher
    /// (`handle_process_spt_settlement_outcome` →
    /// `erc8004_reputation_dispatcher::dispatch_settlement_outcome`).
    /// Both run inside the node's trust boundary; `msg.sender` on the
    /// resulting EVM tx is the validator's `erc8004-system` address.
    /// User-facing RPC writes (`tenzro_registerAgent`,
    /// `submitFeedback`, `requestValidation`) stay caller-signed and
    /// do **not** use this signer — see the
    /// `project_erc8004_evm_architecture` memory for the locked
    /// signing-key decisions.
    ///
    /// The signer bakes the loopback JSON-RPC URL and chain_id at
    /// construction time; submission goes through the node's own
    /// `eth_sendRawTransaction`. `None` until storage is initialised
    /// (the URL needs `self.config.rpc_addr` and the genesis
    /// `chain_id` must be loaded first).
    erc8004_system_signer: Option<Arc<tenzro_bridge::evm_signer::EvmTransactionSigner>>,

    // Monitoring
    health_monitor: Arc<HealthMonitor>,
    metrics: Arc<MetricsCollector>,

    // Event loop
    event_loop_tx: Option<mpsc::Sender<NodeEvent>>,

    /// Cosmos-style snapshot ABCI store. On producer nodes, persists a
    /// snapshot every [`crate::snapshot::SnapshotConfig::interval_blocks`]
    /// finalized blocks under
    /// `<data_dir>/snapshots/<height>/`. Serves the four
    /// `tenzro_listSnapshots` / `tenzro_getSnapshotChunk` /
    /// `tenzro_offerSnapshot` / `tenzro_applySnapshotChunk` RPCs and the
    /// `--state-sync-from <peer>` bootstrap path. `None` when storage isn't
    /// initialised yet.
    snapshot_store: Option<Arc<crate::snapshot::SnapshotStore>>,

    /// Optional peer JSON-RPC URL for state-sync bootstrap. Set via
    /// [`TenzroNode::set_state_sync_peer`] (typically from `--state-sync-from`)
    /// before [`TenzroNode::start`] runs. When set, the start sequence
    /// fetches the highest snapshot from the peer and commits it to the
    /// live KV store between [`init_storage`] and [`init_network`],
    /// skipping block replay from genesis.
    state_sync_peer: Option<String>,

    /// Operator-supplied weak-subjectivity anchor for state-sync. MUST be
    /// the 32-byte state root committed at the snapshot height the peer
    /// will serve; the snapshot manifest's declared root is compared
    /// bit-for-bit against this anchor before any chunk is applied.
    /// Without this anchor, [`crate::snapshot::bootstrap_from_peer`]
    /// refuses to sync (a malicious peer could otherwise seed forged
    /// state). Typically passed via CLI alongside `--state-sync-from`.
    state_sync_anchor: Option<[u8; 32]>,

    /// Weak-subjectivity checkpoint enforced on the *block-sync* path:
    /// `(height, state_root)`. Distinct from `state_sync_anchor`, which only
    /// guards the snapshot-bootstrap path (it needs the root, not the height,
    /// because it takes the newest snapshot and matches the root). Block-sync
    /// imports blocks one at a time and verifies each block's commit-QC, but a
    /// node syncing forward from a low height would otherwise accept any
    /// QC-valid chain — including a forged historical fork signed by an old
    /// validator supermajority's keys (long-range attack). Pinning the imported
    /// block at `height` to `state_root` binds the synced chain to the trusted
    /// checkpoint: any fork diverging before the anchor yields a different
    /// state root at that height and is rejected at import. `None` disables the
    /// check (legacy young-chain replay, or snapshot-only bootstrap).
    weak_subjectivity_anchor: Option<(u64, [u8; 32])>,

    /// Live chain tip height — shared with EventLoop for lock-free RPC reads.
    ///
    /// The EventLoop updates this atomically on every finalized block (both local
    /// consensus blocks and gossipsub network blocks). RPC handlers read it with
    /// Acquire ordering so they always see the true chain tip without any storage I/O.
    ///
    /// This bypasses BlockStoreImpl::latest_height() which reads CF_METADATA and is
    /// subject to the `should_update = height > latest` guard that freezes metadata
    /// when a fresh chain starts at height 1 while CF_METADATA still holds a stale
    /// value from a prior run (e.g. 9998). The atomic is immune to this because it
    /// is always set unconditionally on every finalized block.
    chain_tip: Arc<AtomicU64>,

    /// Tracks the latest `StatusMessage` height advertised by each peer on
    /// `tenzro/status`. Consumed by `eth_syncing` / `tenzro_syncing` to
    /// report a real network-tip estimate (not just `local_tip`) so external
    /// clients can see when this node is lagging behind the network.
    ///
    /// Populated by the inbound status subscription wired in `init_event_loop`;
    /// queried by RPC handlers via `network_tip()`.
    pub(crate) peer_status: Arc<tenzro_network::PeerStatusTracker>,

    // Provider state
    pub provider_schedule: Arc<RwLock<ProviderSchedule>>,
    pub provider_pricing: Arc<RwLock<ProviderPricing>>,
    pub model_downloads: Arc<DashMap<String, ModelDownloadStatus>>,
    /// Background MoE expert-extraction jobs keyed by job id
    /// (`tenzro_moePrepareExperts` / `tenzro_moePrepareStatus`).
    pub moe_prepare_jobs: Arc<DashMap<String, crate::moe::MoePrepareJob>>,
    pub served_models: Arc<DashMap<String, ModelVisibility>>,
    pub model_services: Arc<DashMap<String, ModelServiceInstance>>,
    pub load_tracker: Arc<tenzro_model::LoadTracker>,
    /// In-memory store of recent chat-completion SSE streams keyed by
    /// completion id. Powers `Last-Event-ID`-based resume on
    /// `/v1/chat/completions` (Streaming Stability P0.1). GC is spawned at
    /// node init and runs every 30s; entries are evicted per
    /// [`crate::streaming::DEFAULT_TTL`] (finished) or
    /// [`crate::streaming::cursor::IN_FLIGHT_IDLE_TIMEOUT`] (in-flight).
    pub stream_cursors: crate::streaming::StreamCursorStore,
    /// Per-(provider, model) SLO histograms: TTFT, inter-token latency,
    /// completion/failure counters. Surfaced via `/metrics` as the
    /// `tenzro_inference_*` series. Cheap-to-clone (Arc inside).
    pub stream_slo_metrics: crate::streaming::StreamSloMetrics,
    /// Event bus for structured audit events (stream lifecycle, block
    /// lifecycle, settlement, etc.). Consumed by RPC subscriptions
    /// (`tenzro_subscribeEvents`) and the WebSocket / SSE event endpoints.
    /// Cheap-to-clone (`Arc` inside) — used by RPC handlers to publish.
    pub event_bus: Arc<tenzro_events::EventBus>,
    pub hardware_profile: Arc<RwLock<Option<HardwareProfile>>>,
    pub user_resources: Arc<DashMap<String, UserResource>>,
    pub transaction_history: Arc<RwLock<Vec<TransactionHistoryEntry>>>,
    pub runtime_roles: Arc<RwLock<RoleSet>>,
    /// Storage-provider runtime. `Some` only when this node's roles include
    /// `StorageProvider` — owns the object store, the per-epoch billing meter
    /// (PoR-gated), and the byte-epoch pricing policy. Spawned during startup
    /// once the iroh resolver and staking ledger are available.
    pub storage_runtime: Option<Arc<crate::storage_provider_runtime::StorageProviderRuntime>>,
    /// Compute-rental runtime. `Some` only when this node serves AI — a node
    /// that offers inference also rents out its CPU/GPU capacity for fixed
    /// terms. Owns the streaming-rental manager (availability-gated) and the
    /// per-epoch pricing policy. Shares one provider stake (via the same
    /// `ProviderObligations` tracker) and one balances map with the storage
    /// runtime. Spawned during startup once the staking ledger is available.
    pub compute_runtime: Option<Arc<crate::compute_rental_runtime::ComputeRentalRuntime>>,
    /// Prepaid-balance ledger for the streaming storage/compute settlement path.
    /// Funds the shared balances map from renters' on-chain TNZO (locking it into
    /// the prepaid vault) and persists every balance to `CF_SETTLEMENTS`. `Some`
    /// only when a provider runtime is spawned and durable storage + the token
    /// subsystem are available. The billing epoch calls `persist()` on it after
    /// streaming each epoch's slices.
    pub prepaid_ledger: Option<Arc<tenzro_settlement::PrepaidLedger>>,
    /// Cluster-serving runtime. `Some` only when this node serves AI — it lets
    /// the node join a LAN layer-pipeline cluster as a member and/or head one,
    /// serving a model too large for any single machine. Inert until a cluster
    /// plan activates it. The member splice loop is attached at startup so an
    /// AI-serving node can be recruited into a peer's cluster on demand.
    pub cluster_serving_runtime:
        Option<Arc<crate::cluster_serving_runtime::ClusterServingRuntime>>,
    /// OAuth state for onboarding key management (shared with MCP server)
    pub oauth_state: Arc<RwLock<Option<Arc<crate::mcp::oauth::OAuthState>>>>,
    /// Models discovered from gossipsub network announcements.
    /// Key: "{model_id}:{provider}" to allow multiple providers per model.
    pub network_models: Arc<DashMap<String, NetworkModelEntry>>,
    /// Agents discovered from gossipsub network announcements.
    /// Key: agent_id — last writer wins (most recent heartbeat).
    pub network_agents: Arc<DashMap<String, NetworkAgentEntry>>,
    /// Providers discovered from gossipsub network announcements.
    /// Key: peer_id — last writer wins (most recent heartbeat).
    pub network_providers: Arc<DashMap<String, NetworkProviderEntry>>,

    /// Cortex recurrent-depth workers, keyed by model_id.
    ///
    /// Each entry binds a recurrent-depth model backend (sidecar or mock) to
    /// pricing + receipt signing. Populated dynamically via
    /// `tenzro_registerCortexWorker` and consumed by `tenzro_cortexInference`.
    pub cortex_workers: Arc<DashMap<String, Arc<tenzro_cortex::CortexWorker>>>,

    /// In-memory registry of remote Cortex workers discovered via the
    /// `tenzro/cortex` gossipsub topic. The registry ingests signed
    /// `CortexAdvertisement` payloads, lazily evicts expired entries on
    /// snapshot, and is surfaced to clients via
    /// `tenzro_listRemoteCortexWorkers`.
    pub remote_cortex_workers: Arc<tenzro_cortex::RemoteWorkerRegistry>,

    /// Shared Cortex Prometheus metrics handle. Cloned into every local
    /// `CortexWorker` so per-request counters are aggregated across the
    /// whole node and exposed on the `/metrics` endpoint.
    pub cortex_metrics: tenzro_cortex::CortexMetrics,

    /// Optional source of the wallet-keystore password. When set, the wallet
    /// service is configured with `default_password` so FROST key shares are
    /// written to / loaded from the encrypted keystore on disk and the wallet
    /// PERSISTS across restarts. When `None`, the wallet is ephemeral
    /// (recreated every launch) — the historical behaviour.
    ///
    /// This is a trait object so `tenzro-node` stays platform-agnostic: the
    /// embedding app injects the implementation. Desktop apps inject a
    /// biometric Secure-Enclave unlocker (`tenzro-device-key`); headless nodes
    /// inject an env/file/KMS unlocker (`EnvUnlocker`, `StaticUnlocker`).
    keystore_unlocker: Option<Arc<dyn tenzro_keystore_unlock::KeystoreUnlocker>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeState {
    Created,
    Starting,
    Running,
    Stopping,
    Stopped,
}

// Validator key persistence lives in the `keygen` module. The running
// node never generates keys on `start` — it loads existing files and
// fails loud if any are missing. Generation is gated behind the
// explicit `tenzro-node init` operator subcommand. See `keygen.rs`
// for the rationale (universal production-BFT norm: zero major 2026
// BFT L1 does silent daemon-side auto-keygen on start).

impl TenzroNode {
    /// Create a new Tenzro Network node
    pub async fn new(config: NodeConfig) -> Result<Self> {
        info!("Initializing Tenzro Network node");
        info!("Roles: {}", config.roles);
        info!("Data directory: {:?}", config.data_dir);

        // Ensure directories exist
        config.ensure_data_dir()?;
        config.ensure_models_dir()?;

        // Initialize monitoring
        let health_monitor = Arc::new(HealthMonitor::new());
        let metrics = Arc::new(MetricsCollector::new());
        let initial_roles = config.roles.clone();

        // Derive chain_id from genesis (default 1337 for local). Used by the
        // peer status tracker to drop StatusMessages from peers on a different
        // chain — prevents a misconfigured peer or cross-chain noise from
        // poisoning the network-tip estimate consumed by `eth_syncing`.
        let chain_id = config.genesis.as_ref().map(|g| g.chain_id).unwrap_or(1337);
        let peer_status = tenzro_network::PeerStatusTracker::new(chain_id);
        let moe_disk_dir = config.data_dir.join("moe_experts");

        // Ingress table and placement scheduler share one `IngressTable` Arc so a
        // placement decision writes the routing table the edge reads. Both are
        // rebuilt storage-backed in the boot path once RocksDB is up.
        let ingress_table = Arc::new(crate::ingress::IngressTable::new());
        let placement_scheduler =
            Arc::new(crate::placement::PlacementScheduler::new(ingress_table.clone()));

        // The operator's own card, held at or below the network ceilings. An
        // operator that quotes above them is charged the ceiling, so clamping
        // here means the advertised rate is the one that will actually bill.
        let provider_pricing = {
            let mut p = config.provider_rates.inference.clone();
            p.clamp_to_network_maximums();
            p
        };

        Ok(Self {
            config,
            state: Arc::new(RwLock::new(NodeState::Created)),
            storage: None,
            network: None,
            consensus: None,
            consensus_out_rx: None,
            local_validator_address: None,
            validator_hybrid_signer: None,
            da_peer_registry: None,
            da_committee_backend: None,
            da_committee_server_handle: None,
            db_replicate_server_handle: None,
            da_possession_challenger: None,
            announce_signer: None,
            spt_ceiling_cache: None,
            mandate_store: None,
            vm_runtime: None,
            wallet_service: None,
            token: None,
            fee_processor: None,
            staking: None,
            bond_manager: None,
            compute_bond_manager: None,
            challenge_manager: None,
            sla_manager: None,
            sla_outstanding_probes: Arc::new(DashMap::new()),
            mpc_keygen_sessions: Arc::new(DashMap::new()),
            workflow_runtime: None,
            validator_registry: None,
            aa_validator_registry: None,
            account_factory: None,
            social_recovery_validator: None,
            session_key_validator: None,
            spending_limit_validator: None,
            webauthn_validator: None,
            hardware_signer_validators: None,
            recovery_pending: None,
            passkey_sessions: None,
            identity_scope_oracle: None,
            aa_entry_point: None,
            tee_key_oracle: None,
            tee_bound_validator: None,
            burn_quota_manager: None,
            burn_rate_manager: None,
            seed_agent_manager: None,
            reward_engine: None,
            vesting_manager: None,
            sponsorship_manager: None,
            seed_agent_gossip_tx: None,
            seed_agent_daemon: None,
            trainer_daemon: None,
            liquid_staking_pool: None,
            governance: None,
            treasury: None,
            settlement: None,
            channel_manager: None,
            escrow_manager: None,
            spec4_fill_registry: None,
            kill_switch_store: None,
            batch_processor: None,
            fee_collector: None,
            auth_engine: None,
            api_key_manager: None,
            app_registry: None,
            mcp_plugin_host: None,
            workflow_executor: parking_lot::Mutex::new(None),
            canton_analytics: None,
            bridge_analytics: None,
            chainlink_rate_limiter: Arc::new(
                crate::bridge_analytics::GcraLimiter::default(),
            ),
            tenant_idp_provisioner: None,
            admin_token: None,
            model_registry: None,
            model_hash_registry: None,
            provider_manager: None,
            inference_router: None,
            meta_router: None,
            usage_tracker: None,
            provenance_store: None,
            provenance_signer: None,
            sealed_model_store: None,
            model_recipient_key: None,
            jurisdiction_signer: None,
            jurisdiction_claim: None,
            agent_runtime: None,
            swarm_manager: None,
            liveness_sweeper: None,
            hf_downloader: None,
            model_runtime: None,
            timeseries_runtime: Arc::new(TimeseriesRuntime::new()),
            vision_runtime: Arc::new(VisionRuntime::new()),
            text_embedding_runtime: Arc::new(TextEmbeddingRuntime::new()),
            segmentation_runtime: Arc::new(SegmentationRuntime::new()),
            text_segmentation_runtime: Arc::new(TextSegmentationRuntime::new()),
            detection_runtime: Arc::new(DetectionRuntime::new()),
            audio_runtime: Arc::new(AudioRuntime::new()),
            video_runtime: Arc::new(VideoRuntime::new()),
            training_runtime: Arc::new(tenzro_training::TrainingRuntime::new()),
            media_gen_runtime: Arc::new(tenzro_media_gen::MediaGenRuntime::new()),
            media_gen_output_store: None,
            moe_runtime: Arc::new(tenzro_model::MoeExpertRuntime::with_config(
                tenzro_model::ResidencyConfig::auto().with_disk_dir(moe_disk_dir),
            )),
            iroh_resolver: None,
            iroh_a2a_dispatcher: None,
            iroh_mcp_handler: None,
            iroh_infer_dispatcher: None,
            iroh_http_handler: None,
            identity_registry: None,
            payment_gateway: None,
            x402_server: None,
            x402_facilitator: None,
            #[cfg(feature = "visa-tap")]
            visa_tap_verifier: None,
            x402_settle_event_slot: None,
            database_registry: None,
            db_engine_registry: Arc::new(crate::db_engine_registry::EngineRegistry::new()),
            db_usage_meter: Arc::new(tenzro_database::DatabaseUsageMeter::new()),
            site_registry: Arc::new(crate::sites::SiteRegistry::new()),
            ingress_table,
            function_registry: Arc::new(crate::functions::FunctionRegistry::new()),
            #[cfg(feature = "wasi-skills")]
            function_components: Arc::new(
                crate::functions::FunctionComponentCache::new().map_err(|e| {
                    crate::error::NodeError::Internal(format!(
                        "wasm engine init for functions: {e}"
                    ))
                })?,
            ),
            #[cfg(feature = "wasi-skills")]
            sandboxed_tools: crate::mcp::wasm_tools::SandboxedToolRegistry::with_default_host()
                .map_err(|e| {
                    crate::error::NodeError::Internal(format!(
                        "wasm engine init for the component sandbox: {e}"
                    ))
                })?,
            machine_registry: Arc::new(crate::machines::MachineRegistry::new()),
            #[cfg(feature = "firecracker")]
            machine_supervisor: None,
            placement_scheduler,
            bazaar_catalog: None,
            admission: None,
            agent_kit: None,
            token_registry: None,
            bridge_router: None,
            price_oracle: None,
            canton_adapters: std::collections::BTreeMap::new(),
            cct_bridge: None,
            hyperlane_adapter: Arc::new(HyperlaneAdapter::new(HyperlaneConfig::new(
                10_000,
                "0x0000000000000000000000000000000000000000",
                "0x0000000000000000000000000000000000000000",
            ))),
            axelar_adapter: Arc::new(AxelarAdapter::new(AxelarConfig::new(
                "tenzro",
                "0x0000000000000000000000000000000000000000",
                "0x0000000000000000000000000000000000000000",
            ))),
            babylon_adapter: Arc::new(BabylonAdapter::new(BabylonConfig::testnet(
                "tenzro-testnet",
            ))),
            tee_provider: None,
            tee_registry: None,
            zk_commitment_registry: Arc::new(tenzro_vm::precompiles::ZkCommitmentRegistry::new()),
            zk_quorum_store: None,
            eip7702_delegation_registry: Arc::new(tenzro_vm::eip7702::DelegationRegistry::new()),
            permit2_nonce_bitmap: Arc::new(tenzro_vm::permit2::Permit2NonceBitmap::new()),
            secure_mint_registry: Arc::new(tenzro_vm::secure_mint::SecureMintRegistry::new()),
            chainlink_por_adapter: Arc::new(tenzro_bridge::ChainlinkPorAdapter::new(String::new())),
            corporate_action_engine: Arc::new(tenzro_vm::corporate_actions::CorporateActionEngine::new(
                Arc::new(tenzro_vm::secure_mint::SecureMintRegistry::new()),
            )),
            saga_orchestrator: Arc::new(tenzro_settlement::SagaOrchestrator::new()),
            netting_manager: Arc::new(tenzro_settlement::NettingManager::new()),
            stable_asset_registry: Arc::new(tenzro_vm::stable_asset_registry::StableAssetRegistry::new()),
            stable_rate_oracle: Arc::new(tenzro_vm::stable_rate_oracle::GovernanceSetRateOracle::new()),
            urwa_registry: Arc::new(tenzro_vm::erc7943::UrwaRegistry::new()),
            erc8004_agent_registry: None,
            erc8004_system_signer: None,
            health_monitor,
            metrics,
            event_loop_tx: None,
            snapshot_store: None,
            state_sync_peer: None,
            state_sync_anchor: None,
            weak_subjectivity_anchor: None,
            chain_tip: Arc::new(AtomicU64::new(0)),
            peer_status,
            provider_schedule: Arc::new(RwLock::new(ProviderSchedule::default())),
            provider_pricing: Arc::new(RwLock::new(provider_pricing)),
            model_downloads: Arc::new(DashMap::new()),
            moe_prepare_jobs: Arc::new(DashMap::new()),
            served_models: Arc::new(DashMap::new()),
            model_services: Arc::new(DashMap::new()),
            load_tracker: Arc::new(tenzro_model::LoadTracker::new()),
            stream_cursors: crate::streaming::StreamCursorStore::new(),
            stream_slo_metrics: crate::streaming::StreamSloMetrics::new(),
            event_bus: Arc::new(tenzro_events::EventBus::new(
                tenzro_events::EventBusConfig::default(),
            )),
            hardware_profile: Arc::new(RwLock::new(None)),
            user_resources: Arc::new(DashMap::new()),
            transaction_history: Arc::new(RwLock::new(Vec::new())),
            runtime_roles: Arc::new(RwLock::new(initial_roles)),
            storage_runtime: None,
            compute_runtime: None,
            prepaid_ledger: None,
            cluster_serving_runtime: None,
            oauth_state: Arc::new(RwLock::new(None)),
            network_models: Arc::new(DashMap::new()),
            network_agents: Arc::new(DashMap::new()),
            network_providers: Arc::new(DashMap::new()),
            cortex_workers: Arc::new(DashMap::new()),
            remote_cortex_workers: Arc::new(tenzro_cortex::RemoteWorkerRegistry::new()),
            cortex_metrics: tenzro_cortex::CortexMetrics::new(),
            keystore_unlocker: None,
        })
    }

    /// Inject the keystore-password source that makes the wallet persistent
    /// across restarts. Call this BEFORE [`start`](Self::start) /
    /// [`init_wallet`](Self::init_wallet). See the `keystore_unlocker` field
    /// docs for the trait contract. Returns `self` for builder chaining.
    pub fn with_keystore_unlocker(
        mut self,
        unlocker: Arc<dyn tenzro_keystore_unlock::KeystoreUnlocker>,
    ) -> Self {
        self.keystore_unlocker = Some(unlocker);
        self
    }

    /// Set the keystore-password source on an already-constructed node (e.g.
    /// from an embedding app that built the node, then resolves the unlocker
    /// asynchronously). Same effect as [`with_keystore_unlocker`](Self::with_keystore_unlocker).
    pub fn set_keystore_unlocker(
        &mut self,
        unlocker: Arc<dyn tenzro_keystore_unlock::KeystoreUnlocker>,
    ) {
        self.keystore_unlocker = Some(unlocker);
    }

    /// Returns the live chain tip height maintained by the event loop.
    ///
    /// Reads the shared `Arc<AtomicU64>` that the event loop updates with
    /// `Ordering::Release` on every finalized block (both locally produced and
    /// gossipsub-received). This load uses `Ordering::Acquire` so all writes
    /// made before the store (block persistence, state commit) are visible.
    ///
    /// No storage I/O. Returns the actual current height regardless of whether
    /// CF_METADATA:latest_height is stale.
    pub fn chain_tip_height(&self) -> u64 {
        self.chain_tip.load(Ordering::Acquire)
    }

    /// Returns the maximum block height advertised by any fresh peer on
    /// `tenzro/status`, or `None` if no fresh peer status is recorded.
    ///
    /// "Fresh" = received within the last 60 seconds. Stale entries are
    /// excluded so that a peer that disconnects without sending an explicit
    /// goodbye doesn't pin the network tip at its last advertised height
    /// indefinitely.
    ///
    /// **Diagnostic only.** RPC handlers must call
    /// [`Self::network_tip_capped`] for sync detection — `network_tip`
    /// uses the unfiltered maximum and can be inflated by a single
    /// malicious peer.
    pub fn network_tip(&self) -> Option<u64> {
        self.peer_status.network_tip()
    }

    /// Robust network-tip estimator: median of fresh peer heights,
    /// capped at `local_tip + MAX_TIP_LEAD`. Used by `eth_syncing` /
    /// `tenzro_syncing` so a malicious peer cannot drag the local node
    /// into a fake-sync state.
    pub fn network_tip_capped(&self, local_tip: u64) -> Option<u64> {
        self.peer_status.network_tip_capped(local_tip)
    }

    /// Returns a snapshot of all non-expired network-discovered models.
    pub fn network_models_snapshot(&self) -> Vec<NetworkModelEntry> {
        let now = std::time::Instant::now();
        self.network_models
            .iter()
            .filter(|entry| {
                let ttl = std::time::Duration::from_secs(entry.registration.ttl_secs);
                now.duration_since(entry.last_seen) < ttl
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Returns a snapshot of all non-expired network-discovered agents.
    pub fn network_agents_snapshot(&self) -> Vec<NetworkAgentEntry> {
        let now = std::time::Instant::now();
        self.network_agents
            .iter()
            .filter(|entry| {
                let ttl = std::time::Duration::from_secs(entry.announcement.ttl_secs);
                now.duration_since(entry.last_seen) < ttl
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Returns a snapshot of all non-expired network-discovered providers.
    pub fn network_providers_snapshot(&self) -> Vec<NetworkProviderEntry> {
        let now = std::time::Instant::now();
        self.network_providers
            .iter()
            .filter(|entry| {
                let ttl = std::time::Duration::from_secs(entry.announcement.ttl_secs);
                now.duration_since(entry.last_seen) < ttl
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Start all subsystems
    pub async fn start(&mut self) -> Result<()> {
        {
            let mut state = self.state.write();
            // A node can only be started exactly once; any state other than
            // `Created` means we're either already running, in the middle of
            // a transition, or have been shut down. Distinguish "already
            // started" from generic invalid-state for operator clarity.
            match *state {
                NodeState::Created => {}
                NodeState::Starting | NodeState::Running => {
                    return Err(NodeError::AlreadyStarted("node".to_string()));
                }
                _ => {
                    return Err(NodeError::InvalidState(format!(
                        "Cannot start node in state {:?}",
                        *state
                    )));
                }
            }
            *state = NodeState::Starting;
        }

        info!("Starting Tenzro Network node...");

        // 1. Initialize storage
        self.init_storage().await?;

        // 1b. State-sync bootstrap (optional). If a peer URL was set on the
        //     config via `set_state_sync_peer`, fetch the highest snapshot
        //     from that peer and commit it to the live KV store before
        //     consensus comes up. This skips block replay and lets a fresh
        //     validator catch up to the chain tip in minutes.
        if let Some(peer_url) = self.state_sync_peer.clone() {
            match self.snapshot_store.as_ref() {
                Some(store) => {
                    info!(peer = %peer_url, "Starting state-sync bootstrap from peer");
                    match crate::snapshot::bootstrap_from_peer(
                        store.clone(),
                        &peer_url,
                        0,
                        self.state_sync_anchor,
                    )
                    .await
                    {
                        Ok(m) => info!(
                            height = m.height,
                            num_chunks = m.num_chunks,
                            state_root = %m.state_root_hex,
                            "State-sync bootstrap complete (state_root matched operator anchor)"
                        ),
                        Err(e) => warn!(
                            error = %e,
                            "State-sync bootstrap failed; continuing with normal block replay"
                        ),
                    }
                }
                None => warn!(
                    "State-sync requested but snapshot store unavailable; skipping"
                ),
            }
        }

        // 2. Initialize network
        self.init_network().await?;

        // 3. Initialize TEE (if enabled)
        if self.config.tee_enabled {
            self.init_tee().await?;
        }

        // 3b. Drop any configured role this node's hardware can't back, so it
        // never advertises a capability it lacks. TEE detection (above) and the
        // disk probe decide; an operator who set `--roles tee` on a box without
        // an enclave boots as a normal node rather than falsely claiming TEE.
        // Validator/AI roles are unaffected (stake-gated / permissionless).
        self.prune_unsupported_roles().await;

        // 4. Initialize VM runtime
        self.init_vm().await?;

        // 5. Initialize token economics
        self.init_token_economics().await?;

        // 6. Initialize wallet service
        self.init_wallet().await?;

        // 6b. Load the node Ed25519 signer used to authenticate outbound
        // model / provider / agent gossip announcements. Role-independent:
        // model providers sign announcements too, not just validators. This
        // is a DIFFERENT keypair from the libp2p transport key that derives
        // peer_id (`{data_dir}/p2p_key`) — consumers bind announcements to
        // this pubkey via first-seen pinning, not peer_id derivation. An
        // absent key leaves the signer as `None` — the node boots, but its
        // announcements won't be broadcast (consumers drop unsigned
        // announcements). A key that exists but is unreadable/corrupt is a
        // hard error.
        match crate::keygen::load_validator_keypair(&self.config.data_dir) {
            Ok(announce_keypair) => {
                let signer: Arc<dyn tenzro_crypto::signatures::Signer + Send + Sync> =
                    Arc::new(
                        tenzro_crypto::signatures::Ed25519SignerImpl::new(announce_keypair)
                            .map_err(|e| {
                                NodeError::Other(format!(
                                    "Failed to construct Ed25519 announcement signer: {}",
                                    e
                                ))
                            })?,
                    );
                self.announce_signer = Some(signer);
            }
            Err(NodeError::KeyMissing { .. }) => {
                warn!(
                    "No node Ed25519 key on disk — gossip announcements will not be \
                     signed or broadcast until a key is provisioned"
                );
            }
            Err(e) => return Err(e),
        }

        // 7. Initialize consensus.
        //
        // Only validators propose and vote. Every other role still builds the
        // engine and leaves it unstarted: block-sync accepts a block only after
        // verifying its embedded commit-QC against the validator set active at
        // that block's height, and that set — plus the epoch transitions needed
        // to walk across boundaries while catching up — lives in the engine's
        // `EpochManager`. A ModelProvider without one fetches blocks it can
        // never accept, so its local height never leaves genesis.
        let should_init_consensus = self.config.roles.is_validator();
        self.init_consensus(!should_init_consensus).await?;

        // 7b. Wire validator registry into the network layer for peer authorization
        if let Some(ref network) = self.network {
            let registry = Arc::new(NodeValidatorRegistry::new());

            // Seed the validator IDENTITY set from genesis. Identity checks
            // gate binding-based admission: a peer is only admitted as a
            // validator when its Identify binding is signed by one of these
            // Ed25519 keys (or, once consensus runs, a key in the live
            // epoch's validator set).
            if let Some(genesis) = &self.config.genesis {
                for gv in &genesis.validators {
                    match hex::decode(&gv.public_key) {
                        Ok(pubkey) => registry.add_identity(pubkey),
                        Err(e) => warn!(
                            key = %gv.public_key,
                            "Skipping malformed genesis validator public key: {}", e
                        ),
                    }
                }
            }

            // Prefer the live epoch's validator set once consensus is
            // running — it tracks stake-based joins and rotations that the
            // static genesis seed cannot.
            if let Some(consensus) = &self.consensus {
                registry.set_epoch_manager(consensus.epoch_manager());
            }

            // Register the local node's PeerId as a validator if we run consensus.
            if should_init_consensus
                && let Ok(local_peer_id) = network.local_peer_id().await {
                    registry.add_validator(local_peer_id);
                    info!("Registered local node {} as validator in peer authorization registry", local_peer_id);
                }

            // Register boot node peer IDs as validators. On testnet, boot nodes ARE validators
            // and non-validator nodes need to accept block/consensus messages from them.
            // Peer IDs are extracted from the /p2p/<peer_id> component of boot node multiaddrs.
            for boot_addr in &self.config.network.boot_nodes {
                let mut peer_id_opt = None;
                for proto in boot_addr.iter() {
                    if let libp2p::multiaddr::Protocol::P2p(pid) = proto {
                        peer_id_opt = Some(pid);
                    }
                }
                if let Some(peer_id) = peer_id_opt {
                    registry.add_validator(peer_id);
                    info!(peer = %peer_id, addr = %boot_addr, "Registered boot node as validator in peer authorization registry");
                }
            }

            // Committee-DA PeerId registry (Task #82). Bound to the validator
            // registry BEFORE it is moved into the network layer, so that every
            // subsequent validator admission (`try_add_validator`) records the
            // `(validator_address, peer_id)` binding the committee-DA surface
            // needs to dial committee members. Retained here to build the
            // surface below.
            let da_peers =
                Arc::new(crate::da_committee_surface::AddressPeerRegistry::new());
            registry.set_da_peer_registry(da_peers.clone());
            self.da_peer_registry = Some(da_peers);

            if let Err(e) = network.set_validator_registry(registry).await {
                warn!("Failed to set validator registry in network layer: {}", e);
            } else {
                info!("Validator registry wired into network peer manager");
            }

            // Wire the durable ban store so peer bans survive restarts and
            // are re-enforced at the libp2p transport layer on boot.
            if let Some(storage) = &self.storage {
                let ban_store =
                    Arc::new(NodeBanStore::new(storage.clone() as Arc<dyn KvStore>));
                if let Err(e) = network.set_ban_store(ban_store).await {
                    warn!("Failed to set ban store in network layer: {}", e);
                } else {
                    info!("Durable peer-ban store wired into network peer manager");
                }
            }
        }

        // 7b-bis. Wire the committee-resident Red Stuff DA backend + inbound
        // server (Task #82). Validators erasure-code blobs, distribute slivers
        // to the committee over `/tenzro/da/committee`, and collect `2f+1`
        // signed attestations into an availability certificate. The store is
        // durable (`CF_DA_COMMITTEE`) so a restarted validator still serves the
        // slivers it previously attested to. Only runs for validators (the
        // committee IS the validator set) with storage, network, and consensus
        // all present.
        if should_init_consensus
            && let (Some(network), Some(consensus), Some(storage), Some(da_peers)) = (
                self.network.clone(),
                self.consensus.clone(),
                self.storage.clone(),
                self.da_peer_registry.clone(),
            )
        {
            match self
                .init_committee_da(network, consensus, storage, da_peers)
                .await
            {
                Ok(()) => info!("Committee-resident DA backend + server wired"),
                Err(e) => warn!("Committee-DA init failed (continuing): {}", e),
            }
        }

        // 7b-ter. Wire the database replicated-write inbound server
        // (`/tenzro/db/replicate`). A node that holds a partition applies writes
        // fanned out to it by the serving holder to its own copy of the
        // partition and replies with the engine's response body. Runs on any
        // role with a network handle + a database registry — a ModelProvider or
        // dedicated database node can hold a partition without being a
        // validator. Fail-closed inside the handler: it applies only when this
        // node and the origin peer are both recognized holders.
        if let (Some(network), Some(db_registry)) =
            (self.network.clone(), self.database_registry.clone())
        {
            match network.local_peer_id().await {
                Ok(local_peer) => {
                    let net_dyn: Arc<dyn tenzro_network::NetworkService> = network;
                    let server = crate::db_holder_dispatch::DbReplicateServer::new(
                        net_dyn,
                        self.db_engine_registry.clone(),
                        db_registry,
                        local_peer,
                    );
                    match server.spawn().await {
                        Ok(handle) => {
                            self.db_replicate_server_handle = Some(handle);
                            info!("Database replicated-write inbound server wired");
                        }
                        Err(e) => warn!("Database-replicate server spawn failed (continuing): {}", e),
                    }
                }
                Err(e) => {
                    warn!("Database-replicate server skipped — local peer id unavailable: {}", e)
                }
            }
        }

        // 7c. Spawn the SeedAgent provisioning daemon (Agent-Swarm Spec 10
        // Task #42). Drives per-month treasury draws against every Active
        // SeedAgent and auto-pauses agents under disabled / past-sunset
        // charters. Gated by the consensus leader so only one validator
        // mutates per tick — convergence on other replicas happens via the
        // `tenzro/seed-agents` gossipsub topic.
        if let Some(seed_agents) = self.seed_agent_manager.clone()
            && self.config.roles.is_validator()
        {
            let mut daemon =
                tenzro_token::SeedAgentDaemon::new(seed_agents.clone());
            if let Some(tx) = self.seed_agent_gossip_tx.clone() {
                daemon = daemon.with_gossip(tx);
            }
            // Tick-authority gate: this validator is authorised iff it
            // is the elected leader for any of the next 32 views. The
            // window is wide enough that one validator in a healthy
            // 10-node fleet will consistently win the gate per 6-hour
            // poll interval; if consensus has stalled or this node is
            // not in the validator set, the conservative `Err` path
            // inside `is_leader_in_next_views` returns `true`, but the
            // earmark mutations are still serialised by the local
            // manager's locks so divergence is bounded.
            if let Some(consensus) = self.consensus.clone() {
                let gate: tenzro_token::TickAuthorityFn =
                    Arc::new(move || consensus.is_leader_in_next_views(32));
                daemon = daemon.with_tick_authority(gate);
            }
            // Surplus-disposition callback (Spec 10 Task #44). When the
            // wind-down sweep reports a non-zero surplus we log + emit
            // gossip; the actual burn / treasury-deposit happens via a
            // dedicated `ProposalType::SeedAgentSurplusDispose` governance
            // proposal that consumes the disposition record. Keeping the
            // daemon out of the supply-mutation path is intentional —
            // sensitive flag-day economic events must traverse the
            // proposal pipeline so they're recorded in the governance
            // log and bounded by tally quorum.
            let surplus_cb: tenzro_token::SurplusDispositionFn =
                Arc::new(|disposition| {
                    info!(
                        total = %disposition.total_wei,
                        burn = %disposition.burn_wei,
                        treasury = %disposition.treasury_wei,
                        burn_bps = disposition.surplus_burn_bps,
                        "SeedAgent surplus disposed at sunset — file SeedAgentSurplusDispose proposal to enact burn + treasury deposit"
                    );
                    Ok(())
                });
            daemon = daemon.with_surplus_disposition(surplus_cb);
            let daemon_arc = Arc::new(daemon);
            daemon_arc.clone().spawn();
            self.seed_agent_daemon = Some(daemon_arc);
            info!("SeedAgentDaemon spawned (validator role, leader-gated)");
        }

        // 8. Initialize settlement
        self.init_settlement().await.inspect_err(|e| {
            self.health_monitor.mark_unhealthy("settlement", e.to_string());
        })?;

        // 8b. Initialize OAuth 2.1 + DPoP + RAR auth engine
        self.init_auth().await.inspect_err(|e| {
            self.health_monitor.mark_unhealthy("auth", e.to_string());
        })?;

        // 9. Initialize AI infrastructure
        self.init_ai_infrastructure().await.inspect_err(|e| {
            self.health_monitor.mark_unhealthy("ai_infrastructure", e.to_string());
        })?;

        // 9a. Auto-register configured Cortex (recurrent-depth) workers.
        //     Best-effort: a failing worker is logged and skipped so the
        //     rest of node startup still proceeds.
        self.init_cortex_workers().await;

        // 9b. Wire VM precompiles to real InferenceRouter + SettlementEngine + ZkCommitmentRegistry.
        //     The VM runtime was created in init_vm() without these service-dependent
        //     precompiles registered, because the services did not yet exist. Now that
        //     init_settlement() and init_ai_infrastructure() have run, we register the
        //     three service-dependent precompiles (MODEL_INFERENCE, SETTLEMENT,
        //     ZK_VERIFY) for the first time via PrecompileRegistry::upgrade_services().
        //
        //     The ZK registry is constructed at node startup (zero-cost wrapper around
        //     a HashSet), so PRECOMPILE_ZK_VERIFY is always wired up here. The other
        //     two are wired only when their backing services exist on this node.
        if let Some(ref vm_runtime) = self.vm_runtime {
            vm_runtime.precompiles().upgrade_services(
                self.inference_router.clone(),
                self.settlement.clone(),
                Some(self.zk_commitment_registry.clone()),
            );
            if self.inference_router.is_some() {
                info!("MODEL_INFERENCE precompile wired to InferenceRouter");
            }
            if self.settlement.is_some() {
                info!("SETTLEMENT precompile wired to SettlementEngine");
            }
            info!(
                "ZK_VERIFY precompile wired to commitment-attestation \
                 (ZkCommitmentRegistry, current size: {})",
                self.zk_commitment_registry.len()
            );

            // NFT_FACTORY (0x1006) — swap the in-memory registry created at
            // VM construction time for one backed by RocksDB CF_NFTS, hydrating
            // any pre-existing collection / mint / balance / pointer state.
            if let Some(ref storage) = self.storage {
                vm_runtime
                    .precompiles()
                    .upgrade_nft_factory(storage.clone() as Arc<dyn KvStore>);
                info!("NFT_FACTORY precompile wired to persistent NftRegistry (CF_NFTS)");
            }

            // ERC-8004 system contracts are predeployed at genesis as
            // canonical OpenZeppelin-ERC721 proxies (see
            // `addresses::IDENTITY_REGISTRY` / `REPUTATION_REGISTRY` /
            // `VALIDATION_REGISTRY`); writes flow through standard EVM
            // transactions dispatched by `NativeErc8004Mirror` and read
            // through the `process_erc8004_registered_logs` event listener.
        }

        // 10. Initialize identity registry (TDIP)
        self.init_identity().await.inspect_err(|e| {
            self.health_monitor.mark_unhealthy("identity", e.to_string());
        })?;

        // 10b. Wire Spec-2 per-DID admission controller into the consensus
        //      mempool. Has to happen AFTER both consensus (#7) and identity
        //      (#10) are up — `NodeLaneResolver` reads from
        //      `IdentityRegistry` + `StakingManager`, neither of which exists
        //      at `init_consensus` time. Until this call executes the mempool
        //      runs in legacy size-only mode; the window is bounded by the
        //      few async steps between init_consensus() and here, during
        //      which the node has not yet started servicing inbound traffic.
        if let (Some(consensus), Some(identity), Some(staking), Some(bond_manager)) = (
            self.consensus.clone(),
            self.identity_registry.clone(),
            self.staking.clone(),
            self.bond_manager.clone(),
        ) {
            use crate::lane_resolver::NodeLaneResolver;
            use tenzro_consensus::admission::{AdmissionConfig, AdmissionController};

            let admission_config = AdmissionConfig::default();
            let resolver = Arc::new(NodeLaneResolver::new(
                identity,
                staking,
                bond_manager,
                admission_config.min_verified_stake,
                admission_config.bond_promotes_to_delegated,
                admission_config.bond_min_for_promotion,
            ));
            let admission = Arc::new(AdmissionController::new(admission_config, resolver));
            match consensus.set_admission(admission.clone()) {
                Ok(()) => {
                    info!(
                        "Spec-2 per-DID admission controller wired into consensus mempool \
                         (verified={}/{} burst, delegated={}/{} burst, open={}/{} burst)",
                        admission.config().verified_refill_rate_per_sec,
                        admission.config().verified_burst,
                        admission.config().delegated_refill_rate_per_sec,
                        admission.config().delegated_burst,
                        admission.config().open_refill_rate_per_sec,
                        admission.config().open_burst,
                    );
                    self.admission = Some(admission);
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "Admission controller already wired — refusing to overwrite"
                    );
                }
            }
        }

        // 10c. Wire the live account state reader into the consensus mempool
        //      for stateful admission (nonce ordering + balance coverage).
        //      Reads the same VM execution state (CF_STATE) that block
        //      execution writes, via a fresh StateAdapter per lookup.
        if let (Some(consensus), Some(storage)) = (self.consensus.clone(), self.storage.clone()) {
            use crate::lane_resolver::NodeAccountStateReader;

            let reader = Arc::new(NodeAccountStateReader::new(storage as Arc<dyn KvStore>));
            match consensus.set_state_reader(reader) {
                Ok(()) => {
                    info!(
                        "Mempool stateful admission wired (nonce ordering + balance \
                         coverage from VM execution state)"
                    );
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        "Mempool state reader already wired — refusing to overwrite"
                    );
                }
            }
        }

        // 11. Initialize payment gateway (MPP/x402)
        self.init_payments().await.inspect_err(|e| {
            self.health_monitor.mark_unhealthy("payments", e.to_string());
        })?;

        // 12. Initialize bridge
        self.init_bridge().await.inspect_err(|e| {
            self.health_monitor.mark_unhealthy("bridge", e.to_string());
        })?;

        // 13. Bootstrap reference agent templates (best-effort, non-fatal)
        self.bootstrap_agent_templates().await;

        // 13b. Bootstrap ecosystem tools and skills into CF_TOOLS / CF_SKILLS
        self.bootstrap_ecosystem_tools_and_skills();

        // 14. Initialize and start event loop
        self.init_event_loop().await.inspect_err(|e| {
            self.health_monitor.mark_unhealthy("event_loop", e.to_string());
        })?;

        // Now that the event loop is running, hand its sender to the
        // consensus-mediated x402 settlement callback so admitted settle txs
        // also gossip. `init_payments` built the callback before this point.
        if let (Some(slot), Some(sender)) =
            (&self.x402_settle_event_slot, self.event_loop_tx.clone())
        {
            *slot.lock() = Some(sender);
            info!("x402 settlement callback wired to event-loop gossip sender");
        }

        // 15. Clean up stale model services from previous session
        self.cleanup_expired_model_services();

        // 16. Spawn the streaming cursor GC. The join handle is intentionally
        // detached — the task lifetime is bound to the StreamCursorStore Arc
        // inside, and it runs until the process exits.
        drop(
            self.stream_cursors
                .spawn_gc(std::time::Duration::from_secs(30)),
        );

        // Mark as running
        *self.state.write() = NodeState::Running;
        info!("Tenzro Network node started successfully");

        Ok(())
    }

    /// Stop all subsystems gracefully
    pub async fn stop(&mut self) -> Result<()> {
        {
            let mut state = self.state.write();
            // Only `Running` nodes can be stopped. `Created` / `Starting`
            // means the node hasn't reached a steady state yet — surface
            // that as the `NotStarted` variant so operators get an
            // actionable error rather than a generic state mismatch.
            match *state {
                NodeState::Running => {}
                NodeState::Created | NodeState::Starting => {
                    return Err(NodeError::NotStarted("node".to_string()));
                }
                _ => {
                    return Err(NodeError::InvalidState(format!(
                        "Cannot stop node in state {:?}",
                        *state
                    )));
                }
            }
            *state = NodeState::Stopping;
        }

        info!("Stopping Tenzro Network node...");

        // Stop in reverse order
        // Note: In a full implementation, each subsystem would have a proper shutdown method

        if let Some(mut challenger) = self.da_possession_challenger.take() {
            challenger.stop();
        }
        if let Some(handle) = self.da_committee_server_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.db_replicate_server_handle.take() {
            handle.abort();
        }
        self.da_committee_backend = None;
        self.da_peer_registry = None;

        self.bridge_router = None;
        self.payment_gateway = None;
        self.x402_server = None;
        self.x402_facilitator = None;
        self.bazaar_catalog = None;
        self.database_registry = None;
        self.db_engine_registry = Arc::new(crate::db_engine_registry::EngineRegistry::new());
        self.db_usage_meter = Arc::new(tenzro_database::DatabaseUsageMeter::new());
        self.site_registry = Arc::new(crate::sites::SiteRegistry::new());
        self.ingress_table = Arc::new(crate::ingress::IngressTable::new());
        self.placement_scheduler =
            Arc::new(crate::placement::PlacementScheduler::new(self.ingress_table.clone()));
        self.admission = None;
        self.identity_registry = None;
        self.agent_runtime = None;
        self.aa_validator_registry = None;
        self.aa_entry_point = None;
        self.tee_key_oracle = None;
        self.tee_bound_validator = None;
        self.identity_scope_oracle = None;
        self.inference_router = None;
        self.provider_manager = None;
        self.model_registry = None;
        self.settlement = None;
        self.channel_manager = None;
        self.escrow_manager = None;
        self.spec4_fill_registry = None;
        self.kill_switch_store = None;
        self.auth_engine = None;
        self.treasury = None;
        self.governance = None;
        self.staking = None;
        self.token = None;
        self.fee_processor = None;
        self.wallet_service = None;
        self.vm_runtime = None;
        self.consensus = None;
        self.tee_registry = None;
        self.tee_provider = None;
        self.network = None;
        self.storage = None;

        *self.state.write() = NodeState::Stopped;
        info!("Tenzro Network node stopped");

        Ok(())
    }

    /// Get node status
    pub async fn status(&self) -> NodeStatus {
        let state = *self.state.read();
        let metrics = self.metrics.get_metrics();
        let health = self.health_monitor.get_status(
            tenzro_types::primitives::BlockHeight::from(0),
            metrics.peer_count as usize,
        );

        let (iroh_enabled, iroh_endpoint_id, iroh_alpns) = match &self.iroh_resolver {
            Some(resolver) => {
                let mut alpns = vec!["iroh-blobs".to_string()];
                if self.iroh_a2a_dispatcher.is_some() {
                    alpns.push("tenzro/a2a".to_string());
                }
                if self.iroh_mcp_handler.is_some() {
                    alpns.push("tenzro/mcp".to_string());
                }
                alpns.push("tenzro/moe".to_string());
                if self.iroh_infer_dispatcher.is_some() {
                    alpns.push("tenzro/infer".to_string());
                }
                (true, Some(resolver.endpoint().id().to_string()), alpns)
            }
            None => (false, None, Vec::new()),
        };

        let self_peer_id = match &self.network {
            Some(net) => net.local_peer_id().await.ok().map(|p| p.to_string()),
            None => None,
        };

        NodeStatus {
            state: format!("{:?}", state),
            roles: self.config.roles.clone(),
            health_status: health.overall,
            uptime_secs: metrics.uptime_secs,
            block_height: self.chain_tip_height(),
            peer_count: metrics.peer_count,
            data_dir: self.config.data_dir.clone(),
            tee_capable: self.tee_provider.is_some(),
            tee_vendor: self.tee_provider.as_ref().map(|p| p.vendor()),
            iroh_enabled,
            iroh_endpoint_id,
            iroh_alpns,
            reachability: self.reachability_tier().map(|t| t.as_str().to_string()),
            self_peer_id,
        }
    }

    /// Get health monitor
    pub fn health_monitor(&self) -> &Arc<HealthMonitor> {
        &self.health_monitor
    }

    /// Get metrics collector
    pub fn metrics(&self) -> &Arc<MetricsCollector> {
        &self.metrics
    }

    // Private initialization methods

    async fn init_storage(&mut self) -> Result<()> {
        info!("Initializing storage...");

        let storage_config = StorageConfig::new(self.config.data_dir.join("db"));
        let store = Arc::new(RocksDbStore::open(&storage_config)?);

        // Initialize genesis block if configured
        if let Some(genesis_config) = &self.config.genesis {
            info!("Initializing genesis block...");
            let _genesis_block = crate::genesis::initialize_genesis(&store, genesis_config).await?;
            info!("Genesis block initialized successfully");

            // One-time bootstrap: if the faucet was configured, make sure a
            // real Ed25519 signing key is provisioned so the RPC faucet
            // handler can submit real signed transactions through consensus
            // instead of bypassing it with direct token.transfer() calls.
            // Idempotent on reboot — no-op after the first successful run.
            if genesis_config.faucet.as_ref().map(|f| f.enabled).unwrap_or(false) {
                crate::genesis::provision_faucet_signing_key(&store).await?;
                // Refill the faucet on every boot if its balance has run dry.
                // Pre-alpha-only safety: a chain-state divergence post-OOM can
                // leave the faucet at zero, which blocks all onboarding flows
                // until manually fixed. This auto-tops-up to 10M TNZO if the
                // balance falls below 1M TNZO.
                crate::genesis::refill_faucet_if_low(&store).await?;
            }
        }

        self.storage = Some(store.clone());
        self.health_monitor.mark_healthy("storage");

        // Initialize the API key manager. Hydrates `ApiKeyRecord` cache from
        // `CF_API_KEYS` so previously-issued keys survive restart. Required
        // before any RPC dispatch so the scoped-method gate is active from
        // request #1.
        let api_keys = crate::api_key::ApiKeyManager::new(
            store.clone() as Arc<dyn tenzro_storage::KvStore>,
        )?;
        self.api_key_manager = Some(api_keys);

        // Permissionless application registry for developer payments.
        // Hydrates `AppRecord` rows from `CF_SETTLEMENTS` (`app:` prefix)
        // so registered apps survive restart and every node converges on
        // the same registry.
        let app_registry = crate::app_registry::AppRegistry::new(
            store.clone() as Arc<dyn tenzro_storage::KvStore>,
        )?;
        self.app_registry = Some(app_registry);

        // MCP plugin host. Lets the operator broker custom + third-
        // party MCPs (stdio + remote Streamable HTTP + legacy SSE)
        // through their Tenzro node. Initializes the sealed credential
        // vault rooted at either:
        // - `node_config.mcp_plugin_host.master_secret_hex` (explicit
        //   operator-supplied 32-byte hex string), or
        // - HKDF-SHA256 over a deterministic node-identity-derived
        //   seed (graceful default for single-operator dev).
        //
        // The vault root is opaque to tenants. Tenants never see the
        // operator's upstream credentials — they only present a
        // Tenzro API key, the operator's upstream auth is injected at
        // invocation time from the sealed vault.
        let vault_ikm: [u8; 32] = if let Some(hex) =
            self.config.mcp_plugin_host.master_secret_hex.as_deref()
        {
            let bytes = hex::decode(hex).map_err(|e| {
                NodeError::Internal(format!(
                    "mcp_plugin_host.master_secret_hex: invalid hex: {}",
                    e
                ))
            })?;
            if bytes.len() != 32 {
                return Err(NodeError::Internal(format!(
                    "mcp_plugin_host.master_secret_hex: expected 32 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut ikm = [0u8; 32];
            ikm.copy_from_slice(&bytes);
            ikm
        } else {
            // Auto-derive IKM from the node's persistent identity.
            // The identity key is fixed per data_dir so the vault root
            // is stable across restarts without operator config. We
            // hash a domain-separated label || data_dir path so two
            // node identities on the same machine produce different
            // IKMs.
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"tenzro/mcp/plugin-host/auto-ikm/v1");
            hasher.update(self.config.data_dir.to_string_lossy().as_bytes());
            let digest = hasher.finalize();
            let mut ikm = [0u8; 32];
            ikm.copy_from_slice(&digest);
            ikm
        };
        let vault = Arc::new(crate::mcp_plugin_host::OperatorCredentialVault::new(
            store.clone() as Arc<dyn tenzro_storage::KvStore>,
            vault_ikm,
        ));
        let plugin_host = Arc::new(crate::mcp_plugin_host::McpPluginHost::new(vault));
        self.mcp_plugin_host = Some(plugin_host);

        // Per-tenant Canton usage counters. Hydrates `CantonKeyAnalytics`
        // cache from `CF_CANTON_ANALYTICS` so historical counters survive
        // restart. Incremented from the canton RPC dispatch path; surfaced
        // via `tenzro_canton_getMyAnalytics` (subject self-read) and
        // `tenzro_canton_listApiKeyAnalytics` (operator admin-read).
        let canton_analytics = crate::canton_analytics::CantonAnalyticsManager::new(
            store.clone() as Arc<dyn tenzro_storage::KvStore>,
        )?;
        self.canton_analytics = Some(canton_analytics);

        // Per-tenant Chainlink/bridge usage counters. Same pattern as
        // canton_analytics — hydrates from `CF_BRIDGE_ANALYTICS` so
        // historical CU attribution survives restart. Incremented on
        // every chainlink-scoped RPC call; surfaced via
        // `tenzro_getBridgeAnalytics` (subject self-read) and
        // `tenzro_listBridgeAnalytics` (operator admin-read).
        let bridge_analytics = crate::bridge_analytics::BridgeAnalyticsManager::new(
            store.clone() as Arc<dyn tenzro_storage::KvStore>,
        )?;
        self.bridge_analytics = Some(bridge_analytics);

        // Stage 2.b: per-tenant upstream IdP provisioner. Built only
        // when `canton.identity_providers.enabled` + `mgmt_url` +
        // M2M client credentials are all set. The provisioner mints
        // and caches its own Auth0 Management API token from the
        // client credentials (24h expiry, refreshed 60s before),
        // so no static token ever sits in the env. Devnet leaves
        // everything unset so `handle_create_api_key` falls through
        // to the Stage 1 shared-principal flow. Production flips
        // `CANTON_IDP_ENABLED=true` + sets `CANTON_IDP_MGMT_URL` +
        // `CANTON_IDP_MGMT_CLIENT_ID` + `CANTON_IDP_MGMT_CLIENT_SECRET`
        // so each tenant gets a dedicated OAuth client.
        {
            let idp_cfg = &self.config.canton.identity_providers;
            if idp_cfg.enabled
                && let (Some(mgmt_url), Some(mgmt_client_id), Some(mgmt_client_secret)) = (
                    idp_cfg.mgmt_url.as_deref(),
                    idp_cfg.mgmt_client_id.as_deref(),
                    idp_cfg.mgmt_client_secret.as_deref(),
                )
            {
                match tenzro_bridge::tenant_idp::Auth0ManagementClient::new(
                    mgmt_url,
                    mgmt_client_id,
                    mgmt_client_secret,
                ) {
                    Ok(client) => {
                        self.tenant_idp_provisioner =
                            Some(Arc::new(client) as Arc<dyn tenzro_bridge::tenant_idp::TenantIdpProvisioner>);
                        tracing::info!(
                            "Stage 2.b: tenant-IdP provisioner wired (Auth0 management)"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Stage 2.b: tenant-IdP provisioner construction failed; falling back to Stage 1"
                        );
                    }
                }
            }
        }

        // Swap in the persistent variants of EIP-7702 / Permit2 /
        // Secure-Mint registries now that storage is available. The
        // default `::new()` variants installed at struct-creation time
        // are in-memory-only and would silently drop authorizations /
        // nonce bitmaps / reserve policies across restart.
        self.eip7702_delegation_registry = Arc::new(
            tenzro_vm::eip7702::DelegationRegistry::with_storage(
                store.clone() as Arc<dyn tenzro_storage::KvStore>,
            ),
        );
        self.permit2_nonce_bitmap = Arc::new(
            tenzro_vm::permit2::Permit2NonceBitmap::with_storage(
                store.clone() as Arc<dyn tenzro_storage::KvStore>,
            ),
        );
        self.secure_mint_registry = Arc::new(
            tenzro_vm::secure_mint::SecureMintRegistry::with_storage(
                store.clone() as Arc<dyn tenzro_storage::KvStore>,
            ),
        );
        // Corporate-action engine shares the storage-backed Secure-Mint
        // registry (splits mutate the reserve policy, dividends record only)
        // and persists its own action chain + equity profiles to CF_TOKENS.
        self.corporate_action_engine = Arc::new(
            tenzro_vm::corporate_actions::CorporateActionEngine::with_storage(
                self.secure_mint_registry.clone(),
                store.clone() as Arc<dyn tenzro_storage::KvStore>,
            ),
        );
        // DvP saga orchestrator + netting engine: write-through to
        // CF_SETTLEMENTS and rehydrate open/computed records on boot.
        self.saga_orchestrator = Arc::new(
            tenzro_settlement::SagaOrchestrator::with_storage(
                store.clone() as Arc<dyn tenzro_storage::KvStore>,
            ),
        );
        self.netting_manager = Arc::new(
            tenzro_settlement::NettingManager::with_storage(
                store.clone() as Arc<dyn tenzro_storage::KvStore>,
            ),
        );
        // Chainlink Proof-of-Reserve pull adapter. The aggregator lives on an
        // external chain (e.g. eip155:1), so the operator supplies the RPC
        // endpoint via `TENZRO_POR_RPC_URL`; feeds are registered per
        // tokenized asset over `tenzro_registerPorFeed`. Empty URL leaves the
        // adapter constructed but unable to read until configured.
        let por_rpc_url = std::env::var("TENZRO_POR_RPC_URL").unwrap_or_default();
        self.chainlink_por_adapter =
            Arc::new(tenzro_bridge::ChainlinkPorAdapter::new(por_rpc_url));
        self.stable_asset_registry = Arc::new(
            tenzro_vm::stable_asset_registry::StableAssetRegistry::with_storage(
                store.clone() as Arc<dyn tenzro_storage::KvStore>,
            ),
        );
        self.urwa_registry = Arc::new(
            tenzro_vm::erc7943::UrwaRegistry::with_storage(
                store.clone() as Arc<dyn tenzro_storage::KvStore>,
            ),
        );

        // Load the operator admin token from the environment. Gates
        // operator-only mutation RPCs (createApiKey/revokeApiKey/
        // listApiKeys/stake/unstake/registerProvider). Fail-closed:
        // a node with no env var set rejects every gated call. The
        // token is captured exactly once at startup so the env var can
        // be unset (or rotated and restart) without leaving the in-process
        // copy stale.
        match std::env::var("TENZRO_ADMIN_TOKEN") {
            Ok(token) if !token.is_empty() => {
                self.admin_token = Some(token);
                tracing::info!(
                    "operator admin-token gate ENABLED — mutation RPCs require X-Tenzro-Admin-Token"
                );
            }
            Ok(_) => {
                tracing::warn!(
                    "TENZRO_ADMIN_TOKEN is set but empty — admin gate is fail-closed, mutation RPCs unreachable"
                );
            }
            Err(_) => {
                tracing::warn!(
                    "TENZRO_ADMIN_TOKEN not set — admin gate is fail-closed, mutation RPCs unreachable (set the env var on the service unit to unlock)"
                );
            }
        }

        // Initialize the snapshot ABCI store on top of the live KV store.
        // Snapshots land in `<data_dir>/snapshots/` and are produced
        // periodically by the EventLoop's finality subscriber once the
        // node is fully started.
        let kv: Arc<dyn tenzro_storage::KvStore> = store.clone();
        let snapshot_store = Arc::new(crate::snapshot::SnapshotStore::new(
            &self.config.data_dir,
            kv,
            self.config.snapshot.clone(),
        )?);
        // Reclaim any orphaned snapshot directories left by a prior run —
        // including husks from a crashed/ENOSPC-killed produce_at, which the
        // retention pass alone never collects. Runs on every node regardless
        // of whether this node produces snapshots.
        snapshot_store.sweep_on_startup();
        self.snapshot_store = Some(snapshot_store);

        // Provision the per-node ERC-8004 system signer. Loads the
        // secp256k1 key from `{data_dir}/validator_erc8004_system_key`
        // — silently generated on first boot or after a clean upgrade,
        // per the `load_or_generate_erc8004_system_key` contract — and
        // wires an `EvmTransactionSigner` pointed at this node's own
        // loopback JSON-RPC. Used by two node-internal writers (TDIP
        // mirror + Stripe SPT reputation dispatcher); never used for
        // user-facing RPC writes.
        //
        // Construction is best-effort: a key-decode or signer-init
        // failure logs a warning and leaves `erc8004_system_signer =
        // None`, which in turn leaves the ERC-8004 mirror disabled at
        // `init_identity()` — but the rest of the node still boots.
        let chain_id = self
            .config
            .genesis
            .as_ref()
            .map(|g| g.chain_id)
            .unwrap_or(1337);
        let loopback_rpc_url = format!("http://{}", self.config.rpc_addr);
        match crate::keygen::load_or_generate_erc8004_system_key(&self.config.data_dir) {
            Ok(key_bytes) => {
                match tenzro_bridge::evm_signer::EvmTransactionSigner::new(
                    &key_bytes,
                    chain_id,
                    loopback_rpc_url.clone(),
                ) {
                    Ok(signer) => {
                        let signer = Arc::new(signer);
                        info!(
                            target: "tenzro::erc8004",
                            address = %signer.sender_address(),
                            chain_id,
                            rpc = %loopback_rpc_url,
                            "erc8004-system signer ready (mirror + SPT dispatcher write path)"
                        );
                        self.erc8004_system_signer = Some(signer);
                    }
                    Err(e) => {
                        warn!(
                            target: "tenzro::erc8004",
                            error = %e,
                            "erc8004-system signer init failed — mirror + SPT dispatcher will be disabled"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    target: "tenzro::erc8004",
                    error = %e,
                    "erc8004-system key load/generate failed — mirror + SPT dispatcher will be disabled"
                );
            }
        }

        Ok(())
    }

    async fn init_network(&mut self) -> Result<()> {
        info!("Initializing network...");

        // Pass the node's data_dir to the network config for persistent keypair storage
        let mut network_config = self.config.network.clone();
        network_config.data_dir = Some(self.config.data_dir.clone());

        // Validators attach a signed peer binding to the Identify
        // agent_version: the validator Ed25519 key signs the node's
        // transport PeerId, letting remote peers verify — over the
        // transport-authenticated channel — that this PeerId is operated by
        // an active validator identity. Without the binding, peers are never
        // admitted to validator-only topics via Identify.
        if self.config.roles.is_validator() {
            match crate::keygen::load_validator_keypair(&self.config.data_dir) {
                Ok(validator_keypair) => {
                    let p2p_keypair =
                        tenzro_network::load_or_generate_keypair(&network_config.data_dir)
                            .map_err(|e| {
                                NodeError::Other(format!(
                                    "Failed to load p2p keypair for peer binding: {}",
                                    e
                                ))
                            })?;
                    let local_peer_id = libp2p::PeerId::from(p2p_keypair.public());
                    let validator_pubkey = validator_keypair.public_key().to_bytes();
                    let signer = tenzro_crypto::signatures::Ed25519SignerImpl::new(
                        validator_keypair,
                    )
                    .map_err(|e| {
                        NodeError::Other(format!(
                            "Failed to construct peer-binding signer: {}",
                            e
                        ))
                    })?;
                    let signature = tenzro_crypto::signatures::Signer::sign(
                        &signer,
                        &tenzro_network::binding_payload(&local_peer_id),
                    )
                    .map_err(|e| {
                        NodeError::Other(format!("Failed to sign peer binding: {}", e))
                    })?;
                    network_config.user_agent = tenzro_network::encode_agent_binding(
                        &network_config.user_agent,
                        &validator_pubkey,
                        &signature.to_bytes(),
                    );
                    info!(peer = %local_peer_id, "Attached signed validator peer binding to Identify agent_version");
                }
                Err(NodeError::KeyMissing { .. }) => {
                    warn!(
                        "No validator Ed25519 key on disk — Identify peer binding not \
                         attached; remote peers will not admit this node to \
                         validator-only topics"
                    );
                }
                Err(e) => return Err(e),
            }
        }

        let network = Arc::new(TenzroNetworkService::new(network_config).await?);
        self.network = Some(network);
        self.health_monitor.mark_healthy("network");

        Ok(())
    }

    async fn init_tee(&mut self) -> Result<()> {
        info!("Detecting TEE capability...");

        // TEE is an OPTIONAL capability — every node participates in
        // consensus regardless of whether it has a TEE. TEE-capable nodes
        // additionally serve confidential-compute and custodial-key
        // workloads on behalf of non-TEE peers.
        //
        // Treating TEE absence as a health "degradation" is wrong: a
        // commodity x86 box with no SEV/TDX is not malfunctioning — it
        // simply can't host the optional confidential-compute capability.
        // We therefore only register the "tee" subsystem in the health
        // monitor when a provider is actually present; absence is logged
        // and surfaces through the capability API instead of /health.
        match detect_tee().await {
            Some(provider) => {
                let vendor = provider.vendor();
                info!(
                    tee_vendor = ?vendor,
                    "TEE capability available — node will advertise confidential-compute"
                );
                let registry = Arc::new(TeeRegistry::new(300));
                self.tee_registry = Some(registry);
                // Retain the local hardware provider so the attestation
                // request paths (RPC, MCP, agent workloads) can call
                // `tee_provider().generate_attestation(user_data)` directly
                // against the local enclave instead of returning a stub.
                self.tee_provider = Some(provider);
                self.health_monitor.mark_healthy("tee");
            }
            None => {
                info!(
                    "No TEE hardware on this node — participating in consensus only; \
                     confidential-compute workloads will route to TEE-capable peers"
                );
                // Deliberately do NOT register a "tee" subsystem in the
                // health monitor. `subsystem_is_ok` treats absence as OK,
                // so /health stays Healthy on commodity hardware and the
                // capability is reported via the dedicated TEE API.
            }
        }

        Ok(())
    }

    /// Returns true if this node has a TEE provider available and can
    /// serve confidential-compute / custodial-key workloads.
    ///
    /// All nodes participate in consensus; TEE-capable nodes additionally
    /// advertise this capability so peers can route TEE-gated workloads
    /// (confidential AI inference, custodial key management, attestation
    /// issuance) to them.
    pub fn has_tee_capability(&self) -> bool {
        self.tee_provider.is_some()
    }

    /// Returns the TEE vendor for this node, if any.
    pub fn tee_vendor(&self) -> Option<tenzro_types::tee::TeeVendor> {
        self.tee_provider.as_ref().map(|p| p.vendor())
    }

    async fn init_vm(&mut self) -> Result<()> {
        info!("Initializing VM runtime...");

        let mut vm_config = VmConfig::default();

        // If Canton is not enabled, remove Daml from enabled VMs
        if !self.config.canton.enabled {
            vm_config.enabled_vms.retain(|v| *v != tenzro_vm::VmType::Daml);
            info!("Canton/DAML disabled — DAML VM will not be active");
        }

        // The DAML VM holds a single participant connection, so it targets
        // the default network. Per-request network selection applies to the
        // `tenzro_canton_*` RPC surface, which goes through the adapter map.
        let daml_target = self.config.canton.network(self.config.canton.default_network);
        let vm_runtime = Arc::new(MultiVmRuntime::with_canton_config(
            vm_config,
            daml_target.map(|c| c.host.as_str()).unwrap_or("localhost"),
            daml_target.map(|c| c.port).unwrap_or(7575),
        ).await?);

        // Wire the EIP-1559 fee market into the VM gas oracle. The oracle owns
        // the live FeeMarket; `eth_gasPrice` / `eth_maxPriorityFeePerGas` /
        // `eth_feeHistory` read it at request time, and the event loop
        // advances it after every block via `on_block_finalized(gas_used)`.
        // Without this wiring the oracle falls back to a static 1 Gwei and
        // the EIP-1559 module is dead code.
        vm_runtime.gas_oracle().set_fee_market(FeeMarket::default()).await;

        self.vm_runtime = Some(vm_runtime);
        self.health_monitor.mark_healthy("vm");

        if self.config.canton.enabled {
            for net in self.config.canton.configured_networks() {
                if let Some(c) = self.config.canton.network(net) {
                    info!(
                        network = %net,
                        "Canton configured at {}:{} (connection deferred until first \
                         DAML operation)",
                        c.host,
                        c.port,
                    );
                }
            }
        }

        Ok(())
    }

    async fn init_token_economics(&mut self) -> Result<()> {
        info!("Initializing token economics...");

        // Initialize TNZO token with persistent storage backend
        let token = if let Some(storage) = &self.storage {
            use tenzro_token::tnzo::RocksDbBackend;
            let backend = Arc::new(RocksDbBackend::new(storage.clone() as Arc<dyn KvStore>));
            Arc::new(TnzoToken::with_storage(backend)
                .map_err(|e| NodeError::Other(format!("Failed to init TNZO token: {}", e)))?)
        } else {
            Arc::new(TnzoToken::new())
        };
        // Commission settlement resolves the payee through the token's treasury
        // address; without this every commissioned settlement fails closed.
        // The address is derived, so it is identical on every replica.
        token.set_treasury_address(tenzro_types::network_treasury_address());
        self.token = Some(token);

        // Fee accounting for the gas the executor debits per transaction.
        let fee_processor = if let Some(storage) = &self.storage {
            Arc::new(
                tenzro_token::FeeProcessor::with_storage(storage.clone() as Arc<dyn KvStore>)
                    .map_err(|e| {
                        NodeError::Other(format!("Failed to init fee processor: {}", e))
                    })?,
            )
        } else {
            Arc::new(tenzro_token::FeeProcessor::new())
        };
        self.fee_processor = Some(fee_processor);

        // Initialize staking with persistent storage if available
        let staking = if let Some(storage) = &self.storage {
            Arc::new(StakingManager::with_storage(storage.clone() as Arc<dyn KvStore>))
        } else {
            Arc::new(StakingManager::new())
        };
        self.staking = Some(staking);

        // Initialize liquid staking pool (stTNZO). Creates the pool
        // with default config (10% protocol fee, 7-day unbonding, 0.1 TNZO
        // min deposit). Persists holder balances + withdrawal requests +
        // aggregate totals to CF_TOKENS so the pool survives restarts.
        let liquid_pool = if let Some(storage) = &self.storage {
            match tenzro_token::LiquidStakingPool::with_storage(
                tenzro_token::LiquidStakingConfig::default(),
                storage.clone() as Arc<dyn KvStore>,
            ) {
                Ok(p) => Arc::new(p),
                Err(e) => {
                    warn!(
                        "LiquidStakingPool hydration failed ({}), falling back to in-memory",
                        e
                    );
                    Arc::new(
                        tenzro_token::LiquidStakingPool::new(
                            tenzro_token::LiquidStakingConfig::default(),
                        )
                        .expect("default liquid staking config is valid"),
                    )
                }
            }
        } else {
            Arc::new(
                tenzro_token::LiquidStakingPool::new(
                    tenzro_token::LiquidStakingConfig::default(),
                )
                .expect("default liquid staking config is valid"),
            )
        };
        self.liquid_staking_pool = Some(liquid_pool);

        // Initialize AgentBond manager (Spec 9). Uses CF_AGENTS for bond /
        // claim / pool persistence; no manager-level wallet, just a write-
        // through cache. The VM is the source of truth for bond *funds*
        // (via vault addresses); BondManager owns lifecycle envelope state
        // (Active / Cooldown / Frozen / Slashed / Returned) and the
        // governance-tunable thresholds consulted by the lane resolver.
        let bond_manager = if let Some(storage) = &self.storage {
            match tenzro_token::bond::BondManager::with_storage(
                storage.clone() as Arc<dyn KvStore>,
            ) {
                Ok(m) => Arc::new(m),
                Err(e) => {
                    warn!(
                        "BondManager hydration failed ({}), falling back to in-memory",
                        e
                    );
                    Arc::new(tenzro_token::bond::BondManager::new())
                }
            }
        } else {
            Arc::new(tenzro_token::bond::BondManager::new())
        };
        self.bond_manager = Some(bond_manager);

        // Initialize ComputeBond manager (Phase A #153). Persists to
        // CF_PROVIDERS. Consulted by `handle_register_provider` to gate
        // admission on a minimum compute bond, and by the per-provider
        // ComputeBond RPCs (post / get / list / increase / withdraw).
        let compute_bond_manager = if let Some(storage) = &self.storage {
            match tenzro_token::compute_bond::ComputeBondManager::with_storage(
                storage.clone() as Arc<dyn KvStore>,
            ) {
                Ok(m) => Arc::new(m),
                Err(e) => {
                    warn!(
                        "ComputeBondManager hydration failed ({}), falling back to in-memory",
                        e
                    );
                    Arc::new(tenzro_token::compute_bond::ComputeBondManager::new())
                }
            }
        } else {
            Arc::new(tenzro_token::compute_bond::ComputeBondManager::new())
        };
        self.compute_bond_manager = Some(compute_bond_manager);

        // Initialize the verifiable-inference commitment store +
        // challenge lifecycle (TOPLOC scheme). Persists to
        // CF_CHALLENGES; hydrates filed challenges on boot. Requires
        // durable storage — commitments must survive restarts for
        // challenges to be resolvable, so no in-memory fallback.
        if let Some(storage) = &self.storage {
            match crate::inference_challenge::ChallengeManager::new(
                storage.clone() as Arc<dyn KvStore>,
            ) {
                Ok(m) => self.challenge_manager = Some(m),
                Err(e) => warn!(
                    "ChallengeManager hydration failed ({}), verifiable-inference challenges disabled",
                    e
                ),
            }
        }

        // Initialize permissionless ValidatorRegistry. Persists to
        // CF_TOKENS so candidate / active / pending-exit / jailed state
        // survives restarts. The post-block scan in EventLoop drives the
        // registry from VM-emitted logs; the epoch boundary hook calls
        // compute_epoch_transition() and feeds the resulting plan into
        // the consensus EpochManager.
        let validator_registry = if let Some(storage) = &self.storage {
            Arc::new(tenzro_token::validator_registry::ValidatorRegistry::with_storage(
                storage.clone() as Arc<dyn KvStore>,
            ))
        } else {
            Arc::new(tenzro_token::validator_registry::ValidatorRegistry::new())
        };
        self.validator_registry = Some(validator_registry);

        // Initialize BurnQuota singleton (Agent-Swarm Spec 3).
        // The full dual-rail-gas paymaster comes later once the
        // bridge mesh (Wormhole NTT USDC pool) and Chainlink/Pyth oracles
        // are in place; for now we add the on-chain accounting
        // primitive only, persisted under CF_TOKENS so genesis and any
        // operator-initiated refill survive restarts.
        let burn_quota_manager = if let Some(storage) = &self.storage {
            match tenzro_token::burn_quota::BurnQuotaManager::with_storage(
                storage.clone() as Arc<dyn KvStore>,
            ) {
                Ok(m) => Arc::new(m),
                Err(e) => {
                    warn!(
                        "BurnQuotaManager hydration failed ({}), falling back to in-memory",
                        e
                    );
                    Arc::new(tenzro_token::burn_quota::BurnQuotaManager::new())
                }
            }
        } else {
            Arc::new(tenzro_token::burn_quota::BurnQuotaManager::new())
        };
        self.burn_quota_manager = Some(burn_quota_manager);

        // Initialize adaptive burn governance dial (Agent-Swarm Spec 8).
        // Registers the protocol primitives + read RPCs; the
        // auto-proposal generator and the EIP-1559 fee-market consumer
        // are wired alongside the governance executor later.
        let burn_rate_manager = if let Some(storage) = &self.storage {
            match tenzro_token::adaptive_burn::BurnRateConfigManager::with_storage(
                storage.clone() as Arc<dyn KvStore>,
            ) {
                Ok(m) => Arc::new(m),
                Err(e) => {
                    warn!(
                        "BurnRateConfigManager hydration failed ({}), falling back to in-memory",
                        e
                    );
                    Arc::new(tenzro_token::adaptive_burn::BurnRateConfigManager::new())
                }
            }
        } else {
            Arc::new(tenzro_token::adaptive_burn::BurnRateConfigManager::new())
        };
        self.burn_rate_manager = Some(burn_rate_manager.clone());

        // Wire the adaptive-burn dial into the VM gas oracle so the EIP-1559
        // fee market splits per-block gross revenue between burn and treasury
        // according to `BurnRateConfig.base_fee_burn_bps` and hot-state
        // surcharges according to `local_fee_burn_bps`. Without this wiring
        // the oracle defaults to 100% burn (genesis behavior).
        if let Some(vm_runtime) = self.vm_runtime.as_ref() {
            vm_runtime
                .gas_oracle()
                .set_burn_rate_manager(burn_rate_manager)
                .await;
        }

        // Initialize SeedAgent treasury earmark manager (Agent-Swarm Spec 10).
        // Registers the protocol primitives, persistence, and read-only
        // RPCs. The off-chain provisioning daemon, monthly decay enforcement,
        // sunset wind-down sweep, and governance-executor mutation paths come
        // later.
        let seed_agent_manager = if let Some(storage) = &self.storage {
            match tenzro_token::seed_agent::SeedAgentEarmarkManager::with_storage(
                storage.clone() as Arc<dyn KvStore>,
            ) {
                Ok(m) => Arc::new(m),
                Err(e) => {
                    warn!(
                        "SeedAgentEarmarkManager hydration failed ({}), falling back to in-memory",
                        e
                    );
                    Arc::new(tenzro_token::seed_agent::SeedAgentEarmarkManager::new())
                }
            }
        } else {
            Arc::new(tenzro_token::seed_agent::SeedAgentEarmarkManager::new())
        };
        self.seed_agent_manager = Some(seed_agent_manager);

        // Initialize the work-gated reward engine. Verified work is
        // metered per epoch (consensus participation from finalized
        // blocks, settled inference/TEE/RPC traffic from the usage
        // tracker) and converted to reward coupons when the epoch
        // closes at the consensus epoch boundary. Persists issued
        // coupons + per-epoch summaries + cumulative meters to
        // CF_TOKENS.
        let reward_engine = if let Some(storage) = &self.storage {
            match tenzro_token::RewardEngine::with_storage(
                storage.clone() as Arc<dyn KvStore>,
            ) {
                Ok(e) => Arc::new(e),
                Err(e) => {
                    warn!(
                        "RewardEngine hydration failed ({}), falling back to in-memory",
                        e
                    );
                    Arc::new(tenzro_token::RewardEngine::new())
                }
            }
        } else {
            Arc::new(tenzro_token::RewardEngine::new())
        };
        self.reward_engine = Some(reward_engine);

        // Initialize the vesting manager. Holds reward vesting created by
        // the claim path (75% of every non-sponsored claim), plus
        // admin-created grant and contributor schedules. Persists to
        // CF_TOKENS.
        let vesting_manager = if let Some(storage) = &self.storage {
            match tenzro_token::VestingManager::with_storage(
                storage.clone() as Arc<dyn KvStore>,
            ) {
                Ok(m) => Arc::new(m),
                Err(e) => {
                    warn!(
                        "VestingManager hydration failed ({}), falling back to in-memory",
                        e
                    );
                    Arc::new(tenzro_token::VestingManager::new())
                }
            }
        } else {
            Arc::new(tenzro_token::VestingManager::new())
        };
        self.vesting_manager = Some(vesting_manager);

        // Initialize the foundation sponsorship manager. Slots are
        // created through the admin-gated delegate RPC after off-chain
        // application review; graduation, revocation, bond slashing, and
        // the expiry sweep run against this manager. Persists the pool
        // singleton + per-DID slots to CF_TOKENS.
        let sponsorship_manager = if let Some(storage) = &self.storage {
            match tenzro_token::SponsorshipManager::with_storage(
                storage.clone() as Arc<dyn KvStore>,
            ) {
                Ok(m) => Arc::new(m),
                Err(e) => {
                    warn!(
                        "SponsorshipManager hydration failed ({}), falling back to in-memory",
                        e
                    );
                    Arc::new(tenzro_token::SponsorshipManager::new())
                }
            }
        } else {
            Arc::new(tenzro_token::SponsorshipManager::new())
        };
        self.sponsorship_manager = Some(sponsorship_manager);

        // Initialize governance with persistent storage and staking integration
        let governance = if let Some(ref storage) = self.storage {
            if let Some(ref staking) = self.staking {
                Arc::new(GovernanceEngine::with_staking_and_storage(
                    staking.clone(),
                    storage.clone() as Arc<dyn KvStore>,
                ))
            } else {
                Arc::new(GovernanceEngine::with_storage(
                    storage.clone() as Arc<dyn KvStore>,
                ))
            }
        } else if let Some(ref staking) = self.staking {
            Arc::new(GovernanceEngine::with_staking_manager(staking.clone()))
        } else {
            Arc::new(GovernanceEngine::new())
        };
        self.governance = Some(governance);

        // Initialize treasury with persistent storage if available
        let treasury_addr = tenzro_types::network_treasury_address();
        let treasury = if let Some(storage) = &self.storage {
            use tenzro_token::treasury::TreasuryStorageBackend;
            let backend = Arc::new(TreasuryStorageBackend::new(storage.clone() as Arc<dyn KvStore>));
            Arc::new(NetworkTreasury::with_storage(treasury_addr, backend))
        } else {
            Arc::new(NetworkTreasury::new(treasury_addr))
        };
        self.treasury = Some(treasury);

        // Wire the governance executor now that all subsystems it depends on
        // are constructed. The executor mutates `BurnRateConfigManager` and
        // `NetworkTreasury` when proposals pass; without it `execute_proposal`
        // only flips status with no side effects.
        if let (Some(governance), Some(burn_rate), Some(treasury)) = (
            self.governance.as_ref(),
            self.burn_rate_manager.as_ref(),
            self.treasury.as_ref(),
        ) {
            let mut executor = TenzroProposalExecutor::new(
                burn_rate.clone(),
                treasury.clone(),
                treasury_addr,
            );
            // SeedAgent gossip channel — shared by the governance executor
            // (charter / earmark / status mutations) and the provisioning
            // daemon (monthly refill broadcasts + automatic pause-on-sunset).
            // The forwarder task drains the channel and publishes each
            // envelope on `tenzro/seed-agents`; receivers apply messages
            // idempotently against their own `SeedAgentEarmarkManager`.
            let seed_agent_gossip_tx = if self.seed_agent_manager.is_some()
                && self.network.is_some()
            {
                let network = self.network.clone().unwrap();
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<
                    tenzro_token::SeedAgentGossipMessage,
                >();
                tokio::spawn(async move {
                    while let Some(msg) = rx.recv().await {
                        let bytes = match &msg {
                            tenzro_token::SeedAgentGossipMessage::CharterUpserted(
                                c,
                            ) => tenzro_token::encode_charter_upserted(c),
                            tenzro_token::SeedAgentGossipMessage::EarmarkUpdated(
                                e,
                            ) => tenzro_token::encode_earmark_updated(e),
                            tenzro_token::SeedAgentGossipMessage::AgentRegistered(
                                r,
                            ) => tenzro_token::encode_agent_registered(r),
                            tenzro_token::SeedAgentGossipMessage::AgentStatusChanged {
                                agent_did,
                                status,
                            } => tenzro_token::encode_agent_status_changed(
                                agent_did, *status,
                            ),
                            tenzro_token::SeedAgentGossipMessage::MonthlyRefillCompleted {
                                agent_did,
                                granted_wei,
                                month,
                                earmark_snapshot,
                            } => tenzro_token::encode_monthly_refill_completed(
                                agent_did,
                                *granted_wei,
                                *month,
                                earmark_snapshot,
                            ),
                        };
                        let bytes = match bytes {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "Failed to bincode-encode SeedAgent gossip envelope"
                                );
                                continue;
                            }
                        };
                        let net_msg = tenzro_network::NetworkMessage::new(
                            tenzro_network::MessagePayload::Custom {
                                topic: tenzro_token::SEED_AGENTS_TOPIC.to_string(),
                                data: bytes,
                            },
                        );
                        if let Err(e) = network
                            .broadcast(tenzro_token::SEED_AGENTS_TOPIC, net_msg)
                            .await
                        {
                            tracing::warn!(
                                error = %e,
                                "Failed to broadcast SeedAgent gossip on tenzro/seed-agents"
                            );
                        }
                    }
                });
                info!(
                    topic = tenzro_token::SEED_AGENTS_TOPIC,
                    "SeedAgent gossip forwarder spawned"
                );
                Some(tx)
            } else {
                None
            };

            if let Some(seed_agents) = self.seed_agent_manager.as_ref() {
                executor = executor.with_seed_agents(seed_agents.clone());
                if let Some(tx) = seed_agent_gossip_tx.as_ref() {
                    executor = executor.with_seed_agent_broadcast(tx.clone());
                }
            }
            let executor = Arc::new(executor);
            governance.attach_executor(executor);
            info!("ProposalExecutor wired into GovernanceEngine");

            // Stash the gossip sender so `start()` can hand it to the
            // SeedAgent provisioning daemon after `init_consensus` runs
            // (the daemon's tick-authority gate needs the consensus engine,
            // which doesn't exist at this point in init).
            self.seed_agent_gossip_tx = seed_agent_gossip_tx;

            // Spawn the adaptive-burn AutoProposalGenerator. Polls
            // BurnRateConfigManager::current_recommendation() on the epoch
            // boundary (8h default) and drafts AdaptiveBurnConfigUpdate
            // proposals via GovernanceEngine::create_system_proposal when
            // metrics drift above the proposal floor or trip an alarm.
            // No-op when the dial is Disabled or the recommendation is
            // NoChange / below floor.
            let auto_gen = Arc::new(tenzro_token::adaptive_burn::AutoProposalGenerator::new(
                burn_rate.clone(),
                governance.clone(),
            ));
            auto_gen.spawn();
            info!("AutoProposalGenerator spawned for adaptive burn dial");
        } else {
            warn!(
                "ProposalExecutor not wired: governance / burn_rate / treasury \
                 missing; passed proposals will only flip status"
            );
        }

        // Initialize unified token registry (cross-VM token tracking)
        let token_registry = if let Some(storage) = &self.storage {
            Arc::new(TokenRegistry::with_storage(storage.clone() as Arc<dyn KvStore>)
                .map_err(|e| NodeError::Other(format!("Failed to init token registry: {}", e)))?)
        } else {
            Arc::new(TokenRegistry::new())
        };
        // Register native TNZO token at startup with the full cross-VM pointer
        // triple — wTNZO ERC-20 (EVM), wTNZO SPL mint (SVM), CIP-56 holding
        // template (Canton/DAML). All three share the same underlying TNZO
        // balance under the Sei V2 pointer model; the registry just records
        // the per-VM addresses so callers can resolve the token by any of them.
        let evm_addr = Some([0x10, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]);
        let svm_mint = Some(tenzro_vm::svm::spl_adapter::WTNZO_SPL_MINT);
        let daml_template = Some(tenzro_vm::daml::cip56::TNZO_HOLDING_TEMPLATE.to_string());
        match token_registry.get_by_symbol("TNZO") {
            None => {
                // Fresh deploy — register with the full triple.
                if let Err(e) = token_registry.register_tnzo(
                    evm_addr,
                    svm_mint,
                    daml_template,
                ) {
                    warn!("TNZO token registration: {}", e);
                }
            }
            Some(existing) => {
                // Upgrade path — a previously persisted TNZO entry may be missing
                // the SVM mint or DAML template (pre-2026-06-08 nodes registered
                // EVM-only). Backfill them in place so cross-VM lookups by SPL
                // mint / CIP-56 template resolve to the same TokenId.
                let needs_update = existing.vm_addresses.svm.is_none()
                    || existing.vm_addresses.daml_template_id.is_none();
                if needs_update {
                    let updated = tenzro_token::VmAddresses {
                        evm: existing.vm_addresses.evm.or(evm_addr),
                        svm: existing.vm_addresses.svm.or(svm_mint),
                        daml_template_id: existing
                            .vm_addresses
                            .daml_template_id
                            .clone()
                            .or(daml_template),
                        native: existing.vm_addresses.native,
                        tempo: existing.vm_addresses.tempo,
                    };
                    if let Err(e) =
                        token_registry.update_vm_addresses(&existing.token_id, updated)
                    {
                        warn!("TNZO triple-pointer backfill: {}", e);
                    } else {
                        info!("TNZO triple-pointer backfilled (SVM mint + CIP-56 template)");
                    }
                }
            }
        }

        // Register canonical Tempo L1 TIP-20 stablecoins so the catalog reflects
        // Tempo as a settlement venue of its own. Operator-supplied addresses
        // from `[payments] tempo_stablecoins` take precedence; symbols not
        // overridden fall back to deterministic placeholders so seeing-the-symbol
        // still gives downstream consumers a stable token_id pending canonical
        // Stripe/Paradigm issuance.
        for (symbol, name, decimals, addr_seed) in [
            ("USDC", "USD Coin (Tempo)", 6u8, 0xC1u8),
            ("PYUSD", "PayPal USD (Tempo)", 6u8, 0xC2u8),
            ("USDT", "Tether USD (Tempo)", 6u8, 0xC3u8),
        ] {
            // Skip if already registered on a previous boot — the catalog is
            // RocksDB-persisted, so this hot path runs on every restart.
            if token_registry.get_by_symbol(symbol).is_some() {
                continue;
            }

            // Operator override path: parse `0x...` hex (20 bytes). On malformed
            // input log + skip — don't fall through to the placeholder, since
            // the operator's intent was to pin a canonical address.
            let addr = if let Some(operator_hex) =
                self.config.payments.tempo_stablecoins.get(symbol)
            {
                let trimmed = operator_hex.trim_start_matches("0x");
                match hex::decode(trimmed) {
                    Ok(bytes) if bytes.len() == 20 => {
                        let mut a = [0u8; 20];
                        a.copy_from_slice(&bytes);
                        info!(
                            "Tempo TIP-20 {} using operator-supplied address 0x{}",
                            symbol, trimmed
                        );
                        a
                    }
                    Ok(bytes) => {
                        warn!(
                            "Tempo TIP-20 {} operator address has wrong length ({} bytes, want 20); skipping",
                            symbol,
                            bytes.len()
                        );
                        continue;
                    }
                    Err(e) => {
                        warn!(
                            "Tempo TIP-20 {} operator address is malformed hex ({}); skipping",
                            symbol, e
                        );
                        continue;
                    }
                }
            } else {
                // Deterministic placeholder: 19-byte zero-pad + per-symbol seed byte.
                let mut a = [0u8; 20];
                a[19] = addr_seed;
                a
            };

            if let Err(e) = token_registry.register_tip20(symbol, name, decimals, addr, None) {
                warn!("Tempo TIP-20 {} registration: {}", symbol, e);
            }
        }

        self.token_registry = Some(token_registry);

        self.health_monitor.mark_healthy("token");

        Ok(())
    }

    async fn init_wallet(&mut self) -> Result<()> {
        info!("Initializing wallet service...");

        // Anchor wallet keystore + contacts under the configured data
        // directory rather than the wallet crate's default relative
        // `./data/wallets`. The relative default breaks any caller whose
        // current working directory is read-only (e.g. a packaged macOS
        // .app launched by Finder) and silently splatters writes into
        // arbitrary cwd locations when it isn't.
        let wallet_dir = self.config.data_dir.join("wallets");
        let contacts_path = self.config.data_dir.join("contacts.json");

        // Resolve the keystore password from the injected unlocker, if any.
        // With a password, the wallet service writes/loads FROST key shares
        // from the encrypted on-disk keystore, so wallets PERSIST across
        // restarts. Without an unlocker (or if it's unavailable — e.g. an
        // un-provisioned desktop build that can't reopen its Secure Enclave
        // key after a restart), the wallet stays EPHEMERAL and is recreated
        // each launch. We never fail node init over wallet persistence — a
        // node without a usable unlocker should still boot.
        let mut wallet_config = tenzro_wallet::service::WalletServiceConfig {
            keystore_path: wallet_dir,
            contacts_path,
            ..Default::default()
        };
        if let Some(unlocker) = &self.keystore_unlocker {
            match unlocker.unlock_password() {
                Ok(pw) => {
                    info!("Wallet keystore unlocked — wallets will persist across restarts");
                    wallet_config = wallet_config.with_default_password((*pw).clone());
                }
                Err(tenzro_keystore_unlock::UnlockError::Unavailable(reason)) => {
                    warn!(
                        "Wallet keystore unlock source unavailable ({reason}); wallet will be \
                         ephemeral (recreated each launch)"
                    );
                }
                Err(e) => {
                    warn!("Wallet keystore unlock failed ({e}); wallet will be ephemeral");
                }
            }
        }

        let wallet_service = Arc::new(TenzroWalletService::with_config(wallet_config)?);
        self.wallet_service = Some(wallet_service);
        self.health_monitor.mark_healthy("wallet");

        Ok(())
    }

    async fn init_consensus(&mut self, verify_only: bool) -> Result<()> {
        if verify_only {
            info!("Initializing consensus engine for block verification only...");
        } else {
            info!("Initializing consensus engine...");
        }

        // Load validator key material from disk. The node binary on
        // `start` strictly LOADS — never generates — to keep a
        // misconfigured / empty / re-mounted volume fail-loud rather
        // than fail-silent. `KeyMissing` errors here are actionable:
        // the operator runs `tenzro-node init` to provision the
        // three keys, then re-starts. See `keygen.rs`.
        //
        // A verify-only node holds no bonded stake against these keys and
        // casts no vote, so there is no identity to lose and no double-sign
        // to induce — the reason for the strict load does not apply. Provision
        // on first run instead, so joining the network as a provider is a
        // single command.
        if verify_only
            && matches!(
                crate::keygen::load_validator_keypair(&self.config.data_dir),
                Err(NodeError::KeyMissing { .. })
            )
        {
            crate::keygen::generate_and_persist_keyset(&self.config.data_dir, false)?;
            info!(
                data_dir = ?self.config.data_dir,
                "Provisioned node keyset — this node verifies blocks but does not vote"
            );
        }
        let keypair = crate::keygen::load_validator_keypair(&self.config.data_dir)?;
        let pq_signing_key = crate::keygen::load_validator_pq_key(&self.config.data_dir)?;
        let local_pq_vk = pq_signing_key.verifying_key_bytes().to_vec();
        let bls_signing_key = crate::keygen::load_validator_bls_key(&self.config.data_dir)?;
        let local_bls_vk = bls_signing_key.public_key().to_bytes().to_vec();
        // Capture the BLS secret bytes before `bls_signing_key` is moved into
        // the consensus engine below, so the G6 batch-availability store can
        // rebuild an independent handle to the same key (BLS keypairs are not
        // `Clone` by design — same reason the hybrid signer rebuilds from bytes).
        let bls_secret_bytes = bls_signing_key.secret_key().to_bytes();

        // Build a sibling `InMemoryHybridSigner` from the same key material
        // so webhook-sourced TDIP revocation paths (e.g. Stripe SPT
        // `granted_token.deactivated`) can sign a `SignedRevocationEntry`
        // and fan it out via the `RevocationBroadcaster`. The consensus
        // engine consumes the originals below, so we rebuild a duplicate
        // pair from the same bytes — `KeyPair`/`MlDsaSigningKey` are not
        // `Clone` by design (secret material).
        let signer_keypair = KeyPair::from_bytes(KeyType::Ed25519, &keypair.to_bytes())
            .map_err(|e| NodeError::Other(format!(
                "Failed to rebuild validator keypair for hybrid signer: {}", e
            )))?;
        let signer_pq = tenzro_crypto::pq::MlDsaSigningKey::from_seed(pq_signing_key.seed_bytes())
            .map_err(|e| NodeError::Other(format!(
                "Failed to rebuild validator PQ key for hybrid signer: {}", e
            )))?;
        let classical_signer: Box<dyn tenzro_crypto::signatures::Signer + Send + Sync> =
            Box::new(tenzro_crypto::signatures::Ed25519SignerImpl::new(signer_keypair)
                .map_err(|e| NodeError::Other(format!(
                    "Failed to construct Ed25519 signer for hybrid signer: {}", e
                )))?);
        let hybrid_signer: Arc<dyn tenzro_crypto::composite::HybridSigner> = Arc::new(
            tenzro_crypto::composite::InMemoryHybridSigner::new(classical_signer, signer_pq),
        );
        self.validator_hybrid_signer = Some(hybrid_signer);
        info!("Validator hybrid signer (Ed25519 + ML-DSA-65) constructed for TDIP revocation paths");

        // Convert address
        let crypto_addr = keypair.address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = Address::new(addr_bytes);

        // Create validator set.
        //
        // If the operator supplied a `[[validators]]` block in genesis.toml,
        // use those public keys as the canonical BFT validator set. This is
        // what allows multiple nodes in a deployment to actually vote together
        // (n=4, f=1, threshold=2f+1=3) instead of each running solo with
        // threshold=1.
        //
        // If no genesis validators are configured, fall back to a single-node
        // validator set containing only this node — useful for local dev
        // (`tenzro-node --roles validator` without a genesis file).
        //
        // The local node's keypair is ALWAYS the signing identity it uses for
        // votes. If the local public key isn't present in the genesis set,
        // this node will produce blocks but its votes will be rejected by
        // peers — this is the correct, fail-loud behavior for an unknown
        // validator.
        let local_pk_hex = hex::encode(keypair.public_key().as_bytes());
        let validators = match self.config.genesis.as_ref() {
            Some(g) if !g.validators.is_empty() => {
                use tenzro_crypto::keys::PublicKey;
                let mut out: Vec<ValidatorInfo> = Vec::with_capacity(g.validators.len());
                for gv in &g.validators {
                    let pk_hex = gv.public_key.strip_prefix("0x").unwrap_or(&gv.public_key);
                    let pk_bytes = hex::decode(pk_hex).map_err(|e| {
                        NodeError::Config(format!(
                            "Invalid genesis validator public key '{}': {}",
                            gv.public_key, e
                        ))
                    })?;
                    if pk_bytes.len() != 32 {
                        return Err(NodeError::Config(format!(
                            "Genesis validator public key '{}' has wrong length: expected 32 bytes for Ed25519, got {}",
                            gv.public_key,
                            pk_bytes.len()
                        )));
                    }
                    let pk = PublicKey::new(KeyType::Ed25519, pk_bytes);

                    // Decode mandatory ML-DSA-65 verifying key for the
                    // hybrid signing scheme. This validator entry is
                    // rejected if the PQ key is missing or wrong-length.
                    let pq_hex = gv
                        .pq_public_key
                        .strip_prefix("0x")
                        .unwrap_or(&gv.pq_public_key);
                    let pq_bytes = hex::decode(pq_hex).map_err(|e| {
                        NodeError::Config(format!(
                            "Invalid genesis validator pq_public_key for '{}': {}",
                            gv.public_key, e
                        ))
                    })?;
                    if pq_bytes.len() != 1952 {
                        return Err(NodeError::Config(format!(
                            "Genesis validator pq_public_key for '{}' has wrong length: \
                             expected 1952 bytes for ML-DSA-65, got {}",
                            gv.public_key,
                            pq_bytes.len()
                        )));
                    }

                    // Decode mandatory BLS12-381 G1-compressed verifying key
                    // (`min_pk` scheme) for HotStuff-2 vote aggregation. This
                    // validator entry is rejected if the BLS key is missing
                    // or wrong-length.
                    let bls_hex = gv
                        .bls_public_key
                        .strip_prefix("0x")
                        .unwrap_or(&gv.bls_public_key);
                    let bls_bytes = hex::decode(bls_hex).map_err(|e| {
                        NodeError::Config(format!(
                            "Invalid genesis validator bls_public_key for '{}': {}",
                            gv.public_key, e
                        ))
                    })?;
                    if bls_bytes.len() != 48 {
                        return Err(NodeError::Config(format!(
                            "Genesis validator bls_public_key for '{}' has wrong length: \
                             expected 48 bytes for BLS12-381 G1 (min_pk compressed), got {}",
                            gv.public_key,
                            bls_bytes.len()
                        )));
                    }

                    // Derive the 32-byte address by taking the 20-byte crypto
                    // address (Keccak-256 of pubkey, last 20 bytes) and
                    // left-padding into a 32-byte slot — same convention as
                    // `address` above.
                    let crypto_addr = pk.to_address();
                    let mut addr_bytes = [0u8; 32];
                    addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
                    let v_address = Address::new(addr_bytes);
                    out.push(ValidatorInfo::new(v_address, pk, pq_bytes, bls_bytes, gv.stake as u128));
                }
                if !out
                    .iter()
                    .any(|v| hex::encode(v.public_key.as_bytes()) == local_pk_hex)
                {
                    warn!(
                        local_validator_pubkey = %local_pk_hex,
                        "Local validator keypair not found in genesis validator set — \
                         this node will produce proposals but its votes will be rejected by peers"
                    );
                }
                info!(
                    validator_count = out.len(),
                    "Loaded validator set from genesis.toml"
                );
                out
            }
            _ => {
                info!("No genesis validators configured, running as single-node validator");
                vec![ValidatorInfo::new(
                    address,
                    keypair.public_key().clone(),
                    local_pq_vk.clone(),
                    local_bls_vk.clone(),
                    1000,
                )]
            }
        };

        // Seed permissionless ValidatorRegistry with the genesis validator
        // set as `Active` entries. This is restart-safe and idempotent:
        // `seed_genesis_active` skips any address that already has a registry
        // entry (e.g. on warm restarts where the entries hydrated from
        // CF_TOKENS, or where a validator has since exited and re-registered).
        // Without this, genesis validators would have no registry entry and
        // therefore couldn't be `jail()`ed on equivocation, nor surfaced via
        // `tenzro_listValidators`.
        if let Some(ref registry) = self.validator_registry {
            for v in &validators {
                match registry.seed_genesis_active(
                    v.address,
                    v.public_key.as_bytes().to_vec(),
                    v.pq_public_key.clone(),
                    v.bls_public_key.clone(),
                    v.address, // withdrawal == operator address by default at genesis
                    v.stake,
                    String::new(),
                ) {
                    Ok(true) => {
                        info!(
                            validator = %v.address,
                            stake = v.stake,
                            "Seeded genesis validator into permissionless registry"
                        );
                    }
                    Ok(false) => {
                        // Already present (warm restart or prior re-registration).
                    }
                    Err(e) => {
                        warn!(
                            validator = %v.address,
                            error = %e,
                            "Failed to seed genesis validator into registry — \
                             slashing/jail integration will not apply to this validator"
                        );
                    }
                }
            }
        }

        // Create epoch manager — backed by RocksDB when storage is available,
        // so validator-set history for past epochs survives restart and
        // block-sync can verify historical commit-QCs against the correct
        // set. Without persistence, a node falling behind across an epoch
        // boundary would reject every historical block as `InvalidValidatorSet`
        // and never re-converge — the May 2026 testnet stall root cause.
        let epoch_manager = if let Some(ref storage) = self.storage {
            let epoch_store = std::sync::Arc::new(
                crate::epoch_state_store::RocksDbEpochStateStore::new(storage.clone()),
            );
            EpochManager::with_store(validators, 10000, epoch_store)?
        } else {
            // Ephemeral nodes (no storage) get an in-memory-only manager.
            // Used by tests and by short-lived light-client roles that don't
            // produce blocks and therefore don't traverse epoch transitions.
            EpochManager::new(validators, 10000)?
        };

        // Create consensus engine with slashing callback wired to StakingManager
        let consensus_config = self.config.consensus.clone().unwrap_or_default();
        let mut engine = HotStuff2Engine::new(
            keypair,
            pq_signing_key,
            bls_signing_key,
            consensus_config,
            epoch_manager,
        );

        // Stash the local validator address so the inbound consensus
        // gossipsub bridge (wired in `start()`) can drop self-broadcasts
        // before they re-enter the engine.
        if !verify_only {
            self.local_validator_address = Some(address);
        }

        // Wire slashing callback so equivocation triggers real stake slashing.
        // Also pass the engine's epoch-manager handle so slashed validators are
        // dropped from the next epoch's pending-validator queue.
        if !verify_only
            && let Some(ref staking) = self.staking {
            let mut cb = StakingSlashingCallback::new(staking.clone())
                .with_epoch_manager(engine.epoch_manager());
            if let Some(ref vr) = self.validator_registry {
                cb = cb.with_validator_registry(vr.clone());
            }
            let callback = Arc::new(cb);
            engine = engine.with_slashing_callback(callback);
            info!("Slashing callback wired to consensus engine (with epoch-manager handle)");
        }

        // Wire state root provider so block proposals include real state roots.
        // Create a StateAdapter backed by storage and wrap it in a NodeStateRootProvider.
        // Uses parking_lot::Mutex (not tokio::sync::Mutex) because StateRootProvider::current_state_root()
        // is a sync method called from within the tokio runtime's consensus loop.
        // tokio::sync::Mutex::blocking_lock() panics in that context.
        if let Some(ref storage) = self.storage {
            use tenzro_vm::StateAdapter;

            let state_adapter = Arc::new(parking_lot::Mutex::new(
                StateAdapter::with_storage(storage.clone() as Arc<dyn tenzro_storage::KvStore>),
            ));
            let state_root_provider = Arc::new(NodeStateRootProvider::new(state_adapter));
            engine = engine.with_state_root_provider(state_root_provider);
            info!("State root provider wired to consensus engine");

            // Wire block provider so the consensus engine can fetch parent
            // blocks during proposal validation (EIP-1559 base-fee derivation
            // + child→parent header check). The engine consults
            // `FinalityTracker::get_finalized_block` first; this provider is
            // the durable RocksDB fallback for post-restart resume scenarios
            // where the in-memory cache has not yet been re-populated.
            let block_provider = Arc::new(NodeBlockProvider::new(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            ));
            engine = engine.with_block_provider(block_provider);
            info!("Block provider wired to consensus engine");

            // Wire the audit store so equivocation votes + evidence and
            // proposal records + proposal-equivocation evidence survive
            // restarts. Without this, an operator-induced restart erases
            // slashing evidence and lets a convicted offence re-fire.
            engine = engine
                .with_audit_storage(storage.clone() as Arc<dyn tenzro_storage::KvStore>);
            info!("Equivocation audit store wired to consensus engine (CF_AUDIT)");

            // Wire the G6 batch-availability store: the producer path snapshots
            // pending transactions into a batch, disseminates it over
            // `tenzro/batches`, and collects a 2f+1 BLS-aggregated availability
            // certificate so the ordering path can reference certified batches
            // by hash. Durable (`CF_AUDIT`), so certified-but-unexecuted batches
            // survive a restart. Rebuilds an independent BLS handle from the
            // secret bytes captured before the engine consumed the original.
            match tenzro_crypto::bls::BlsSecretKey::from_bytes(&bls_secret_bytes) {
                Ok(sk) => {
                    let batch_bls = Arc::new(
                        tenzro_crypto::bls::BlsKeyPair::from_secret_key(sk),
                    );
                    let batch_store = Arc::new(
                        tenzro_consensus::BatchCertStore::with_storage(
                            batch_bls,
                            address,
                            storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                        ),
                    );
                    engine = engine.with_batch_cert_store(batch_store);
                    info!("Batch-availability store wired to consensus engine (CF_AUDIT)");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to rebuild BLS key for batch store; batch-availability plane disabled");
                }
            }

            // Wire the ZK quorum store: a proof commitment is admitted to the
            // on-chain `ZkCommitmentRegistry` only once a 2f+1 stake-weight
            // BLS quorum of validators has each independently re-run
            // `verify_proof_envelope` and co-signed the 32-byte commitment
            // hash. The store buffers co-signatures until quorum, then opens
            // a fraud-proof window during which any staked party can trigger
            // deterministic re-verification. Durable (`CF_AUDIT`), so open
            // windows survive a restart. Rebuilds an independent BLS handle
            // from the secret bytes captured before the engine consumed the
            // original.
            //
            // Co-signing is stake-weighted, so it is reachable only from a
            // validator: a verify-only node's BLS key carries no weight and its
            // co-signature would be discarded by every peer that received it.
            if !verify_only {
                match tenzro_crypto::bls::BlsSecretKey::from_bytes(&bls_secret_bytes) {
                    Ok(sk) => {
                        let zk_bls = Arc::new(
                            tenzro_crypto::bls::BlsKeyPair::from_secret_key(sk),
                        );
                        let zk_store = Arc::new(
                            tenzro_consensus::ZkQuorumStore::with_storage(
                                zk_bls,
                                address,
                                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                            ),
                        );
                        self.zk_quorum_store = Some(zk_store);
                        info!("ZK quorum store wired (CF_AUDIT; 2f+1 co-sign gate on commitment attestation)");
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to rebuild BLS key for ZK quorum store; commitment quorum gate disabled");
                    }
                }
            }
        }

        // Wire the persistent vote-state store so equivocation can never be
        // self-induced by a crash between sign and broadcast. The store
        // refuses any (view, height, step) ≤ last-persisted, with fsync on
        // record. A persisted last-sign-state record preventing double-sign
        // across restarts.
        //
        // ORDER MATTERS: this MUST run before `resume_from_height` below.
        // `resume_from_height` consults the vote-state store to jump
        // `current_view` past the persisted last-vote view at the same
        // height — without this jump the engine starts at view=0, hits the
        // CheckHRS rule, and refuses every vote (height=0 wedge observed
        // 2026-04-28T09:12Z testnet).
        //
        // A verify-only node casts no vote, so there is no sign-state to
        // protect and no wedge to clear.
        if !verify_only {
            match open_default_file_store(&self.config.data_dir) {
                Ok(store) => {
                    engine = engine.with_vote_state_store(store);
                    info!(
                        data_dir = ?self.config.data_dir,
                        "Persistent vote-state store wired (last_sign.json)"
                    );
                }
                Err(e) => {
                    // Refuse to start consensus without durable vote state — the
                    // alternative (in-memory store) would silently re-introduce
                    // the self-equivocation risk we're trying to eliminate.
                    return Err(NodeError::Other(format!(
                        "Failed to open persistent vote-state store: {}", e
                    )));
                }
            }
        }

        // Resume consensus from the last persisted block height so the engine
        // doesn't re-propose blocks that are already committed to storage.
        // Without this, FinalityTracker starts at 0 on every restart, causing
        // eth_blockNumber to return stale values and duplicate block proposals.
        // Also: consults the vote_state_store wired above to advance
        // `current_view` past any vote already cast in a prior run at the
        // next-to-be-proposed height (CheckHRS jump).
        if let Some(ref storage) = self.storage {
            use tenzro_storage::block_store::BlockStoreImpl;
            use tenzro_storage::BlockStore;
            match BlockStoreImpl::new(storage.clone()) {
                Ok(block_store) => {
                    match block_store.latest_height().await {
                        Ok(Some(height)) => {
                            engine.resume_from_height(height);
                            info!(height = %height, "Consensus engine resuming from stored height");
                        }
                        Ok(None) => {
                            // No finalized blocks yet — but persisted vote state
                            // may still exist from a prior unproductive run.
                            // Pass height=0 so resume_from_height still consults
                            // vote_state_store and jumps the view if needed.
                            engine.resume_from_height(tenzro_types::BlockHeight(0));
                            info!("No stored blocks found, consensus starting from genesis (vote-state view-jump may still apply)");
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to read stored block height, starting from genesis");
                            engine.resume_from_height(tenzro_types::BlockHeight(0));
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to open block store for height check");
                }
            }
        }

        // A verify-only node holds the engine solely to answer "which validator
        // set was active at height H" while importing synced blocks. It never
        // proposes, votes, or emits a consensus message, so the outbound channel
        // and the consensus loop stay unbuilt.
        if verify_only {
            self.consensus = Some(Arc::new(engine));
            info!("Consensus engine built for block verification (not started; this node does not vote)");
            return Ok(());
        }

        // Create the outbound channel BEFORE starting the engine so the engine
        // can immediately start sending ConsensusOutMessage values.  The RX half
        // is stored on the node and consumed once by init_event_loop().
        let (consensus_out_tx, consensus_out_rx) =
            tokio::sync::mpsc::unbounded_channel::<ConsensusOutMessage>();
        engine = engine.with_consensus_out(consensus_out_tx);

        // START the consensus engine BEFORE wrapping in Arc.
        // start() takes &mut self — it initializes the vote collector,
        // creates the shutdown channel, and spawns the consensus loop task.
        engine.start().await
            .map_err(|e| NodeError::Other(format!("Failed to start consensus: {}", e)))?;

        info!("Consensus engine started successfully");

        self.consensus = Some(Arc::new(engine));
        self.consensus_out_rx = Some(consensus_out_rx);
        info!("Consensus outbound channel wired");
        self.health_monitor.mark_healthy("consensus");

        Ok(())
    }

    /// Wire the committee-resident Red Stuff DA backend (Task #82).
    ///
    /// Builds a durable per-validator custody store, an `EpochManagerCommitteeView`
    /// that shapes erasure coding against the live validator set, a
    /// `NetworkDaCommitteeSurface` over the `/tenzro/da/committee` protocol, the
    /// writer-side `DaCommitteeBackend`, and the inbound `DaCommitteeServer`
    /// serving loop. The store is shared between the backend (writer side) and
    /// the server (custody side) so a sliver received over the wire is visible
    /// to a later local fetch. Retains the backend handle and the server task.
    async fn init_committee_da(
        &mut self,
        network: Arc<TenzroNetworkService>,
        consensus: Arc<HotStuff2Engine>,
        storage: Arc<dyn KvStore>,
        da_peers: Arc<crate::da_committee_surface::AddressPeerRegistry>,
    ) -> Result<()> {
        use crate::da_committee::{
            committee_address, DaCommitteeBackend, DaCommitteeStore,
        };
        use crate::da_committee_surface::{
            register_local, DaCommitteeServer, EpochManagerCommitteeView,
            NetworkDaCommitteeSurface,
        };

        // The validator's Ed25519 key: signs this node's own attestations when
        // it holds a sliver. Same key consensus loads.
        let keypair = crate::keygen::load_validator_keypair(&self.config.data_dir)?;
        let local_address = committee_address(&keypair)
            .map_err(|e| NodeError::Other(format!("committee-DA local address: {e}")))?;

        // Record this node's own (address, PeerId) in the surface's registry so
        // the committee index → address → PeerId path resolves the local index
        // (a validator storing/fetching a sliver it holds itself). Remote
        // members are recorded by `record_da_peer` at validator admission.
        let local_peer = network
            .local_peer_id()
            .await
            .map_err(|e| NodeError::Other(format!("committee-DA local peer id: {e}")))?;
        register_local(&da_peers, keypair.public_key(), local_peer);

        // Durable custody store, hydrated from CF_DA_COMMITTEE.
        let store = Arc::new(
            DaCommitteeStore::with_storage(storage)
                .map_err(|e| NodeError::Other(format!("committee-DA store: {e}")))?,
        );

        // CommitteeView over the live epoch validator set.
        let committee: Arc<dyn crate::da_committee::CommitteeView> =
            Arc::new(EpochManagerCommitteeView::new(consensus.epoch_manager()));

        // Outbound surface over the request_response protocol.
        let net_dyn: Arc<dyn tenzro_network::NetworkService> = network.clone();
        let surface: Arc<dyn crate::da_committee::DaCommitteeSurface> =
            Arc::new(NetworkDaCommitteeSurface::new(
                net_dyn.clone(),
                committee.clone(),
                da_peers,
                local_address,
            ));

        // Writer-side backend. Rebuild the keypair for the server (KeyPair is
        // not Clone by design — secret material), so the backend and server
        // each own their signing identity from the same bytes.
        let server_keypair = KeyPair::from_bytes(KeyType::Ed25519, &keypair.to_bytes())
            .map_err(|e| NodeError::Other(format!("committee-DA server keypair: {e}")))?;
        let backend = Arc::new(
            DaCommitteeBackend::new(keypair, committee.clone(), surface, store.clone())
                .map_err(|e| NodeError::Other(format!("committee-DA backend: {e}")))?,
        );
        self.da_committee_backend = Some(backend.clone());

        // Background possession auditor (Task #92): every interval, challenge
        // one random attester of one random held certificate to prove current
        // custody of its own sliver. 10 minutes keeps challenge traffic to a
        // single sliver round-trip per tick while still surfacing a member
        // that dropped its slivers within a handful of ticks.
        self.da_possession_challenger = Some(crate::da_committee::spawn_possession_challenger(
            backend,
            std::time::Duration::from_secs(600),
        ));

        // Inbound serving loop.
        let server = DaCommitteeServer::new(net_dyn, committee, store, server_keypair)
            .map_err(|e| NodeError::Other(format!("committee-DA server: {e}")))?;
        let handle = server
            .spawn()
            .await
            .map_err(|e| NodeError::Other(format!("committee-DA server spawn: {e}")))?;
        self.da_committee_server_handle = Some(handle);

        Ok(())
    }

    async fn init_settlement(&mut self) -> Result<()> {
        info!("Initializing settlement engine...");

        let treasury_addr = tenzro_types::network_treasury_address();
        let config = SettlementConfig::new(treasury_addr);
        let treasury = self.treasury.clone().unwrap();

        // SettlementEngine — when storage is available, persist receipts and
        // per-address indices to `CF_SETTLEMENTS` (`receipt:`, `settlement_addr:`
        // prefixes). Hydrates the receipts cache + per-address history on startup.
        let settlement = if let Some(ref storage) = self.storage {
            let engine = SettlementEngine::with_storage(
                config,
                treasury.clone(),
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            )?;
            info!("SettlementEngine initialized with persistent storage (CF_SETTLEMENTS)");
            Arc::new(engine)
        } else {
            Arc::new(SettlementEngine::new(config, treasury.clone())?)
        };
        self.settlement = Some(settlement);

        // ChannelManager — when storage is available, wrap a `RocksDbChannelStorage`
        // adapter so channels and disputes survive restarts (CF_CHANNELS).
        let channel_manager = if let Some(ref storage) = self.storage {
            let backend: Arc<dyn tenzro_settlement::ChannelStorage> =
                Arc::new(RocksDbChannelStorage::new(
                    storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                ));
            let mgr = ChannelManager::with_storage(backend);
            info!("ChannelManager initialized with persistent storage (CF_CHANNELS)");
            Arc::new(mgr)
        } else {
            Arc::new(ChannelManager::new())
        };
        self.channel_manager = Some(channel_manager);

        // Initialize shared escrow manager. When durable storage is available we
        // wire it through `EscrowManager::with_storage`, which both write-through
        // persists every mutation to `CF_SETTLEMENTS` (under `escrow:`,
        // `escrow_payer:`, `escrow_payee:` prefixes) and rehydrates the in-memory
        // index from disk on startup. Note: this in-memory `EscrowManager` is now
        // a *query index* over escrow records — the Native VM is the source of
        // truth for escrow state and vault balances. The shared `balances`
        // DashMap is kept only to satisfy the legacy constructor contract; it is
        // not consulted for VM-mediated escrows.
        let balances = Arc::new(dashmap::DashMap::new());
        let escrow_manager = if let Some(ref storage) = self.storage {
            let mgr = EscrowManager::with_storage(
                balances,
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            );
            info!("EscrowManager initialized with persistent storage (CF_SETTLEMENTS)");
            Arc::new(mgr)
        } else {
            Arc::new(EscrowManager::new(balances))
        };
        self.escrow_manager = Some(escrow_manager);

        // Spec4FillRegistry — ERC-7683 destination-side idempotency guard.
        // Sits in CF_SETTLEMENTS alongside the escrow records under the
        // dedicated `7683_dest:<order_id>` keyspace; the open-side envelopes
        // are under `7683_origin:` and managed elsewhere. The registry is
        // a denormalized query cache + write-through persistence layer —
        // the fund movement (pulling outputs from the solver, crediting
        // the recipient) happens in the destination settler precompile
        // against VM state. The registry only enforces "filled at most
        // once per order_id".
        let spec4_fill_registry = if let Some(ref storage) = self.storage {
            let reg = Spec4FillRegistry::with_storage(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            );
            info!("Spec4FillRegistry initialized with persistent storage (CF_SETTLEMENTS / 7683_dest:)");
            Arc::new(reg)
        } else {
            Arc::new(Spec4FillRegistry::new())
        };
        self.spec4_fill_registry = Some(spec4_fill_registry);

        // KillSwitchStore — write-through to CF_SETTLEMENTS for kill-switch
        // receipts (Agent-Swarm Spec 1). Hydrates `by_agent`/`by_controller`
        // indices on startup from persisted records.
        let kill_switch_store = if let Some(ref storage) = self.storage {
            let store = tenzro_settlement::KillSwitchStore::with_storage(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            );
            info!("KillSwitchStore initialized with persistent storage (CF_SETTLEMENTS)");
            Arc::new(store)
        } else {
            Arc::new(tenzro_settlement::KillSwitchStore::new())
        };
        self.kill_switch_store = Some(kill_switch_store);

        // BatchProcessor — write-through to CF_SETTLEMENTS via the storage
        // builder. `BatchProcessor::with_storage` is a builder method on `new()`.
        let batch_processor = if let Some(ref storage) = self.storage {
            let bp = BatchProcessor::new(100)
                .with_storage(storage.clone() as Arc<dyn tenzro_storage::KvStore>);
            info!("BatchProcessor initialized with persistent storage (CF_SETTLEMENTS)");
            Arc::new(bp)
        } else {
            Arc::new(BatchProcessor::new(100))
        };
        self.batch_processor = Some(batch_processor);

        // FeeCollector — write-through to CF_SETTLEMENTS (`fee:`, `fee_total:`,
        // `fee_count:` prefixes); hydrates totals + counts + history on startup.
        let fee_collector = if let Some(ref storage) = self.storage {
            let fc = FeeCollector::with_storage(
                treasury.clone(),
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            );
            info!("FeeCollector initialized with persistent storage (CF_SETTLEMENTS)");
            Arc::new(fc)
        } else {
            Arc::new(FeeCollector::new(treasury.clone()))
        };
        self.fee_collector = Some(fee_collector);

        // WorkflowRuntime — typed mirror of the privileged-VM workflow
        // selectors `0x01000040`–`0x0100004B`. Bundles `WorkflowManager`
        // (workflows / obligations / approvals / lifecycle, persisted to
        // `CF_SETTLEMENTS` + `CF_APPROVALS`) and `PrivacyDomainRegistry`
        // (persisted to `CF_SETTLEMENTS` under `wf_pd:`). Both hydrate from
        // RocksDB on construction. Wired into the event loop in
        // `init_event_loop` so post-block scans can dispatch the 12
        // `Workflow*` log topics.
        let workflow_runtime = if let Some(ref storage) = self.storage {
            let rt = crate::workflow_runtime::WorkflowRuntime::with_storage(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            )
            .map_err(|e| NodeError::Internal(format!("workflow runtime init: {}", e)))?;
            info!("WorkflowRuntime initialized with persistent storage (CF_SETTLEMENTS + CF_APPROVALS)");
            Arc::new(rt)
        } else {
            Arc::new(crate::workflow_runtime::WorkflowRuntime::new())
        };
        self.workflow_runtime = Some(workflow_runtime);

        self.health_monitor.mark_healthy("settlement");

        Ok(())
    }

    /// Initializes the OAuth 2.1 + DPoP + RAR auth engine.
    ///
    /// The signing secret is loaded from `<data_dir>/auth_secret.bin`,
    /// generated on first boot from the OS RNG (32 bytes). This keeps
    /// the secret stable across restarts (so JWTs survive a node
    /// restart) without sharing it across nodes — JWT validation is
    /// per-node, not federated.
    ///
    /// `issuer` is the node's HTTP RPC URL; `audience` is the same URL
    /// — the RPC server is its own resource server.
    async fn init_auth(&mut self) -> Result<()> {
        info!("Initializing auth engine (OAuth 2.1 + DPoP + RAR)...");

        let storage = match self.storage.as_ref() {
            Some(s) => s.clone() as Arc<dyn tenzro_storage::KvStore>,
            None => {
                warn!("Storage not initialized; skipping auth engine init");
                return Ok(());
            }
        };

        // Load-or-generate a per-node signing secret. Storing it in the
        // data dir (chmod 600 isn't enforced here — operators are
        // expected to run the node under a dedicated user with a
        // mode-0700 data dir).
        let secret_path = self.config.data_dir.join("auth_secret.bin");
        let signing_secret: Vec<u8> = match std::fs::read(&secret_path) {
            Ok(bytes) if bytes.len() >= 32 => {
                info!("Loaded auth signing secret from {}", secret_path.display());
                bytes
            }
            _ => {
                use rand::RngCore;
                let mut buf = vec![0u8; 32];
                rand::thread_rng().fill_bytes(&mut buf);
                if let Some(parent) = secret_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                std::fs::write(&secret_path, &buf).map_err(|e| {
                    NodeError::Internal(format!(
                        "failed to persist auth signing secret to {}: {}",
                        secret_path.display(),
                        e
                    ))
                })?;
                info!(
                    "Generated new auth signing secret at {}",
                    secret_path.display()
                );
                buf
            }
        };

        let rpc_addr = if self.config.rpc_addr.is_empty() {
            "127.0.0.1:8545".to_string()
        } else {
            self.config.rpc_addr.clone()
        };
        let issuer = format!("http://{rpc_addr}");
        let audience = issuer.clone();

        let cfg = tenzro_auth::AuthEngineConfig::new(issuer, audience, signing_secret);
        let engine = tenzro_auth::AuthEngine::new(cfg, storage).map_err(|e| {
            NodeError::Internal(format!("auth engine init: {}", e))
        })?;
        self.auth_engine = Some(Arc::new(engine));
        info!("AuthEngine initialized (CF_AUDIT, CF_APPROVALS hydrated)");
        self.health_monitor.mark_healthy("auth");

        Ok(())
    }

    async fn init_ai_infrastructure(&mut self) -> Result<()> {
        info!("Initializing AI infrastructure...");

        // Initialize model registry with durable backing store when available.
        // ModelRegistry::with_storage() scans CF_MODELS for `info:` prefix keys
        // and rehydrates the in-memory catalog so models registered before the
        // restart remain discoverable.
        let acceptance = self.config.model_licensing.clone();
        let registry = if let Some(ref storage) = self.storage {
            Arc::new(
                ModelRegistry::with_storage(storage.clone() as Arc<dyn tenzro_storage::KvStore>)
                    .with_acceptance_policy(acceptance),
            )
        } else {
            Arc::new(ModelRegistry::new().with_acceptance_policy(acceptance))
        };
        self.model_registry = Some(registry);

        // Governance-anchored model-weight transparency log. Hydrates the
        // `model_id → canonical_hash` map from CF_MODEL_HASHES so records
        // asserted before the restart survive. Recording is permissionless
        // first-recorder-wins; correction flows only through a governance
        // override verified at the RPC layer before `override_hash` is called.
        let model_hash_registry = if let Some(ref storage) = self.storage {
            Arc::new(tenzro_model::ModelHashRegistry::with_storage(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            ))
        } else {
            Arc::new(tenzro_model::ModelHashRegistry::new())
        };
        info!(
            "Model-hash transparency log ready ({} canonical records)",
            model_hash_registry.list().len()
        );
        self.model_hash_registry = Some(model_hash_registry);

        // Initialize provider manager (with storage persistence if available)
        let provider_manager = if let Some(ref storage) = self.storage {
            Arc::new(ProviderManager::with_storage(storage.clone() as Arc<dyn tenzro_storage::KvStore>))
        } else {
            Arc::new(ProviderManager::new())
        };
        self.provider_manager = Some(provider_manager.clone());

        // Initialize usage tracker (with storage persistence if available).
        // The tracker is the producer-side aggregation point for every
        // successful inference's `UsageRecord`; failure to construct with
        // storage falls back to in-memory only so the node still runs.
        let usage_tracker = if let Some(ref storage) = self.storage {
            match tenzro_model::UsageTracker::with_storage(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            ) {
                Ok(t) => Arc::new(t),
                Err(e) => {
                    tracing::warn!(
                        "UsageTracker storage hydration failed ({}); falling back to in-memory",
                        e
                    );
                    Arc::new(tenzro_model::UsageTracker::new())
                }
            }
        } else {
            Arc::new(tenzro_model::UsageTracker::new())
        };
        self.usage_tracker = Some(usage_tracker.clone());

        // Sealed-model infrastructure: the manifest store hydrates
        // `sealed:`-prefixed records from CF_MODELS so sealed models
        // installed before a restart remain resolvable, and the X25519
        // recipient key is this node's decryption identity for
        // per-recipient wrapped content keys. Key failure is non-fatal:
        // the node can still seal (publisher role needs only recipients'
        // public keys) but cannot install sealed models addressed to it.
        let sealed_store = if let Some(ref storage) = self.storage {
            Arc::new(tenzro_model::SealedModelStore::with_storage(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            ))
        } else {
            Arc::new(tenzro_model::SealedModelStore::new())
        };
        self.sealed_model_store = Some(sealed_store);
        match crate::keygen::load_or_generate_model_recipient_key(&self.config.data_dir) {
            Ok(secret) => {
                match tenzro_crypto::encryption::X25519KeyPair::from_secret_bytes(&secret) {
                    Ok(kp) => {
                        info!(
                            "Sealed-model recipient key ready (x25519 pubkey {})",
                            hex::encode(kp.public_key_bytes())
                        );
                        self.model_recipient_key = Some(Arc::new(kp));
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Sealed-model recipient key on disk is invalid ({}); \
                             this node cannot install sealed models until the key \
                             file is removed and regenerated",
                            e
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to load or generate sealed-model recipient key ({}); \
                     this node cannot install sealed models",
                    e
                );
            }
        }

        // EU AI Act Art. 50(2): every node that serves inference produces a
        // signed provenance manifest for each response. The signer uses the
        // node's long-term Ed25519 key — the same key that signs gossip
        // announcements — so consumers can verify response manifests against
        // the announcement pubkey they already pinned. Nodes without a key
        // on disk fall back to an ephemeral signer (manifest is still a
        // valid disclosure mark, just not bindable to a registered
        // provider). The store is shared with the `tenzro_getProvenance`
        // RPC so the read and write paths see the same in-memory cache.
        // Failure to mint any key is non-fatal: the router degrades to
        // "synthetic_content=true but no signature", matching dev-mode
        // nodes.
        let provenance_store = Arc::new(tenzro_model::ProvenanceStore::default());
        self.provenance_store = Some(provenance_store.clone());
        let provenance_signer: Option<tenzro_model::SharedProvenanceSigner> =
            match crate::keygen::load_validator_keypair(&self.config.data_dir) {
                Ok(keypair) => {
                    match tenzro_crypto::signatures::Ed25519SignerImpl::new(keypair) {
                        Ok(signer) => Some(
                            tenzro_model::Ed25519ProvenanceSigner::new(signer).into_shared(),
                        ),
                        Err(e) => {
                            tracing::warn!(
                                "Failed to construct provenance signer from node key ({}); \
                                 responses will carry synthetic_content=true but no signed \
                                 manifest",
                                e
                            );
                            None
                        }
                    }
                }
                Err(_) => match tenzro_model::Ed25519ProvenanceSigner::generate() {
                    Ok(s) => Some(s.into_shared()),
                    Err(e) => {
                        tracing::warn!(
                            "Failed to mint provenance signer ({}); responses will carry \
                             synthetic_content=true but no signed manifest",
                            e
                        );
                        None
                    }
                },
            };
        self.provenance_signer = provenance_signer.clone();

        // Operator-declared jurisdiction claim, built once here so the
        // provider announcement and the local response stamp agree on a
        // single claim. When the node has TEE hardware, the claim is bound
        // to a fresh attestation report whose user_data commits to the
        // declared country + blocs; the SHA-256 of the attestation evidence
        // rides the claim so relying parties can tie it back to the enclave.
        // Without TEE hardware the claim is operator-asserted only
        // (attestation_hash = None) — receipts still verify, they just
        // carry a weaker trust story. This is an attestation-bound locality
        // claim, not cryptographic proof of location: false declarations
        // are punished economically (slashing / reputation), not prevented
        // mathematically.
        if let Some(country) = &self.config.jurisdiction_country {
            let country = country.trim().to_ascii_uppercase();
            let blocs: Vec<String> = self
                .config
                .jurisdiction_blocs
                .iter()
                .map(|b| b.trim().to_ascii_uppercase())
                .filter(|b| !b.is_empty())
                .collect();
            let attestation_hash = if let Some(tee) = &self.tee_provider {
                let mut binding = b"tenzro/jurisdiction".to_vec();
                binding.extend_from_slice(country.as_bytes());
                for b in &blocs {
                    binding.push(0);
                    binding.extend_from_slice(b.as_bytes());
                }
                let user_data = tenzro_crypto::sha256(&binding);
                match tee.generate_attestation(user_data.as_bytes()).await {
                    Ok(report) => tenzro_types::Hash::from_bytes(
                        tenzro_crypto::sha256(&report.attestation_data).as_bytes(),
                    ),
                    Err(e) => {
                        tracing::warn!(
                            "Failed to bind jurisdiction claim to TEE attestation ({}); \
                             claim will be operator-asserted only",
                            e
                        );
                        None
                    }
                }
            } else {
                None
            };
            tracing::info!(
                country = %country,
                blocs = ?blocs,
                attested = attestation_hash.is_some(),
                "Jurisdiction claim declared"
            );
            self.jurisdiction_claim = Some(tenzro_types::JurisdictionClaim {
                country,
                blocs,
                attestation_hash,
                declared_at: tenzro_types::Timestamp::now(),
            });

            // Jurisdiction signer: same node key as the provenance signer so
            // `tenzro_jurisdiction` receipts verify against the announcement
            // pubkey consumers pinned. No ephemeral fallback — a locality
            // claim that can't be bound to a registered provider key is not
            // worth stamping.
            self.jurisdiction_signer =
                match crate::keygen::load_validator_keypair(&self.config.data_dir) {
                    Ok(keypair) => {
                        match tenzro_crypto::signatures::Ed25519SignerImpl::new(keypair) {
                            Ok(signer) => Some(
                                tenzro_model::Ed25519JurisdictionSigner::new(signer)
                                    .into_shared(),
                            ),
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to construct jurisdiction signer from node key \
                                     ({}); locally served responses will not carry \
                                     jurisdiction receipts",
                                    e
                                );
                                None
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Jurisdiction declared but no node key available ({}); locally \
                             served responses will not carry jurisdiction receipts",
                            e
                        );
                        None
                    }
                };
        }

        // Initialize inference router with the tracker attached so every
        // successful inference flows through `record_usage` for durable
        // per-model / per-provider / global aggregation, and stamps a
        // provenance manifest before returning each response.
        let mut router_builder = InferenceRouter::new(provider_manager)
            .with_usage_tracker(usage_tracker)
            .with_provenance_store(provenance_store);
        if let Some(signer) = provenance_signer {
            router_builder = router_builder.with_provenance_signer(signer);
        }
        let router = Arc::new(router_builder);
        self.inference_router = Some(router);

        // Initialize agent runtime with gossipsub network transport
        let agent_runtime = if let Some(ref network) = self.network {
            // Create outbound channel for publishing agent messages to gossipsub
            let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<(String, Vec<u8>)>(1000);

            // Create the transport wired to the network
            let (transport, inbound_tx) =
                tenzro_agent::messaging::GossipsubTransport::with_network(outbound_tx);

            // Spawn outbound bridge: reads from channel → broadcasts via gossipsub
            let net_out = network.clone();
            tokio::spawn(async move {
                while let Some((topic, data)) = outbound_rx.recv().await {
                    let msg = NetworkMessage::new(
                        MessagePayload::Custom {
                            topic: topic.clone(),
                            data: data.clone(),
                        },
                    );
                    if let Err(e) = net_out.broadcast(&topic, msg).await {
                        tracing::warn!("Failed to broadcast agent message on gossipsub: {}", e);
                    }
                }
            });

            // Spawn inbound bridge: subscribes to agents topic → feeds into transport
            let net_in = network.clone();
            tokio::spawn(async move {
                match net_in.subscribe("tenzro/agents").await {
                    Ok(mut rx) => {
                        while let Some(msg) = rx.recv().await {
                            if let tenzro_network::MessagePayload::Custom { data, .. } = msg.payload
                            {
                                match serde_json::from_slice::<tenzro_types::AgentMessage>(&data) {
                                    Ok(agent_msg) => {
                                        let _ = inbound_tx.send(agent_msg).await;
                                    }
                                    Err(e) => {
                                        tracing::debug!(
                                            "Ignoring non-agent message on agents topic: {}",
                                            e
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to subscribe to agents gossipsub topic: {}",
                            e
                        );
                    }
                }
            });

            info!("Agent messaging wired to gossipsub (tenzro/agents)");
            // Prefer the storage-backed constructor so RegisteredAgent,
            // AgentLifecycleInfo, and the spawn tree are hydrated on boot and
            // every subsequent mutation is written through to CF_AGENTS.
            if let Some(ref storage) = self.storage {
                Arc::new(AgentRuntime::with_storage(
                    storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                    Some(Arc::new(transport)),
                )?)
            } else {
                Arc::new(AgentRuntime::with_network_transport(Arc::new(transport))?)
            }
        } else {
            // No network available — use local-only message routing
            info!("Agent messaging in local-only mode (no network)");
            if let Some(ref storage) = self.storage {
                Arc::new(AgentRuntime::with_storage(
                    storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                    None,
                )?)
            } else {
                Arc::new(AgentRuntime::new()?)
            }
        };
        // SwarmManager mirrors the same storage so swarm membership and
        // status survive restarts via the `swarm:` prefix in CF_AGENTS.
        let swarm_mgr = if let Some(ref storage) = self.storage {
            Arc::new(SwarmManager::with_storage(
                agent_runtime.clone(),
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            )?)
        } else {
            Arc::new(SwarmManager::new(agent_runtime.clone()))
        };
        // Tenzro iroh endpoint (Phase C1, #219) — single resolver shared
        // across the training `GradientPayloadStore`, the storage
        // `IrohBlobsDaBackend`, agent-memory archival (Phase D1, #222), and
        // direct `tenzro://blob/<hash>` URI fetches. Construction is opt-in
        // via `NodeConfig::iroh`; when absent the node runs without an iroh
        // data plane (inline DA fallback only).
        //
        // Bound here — before the agent-memory tier and the training runtime —
        // so downstream consumers in this function can detect `self.iroh_resolver`
        // and prefer the iroh-blobs DA backend over `InlineFallbackBackend`.
        //
        // Per the locked model statement (2026-05-17): the resolver runs
        // **alongside** libp2p, not in place of it. libp2p remains the
        // control plane (gossipsub, kademlia, consensus dispatch); iroh
        // is the bulk-transfer data plane.
        // Iroh data plane is always bound. The default Pkarr relay
        // (`https://pkarr.tenzro.xyz`) is operator-deployed; on a
        // dev/laptop node without DNS access the bind still succeeds because
        // PkarrPublisher tolerates a transient relay outage and the local
        // endpoint stays usable for direct dials.
        //
        // Rebase iroh's blob/docs storage under the node's `--data-dir` so
        // operators only have to manage one data root.
        let mut iroh_cfg = self.config.iroh.clone();
        iroh_cfg.data_dir = self.config.data_dir.join("iroh");

        // Anchor the iroh endpoint to the node's TDIP Ed25519 seed so the
        // resulting iroh `EndpointId` is byte-identical to the node DID's
        // public key. Pkarr records published to the Tenzro-operated relay
        // are therefore signed by the on-chain identity key — no extra
        // attestation layer needed.
        let cfg = match crate::keygen::load_validator_keypair(&self.config.data_dir) {
            Ok(keypair) => {
                let seed_bytes = keypair.secret_key().as_bytes();
                if seed_bytes.len() == 32 {
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(seed_bytes);
                    iroh_cfg.with_secret_key_seed(seed)
                } else {
                    tracing::warn!(
                        "Validator Ed25519 seed has unexpected length {} (want 32); \
                         binding iroh endpoint with a fresh ephemeral key — \
                         discovery will not be TDIP-anchored",
                        seed_bytes.len()
                    );
                    iroh_cfg
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Could not load validator keypair ({}); binding iroh endpoint \
                     with a fresh ephemeral key — discovery will not be TDIP-anchored",
                    e
                );
                iroh_cfg
            }
        };

        // Construct a deferred A2A dispatcher now so the `tenzro/a2a` ALPN is
        // registered on the iroh router at bind time. The real backing
        // dispatcher (which needs `Arc<TenzroNode>` for `A2aState`) gets
        // installed in `main.rs` after `Arc::new(node)`. Until then, the
        // dispatcher returns a JSON-RPC `-32603` envelope — peers see a
        // defined response rather than a hung stream.
        let a2a_deferred = Arc::new(tenzro_iroh::DeferredJsonRpcDispatcher::new("a2a"));
        self.iroh_a2a_dispatcher = Some(a2a_deferred.clone());

        let a2a_dispatcher: Arc<dyn tenzro_iroh::JsonRpcDispatcher> = a2a_deferred;

        // MCP-over-iroh: same trampoline pattern. The real handler
        // (`mcp::iroh_transport::IrohMcpHandler`) needs `Arc<TenzroNode>`
        // and is installed from `main.rs` after `Arc::new(node)`.
        let mcp_deferred = Arc::new(tenzro_iroh::DeferredMcpHandler::new());
        self.iroh_mcp_handler = Some(mcp_deferred.clone());
        let mcp_handler: Arc<dyn tenzro_iroh::McpStreamHandler> = mcp_deferred;

        // MoE-over-iroh: unlike A2A/MCP, the dispatcher needs only the
        // expert runtime and the announce-signer receipt identity, both of
        // which already exist — register the real one. Without a signer on
        // disk the holder serves receiptless and remote routers reject it,
        // matching the fail-closed provider-announcement policy.
        let moe_receipt_identity = self
            .announce_signer
            .clone()
            .zip(self.self_provider_address())
            .map(|(signer, provider)| crate::moe::MoeReceiptIdentity { signer, provider });
        let moe_dispatcher: Arc<dyn tenzro_iroh::JsonRpcDispatcher> = Arc::new(
            crate::moe::MoeIrohDispatcher::new(Arc::clone(&self.moe_runtime), moe_receipt_identity),
        );

        // Inference-over-iroh: same trampoline pattern as A2A. The real
        // dispatcher (`crate::infer::IrohInferDispatcher`) needs
        // `Arc<TenzroNode>` to reach `handle_chat` and is installed from
        // `main.rs` after `Arc::new(node)`.
        let infer_deferred = Arc::new(tenzro_iroh::DeferredJsonRpcDispatcher::new("infer"));
        self.iroh_infer_dispatcher = Some(infer_deferred.clone());
        let infer_dispatcher: Arc<dyn tenzro_iroh::JsonRpcDispatcher> = infer_deferred;

        // HTTP-forward-over-iroh (app-hosting ingress data plane): same
        // trampoline pattern. The real handler (`crate::ingress::IrohIngressHandler`)
        // needs `Arc<TenzroNode>` to reach the site registry + app runtimes
        // and is installed from `main.rs` after `Arc::new(node)`.
        let http_deferred = Arc::new(tenzro_iroh::DeferredHttpHandler::new());
        self.iroh_http_handler = Some(http_deferred.clone());
        let http_handler: Arc<dyn tenzro_iroh::HttpForwardHandler> = http_deferred;

        match tenzro_iroh::IrohBackedResolver::bind_with_jsonrpc(
            &cfg,
            Some(a2a_dispatcher),
            Some(mcp_handler),
            Some(moe_dispatcher),
            Some(infer_dispatcher),
            Some(http_handler),
        )
        .await
        {
            Ok(resolver) => {
                if let Some(pkarr_relay) = cfg.pkarr_relay_url.as_ref()
                    && cfg.secret_key_seed.is_some()
                {
                    info!(
                        pkarr_relay = %pkarr_relay,
                        bind_addr = %cfg.bind_addr,
                        "Tenzro iroh resolver bound (TDIP-anchored, Pkarr discovery via Tenzro relay, A2A + MCP + MoE + infer + http ALPNs registered)"
                    );
                } else if cfg.secret_key_seed.is_some() {
                    info!(
                        bind_addr = %cfg.bind_addr,
                        "Tenzro iroh resolver bound (TDIP-anchored, n0-dns discovery only, A2A + MCP + MoE + infer + http ALPNs registered)"
                    );
                } else {
                    info!(
                        bind_addr = %cfg.bind_addr,
                        "Tenzro iroh resolver bound (ephemeral key, persistent blob store, A2A + MCP + MoE + infer + http ALPNs registered)"
                    );
                }
                self.iroh_resolver = Some(resolver);

                // Machine supervisor: only on a node built with the
                // `firecracker` feature. The microVM image is fetched over this
                // iroh resolver, and sealed env vars are unwrapped against an
                // X25519 sealing key derived from the node's validator secret
                // (domain-separated hash) so the sealing pubkey is stable and
                // advertisable. Absent hardware, launches surface an explicit
                // error rather than a silent no-op (no simulation on testnet).
                #[cfg(feature = "firecracker")]
                if let Some(resolver) = &self.iroh_resolver {
                    match crate::keygen::load_validator_keypair(&self.config.data_dir) {
                        Ok(vkp) => {
                            let seed = tenzro_crypto::sha256(
                                &[b"tenzro/hosting/machine/sealing".as_ref(), &vkp.to_bytes()]
                                    .concat(),
                            );
                            match tenzro_crypto::encryption::X25519KeyPair::from_secret_bytes(
                                seed.as_bytes(),
                            ) {
                                Ok(sealing_key) => {
                                    let chroot_base =
                                        self.config.data_dir.join("machines");
                                    let resolver: Arc<dyn tenzro_iroh::IrohResolver> =
                                        resolver.clone();
                                    let mut supervisor =
                                        crate::machines::MachineSupervisor::new(
                                            resolver,
                                            Arc::new(sealing_key),
                                            chroot_base,
                                        );
                                    // Firecracker / jailer binaries and the guest
                                    // kernel are operator infrastructure, so let
                                    // the operator point at their own via env.
                                    if let (Ok(fc), Ok(jl)) = (
                                        std::env::var("TENZRO_FIRECRACKER_BIN"),
                                        std::env::var("TENZRO_JAILER_BIN"),
                                    ) {
                                        supervisor = supervisor.with_binaries(fc, jl);
                                    }
                                    if let Ok(kernel) =
                                        std::env::var("TENZRO_MACHINE_KERNEL")
                                    {
                                        supervisor = supervisor
                                            .with_kernel(std::path::PathBuf::from(kernel));
                                    }
                                    // Hardened jailer defaults drop each microVM
                                    // to an unprivileged uid/gid; operators with a
                                    // dedicated system account override the pair.
                                    if let (Ok(uid), Ok(gid)) = (
                                        std::env::var("TENZRO_JAILER_UID"),
                                        std::env::var("TENZRO_JAILER_GID"),
                                    ) {
                                        if let (Ok(uid), Ok(gid)) =
                                            (uid.parse::<u32>(), gid.parse::<u32>())
                                        {
                                            supervisor =
                                                supervisor.with_jailer_identity(uid, gid);
                                        }
                                    }
                                    if let Ok(cg) =
                                        std::env::var("TENZRO_JAILER_CGROUP_VERSION")
                                    {
                                        if let Ok(cg) = cg.parse::<u8>() {
                                            let sc = std::env::var(
                                                "TENZRO_JAILER_SECCOMP_LEVEL",
                                            )
                                            .ok()
                                            .and_then(|s| s.parse::<u8>().ok())
                                            .unwrap_or(
                                                crate::machines::DEFAULT_JAILER_SECCOMP_LEVEL,
                                            );
                                            supervisor =
                                                supervisor.with_jailer_isolation(cg, sc);
                                        }
                                    }
                                    self.machine_supervisor = Some(Arc::new(supervisor));
                                    info!("Machine supervisor wired (firecracker feature)");
                                }
                                Err(e) => tracing::warn!(
                                    "Machine sealing key derivation failed ({e}); \
                                     machine hosting disabled on this node"
                                ),
                            }
                        }
                        Err(e) => tracing::warn!(
                            "Machine supervisor needs the validator keypair ({e}); \
                             machine hosting disabled on this node"
                        ),
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Iroh resolver bind failed ({}); continuing without iroh data plane",
                    e
                );
                // Bind failed — drop the deferred dispatcher handles since
                // no router will ever call into them.
                self.iroh_a2a_dispatcher = None;
                self.iroh_mcp_handler = None;
                self.iroh_infer_dispatcher = None;
                self.iroh_http_handler = None;
            }
        }

        // Provider service runtimes (storage + compute rental). Both draw on the
        // same provider stake, so they share one `ProviderObligations` tracker
        // (cross-service coverage: storage byte-epoch exposure + compute
        // per-epoch exposure admit against one stake) and one prepaid `balances`
        // map (the streaming-escrow deposit ledger). The shared state is built
        // once here and handed to whichever runtimes this node's roles enable.
        if (self.config.roles.serves_storage() || self.config.roles.serves_ai())
            && let Some(staking) = self.staking.as_ref()
        {
            let staking = staking.clone();
            let provider_address = self.operator_payee().unwrap_or_default();
            let stake_ledger: Arc<dyn tenzro_settlement::rental::StakeLedger> = Arc::new(
                crate::storage_provider_runtime::StakingStakeLedger::new(staking),
            );
            let obligations =
                Arc::new(tenzro_settlement::obligations::ProviderObligations::new());

            // Prepaid-balance ledger: funds the shared balances map from renters'
            // on-chain TNZO and persists it. Built only when both durable storage
            // and the token subsystem are present; otherwise the streaming path
            // runs over an in-memory, unfunded map (test/dev). When present, the
            // ledger's own map becomes the shared `balances` so deposits, per-epoch
            // streaming, and refunds all move value inside the durable ledger.
            let balances: Arc<dashmap::DashMap<(tenzro_types::primitives::Address, tenzro_types::asset::AssetId), u128>> =
                match (&self.storage, &self.token) {
                    (Some(kv), Some(token)) => {
                        let accounts: Arc<dyn tenzro_settlement::AccountLedger> = Arc::new(
                            crate::prepaid_account_ledger::TnzoAccountLedger::new(token.clone()),
                        );
                        let ledger = Arc::new(tenzro_settlement::PrepaidLedger::new(
                            accounts,
                            kv.clone() as Arc<dyn tenzro_storage::KvStore>,
                        ));
                        let inner = ledger.inner();
                        self.prepaid_ledger = Some(ledger);
                        info!("Prepaid-balance ledger initialized (CF_SETTLEMENTS / prepaid_balance:)");
                        inner
                    }
                    _ => Arc::new(dashmap::DashMap::new()),
                };

            // Storage-provider runtime. Needs the iroh data plane for shard
            // transport in addition to the staking-backed coverage above.
            if self.config.roles.serves_storage() {
                match &self.iroh_resolver {
                    Some(resolver) => {
                        let resolver: Arc<dyn tenzro_iroh::IrohResolver> = resolver.clone();
                        let policy = self.config.provider_rates.storage.clone();
                        let storage_rate = policy.effective_rate();
                        let runtime = match &self.storage {
                            Some(kv) => crate::storage_provider_runtime::StorageProviderRuntime::with_storage(
                                provider_address,
                                resolver,
                                balances.clone(),
                                stake_ledger.clone(),
                                obligations.clone(),
                                policy,
                                kv.clone() as Arc<dyn tenzro_storage::KvStore>,
                            ),
                            None => crate::storage_provider_runtime::StorageProviderRuntime::new(
                                provider_address,
                                resolver,
                                balances.clone(),
                                stake_ledger.clone(),
                                obligations.clone(),
                                policy,
                            ),
                        };
                        self.storage_runtime = Some(Arc::new(runtime));
                        info!(
                            provider = %provider_address,
                            rate = storage_rate,
                            "Storage-provider runtime spawned"
                        );
                    }
                    None => warn!(
                        "StorageProvider role set but iroh resolver unavailable; storage runtime not spawned"
                    ),
                }
            }

            // Compute-rental runtime. Serves the compute role directly, and a
            // node serving AI rents out the same accelerators for fixed terms;
            // no transport is needed, just the shared coverage backing.
            if self.config.roles.serves_ai() || self.config.roles.serves_compute() {
                let policy = self.config.provider_rates.compute.clone();
                let compute_rate = policy.effective_rate();
                let runtime = match &self.storage {
                    Some(kv) => crate::compute_rental_runtime::ComputeRentalRuntime::with_storage(
                        provider_address,
                        balances.clone(),
                        stake_ledger.clone(),
                        obligations.clone(),
                        policy,
                        kv.clone() as Arc<dyn tenzro_storage::KvStore>,
                    ),
                    None => crate::compute_rental_runtime::ComputeRentalRuntime::new(
                        provider_address,
                        balances.clone(),
                        stake_ledger.clone(),
                        obligations.clone(),
                        policy,
                    ),
                };
                self.compute_runtime = Some(Arc::new(runtime));
                info!(
                    provider = %provider_address,
                    rate = compute_rate,
                    "Compute-rental runtime spawned"
                );

                // LAN cluster-serving runtime. A node serving AI also offers
                // its layer range as a pipeline stage to head nodes on the
                // local network, so a model too large for one machine can be
                // split across members. Only boundary activations cross the
                // wire, tunnelled over the cluster request-response protocol.
                if self.config.roles.serves_ai()
                    && let Some(ref network) = self.network
                {
                    let net: Arc<dyn tenzro_network::NetworkService> = network.clone();
                    let runtime =
                        Arc::new(crate::cluster_serving_runtime::ClusterServingRuntime::new(net));
                    if let Err(e) = runtime.serve_as_member().await {
                        warn!(error = %e, "Cluster-serving member loop not attached");
                    } else {
                        self.cluster_serving_runtime = Some(runtime);
                        info!("Cluster-serving runtime spawned (LAN pipeline member)");
                    }
                }
            }
        } else if self.config.roles.serves_storage()
            || self.config.roles.serves_ai()
            || self.config.roles.serves_compute()
        {
            warn!(
                "Provider role set but staking ledger unavailable; storage/compute runtimes not spawned"
            );
        }

        // Billing epoch loop. When this node runs a storage and/or compute
        // provider runtime, a background task streams one epoch's slice of every
        // active deal + rental each interval: storage charges are PoR-gated
        // (`StorageMeter::charge_epoch`), compute slices are availability-gated
        // (`RentalManager::settle_epoch`). After streaming, it persists the
        // prepaid ledger so the durable balances track the epoch's value moves.
        // Provider-local metering only — every replica bills the deals it serves;
        // no leader gate.
        if self.storage_runtime.is_some() || self.compute_runtime.is_some() {
            let storage_runtime = self.storage_runtime.clone();
            let compute_runtime = self.compute_runtime.clone();
            let prepaid_ledger = self.prepaid_ledger.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
                    BILLING_EPOCH_INTERVAL_SECS,
                ));
                // Skip the immediate first tick — no deals exist at boot.
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    // Each runtime logs its own per-epoch counts internally.
                    if let Some(rt) = &storage_runtime {
                        rt.run_billing_epoch().await;
                    }
                    if let Some(rt) = &compute_runtime {
                        rt.run_billing_epoch();
                    }
                    if let Some(ledger) = &prepaid_ledger {
                        ledger.persist();
                    }
                }
            });
            info!(
                interval_secs = BILLING_EPOCH_INTERVAL_SECS,
                "Provider billing epoch loop spawned"
            );
        }

        // DvP saga expiry sweep. Compensates and expires every Open/Executing
        // saga past its deadline; without this driver a stalled counterparty
        // could pin an escrow's funds indefinitely. Compensation refunds
        // already-completed legs, so it mutates escrow balances — validator
        // role + leader gate, matching the SeedAgent daemon precedent, so one
        // validator per tick drives the sweep. Convergence on other replicas
        // is automatic: the orchestrator write-through to CF_SETTLEMENTS makes
        // the expired state visible on the next hydrate, and `expire_sweep` is
        // idempotent under the orchestrator's in-flight guard.
        if self.config.roles.is_validator()
            && let Some(escrow_manager) = self.escrow_manager.clone()
        {
            let saga_orchestrator = self.saga_orchestrator.clone();
            let consensus = self.consensus.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
                    SAGA_EXPIRY_SWEEP_INTERVAL_SECS,
                ));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                // Skip the immediate first tick — nothing is expired at boot.
                ticker.tick().await;
                let executor =
                    crate::saga_executor::NodeLegExecutor::new(escrow_manager);
                loop {
                    ticker.tick().await;
                    // Leader gate: only the elected leader for the next 32
                    // views drives the sweep. The conservative `Err` path
                    // in `is_leader_in_next_views` returns `true` when
                    // consensus has stalled or this node is outside the
                    // set, but the in-flight guard still serialises the
                    // compensation so double-refund is impossible.
                    let is_authority = consensus
                        .as_ref()
                        .map(|c| c.is_leader_in_next_views(32))
                        .unwrap_or(true);
                    if !is_authority {
                        continue;
                    }
                    let expired = saga_orchestrator.expire_sweep(&executor).await;
                    if expired > 0 {
                        info!(expired, "DvP saga expiry sweep compensated expired sagas");
                    }
                }
            });
            info!(
                interval_secs = SAGA_EXPIRY_SWEEP_INTERVAL_SECS,
                "DvP saga expiry sweep spawned (validator role, leader-gated)"
            );
        }

        // App-hosting placement reconcile. Each node reconciles the leases it
        // created: sweep expired leases, and evict any serving node whose
        // provider announcement has aged out of the live candidate set,
        // re-letting its replica slot over the survivors. No leader gate — a
        // lease is owned by the node that placed it, and `handle_liveness_loss`
        // + `sweep_expired` both terminate in an idempotent
        // `IngressTable::set_placement` write-through, so concurrent reconciles
        // on different nodes converge. Skipped in in-memory mode (no storage).
        if self.storage.is_some() {
            let scheduler = self.placement_scheduler.clone();
            let providers = self.network_providers.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(
                    PLACEMENT_RECONCILE_INTERVAL_SECS,
                ));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                // Skip the immediate first tick — nothing is placed at boot.
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    let candidates = distill_hosting_candidates(&providers);
                    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
                    let evicted = scheduler.reconcile(&candidates, now_ms);
                    if evicted > 0 {
                        info!(evicted, "placement reconcile evicted stale serving node(s)");
                    }
                }
            });
            info!(
                interval_secs = PLACEMENT_RECONCILE_INTERVAL_SECS,
                "App-hosting placement reconcile spawned"
            );
        }

        // Phase B agent memory tier: Lance vector + Tantivy BM25 + DA archive,
        // rooted at `{data_dir}/agent_memory/`. The text-embedding runtime is
        // shared across the node so any model loaded via
        // `tenzro_loadTextEmbeddingModel` becomes addressable for `memory.grant`
        // by setting `MemoryManagerConfig::embedder_model_id`.
        //
        // The embedding dim is fixed at table-creation time and must equal the
        // dim of the embedder. We default to 1024 (Qwen3-Embedding 0.6B,
        // BGE-M3, Snowflake Arctic Embed L). Operators with a different
        // default model should provision a fresh `agent_memory/` directory.
        let memory_root = self.config.data_dir.join("agent_memory");
        let embedding_dim: usize = 1024;
        match (
            tenzro_agent::memory::LanceVectorBackend::new(&memory_root, embedding_dim).await,
            tenzro_agent::memory::TantivyTextBackend::new(&memory_root),
        ) {
            (Ok(vec_backend), Ok(text_backend)) => {
                // Agent-memory archival DA backend, selected by
                // `NodeConfig::da_backend`. `Auto` prefers iroh-blobs when the
                // resolver is bound (the canonical archive payload becomes a
                // BLAKE3-addressed blob reachable from any node via
                // `tenzro://memory/<did>/<uuid>`) and falls back to the
                // in-process inline store when iroh is disabled. `Inline`
                // always uses the inline store. `IrohBlobs` requires the
                // resolver and refuses to start without it.
                let da: Arc<dyn tenzro_storage::da::DaBackend> = match self.config.da_backend {
                    crate::config::DaBackendSelector::Inline => {
                        info!("Agent memory tier wired with inline DA backend (da_backend=inline)");
                        Arc::new(tenzro_storage::da::InlineFallbackBackend::new())
                    }
                    crate::config::DaBackendSelector::IrohBlobs => match self.iroh_resolver {
                        Some(ref resolver) => {
                            info!("Agent memory tier wired with iroh-blobs DA backend (da_backend=iroh_blobs)");
                            tenzro_iroh::IrohBlobsDaBackend::arc(resolver.clone())
                        }
                        None => {
                            return Err(NodeError::Other(
                                "da_backend=iroh_blobs requires the iroh resolver, but it is not bound".to_string(),
                            ));
                        }
                    },
                    crate::config::DaBackendSelector::Committee => {
                        match self.da_committee_backend {
                            Some(ref backend) => {
                                info!("Agent memory tier wired with committee-resident DA backend (da_backend=committee)");
                                backend.clone()
                            }
                            None => {
                                return Err(NodeError::Other(
                                    "da_backend=committee requires the committee-resident backend, but it is not bound (validator role + consensus required)".to_string(),
                                ));
                            }
                        }
                    }
                    crate::config::DaBackendSelector::Auto => {
                        if let Some(ref resolver) = self.iroh_resolver {
                            info!("Agent memory tier wired with iroh-blobs DA backend (da_backend=auto)");
                            tenzro_iroh::IrohBlobsDaBackend::arc(resolver.clone())
                        } else {
                            Arc::new(tenzro_storage::da::InlineFallbackBackend::new())
                        }
                    }
                };
                let mgr = Arc::new(tenzro_agent::memory::MemoryManager::new(
                    Arc::new(vec_backend),
                    Arc::new(text_backend),
                    da,
                    Some(self.text_embedding_runtime.clone()),
                    tenzro_agent::memory::MemoryManagerConfig::default(),
                ));
                if agent_runtime.set_memory_manager(mgr) {
                    info!(
                        "Agent memory tier initialized at {:?} (dim={})",
                        memory_root, embedding_dim
                    );
                } else {
                    tracing::warn!(
                        "Agent memory tier already attached to runtime; skipping"
                    );
                }
            }
            (Err(e), _) => {
                tracing::warn!(
                    "Agent memory tier disabled (Lance backend init failed): {}",
                    e
                );
            }
            (_, Err(e)) => {
                tracing::warn!(
                    "Agent memory tier disabled (Tantivy backend init failed): {}",
                    e
                );
            }
        }

        self.agent_runtime = Some(agent_runtime);
        self.swarm_manager = Some(swarm_mgr);
        info!("Swarm manager initialized");

        // Intent router (model selection tier). Reuses the registry, usage
        // tracker, and inference router already built above, and adapts the
        // agent runtime's per-machine spending policy into the meta-router's
        // per-DID budget gate so intent-routed dispatch enforces the same
        // rolling-window ceiling as direct payments.
        if let (Some(registry), Some(usage), Some(router)) = (
            self.model_registry.clone(),
            self.usage_tracker.clone(),
            self.inference_router.clone(),
        ) {
            let mut meta = tenzro_model::meta_router::MetaRouter::new(registry, usage, router);
            if let Some(ref runtime) = self.agent_runtime {
                let gate = Arc::new(crate::spending_policy_bridge::SpendingPolicyBudgetGate::new(
                    runtime.clone(),
                ));
                meta = meta.with_budget_gate(gate);
            }
            // Wallet-balance ceiling: read the payer's on-chain TNZO balance so
            // no intent is ever routed to a model the payer cannot pay for.
            if let Some(ref token) = self.token {
                let balance = Arc::new(crate::spending_policy_bridge::TnzoBalanceProvider::new(
                    token.clone(),
                ));
                meta = meta.with_balance_provider(balance);
            }
            // Per-query difficulty: cluster prompts by embedding and score
            // candidates on the error rate each has actually shown in that
            // neighbourhood, instead of on declared parameter counts alone.
            // Observations persist so the index survives restarts.
            let difficulty = match self.storage.clone() {
                Some(storage) => tenzro_model::difficulty::DifficultyIndex::with_storage(
                    tenzro_model::difficulty::DEFAULT_CLUSTER_CAPACITY,
                    storage as Arc<dyn tenzro_storage::KvStore>,
                )
                .unwrap_or_else(|e| {
                    warn!("route difficulty index starting empty (hydrate failed): {e}");
                    tenzro_model::difficulty::DifficultyIndex::new(
                        tenzro_model::difficulty::DEFAULT_CLUSTER_CAPACITY,
                    )
                }),
                None => tenzro_model::difficulty::DifficultyIndex::new(
                    tenzro_model::difficulty::DEFAULT_CLUSTER_CAPACITY,
                ),
            };
            let clusters = difficulty.cluster_count();
            meta = meta.with_difficulty_index(Arc::new(difficulty));
            // Prompt embedding reuses the text-embedding runtime shared with the
            // agent memory tier. With no embedding model loaded, routing falls
            // back to declared metadata rather than failing.
            meta = meta.with_prompt_embedder(Arc::new(
                crate::spending_policy_bridge::RuntimePromptEmbedder::new(
                    self.text_embedding_runtime.clone(),
                ),
            ));
            // The offers other providers are announcing on `tenzro/models` right
            // now, scored alongside this node's own catalog. Without this the
            // intent tier only ever sees what this operator registered locally,
            // so what the network can serve would depend on per-node curation.
            // Each offer also names the address that serves it, so the provider
            // share follows from the winning offer.
            meta = meta.with_network_catalog(Arc::new(
                crate::network_catalog::GossipNetworkCatalog::new(self.network_models.clone()),
            ));
            self.meta_router = Some(Arc::new(meta));
            info!("Meta-router (intent → model) initialized with {clusters} difficulty cluster(s)");
        }

        // Background liveness sweeper. Marks silent skills/tools/templates/
        // tasks/sessions/services as Inactive and purges terminal rows past
        // the configured TTL. Also auto-Terminates agents stuck in Suspended
        // past `agent_purge_after_secs`. Only runs when storage is wired —
        // in-memory mode (tests) skips the sweeper entirely so they don't race.
        if let Some(ref storage) = self.storage {
            let lifecycle = self
                .agent_runtime
                .as_ref()
                .map(|ar| ar.lifecycle_manager());
            let sweeper = crate::liveness::spawn_liveness_sweeper(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                crate::liveness::LivenessConfig::default(),
                lifecycle,
            );
            self.liveness_sweeper = Some(sweeper);
            info!("Liveness sweeper spawned (5min cadence)");
        }

        // Auto-register TenzroClaw agents on every startup so they survive restarts.
        // Registration is idempotent: AgentRuntime hydrates `RegisteredAgent` records
        // from CF_AGENTS on boot, so on every restart after the first these calls
        // return `AgentAlreadyExists`. Treat that variant as a no-op (debug log).
        {
            use tenzro_agent::AgentError;
            use tenzro_types::agent::Capability;
            let system_addr = Address::zero();
            let tenzroclaw_caps = vec![
                Capability::NaturalLanguageProcessing { languages: vec!["en".to_string()] },
                Capability::CodeGeneration { languages: vec!["rust".to_string(), "python".to_string(), "typescript".to_string()] },
                Capability::BlockchainInteraction { chains: vec!["tenzro".to_string(), "ethereum".to_string()] },
                Capability::MultiAgentCoordination,
            ];
            if let Some(ref ar) = self.agent_runtime {
                let ar1 = ar.clone();
                let caps1 = tenzroclaw_caps.clone();
                let addr1 = system_addr;
                tokio::spawn(async move {
                    match ar1.register_agent("TenzroClaw-1".to_string(), addr1, caps1, false, 1).await {
                        Ok(a) => info!("Auto-registered TenzroClaw-1: agent_id={}", a.identity.agent_id),
                        Err(AgentError::AgentAlreadyExists(id)) => {
                            debug!("TenzroClaw-1 already registered (hydrated from storage): agent_id={}", id);
                        }
                        Err(e) => warn!("Failed to auto-register TenzroClaw-1: {}", e),
                    }
                });
                let ar2 = ar.clone();
                let addr2 = system_addr;
                tokio::spawn(async move {
                    match ar2.register_agent("TenzroClaw-2".to_string(), addr2, tenzroclaw_caps, false, 2).await {
                        Ok(a) => info!("Auto-registered TenzroClaw-2: agent_id={}", a.identity.agent_id),
                        Err(AgentError::AgentAlreadyExists(id)) => {
                            debug!("TenzroClaw-2 already registered (hydrated from storage): agent_id={}", id);
                        }
                        Err(e) => warn!("Failed to auto-register TenzroClaw-2: {}", e),
                    }
                });
            }
        }

        // ═══════════════════════════════════════════════════════════════════════
        // AUTO-REGISTER BUILT-IN SKILLS, TOOLS, AND AGENT TEMPLATES
        // Uses deterministic name-based keys for idempotent writes (no duplicates on restart)
        // ═══════════════════════════════════════════════════════════════════════
        if let Some(ref storage) = self.storage {
            use tenzro_types::skill::SkillDefinition;
            use tenzro_types::tool::ToolDefinition;
            use tenzro_types::agent_template::{AgentTemplate, AgentTemplateType};

            // --- Built-in Skills ---
            let builtin_skills: Vec<SkillDefinition> = vec![
                {
                    let mut s = SkillDefinition::new(
                        "web-search".to_string(), "1.0.0".to_string(),
                        tenzro_types::SYSTEM_CREATOR_DID.to_string(),
                        "Search the web and return relevant results".to_string(), 0,
                    );
                    s.tags = vec!["search".to_string(), "web".to_string(), "retrieval".to_string()];
                    s.endpoint = Some("builtin://web-search".to_string());
                    s
                },
                {
                    let mut s = SkillDefinition::new(
                        "code-review".to_string(), "1.0.0".to_string(),
                        tenzro_types::SYSTEM_CREATOR_DID.to_string(),
                        "Review code and suggest improvements".to_string(), 0,
                    );
                    s.tags = vec!["code".to_string(), "review".to_string(), "quality".to_string()];
                    s.endpoint = Some("builtin://code-review".to_string());
                    s
                },
                {
                    let mut s = SkillDefinition::new(
                        "data-analysis".to_string(), "1.0.0".to_string(),
                        tenzro_types::SYSTEM_CREATOR_DID.to_string(),
                        "Analyze datasets and generate insights".to_string(), 0,
                    );
                    s.tags = vec!["data".to_string(), "analysis".to_string(), "insights".to_string()];
                    s.endpoint = Some("builtin://data-analysis".to_string());
                    s
                },
                {
                    let mut s = SkillDefinition::new(
                        "text-summarization".to_string(), "1.0.0".to_string(),
                        tenzro_types::SYSTEM_CREATOR_DID.to_string(),
                        "Summarize long documents into concise summaries".to_string(), 0,
                    );
                    s.tags = vec!["text".to_string(), "summarization".to_string(), "nlp".to_string()];
                    s.endpoint = Some("builtin://text-summarization".to_string());
                    s
                },
                {
                    let mut s = SkillDefinition::new(
                        "blockchain-query".to_string(), "1.0.0".to_string(),
                        tenzro_types::SYSTEM_CREATOR_DID.to_string(),
                        "Query blockchain state, balances, and transactions".to_string(), 0,
                    );
                    s.tags = vec!["blockchain".to_string(), "query".to_string(), "ledger".to_string()];
                    s.endpoint = Some("builtin://blockchain-query".to_string());
                    s
                },
                {
                    let mut s = SkillDefinition::new(
                        "solana-defi".to_string(), "1.0.0".to_string(),
                        tenzro_types::SYSTEM_CREATOR_DID.to_string(),
                        "Solana DeFi operations: Jupiter swaps, SPL tokens, Metaplex NFTs, SNS domains, staking and yield".to_string(), 0,
                    );
                    s.tags = vec![
                        "solana-defi".to_string(), "solana".to_string(), "defi".to_string(),
                        "jupiter".to_string(), "swap".to_string(),
                    ];
                    s.endpoint = Some("https://solana-mcp.tenzro.xyz/mcp".to_string());
                    s
                },
                {
                    let mut s = SkillDefinition::new(
                        "ethereum-defi".to_string(), "1.0.0".to_string(),
                        tenzro_types::SYSTEM_CREATOR_DID.to_string(),
                        "Ethereum DeFi operations: balances, ENS resolution, ERC-8004 agent registry, EAS attestations, gas and contract calls".to_string(), 0,
                    );
                    s.tags = vec![
                        "ethereum-defi".to_string(), "ethereum".to_string(), "defi".to_string(),
                        "ens".to_string(), "erc8004".to_string(),
                        "margin-call".to_string(), "liquidation".to_string(),
                    ];
                    s.endpoint = Some("https://ethereum-mcp.tenzro.xyz/mcp".to_string());
                    s
                },
                {
                    let mut s = SkillDefinition::new(
                        "canton-enterprise".to_string(), "1.0.0".to_string(),
                        tenzro_types::SYSTEM_CREATOR_DID.to_string(),
                        "Canton enterprise operations: DAML contracts, CIP-56 tokens, DvP settlement, RWA tokenization, trade finance".to_string(), 0,
                    );
                    s.tags = vec![
                        "canton-enterprise".to_string(), "canton".to_string(), "daml".to_string(),
                        "tokenization".to_string(), "dvp".to_string(), "atomic-swap".to_string(),
                        "trade-finance".to_string(), "letter-of-credit".to_string(),
                        "rwa".to_string(), "nav".to_string(), "treasury".to_string(),
                        "fixed-income".to_string(), "rfq".to_string(),
                    ];
                    s.endpoint = Some("https://canton-mcp.tenzro.xyz/mcp".to_string());
                    s
                },
                {
                    let mut s = SkillDefinition::new(
                        "layerzero-bridge".to_string(), "1.0.0".to_string(),
                        tenzro_types::SYSTEM_CREATOR_DID.to_string(),
                        "LayerZero V2 cross-chain operations: omnichain messaging, OFT transfers, Stargate bridging, DVN queries".to_string(), 0,
                    );
                    s.tags = vec![
                        "layerzero-bridge".to_string(), "layerzero".to_string(),
                        "cross-chain".to_string(), "bridge".to_string(),
                        "oft".to_string(), "messaging".to_string(),
                    ];
                    s.endpoint = Some("https://layerzero-mcp.tenzro.xyz/mcp".to_string());
                    s
                },
                {
                    let mut s = SkillDefinition::new(
                        "chainlink-oracle".to_string(), "1.0.0".to_string(),
                        tenzro_types::SYSTEM_CREATOR_DID.to_string(),
                        "Chainlink operations: CCIP cross-chain messaging, data feeds, data streams, VRF randomness, proof of reserve, automation".to_string(), 0,
                    );
                    s.tags = vec![
                        "chainlink-oracle".to_string(), "chainlink".to_string(), "ccip".to_string(),
                        "oracle".to_string(), "data-feeds".to_string(), "proof-of-reserve".to_string(),
                    ];
                    s.endpoint = Some("https://chainlink-mcp.tenzro.xyz/mcp".to_string());
                    s
                },
                {
                    let mut s = SkillDefinition::new(
                        "debridge-cross-chain".to_string(), "1.0.0".to_string(),
                        tenzro_types::SYSTEM_CREATOR_DID.to_string(),
                        "deBridge DLN intent-based cross-chain swaps and order tracking".to_string(), 0,
                    );
                    s.tags = vec![
                        "debridge-cross-chain".to_string(), "debridge".to_string(),
                        "cross-chain".to_string(), "bridge".to_string(),
                        "dln".to_string(), "intent".to_string(),
                    ];
                    s.endpoint = Some("https://agents.debridge.com/mcp".to_string());
                    s
                },
                {
                    let mut s = SkillDefinition::new(
                        "oneinch-aggregator".to_string(), "1.0.0".to_string(),
                        tenzro_types::SYSTEM_CREATOR_DID.to_string(),
                        "1inch DEX aggregation: best-execution swap routing, Fusion+ cross-chain, portfolio rebalancing".to_string(), 0,
                    );
                    s.tags = vec![
                        "oneinch-aggregator".to_string(), "1inch".to_string(), "dex".to_string(),
                        "aggregator".to_string(), "swap".to_string(), "best-execution".to_string(),
                        "router".to_string(), "rebalance".to_string(),
                    ];
                    s.endpoint = Some("builtin://oneinch-aggregator".to_string());
                    s
                },
                {
                    let mut s = SkillDefinition::new(
                        "openclaw-tenzro".to_string(), "1.0.0".to_string(),
                        tenzro_types::SYSTEM_CREATOR_DID.to_string(),
                        "Full Tenzro Network surface: wallet, identity, payments, inference, staking, marketplace, verification".to_string(), 0,
                    );
                    s.tags = vec![
                        "openclaw-tenzro".to_string(), "tenzro".to_string(), "blockchain".to_string(),
                        "ai".to_string(), "identity".to_string(), "payments".to_string(),
                        "inference".to_string(),
                    ];
                    s.endpoint = Some("https://mcp.tenzro.xyz/mcp".to_string());
                    s
                },
                {
                    let mut s = SkillDefinition::new(
                        "tenzro-trainer".to_string(), "1.0.0".to_string(),
                        tenzro_types::SYSTEM_CREATOR_DID.to_string(),
                        "Tenzro Train reference trainer: decentralized training rounds for timeseries, language, and vision modalities".to_string(), 0,
                    );
                    s.tags = vec![
                        "tenzro-trainer".to_string(), "training".to_string(),
                        "language-training".to_string(), "timeseries-training".to_string(),
                        "vision-training".to_string(),
                    ];
                    s.endpoint = Some("builtin://tenzro-trainer".to_string());
                    s
                },
            ];

            // Drop the builtins whose upstream this operator has not
            // configured, so discovery lists only what the node can serve.
            // Reconciliation below deletes any row a prior configuration
            // left behind.
            let mut builtin_skills = builtin_skills;
            let search_configured = self.config.builtins.search_url.is_some();
            let oneinch_configured = self.config.builtins.oneinch_api_key.is_some();
            builtin_skills.retain(|s| match s.name.as_str() {
                "web-search" => search_configured,
                "oneinch-aggregator" => oneinch_configured,
                _ => true,
            });

            // Derive each id from the name so it is the same on every node
            // and a caller can pin one. `SkillDefinition::new` assigns a
            // random id — right for a provider registering its own skill,
            // wrong for the node's own, which have to be addressable from
            // outside.
            for s in &mut builtin_skills {
                s.skill_id = format!("skill-{}", s.name);
            }

            // Reconcile system-creator rows in CF_SKILLS to exactly the
            // builtin set: refresh matching rows in place (preserving
            // creation time and usage counters), insert missing ones, and
            // delete strays from prior builds. Builtins never heartbeat —
            // boot-time reconciliation owns their lifecycle and the
            // liveness sweeper exempts system-creator rows.
            let existing_system_skills: Vec<(Vec<u8>, SkillDefinition)> = storage
                .get_keys_with_prefix(CF_SKILLS, b"")
                .unwrap_or_default()
                .into_iter()
                .filter_map(|k| {
                    let v = storage.get(CF_SKILLS, &k).ok().flatten()?;
                    let s: SkillDefinition = serde_json::from_slice(&v).ok()?;
                    (s.creator_did == tenzro_types::SYSTEM_CREATOR_DID).then_some((k, s))
                })
                .collect();
            let mut skills_registered = 0usize;
            let mut skill_keys_kept: Vec<Vec<u8>> = Vec::new();
            for skill in &builtin_skills {
                // Match on the key, not the name: the id is derived, so a
                // row an earlier build wrote under a random id carries the
                // same name but a different key and falls to the removal
                // sweep below.
                let key = skill.skill_id.as_bytes().to_vec();
                let mut updated = skill.clone();
                match existing_system_skills
                    .iter()
                    .find(|(k, _)| k.as_slice() == key.as_slice())
                {
                    Some((_, old)) => {
                        updated.created_at = old.created_at;
                        updated.invocation_count = old.invocation_count;
                        updated.rating = old.rating;
                    }
                    None => skills_registered += 1,
                }
                if let Ok(value) = serde_json::to_vec(&updated) {
                    let _ = storage.put(CF_SKILLS, &key, &value);
                }
                skill_keys_kept.push(key);
            }
            let mut skills_removed = 0usize;
            for (key, _) in &existing_system_skills {
                if !skill_keys_kept.contains(key) && storage.delete(CF_SKILLS, key).is_ok() {
                    skills_removed += 1;
                }
            }
            info!(
                refreshed = skill_keys_kept.len(),
                inserted = skills_registered,
                removed = skills_removed,
                "Reconciled built-in skills in CF_SKILLS"
            );

            // --- Built-in Tools (MCP servers and native capabilities) ---
            let builtin_tools: Vec<ToolDefinition> = vec![
                {
                    let mut t = ToolDefinition::new(
                        "tenzro-mcp-server".to_string(), "1.0.0".to_string(),
                        "mcp".to_string(), "https://mcp.tenzro.xyz/mcp".to_string(),
                        "Tenzro Network MCP server with 24 tools for wallet, identity, payments, models, bridge, staking".to_string(),
                        "blockchain".to_string(),
                    );
                    t.capabilities = vec![
                        "wallet".to_string(), "identity".to_string(), "payments".to_string(),
                        "models".to_string(), "bridge".to_string(), "staking".to_string(),
                        "verification".to_string(), "network".to_string(),
                    ];
                    t.creator_did = Some(tenzro_types::SYSTEM_CREATOR_DID.to_string());
                    t
                },
                {
                    let mut t = ToolDefinition::new(
                        "web-search-mcp".to_string(), "1.0.0".to_string(),
                        "mcp".to_string(), "builtin://web-search-mcp".to_string(),
                        "MCP server providing web search capabilities".to_string(),
                        "search".to_string(),
                    );
                    t.capabilities = vec!["web-search".to_string(), "url-fetch".to_string()];
                    t.creator_did = Some(tenzro_types::SYSTEM_CREATOR_DID.to_string());
                    t
                },
                {
                    let mut t = ToolDefinition::new(
                        "code-executor".to_string(), "1.0.0".to_string(),
                        "mcp".to_string(), "builtin://code-executor".to_string(),
                        "Execute a caller-supplied WASI 0.2 component under a fuel and deadline budget".to_string(),
                        "code".to_string(),
                    );
                    t.capabilities = vec![
                        "wasi-component".to_string(),
                        "content-addressed".to_string(),
                        "metered".to_string(),
                    ];
                    t.creator_did = Some(tenzro_types::SYSTEM_CREATOR_DID.to_string());
                    t
                },
                {
                    let mut t = ToolDefinition::new(
                        "file-manager".to_string(), "1.0.0".to_string(),
                        "native".to_string(), "builtin://file-manager".to_string(),
                        "Read, write, and manage files in agent workspaces".to_string(),
                        "storage".to_string(),
                    );
                    t.capabilities = vec!["read".to_string(), "write".to_string(), "list".to_string()];
                    t.creator_did = Some(tenzro_types::SYSTEM_CREATOR_DID.to_string());
                    t
                },
                {
                    let mut t = ToolDefinition::new(
                        "tenzro-a2a-server".to_string(), "1.0.0".to_string(),
                        "api".to_string(), "https://a2a.tenzro.xyz".to_string(),
                        "Agent-to-Agent protocol server for inter-agent communication (Google A2A spec)".to_string(),
                        "communication".to_string(),
                    );
                    t.capabilities = vec!["agent-messaging".to_string(), "task-delegation".to_string(), "sse-streaming".to_string()];
                    t.creator_did = Some(tenzro_types::SYSTEM_CREATOR_DID.to_string());
                    t
                },
                {
                    let mut t = ToolDefinition::new(
                        "canton-submit-mandate".to_string(), "1.0.0".to_string(),
                        "native".to_string(), "builtin://canton-submit-mandate".to_string(),
                        "Submit a DAML command to Canton behind an AP2 mandate pair, returning both the validation and the ledger receipt".to_string(),
                        "settlement".to_string(),
                    );
                    t.capabilities = vec![
                        "daml-command".to_string(),
                        "ap2-mandate".to_string(),
                        "receipt".to_string(),
                    ];
                    t.creator_did = Some(tenzro_types::SYSTEM_CREATOR_DID.to_string());
                    t
                },
                {
                    let mut t = ToolDefinition::new(
                        "identity-register".to_string(), "1.0.0".to_string(),
                        "native".to_string(), "builtin://identity-register".to_string(),
                        "Register a human or machine identity under TDIP and provision its wallet".to_string(),
                        "identity".to_string(),
                    );
                    t.capabilities = vec![
                        "tdip".to_string(),
                        "did-document".to_string(),
                        "wallet-provisioning".to_string(),
                    ];
                    t.creator_did = Some(tenzro_types::SYSTEM_CREATOR_DID.to_string());
                    t
                },
                {
                    let mut t = ToolDefinition::new(
                        "da-publish".to_string(), "1.0.0".to_string(),
                        "native".to_string(), "builtin://da-publish".to_string(),
                        "Publish bytes to the node's content-addressed blob store and return the tenzro:// URI".to_string(),
                        "storage".to_string(),
                    );
                    t.capabilities = vec![
                        "content-addressed".to_string(),
                        "blob-publish".to_string(),
                    ];
                    t.creator_did = Some(tenzro_types::SYSTEM_CREATOR_DID.to_string());
                    t
                },
                {
                    let mut t = ToolDefinition::new(
                        "erc7683-origin".to_string(), "1.0.0".to_string(),
                        "native".to_string(), "builtin://erc7683-origin".to_string(),
                        "Open an ERC-7683 cross-chain order on the origin side and return the order id".to_string(),
                        "crosschain".to_string(),
                    );
                    t.capabilities = vec![
                        "erc7683".to_string(),
                        "intent".to_string(),
                        "order-open".to_string(),
                    ];
                    t.creator_did = Some(tenzro_types::SYSTEM_CREATOR_DID.to_string());
                    t
                },
            ];

            // Same upstream gating as the builtin skills. `code-executor`
            // needs the component sandbox, which is compiled in only with
            // the `wasi-skills` feature.
            let mut builtin_tools = builtin_tools;
            let sandbox_available = cfg!(feature = "wasi-skills");
            let canton_configured = self.config.canton.enabled;
            let blobs_available = self.iroh_resolver.is_some();
            builtin_tools.retain(|t| match t.name.as_str() {
                "web-search-mcp" => search_configured,
                "code-executor" => sandbox_available,
                "canton-submit-mandate" => canton_configured,
                "da-publish" => blobs_available,
                _ => true,
            });

            // Derive each id from the name so the row key is the same on
            // every node and across restarts, which is what lets a
            // workflow template or a doc pin one. `ToolDefinition::new`
            // assigns a random id — correct for a provider registering
            // its own tool, but it leaves the node's own tools
            // unaddressable from outside.
            for t in &mut builtin_tools {
                t.tool_id = format!("tool-{}", t.name);
            }

            // Same reconciliation discipline as the builtin skills above.
            let existing_system_tools: Vec<(Vec<u8>, ToolDefinition)> = storage
                .get_keys_with_prefix(CF_TOOLS, b"")
                .unwrap_or_default()
                .into_iter()
                .filter_map(|k| {
                    let v = storage.get(CF_TOOLS, &k).ok().flatten()?;
                    let t: ToolDefinition = serde_json::from_slice(&v).ok()?;
                    (t.creator_did.as_deref() == Some(tenzro_types::SYSTEM_CREATOR_DID))
                        .then_some((k, t))
                })
                .collect();
            let mut tools_registered = 0usize;
            let mut tool_keys_kept: Vec<Vec<u8>> = Vec::new();
            for tool in &builtin_tools {
                // Match on the key, not the name: the id is derived, so a
                // row written under an earlier random id carries the same
                // name but a different key and falls to the removal sweep.
                let key = tool.tool_id.as_bytes().to_vec();
                let mut updated = tool.clone();
                match existing_system_tools
                    .iter()
                    .find(|(k, _)| k.as_slice() == key.as_slice())
                {
                    Some((_, old)) => {
                        updated.created_at = old.created_at;
                        updated.invocation_count = old.invocation_count;
                    }
                    None => tools_registered += 1,
                }
                if let Ok(value) = serde_json::to_vec(&updated) {
                    let _ = storage.put(CF_TOOLS, &key, &value);
                }
                tool_keys_kept.push(key);
            }
            let mut tools_removed = 0usize;
            for (key, _) in &existing_system_tools {
                if !tool_keys_kept.contains(key) && storage.delete(CF_TOOLS, key).is_ok() {
                    tools_removed += 1;
                }
            }
            info!(
                refreshed = tool_keys_kept.len(),
                inserted = tools_registered,
                removed = tools_removed,
                "Reconciled built-in tools in CF_TOOLS"
            );

            // --- Built-in Agent Templates ---
            let system_addr = Address::zero();
            let builtin_templates: Vec<AgentTemplate> = vec![
                {
                    let mut t = AgentTemplate::new(
                        "Research Agent".to_string(),
                        "Autonomous research agent that searches the web, analyzes sources, and produces comprehensive reports".to_string(),
                        AgentTemplateType::Autonomous,
                        system_addr,
                        "You are a research agent. Search for information, analyze sources, synthesize findings, and produce clear reports.".to_string(),
                    );
                    t.tags = vec!["research".to_string(), "analysis".to_string(), "autonomous".to_string()];
                    t
                },
                {
                    let mut t = AgentTemplate::new(
                        "Code Assistant".to_string(),
                        "Tool-augmented coding agent with code execution, review, and debugging capabilities".to_string(),
                        AgentTemplateType::ToolAgent,
                        system_addr,
                        "You are a coding assistant. Help users write, review, debug, and optimize code across multiple languages.".to_string(),
                    );
                    t.tags = vec!["code".to_string(), "development".to_string(), "debugging".to_string()];
                    t
                },
                {
                    let mut t = AgentTemplate::new(
                        "Trading Agent".to_string(),
                        "Specialist agent for DeFi trading, portfolio management, and market analysis on Tenzro Network".to_string(),
                        AgentTemplateType::Specialist,
                        system_addr,
                        "You are a DeFi trading specialist on Tenzro Network. Analyze markets, execute trades, and manage portfolios using TNZO.".to_string(),
                    );
                    t.tags = vec!["trading".to_string(), "defi".to_string(), "finance".to_string()];
                    t
                },
                {
                    let mut t = AgentTemplate::new(
                        "Orchestrator Agent".to_string(),
                        "Multi-agent orchestrator that decomposes complex tasks and delegates to specialized agents".to_string(),
                        AgentTemplateType::Orchestrator,
                        system_addr,
                        "You are an orchestrator agent. Break down complex tasks, delegate subtasks to specialized agents, and synthesize results.".to_string(),
                    );
                    t.tags = vec!["orchestration".to_string(), "multi-agent".to_string(), "coordination".to_string()];
                    t
                },
                {
                    let mut t = AgentTemplate::new(
                        "Data Analyst".to_string(),
                        "Multimodal data analysis agent that processes text, images, and structured data to generate insights".to_string(),
                        AgentTemplateType::MultiModal,
                        system_addr,
                        "You are a data analyst agent. Process and analyze datasets, create visualizations, and generate actionable insights.".to_string(),
                    );
                    t.tags = vec!["data".to_string(), "analytics".to_string(), "visualization".to_string()];
                    t
                },
            ];

            // Derive each id from the name. `AgentTemplate::new` assigns a
            // random one, which the seed below would then rewrite under a
            // new key on every boot — nothing outside the node could pin
            // it. The reference workflow templates under
            // `templates/workflows/` address these ids directly.
            let mut builtin_templates = builtin_templates;
            for t in &mut builtin_templates {
                let slug = t.name.to_lowercase().replace(' ', "-");
                let slug = slug.strip_suffix("-agent").unwrap_or(&slug);
                t.template_id = format!("agent-template-{slug}");
            }

            // Storage key scheme for CF_AGENT_TEMPLATES is the template id so
            // that list_agent_templates → get_agent_template /
            // spawn_agent_from_template lookups resolve correctly.
            //
            // For each built-in template: check the derived key, and if the
            // row is absent, delete any row matching by (name, creator)
            // under a different key before writing. That sweep is what
            // clears a row an earlier build left under a random id, so two
            // entries for the same template never both appear in
            // discovery.
            let mut templates_registered = 0usize;
            let mut templates_migrated = 0usize;
            let all_keys = storage
                .get_keys_with_prefix(CF_AGENT_TEMPLATES, b"")
                .unwrap_or_default();
            for template in &builtin_templates {
                let key = template.template_id.as_bytes().to_vec();
                let canonical_present = storage
                    .get(CF_AGENT_TEMPLATES, &key)
                    .ok()
                    .flatten()
                    .and_then(|v| serde_json::from_slice::<AgentTemplate>(&v).ok())
                    .map(|t| t.name == template.name && t.creator == template.creator)
                    .unwrap_or(false);
                if canonical_present {
                    continue;
                }
                // Purge any legacy entries at non-canonical keys that match by (name, creator).
                for legacy_key in &all_keys {
                    if legacy_key == &key {
                        continue;
                    }
                    if let Ok(Some(v)) = storage.get(CF_AGENT_TEMPLATES, legacy_key)
                        && let Ok(t) = serde_json::from_slice::<AgentTemplate>(&v)
                            && t.name == template.name && t.creator == template.creator
                                && storage.delete(CF_AGENT_TEMPLATES, legacy_key).is_ok() {
                                    templates_migrated += 1;
                                }
                }
                if let Ok(value) = serde_json::to_vec(template)
                    && storage.put(CF_AGENT_TEMPLATES, &key, &value).is_ok() {
                        templates_registered += 1;
                    }
            }
            if templates_registered > 0 || templates_migrated > 0 {
                info!(
                    "Agent templates seeded: {} new, {} legacy-key entries migrated in CF_AGENT_TEMPLATES",
                    templates_registered, templates_migrated
                );
            }
        }

        // Initialize HuggingFace downloader. Weights are stored under the node's
        // persistent data_dir (data_dir/models by default) so they survive a
        // restart rather than being re-downloaded every boot.
        let models_dir = self.config.effective_models_dir();
        std::fs::create_dir_all(&models_dir).map_err(|e| {
            NodeError::Internal(format!("Failed to create models directory: {}", e))
        })?;
        let hf_downloader = match self.iroh_resolver.as_ref() {
            Some(resolver) => {
                let fetcher = crate::model_blob_fetcher_bridge::IrohBlobFetcher::arc(
                    Arc::clone(resolver),
                );
                info!("HuggingFace downloader wired with iroh peer-first blob fetcher");
                Arc::new(HfDownloader::new(models_dir).with_blob_fetcher(fetcher))
            }
            None => {
                info!("HuggingFace downloader initialized (no iroh resolver — HF CDN only)");
                Arc::new(HfDownloader::new(models_dir))
            }
        };
        self.hf_downloader = Some(hf_downloader);

        // Initialize model runtime (candle GGUF inference)
        let model_runtime = Arc::new(ModelRuntime::new());
        self.model_runtime = Some(model_runtime);
        info!("Model runtime initialized");

        // ═══════════════════════════════════════════════════════════════════════
        // STARTUP RESTORATION: Restore served_models from RocksDB CF_MODELS
        // The existing gossipsub heartbeat will re-announce restored models to peers.
        // ═══════════════════════════════════════════════════════════════════════
        if let Some(ref storage) = self.storage {
            match storage.get_keys_with_prefix(CF_MODELS, b"served:") {
                Ok(keys) => {
                    let mut restored = 0usize;
                    for key_bytes in &keys {
                        if let Ok(key_str) = std::str::from_utf8(key_bytes) {
                            let Some(model_id) = key_str.strip_prefix("served:") else {
                                continue;
                            };
                            let visibility = storage
                                .get(CF_MODELS, key_bytes)
                                .ok()
                                .flatten()
                                .and_then(|data| serde_json::from_slice::<serde_json::Value>(&data).ok())
                                .and_then(|record| {
                                    record
                                        .get("visibility")
                                        .and_then(|v| v.as_str())
                                        .and_then(ModelVisibility::parse)
                                })
                                .unwrap_or_default();
                            self.served_models.insert(model_id.to_string(), visibility);
                            restored += 1;
                        }
                    }
                    if restored > 0 {
                        info!("Restored {} served model(s) from RocksDB CF_MODELS on startup", restored);
                    }
                }
                Err(e) => {
                    warn!("Failed to restore served models from CF_MODELS on startup: {}", e);
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════════════
        // STARTUP RESTORATION: Restore model_services from RocksDB CF_MODEL_SERVICES
        // ═══════════════════════════════════════════════════════════════════════
        if let Some(ref storage) = self.storage {
            match storage.get_keys_with_prefix(CF_MODEL_SERVICES, b"") {
                Ok(keys) => {
                    let mut restored = 0usize;
                    for key_bytes in &keys {
                        if let Ok(instance_id) = std::str::from_utf8(key_bytes)
                            && let Ok(Some(data)) = storage.get(CF_MODEL_SERVICES, key_bytes)
                                && let Ok(instance) = serde_json::from_slice::<tenzro_types::model::ModelServiceInstance>(&data) {
                                    self.model_services.insert(instance_id.to_string(), instance);
                                    restored += 1;
                                }
                    }
                    if restored > 0 {
                        info!("Restored {} model service(s) from RocksDB CF_MODEL_SERVICES on startup", restored);
                    }

                    // Also restore network-discovered model endpoints (from gossipsub, persisted)
                    let mut net_restored = 0usize;
                    for key_bytes in &keys {
                        if let Ok(key_str) = std::str::from_utf8(key_bytes)
                            && key_str.starts_with("net_model:")
                                && let Ok(Some(data)) = storage.get(CF_MODEL_SERVICES, key_bytes)
                                    && let Ok(reg) = serde_json::from_slice::<tenzro_network::ModelRegistrationMessage>(&data) {
                                        // Only restore non-withdrawn, non-expired entries
                                        if !reg.withdrawn {
                                            let model_key = key_str.trim_start_matches("net_model:").to_string();
                                            self.network_models.insert(model_key, NetworkModelEntry {
                                                registration: reg,
                                                last_seen: std::time::Instant::now(), // reset TTL
                                            });
                                            net_restored += 1;
                                        }
                                    }
                    }
                    if net_restored > 0 {
                        info!("Restored {} network model endpoint(s) from RocksDB on startup", net_restored);
                    }
                }
                Err(e) => {
                    warn!("Failed to restore model services from CF_MODEL_SERVICES on startup: {}", e);
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════════════
        // STARTUP RECONCILE: auto-reload served models from disk, evict stale
        // entries whose GGUF file is gone or that no longer match the catalog.
        // This fixes the "model listed as serving but runtime says not loaded"
        // gap that occurred after restarts, because CF_MODELS/CF_MODEL_SERVICES
        // survive process death but the in-memory ModelRuntime starts empty.
        // ═══════════════════════════════════════════════════════════════════════
        let (reloaded, cleared_models, cleared_services) =
            self.reconcile_model_registry().await;
        if reloaded > 0 || cleared_models > 0 || cleared_services > 0 {
            info!(
                "Startup reconcile: auto-reloaded {} model(s), cleared {} served flag(s), pruned {} endpoint(s)",
                reloaded, cleared_models, cleared_services,
            );
        }

        // ═══════════════════════════════════════════════════════════════════════
        // STARTUP: AgentRuntime::with_storage() and SwarmManager::with_storage()
        // already performed full hydration from CF_AGENTS above (agents,
        // lifecycles, spawn tree, swarms). Report the final counts so
        // operators can confirm rehydration succeeded.
        // ═══════════════════════════════════════════════════════════════════════
        if let Some(ref ar) = self.agent_runtime {
            let restored = ar.list_agents(None).len();
            if restored > 0 {
                info!(
                    "AgentRuntime restored {} agent(s) from CF_AGENTS on startup",
                    restored
                );
            }
        }
        if let Some(ref sm) = self.swarm_manager {
            let restored = sm.swarm_count();
            if restored > 0 {
                info!(
                    "SwarmManager restored {} swarm(s) from CF_AGENTS on startup",
                    restored
                );
            }
        }

        // ═══════════════════════════════════════════════════════════════════════
        // SLA fault detector (Phase B Thread 5). Validators only — slashing
        // authority requires consensus participation. Re-loads the persisted
        // Ed25519 seed from `{data_dir}/validator_key` (the same bytes that
        // back the validator's HotStuff-2 signing key — RFC 9381 ECVRF over
        // Curve25519 is byte-compatible with Ed25519 keys, so the same 32-byte
        // seed serves both consensus signing and VRF probe stamping). The
        // bridge translates the async `ProviderSlashingCallback` trait to the
        // synchronous `ComputeBondManager` API and stamps audit-trail events
        // with the latest finalized height pulled from the consensus engine.
        // ═══════════════════════════════════════════════════════════════════════
        if self.config.roles.is_validator()
            && let (Some(consensus), Some(bonds)) =
                (self.consensus.clone(), self.compute_bond_manager.clone())
        {
            let keypair = crate::keygen::load_validator_keypair(&self.config.data_dir)?;
            let seed_bytes = keypair.secret_key().as_bytes();
            if seed_bytes.len() != 32 {
                return Err(NodeError::Other(format!(
                    "Validator Ed25519 seed has unexpected length {} (want 32)",
                    seed_bytes.len()
                )));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(seed_bytes);
            let vrf_secret = tenzro_crypto::vrf::VrfSecretKey(seed);
            let issuer = keypair.address();

            let height_fn: crate::sla_slashing_bridge::BlockHeightFn = {
                let consensus = consensus.clone();
                Arc::new(move || consensus.current_finalized_height().0)
            };
            let bridge = Arc::new(
                crate::sla_slashing_bridge::ComputeBondSlashingBridge::new(bonds, height_fn),
            );
            let sla_manager = Arc::new(
                tenzro_model::SlaManager::new(issuer, vrf_secret, bridge),
            );
            self.sla_manager = Some(sla_manager.clone());

            // Subscribe to `tenzro/sla` so provider responses flow into
            // `apply_response`. Custom-topic transport with bincode payload
            // mirrors the agent-messaging pattern (no MessagePayload variant
            // explosion, no cross-crate type leak of tenzro-model into
            // tenzro-network). Outstanding probes are correlated by their
            // 32-byte challenge_nonce (hex-encoded for DashMap key).
            if let Some(network) = self.network.clone() {
                let outstanding = self.sla_outstanding_probes.clone();
                let mgr = sla_manager.clone();
                tokio::spawn(async move {
                    match network.subscribe("tenzro/sla").await {
                        Ok(mut rx) => {
                            info!("SLA: subscribed to tenzro/sla");
                            while let Some(msg) = rx.recv().await {
                                let data = match msg.payload {
                                    tenzro_network::MessagePayload::Custom { data, .. } => data,
                                    _ => continue,
                                };
                                let response: tenzro_model::SlaResponse =
                                    match bincode::deserialize(&data) {
                                        Ok(r) => r,
                                        Err(e) => {
                                            tracing::debug!(
                                                error = %e,
                                                "Ignoring non-SlaResponse payload on tenzro/sla"
                                            );
                                            continue;
                                        }
                                    };
                                let nonce_hex = hex::encode(response.challenge_nonce);
                                let probe = match outstanding.remove(&nonce_hex) {
                                    Some((_, p)) => p,
                                    None => {
                                        tracing::debug!(
                                            provider = %response.provider_did,
                                            nonce = %nonce_hex,
                                            "SLA response references unknown probe — likely \
                                             issued by a different validator; dropping"
                                        );
                                        continue;
                                    }
                                };
                                let received_at_ms = chrono::Utc::now().timestamp_millis();
                                match mgr
                                    .apply_response(&probe, Some(&response), received_at_ms)
                                    .await
                                {
                                    Ok(result) => {
                                        tracing::info!(
                                            provider = %probe.provider_did,
                                            epoch = probe.epoch,
                                            round = probe.round,
                                            result = result.as_reason(),
                                            "Applied SLA probe response"
                                        );
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            provider = %probe.provider_did,
                                            error = %e,
                                            "SLA apply_response failed"
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to subscribe to tenzro/sla gossipsub topic: {}",
                                e
                            );
                        }
                    }
                });
            }
            info!(
                "SLA fault detector wired: VRF-stamped probes → ComputeBond slashing"
            );
        }

        // Tenzro Train protocol runtime — write-through to CF_TRAINING_RUNS /
        // CF_TRAINING_RECEIPTS and rehydrate active syncer state on boot.
        // Terminal runs (completed/failed) are skipped during hydration; only
        // in-flight runs are restored so trainers can re-enroll and resume.
        //
        // When the iroh resolver is bound, the runtime is constructed with
        // `IrohGradientStore` as its `GradientPayloadStore` so outer-gradient
        // bulk transfer flows through iroh-blobs (the gossiped envelope on
        // `tenzro/training` carries only the SHA-256 hash; the safetensors
        // bytes ride iroh-blobs via the shared resolver — see Phase B1, #216).
        if let Some(ref storage) = self.storage {
            let mut training_runtime = tenzro_training::TrainingRuntime::with_storage(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            );
            // Slash-and-evict bridge: a contribution that fails accept-time
            // verification, or a buffered gradient outside the round's
            // norm/agreement band, evicts the trainer from the run and slashes
            // its compute bond (terminal, no rehabilitation). Requires both a
            // consensus engine (finalized-height source for the audit event)
            // and a compute-bond manager; on nodes without either, eviction
            // still removes the DID from the active set but debits no bond.
            if let (Some(consensus), Some(bonds)) =
                (self.consensus.clone(), self.compute_bond_manager.clone())
            {
                let height_fn: crate::train_slashing_bridge::BlockHeightFn = {
                    let consensus = consensus.clone();
                    Arc::new(move || consensus.current_finalized_height().0)
                };
                let bridge = Arc::new(
                    crate::train_slashing_bridge::TrainerComputeBondSlashingBridge::new(
                        bonds, height_fn,
                    ),
                );
                training_runtime = training_runtime.with_slashing_callback(bridge);
                info!("TrainingRuntime wired with slash-and-evict ComputeBond bridge");
            }
            if let Some(ref resolver) = self.iroh_resolver {
                training_runtime = training_runtime.with_payload_store(
                    tenzro_iroh::IrohGradientStore::arc(resolver.clone()),
                );
                info!(
                    "TrainingRuntime wired with iroh-blobs GradientPayloadStore (Phase B1)"
                );
                training_runtime = training_runtime.with_sealed_shard_store(
                    tenzro_iroh::IrohSealedShardStore::arc(resolver.clone()),
                );
                info!(
                    "TrainingRuntime wired with iroh-blobs SealedShardStore (Phase B2)"
                );
            }
            let training_runtime = Arc::new(training_runtime);
            match training_runtime.hydrate() {
                Ok(restored) => {
                    info!(
                        restored,
                        "Tenzro Train runtime initialized (CF_TRAINING_RUNS hydrated)"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "TrainingRuntime hydration failed ({}); continuing with empty syncer set",
                        e
                    );
                }
            }
            self.training_runtime = training_runtime;

            // Trainer auto-provisioning daemon (Task #41). Polls the hydrated
            // runtime for runs in Enrolling / Training status and supervises
            // one Python reference-trainer subprocess per active run, up to
            // `[training].max_concurrent_trainers`. Dead trainers are reaped
            // and respawned on the next poll with exponential backoff. The
            // trainer's Ed25519 identity is HKDF-derived from the node's TDIP
            // seed (domain-separated) so reward attribution is stable across
            // restarts without provisioning a second on-disk secret.
            if self.config.training.enabled {
                let rpc_url = format!(
                    "http://{}",
                    self.config
                        .rpc_addr
                        .replacen("0.0.0.0", "127.0.0.1", 1)
                );
                let (seed, address_hex) =
                    match crate::keygen::load_validator_keypair(&self.config.data_dir) {
                        Ok(keypair) => {
                            let seed_bytes = keypair.secret_key().as_bytes();
                            let seed = if seed_bytes.len() == 32 {
                                let mut s = [0u8; 32];
                                s.copy_from_slice(seed_bytes);
                                Some(s)
                            } else {
                                None
                            };
                            (seed, keypair.address().to_hex())
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Could not load validator keypair for trainer identity ({}); \
                                 trainer will run with an ephemeral key",
                                e
                            );
                            (None, "ephemeral".to_string())
                        }
                    };

                if let Some(daemon) = crate::trainer_daemon::TrainerDaemon::new(
                    self.config.training.clone(),
                    self.training_runtime.clone(),
                    rpc_url,
                    &self.config.data_dir,
                    seed,
                    address_hex,
                ) {
                    // Leader-gate provisioning so only one validator in the
                    // fleet supervises trainers per run; convergence on the
                    // finalized round-state happens over `tenzro/training`.
                    // A node that does not vote is never the leader, so it
                    // takes no gate — it supervises the trainers it enrolled
                    // and nobody else's.
                    let daemon = match (
                        self.config.roles.is_validator(),
                        self.consensus.clone(),
                    ) {
                        (true, Some(consensus)) => {
                            let gate: crate::trainer_daemon::TickAuthorityFn =
                                Arc::new(move || consensus.is_leader_in_next_views(32));
                            daemon.with_tick_authority(gate)
                        }
                        _ => daemon,
                    };
                    let daemon_arc = Arc::new(daemon);
                    daemon_arc.clone().spawn();
                    self.trainer_daemon = Some(daemon_arc);
                    info!("Trainer auto-provisioning daemon spawned");
                }
            }

            // Generative-media runtime — write-through to CF_MEDIA_GEN_RUNS /
            // CF_MEDIA_GEN_WORKERS / CF_MEDIA_GEN_RECEIPTS, rehydrating the
            // in-flight queue and the enrolled worker set on boot. Terminal
            // jobs stay on disk for audit but are not re-queued.
            //
            // When the iroh resolver is bound, rendered output rides iroh-blobs
            // via `IrohMediaGenOutputStore`; the gossiped receipt carries only
            // the SHA-256 hash, and the adapter re-verifies that hash at the
            // protocol boundary because iroh-blobs indexes by BLAKE3.
            let mut media_gen_runtime = tenzro_media_gen::MediaGenRuntime::with_storage(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
            );
            if let Some(ref resolver) = self.iroh_resolver {
                let store = Arc::new(tenzro_iroh::IrohMediaGenOutputStore::new(resolver.clone()));
                media_gen_runtime = media_gen_runtime.with_output_store(
                    store.clone() as Arc<dyn tenzro_media_gen::MediaGenOutputStore>,
                );
                self.media_gen_output_store = Some(store);
                info!("MediaGenRuntime wired with iroh-blobs MediaGenOutputStore");
            }
            let media_gen_runtime = Arc::new(media_gen_runtime);
            match media_gen_runtime.hydrate() {
                Ok((jobs, workers)) => {
                    info!(jobs, workers, "Media-gen runtime initialized");
                }
                Err(e) => {
                    tracing::warn!(
                        "MediaGenRuntime hydration failed ({}); continuing with an empty queue",
                        e
                    );
                }
            }
            self.media_gen_runtime = media_gen_runtime;
        }

        self.health_monitor.mark_healthy("ai");

        Ok(())
    }

    /// Auto-register Cortex (recurrent-depth) workers declared in `NodeConfig.cortex.workers`.
    ///
    /// Each entry builds an HTTP `SidecarModel` + `CortexWorker` and inserts it into
    /// `self.cortex_workers` so `tenzro_cortexInference` / the `cortex_reason` MCP tool
    /// can route requests to it without an explicit RPC registration step.
    ///
    /// Best-effort: workers whose construction fails are logged and skipped so a
    /// mis-configured sidecar cannot block the rest of node startup.
    async fn init_cortex_workers(&mut self) {
        use tenzro_cortex::{CortexWorker, PersistentCortexSigner, SidecarConfig, SidecarModel};
        use tenzro_crypto::signatures::Signer;
        use tenzro_types::cortex::{CortexModelFamily, CortexPricing, ReasoningTier};

        if !self.config.cortex.enabled {
            return;
        }
        if self.config.cortex.workers.is_empty() {
            info!("Cortex subsystem enabled but no workers configured");
            return;
        }

        info!(
            count = self.config.cortex.workers.len(),
            "Auto-registering configured Cortex workers"
        );

        for wc in &self.config.cortex.workers {
            let model_id = wc.model_id.clone();
            let family = CortexModelFamily {
                arch: wc.arch.clone(),
                max_loops: wc.max_loops,
                moe_experts: wc.moe_experts,
                experts_per_token: wc.experts_per_token,
                attn_type: wc.attn_type.clone(),
                supported_tiers: vec![
                    ReasoningTier::Fast,
                    ReasoningTier::Standard,
                    ReasoningTier::Deep,
                    ReasoningTier::Institutional,
                ],
            };

            let pricing: CortexPricing = wc
                .pricing
                .clone()
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default();

            let worker_did = wc
                .worker_did
                .clone()
                .unwrap_or_else(|| format!("did:tenzro:machine:cortex-{}", model_id));

            // Per-worker persistent Ed25519 signer. Keys are stored at
            // <data_dir>/cortex/<sanitized-model-id>.key with mode 0o600
            // on Unix, so `worker_did` remains stable across node restarts.
            let sanitized = model_id.replace(['/', ':'], "_");
            let key_path = self
                .config
                .data_dir
                .join("cortex")
                .join(format!("{}.key", sanitized));
            let signer: Arc<dyn Signer + Send + Sync> =
                match PersistentCortexSigner::load_or_generate(&key_path) {
                    Ok(s) => s.into_arc(),
                    Err(e) => {
                        warn!(
                            model_id = %model_id,
                            key_path = %key_path.display(),
                            "Skipping Cortex worker: failed to load/generate persistent signer: {e}"
                        );
                        continue;
                    }
                };
            let worker_address = Address::default();

            let cfg = SidecarConfig {
                base_url: wc.sidecar_url.clone(),
                timeout: std::time::Duration::from_secs(wc.timeout_secs),
                bearer_token: wc.bearer_token.clone(),
            };

            // Clone family + pricing so we can hand copies to the backend/worker
            // as well as to the advertisement broadcaster below.
            let family_for_backend = family.clone();
            let pricing_for_worker = pricing;

            let backend = match SidecarModel::new(
                model_id.clone(),
                family_for_backend,
                worker_did.clone(),
                worker_address,
                signer.clone(),
                cfg,
            ) {
                Ok(b) => Arc::new(b),
                Err(e) => {
                    warn!(
                        model_id = %model_id,
                        "Skipping Cortex worker: sidecar init failed: {e}"
                    );
                    continue;
                }
            };

            let worker = Arc::new(
                CortexWorker::new(
                    backend,
                    pricing_for_worker,
                    signer.clone(),
                    worker_did.clone(),
                    worker_address,
                )
                .with_metrics(self.cortex_metrics.clone()),
            );

            self.cortex_workers.insert(model_id.clone(), worker.clone());

            // Also advertise this worker in the shared ModelRegistry so
            // `tenzro_listModels` / discovery surfaces Cortex models alongside
            // llama.cpp-served models. Best-effort: a registry error is
            // logged but does not block startup.
            if let Some(ref registry) = self.model_registry {
                let info = cortex_model_info(&model_id, &worker, &wc.arch);
                let result = match registry.register_model(info.clone()) {
                    Err(tenzro_model::ModelError::ModelAlreadyExists(_)) => {
                        // Hydrated from a previous process lifetime — refresh.
                        registry.update_model(info)
                    }
                    other => other,
                };
                if let Err(e) = result {
                    warn!(
                        model_id = %model_id,
                        "Failed to publish Cortex model in ModelRegistry: {e}"
                    );
                }
            }

            // Spawn a periodic advertisement broadcaster so peers can discover
            // this cortex worker over the `tenzro/cortex` gossipsub
            // topic. Requires libp2p `NetworkService` to be live — if the node
            // is running in single-process mode (e.g. an in-process test
            // harness with `network = None`) we skip the spawn and the worker
            // is only reachable via local RPC.
            if let Some(ref net) = self.network {
                use crate::cortex_gossip::NetworkCortexPublisher;
                let publisher_net: Arc<dyn tenzro_network::NetworkService> = net.clone();
                let publisher: Arc<dyn tenzro_cortex::CortexGossipPublisher> =
                    Arc::new(NetworkCortexPublisher::new(publisher_net));

                // Advertisement TTL/interval defaults — the cortex config
                // currently has no explicit fields for these, so pick
                // conservative values: re-advertise every 60s with a 120s TTL
                // so peers drop stale workers ~1 minute after a node
                // disappears.
                let ttl_secs: u64 = 120;
                let interval = std::time::Duration::from_secs(60);

                let broadcaster = tenzro_cortex::AdvertisementBroadcaster {
                    publisher,
                    signer: signer.clone(),
                    worker_did: worker_did.clone(),
                    worker_address,
                    model_id: model_id.clone(),
                    family: family.clone(),
                    pricing,
                    endpoint: Some(wc.sidecar_url.clone()),
                    ttl_secs,
                };

                let adv_model_id = model_id.clone();
                let adv_worker_did = worker_did.clone();
                tokio::spawn(async move {
                    // Brief startup delay so the gossipsub mesh has time to
                    // form before the first publish attempt.
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    loop {
                        match broadcaster.broadcast_once().await {
                            Ok(()) => {
                                debug!(
                                    model_id = %adv_model_id,
                                    worker_did = %adv_worker_did,
                                    "Published cortex advertisement to gossipsub"
                                );
                            }
                            Err(e) => {
                                warn!(
                                    model_id = %adv_model_id,
                                    worker_did = %adv_worker_did,
                                    error = %e,
                                    "Cortex advertisement broadcast failed"
                                );
                            }
                        }
                        tokio::time::sleep(interval).await;
                    }
                });

                info!(
                    model_id = %model_id,
                    worker_did = %worker_did,
                    ttl_secs = ttl_secs,
                    interval_secs = interval.as_secs(),
                    "Spawned cortex advertisement broadcaster"
                );
            } else {
                debug!(
                    model_id = %model_id,
                    "Skipping cortex advertisement broadcaster (no NetworkService)"
                );
            }

            info!(
                model_id = %model_id,
                worker_did = %worker_did,
                sidecar = %wc.sidecar_url,
                "Cortex worker auto-registered from config"
            );
        }
    }

    /// Builds an `EvmTransactionSigner` from a [`BridgeAdapterConfig`],
    /// dispatching in priority order:
    ///   1. `mpc_threshold` → DKLS23 t-of-n threshold ECDSA
    ///   2. `tee_sealed`    → TEE-derived single-key
    ///   3. raw / env       → in-memory secp256k1 key (dev only)
    ///
    /// Returns `None` when none of the above produce a working signer —
    /// the adapter then runs in quote-only mode.
    ///
    /// Errors and missing-key conditions are logged at the call site so
    /// that adapter init can keep going (e.g., LayerZero stays quote-only
    /// while CCIP gets a working signer).
    async fn build_bridge_signer(
        &self,
        adapter_name: &str,
        cfg: &crate::config::BridgeAdapterConfig,
    ) -> Option<EvmTransactionSigner> {
        if let Some(mpc_cfg) = cfg.mpc_threshold.as_ref() {
            return self
                .build_threshold_bridge_signer(adapter_name, cfg, mpc_cfg)
                .await;
        }
        if cfg.tee_sealed {
            let label = cfg.tee_label_bytes();
            match EvmTransactionSigner::with_tee_sealed(
                &label,
                cfg.chain_id,
                cfg.rpc_url.clone(),
            )
            .await
            {
                Ok(signer) => {
                    info!(
                        "{} signer configured (TEE-sealed): chain_id={}, sender={}, label={:?}",
                        adapter_name,
                        cfg.chain_id,
                        signer.sender_address(),
                        String::from_utf8_lossy(&label)
                    );
                    Some(signer)
                }
                Err(e) => {
                    warn!(
                        "{} TEE-sealed signer build failed: {} — adapter will be quote-only \
                         (no raw-key fallback when tee_sealed=true)",
                        adapter_name, e
                    );
                    None
                }
            }
        } else {
            match cfg.resolve_private_key() {
                Ok(Some(pk_hex)) => {
                    let signer_cfg =
                        EvmSignerConfig::custom(pk_hex, cfg.chain_id, cfg.rpc_url.clone());
                    match signer_cfg.build() {
                        Ok(signer) => {
                            info!(
                                "{} signer configured (raw key): chain_id={}, sender={}",
                                adapter_name,
                                cfg.chain_id,
                                signer.sender_address()
                            );
                            Some(signer)
                        }
                        Err(e) => {
                            warn!(
                                "{} raw-key signer build failed: {} — adapter will be quote-only",
                                adapter_name, e
                            );
                            None
                        }
                    }
                }
                Ok(None) => {
                    info!("{} adapter registered without signer (quote-only)", adapter_name);
                    None
                }
                Err(e) => {
                    warn!("{} signer config error: {}", adapter_name, e);
                    None
                }
            }
        }
    }

    /// Build an `EvmTransactionSigner` backed by a node-layer
    /// `NodeThresholdSigner` (DKLS23 t-of-n threshold ECDSA).
    ///
    /// Wires together — for this single adapter — the four dependencies the
    /// bridge crate intentionally does NOT depend on directly:
    /// `NodeKeyshareStore` (RocksDB), `TeeKeyshareSealer` (TEE-rooted in
    /// production, fails closed off-hardware), `NetworkMpcSurface` (libp2p
    /// `/tenzro/mpc/v1` request_response), and `BlockStoreEntropyProvider`
    /// (HotStuff-2 finalized block hash for grinding-resistant committee
    /// draw).
    ///
    /// Returns `None` on any wiring failure — the adapter then runs in
    /// quote-only mode. Per `feedback_no_simulation_in_testnet`, the
    /// sealer construction errors loudly (no fallback to an in-memory
    /// keyshare sealer in production).
    async fn build_threshold_bridge_signer(
        &self,
        adapter_name: &str,
        cfg: &crate::config::BridgeAdapterConfig,
        mpc_cfg: &crate::config::MpcThresholdConfig,
    ) -> Option<EvmTransactionSigner> {
        use tenzro_bridge::mpc::sealing::TeeKeyshareSealer;
        use tenzro_bridge::mpc::setup::{MpcCurve, MpcParameters};
        use tenzro_bridge::mpc::store::GroupId;

        // -------- Prerequisite: storage + network must be initialized -----
        let storage = match self.storage.as_ref() {
            Some(s) => s.clone(),
            None => {
                warn!(
                    "{} threshold signer requires storage to be initialized — adapter will be \
                     quote-only",
                    adapter_name
                );
                return None;
            }
        };
        let network = match self.network.as_ref() {
            Some(n) => n.clone(),
            None => {
                warn!(
                    "{} threshold signer requires network to be initialized — adapter will be \
                     quote-only",
                    adapter_name
                );
                return None;
            }
        };

        // -------- Parse hex-encoded group identifier ----------------------
        let group_id_bytes = match hex::decode(&mpc_cfg.group_id_hex) {
            Ok(b) if b.len() == 32 => b,
            Ok(b) => {
                warn!(
                    "{} threshold signer: group_id_hex decoded to {} bytes, expected 32 — \
                     adapter will be quote-only",
                    adapter_name,
                    b.len()
                );
                return None;
            }
            Err(e) => {
                warn!(
                    "{} threshold signer: group_id_hex decode failed: {} — adapter will be \
                     quote-only",
                    adapter_name, e
                );
                return None;
            }
        };
        let mut group_id_arr = [0u8; 32];
        group_id_arr.copy_from_slice(&group_id_bytes);
        let group_id = GroupId(group_id_arr);

        // -------- Parse hex-encoded group public key ----------------------
        let group_public_key_compressed =
            match hex::decode(&mpc_cfg.group_public_key_hex) {
                Ok(b) if b.len() == 33 => b,
                Ok(b) => {
                    warn!(
                        "{} threshold signer: group_public_key_hex decoded to {} bytes, \
                         expected 33 (SEC1-compressed) — adapter will be quote-only",
                        adapter_name,
                        b.len()
                    );
                    return None;
                }
                Err(e) => {
                    warn!(
                        "{} threshold signer: group_public_key_hex decode failed: {} — adapter \
                         will be quote-only",
                        adapter_name, e
                    );
                    return None;
                }
            };

        // -------- Validate parameters + group membership ------------------
        let parameters = match MpcParameters::new(
            MpcCurve::Secp256k1,
            mpc_cfg.threshold,
            mpc_cfg.total_parties,
        ) {
            Some(p) => p,
            None => {
                warn!(
                    "{} threshold signer: invalid MpcParameters threshold={} total_parties={} \
                     (need 2 <= t <= n <= 32) — adapter will be quote-only",
                    adapter_name, mpc_cfg.threshold, mpc_cfg.total_parties
                );
                return None;
            }
        };
        if mpc_cfg.group_members.len() != mpc_cfg.total_parties as usize {
            warn!(
                "{} threshold signer: group_members.len()={} but total_parties={} — adapter \
                 will be quote-only",
                adapter_name,
                mpc_cfg.group_members.len(),
                mpc_cfg.total_parties
            );
            return None;
        }
        if mpc_cfg.local_did.is_empty() {
            warn!(
                "{} threshold signer: local_did is empty — adapter will be quote-only",
                adapter_name
            );
            return None;
        }
        if !mpc_cfg.group_members.iter().any(|d| d == &mpc_cfg.local_did) {
            warn!(
                "{} threshold signer: local_did={} is not a member of group_members — adapter \
                 will be quote-only",
                adapter_name, mpc_cfg.local_did
            );
            return None;
        }

        // -------- Build the four runtime dependencies ---------------------
        let keyshare_store = std::sync::Arc::new(
            crate::mpc_keyshare_store::NodeKeyshareStore::new(storage.clone()),
        );

        // Production-posture sealer: TEE-rooted IKM. Fails closed
        // off-hardware (no-simulation policy).
        let sealer: std::sync::Arc<dyn tenzro_bridge::mpc::sealing::KeyshareSealer> =
            match TeeKeyshareSealer::derive_auto().await {
                Ok(s) => std::sync::Arc::new(s),
                Err(e) => {
                    warn!(
                        "{} threshold signer: TEE keyshare sealer unavailable: {} — adapter \
                         will be quote-only (no raw-IKM fallback in production)",
                        adapter_name, e
                    );
                    return None;
                }
            };

        let surface: std::sync::Arc<
            dyn tenzro_bridge::mpc::libp2p_relay::MpcLibp2pSurface,
        > = match crate::mpc_libp2p_adapter::NetworkMpcSurface::new(network).await {
            Ok(s) => std::sync::Arc::new(s),
            Err(e) => {
                warn!(
                    "{} threshold signer: network MPC surface subscription failed: {} — \
                     adapter will be quote-only",
                    adapter_name, e
                );
                return None;
            }
        };

        let block_store = match tenzro_storage::block_store::BlockStoreImpl::new(
            storage,
        ) {
            Ok(bs) => std::sync::Arc::new(bs),
            Err(e) => {
                warn!(
                    "{} threshold signer: block store construction failed: {} — adapter will \
                     be quote-only",
                    adapter_name, e
                );
                return None;
            }
        };
        let chain_entropy: std::sync::Arc<
            dyn crate::mpc_threshold_signer::ChainEntropyProvider,
        > = std::sync::Arc::new(
            crate::mpc_threshold_signer::BlockStoreEntropyProvider::new(block_store),
        );

        // -------- Construct + dispatch ------------------------------------
        let signer = match crate::mpc_threshold_signer::NodeThresholdSigner::new(
            group_id,
            mpc_cfg.local_did.clone(),
            mpc_cfg.group_members.clone(),
            group_public_key_compressed,
            parameters,
            keyshare_store,
            sealer,
            surface,
            chain_entropy,
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "{} threshold signer construction failed: {} — adapter will be quote-only",
                    adapter_name, e
                );
                return None;
            }
        };

        let sender_address = signer.cached_sender_address();
        let evm_signer = EvmTransactionSigner::with_threshold_signer(
            std::sync::Arc::new(signer),
            cfg.chain_id,
            cfg.rpc_url.clone(),
        );
        info!(
            "{} signer configured (DKLS23 threshold {}-of-{}): chain_id={}, sender=0x{}, \
             group_id={}",
            adapter_name,
            mpc_cfg.threshold,
            mpc_cfg.total_parties,
            cfg.chain_id,
            hex::encode(sender_address),
            group_id.to_hex()
        );
        Some(evm_signer)
    }

    async fn init_bridge(&mut self) -> Result<()> {
        info!("Initializing bridge router...");

        // Bridge replay-cache persistence: hydrate each adapter's
        // seen-message cache + inbound nonce tracker from
        // CF_SETTLEMENTS so replay protection survives restarts.
        let bridge_storage: Option<Arc<dyn KvStore>> =
            self.storage.clone().map(|s| s as Arc<dyn KvStore>);

        // The Hyperlane / Axelar adapters serve their RPC namespaces
        // unconditionally and are constructed before storage opens;
        // rebuild them here with persistence attached. Runs before any
        // RPC serving (start() step 12), so the swap is not observable.
        if let Some(ref st) = bridge_storage {
            self.hyperlane_adapter = Arc::new(
                HyperlaneAdapter::new(HyperlaneConfig::new(
                    10_000,
                    "0x0000000000000000000000000000000000000000",
                    "0x0000000000000000000000000000000000000000",
                ))
                .with_storage(st.clone()),
            );
            self.axelar_adapter = Arc::new(
                AxelarAdapter::new(AxelarConfig::new(
                    "tenzro",
                    "0x0000000000000000000000000000000000000000",
                    "0x0000000000000000000000000000000000000000",
                ))
                .with_storage(st.clone()),
            );
        }

        // Wire the fee-in-TNZO surface onto every router from the start so
        // adapters can quote / sponsor uniformly via `tenzro_quoteBridgeFeeInTnzo`
        // and `tenzro_listBridgeSponsorshipPools`. When `bridge.chainlink_feeds`
        // is set + enabled, the oracle is a `ChainlinkFeedFeeOracle` backed by
        // live `eth_call` against AggregatorV3Interface — falls through to the
        // inner `GovernanceSetFeeOracle` on stale / invalid / RPC failures.
        let governance_oracle = std::sync::Arc::new(
            tenzro_bridge::fee_oracle::GovernanceSetFeeOracle::new(),
        );
        let bridge_cfg = &self.config.bridge;
        let oracle: std::sync::Arc<dyn tenzro_bridge::fee_oracle::BridgeFeeOracle> =
            if let Some(cf) = bridge_cfg.chainlink_feeds.as_ref().filter(|c| c.enabled) {
                let rpc = cf
                    .rpc_url
                    .clone()
                    .unwrap_or_else(|| "https://eth.llamarpc.com".to_string());
                let client = std::sync::Arc::new(
                    tenzro_bridge::ChainlinkFeedClient::new(rpc.clone()),
                );
                let chainlink_oracle =
                    tenzro_bridge::fee_oracle::ChainlinkFeedFeeOracle::new(governance_oracle.clone())
                        .with_feed_client(client.clone())
                        .with_markup_bps(cf.markup_bps)
                        .with_valid_window_ms(cf.valid_window_ms);
                if let Some(tnzo_feed) = cf.tnzo_usd_feed.as_ref() {
                    // Eagerly register the TNZO/USD feed so `decimals()` is
                    // cached at startup. Failure is non-fatal — the oracle
                    // simply falls back to governance for that pair.
                    if let Err(e) = client.register_feed(tnzo_feed.as_str(), "major").await {
                        tracing::warn!("failed to register TNZO/USD feed: {}", e);
                    }
                    chainlink_oracle.set_tnzo_usd_feed(tnzo_feed.as_str());
                }
                for entry in &cf.dest_native_feeds {
                    if let Some(adapter_id) =
                        tenzro_bridge::fee_oracle::BridgeAdapterId::from_str(&entry.adapter)
                    {
                        let tier = entry.tier.as_deref().unwrap_or("major");
                        if let Err(e) = client
                            .register_feed(entry.feed_address.as_str(), tier)
                            .await
                        {
                            tracing::warn!(
                                "failed to register dest-native feed {} for {}: {}",
                                entry.feed_address,
                                entry.adapter,
                                e
                            );
                        }
                        chainlink_oracle.set_dest_native_feed(
                            adapter_id,
                            entry.dest_chain.as_str(),
                            entry.feed_address.as_str(),
                        );
                    } else {
                        tracing::warn!(
                            "unknown bridge adapter id in chainlink_feeds config: {}",
                            entry.adapter
                        );
                    }
                }
                info!(
                    "Bridge fee oracle: ChainlinkFeedFeeOracle (rpc={}, feeds={})",
                    rpc,
                    cf.dest_native_feeds.len()
                );
                std::sync::Arc::new(chainlink_oracle)
            } else {
                info!("Bridge fee oracle: GovernanceSetFeeOracle (governance table only)");
                governance_oracle.clone()
            };
        let fee_sponsor = std::sync::Arc::new(tenzro_bridge::fee_sponsor::BridgeFeeSponsor::new());
        let fee_surface = std::sync::Arc::new(
            tenzro_bridge::fee_sponsor::WiredBridgeFeeSurface::new(oracle, fee_sponsor.clone()),
        );
        let bridge_router = Arc::new(BridgeRouter::new().with_fee_surface(fee_surface));

        // Asset USD price oracle (independent of the fee oracle above). Backs
        // `tenzro_getPrice` for wallet portfolio views. Registers each
        // configured `SYMBOL/USD` feed; failures are non-fatal (that symbol is
        // simply unpriceable until the feed responds).
        if let Some(pc) = bridge_cfg.prices.as_ref().filter(|c| c.enabled) {
            let rpc = pc
                .rpc_url
                .clone()
                .unwrap_or_else(|| "https://eth.llamarpc.com".to_string());
            let client = Arc::new(tenzro_bridge::ChainlinkFeedClient::new(rpc.clone()));
            let oracle = Arc::new(tenzro_bridge::PriceOracle::new(client));
            let mut registered = 0usize;
            for s in &pc.symbols {
                let feed = tenzro_bridge::SymbolFeed {
                    symbol: s.symbol.clone(),
                    feed_address: s.feed_address.clone(),
                    tier: s.tier.clone().unwrap_or_else(|| "major".to_string()),
                };
                match oracle.register_symbol(&feed).await {
                    Ok(()) => registered += 1,
                    Err(e) => tracing::warn!(
                        "failed to register price feed for {}: {}",
                        s.symbol,
                        e
                    ),
                }
            }
            info!(
                "Asset price oracle: PriceOracle (rpc={}, symbols={}/{})",
                rpc,
                registered,
                pc.symbols.len()
            );
            self.price_oracle = Some(oracle);
        }

        if !bridge_cfg.enabled {
            info!("Bridge subsystem disabled — router initialized with no adapters");
            self.bridge_router = Some(bridge_router);
            self.health_monitor.mark_healthy("bridge");
            return Ok(());
        }

        // LayerZero V2 adapter
        if let Some(lz_cfg) = &bridge_cfg.layerzero
            && lz_cfg.enabled {
                // LayerZero V2 EndpointV2 address is the same across all EVM chains
                let lz_config = LayerZeroConfig::new(
                    "0x1a44076050125825900e736c501f859c50fE728c",
                    30101, // default to ethereum EID; operators override via peers
                    "0x0000000000000000000000000000000000000001",
                    "0x0000000000000000000000000000000000000002",
                );
                let mut adapter = LayerZeroAdapter::new(lz_config);
                if let Some(ref st) = bridge_storage {
                    adapter = adapter.with_storage(st.clone());
                }
                if let Some(signer) = self.build_bridge_signer("LayerZero", lz_cfg).await {
                    adapter = adapter.with_signer(signer);
                }

                // Install configured DVN sets. Without at least one DVN set
                // the adapter refuses inbound traffic at runtime
                // (fail-closed).
                for entry in &lz_cfg.inbound_verifier_sets {
                    if entry.kind != "dvn" {
                        warn!(
                            kind = %entry.kind,
                            "Skipping non-'dvn' inbound_verifier_set entry on LayerZero adapter"
                        );
                        continue;
                    }
                    match decode_verifier_addresses(&entry.addresses) {
                        Ok(addrs) => {
                            adapter.install_dvn_set(entry.source_id as u32, addrs, entry.threshold);
                            info!(
                                src_eid = entry.source_id,
                                threshold = entry.threshold,
                                "LayerZero DVN set installed"
                            );
                        }
                        Err(e) => warn!(
                            error = %e,
                            "Failed to decode LayerZero DVN addresses"
                        ),
                    }
                }

                bridge_router.register_adapter("layerzero", Box::new(adapter)).await;
                info!("Registered LayerZero V2 bridge adapter");
            }

        // Chainlink CCIP adapter
        if let Some(ccip_cfg) = &bridge_cfg.ccip
            && ccip_cfg.enabled {
                let mut adapter = ChainlinkCcipAdapter::new(
                    CcipConfig::ethereum_mainnet(FeeToken::Native),
                );
                if let Some(ref st) = bridge_storage {
                    adapter = adapter.with_storage(st.clone());
                }

                if let Some(signer) = self.build_bridge_signer("CCIP", ccip_cfg).await {
                    adapter = adapter.with_signer(signer);
                }

                // CCIP requires BOTH a commit-store committee set and an
                // RMN ARM blessing set per source selector. Either missing
                // = adapter refuses inbound traffic for that selector.
                for entry in &ccip_cfg.inbound_verifier_sets {
                    match decode_verifier_addresses(&entry.addresses) {
                        Ok(addrs) => match entry.kind.as_str() {
                            "ccip_commit" => {
                                adapter.install_commit_set(entry.source_id, addrs, entry.threshold);
                                info!(
                                    selector = entry.source_id,
                                    threshold = entry.threshold,
                                    "CCIP commit-store set installed"
                                );
                            }
                            "ccip_rmn" => {
                                adapter.install_rmn_set(entry.source_id, addrs, entry.threshold);
                                info!(
                                    selector = entry.source_id,
                                    threshold = entry.threshold,
                                    "CCIP RMN ARM set installed"
                                );
                            }
                            other => warn!(
                                kind = %other,
                                "Skipping unknown inbound_verifier_set kind on CCIP adapter"
                            ),
                        },
                        Err(e) => warn!(
                            error = %e,
                            kind = %entry.kind,
                            "Failed to decode CCIP verifier addresses"
                        ),
                    }
                }

                bridge_router.register_adapter("ccip", Box::new(adapter)).await;
                info!("Registered Chainlink CCIP bridge adapter");
            }

        // deBridge DLN adapter
        if let Some(db_cfg) = &bridge_cfg.debridge
            && db_cfg.enabled {
                let debridge_config = DeBridgeConfig::new(
                    "https://dln.debridge.finance",
                    db_cfg.chain_id,
                    "0x0000000000000000000000000000000000000000",
                    "0x0000000000000000000000000000000000000000",
                );
                let mut adapter = DeBridgeAdapter::new(debridge_config);
                if let Some(ref st) = bridge_storage {
                    adapter = adapter.with_storage(st.clone());
                }

                if let Some(signer) = self.build_bridge_signer("deBridge", db_cfg).await {
                    adapter = adapter.with_signer(signer);
                }

                // Install configured DLN validator sets. Without at least
                // one set the adapter refuses inbound traffic (fail-closed).
                for entry in &db_cfg.inbound_verifier_sets {
                    if entry.kind != "dln" {
                        warn!(
                            kind = %entry.kind,
                            "Skipping non-'dln' inbound_verifier_set entry on deBridge adapter"
                        );
                        continue;
                    }
                    match decode_verifier_addresses(&entry.addresses) {
                        Ok(addrs) => {
                            adapter.install_validator_set(entry.source_id, addrs, entry.threshold);
                            info!(
                                src_chain = entry.source_id,
                                threshold = entry.threshold,
                                "deBridge DLN validator set installed"
                            );
                        }
                        Err(e) => warn!(
                            error = %e,
                            "Failed to decode deBridge DLN validator addresses"
                        ),
                    }
                }

                bridge_router.register_adapter("debridge", Box::new(adapter)).await;
                info!("Registered deBridge DLN bridge adapter");
            }

        // LI.FI aggregator adapter
        if let Some(lifi_cfg) = &bridge_cfg.lifi
            && lifi_cfg.enabled {
                let mut adapter = LiFiAdapter::new(LiFiConfig::default());

                if let Some(signer) = self.build_bridge_signer("LI.FI", lifi_cfg).await {
                    adapter = adapter.with_signer(signer);
                }

                bridge_router.register_adapter("lifi", Box::new(adapter)).await;
                info!("Registered LI.FI aggregator bridge adapter");
            }

        // Wormhole adapter (Guardian-VAA token + message bridge). Constructed
        // with a Tenzro-local sentinel chain ID (10_000) until Tenzro receives
        // an officially assigned Wormhole chain ID. Core / token bridge
        // contract addresses default to the zero address — operators that
        // need to publish messages on-chain must override via their own
        // signer + chain-specific contract deployment.
        if let Some(wh_cfg) = &bridge_cfg.wormhole
            && wh_cfg.enabled {
                let wormhole_config = WormholeConfig::new(
                    10_000, // Tenzro-local sentinel; not officially assigned.
                    "0x0000000000000000000000000000000000000000",
                    "0x0000000000000000000000000000000000000000",
                );
                let mut adapter = WormholeAdapter::new(wormhole_config);
                if let Some(ref st) = bridge_storage {
                    adapter = adapter.with_storage(st.clone());
                }

                if let Some(signer) = self.build_bridge_signer("Wormhole", wh_cfg).await {
                    adapter = adapter.with_signer(signer);
                }

                // Install the Guardian set used to quorum-verify inbound
                // VAAs. Config override (`kind = "wormhole_guardian"`,
                // `source_id` = guardian set index) wins; otherwise the
                // pinned mainnet set keeps the adapter fail-closed.
                let mut guardian_set_installed = false;
                for entry in &wh_cfg.inbound_verifier_sets {
                    if entry.kind != "wormhole_guardian" {
                        warn!(
                            kind = %entry.kind,
                            "Skipping non-'wormhole_guardian' inbound_verifier_set entry on Wormhole adapter"
                        );
                        continue;
                    }
                    match decode_verifier_addresses(&entry.addresses) {
                        Ok(addrs) => {
                            let set = GuardianSet {
                                index: entry.source_id as u32,
                                guardians: addrs,
                                expiration_time: 0,
                            };
                            let quorum = set.quorum();
                            adapter.set_guardian_set(set);
                            guardian_set_installed = true;
                            info!(
                                guardian_set_index = entry.source_id,
                                quorum,
                                "Wormhole Guardian set installed from config"
                            );
                        }
                        Err(e) => warn!(
                            error = %e,
                            "Failed to decode Wormhole guardian addresses"
                        ),
                    }
                }
                if !guardian_set_installed {
                    let set = GuardianSet::mainnet();
                    info!(
                        guardian_set_index = set.index,
                        guardians = set.guardians.len(),
                        quorum = set.quorum(),
                        "Wormhole Guardian set defaulted to pinned mainnet set"
                    );
                    adapter.set_guardian_set(set);
                }

                bridge_router.register_adapter("wormhole", Box::new(adapter)).await;
                info!("Registered Wormhole bridge adapter");
            }

        // Hyperlane V3 inbound ISM validator sets. The adapter itself is
        // constructed unconditionally (it serves the `tenzro_hyperlane*`
        // RPC namespace); without at least one installed set per origin
        // domain it refuses inbound traffic (fail-closed).
        if let Some(hl_cfg) = &bridge_cfg.hyperlane
            && hl_cfg.enabled {
                for entry in &hl_cfg.inbound_verifier_sets {
                    if entry.kind != "hyperlane" {
                        warn!(
                            kind = %entry.kind,
                            "Skipping non-'hyperlane' inbound_verifier_set entry on Hyperlane adapter"
                        );
                        continue;
                    }
                    match decode_verifier_addresses(&entry.addresses) {
                        Ok(addrs) => {
                            self.hyperlane_adapter.install_validator_set(HyperlaneValidatorSet {
                                origin_domain: entry.source_id as u32,
                                validators: addrs,
                                threshold: entry.threshold,
                            });
                            info!(
                                origin_domain = entry.source_id,
                                threshold = entry.threshold,
                                "Hyperlane ISM validator set installed"
                            );
                        }
                        Err(e) => warn!(
                            error = %e,
                            "Failed to decode Hyperlane validator addresses"
                        ),
                    }
                }
            }

        // Axelar GMP inbound validator set (single global set). Without an
        // installed set the adapter refuses inbound traffic (fail-closed).
        if let Some(ax_cfg) = &bridge_cfg.axelar
            && ax_cfg.enabled {
                for entry in &ax_cfg.inbound_verifier_sets {
                    if entry.kind != "axelar" {
                        warn!(
                            kind = %entry.kind,
                            "Skipping non-'axelar' inbound_verifier_set entry on Axelar adapter"
                        );
                        continue;
                    }
                    match decode_verifier_addresses(&entry.addresses) {
                        Ok(addrs) => {
                            self.axelar_adapter.install_validator_set(AxelarValidatorSet {
                                validators: addrs,
                                threshold: entry.threshold,
                            });
                            info!(
                                threshold = entry.threshold,
                                "Axelar GMP validator set installed"
                            );
                        }
                        Err(e) => warn!(
                            error = %e,
                            "Failed to decode Axelar validator addresses"
                        ),
                    }
                }
            }

        // TNZO CCT bridge — only useful when CCIP is also enabled, since the
        // CCT path delegates CCIP fee quoting / message submission. The CCT
        // bridge holds its own `ChainlinkCcipAdapter` instance (sharing the
        // router's would require Arc-wrapping the registered adapter; for
        // pre-alpha simplicity we construct a second instance with the same
        // config). The canonical Tenzro mainnet pool registry is seeded
        // automatically (Ethereum / Base / Arbitrum / Optimism LockRelease
        // + Solana BurnMint).
        if let Some(ccip_cfg) = &bridge_cfg.ccip
            && ccip_cfg.enabled {
                let mut cct_ccip_adapter = ChainlinkCcipAdapter::new(
                    CcipConfig::ethereum_mainnet(FeeToken::Native),
                );
                if let Some(ref st) = bridge_storage {
                    cct_ccip_adapter = cct_ccip_adapter.with_storage(st.clone());
                }
                if let Some(signer) = self.build_bridge_signer("CCT-CCIP", ccip_cfg).await {
                    cct_ccip_adapter = cct_ccip_adapter.with_signer(signer);
                }
                let cct_bridge = TnzoCctBridge::new(
                    Arc::new(cct_ccip_adapter),
                    TnzoCctRegistry::tenzro_mainnet(),
                );
                self.cct_bridge = Some(Arc::new(cct_bridge));
                info!("Registered TNZO CCT bridge with canonical mainnet pool topology");
            }

        // Canton adapter — constructed independently of the per-protocol
        // bridge adapters because Canton mirroring uses a different surface
        // (typed `mirror_*` / `consume_daml_events` methods on the adapter
        // directly, not the unified `BridgeAdapter` trait). Operators
        // configure Canton via the top-level `[canton]` config section,
        // not under `[bridge.*]`.
        if self.config.canton.enabled {
            // One adapter per configured network. Within a network, auth is
            // one of three profiles: OAuth2 client-credentials, a long-lived
            // static JWT, or unauthenticated (plaintext HTTP over a private
            // path, dev/test only).
            use tenzro_bridge::canton::{CantonAdapter, CantonConfig as BridgeCantonConfig};
            use tenzro_bridge::canton_auth::{CantonAuthConfig, CantonTokenProvider};

            let networks = self.config.canton.configured_networks();
            if networks.is_empty() {
                return Err(NodeError::Internal(
                    "Canton enabled but no network is configured — set \
                     CANTON_DEVNET_LEDGER_API_HOST and/or \
                     CANTON_MAINNET_LEDGER_API_HOST"
                        .to_string(),
                ));
            }

            for net in networks {
                let net_cfg = match self.config.canton.network(net) {
                    Some(c) => c,
                    None => continue,
                };

                let mut canton_cfg = BridgeCantonConfig::new(
                    net_cfg.host.clone(),
                    net_cfg.port,
                    Vec::<String>::new(),
                    String::new(),
                    "tenzro-node-workflow-mirror",
                );

                let (token_provider, profile_label) = if let Some(oauth) = &net_cfg.oauth {
                    let provider = CantonTokenProvider::new(CantonAuthConfig {
                        token_url: oauth.token_url.clone(),
                        client_id: oauth.client_id.clone(),
                        client_secret: oauth.client_secret.clone(),
                        audience: oauth.audience.clone(),
                        scope: oauth.scope.clone(),
                    });
                    (Some(provider), "oauth2")
                } else if let Some(jwt) = &net_cfg.static_jwt {
                    canton_cfg = canton_cfg.with_jwt_token(jwt.clone());
                    (None, "static jwt")
                } else {
                    (None, "unauthenticated")
                };

                if net_cfg.tls {
                    canton_cfg = canton_cfg.with_tls(true);
                }

                let mut adapter = CantonAdapter::new(canton_cfg);
                if let Some(provider) = token_provider {
                    adapter = adapter.with_token_provider(provider);
                }

                info!(
                    network = %net,
                    host = %net_cfg.host,
                    port = net_cfg.port,
                    tls = net_cfg.tls,
                    auth = profile_label,
                    "Canton adapter initialized"
                );

                let adapter = Arc::new(adapter);
                // Which synchronizers a participant is subscribed to is
                // decided at the Canton console, so read it rather than
                // expecting it in this node's config. A participant that
                // is not reachable yet is not a startup failure — the
                // list refreshes on the next request.
                match adapter.discover_synchronizers().await {
                    Ok(ids) if !ids.is_empty() => info!(
                        network = %net,
                        synchronizers = ?ids,
                        "Canton synchronizers discovered"
                    ),
                    Ok(_) => warn!(
                        network = %net,
                        "Canton participant reports no connected synchronizer — \
                         run `synchronizers.reconnect_all()` on the participant"
                    ),
                    Err(e) => warn!(
                        network = %net,
                        error = %e,
                        "Canton synchronizer discovery failed — retrying on next request"
                    ),
                }
                self.canton_adapters.insert(net, adapter);
            }

            if self.config.canton.network(self.config.canton.default_network).is_none() {
                warn!(
                    default_network = %self.config.canton.default_network,
                    "Canton default_network is not configured — requests that do not \
                     name a network will be refused"
                );
            }
        } else {
            info!("Canton subsystem disabled — workflow mirror surface inactive");
        }

        self.bridge_router = Some(bridge_router);
        self.health_monitor.mark_healthy("bridge");

        Ok(())
    }

    async fn init_identity(&mut self) -> Result<()> {
        info!("Initializing identity registry (TDIP)...");

        let mut registry = if let Some(storage) = &self.storage {
            info!("Identity registry initialized with persistent RocksDB storage");
            IdentityRegistry::with_storage(storage.clone() as Arc<dyn KvStore>)
        } else {
            warn!("Identity registry initialized without persistent storage — data will be lost on restart");
            IdentityRegistry::new()
        };

        // Wire the shared wallet service into the identity registry so the
        // binder-based registration path (`register_human_via_binder`) and
        // the rpc-level signing handlers operate against the same
        // `TenzroWalletService` instance. Without this binding, onboarding
        // RPCs that call `register_human_via_binder` would fail with
        // `WalletError("no wallet binder configured")`, and the legacy
        // `register_human_with_fee(public_key, ...)` path falls back to a
        // deterministic placeholder `wallet-{12hex}` id that the wallet
        // service has no record of.
        if let Some(wallet_service) = self.wallet_service.clone() {
            let binder = Arc::new(tenzro_identity::WalletBinder::from_service(wallet_service));
            registry = registry.with_wallet_binder_arc(binder);
            info!("Wallet binder wired: identity registrations provision MPC wallets via the shared WalletService");
        } else {
            warn!("Wallet service unavailable at identity init — binder-based registration disabled");
        }

        // Wire ERC-8004 auto-mirror: when a TDIP machine identity is
        // registered, submit a signed `register(string agentURI)` EVM
        // tx against the canonical IdentityRegistry proxy predeployed
        // at `addresses::IDENTITY_REGISTRY`. Returns immediately; the
        // tx is dispatched in a detached `tokio::spawn`. The off-chain
        // `did → agentId` index is populated by
        // `event_loop::process_erc8004_registered_logs` when the
        // resulting `Registered(uint256,string,address)` event lands
        // in a finalized block.
        //
        // Requires both storage (for the DID index in CF_IDENTITIES)
        // and the per-node `erc8004-system` signer (loaded or
        // silent-generated from `{data_dir}/validator_erc8004_system_key`).
        // The signer bakes the loopback JSON-RPC URL + chain_id so
        // submission goes through this node's own `eth_sendRawTransaction`.
        match (&self.storage, &self.erc8004_system_signer) {
            (Some(storage), Some(signer)) => {
                let mirror = Arc::new(crate::erc8004_mirror::NativeErc8004Mirror::new(
                    signer.clone(),
                    storage.clone() as Arc<dyn KvStore>,
                ));
                registry = registry.with_on_chain_agent_registry(mirror.clone());
                self.erc8004_agent_registry = Some(
                    mirror as Arc<dyn tenzro_identity::erc8004::OnChainAgentRegistry>,
                );
                info!(
                    target: "tenzro::erc8004",
                    "ERC-8004 auto-mirror wired: TDIP machine registrations \
                     dispatch signed EVM tx to canonical IdentityRegistry proxy"
                );
            }
            (None, _) => {
                warn!(
                    target: "tenzro::erc8004",
                    "ERC-8004 auto-mirror NOT wired: storage unavailable \
                     (no DID index backing store)"
                );
            }
            (_, None) => {
                warn!(
                    target: "tenzro::erc8004",
                    "ERC-8004 auto-mirror NOT wired: erc8004-system signer \
                     unavailable (init_storage must run before init_identity)"
                );
            }
        }

        // Wire remote DID fallback resolution: when a DID is absent from
        // the local registry, `resolve()` consults the configured upstream
        // node's `tenzro_resolveIdentity` (with `include_record: true`) and
        // caches successful resolutions locally. Pointing this at the node's
        // own endpoint cannot recurse — the RPC handler reads CF_IDENTITIES
        // directly, never `registry.resolve()`.
        if let Some(endpoint) = self.config.did_fallback_rpc.clone() {
            let backend = Arc::new(crate::did_resolution::RemoteDidResolutionBackend::new(
                endpoint.clone(),
            ));
            registry = registry.with_resolution_backend(backend);
            info!(endpoint = %endpoint, "Remote DID resolution fallback wired");
        }

        // Wire the revocation broadcaster: local `revoke()` calls sign each
        // entry with the validator hybrid key and fan it out on the
        // `tenzro/identity` gossipsub topic. The channel-backed forwarder
        // decouples the registry's sync trait call from the async publish.
        // Receivers apply entries via `apply_remote_revocation` (signature-
        // verified, idempotent) in the event loop.
        if let Some(network) = self.network.clone() {
            let broadcaster =
                Arc::new(crate::identity_gossip::GossipRevocationBroadcaster::spawn(network));
            registry = registry.with_revocation_broadcaster(broadcaster);
            info!(
                topic = tenzro_identity::IDENTITY_TOPIC,
                "Identity revocation broadcaster wired to gossipsub"
            );
        } else {
            warn!("Identity revocation broadcaster NOT wired: network unavailable");
        }

        // Parallel SVM mirror wiring: every TDIP machine registration is
        // also reflected into the canonical QuantuLabs
        // `agent_registry_8004` Anchor program. Storage-only (no Solana
        // transport configured by default) — calldata is buffered to the
        // pending-tx queue under `erc8004_svm_pending_tx:` and drained
        // once an operator attaches a `SvmMirrorTransport` impl.
        if let Some(storage) = &self.storage {
            let svm_mirror = Arc::new(
                crate::erc8004_svm_mirror::NativeErc8004SvmMirror::new(
                    storage.clone() as Arc<dyn KvStore>,
                ),
            );
            registry = registry.with_on_chain_agent_svm_registry(svm_mirror);
            info!(
                target: "tenzro::erc8004::svm",
                "ERC-8004 SVM auto-mirror wired: TDIP machine registrations \
                 buffer Anchor calldata to pending-tx queue (no Solana \
                 transport configured)"
            );
        } else {
            warn!(
                target: "tenzro::erc8004::svm",
                "ERC-8004 SVM auto-mirror NOT wired: storage unavailable \
                 (no DID index backing store)"
            );
        }

        // Parallel DAML mirror wiring: every TDIP machine registration is
        // also reflected into the in-tree Canton/DAML port of the canonical
        // ERC-8004 IdentityRegistry (`vendor/erc8004-daml/`). Storage-only
        // (no Canton transport configured by default) — the full Canton v2
        // `submit-and-wait` command JSON is buffered to the pending-tx
        // queue under `erc8004_daml_pending_tx:` and drained once an
        // operator attaches a `DamlMirrorTransport` impl + supplies the
        // participant-side admin party id, admin contract id, and compiled
        // DAR package id via the node config.
        //
        // The DAML mirror is wiring-gated on the operator-supplied
        // `node_config.erc8004_daml`: without that config block we skip
        // wiring (rather than buffering with placeholder party ids that
        // would never be drainable). This mirrors how Canton itself is
        // opt-in operator infrastructure.
        if let (Some(storage), Some(daml_cfg)) =
            (&self.storage, self.config.erc8004_daml.as_ref())
        {
            let mirror_cfg = crate::erc8004_daml_mirror::DamlMirrorConfig {
                package_ids: tenzro_identity::erc8004_daml::DamlPackageIds::new_single(
                    daml_cfg.package_id.clone(),
                ),
                admin_party: daml_cfg.admin_party.clone(),
                admin_contract_id: daml_cfg.admin_contract_id.clone(),
                default_controller_party: daml_cfg.default_controller_party.clone(),
            };
            let daml_mirror = Arc::new(
                crate::erc8004_daml_mirror::NativeErc8004DamlMirror::new(
                    storage.clone() as Arc<dyn KvStore>,
                    mirror_cfg,
                ),
            );
            registry = registry.with_on_chain_agent_daml_registry(daml_mirror);
            info!(
                target: "tenzro::erc8004::daml",
                "ERC-8004 DAML auto-mirror wired: TDIP machine registrations \
                 buffer Canton submit-and-wait command JSON to pending-tx \
                 queue (no Canton transport configured)"
            );
        } else if self.storage.is_some() {
            // Common case: storage is up, but no operator has supplied
            // Canton wiring. Stay silent at debug to avoid log spam on
            // the typical pre-Canton fleet.
            tracing::debug!(
                target: "tenzro::erc8004::daml",
                "ERC-8004 DAML auto-mirror skipped: no erc8004_daml config block \
                 (Canton participant not configured)"
            );
        } else {
            warn!(
                target: "tenzro::erc8004::daml",
                "ERC-8004 DAML auto-mirror NOT wired: storage unavailable \
                 (no DID index backing store)"
            );
        }

        // Wire the AgentBond lookup (Spec 9). When set, every receipt
        // the principal-chain resolver produces carries `actor_bond` and
        // `controller_bond_aggregate` snapshots — regulators see real
        // skin-in-the-game on every settlement, payment, and lifecycle
        // event without recursive walks.
        if let Some(ref bond_manager) = self.bond_manager {
            registry = registry.with_bond_lookup(
                bond_manager.clone()
                    as Arc<dyn tenzro_types::principal_chain::BondLookup>,
            );
            info!("BondManager wired into IdentityRegistry: receipts will carry Spec-9 bond fields");
        } else {
            warn!("BondManager unavailable at identity init — receipt bond fields will be None");
        }

        let registry_arc = Arc::new(registry);
        self.identity_registry = Some(registry_arc.clone());

        // Wire the live `PrincipalChainResolver` (Agent-Swarm Spec 5)
        // into the settlement engine. Settlement is constructed earlier
        // (`init_settlement`) than identity, so we attach the resolver
        // after both are up. From this point on every receipt the
        // engine writes carries a real principal chain rather than a
        // synthetic anonymous one.
        if let Some(ref settlement) = self.settlement {
            settlement.set_principal_resolver(
                registry_arc.clone()
                    as Arc<dyn tenzro_types::principal_chain::PrincipalChainResolver>,
            );
            info!("SettlementEngine wired with live PrincipalChainResolver (Spec 5)");
        }

        self.health_monitor.mark_healthy("identity");

        Ok(())
    }

    /// Build the x402 scheme registry with self-hosted EIP-3009 / Permit2
    /// facilitation when the operator has configured an external EVM relayer.
    ///
    /// Returns `None` when no `payments.x402_facilitator` block is set or the
    /// relayer key cannot be resolved / the signer fails to build — in which
    /// case the x402 server and facilitator keep the default registry, which
    /// routes those schemes through the remote CDP verifier.
    fn build_x402_self_hosted_registry(
        &self,
    ) -> Option<tenzro_payments::x402::scheme::SchemeRegistry> {
        let cfg = self.config.payments.x402_facilitator.as_ref()?;

        let key_hex = match cfg.resolve_relayer_key() {
            Some(k) => k,
            None => {
                warn!(
                    "x402 self-hosted facilitator configured for chain {} but no relayer key \
                     resolved (config field or TENZRO_X402_RELAYER_KEY) — EIP-3009 / Permit2 \
                     will use the remote CDP verifier",
                    cfg.chain_id
                );
                return None;
            }
        };

        let signer_cfg =
            EvmSignerConfig::custom(key_hex, cfg.chain_id, cfg.evm_rpc_url.clone());
        match signer_cfg.build() {
            Ok(signer) => {
                let signer = Arc::new(signer);
                info!(
                    chain_id = cfg.chain_id,
                    rpc = %cfg.evm_rpc_url,
                    relayer = %signer.sender_address(),
                    "x402 self-hosted facilitation enabled (EIP-3009 / Permit2 verify + settle)"
                );
                Some(tenzro_payments::x402::scheme::SchemeRegistry::with_local_facilitator(
                    signer,
                    cfg.evm_rpc_url.clone(),
                ))
            }
            Err(e) => {
                warn!(
                    "x402 self-hosted relayer signer build failed for chain {}: {} — EIP-3009 / \
                     Permit2 will use the remote CDP verifier",
                    cfg.chain_id, e
                );
                None
            }
        }
    }

    async fn init_payments(&mut self) -> Result<()> {
        info!("Initializing payment gateway (MPP/x402/Visa TAP/Mastercard Agent Pay)...");

        let gateway = if let Some(ref storage) = self.storage {
            info!("Payment gateway initialized with persistent storage");
            TenzroPaymentGateway::with_storage(storage.clone() as Arc<dyn KvStore>)
        } else {
            warn!("Payment gateway initialized without persistent storage — challenges will be lost on restart");
            TenzroPaymentGateway::new()
        };
        let challenge_store = gateway.challenge_store();

        // Validated-AP2-mandate store — write-through + hydrate when the node
        // has persistent storage; `handle_ap2_validate_mandate_pair` records a
        // pair here on successful cross-validation and `tenzro_listMandates`
        // reads it back scoped by controller DID.
        if let Some(storage) = &self.storage {
            match crate::mandate_store::MandateStore::with_storage(
                storage.clone() as Arc<dyn KvStore>
            ) {
                Ok(store) => self.mandate_store = Some(Arc::new(store)),
                Err(e) => warn!("Mandate store hydration failed ({e}); mandate listing disabled"),
            }
        } else {
            warn!(
                "Mandate store initialized without persistent storage — \
                 validated mandates will not be listable"
            );
            self.mandate_store =
                Some(Arc::new(crate::mandate_store::MandateStore::new()));
        }

        // Register MPP protocol server (session-based streaming payments)
        let mpp_server = MppPaymentServer::new("0x0000000000000000000000000000000000000001")
            .with_default_asset("USDC")
            .with_default_chain("tenzro")
            .with_challenge_store(challenge_store.clone());
        gateway.register_protocol(Arc::new(mpp_server));

        // Register x402 protocol server (stateless one-shot payments).
        //
        // Two optional capabilities are wired when their prerequisites exist:
        //
        //   * offer signing — the node signs each 402 payment requirement with
        //     its long-term Ed25519 key (the same key that signs gossip
        //     announcements), letting the buyer verify the offer commitment
        //     against the node's advertised identity before paying.
        //   * idempotency — a RocksDB-backed ledger keyed by
        //     `pay_<offer-commitment×payer-did>` collapses duplicate
        //     settlements to the first receipt, hydrating prior receipts on
        //     boot so replay protection survives restart.
        // Self-hosted x402 facilitation (EIP-3009 / Permit2). When the
        // operator configures an external EVM relayer, the EIP-3009 / Permit2
        // schemes verify and settle against the operator's own RPC + relayer
        // signer via `LocalFacilitatorVerifier`, with no dependency on a remote
        // Coinbase CDP facilitator. Absent config (or a resolvable key), those
        // schemes fall back to the remote CDP verifier in the default registry.
        let self_hosted_registry = self.build_x402_self_hosted_registry();

        let mut x402_builder = X402PaymentServer::new(
            "0x0000000000000000000000000000000000000001",
            vec!["tenzro".to_string(), "base".to_string(), "ethereum".to_string()],
        )
        .with_default_asset("USDC")
        .with_challenge_store(challenge_store.clone());

        if let Some(registry) = &self_hosted_registry {
            x402_builder = x402_builder.with_scheme_registry(registry.clone());
        }

        match crate::keygen::load_validator_keypair(&self.config.data_dir) {
            Ok(offer_keypair) => {
                match tenzro_crypto::signatures::Ed25519SignerImpl::new(offer_keypair) {
                    Ok(signer) => {
                        x402_builder = x402_builder.with_offer_signer(Arc::new(signer));
                        info!("x402 offer signing enabled (node Ed25519 key)");
                    }
                    Err(e) => warn!(
                        "x402 offer signer construction failed ({e}); 402 offers will be unsigned"
                    ),
                }
            }
            Err(NodeError::KeyMissing { .. }) => {
                warn!("No node Ed25519 key on disk — x402 402 offers will be unsigned");
            }
            Err(e) => return Err(e),
        }

        let idempotency_ledger = if let Some(storage) = &self.storage {
            let store = Arc::new(crate::x402_idempotency_store::NodeIdempotencyStore::new(
                storage.clone() as Arc<dyn KvStore>,
            ));
            match tenzro_payments::x402::IdempotencyLedger::with_store(store) {
                Ok(ledger) => {
                    info!(
                        "x402 idempotency ledger hydrated: {} payment ids",
                        ledger.len()
                    );
                    ledger
                }
                Err(e) => {
                    warn!("x402 idempotency ledger hydration failed ({e}); starting empty");
                    tenzro_payments::x402::IdempotencyLedger::new()
                }
            }
        } else {
            warn!(
                "x402 idempotency ledger without persistent storage — replay protection \
                 resets on restart"
            );
            tenzro_payments::x402::IdempotencyLedger::new()
        };
        x402_builder = x402_builder.with_idempotency_ledger(Arc::new(idempotency_ledger));

        let x402_server = Arc::new(x402_builder);
        gateway.register_protocol(x402_server.clone());
        self.x402_server = Some(x402_server);

        // x402 facilitator (verify/settle role) — mounted on the web API so
        // external resource servers can forward payloads for verification and
        // settlement. Same supported-chain set as the payment server; the
        // node's settlement engine executes the Tenzro-native settle path.
        let mut facilitator = tenzro_payments::x402::X402Facilitator::new(vec![
            "tenzro".to_string(),
            "base".to_string(),
            "ethereum".to_string(),
        ]);
        if let Some(registry) = &self_hosted_registry {
            facilitator = facilitator.with_scheme_registry(registry.clone());
        }
        if let Some(engine) = &self.settlement {
            facilitator = facilitator.with_settlement_engine(engine.clone());
        }
        self.x402_facilitator = Some(Arc::new(facilitator));

        // x402 Bazaar resource catalog — RocksDB-backed when storage is up,
        // hydrating any previously-registered listings on boot; in-memory
        // otherwise (storage-less test/dev node). Discovery joins seller
        // reputation from the provider ledger (init_ai_infrastructure runs
        // before init_payments, so the manager is available here).
        let catalog = if let Some(storage) = &self.storage {
            let store = Arc::new(crate::bazaar_store::NodeResourceCatalogStore::new(
                storage.clone() as Arc<dyn KvStore>,
            ));
            match tenzro_payments::x402::ResourceCatalog::with_store(store) {
                Ok(c) => {
                    info!("x402 Bazaar catalog hydrated: {} listings", c.len());
                    c
                }
                Err(e) => {
                    warn!("x402 Bazaar catalog hydration failed ({e}); starting empty");
                    tenzro_payments::x402::ResourceCatalog::new()
                }
            }
        } else {
            tenzro_payments::x402::ResourceCatalog::new()
        };
        let catalog = if let Some(pm) = &self.provider_manager {
            info!("x402 Bazaar discovery joined to provider reputation ledger");
            catalog.with_reputation_resolver(Arc::new(
                crate::bazaar_store::ProviderReputationResolver::new(pm.clone()),
            ))
        } else {
            catalog
        };
        self.bazaar_catalog = Some(Arc::new(catalog));

        // Distributed database registry — RocksDB-backed when storage is up,
        // hydrating every database this node serves on boot; in-memory
        // otherwise (storage-less test/dev node).
        let database_registry = if let Some(storage) = &self.storage {
            match tenzro_database::DatabaseRegistry::with_storage(storage.clone() as Arc<dyn KvStore>)
            {
                Ok(reg) => {
                    info!("Database registry hydrated: {} databases", reg.list_databases().len());
                    Arc::new(reg)
                }
                Err(e) => {
                    warn!("Database registry hydration failed ({e}); starting empty");
                    Arc::new(tenzro_database::DatabaseRegistry::new())
                }
            }
        } else {
            Arc::new(tenzro_database::DatabaseRegistry::new())
        };
        self.database_registry = Some(database_registry);

        // Usage meter alongside the registry — durable per-database counters
        // (queries, bytes, billed totals) under `CF_DATABASES / usage/*`.
        self.db_usage_meter = if let Some(storage) = &self.storage {
            match tenzro_database::DatabaseUsageMeter::with_storage(
                storage.clone() as Arc<dyn KvStore>,
            ) {
                Ok(meter) => Arc::new(meter),
                Err(e) => {
                    warn!("Database usage meter hydration failed ({e}); starting in-memory");
                    Arc::new(tenzro_database::DatabaseUsageMeter::new())
                }
            }
        } else {
            Arc::new(tenzro_database::DatabaseUsageMeter::new())
        };

        // Engine backends: link the concrete drivers the operator wired up in
        // `[databases]` config (external Postgres/Qdrant/Valkey by URL, embedded
        // Lance/Tantivy under {data_dir}/databases/). A node with no database
        // config serves no engines and the query path answers with a routing
        // error — never a panic.
        let engine_registry = crate::db_engines::build_registry_from_config(
            &self.config.databases,
            &self.config.data_dir,
        );
        let engine_ids = engine_registry.serving_engine_ids();
        if engine_ids.is_empty() {
            info!("Database engine registry: no engines configured");
        } else {
            info!("Database engine registry serving: {}", engine_ids.join(", "));
        }
        self.db_engine_registry = Arc::new(engine_registry);

        // Static-site registry — durable site manifests under `CF_METADATA /
        // site:*`, hydrated on boot.
        let sites_config = crate::sites::SitesConfig::default()
            .with_app_domain(self.config.hosting.app_domain.clone())
            .with_edge_addrs(
                self.config.hosting.edge_ipv4.clone(),
                self.config.hosting.edge_ipv6.clone(),
            );
        self.site_registry = if let Some(storage) = &self.storage {
            match crate::sites::SiteRegistry::with_storage(
                storage.clone() as Arc<dyn KvStore>,
                sites_config,
            ) {
                Ok(registry) => Arc::new(registry),
                Err(e) => {
                    warn!("Site registry hydration failed ({e}); starting in-memory");
                    Arc::new(crate::sites::SiteRegistry::new())
                }
            }
        } else {
            Arc::new(crate::sites::SiteRegistry::new())
        };

        // Dynamic-ingress placement table — durable `site_id → serving-node`
        // records under `CF_METADATA / site_placement:*`, hydrated on boot.
        self.ingress_table = if let Some(storage) = &self.storage {
            match crate::ingress::IngressTable::with_storage(storage.clone() as Arc<dyn KvStore>) {
                Ok(table) => Arc::new(table),
                Err(e) => {
                    warn!("Ingress table hydration failed ({e}); starting in-memory");
                    Arc::new(crate::ingress::IngressTable::new())
                }
            }
        } else {
            Arc::new(crate::ingress::IngressTable::new())
        };

        // Placement scheduler — durable app-hosting leases under
        // `CF_METADATA / hosting_lease:*`, hydrated on boot. Shares the
        // storage-backed ingress table so a placement decision writes the routing
        // table the edge reads.
        self.placement_scheduler = if let Some(storage) = &self.storage {
            match crate::placement::PlacementScheduler::with_storage(
                self.ingress_table.clone(),
                storage.clone() as Arc<dyn KvStore>,
            ) {
                Ok(scheduler) => Arc::new(scheduler),
                Err(e) => {
                    warn!("Placement scheduler hydration failed ({e}); starting in-memory");
                    Arc::new(crate::placement::PlacementScheduler::new(
                        self.ingress_table.clone(),
                    ))
                }
            }
        } else {
            Arc::new(crate::placement::PlacementScheduler::new(
                self.ingress_table.clone(),
            ))
        };

        // Function-runtime registry — durable `wasi:http` component
        // deployments under `CF_METADATA / function:*`, hydrated on boot.
        // The compiled-component cache is not persisted; components are
        // recompiled on first invocation from the content-addressed blob.
        self.function_registry = if let Some(storage) = &self.storage {
            match crate::functions::FunctionRegistry::with_storage(storage.clone() as Arc<dyn KvStore>)
            {
                Ok(registry) => Arc::new(registry),
                Err(e) => {
                    warn!("Function registry hydration failed ({e}); starting in-memory");
                    Arc::new(crate::functions::FunctionRegistry::new())
                }
            }
        } else {
            Arc::new(crate::functions::FunctionRegistry::new())
        };

        // Machine-runtime registry — durable microVM deployments under
        // `CF_METADATA / machine:*`, hydrated on boot. The live Firecracker
        // supervisor (feature-gated) is set later once the iroh resolver and
        // sealing key are available; the registry itself is metadata-only.
        self.machine_registry = if let Some(storage) = &self.storage {
            match crate::machines::MachineRegistry::with_storage(storage.clone() as Arc<dyn KvStore>)
            {
                Ok(registry) => Arc::new(registry),
                Err(e) => {
                    warn!("Machine registry hydration failed ({e}); starting in-memory");
                    Arc::new(crate::machines::MachineRegistry::new())
                }
            }
        } else {
            Arc::new(crate::machines::MachineRegistry::new())
        };

        // Epoch ticker for the function wasm engine. `HttpComponent::serve`
        // sets an epoch deadline per request; the deadline only trips if the
        // engine's global epoch is advanced. One ticker at 1ms granularity
        // drives every function invocation on this node.
        #[cfg(feature = "wasi-skills")]
        {
            let cache = self.function_components.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_millis(1));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    ticker.tick().await;
                    cache.engine().tick_epoch();
                }
            });
        }

        // Register Visa TAP server (RFC 9421 HTTP Message Signatures).
        //
        // The TAP verifier requires an `AgentRegistryClient` to resolve
        // `keyid` parameters to public keys. We pass the TDIP identity
        // registry wrapped in `DidResolverAgentRegistry::did_only` so
        // that DID-form keyids (`did:tenzro:machine:*`) resolve against
        // our local registry. Non-DID keyids are rejected — Tenzro-only
        // mesh until JWKS federation is implemented.
        #[cfg(feature = "visa-tap")]
        {
            use tenzro_payments::rfc9421::TenzroAgentRegistry;
            use tenzro_payments::visa_tap::{DidResolverAgentRegistry, TapVerifier, VisaTapServer};

            if let Some(ref identity_registry) = self.identity_registry {
                let did_resolver = Arc::new(TenzroAgentRegistry::new(identity_registry.clone()));
                let agent_registry = Arc::new(DidResolverAgentRegistry::did_only(did_resolver));
                let visa_tap_server = VisaTapServer::new(
                    "api.tenzro.xyz".to_string(),
                    "0x0000000000000000000000000000000000000001".to_string(),
                    agent_registry.clone(),
                )
                .with_default_asset("TNZO".to_string())
                .with_default_chain("tenzro".to_string())
                .with_challenge_store(challenge_store.clone());
                gateway.register_protocol(Arc::new(visa_tap_server));

                // Standalone recognition verifier over the same agent
                // registry, exposed as the HTTP facilitator on the web API.
                // `@authority` binding is enforced against the same domain
                // the gateway server advertises.
                let verifier =
                    TapVerifier::new(agent_registry).with_domain("api.tenzro.xyz".to_string());
                self.visa_tap_verifier = Some(Arc::new(verifier));

                info!("Registered Visa TAP payment protocol (DID-resolver agent registry)");
            } else {
                warn!("Skipping Visa TAP protocol registration — identity registry not available");
            }
        }

        // Register Mastercard Agent Pay server (KYA + agentic tokens).
        //
        // KYA verification resolves the payer's TDIP identity, and agent
        // signature checks resolve `keyid` DIDs through the same
        // DID-resolver agent registry the Visa TAP path uses. Both require
        // the identity registry, so registration is gated on its presence.
        #[cfg(feature = "mastercard-agent-pay")]
        {
            use tenzro_payments::mastercard::MastercardAgentPayServer;
            use tenzro_payments::rfc9421::TenzroAgentRegistry;
            use tenzro_payments::visa_tap::DidResolverAgentRegistry;

            if let Some(ref identity_registry) = self.identity_registry {
                let did_resolver = Arc::new(TenzroAgentRegistry::new(identity_registry.clone()));
                let agent_registry = Arc::new(DidResolverAgentRegistry::did_only(did_resolver));
                let mastercard_server = MastercardAgentPayServer::new(
                    "0x0000000000000000000000000000000000000001",
                    "tenzro-network",
                    agent_registry,
                    identity_registry.clone(),
                )
                .with_default_asset("TNZO")
                .with_default_chain("tenzro")
                .with_challenge_store(challenge_store.clone());
                gateway.register_protocol(Arc::new(mastercard_server));
                info!("Registered Mastercard Agent Pay payment protocol (DID-resolver agent registry)");
            } else {
                warn!("Skipping Mastercard Agent Pay protocol registration — identity registry not available");
            }
        }

        info!("Registered payment protocols: {:?}", gateway.supported_protocols());

        // Wire on-chain settlement callback: TNZO settlements move balance
        // consensus-mediated via a system-key signed `X402Settle` tx that lands
        // in a finalized block, with the SettlementEngine kept audit-only. The
        // consensus-mediated path requires the consensus engine, the composite
        // (Ed25519 + ML-DSA-65) signer, the system address, and storage — all
        // set during `init_consensus`, which runs before `init_payments`.
        let gateway = if let (
            Some(consensus),
            Some(hybrid_signer),
            Some(system_addr),
            Some(storage),
            Some(settlement),
        ) = (
            self.consensus.clone(),
            self.validator_hybrid_signer.clone(),
            self.local_validator_address,
            self.storage.clone(),
            self.settlement.clone(),
        ) {
            let chain_id = self
                .config
                .genesis
                .as_ref()
                .map(|g| g.chain_id)
                .unwrap_or(1337);
            let callback = Arc::new(TnzoSettlementCallback::new(
                consensus,
                hybrid_signer,
                system_addr,
                storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                chain_id,
                settlement,
                self.provider_manager.clone(),
            ));
            // Stash the deferred event-sender slot so `start()` can populate it
            // after the event loop starts (enables gossip of admitted settle txs).
            self.x402_settle_event_slot = Some(callback.event_sender_slot());
            info!("Payment gateway wired to consensus-mediated TNZO settlement (X402Settle)");
            gateway.with_settlement_callback(callback)
        } else {
            warn!("Payment gateway initialized without on-chain settlement — consensus, signer, system address, storage, or settlement engine not available");
            gateway
        };

        // Attach the stable-unit conversion hook so an agent can spend a
        // stable unit while the payee settles in another asset; the gateway
        // resolves the rate via the oracle between protocol and on-chain
        // settle. Direct-token payments (from==to) pass through untouched.
        let conversion_hook = Arc::new(crate::stable_conversion::OracleConversionHook::new(
            self.stable_rate_oracle.clone(),
        ));
        let gateway = gateway.with_conversion_hook(conversion_hook);
        info!("Payment gateway wired to stable-unit conversion hook");

        self.payment_gateway = Some(Arc::new(gateway));
        self.health_monitor.mark_healthy("payments");

        Ok(())
    }

    /// Initializes the AgentKit runtime and bootstraps reference templates.
    /// Non-fatal: logs warnings on failure so the node still starts.
    ///
    /// The reference-template bootstrap is dispatched as a background task
    /// that waits for the RPC server to bind on `rpc_addr` before issuing
    /// the `tenzro_registerAgentTemplate` calls. This is necessary because
    /// `Self::start()` runs to completion *before* `main.rs` spawns the
    /// RPC server (line 234 in `main.rs`) — calling the RPC inline from
    /// `start()` produces `rpc transport error: connection refused` on
    /// every template. The deferred task polls TCP connect against
    /// `rpc_addr` for up to 30s before giving up.
    async fn bootstrap_agent_templates(&mut self) {
        let rpc_addr = if self.config.rpc_addr.is_empty() {
            "127.0.0.1:8545".to_string()
        } else {
            self.config.rpc_addr.clone()
        };
        let rpc_url = format!("http://{rpc_addr}");

        // Build the AgentKit instance if both identity_registry and agent_runtime are available.
        // This is purely in-process state — does not touch the RPC, so it stays inline.
        if let (Some(identity_registry), Some(agent_runtime)) =
            (self.identity_registry.clone(), self.agent_runtime.clone())
        {
            // Wire the canonical `AuthIssuer` adapter (`NodeAuthIssuer`)
            // when the `AuthEngine` is available. `init_auth()` runs
            // earlier in `start()` so by the time we land here the
            // engine is either present and ready, or the operator
            // explicitly disabled auth — in which case every
            // authenticated dispatch step (EVM / SVM / DAML) on the
            // spawned agent will fail loudly per `auth.rs` docstring.
            // We never silently fall back to an unauthenticated path.
            let kit = if let Some(engine) = self.auth_engine.clone() {
                let issuer: std::sync::Arc<dyn tenzro_agent_kit::AuthIssuer> =
                    std::sync::Arc::new(crate::agent_kit_auth::NodeAuthIssuer::new(engine));
                info!("AgentKit wired with NodeAuthIssuer (DPoP-bound credentials enabled)");
                tenzro_agent_kit::AgentKit::with_auth_issuer(
                    rpc_url.clone(),
                    identity_registry.clone(),
                    agent_runtime.clone(),
                    issuer,
                )
            } else {
                warn!(
                    "AgentKit initialized WITHOUT AuthIssuer — \
                     spawned agents will not receive DPoP-bound credentials; \
                     authenticated dispatch steps will fail at runtime"
                );
                tenzro_agent_kit::AgentKit::new(
                    rpc_url.clone(),
                    identity_registry.clone(),
                    agent_runtime.clone(),
                )
            };
            self.agent_kit = Some(Arc::new(kit));
            info!("AgentKit runtime initialized");

            // Phase B Thread 3 / B.3.5 — AA validator registry + IdentityScopeOracle.
            // The oracle does a fresh `IdentityRegistry::resolve(did)` on every
            // `lookup`, so a `DelegationScope` revoked between install time and
            // signing time fails the validator at signing time (the literal
            // B.3.5 acceptance criterion). Same `(identity_registry,
            // agent_runtime)` Arcs as AgentKit — same guarantees apply.
            //
            // The registry is in-memory: per-account installs are
            // re-built from on-chain `InstalledModule` logs once
            // `EntryPoint` is wired through the EVM execution path (#165).
            let scope_oracle = Arc::new(
                crate::delegation_scope_oracle::IdentityScopeOracle::new(
                    identity_registry,
                    agent_runtime,
                ),
            );
            let aa_registry = Arc::new(
                tenzro_vm::aa_validators::ValidatorRegistry::new(),
            );

            // Autonomous-machine custody: TEE-key oracle. Resolves a smart
            // account to its enrolled `TeeBoundAccountKey`. Backed by
            // `TeeEnrollmentKvStore` (CF_VALIDATOR_MODULES under
            // `erc7579/tee_enrollment/`) so enrollments survive restart;
            // hydrated on construction. Shared by the `TeeBoundValidator`
            // (module 0x1021) and the `TnzoBootstrapPaymaster`.
            let tee_key_oracle = if let Some(ref storage) = self.storage {
                let store = Arc::new(crate::passkey_rpc::TeeEnrollmentKvStore::new(
                    storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                ));
                Arc::new(tenzro_vm::InMemoryTeeKeyOracle::with_store(store))
            } else {
                Arc::new(tenzro_vm::InMemoryTeeKeyOracle::new())
            };
            self.tee_key_oracle = Some(tee_key_oracle.clone());

            // Seed the ERC-7484 attestation gate for our `DelegationScopeValidator`
            // module address. Without this, every `aa_registry.install(...)` for
            // the validator would fail with `ModuleNotAttested`. The attester
            // address is the all-zero placeholder for the protocol-issued
            // attestation; in production, on-chain `attestModule` calls from
            // approved auditors land here via the EVM execution path (#165).
            let dsv_address =
                crate::delegation_scope_oracle::delegation_scope_validator_module_address();
            aa_registry.attestations().attest(
                tenzro_vm::aa_validators::ModuleAttestation {
                    module_address: dsv_address,
                    module_type: tenzro_vm::aa_validators::ModuleType::Validator,
                    registry: *aa_registry.trusted_registry(),
                    attester: [0u8; 20],
                    attestation_data: b"tenzro-protocol-attestation".to_vec(),
                    revoked: false,
                },
            );

            self.identity_scope_oracle = Some(scope_oracle.clone());
            self.aa_validator_registry = Some(aa_registry.clone());
            info!(
                dsv_address = %hex::encode(dsv_address),
                "AA ValidatorRegistry + IdentityScopeOracle initialized; DelegationScopeValidator attested (Phase B B.3.5)"
            );

            // Passkey-first custody substrate: AccountFactory + the four
            // ERC-7579 validators (WebAuthn + SocialRecovery + SessionKey +
            // SpendingLimit) all wired with persistence to CF_VALIDATOR_MODULES.
            // The factory's deterministic address (`0x0000...0400`) is the
            // canonical Tenzro AccountFactory precompile — every smart account
            // deployed via `tenzro_enrollPasskey` is created here and inherits
            // the per-account validator install set from these validators.
            let factory_address = {
                let mut a = [0u8; 20];
                a[18] = 0x04; // 0x0000...0400
                a.to_vec()
            };
            let account_factory = if let Some(ref storage) = self.storage {
                Arc::new(tenzro_vm::AccountFactory::with_storage(
                    factory_address,
                    storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                ))
            } else {
                Arc::new(tenzro_vm::AccountFactory::new(factory_address))
            };
            self.account_factory = Some(account_factory.clone());

            let webauthn_origin = std::env::var("TENZRO_WEBAUTHN_ORIGIN")
                .unwrap_or_else(|_| "https://wallet.tenzro.xyz".to_string());
            let webauthn_module_addr = {
                let mut a = [0u8; 20];
                a[18] = 0x10; a[19] = 0x20;
                a
            };
            let webauthn_validator = if let Some(ref storage) = self.storage {
                Arc::new(tenzro_vm::WebAuthnValidator::with_storage(
                    webauthn_module_addr,
                    webauthn_origin.clone(),
                    storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                ))
            } else {
                Arc::new(tenzro_vm::WebAuthnValidator::new(
                    webauthn_module_addr,
                    webauthn_origin.clone(),
                ))
            };
            self.webauthn_validator = Some(webauthn_validator.clone());

            let social_module_addr = {
                let mut a = [0u8; 20];
                a[18] = 0x10; a[19] = 0x1d;
                a
            };
            let social_validator = if let Some(ref storage) = self.storage {
                Arc::new(tenzro_vm::SocialRecoveryValidator::with_storage(
                    social_module_addr,
                    storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                ))
            } else {
                Arc::new(tenzro_vm::SocialRecoveryValidator::new(social_module_addr))
            };
            self.social_recovery_validator = Some(social_validator.clone());

            let session_module_addr = {
                let mut a = [0u8; 20];
                a[18] = 0x10; a[19] = 0x1e;
                a
            };
            let session_validator = if let Some(ref storage) = self.storage {
                Arc::new(tenzro_vm::SessionKeyValidator::with_storage(
                    session_module_addr,
                    storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                ))
            } else {
                Arc::new(tenzro_vm::SessionKeyValidator::new(session_module_addr))
            };
            self.session_key_validator = Some(session_validator.clone());

            let spending_module_addr = {
                let mut a = [0u8; 20];
                a[18] = 0x10; a[19] = 0x1f;
                a
            };
            let spending_validator = if let Some(ref storage) = self.storage {
                Arc::new(tenzro_vm::SpendingLimitValidator::with_storage(
                    spending_module_addr,
                    storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                ))
            } else {
                Arc::new(tenzro_vm::SpendingLimitValidator::new(spending_module_addr))
            };
            self.spending_limit_validator = Some(spending_validator.clone());

            // Hardware-signer validators (Ledger / Trezor / GridPlus / YubiKey
            // / Generic). Each device kind gets its own module address +
            // its own `HardwareSignerValidator` instance so multiple hardware
            // signers can coexist on the same smart account. Per-account
            // configs persist to `CF_VALIDATOR_MODULES / erc7579/hardware/<module>/<account>`
            // via `with_storage`.
            let hardware_module_addrs = [
                tenzro_vm::erc7579::HARDWARE_VALIDATOR_LEDGER,
                tenzro_vm::erc7579::HARDWARE_VALIDATOR_TREZOR,
                tenzro_vm::erc7579::HARDWARE_VALIDATOR_GRIDPLUS,
                tenzro_vm::erc7579::HARDWARE_VALIDATOR_YUBIKEY,
                tenzro_vm::erc7579::HARDWARE_VALIDATOR_GENERIC,
            ];
            let mut hardware_validators = Vec::with_capacity(hardware_module_addrs.len());
            for hw_addr in &hardware_module_addrs {
                let v = if let Some(ref storage) = self.storage {
                    Arc::new(tenzro_vm::erc7579::HardwareSignerValidator::with_storage(
                        *hw_addr,
                        storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                    ))
                } else {
                    Arc::new(tenzro_vm::erc7579::HardwareSignerValidator::new(*hw_addr))
                };
                hardware_validators.push(v);
            }
            self.hardware_signer_validators = Some(hardware_validators);

            // Autonomous-machine custody: TEE-bound validator (module 0x1021).
            // Gates every UserOp on a fresh, key-bound TEE attestation resolved
            // via the shared `tee_key_oracle`. Shares one `AttestationVerifier`
            // with the bootstrap paymaster so both apply the same vendor
            // root-CA + measurement-binding chain. The validator holds no
            // per-account state of its own (the oracle is the source of
            // truth), so no `with_storage` variant is needed.
            let tee_attestation_verifier =
                Arc::new(tenzro_tee::AttestationVerifier::new());
            let tee_bound_module_addr = {
                let mut a = [0u8; 20];
                a[18] = 0x10; a[19] = 0x21;
                a
            };
            let tee_bound_validator = Arc::new(tenzro_vm::TeeBoundValidator::new(
                tee_bound_module_addr,
                tee_key_oracle.clone() as Arc<dyn tenzro_vm::TeeKeyOracle>,
                tee_attestation_verifier.clone(),
            ));
            self.tee_bound_validator = Some(tee_bound_validator.clone());

            // Attest the ERC-7579 modules (WebAuthn / social / session /
            // spending) + the TEE-bound validator + the hardware-validator
            // slots so the registry accepts installs against them.
            let mut to_attest = vec![
                webauthn_module_addr,
                social_module_addr,
                session_module_addr,
                spending_module_addr,
                tee_bound_module_addr,
            ];
            to_attest.extend_from_slice(&hardware_module_addrs);
            for module_addr in to_attest {
                aa_registry.attestations().attest(
                    tenzro_vm::aa_validators::ModuleAttestation {
                        module_address: module_addr,
                        module_type: tenzro_vm::aa_validators::ModuleType::Validator,
                        registry: *aa_registry.trusted_registry(),
                        attester: [0u8; 20],
                        attestation_data: b"tenzro-protocol-attestation".to_vec(),
                        revoked: false,
                    },
                );
            }

            // Pending-recovery store for the social-recovery guardian-quorum
            // flow. Persists in-progress recoveries to CF_VALIDATOR_MODULES so
            // they survive node restart.
            if let Some(ref storage) = self.storage {
                let store = Arc::new(crate::passkey_rpc::PendingRecoveryStore::with_storage(
                    storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                ));
                self.recovery_pending = Some(store);
                self.passkey_sessions =
                    Some(Arc::new(crate::passkey_rpc::PasskeySessionStore::with_storage(
                        storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                    )));
            }

            info!(
                webauthn_origin = %webauthn_origin,
                factory_addr = "0x0000...0400",
                "Passkey-first custody substrate initialized — WebAuthnValidator, \
                 SocialRecoveryValidator, SessionKeyValidator, SpendingLimitValidator, \
                 AccountFactory, PendingRecoveryStore all wired with persistence"
            );

            // Phase B Thread 3c / #165 — wire the ERC-4337 v0.8 EntryPoint
            // singleton. Bound to the AA registry (validator dispatch) and the
            // multi-VM runtime (UserOp `call_data` execution). Storage backs
            // nonce + receipt persistence to `CF_AGENTS` under `aa/nonce/` and
            // `aa/receipt/` prefixes; `hydrate_nonces()` restores the in-memory
            // nonce table on every node restart so replay protection survives.
            //
            // Address `0x4337084d9e255ff0702461cf8895ce9e3b5ff108` is the
            // canonical ERC-4337 v0.8 EntryPoint deployment address — used here
            // as the EIP-712 verifying-contract field for UserOp hashing so
            // off-chain bundlers / SDKs that expect the same address sign
            // hashes that match what the node will verify.
            if let Some(ref vm_runtime) = self.vm_runtime {
                let chain_id = self
                    .config
                    .genesis
                    .as_ref()
                    .map(|g| g.chain_id)
                    .unwrap_or(1337);
                let ep_address: Vec<u8> = hex::decode(
                    "4337084d9e255ff0702461cf8895ce9e3b5ff108",
                )
                .expect("hardcoded EntryPoint address is valid hex");
                let mut entry_point = tenzro_vm::EntryPoint::new(ep_address)
                    .with_chain_id(chain_id)
                    .with_validator_registry(aa_registry.clone())
                    .with_runtime(vm_runtime.clone());
                if let Some(ref storage) = self.storage {
                    entry_point = entry_point.with_storage(
                        storage.clone() as Arc<dyn KvStore>,
                    );
                    match entry_point.hydrate_nonces() {
                        Ok(restored) => info!(
                            restored_nonces = restored,
                            "EntryPoint nonces hydrated from CF_AGENTS"
                        ),
                        Err(e) => tracing::warn!(
                            error = %e,
                            "EntryPoint nonce hydration failed; starting with empty nonce table"
                        ),
                    }
                }

                // Autonomous-machine custody: bootstrap paymaster. Sponsors an
                // agent's FIRST UserOp (the account-creation `factory` call)
                // iff the sender is (a) enrolled in the TEE-key oracle, (b)
                // ERC-8004-registered, and (c) accompanied by a fresh
                // attestation binding the enclave key + measurement to the
                // enrolled account key. One-shot per agent — the
                // `TeeBoundValidator` (0x1021) enforces every op thereafter.
                //
                // The paymaster is only wired when storage is present (so the
                // ERC-8004 owner-index it reads is durable). Initial balance
                // comes from `TENZRO_BOOTSTRAP_PAYMASTER_BALANCE` (base units);
                // absent/zero means unfunded — `sponsor()` fails closed until
                // the operator tops it up via the treasury.
                if let Some(ref storage) = self.storage {
                    let paymaster_address = {
                        let mut a = [0u8; 20];
                        a[18] = 0x04; a[19] = 0x02; // 0x0000...0402
                        a.to_vec()
                    };
                    let initial_balance: u128 =
                        std::env::var("TENZRO_BOOTSTRAP_PAYMASTER_BALANCE")
                            .ok()
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                    let registry_lookup =
                        Arc::new(crate::erc8004_mirror::Erc8004OwnerRegistryLookup::new(
                            storage.clone() as Arc<dyn tenzro_storage::KvStore>,
                        ));
                    let bootstrap_paymaster =
                        tenzro_vm::TnzoBootstrapPaymaster::new(
                            paymaster_address,
                            initial_balance,
                            tee_key_oracle.clone() as Arc<dyn tenzro_vm::TeeKeyOracle>,
                            registry_lookup as Arc<dyn tenzro_vm::AgentRegistryLookup>,
                            tee_attestation_verifier.clone(),
                        );
                    entry_point = entry_point.with_bootstrap_paymaster(Arc::new(
                        parking_lot::RwLock::new(bootstrap_paymaster),
                    ));
                    info!(
                        paymaster_addr = "0x0000...0402",
                        initial_balance,
                        "Autonomous-machine bootstrap paymaster wired to EntryPoint \
                         (TEE-gated one-shot first-op sponsorship)"
                    );
                }

                self.aa_entry_point = Some(Arc::new(entry_point));
                info!(
                    chain_id = chain_id,
                    "ERC-4337 v0.8 EntryPoint initialized (Phase B Thread 3c / #165)"
                );
            } else {
                tracing::warn!(
                    "EntryPoint not initialized: vm_runtime unavailable"
                );
            }
        } else {
            tracing::warn!(
                "AgentKit not initialized: identity_registry or agent_runtime unavailable"
            );
        }

        // Defer the actual registry bootstrap until after the RPC server
        // is listening. main.rs spawns the RPC server after start() returns,
        // so issuing RPCs inline here always fails with connection refused.
        let probe_addr = rpc_addr.clone();
        tokio::spawn(async move {
            // Wait up to 30s for the RPC listener to accept connections.
            // main.rs spawns the RPC server after node.start() returns, so we
            // must poll until the listener binds before issuing any RPCs.
            let timeout = std::time::Duration::from_secs(30);
            let backoff = std::time::Duration::from_millis(250);
            let deadline = std::time::Instant::now() + timeout;
            let mut connected = false;
            while std::time::Instant::now() < deadline {
                match tokio::net::TcpStream::connect(&probe_addr).await {
                    Ok(_) => { connected = true; break; }
                    Err(_) => tokio::time::sleep(backoff).await,
                }
            }
            if !connected {
                tracing::warn!(
                    rpc_addr = %probe_addr,
                    "RPC server did not bind within 30s — skipping reference-template bootstrap"
                );
                return;
            }
            let registry = std::sync::Arc::new(tenzro_agent_kit::RegistryClient::new(rpc_url));
            match tenzro_agent_kit::bootstrap_reference_templates(&registry).await {
                Ok(report) => {
                    if !report.published.is_empty() {
                        info!(
                            published = report.published.len(),
                            skipped = report.skipped.len(),
                            "Bootstrapped reference agent templates"
                        );
                    } else {
                        tracing::debug!(
                            skipped = report.skipped.len(),
                            "All reference agent templates already registered"
                        );
                    }
                    for (label, err) in &report.failed {
                        tracing::warn!(
                            template = %label,
                            error = %err,
                            "Failed to bootstrap template"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Agent template bootstrap failed (non-fatal)"
                    );
                }
            }
        });
    }

    /// Bootstrap ecosystem MCP server tools and skills into CF_TOOLS / CF_SKILLS.
    /// Idempotent: skips entries that already exist (matched by name).
    fn bootstrap_ecosystem_tools_and_skills(&self) {
        let storage = match self.storage.as_ref() {
            Some(s) => s,
            None => {
                tracing::warn!("Storage not available, skipping ecosystem tool/skill bootstrap");
                return;
            }
        };

        // ─── Tools (MCP servers) ───
        let tools: Vec<(&str, &str, &str, &str, &[&str])> = vec![
            // (name, tool_type, endpoint, description, capabilities)
            ("tenzro-solana-mcp", "mcp", "/mcp", "Solana blockchain tools — DeFi (Jupiter), tokens (SPL), NFTs (Metaplex), network queries", &["solana", "defi", "swap", "nft", "spl"]),
            ("tenzro-ethereum-mcp", "mcp", "/mcp", "Ethereum blockchain tools — DeFi, ERC-20/721, ENS, ERC-8004 agent registry, EAS attestations", &["ethereum", "defi", "erc20", "ens", "erc8004", "eas"]),
            ("tenzro-canton-mcp", "mcp", "/mcp", "Canton Network / DAML tools — smart contracts, parties, CIP-56 tokens, DvP settlement, tokenized assets", &["canton", "daml", "enterprise", "tokenization", "dvp"]),
            ("tenzro-layerzero-mcp", "mcp", "/mcp", "LayerZero V2 cross-chain messaging — fee quoting, message tracking, OFT transfers, DVN configuration", &["layerzero", "cross-chain", "bridge", "omnichain", "oft"]),
            ("tenzro-chainlink-mcp", "mcp", "/mcp", "Chainlink tools — CCIP cross-chain messaging, data feeds (price oracles), automation, functions", &["chainlink", "ccip", "oracle", "data-feeds", "automation"]),
            ("debridge-mcp", "mcp", "https://agents.debridge.com/mcp", "deBridge DLN cross-chain swaps — intent-based bridging, order creation, tracking. Official hosted MCP.", &["debridge", "cross-chain", "bridge", "dln", "swap"]),
            ("1inch-mcp", "mcp", "https://api.1inch.com", "1inch DEX aggregator — swap across 400+ DEXes, Fusion+ cross-chain, portfolio tracking. Requires API key.", &["1inch", "dex", "aggregator", "swap", "defi", "fusion"]),
        ];

        let mut tool_registered = 0u32;
        let mut tool_skipped = 0u32;

        for (name, tool_type, endpoint, description, caps) in &tools {
            // Check if already exists by scanning for matching name
            let existing = storage.get_keys_with_prefix(CF_TOOLS, b"").ok().unwrap_or_default();
            let already_exists = existing.iter().any(|key| {
                if let Ok(Some(bytes)) = storage.get(CF_TOOLS, key)
                    && let Ok(t) = serde_json::from_slice::<tenzro_types::ToolDefinition>(&bytes) {
                        return t.name == *name;
                    }
                false
            });

            if already_exists {
                tool_skipped += 1;
                continue;
            }

            let category = if caps.contains(&"cross-chain") || caps.contains(&"bridge") {
                "bridge"
            } else if caps.contains(&"defi") || caps.contains(&"swap") || caps.contains(&"dex") {
                "defi"
            } else if caps.contains(&"enterprise") || caps.contains(&"daml") {
                "enterprise"
            } else if caps.contains(&"oracle") {
                "oracle"
            } else {
                "blockchain"
            };

            let mut tool = tenzro_types::ToolDefinition::new(
                name.to_string(),
                "0.1.0".to_string(),
                tool_type.to_string(),
                endpoint.to_string(),
                description.to_string(),
                category.to_string(),
            );
            tool.capabilities = caps.iter().map(|s| s.to_string()).collect();
            tool.creator_did = Some("did:tenzro:human:tenzro-network".to_string());

            if let Ok(bytes) = serde_json::to_vec(&tool)
                && storage.put(CF_TOOLS, tool.tool_id.as_bytes(), &bytes).is_ok() {
                    tool_registered += 1;
                }
        }

        // ─── Skills ───
        let skills: Vec<(&str, &str, &[&str], &str)> = vec![
            // (name, description, tags, category)
            ("solana-defi", "Solana DeFi — swap via Jupiter, get prices, stake SOL, query balances, transfer SPL tokens, browse NFTs via Metaplex DAS, resolve .sol domains", &["solana", "defi", "swap", "jupiter", "nft", "metaplex", "spl", "staking"], "defi"),
            ("ethereum-defi", "Ethereum DeFi — query balances, Chainlink prices, estimate gas, resolve ENS, call smart contracts, ABI-encode, ERC-8004 agent registry, EAS attestations", &["ethereum", "defi", "erc20", "ens", "chainlink", "erc8004", "eas", "smart_contracts"], "defi"),
            ("canton-enterprise", "Canton enterprise — DAML contracts, party management, CIP-56 tokens, tokenized assets, atomic DvP settlement, DAR uploads", &["canton", "daml", "enterprise", "tokenization", "dvp", "cip56", "rwa", "institutional"], "enterprise"),
            ("layerzero-bridge", "LayerZero V2 cross-chain — quote messaging fees, send omnichain messages, track delivery, OFT transfers, list DVNs, encode options", &["layerzero", "cross-chain", "bridge", "omnichain", "oft", "messaging"], "bridge"),
            ("chainlink-oracle", "Chainlink — CCIP cross-chain messaging, price data feeds, automation upkeeps, Functions (DON serverless)", &["chainlink", "ccip", "cross-chain", "oracle", "data-feeds", "automation", "functions"], "oracle"),
            ("debridge-cross-chain", "deBridge DLN — intent-based cross-chain bridging, get quotes, create orders, track status, list supported chains/tokens", &["debridge", "cross-chain", "bridge", "dln", "intent", "swap"], "bridge"),
            ("oneinch-aggregator", "1inch DEX aggregator — swap tokens across 400+ DEXes, get quotes, check approvals, Fusion+ cross-chain, portfolio tracking", &["1inch", "dex", "aggregator", "swap", "defi", "fusion", "cross-chain"], "defi"),
        ];

        let mut skill_registered = 0u32;
        let mut skill_skipped = 0u32;

        for (name, description, tags, category) in &skills {
            let existing = storage.get_keys_with_prefix(CF_SKILLS, b"").ok().unwrap_or_default();
            let already_exists = existing.iter().any(|key| {
                if let Ok(Some(bytes)) = storage.get(CF_SKILLS, key)
                    && let Ok(s) = serde_json::from_slice::<tenzro_types::SkillDefinition>(&bytes) {
                        return s.name == *name;
                    }
                false
            });

            if already_exists {
                skill_skipped += 1;
                continue;
            }

            let mut skill = tenzro_types::SkillDefinition::new(
                name.to_string(),
                "0.1.0".to_string(),
                "did:tenzro:human:tenzro-network".to_string(),
                description.to_string(),
                0, // free for now
            );
            skill.tags = tags.iter().map(|s| s.to_string()).collect();
            skill.category = category.to_string();

            if let Ok(bytes) = serde_json::to_vec(&skill)
                && storage.put(CF_SKILLS, skill.skill_id.as_bytes(), &bytes).is_ok() {
                    skill_registered += 1;
                }
        }

        if tool_registered > 0 || skill_registered > 0 {
            info!(
                tools_registered = tool_registered,
                tools_skipped = tool_skipped,
                skills_registered = skill_registered,
                skills_skipped = skill_skipped,
                "Bootstrapped ecosystem tools and skills"
            );
        } else {
            tracing::debug!(
                tools_skipped = tool_skipped,
                skills_skipped = skill_skipped,
                "All ecosystem tools and skills already registered"
            );
        }
    }

    async fn init_event_loop(&mut self) -> Result<()> {
        info!("Initializing event loop...");

        // Ensure required subsystems are initialized
        let storage = self.storage.as_ref()
            .ok_or_else(|| NodeError::Internal("Storage not initialized".to_string()))?
            .clone();

        let vm_runtime = self.vm_runtime.as_ref()
            .ok_or_else(|| NodeError::Internal("VM runtime not initialized".to_string()))?
            .clone();

        // Create event loop with optional consensus and network.
        // Pass the shared chain_tip atomic so the event loop can update it on
        // every finalized block — enabling lock-free RPC reads via chain_tip_height().
        let event_loop = EventLoop::new(
            storage,
            vm_runtime,
            self.consensus.clone(),
            self.network.clone(),
            self.chain_tip.clone(),
            self.metrics.clone(),
        );

        // Every role holds a consensus engine so block-sync can check each
        // block's commit-QC against the validator set active at that height,
        // so engine presence does not answer "do I propose and vote". The role
        // does.
        let event_loop =
            event_loop.with_consensus_participation(self.config.roles.is_validator());

        // Wire the weak-subjectivity checkpoint (if configured) so the
        // block-sync import path rejects any historical fork whose committed
        // state root at the anchor height diverges from the trusted value.
        let event_loop = if let Some((height, root)) = self.weak_subjectivity_anchor {
            event_loop.with_weak_subjectivity_anchor(height, tenzro_types::Hash::new(root))
        } else {
            event_loop
        };

        // Wire outbound consensus messages into the event loop so that votes
        // and proposals produced by HotStuff-2 are broadcast over gossipsub.
        // `take()` ensures the RX is consumed exactly once.
        let event_loop = if let Some(rx) = self.consensus_out_rx.take() {
            event_loop.with_consensus_out_rx(rx)
        } else {
            event_loop
        };

        // Wire model services for periodic cleanup of expired network endpoints
        let event_loop = event_loop.with_model_services(self.model_services.clone());

        // Wire ModelRuntime + LoadTracker into the event loop so the heartbeat
        // can run the 1-hour idle TTL reconciler against live runtime state.
        let event_loop = if let Some(ref runtime) = self.model_runtime {
            event_loop.with_model_runtime(runtime.clone(), self.load_tracker.clone())
        } else {
            event_loop
        };

        // Wire model discovery state into the event loop for P2P model announcements
        let event_loop = event_loop.with_model_discovery(
            self.network_models.clone(),
            self.served_models.clone(),
            self.provider_pricing.clone(),
            self.provider_schedule.clone(),
            self.config.rpc_addr.clone(),
        );

        // Wire agent runtime into event loop for gossipsub agent heartbeat announcements
        let event_loop = if let Some(ref ar) = self.agent_runtime {
            event_loop.with_agent_runtime(ar.clone())
        } else {
            event_loop
        };

        // Wire swarm manager into event loop for periodic liveness sweep.
        let event_loop = if let Some(ref sm) = self.swarm_manager {
            event_loop.with_swarm_manager(sm.clone())
        } else {
            event_loop
        };

        // Wire the ZK quorum store so closed fraud windows are pruned on each
        // finalized-block advance.
        let event_loop = if let Some(ref zq) = self.zk_quorum_store {
            event_loop.with_zk_quorum_store(zq.clone())
        } else {
            event_loop
        };

        // Wire network_agents map for gossipsub-discovered agent merging
        let event_loop = event_loop.with_agent_discovery(self.network_agents.clone());

        // Wire network_providers map for gossipsub-discovered provider merging
        let mut event_loop = event_loop.with_provider_discovery(self.network_providers.clone());

        // Bridge verified provider announcements into the ProviderManager so
        // the InferenceRouter (which dispatches chat traffic) sees them with
        // their advertised HardwareCapabilities. Absent on nodes with no
        // router (light clients that never route inference).
        if let Some(ref pm) = self.provider_manager {
            event_loop = event_loop.with_provider_manager(pm.clone());
        }

        // Wire the node's Ed25519 announce signer, loaded once in step 6b.
        // NOTE: this is a DIFFERENT keypair from the libp2p transport key
        // that derives peer_id (`{data_dir}/p2p_key`) — consumers bind
        // announcements to the announce pubkey via first-seen pinning, not
        // via peer_id derivation. Signs every outbound model, provider, and
        // agent announcement. Absent when no key is provisioned — the node
        // simply doesn't self-announce (peers drop unsigned announcements).
        if let Some(signer) = self.announce_signer.clone() {
            event_loop = event_loop.with_announce_signer(signer);
        } else {
            warn!(
                "Skipping announcement signing setup — no node Ed25519 signer \
                 (announcements require a provisioned key)"
            );
        }

        // Wire provider announcement broadcast context. Only providers (model
        // / TEE / storage / validator) self-announce; light clients stay
        // anonymous on this topic. Hardware is detected once at startup; the
        // served-models snapshot is re-read from the live `Arc<DashMap>` at
        // each tick.
        if self.config.roles.is_provider()
            || self.config.roles.is_validator()
            || self.config.roles.serves_edge()
        {
            // The probe shells out to vendor tools (nvidia-smi / rocm-smi /
            // sysctl) synchronously — keep it off the async executor.
            let mut hardware =
                tokio::task::spawn_blocking(tenzro_types::HardwareCapabilities::detect)
                    .await
                    .unwrap_or_default();
            // `config.tee_enabled` is the operator's intent; presence of an
            // initialized `tee_provider` means the runtime probe at startup
            // succeeded. Both must hold before we advertise TEE availability
            // to peers.
            hardware.tee_available = self.config.tee_enabled && self.tee_provider.is_some();

            let provider_address = self
                .operator_payee()
                .map(|addr| format!("0x{}", hex::encode(addr.as_bytes())))
                .unwrap_or_default();

            // A multi-role node advertises every capability it serves. The
            // `provider_type` string is a coarse routing hint; we pick the
            // most specific service role the node fills, falling back to
            // "general" for a validator-only node.
            let mut capabilities: Vec<String> = Vec::new();
            if self.config.roles.serves_ai() {
                capabilities.push("inference".to_string());
            }
            if self.config.roles.serves_tee() {
                capabilities.push("tee-attestation".to_string());
                capabilities.push("confidential-compute".to_string());
            }
            if self.config.roles.serves_compute() {
                // The renter brings their own work, so this says only that the
                // accelerator is for hire — not what runs on it.
                capabilities.push("accelerator-rental".to_string());
            }
            if self.config.roles.serves_cloud() {
                capabilities.push("site-hosting".to_string());
                capabilities.push("function-hosting".to_string());
            }
            if self.config.roles.serves_storage() {
                capabilities.push("storage".to_string());
            }
            if self.config.roles.is_validator() {
                capabilities.push("consensus".to_string());
            }
            if self.config.roles.serves_edge() {
                // Serving nodes read this to discover which peers can terminate
                // public TLS and front them over the `tenzro/http` ALPN.
                capabilities.push("edge-ingress".to_string());
            }
            let provider_type: &str = if self.config.roles.serves_ai() {
                "llm"
            } else if self.config.roles.serves_tee() {
                "tee"
            } else if self.config.roles.serves_compute() {
                "compute"
            } else if self.config.roles.serves_cloud() {
                "cloud"
            } else if self.config.roles.serves_storage() {
                "storage"
            } else if self.config.roles.serves_edge() {
                "edge"
            } else {
                "general"
            };

            let rpc_endpoint = self
                .config
                .external_rpc_addr
                .clone()
                .unwrap_or_else(|| format!("http://{}", self.config.rpc_addr));

            // Cluster-serving profile: only AI-serving nodes advertise the
            // facts a LAN pipeline head needs to admit them as a member (the
            // llama.cpp commit + serving device backend / capability key).
            // Absent on non-AI nodes, so they are never auto-clustered.
            let cluster_profile = if self.config.roles.serves_ai() {
                let profile = tenzro_model::cluster::detect_node_profile();
                Some(tenzro_types::ClusterProfile {
                    llama_commit: profile.llama_commit.clone(),
                    backend: profile.serving_backend().ggml_name().to_string(),
                    cap_key: profile.serving_cap_key(),
                })
            } else {
                None
            };

            // Advertised serving capacity: read the node's own registered
            // provider entry if it has one, else fall back to the default
            // envelope. Only the numeric throughput/concurrency subset is
            // carried on gossip.
            let mut capacity = self
                .provider_manager
                .as_ref()
                .and_then(|pm| {
                    Address::from_hex(provider_address.strip_prefix("0x").unwrap_or(&provider_address))
                        .ok()
                        .and_then(|addr| pm.get_provider(&addr).ok())
                })
                .map(|p| p.capacity.advertised())
                .unwrap_or_else(|| tenzro_types::ProviderCapacity::default().advertised());
            // The built-in llama.cpp runtime reads raw logits in-process, so
            // any AI-serving node can produce TOPLOC commitments without
            // configuration. Models served through external engines return
            // no commitment per-request regardless of this flag.
            capacity.verifiable_inference = self.config.roles.serves_ai();
            // Operator-declared jurisdiction rides the announcement so remote
            // routers can hard-filter on it. Absent claim = this node never
            // satisfies a jurisdiction pin (fail-closed).
            capacity.jurisdiction = self.jurisdiction_claim.clone();

            let ctx = crate::event_loop::ProviderAnnouncementContext {
                hardware,
                geography: self.config.geography.clone(),
                provider_address,
                provider_type: provider_type.to_string(),
                capabilities,
                rpc_endpoint,
                ttl_secs: 120,
                cluster_profile,
                capacity,
                hosting_price_per_hour: self.config.hosting.price_per_hour,
            };
            event_loop = event_loop.with_provider_announcement(ctx);
        }

        // A storage-serving node opts into HRW shard self-selection: inbound
        // shard-replication requests are ranked against its local membership
        // view and the top-`R` shards for this node are pinned locally. The
        // mDNS-discovered local-peer set lets self-selection fill replicas
        // from the caller's own LAN segment before spilling onto the wider
        // network — the local-machine → LAN-cluster → network progression the
        // model-serving tier uses, applied to shard placement.
        if self.config.roles.serves_storage() {
            event_loop = event_loop.with_storage_replicas(DEFAULT_STORAGE_REPLICAS);
            if let Some(lp) = self.local_peers() {
                event_loop = event_loop.with_local_peers(lp);
            }
        }

        // Wire the snapshot ABCI store so the finality hook produces a
        // state-sync snapshot at the configured interval on producer nodes.
        let event_loop = if let Some(ref s) = self.snapshot_store {
            event_loop.with_snapshot_store(s.clone())
        } else {
            event_loop
        };

        // Wire kill-switch dependencies (post-execute scan side-effects:
        // lifecycle FSM, stake freeze/slash, cascade traversal, receipt
        // store). Each is best-effort: if a dependency is missing, the
        // matching side-effect is logged at debug and skipped.
        let event_loop = if let Some(ref store) = self.kill_switch_store {
            event_loop.with_kill_switch_store(store.clone())
        } else {
            event_loop
        };
        let event_loop = if let Some(ref staking) = self.staking {
            event_loop.with_staking(staking.clone())
        } else {
            event_loop
        };
        let event_loop = if let Some(ref registry) = self.identity_registry {
            event_loop.with_identity_registry(registry.clone())
        } else {
            event_loop
        };

        // Wire the AgentBond manager (Spec 9) so the post-execute scan can
        // mirror BondPosted/Increased/WithdrawInitiated/Slashed and
        // InsuranceClaimPaid logs into the off-chain BondManager state
        // that lane resolution and Spec-5 receipt envelopes consult.
        let event_loop = if let Some(ref bond_manager) = self.bond_manager {
            event_loop.with_bond_manager(bond_manager.clone())
        } else {
            event_loop
        };

        // Wire the compute-bond manager so the post-execute scan can mirror
        // ComputeBondPosted/Increased/WithdrawInitiated logs into the
        // off-chain ComputeBondManager. Without this the VM locks provider
        // collateral in the vault but `tenzro_registerProvider` never sees
        // the bond, so provider admission stays closed.
        let event_loop = if let Some(ref cbm) = self.compute_bond_manager {
            event_loop.with_compute_bond_manager(cbm.clone())
        } else {
            event_loop
        };

        // Wire the on-chain escrow query index. The post-execute scan
        // mirrors VM-emitted EscrowCreated/Released/Refunded logs into
        // the off-chain EscrowManager (which the by-payer/by-payee read
        // RPCs query). Without this, escrow txs commit on chain but the
        // by-payer / by-payee indices stay empty.
        let event_loop = if let Some(ref em) = self.escrow_manager {
            event_loop.with_escrow_manager(em.clone())
        } else {
            event_loop
        };

        // Wire permissionless ValidatorRegistry. The event loop's
        // post-block scan mirrors VM-emitted ValidatorRegister /
        // ValidatorExit / ValidatorMetadataUpdate logs into this
        // registry, and the epoch boundary hook drives the resulting
        // EpochTransitionPlan into the consensus EpochManager queues.
        let event_loop = if let Some(ref vr) = self.validator_registry {
            event_loop.with_validator_registry(vr.clone())
        } else {
            event_loop
        };

        // Wire the WorkflowRuntime (Canton-native workflow stack). The
        // post-execute scan in `EventLoop::process_workflow_logs` decodes
        // the 12 typed `Workflow*` log topics emitted by the privileged-VM
        // workflow selectors (`0x01000040`–`0x0100004B`) and dispatches
        // them into `WorkflowManager` / `PrivacyDomainRegistry`.
        let event_loop = if let Some(ref rt) = self.workflow_runtime {
            event_loop.with_workflow_runtime(rt.clone())
        } else {
            event_loop
        };

        // Wire the adaptive-burn manager + canonical TNZO token so the
        // event loop's per-epoch supply observer feeds
        // `BurnRateConfigManager::record_metrics` at every epoch boundary.
        // Without this, `record_metrics` is dead code and the burn-rate
        // recommendation engine scores against a default snapshot —
        // governance would never see real network signal.
        let event_loop = if let (Some(burn_rate), Some(token)) =
            (self.burn_rate_manager.as_ref(), self.token.as_ref())
        {
            event_loop.with_burn_rate_manager(burn_rate.clone(), token.clone())
        } else {
            event_loop
        };

        // Wire the shared RemoteWorkerRegistry so the event loop can ingest verified
        // Cortex advertisements received over the tenzro/cortex gossipsub topic.
        let event_loop = event_loop.with_cortex_registry(self.remote_cortex_workers.clone());

        // Wire the iroh resolver so the blob heartbeat can announce locally
        // held blobs on tenzro/blobs and inbound peer announcements populate
        // the resolver's blob-provider hint cache.
        let event_loop = if let Some(resolver) = self.iroh_resolver.clone() {
            event_loop.with_iroh_resolver(resolver)
        } else {
            event_loop
        };

        // Wire the shared TrainingRuntime so the event loop can dispatch
        // OuterGradient / SyncRound payloads received over the tenzro/training
        // and tenzro/training/syncer gossipsub topics into the local syncer
        // state. accept_outer_gradient dedups by trainer_did, so re-receiving
        // a self-published gradient is a no-op.
        let event_loop = event_loop.with_training_runtime(self.training_runtime.clone());

        // Wire the shared MediaGenRuntime so the event loop can mirror job
        // state announced over the tenzro/media-gen gossipsub topic, and the
        // iroh-backed output store so locators carried alongside a handoff or
        // receipt are recorded against the content hash they name. Without the
        // store a split job's intermediate latent stays reachable only from the
        // machine that produced it, which is the one machine that does not need
        // to fetch it.
        let event_loop = event_loop.with_media_gen_runtime(self.media_gen_runtime.clone());
        let event_loop = if let Some(store) = self.media_gen_output_store.clone() {
            event_loop.with_media_gen_output_store(store)
        } else {
            event_loop
        };

        // Wire the shared SeedAgentEarmarkManager (Spec 10) so the event
        // loop can apply idempotent state updates received over the
        // tenzro/seed-agents gossipsub topic. `MonthlyRefillCompleted`
        // is informational only — receivers refresh their earmark snapshot
        // but do NOT replay the refill (that would double-spend).
        let event_loop = if let Some(seed_agents) = self.seed_agent_manager.clone() {
            event_loop.with_seed_agent_manager(seed_agents)
        } else {
            event_loop
        };

        // Wire the distributed-database registry so the event loop can upsert
        // descriptors received over the tenzro/databases gossipsub topic into
        // the same registry the RPC handlers serve from. Upserts are idempotent
        // and metadata-only — the receiver is not a partition holder, so it
        // records the origin's authoritative descriptor without recomputing
        // placement.
        let event_loop = if let Some(db_registry) = self.database_registry.clone() {
            event_loop.with_database_registry(db_registry)
        } else {
            event_loop
        };

        // Wire the work-gated reward engine so the event loop can record
        // per-block consensus participation (proposer + QC signers) and, at
        // epoch boundaries, ingest cumulative provider usage as InferenceServed
        // work before closing the epoch and minting reward coupons.
        let event_loop = if let Some(rewards) = self.reward_engine.clone() {
            event_loop.with_reward_engine(rewards)
        } else {
            event_loop
        };

        // Wire the sponsorship manager so the event loop can run the slot
        // expiry sweep at epoch boundaries, returning lapsed foundation
        // delegations to the revolving pool.
        let event_loop = if let Some(sponsorship) = self.sponsorship_manager.clone() {
            event_loop.with_sponsorship_manager(sponsorship)
        } else {
            event_loop
        };

        // Wire the usage tracker so epoch-boundary reward metering can read
        // cumulative per-provider revenue for InferenceServed work credit.
        let event_loop = if let Some(usage) = self.usage_tracker.clone() {
            event_loop.with_usage_tracker(usage)
        } else {
            event_loop
        };

        // Wire the fee processor so per-block gas settlement is recorded.
        let event_loop = if let (Some(processor), Some(token)) =
            (self.fee_processor.clone(), self.token.clone())
        {
            event_loop.with_fee_processor(processor, token)
        } else {
            event_loop
        };

        // Store the event sender for RPC to submit transactions
        self.event_loop_tx = Some(event_loop.event_sender());

        // Log the startup chain state using the event loop's chain-tip getters.
        // These calls produce valuable observability on every node restart and ensure
        // the getters are exercised at runtime rather than just sitting unused.
        {
            let initial_height = event_loop.current_height();
            let initial_hash = event_loop.last_block_hash();
            let initial_state_root = event_loop.state_adapter().lock().await.compute_state_root();
            info!(
                height = initial_height.0,
                last_hash = %initial_hash,
                state_root = %initial_state_root,
                "Event loop initialized, resuming from stored chain tip"
            );
        }

        // Wire block sync: subscribe to gossipsub blocks topic and forward to event loop.
        // This follows the same pattern as the agent gossipsub bridge (init_ai_infrastructure).
        // All nodes subscribe — validators will receive their own blocks back from gossipsub
        // but the event loop's height check will skip duplicates.
        if let Some(ref network) = self.network {
            let event_tx = event_loop.event_sender();
            let net_in = network.clone();
            tokio::spawn(async move {
                match net_in.subscribe("tenzro/blocks").await {
                    Ok(mut rx) => {
                        tracing::info!("Block sync: subscribed to tenzro/blocks");
                        while let Some(msg) = rx.recv().await {
                            if let tenzro_network::MessagePayload::Block(block) = msg.payload {
                                let height = block.height();
                                tracing::debug!(height = %height, "Received block from gossipsub");
                                if let Err(e) = event_tx.send(NodeEvent::NetworkBlock(block)).await {
                                    tracing::error!("Failed to forward network block to event loop: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to subscribe to blocks gossipsub topic: {}", e);
                    }
                }
            });
            info!("Block sync wired to gossipsub (tenzro/blocks)");

            // Wire transaction gossip: subscribe to tenzro/transactions and
            // forward each inbound `MessagePayload::Transaction(tx)` into
            // `NodeEvent::NewTransaction`, which runs signature verification
            // and admits the tx to the local consensus mempool.
            //
            // Without this subscriber, RPC pods publish transactions to the
            // gossipsub mesh but no validator's mempool ever receives them,
            // so every block proposer emits an empty block. That was the
            // root cause of the testnet wedge where `eth_blockNumber`
            // advanced normally but every finalized block had `tx_count=0`
            // and no transaction (faucet, transfer, contract call) ever
            // settled despite the JSON-RPC layer reporting `submitted:queued`.
            //
            // Note: gossipsub deduplicates by `message_id`, so even though
            // `handle_new_transaction` re-broadcasts on receive, this does
            // not produce a storm — duplicate publications collapse to a
            // single mesh propagation cycle.
            {
                let event_tx = event_loop.event_sender();
                let net_in = network.clone();
                tokio::spawn(async move {
                    match net_in.subscribe("tenzro/transactions").await {
                        Ok(mut rx) => {
                            tracing::info!("Transaction sync: subscribed to tenzro/transactions");
                            while let Some(msg) = rx.recv().await {
                                if let tenzro_network::MessagePayload::Transaction(mut tx) = msg.payload {
                                    let tx_hash = tx.hash();
                                    tracing::debug!(
                                        hash = %tx_hash,
                                        "Received transaction from gossipsub"
                                    );
                                    if let Err(e) =
                                        event_tx.send(NodeEvent::NewTransaction(tx)).await
                                    {
                                        tracing::error!(
                                            error = %e,
                                            "Failed to forward gossiped transaction to event loop"
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "Failed to subscribe to transactions gossipsub topic"
                            );
                        }
                    }
                });
                info!("Transaction sync wired to gossipsub (tenzro/transactions)");
            }

            // Wire status gossip: subscribe to tenzro/status and feed
            // peer heights into the PeerStatusTracker so eth_syncing /
            // tenzro_syncing can report a real network-tip estimate.
            //
            // Outbound: every 10s broadcast our own StatusMessage with the
            // current chain tip. The PeerStatusTracker drops entries from
            // peers whose chain_id doesn't match (silent), so cross-chain
            // noise can't poison the estimate.
            {
                use std::str::FromStr;
                let net_status = network.clone();
                let peer_status_tracker = self.peer_status.clone();
                let local_chain_id = self
                    .config
                    .genesis
                    .as_ref()
                    .map(|g| g.chain_id)
                    .unwrap_or(1337);
                tokio::spawn(async move {
                    let mut rx = match net_status.subscribe("tenzro/status").await {
                        Ok(rx) => rx,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "Failed to subscribe to status gossipsub topic"
                            );
                            return;
                        }
                    };
                    tracing::info!("Status sync: subscribed to tenzro/status");
                    while let Some(msg) = rx.recv().await {
                        if let tenzro_network::MessagePayload::Status(status) = msg.payload {
                            // Drop messages from a different chain — defense
                            // against cross-chain gossip leak. Tracker also
                            // re-checks this, but doing it here keeps the log
                            // signal cleaner.
                            if status.chain_id != local_chain_id {
                                continue;
                            }
                            let peer_id = match libp2p::PeerId::from_str(&status.peer_id) {
                                Ok(p) => p,
                                Err(e) => {
                                    tracing::debug!(
                                        peer = %status.peer_id,
                                        error = %e,
                                        "Dropping StatusMessage with malformed peer_id"
                                    );
                                    continue;
                                }
                            };
                            tracing::trace!(
                                peer = %peer_id,
                                height = status.height,
                                tee_capable = status.tee_capable,
                                tee_vendor = ?status.tee_vendor,
                                "Recorded peer status"
                            );
                            peer_status_tracker.record(
                                peer_id,
                                status.height,
                                status.chain_id,
                                status.tee_capable,
                                status.tee_vendor,
                            );
                        }
                    }
                });
                info!("Status sync wired to gossipsub (tenzro/status)");
            }

            // Outbound status broadcast tick: every 10s, broadcast our own
            // best block + height so peers can track our chain tip.
            {
                let net_out = network.clone();
                let chain_tip_atomic = self.chain_tip.clone();
                let peer_status_tracker = self.peer_status.clone();
                let local_chain_id = self
                    .config
                    .genesis
                    .as_ref()
                    .map(|g| g.chain_id)
                    .unwrap_or(1337);
                let protocol_version = format!("tenzro/{}", env!("CARGO_PKG_VERSION"));
                // TEE capability is fixed at startup (no hot-attach
                // path), so we snapshot it once here and embed it in
                // every status broadcast. Peers consult these fields to
                // discover routing targets for confidential-compute /
                // custodial workloads.
                let local_tee_capable = self.tee_provider.is_some();
                let local_tee_vendor = self.tee_provider.as_ref().map(|p| p.vendor());
                tokio::spawn(async move {
                    // Resolve our local PeerId once (the network service spawns
                    // its own swarm task, so the PeerId is stable for the
                    // lifetime of the process).
                    let local_peer_id = match net_out.local_peer_id().await {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "Status broadcast: failed to resolve local PeerId; aborting"
                            );
                            return;
                        }
                    };
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    // Skip the immediate fire so we don't broadcast height=0
                    // before the chain tip has been hydrated from storage.
                    tick.tick().await;
                    loop {
                        tick.tick().await;
                        // Periodically prune stale entries from the tracker
                        // so the map stays bounded as peers drop off.
                        peer_status_tracker.prune_stale();

                        let height = chain_tip_atomic.load(std::sync::atomic::Ordering::Acquire);
                        let status = tenzro_network::StatusMessage {
                            peer_id: local_peer_id.to_string(),
                            best_block: tenzro_types::Hash::zero(),
                            height,
                            chain_id: local_chain_id,
                            protocol_version: protocol_version.clone(),
                            tee_capable: local_tee_capable,
                            tee_vendor: local_tee_vendor,
                        };
                        let msg = tenzro_network::NetworkMessage::new(
                            tenzro_network::MessagePayload::Status(status),
                        );
                        if let Err(e) = net_out.broadcast("tenzro/status", msg).await {
                            tracing::debug!(
                                error = %e,
                                "Status broadcast failed (likely no mesh peers yet)"
                            );
                        }
                    }
                });
                info!("Status broadcast wired (every 10s on tenzro/status)");
            }

            // Wire the G6 batch-availability plane: subscribe to
            // `tenzro/batches` and dispatch inbound batch bodies, acks, and
            // availability certificates into the local HotStuff-2 engine. The
            // network crate carries these as opaque bincode blobs (it does not
            // depend on the consensus crate), so this subscriber decodes them:
            //   - `BatchBody(bytes)`      → `Batch`      → `ingest_batch_body`
            //   - `BatchAvailability(b)`  → try `BatchAvailabilityCertificate`,
            //                               else `BatchAck` → the matching ingest
            //   - `BatchBodyRequest(id)`  → serve the body if held locally
            // Only nodes running consensus wire this; RPC-only nodes still
            // subscribe (peer_manager gates publishing to validators) so they
            // can pull bodies for execution.
            if let Some(consensus) = self.consensus.clone() {
                let net_batches = network.clone();
                tokio::spawn(async move {
                    let mut rx = match net_batches.subscribe("tenzro/batches").await {
                        Ok(rx) => rx,
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed to subscribe to tenzro/batches");
                            return;
                        }
                    };
                    tracing::info!("Batch availability: subscribed to tenzro/batches");
                    while let Some(msg) = rx.recv().await {
                        match msg.payload {
                            tenzro_network::MessagePayload::BatchBody(bytes) => {
                                match bincode::deserialize::<tenzro_consensus::Batch>(&bytes) {
                                    Ok(batch) => consensus.ingest_batch_body(batch),
                                    Err(e) => tracing::debug!(error = %e, "batch_cert: malformed BatchBody"),
                                }
                            }
                            tenzro_network::MessagePayload::BatchAvailability(bytes) => {
                                // The producer aggregates acks into a certificate,
                                // so a peer receives both shapes on this variant.
                                // Prefer the certificate decode (verified + installed
                                // by the engine), fall back to a single ack.
                                if let Ok(cert) = bincode::deserialize::<
                                    tenzro_consensus::BatchAvailabilityCertificate,
                                >(&bytes)
                                {
                                    consensus.ingest_batch_certificate(cert);
                                } else if let Ok(ack) =
                                    bincode::deserialize::<tenzro_consensus::BatchAck>(&bytes)
                                {
                                    let batch_id = ack.batch_id;
                                    consensus.ingest_batch_ack(batch_id, ack);
                                } else {
                                    tracing::debug!("batch_cert: malformed BatchAvailability payload");
                                }
                            }
                            tenzro_network::MessagePayload::BatchBodyRequest(id) => {
                                // Serve the requested body back onto the mesh when
                                // this node holds it, so a peer that only has a
                                // certificate can pull the transactions for
                                // execution.
                                if let Some(store) = consensus.batch_cert_store()
                                    && let Some(batch) = store.get_body(&id)
                                    && let Ok(b) = bincode::serialize(&batch)
                                {
                                    let reply = tenzro_network::NetworkMessage::new(
                                        tenzro_network::MessagePayload::BatchBody(b),
                                    );
                                    if let Err(e) =
                                        net_batches.broadcast("tenzro/batches", reply).await
                                    {
                                        tracing::debug!(error = %e, "batch_cert: body reply broadcast failed");
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                });
                info!("Batch availability wired to gossipsub (tenzro/batches)");
            }

            // Wire the ZK quorum plane: subscribe to `tenzro/zk-quorum`.
            //   - `Claim`  → a peer verified a proof and wants co-signatures.
            //                Fetch the proof by its DA locator, re-run
            //                `verify_proof_envelope`, and if it verifies, reply
            //                with our own co-signature (and also fold the
            //                claimer's co-sign toward quorum here so a small
            //                validator set converges).
            //   - `Cosign` → a peer's co-signature toward a commitment we are
            //                aggregating. Fold it in; on quorum, attest +
            //                open the fraud window.
            // Only validators holding a quorum store aggregate; RPC-only nodes
            // still subscribe but simply cannot form a certificate.
            if let (Some(zk_store), Some(consensus), Some(resolver)) = (
                self.zk_quorum_store.clone(),
                self.consensus.clone(),
                self.iroh_resolver.clone(),
            ) {
                let net_zk = network.clone();
                let zk_registry = self.zk_commitment_registry.clone();
                tokio::spawn(async move {
                    let mut rx = match net_zk.subscribe(tenzro_consensus::ZK_QUORUM_TOPIC).await {
                        Ok(rx) => rx,
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed to subscribe to tenzro/zk-quorum");
                            return;
                        }
                    };
                    tracing::info!("ZK quorum: subscribed to tenzro/zk-quorum");
                    let self_addr = *zk_store.address();
                    while let Some(msg) = rx.recv().await {
                        let tenzro_network::MessagePayload::Custom { topic, data } = msg.payload
                        else {
                            continue;
                        };
                        if topic != tenzro_consensus::ZK_QUORUM_TOPIC {
                            continue;
                        }
                        let decoded = match bincode::deserialize::<tenzro_consensus::ZkQuorumMsg>(&data) {
                            Ok(m) => m,
                            Err(e) => {
                                tracing::debug!(error = %e, "zk-quorum: malformed gossip message");
                                continue;
                            }
                        };
                        match decoded {
                            tenzro_consensus::ZkQuorumMsg::Claim { claim, cosign } => {
                                // Fold the claimer's co-signature toward quorum.
                                fold_zk_cosign(
                                    &zk_store,
                                    &consensus,
                                    &zk_registry,
                                    &claim.circuit_id,
                                    cosign,
                                    &claim.proof_locator,
                                );
                                // Independently fetch + re-verify the proof; if
                                // it verifies, co-sign and reply.
                                let uri = match tenzro_iroh::TenzroUri::parse(&claim.proof_locator) {
                                    Ok(u) => u,
                                    Err(e) => {
                                        tracing::debug!(error = %e, "zk-quorum: bad proof locator in claim");
                                        continue;
                                    }
                                };
                                use tenzro_iroh::IrohResolver;
                                let bytes = match resolver.fetch_bytes(&uri).await {
                                    Ok(b) => b,
                                    Err(e) => {
                                        tracing::debug!(error = %e, "zk-quorum: proof fetch failed; cannot co-sign");
                                        continue;
                                    }
                                };
                                let envelope: tenzro_zk::Proof = match serde_json::from_slice(&bytes) {
                                    Ok(e) => e,
                                    Err(e) => {
                                        tracing::debug!(error = %e, "zk-quorum: proof decode failed");
                                        continue;
                                    }
                                };
                                let commitment = claim.commitment;
                                // The commitment must actually be the commitment
                                // of the fetched proof, or a co-signer could be
                                // tricked into co-signing hash A while verifying
                                // proof B.
                                let recomputed =
                                    tenzro_vm::precompiles::compute_zk_commitment(&envelope);
                                if recomputed != commitment {
                                    tracing::debug!("zk-quorum: claim commitment does not match fetched proof; ignoring");
                                    continue;
                                }
                                let verified = tokio::task::spawn_blocking(move || {
                                    tenzro_zk::verify_proof_envelope(&envelope).is_ok()
                                })
                                .await
                                .unwrap_or(false);
                                if !verified {
                                    tracing::debug!("zk-quorum: claimed proof failed re-verification; not co-signing");
                                    continue;
                                }
                                let my_cosign = zk_store.cosign(commitment);
                                // Fold our own co-sign locally (drives quorum on
                                // this node if we are the aggregator).
                                fold_zk_cosign(
                                    &zk_store,
                                    &consensus,
                                    &zk_registry,
                                    &claim.circuit_id,
                                    my_cosign.clone(),
                                    &claim.proof_locator,
                                );
                                // Reply with our co-signature so the claimer (and
                                // any other aggregator) can reach quorum.
                                let reply = tenzro_consensus::ZkQuorumMsg::Cosign {
                                    circuit_id: claim.circuit_id.clone(),
                                    cosign: my_cosign,
                                };
                                if let Ok(rdata) = bincode::serialize(&reply) {
                                    let net_msg = tenzro_network::NetworkMessage::new(
                                        tenzro_network::MessagePayload::Custom {
                                            topic: tenzro_consensus::ZK_QUORUM_TOPIC.to_string(),
                                            data: rdata,
                                        },
                                    );
                                    if let Err(e) = net_zk
                                        .broadcast(tenzro_consensus::ZK_QUORUM_TOPIC, net_msg)
                                        .await
                                    {
                                        tracing::debug!(error = %e, "zk-quorum: cosign reply broadcast failed");
                                    }
                                }
                            }
                            tenzro_consensus::ZkQuorumMsg::Cosign { circuit_id, cosign } => {
                                if cosign.validator == self_addr {
                                    // Our own reply echoed back — ignore.
                                    continue;
                                }
                                // A peer's co-signature. We can only fold it if
                                // we know the proof locator, which we recorded
                                // when we saw the claim. The store keeps pending
                                // co-signs keyed by commitment; if we never saw
                                // the claim we have no locator to open a window
                                // with, so we buffer against an empty locator —
                                // the aggregator that DID see the claim carries
                                // the real locator. To avoid attesting with an
                                // empty locator here, we only fold when this node
                                // already holds an attested record or pending
                                // entry that came from a claim. In practice the
                                // initiating validator is the aggregator; this
                                // branch keeps other validators' partial tallies
                                // warm without letting them attest locator-less.
                                fold_zk_cosign_no_attest(
                                    &zk_store,
                                    &consensus,
                                    &circuit_id,
                                    cosign,
                                );
                            }
                        }
                    }
                });
                info!("ZK quorum plane wired to gossipsub (tenzro/zk-quorum)");
            }

            // Wire inbound consensus: subscribe to the consensus-direct
            // request-response overlay (#144) and dispatch proposals +
            // votes into the local HotStuff-2 engine.
            //
            // Without this bridge, every validator only sees its own
            // self-vote produced by `consensus.on_proposal()`. Quorum
            // threshold (2f+1 = 3 of 4) can never be reached, so block
            // height stays at 0 forever. The outbound side lives in
            // `event_loop.rs::outbound_consensus`, which now calls
            // `network.broadcast_to_validators(consensus_msg)`.
            //
            // The overlay does NOT echo our own broadcasts back to us
            // (the dispatch loop in `service.rs` skips `local_peer_id`),
            // but a defense-in-depth self-loop filter on `local_addr`
            // remains — peers may forward our messages on rare paths,
            // and the cost of an extra address compare is negligible
            // compared to the deserialization cost of the embedded
            // signatures.
            if let (Some(consensus), Some(local_addr)) =
                (self.consensus.clone(), self.local_validator_address)
            {
                let net_consensus = network.clone();
                tokio::spawn(async move {
                    let mut rx = match net_consensus.subscribe_consensus_direct().await {
                        Ok(rx) => rx,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "Failed to subscribe to consensus-direct overlay"
                            );
                            return;
                        }
                    };
                    tracing::info!(
                        local = %hex::encode(local_addr.as_bytes()),
                        "Consensus inbound: subscribed to consensus-direct overlay"
                    );
                    while let Some(consensus_msg) = rx.recv().await {
                        match consensus_msg {
                            tenzro_network::ConsensusMessage::Proposal {
                                block,
                                proposer,
                                round,
                                high_qc_view,
                                timeout_certificate,
                                no_endorsement_certificate,
                                proposer_signature,
                            } => {
                                // Decode hex proposer → Address. On malformed input,
                                // log and drop — the proposer field is informational
                                // for the self-loop filter; the engine doesn't rely
                                // on it for proposal admission.
                                let proposer_addr = match hex::decode(&proposer)
                                    .ok()
                                    .and_then(|b| Address::from_bytes(&b))
                                {
                                    Some(a) => a,
                                    None => {
                                        tracing::warn!(
                                            proposer = %proposer,
                                            "Dropping consensus proposal with malformed proposer address"
                                        );
                                        continue;
                                    }
                                };
                                if proposer_addr == local_addr {
                                    // Echo of our own proposal — already processed
                                    // locally by the engine; skip.
                                    continue;
                                }
                                // Decode the optional TC. A bincode failure here
                                // means the proposer attached a malformed TC —
                                // drop the proposal entirely rather than vote on
                                // an unverified view jump.
                                let tc = match timeout_certificate
                                    .as_deref()
                                    .map(bincode::deserialize::<tenzro_consensus::TimeoutCertificate>)
                                {
                                    None => None,
                                    Some(Ok(tc)) => Some(tc),
                                    Some(Err(e)) => {
                                        tracing::warn!(
                                            proposer = %hex::encode(proposer_addr.as_bytes()),
                                            error = %e,
                                            "Dropping proposal with malformed TC"
                                        );
                                        continue;
                                    }
                                };
                                let nec = match no_endorsement_certificate
                                    .as_deref()
                                    .map(bincode::deserialize::<tenzro_consensus::NoEndorsementCertificate>)
                                {
                                    None => None,
                                    Some(Ok(nec)) => Some(nec),
                                    Some(Err(e)) => {
                                        tracing::warn!(
                                            proposer = %hex::encode(proposer_addr.as_bytes()),
                                            error = %e,
                                            "Dropping proposal with malformed NEC"
                                        );
                                        continue;
                                    }
                                };
                                // Decode the mandatory hybrid proposer
                                // signature. A malformed blob means the
                                // proposal cannot be attributed — drop it
                                // rather than hand the engine an
                                // unverifiable proposal.
                                let proposer_sig = match bincode::deserialize::<
                                    tenzro_crypto::composite::CompositeSignature,
                                >(&proposer_signature)
                                {
                                    Ok(sig) => sig,
                                    Err(e) => {
                                        tracing::warn!(
                                            proposer = %hex::encode(proposer_addr.as_bytes()),
                                            error = %e,
                                            "Dropping proposal with malformed proposer signature"
                                        );
                                        continue;
                                    }
                                };
                                let height = block.height();
                                tracing::debug!(
                                    height = %height,
                                    round = round,
                                    proposer = %hex::encode(proposer_addr.as_bytes()),
                                    has_tc = tc.is_some(),
                                    has_nec = nec.is_some(),
                                    "Received consensus proposal from peer"
                                );
                                match consensus
                                    .on_proposal(&block, tc, nec, high_qc_view, &proposer_sig)
                                    .await
                                {
                                    Ok(_vote) => {
                                        // The vote is also emitted on `consensus_out_rx`
                                        // by the engine, which the event loop picks up
                                        // and broadcasts on the consensus topic. We do
                                        // not need to broadcast it here.
                                        tracing::debug!(
                                            height = %height,
                                            "Voted on peer proposal"
                                        );
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            height = %height,
                                            error = %e,
                                            "Failed to handle peer proposal"
                                        );
                                    }
                                }
                            }
                            tenzro_network::ConsensusMessage::Vote {
                                block_hash,
                                voter,
                                vote_type,
                                round,
                                height,
                                high_qc_view,
                                signature,
                                public_key,
                                bls_signature,
                            } => {
                                let voter_addr = match hex::decode(&voter)
                                    .ok()
                                    .and_then(|b| Address::from_bytes(&b))
                                {
                                    Some(a) => a,
                                    None => {
                                        tracing::warn!(
                                            voter = %voter,
                                            "Dropping consensus vote with malformed voter address"
                                        );
                                        continue;
                                    }
                                };
                                if voter_addr == local_addr {
                                    // Echo of our own vote — collector would dedupe
                                    // anyway; skip the deserialization cost.
                                    continue;
                                }
                                let sig: tenzro_crypto::composite::CompositeSignature =
                                    match bincode::deserialize(&signature) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            tracing::warn!(
                                                voter = %hex::encode(voter_addr.as_bytes()),
                                                error = %e,
                                                "Dropping vote: failed to bincode-decode CompositeSignature"
                                            );
                                            continue;
                                        }
                                    };
                                let pk: tenzro_crypto::composite::CompositePublicKey =
                                    match bincode::deserialize(&public_key) {
                                        Ok(p) => p,
                                        Err(e) => {
                                            tracing::warn!(
                                                voter = %hex::encode(voter_addr.as_bytes()),
                                                error = %e,
                                                "Dropping vote: failed to bincode-decode CompositePublicKey"
                                            );
                                            continue;
                                        }
                                    };
                                let bls_sig =
                                    match tenzro_crypto::bls::BlsSignature::from_bytes(&bls_signature) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            tracing::warn!(
                                                voter = %hex::encode(voter_addr.as_bytes()),
                                                error = %e,
                                                "Dropping vote: failed to decode BLS signature (expected 96 bytes)"
                                            );
                                            continue;
                                        }
                                    };
                                let cons_vote_type = match vote_type {
                                    tenzro_network::VoteType::Prevote => {
                                        tenzro_consensus::VoteType::Prepare
                                    }
                                    tenzro_network::VoteType::Precommit => {
                                        tenzro_consensus::VoteType::Commit
                                    }
                                };
                                let vote = tenzro_consensus::Vote::new(
                                    round,
                                    tenzro_types::primitives::BlockHeight(height),
                                    block_hash,
                                    voter_addr,
                                    sig,
                                    pk,
                                    bls_sig,
                                    cons_vote_type,
                                    high_qc_view,
                                );
                                tracing::debug!(
                                    height = height,
                                    round = round,
                                    voter = %hex::encode(voter_addr.as_bytes()),
                                    vote_type = ?cons_vote_type,
                                    "Received consensus vote from peer"
                                );
                                if let Err(e) = consensus.on_vote(&vote).await {
                                    // Equivocation errors are expected to be loud — the
                                    // engine logs + slashes. Other errors (NotStarted,
                                    // dedup-style) we just trace.
                                    tracing::warn!(
                                        height = height,
                                        error = %e,
                                        "on_vote rejected peer vote"
                                    );
                                }
                            }
                            tenzro_network::ConsensusMessage::Timeout {
                                format_version,
                                view,
                                high_qc_view,
                                finalized_height,
                                voter,
                                signature,
                                public_key,
                            } => {
                                if voter == local_addr {
                                    // Echo of our own timeout — skip the deserialization cost.
                                    continue;
                                }
                                let sig: tenzro_crypto::composite::CompositeSignature =
                                    match bincode::deserialize(&signature) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            tracing::warn!(
                                                voter = %hex::encode(voter.as_bytes()),
                                                error = %e,
                                                "Dropping timeout: failed to bincode-decode CompositeSignature"
                                            );
                                            continue;
                                        }
                                    };
                                let pk: tenzro_crypto::composite::CompositePublicKey =
                                    match bincode::deserialize(&public_key) {
                                        Ok(p) => p,
                                        Err(e) => {
                                            tracing::warn!(
                                                voter = %hex::encode(voter.as_bytes()),
                                                error = %e,
                                                "Dropping timeout: failed to bincode-decode CompositePublicKey"
                                            );
                                            continue;
                                        }
                                    };
                                let timeout_msg = tenzro_consensus::TimeoutMsg {
                                    format_version,
                                    view,
                                    high_qc_view,
                                    finalized_height,
                                    voter,
                                    signature: sig,
                                    public_key: pk,
                                };
                                tracing::debug!(
                                    view = view,
                                    voter = %hex::encode(voter.as_bytes()),
                                    "Received pacemaker TimeoutMsg from peer"
                                );
                                if let Err(e) = consensus.on_timeout_msg(&timeout_msg).await {
                                    // on_timeout_msg rejects unknown voters,
                                    // bad signatures, format-version mismatches.
                                    // Log and move on — pacemaker is best-effort.
                                    tracing::warn!(
                                        view = view,
                                        error = %e,
                                        "on_timeout_msg rejected peer timeout"
                                    );
                                }
                            }
                            tenzro_network::ConsensusMessage::Commit { .. } => {
                                // Commit messages are not currently consumed by the
                                // engine — finality is driven by QC formation in the
                                // vote collector. Drop silently.
                            }
                            tenzro_network::ConsensusMessage::NoEndorsement {
                                format_version,
                                view,
                                voter,
                                signature,
                                public_key,
                            } => {
                                if voter == local_addr {
                                    // Echo of our own NEC msg — skip the deserialization cost.
                                    continue;
                                }
                                let sig: tenzro_crypto::composite::CompositeSignature =
                                    match bincode::deserialize(&signature) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            tracing::warn!(
                                                voter = %hex::encode(voter.as_bytes()),
                                                error = %e,
                                                "Dropping NoEndorsement: failed to bincode-decode CompositeSignature"
                                            );
                                            continue;
                                        }
                                    };
                                let pk: tenzro_crypto::composite::CompositePublicKey =
                                    match bincode::deserialize(&public_key) {
                                        Ok(p) => p,
                                        Err(e) => {
                                            tracing::warn!(
                                                voter = %hex::encode(voter.as_bytes()),
                                                error = %e,
                                                "Dropping NoEndorsement: failed to bincode-decode CompositePublicKey"
                                            );
                                            continue;
                                        }
                                    };
                                let nec_msg = tenzro_consensus::NoEndorsementMsg {
                                    format_version,
                                    view,
                                    voter,
                                    signature: sig,
                                    public_key: pk,
                                };
                                tracing::debug!(
                                    view = view,
                                    voter = %hex::encode(voter.as_bytes()),
                                    "Received NoEndorsementMsg from peer"
                                );
                                if let Err(e) = consensus.on_no_endorsement_msg(&nec_msg).await {
                                    // on_no_endorsement_msg rejects unknown voters,
                                    // bad signatures, format-version mismatches.
                                    tracing::warn!(
                                        view = view,
                                        error = %e,
                                        "on_no_endorsement_msg rejected peer NoEndorsement"
                                    );
                                }
                            }
                        }
                    }
                });
                info!("Consensus inbound wired to consensus-direct overlay");
            } else {
                // Non-validator nodes (LightClient, ModelProvider without consensus)
                // skip this wiring entirely — they have nothing to vote with.
                tracing::debug!(
                    "Skipping consensus inbound wiring: no consensus engine on this node"
                );
            }

            // Wire model discovery: subscribe to gossipsub models topic and forward to event loop.
            // This enables decentralized P2P model discovery — no centralized registry required.
            let event_tx_models = event_loop.event_sender();
            let net_models = network.clone();
            tokio::spawn(async move {
                match net_models.subscribe("tenzro/models").await {
                    Ok(mut rx) => {
                        tracing::info!("Model discovery: subscribed to tenzro/models");
                        while let Some(msg) = rx.recv().await {
                            if let tenzro_network::MessagePayload::ModelRegistration(reg) = msg.payload
                                && let Err(e) = event_tx_models.send(NodeEvent::ModelAnnouncement(reg)).await {
                                    tracing::error!("Failed to forward model announcement to event loop: {}", e);
                                    break;
                                }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to subscribe to models gossipsub topic: {}", e);
                    }
                }
            });
            info!("Model discovery wired to gossipsub (tenzro/models)");

            // Wire agent discovery: subscribe to gossipsub agents topic and forward to event loop.
            // This enables decentralized P2P agent discovery — every node learns about every agent
            // on the network via gossipsub heartbeats, with no central registry required.
            let event_tx_agents = event_loop.event_sender();
            let net_agents = network.clone();
            tokio::spawn(async move {
                match net_agents.subscribe("tenzro/agents").await {
                    Ok(mut rx) => {
                        tracing::info!("Agent discovery: subscribed to tenzro/agents");
                        while let Some(msg) = rx.recv().await {
                            if let tenzro_network::MessagePayload::AgentAnnouncement(ann) = msg.payload
                                && let Err(e) = event_tx_agents.send(NodeEvent::AgentAnnouncement(ann)).await {
                                    tracing::error!("Failed to forward agent announcement to event loop: {}", e);
                                    break;
                                }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to subscribe to agents gossipsub topic: {}", e);
                    }
                }
            });
            info!("Agent discovery wired to gossipsub (tenzro/agents)");

            // Wire provider discovery: subscribe to gossipsub providers topic and forward to event loop.
            // This enables decentralized P2P provider discovery — every node learns about every provider
            // on the network via gossipsub heartbeats, with no central registry required.
            let event_tx_providers = event_loop.event_sender();
            let net_providers = network.clone();
            tokio::spawn(async move {
                match net_providers.subscribe("tenzro/providers").await {
                    Ok(mut rx) => {
                        tracing::info!("Provider discovery: subscribed to tenzro/providers");
                        while let Some(msg) = rx.recv().await {
                            if let tenzro_network::MessagePayload::ProviderAnnouncement(ann) = msg.payload
                                && let Err(e) = event_tx_providers.send(NodeEvent::ProviderAnnouncement(ann)).await {
                                    tracing::error!("Failed to forward provider announcement to event loop: {}", e);
                                    break;
                                }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to subscribe to providers gossipsub topic: {}", e);
                    }
                }
            });
            info!("Provider discovery wired to gossipsub (tenzro/providers)");

            // Wire blob availability discovery: subscribe to gossipsub blobs topic
            // and forward to event loop. Announcements feed the iroh resolver's
            // blob-provider hint cache so hint-less `tenzro://blob/...` fetches
            // can dial announced holders.
            let event_tx_blobs = event_loop.event_sender();
            let net_blobs = network.clone();
            tokio::spawn(async move {
                match net_blobs.subscribe("tenzro/blobs").await {
                    Ok(mut rx) => {
                        tracing::info!("Blob discovery: subscribed to tenzro/blobs");
                        while let Some(msg) = rx.recv().await {
                            match msg.payload {
                                tenzro_network::MessagePayload::BlobAnnouncement(ann) => {
                                    if let Err(e) =
                                        event_tx_blobs.send(NodeEvent::BlobAnnouncement(ann)).await
                                    {
                                        tracing::error!(
                                            "Failed to forward blob announcement to event loop: {}",
                                            e
                                        );
                                        break;
                                    }
                                }
                                tenzro_network::MessagePayload::ShardReplication(req) => {
                                    if let Err(e) =
                                        event_tx_blobs.send(NodeEvent::ShardReplication(req)).await
                                    {
                                        tracing::error!(
                                            "Failed to forward shard replication to event loop: {}",
                                            e
                                        );
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to subscribe to blobs gossipsub topic: {}", e);
                    }
                }
            });
            info!("Blob discovery wired to gossipsub (tenzro/blobs)");

            // Wire cortex advertisement discovery: subscribe to gossipsub cortex topic
            // and forward opaque payloads to the event loop for signature verification
            // and ingestion into the RemoteWorkerRegistry. Cortex advertisements are
            // serialized as JSON and carried over the generic MessagePayload::Custom
            // envelope so no cortex-specific knowledge is required in the networking
            // layer.
            let event_tx_cortex = event_loop.event_sender();
            let net_cortex = network.clone();
            tokio::spawn(async move {
                match net_cortex.subscribe(tenzro_cortex::CORTEX_TOPIC).await {
                    Ok(mut rx) => {
                        tracing::info!(
                            topic = tenzro_cortex::CORTEX_TOPIC,
                            "Cortex discovery: subscribed to gossipsub topic"
                        );
                        while let Some(msg) = rx.recv().await {
                            if let tenzro_network::MessagePayload::Custom { topic, data } = msg.payload {
                                if topic != tenzro_cortex::CORTEX_TOPIC {
                                    continue;
                                }
                                if let Err(e) = event_tx_cortex
                                    .send(NodeEvent::CortexAdvertisementReceived(data))
                                    .await
                                {
                                    tracing::error!(
                                        "Failed to forward cortex advertisement to event loop: {}",
                                        e
                                    );
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            topic = tenzro_cortex::CORTEX_TOPIC,
                            error = %e,
                            "Failed to subscribe to cortex gossipsub topic"
                        );
                    }
                }
            });
            info!(
                topic = tenzro_cortex::CORTEX_TOPIC,
                "Cortex discovery wired to gossipsub"
            );

            // Wire Tenzro Train cross-syncer gossipsub bridge: subscribe to both
            // training topics and forward opaque payloads to the event loop for
            // decode + ingestion. `OuterGradient` payloads arrive on
            // `tenzro/training` and are dispatched into the local syncer's
            // `accept_outer_gradient` path (idempotent on `trainer_did`).
            // `SyncRound` payloads arrive on `tenzro/training/syncer` and
            // are recorded as informational state-root observations.
            for topic in [
                tenzro_training::TRAINING_TOPIC,
                tenzro_training::TRAINING_SYNCER_TOPIC,
            ] {
                let event_tx_training = event_loop.event_sender();
                let net_training = network.clone();
                let topic_owned = topic.to_string();
                tokio::spawn(async move {
                    match net_training.subscribe(&topic_owned).await {
                        Ok(mut rx) => {
                            tracing::info!(
                                topic = %topic_owned,
                                "Tenzro Train: subscribed to gossipsub topic"
                            );
                            while let Some(msg) = rx.recv().await {
                                if let tenzro_network::MessagePayload::Custom { topic, data } =
                                    msg.payload
                                {
                                    if topic != topic_owned {
                                        continue;
                                    }
                                    if let Err(e) = event_tx_training
                                        .send(NodeEvent::TrainingGossipReceived {
                                            topic: topic.clone(),
                                            bytes: data,
                                        })
                                        .await
                                    {
                                        tracing::error!(
                                            "Failed to forward training gossip to event loop: {}",
                                            e
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                topic = %topic_owned,
                                error = %e,
                                "Failed to subscribe to training gossipsub topic"
                            );
                        }
                    }
                });
            }
            info!("Tenzro Train discovery wired to gossipsub (tenzro/training + tenzro/training/syncer)");

            // Wire the generative-media gossipsub bridge: subscribe to
            // `tenzro/media-gen` and forward opaque payloads to the event loop
            // for decode + mirroring. This is how a worker learns which jobs
            // are already taken before it claims one, and how the low-noise
            // half of a split job learns that the high-noise half has finished
            // and where its intermediate latent can be fetched from.
            {
                let event_tx_media_gen = event_loop.event_sender();
                let net_media_gen = network.clone();
                let topic_owned = tenzro_media_gen::MEDIA_GEN_TOPIC.to_string();
                tokio::spawn(async move {
                    match net_media_gen.subscribe(&topic_owned).await {
                        Ok(mut rx) => {
                            tracing::info!(
                                topic = %topic_owned,
                                "Tenzro Media Gen: subscribed to gossipsub topic"
                            );
                            while let Some(msg) = rx.recv().await {
                                if let tenzro_network::MessagePayload::Custom { topic, data } =
                                    msg.payload
                                {
                                    if topic != topic_owned {
                                        continue;
                                    }
                                    if let Err(e) = event_tx_media_gen
                                        .send(NodeEvent::MediaGenGossipReceived {
                                            topic: topic.clone(),
                                            bytes: data,
                                        })
                                        .await
                                    {
                                        tracing::error!(
                                            "Failed to forward media-gen gossip to event loop: {}",
                                            e
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                topic = %topic_owned,
                                error = %e,
                                "Failed to subscribe to media-gen gossipsub topic"
                            );
                        }
                    }
                });
            }
            info!("Tenzro Media Gen discovery wired to gossipsub (tenzro/media-gen)");

            // Wire SeedAgent (Spec 10) gossipsub bridge: subscribe to
            // `tenzro/seed-agents` and forward opaque payloads to the event
            // loop for decode + idempotent application against the local
            // `SeedAgentEarmarkManager`. The five variants
            // (CharterUpserted / EarmarkUpdated / AgentRegistered /
            // AgentStatusChanged / MonthlyRefillCompleted) are all
            // safe to re-apply — MonthlyRefillCompleted is informational
            // only and never re-executes the refill on the receiver.
            {
                let event_tx_seed = event_loop.event_sender();
                let net_seed = network.clone();
                let topic_owned = tenzro_token::SEED_AGENTS_TOPIC.to_string();
                tokio::spawn(async move {
                    match net_seed.subscribe(&topic_owned).await {
                        Ok(mut rx) => {
                            tracing::info!(
                                topic = %topic_owned,
                                "SeedAgent: subscribed to gossipsub topic"
                            );
                            while let Some(msg) = rx.recv().await {
                                if let tenzro_network::MessagePayload::Custom { topic, data } =
                                    msg.payload
                                {
                                    if topic != topic_owned {
                                        continue;
                                    }
                                    if let Err(e) = event_tx_seed
                                        .send(NodeEvent::SeedAgentGossipReceived {
                                            topic: topic.clone(),
                                            bytes: data,
                                        })
                                        .await
                                    {
                                        tracing::error!(
                                            "Failed to forward seed-agent gossip to event loop: {}",
                                            e
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                topic = %topic_owned,
                                error = %e,
                                "Failed to subscribe to seed-agent gossipsub topic"
                            );
                        }
                    }
                });
                info!(
                    topic = tenzro_token::SEED_AGENTS_TOPIC,
                    "SeedAgent discovery wired to gossipsub"
                );
            }

            // Wire the identity revocation gossipsub bridge: subscribe to
            // `tenzro/identity` and forward opaque payloads to the event
            // loop for decode + signature-verified, idempotent application
            // via `IdentityRegistry::apply_remote_revocation`.
            {
                let event_tx_identity = event_loop.event_sender();
                let net_identity = network.clone();
                let topic_owned = tenzro_identity::IDENTITY_TOPIC.to_string();
                tokio::spawn(async move {
                    match net_identity.subscribe(&topic_owned).await {
                        Ok(mut rx) => {
                            tracing::info!(
                                topic = %topic_owned,
                                "Identity: subscribed to gossipsub topic"
                            );
                            while let Some(msg) = rx.recv().await {
                                if let tenzro_network::MessagePayload::Custom { topic, data } =
                                    msg.payload
                                {
                                    if topic != topic_owned {
                                        continue;
                                    }
                                    if let Err(e) = event_tx_identity
                                        .send(NodeEvent::IdentityGossipReceived {
                                            topic: topic.clone(),
                                            bytes: data,
                                        })
                                        .await
                                    {
                                        tracing::error!(
                                            "Failed to forward identity gossip to event loop: {}",
                                            e
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                topic = %topic_owned,
                                error = %e,
                                "Failed to subscribe to identity gossipsub topic"
                            );
                        }
                    }
                });
                info!(
                    topic = tenzro_identity::IDENTITY_TOPIC,
                    "Identity revocation propagation wired to gossipsub"
                );
            }

            // Wire the distributed-database gossipsub bridge: subscribe to
            // `tenzro/databases` and forward opaque payloads to the event loop
            // for decode + idempotent upsert into the local `DatabaseRegistry`.
            // Only network-tier create/rescale events ride this topic; local-
            // and LAN-tier databases have no network holders to announce.
            {
                let event_tx_db = event_loop.event_sender();
                let net_db = network.clone();
                let topic_owned = tenzro_database::DATABASES_TOPIC.to_string();
                tokio::spawn(async move {
                    match net_db.subscribe(&topic_owned).await {
                        Ok(mut rx) => {
                            tracing::info!(
                                topic = %topic_owned,
                                "Database: subscribed to gossipsub topic"
                            );
                            while let Some(msg) = rx.recv().await {
                                if let tenzro_network::MessagePayload::Custom { topic, data } =
                                    msg.payload
                                {
                                    if topic != topic_owned {
                                        continue;
                                    }
                                    if let Err(e) = event_tx_db
                                        .send(NodeEvent::DatabaseGossipReceived {
                                            topic: topic.clone(),
                                            bytes: data,
                                        })
                                        .await
                                    {
                                        tracing::error!(
                                            "Failed to forward database gossip to event loop: {}",
                                            e
                                        );
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                topic = %topic_owned,
                                error = %e,
                                "Failed to subscribe to database gossipsub topic"
                            );
                        }
                    }
                });
                info!(
                    topic = tenzro_database::DATABASES_TOPIC,
                    "Database discovery wired to gossipsub"
                );
            }
        }

        // Spawn the event loop in the background
        tokio::spawn(async move {
            if let Err(e) = event_loop.run().await {
                tracing::error!(error = %e, "Event loop error");
            }
        });

        self.health_monitor.mark_healthy("event_loop");
        info!("Event loop started");

        Ok(())
    }

    /// Returns the identity registry (TDIP) if initialized
    pub fn identity_registry(&self) -> Option<&Arc<IdentityRegistry>> {
        self.identity_registry.as_ref()
    }

    /// The wallet this node is paid at.
    ///
    /// Both the advertised payee (model / provider gossip announcements) and
    /// the settled payee (inference, hosting, rental, storage) resolve through
    /// here, so the address a consumer sees in an offer is the address the
    /// transfer lands at. Resolution is total-ordered rather than
    /// registry-iteration-ordered, which means it is stable across restarts and
    /// identical for every caller on the node:
    ///
    /// 1. the identity whose wallet is the node's own announce key
    ///    (`sha256(announce_pubkey)`) — an exact key ↔ wallet binding;
    /// 2. the lowest-DID active human or institution — the owner classes;
    /// 3. the lowest-DID active autonomous agent (no controller) — a node run by
    ///    an agent on its own behalf earns into that agent's wallet;
    /// 4. the lowest-DID active delegated agent — earns into the agent's own
    ///    wallet, with the controller retaining oversight through its
    ///    delegation scope;
    /// 5. `sha256(announce_pubkey)` with no registry entry at all, so a node
    ///    that never provisioned an identity still has a self-custodial payee
    ///    instead of the zero address.
    pub fn operator_payee(&self) -> Option<Address> {
        match self.operator_identity() {
            Some((_, wallet)) => Some(wallet),
            None => self.announce_signer_payee(),
        }
    }

    /// The DID that owns [`TenzroNode::operator_payee`]. `None` when this node
    /// has no provisioned identity and is falling back to its announce key, so
    /// a caller that needs an attributable DID (transparency-log recorder,
    /// provider announcement) can tell the difference instead of recording an
    /// empty string against a real wallet.
    pub fn operator_did(&self) -> Option<String> {
        self.operator_identity().map(|(did, _)| did)
    }

    /// Payee derived from this node's own announce key, when it has one.
    fn announce_signer_payee(&self) -> Option<Address> {
        self.announce_signer
            .as_ref()
            .and_then(|s| announce_signer_wallet_address(s.as_ref()))
            .filter(|a| *a != Address::default())
    }

    /// The (DID, wallet) pair this node earns as, both taken from the same
    /// identity so an announcement's DID and payee never disagree.
    fn operator_identity(&self) -> Option<(String, Address)> {
        use tenzro_identity::{IdentityData, IdentityStatus};

        let registry = self.identity_registry.as_ref()?;
        let all = registry.list_all();
        let usable = |identity: &tenzro_identity::TenzroIdentity| {
            identity.status == IdentityStatus::Active
                && identity.wallet_address != Address::default()
        };

        if let Some(wallet) = self.announce_signer_payee()
            && let Some((did, _)) = all
                .iter()
                .filter(|(_, id)| usable(id) && id.wallet_address == wallet)
                .min_by(|a, b| a.0.cmp(&b.0))
        {
            return Some((did.clone(), wallet));
        }

        // Lower rank wins; ties break on the DID string.
        let rank = |data: &IdentityData| match data {
            IdentityData::Human { .. } | IdentityData::Institution { .. } => 0u8,
            IdentityData::Machine {
                controller_did: None,
                ..
            } => 1,
            IdentityData::Machine { .. } => 2,
        };

        all.iter()
            .filter(|(_, id)| usable(id))
            .min_by(|a, b| {
                rank(&a.1.identity_data)
                    .cmp(&rank(&b.1.identity_data))
                    .then_with(|| a.0.cmp(&b.0))
            })
            .map(|(did, id)| (did.clone(), id.wallet_address))
    }

    /// Returns the validator-owned hybrid signer (Ed25519 + ML-DSA-65)
    /// constructed in [`init_consensus`]. Webhook-sourced TDIP revocation
    /// paths (Stripe SPT `granted_token.deactivated`, future PSP-side
    /// signal cascades) consume this to sign a `SignedRevocationEntry`
    /// before the `RevocationBroadcaster` fans it out to the mesh.
    /// Returns `None` on non-validator roles.
    pub fn validator_hybrid_signer(
        &self,
    ) -> Option<&Arc<dyn tenzro_crypto::composite::HybridSigner>> {
        self.validator_hybrid_signer.as_ref()
    }

    /// Returns the Stripe SPT ceiling-resolver cache adapter if Stripe
    /// integration is configured. Used by the SPT revocation dispatcher
    /// to invalidate cached snapshots in lockstep with the TDIP cascade.
    pub fn spt_ceiling_cache(
        &self,
    ) -> Option<Arc<crate::spt_ceiling_bridge::SptCeilingResolverAdapter>> {
        self.spt_ceiling_cache.clone()
    }

    /// Returns the validated-AP2-mandate store when persistent storage was
    /// available at `init_payments`. `tenzro_listMandates` reads from it.
    pub fn mandate_store(&self) -> Option<&Arc<crate::mandate_store::MandateStore>> {
        self.mandate_store.as_ref()
    }

    /// Returns the per-node `erc8004-system` secp256k1 signer used by
    /// the two internal writers (TDIP mirror + Stripe SPT reputation
    /// dispatcher) to submit signed EVM tx against the canonical
    /// ERC-8004 proxies. Returns `None` when storage / signer init
    /// failed at `init_storage()` time — both internal write paths
    /// log-and-drop when this is absent.
    ///
    /// User-facing RPC writes (`tenzro_registerAgent`,
    /// `submitFeedback`, `requestValidation`) do **not** consume this
    /// signer; they are caller-signed via `eth_sendRawTransaction`.
    pub fn erc8004_system_signer(
        &self,
    ) -> Option<&Arc<tenzro_bridge::evm_signer::EvmTransactionSigner>> {
        self.erc8004_system_signer.as_ref()
    }

    /// Returns the [`OnChainAgentRegistry`] mirror that resolves TDIP
    /// machine DIDs to their sequential `uint256 agentId` allocated by
    /// the canonical on-chain `IdentityRegistry` proxy
    /// (`addresses::IDENTITY_REGISTRY`). Settlement-outcome
    /// dispatchers consult this before writing reputation rows so the
    /// `submitFeedback` subject word matches the `agentId` assigned at
    /// machine-identity registration time. Lookups read the off-chain
    /// `did → agentId` index in `CF_IDENTITIES` populated by
    /// `event_loop::process_erc8004_registered_logs`; callers MUST
    /// tolerate `None` for DIDs whose mirror tx has not yet been
    /// included in a finalized block. Returns `None` when the mirror
    /// wiring was skipped at `init_identity()` (no storage, no
    /// signer).
    ///
    /// [`OnChainAgentRegistry`]: tenzro_identity::erc8004::OnChainAgentRegistry
    pub fn erc8004_agent_registry(
        &self,
    ) -> Option<&Arc<dyn tenzro_identity::erc8004::OnChainAgentRegistry>> {
        self.erc8004_agent_registry.as_ref()
    }

    /// Returns the validator address this node uses as block proposer
    /// and consensus voter — set once in [`init_consensus`] from the
    /// loaded validator keypair. The Stripe SPT settlement-outcome
    /// dispatcher reads this to populate the `rater` field on the
    /// ERC-8004 `FeedbackEntry` row, anchoring the cross-write to the
    /// validator that observed the webhook. Returns `None` on
    /// non-validator roles.
    pub fn local_validator_address(&self) -> Option<&Address> {
        self.local_validator_address.as_ref()
    }

    /// Wires the Stripe SPT ceiling-resolver cache adapter onto this
    /// node. Called once from `main.rs` when constructing the payment
    /// binder so the same adapter instance is shared between the binder
    /// (read path) and the revocation dispatcher (invalidate path).
    pub fn set_spt_ceiling_cache(
        &mut self,
        cache: Arc<crate::spt_ceiling_bridge::SptCeilingResolverAdapter>,
    ) {
        self.spt_ceiling_cache = Some(cache);
    }

    /// Returns the payment gateway if initialized
    pub fn payment_gateway(&self) -> Option<&Arc<TenzroPaymentGateway>> {
        self.payment_gateway.as_ref()
    }

    /// Returns the shared Visa TAP recognition verifier if initialized. The
    /// web server mounts the facilitator recognition routes over this.
    #[cfg(feature = "visa-tap")]
    pub fn visa_tap_verifier(
        &self,
    ) -> Option<&Arc<tenzro_payments::visa_tap::TapVerifier>> {
        self.visa_tap_verifier.as_ref()
    }

    /// Returns the registered x402 payment server (with its scheme registry) if initialized.
    pub fn x402_server(&self) -> Option<&Arc<X402PaymentServer>> {
        self.x402_server.as_ref()
    }

    /// Returns the x402 facilitator (verify/settle role) if the payment
    /// gateway is up. The web server mounts the `/facilitator/x402/*` routes
    /// over this so external resource servers can forward payment payloads.
    pub fn x402_facilitator(
        &self,
    ) -> Option<&Arc<tenzro_payments::x402::X402Facilitator>> {
        self.x402_facilitator.as_ref()
    }

    /// Returns the x402 Bazaar resource catalog if the payment gateway is up.
    pub fn bazaar_catalog(&self) -> Option<&Arc<tenzro_payments::x402::ResourceCatalog>> {
        self.bazaar_catalog.as_ref()
    }

    /// Returns the distributed database registry if initialized.
    pub fn database_registry(&self) -> Option<&Arc<tenzro_database::DatabaseRegistry>> {
        self.database_registry.as_ref()
    }

    /// Returns the live database-engine backend registry (always present, may be
    /// empty if this node links no engine driver).
    pub fn db_engine_registry(&self) -> &Arc<crate::db_engine_registry::EngineRegistry> {
        &self.db_engine_registry
    }

    /// Returns the managed-database usage meter (always present; durable once
    /// storage is up).
    pub fn db_usage_meter(&self) -> &Arc<tenzro_database::DatabaseUsageMeter> {
        &self.db_usage_meter
    }

    /// Returns the static-site registry (always present; durable once storage
    /// is up).
    pub fn site_registry(&self) -> &Arc<crate::sites::SiteRegistry> {
        &self.site_registry
    }

    /// Returns the dynamic-ingress placement table (always present; durable
    /// once storage is up).
    pub fn ingress_table(&self) -> &Arc<crate::ingress::IngressTable> {
        &self.ingress_table
    }

    /// Returns the app-hosting placement scheduler (always present; durable once
    /// storage is up).
    pub fn placement_scheduler(&self) -> &Arc<crate::placement::PlacementScheduler> {
        &self.placement_scheduler
    }

    /// Distill the current provider-announcement snapshot into placement
    /// candidates. Each fresh announcement that carries a bound iroh endpoint and
    /// advertises at least one hosting runtime class becomes a [`NodeCandidate`];
    /// placement's `select` applies the per-request filters (class, TEE, headroom,
    /// price ceiling, reachability) on top. A node advertising no hosting runtime
    /// is dropped here so it never enters ranking.
    pub fn hosting_candidates(&self) -> Vec<crate::placement::NodeCandidate> {
        distill_hosting_candidates(&self.network_providers)
    }

    /// Best-effort auto-placement for a deployment. Selects serving nodes from
    /// the current announcement snapshot and writes the ingress routing table.
    /// A deployment with no capable remote node is left with an empty placement
    /// — the edge then serves it locally on whichever node receives the request,
    /// so deploy never fails for want of a remote host. Returns the chosen
    /// serving-node ids (empty when placed locally).
    pub fn auto_place(&self, req: &crate::placement::PlacementRequest) -> Vec<String> {
        let candidates = self.hosting_candidates();
        let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
        match self.placement_scheduler.select_and_lease(
            req,
            &candidates,
            now_ms,
            crate::placement::DEFAULT_LEASE_MS,
        ) {
            Ok(nodes) => {
                tracing::info!(
                    app_id = %req.app_id,
                    class = req.class.as_str(),
                    replicas = nodes.len(),
                    "auto-placed deployment onto {} serving node(s)",
                    nodes.len()
                );
                nodes
            }
            Err(e) => {
                tracing::debug!(
                    app_id = %req.app_id,
                    class = req.class.as_str(),
                    "no remote placement ({e}); deployment serves locally"
                );
                Vec::new()
            }
        }
    }

    /// Returns the function-deployment registry (always present; durable once
    /// storage is up).
    pub fn function_registry(&self) -> &Arc<crate::functions::FunctionRegistry> {
        &self.function_registry
    }

    /// Returns the compiled `wasi:http` component cache used to serve function
    /// deployments. Present only when built with the `wasi-skills` feature.
    #[cfg(feature = "wasi-skills")]
    pub fn function_components(&self) -> &Arc<crate::functions::FunctionComponentCache> {
        &self.function_components
    }

    /// Returns the WASI 0.2 component sandbox backing the `code-executor`
    /// builtin tool. Present only when built with the `wasi-skills` feature.
    #[cfg(feature = "wasi-skills")]
    pub fn sandboxed_tools(&self) -> &crate::mcp::wasm_tools::SandboxedToolRegistry {
        &self.sandboxed_tools
    }

    /// Returns the machine-deployment registry (always present; durable once
    /// storage is up).
    pub fn machine_registry(&self) -> &Arc<crate::machines::MachineRegistry> {
        &self.machine_registry
    }

    /// Returns the Firecracker microVM supervisor if this node can run machine
    /// apps. Present only when built with the `firecracker` feature and after
    /// the boot path has wired it. `None` means machine requests answer 501.
    #[cfg(feature = "firecracker")]
    pub fn machine_supervisor(&self) -> Option<&Arc<crate::machines::MachineSupervisor>> {
        self.machine_supervisor.as_ref()
    }

    /// Returns the model registry if initialized
    pub fn model_registry(&self) -> Option<&Arc<ModelRegistry>> {
        self.model_registry.as_ref()
    }

    /// Returns the governance-anchored model-hash transparency log if
    /// initialized. Read by the verify-before-load gate and the model-hash
    /// RPC handlers (`tenzro_getModelHash`, `tenzro_listModelHashes`,
    /// `tenzro_recordModelHash`, `tenzro_overrideModelHash`).
    pub fn model_hash_registry(&self) -> Option<&Arc<tenzro_model::ModelHashRegistry>> {
        self.model_hash_registry.as_ref()
    }

    /// Returns the provider manager if initialized. Consumed by RPC handlers
    /// (`handle_provider_status`, `handle_register_provider`) to look up
    /// per-provider health, reputation, and circuit-breaker state.
    pub fn provider_manager(&self) -> Option<&Arc<ProviderManager>> {
        self.provider_manager.as_ref()
    }

    /// This node's own provider wallet address, resolved by
    /// [`TenzroNode::operator_payee`]. Self-installed provider entries (e.g.
    /// MoE expert-shard declarations) therefore key to the identical address
    /// remote peers see on gossip and pay at settlement.
    pub(crate) fn self_provider_address(&self) -> Option<Address> {
        self.operator_payee()
    }

    /// Returns the inference router if initialized. Wired into the web
    /// API's `/chat` handler in `main.rs` so OpenAI-compatible chat
    /// completion requests can be dispatched to the correct serving
    /// provider.
    pub fn inference_router(&self) -> Option<&Arc<InferenceRouter>> {
        self.inference_router.as_ref()
    }

    /// Owned clone of the inference router Arc, for library consumers that
    /// need to keep a reference past the lifetime of the node borrow
    /// (typical in embedded-node apps where the app's UI thread shares a
    /// router with the node's RPC dispatcher).
    pub fn inference_router_arc(&self) -> Option<Arc<InferenceRouter>> {
        self.inference_router.clone()
    }

    /// Returns the committee-resident Red Stuff DA backend if this node is a
    /// validator with committee-DA wired. Read by the `tenzro_daChallenge`,
    /// `tenzro_daListChallenges`, `tenzro_daAvailability`, `tenzro_daCommittee`,
    /// and `tenzro_daListBlobs` RPC handlers.
    pub fn da_committee(&self) -> Option<&Arc<crate::da_committee::DaCommitteeBackend>> {
        self.da_committee_backend.as_ref()
    }

    /// Returns the meta-router (intent → model) if initialized. Read by the
    /// `tenzro_routeIntent` and `tenzro_chatByIntent` RPC handlers.
    pub fn meta_router(&self) -> Option<&Arc<tenzro_model::meta_router::MetaRouter>> {
        self.meta_router.as_ref()
    }

    /// Owned clone of the shared `ModelRuntime` Arc. The runtime is
    /// process-global by design (one `llama.cpp` backend per node), so
    /// every consumer — the RPC `tenzro_chat` handler, the embedded
    /// `/v1/chat/completions` web surface, the desktop app's local chat
    /// pane, and any provider-side serving wiring — must share this Arc
    /// rather than instantiating their own. Returns `None` only when AI
    /// infrastructure was disabled at startup.
    pub fn model_runtime_arc(&self) -> Option<Arc<ModelRuntime>> {
        self.model_runtime.clone()
    }

    /// Returns the local TEE hardware provider if one was detected at
    /// startup. Used by the RPC `tenzro_getAttestation` handler and the
    /// MCP `attest` tool to generate attestations against the local
    /// enclave without re-running TEE auto-detection on every request.
    pub fn tee_provider(&self) -> Option<&dyn TeeProvider> {
        self.tee_provider.as_deref()
    }

    /// Checks whether this node's hardware can back every role in `roles`,
    /// returning a human-readable error naming the first role it cannot serve.
    ///
    /// The gate exists so a node cannot advertise a capability it does not
    /// have — otherwise any peer could claim to be a TEE or storage provider
    /// and collect work it can't honor. The policy is deliberately uneven:
    ///
    /// - `TeeProvider` is hard-gated: the node must have detected real TEE
    ///   hardware at startup (`tee_provider.is_some()`). Confidential compute
    ///   is a trust claim, so a self-report is never enough — and the quote is
    ///   re-verified at request time regardless.
    /// - `StorageProvider` requires verified free disk at or above
    ///   [`MIN_STORAGE_PROVIDER_FREE_GB`]. Capacity is the one storage input a
    ///   node cannot fake.
    /// - `CloudProvider` requires free disk at or above
    ///   [`MIN_CLOUD_PROVIDER_FREE_GB`] to hold the bundles it serves.
    /// - `ComputeProvider` requires a detected accelerator. The role rents the
    ///   card out by the hour, so a node without one has nothing to sell.
    /// - `ModelProvider` is permissionless: the floor is "can run the smallest
    ///   model on CPU" (Gemma 3 270M), which every machine that boots the node
    ///   clears, so there is nothing to reject. A GPU only widens which larger
    ///   models the node can serve, never whether it may join.
    /// - Validator / full-node / client roles are gated by stake and protocol
    ///   elsewhere, not by hardware, so they always pass here.
    pub async fn validate_role_capability(
        &self,
        roles: &RoleSet,
    ) -> std::result::Result<(), String> {
        if roles.serves_tee() && self.tee_provider.is_none() {
            return Err(
                "cannot serve the 'tee' role: no TEE hardware detected on this node \
                 (Intel TDX, AMD SEV-SNP, or AWS Nitro required)"
                    .to_string(),
            );
        }

        if roles.serves_storage() || roles.serves_cloud() || roles.serves_compute() {
            // The hardware profile is populated lazily (first probe RPC), so an
            // absent profile means "not measured yet", not "zero disk" — detect
            // and cache on demand rather than rejecting on a missing reading.
            let measured = self.hardware_profile.read().clone();
            let profile = match measured {
                Some(hw) => hw,
                None => {
                    let hw = detect_hardware(&self.config.data_dir)
                        .await
                        .map_err(|e| format!("hardware probe failed: {e}"))?;
                    *self.hardware_profile.write() = Some(hw.clone());
                    hw
                }
            };

            let free_gb = profile.storage_available_gb;
            if roles.serves_storage() && free_gb < MIN_STORAGE_PROVIDER_FREE_GB {
                return Err(format!(
                    "cannot serve the 'storage' role: {free_gb:.1} GB free disk, \
                     need at least {MIN_STORAGE_PROVIDER_FREE_GB:.0} GB"
                ));
            }
            if roles.serves_cloud() && free_gb < MIN_CLOUD_PROVIDER_FREE_GB {
                return Err(format!(
                    "cannot serve the 'cloud' role: {free_gb:.1} GB free disk, \
                     need at least {MIN_CLOUD_PROVIDER_FREE_GB:.0} GB to hold site, \
                     function and machine images"
                ));
            }
            if roles.serves_compute() && profile.gpus.is_empty() {
                return Err(
                    "cannot serve the 'compute' role: no accelerator detected on this node \
                     (compute rents the card out by the hour, so there has to be one)"
                        .to_string(),
                );
            }
        }

        Ok(())
    }

    /// Soft connectivity gate for *runtime* role changes. A node opting into a
    /// role that serves traffic must be reachable on *some*
    /// lane, or the work routed to it would silently fail. The gate accepts any
    /// reachable WAN tier — a directly-dialable node and a relay-reachable node
    /// both pass — *and* a node that has only a confirmed local-network peer: a
    /// cluster behind one NAT is unreachable on the public mesh yet fully
    /// serveable to its own segment, which is exactly the local-MoE case. Only
    /// a node with no confirmed path on any lane is turned away, and it can
    /// retry once its reachability stabilizes. The request router uses the
    /// finer tier ([`reachability_tier`]) to prefer direct providers over
    /// relay-only ones.
    ///
    /// This is deliberately *not* part of [`validate_role_capability`], which
    /// runs at startup before any reachability probe has completed — gating on
    /// connectivity there would strip every node of its serving roles on boot.
    /// Connectivity is only meaningful once the node has been live long enough
    /// for AutoNAT / relay / mDNS events to arrive, which is exactly the
    /// `setRole` case.
    pub fn validate_role_connectivity(
        &self,
        roles: &RoleSet,
    ) -> std::result::Result<(), String> {
        let serves_traffic = roles.serves_ai()
            || roles.serves_storage()
            || roles.serves_tee()
            || roles.serves_compute()
            || roles.serves_cloud();
        if !serves_traffic {
            return Ok(());
        }
        match self.network.as_ref() {
            // No network service wired (e.g. a client-only embedding) — nothing
            // to gate on; defer to the other checks.
            None => Ok(()),
            Some(network) if network.reachability().can_serve_anywhere() => Ok(()),
            Some(_) => Err(
                "cannot serve a traffic role yet: this node is not reachable on any lane \
                 (no direct address confirmed, no relay reservation held, and no \
                 local-network peer discovered). Reachability stabilizes as the node stays \
                 connected — retry once it does, open inbound connectivity / a relay path, \
                 or join a peer on the same local network."
                    .to_string(),
            ),
        }
    }

    /// The node's current connectivity tier, or `None` if the network service
    /// is not running. Read by the request router to prefer directly-reachable
    /// providers over relay-only ones.
    pub fn reachability_tier(&self) -> Option<tenzro_network::ReachabilityTier> {
        self.network.as_ref().map(|n| n.reachability().tier())
    }

    /// The set of peer IDs on this node's local network segment (mDNS-
    /// discovered), or `None` if networking is not running. Read by the
    /// request router to prefer a same-LAN provider over any WAN provider.
    pub fn local_peers(&self) -> Option<Arc<tenzro_network::LocalPeerSet>> {
        self.network.as_ref().map(|n| n.local_peers())
    }

    /// Removes from `config.roles` any role this node's hardware can't back,
    /// logging each drop. Called once at startup after TEE detection so every
    /// downstream reader (runtime spawn, capability announce, status) sees only
    /// roles the node can honor. A node never fails to boot over this — it just
    /// comes up serving fewer roles.
    async fn prune_unsupported_roles(&mut self) {
        let mut kept = Vec::new();
        let mut dropped = false;
        for role in self.config.roles.iter() {
            match self
                .validate_role_capability(&RoleSet::from_roles([role]))
                .await
            {
                Ok(()) => kept.push(role),
                Err(reason) => {
                    warn!("Dropping role '{role}' at startup: {reason}");
                    dropped = true;
                }
            }
        }
        if dropped {
            // Empty input falls back to the client role, so a node that loses
            // every configured role still has a valid identity.
            let pruned = RoleSet::from_roles(kept);
            info!("Roles after capability check: {pruned}");
            self.config.roles = pruned;
            *self.runtime_roles.write() = self.config.roles.clone();
        }
    }

    /// Returns the durable usage tracker, the producer-side recipient of
    /// every successful inference's `UsageRecord`. Used by the
    /// `tenzro_listInferenceUsage` and `tenzro_getProviderReputation`
    /// RPC handlers to surface marketplace observability data.
    pub fn usage_tracker(&self) -> Option<&Arc<tenzro_model::UsageTracker>> {
        self.usage_tracker.as_ref()
    }

    /// Returns the EU AI Act Art. 50(2) provenance store. Populated by the
    /// inference router on every successful response and queried by the
    /// `tenzro_getProvenance` RPC handler.
    pub fn provenance_store(&self) -> Option<&Arc<tenzro_model::ProvenanceStore>> {
        self.provenance_store.as_ref()
    }

    /// Returns the provenance signer used to stamp locally-served inference
    /// responses with a `tenzro_provenance` manifest.
    pub fn provenance_signer(&self) -> Option<&tenzro_model::SharedProvenanceSigner> {
        self.provenance_signer.as_ref()
    }

    /// Returns the jurisdiction signer used to stamp locally-served
    /// inference responses with a `tenzro_jurisdiction` receipt.
    pub fn jurisdiction_signer(&self) -> Option<&tenzro_model::SharedJurisdictionSigner> {
        self.jurisdiction_signer.as_ref()
    }

    /// Returns the sealed-model manifest store (write-through to the
    /// `sealed:` prefix in CF_MODELS).
    pub fn sealed_model_store(&self) -> Option<&Arc<tenzro_model::SealedModelStore>> {
        self.sealed_model_store.as_ref()
    }

    /// Returns this node's X25519 recipient keypair for sealed model
    /// shards. `None` when the key file could not be loaded or minted.
    pub fn model_recipient_key(
        &self,
    ) -> Option<&Arc<tenzro_crypto::encryption::X25519KeyPair>> {
        self.model_recipient_key.as_ref()
    }

    /// Returns this node's operator-declared jurisdiction claim, if any.
    /// Built once at startup; `None` means the node never satisfies a
    /// jurisdiction pin.
    pub fn jurisdiction_claim(&self) -> Option<&tenzro_types::JurisdictionClaim> {
        self.jurisdiction_claim.as_ref()
    }

    /// Returns the event loop sender for submitting transactions
    pub fn event_sender(&self) -> Option<&mpsc::Sender<NodeEvent>> {
        self.event_loop_tx.as_ref()
    }

    /// Returns the storage backend if initialized
    pub fn storage(&self) -> Option<&Arc<RocksDbStore>> {
        self.storage.as_ref()
    }

    /// Returns the EIP-7702 delegation registry handle.
    pub fn eip7702_delegation_registry(
        &self,
    ) -> Arc<tenzro_vm::eip7702::DelegationRegistry> {
        self.eip7702_delegation_registry.clone()
    }

    /// Returns the Permit2 nonce bitmap handle.
    pub fn permit2_nonce_bitmap(
        &self,
    ) -> Arc<tenzro_vm::permit2::Permit2NonceBitmap> {
        self.permit2_nonce_bitmap.clone()
    }

    /// Returns the Secure-Mint registry handle.
    pub fn secure_mint_registry(
        &self,
    ) -> Arc<tenzro_vm::secure_mint::SecureMintRegistry> {
        self.secure_mint_registry.clone()
    }

    pub fn chainlink_por_adapter(&self) -> Arc<tenzro_bridge::ChainlinkPorAdapter> {
        self.chainlink_por_adapter.clone()
    }

    pub fn corporate_action_engine(
        &self,
    ) -> Arc<tenzro_vm::corporate_actions::CorporateActionEngine> {
        self.corporate_action_engine.clone()
    }

    pub fn saga_orchestrator(&self) -> Arc<tenzro_settlement::SagaOrchestrator> {
        self.saga_orchestrator.clone()
    }

    pub fn netting_manager(&self) -> Arc<tenzro_settlement::NettingManager> {
        self.netting_manager.clone()
    }

    /// Spawn the stable-unit controller driver loop. Every `period_secs` it
    /// runs one peg/buffer epoch per registered unit, sizing supply moves
    /// against the SecureMint floor. Price and buffer observations come from
    /// the supplied sources, so this is only spawned once a node has live
    /// telemetry wired — the driver never fabricates a market price.
    pub fn start_stable_controller(
        &self,
        price_source: Arc<dyn crate::stable_controller_driver::MarketPriceSource>,
        buffer_source: Arc<dyn crate::stable_controller_driver::BufferValueSource>,
        period_secs: u64,
    ) {
        let driver = Arc::new(crate::stable_controller_driver::StableControllerDriver::new(
            self.stable_asset_registry.clone(),
            self.secure_mint_registry.clone(),
            price_source,
            buffer_source,
        ));
        tokio::spawn(async move {
            let mut tick =
                tokio::time::interval(std::time::Duration::from_secs(period_secs.max(1)));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // skip the immediate fire
            loop {
                tick.tick().await;
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                for step in driver.step_all(now_secs) {
                    if step.applied_delta != 0 {
                        info!(
                            symbol = %step.symbol,
                            applied_delta = step.applied_delta,
                            band = ?step.output.band,
                            buffer_action = ?step.output.buffer_action,
                            "stable controller actuated supply"
                        );
                    }
                }
            }
        });
        info!("Stable controller driver started (every {period_secs}s)");
    }

    /// Returns the stable-asset registry handle.
    pub fn stable_asset_registry(
        &self,
    ) -> Arc<tenzro_vm::stable_asset_registry::StableAssetRegistry> {
        self.stable_asset_registry.clone()
    }

    /// Returns the stable-unit rate oracle handle.
    pub fn stable_rate_oracle(
        &self,
    ) -> Arc<tenzro_vm::stable_rate_oracle::GovernanceSetRateOracle> {
        self.stable_rate_oracle.clone()
    }

    /// Returns the ERC-7943 (uRWA) registry handle. EVM transfer hook
    /// consults this for kill-switch + freeze enforcement; mutation
    /// RPCs write through.
    pub fn urwa_registry(
        &self,
    ) -> Arc<tenzro_vm::erc7943::UrwaRegistry> {
        self.urwa_registry.clone()
    }

    /// Returns the Cosmos-style snapshot ABCI store if initialized.
    ///
    /// Used by the four snapshot RPCs and by the EventLoop's periodic
    /// snapshot producer.
    pub fn snapshot_store(&self) -> Option<&Arc<crate::snapshot::SnapshotStore>> {
        self.snapshot_store.as_ref()
    }

    /// Shared handle to the on-node ZK commitment registry.
    ///
    /// The EVM `ZK_VERIFY` precompile (0x0101) returns `1` iff the
    /// queried commitment hash is present in this set. Off-EVM
    /// callers — primarily the `tenzro_verifyZkProof` RPC handler —
    /// MUST insert a commitment via `attest()` after a successful
    /// `verify_proof_envelope`, otherwise downstream EVM contracts
    /// that gate on ZK verification will reject otherwise-valid
    /// proofs.
    pub fn zk_commitment_registry(&self)
        -> &Arc<tenzro_vm::precompiles::ZkCommitmentRegistry>
    {
        &self.zk_commitment_registry
    }

    /// The quorum-gated ZK attestation store, present only on validator nodes
    /// holding a BLS key. When present, the RPC verify path admits a commitment
    /// to [`Self::zk_commitment_registry`] only after collecting a `2f+1`
    /// quorum certificate, and opens a fraud-proof window. When absent (RPC-only
    /// / non-validator nodes), the verify path has no way to co-sign or gate, so
    /// the commitment is not self-attested — it is picked up from a validator's
    /// gossiped claim instead.
    pub fn zk_quorum_store(&self) -> Option<&Arc<tenzro_consensus::ZkQuorumStore>> {
        self.zk_quorum_store.as_ref()
    }

    /// Publish a proof envelope this node has independently verified to the DA
    /// layer, returning the `tenzro://blob/<hash>` locator co-signers use to
    /// fetch and re-verify it. Returns `None` when no iroh resolver is bound
    /// (the quorum plane is then inert on this node).
    pub async fn publish_zk_proof_for_quorum(
        &self,
        envelope: &tenzro_zk::Proof,
    ) -> Option<String> {
        let resolver = self.iroh_resolver.as_ref()?;
        let bytes = match serde_json::to_vec(envelope) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "zk-quorum: failed to encode proof envelope for DA");
                return None;
            }
        };
        use tenzro_iroh::IrohResolver;
        match resolver.publish_bytes(bytes.into()).await {
            Ok(uri) => Some(uri.to_string()),
            Err(e) => {
                warn!(error = %e, "zk-quorum: failed to publish proof to DA");
                None
            }
        }
    }

    /// Fetch a proof envelope from its DA locator and deterministically re-run
    /// `verify_proof_envelope`. Returns the boolean verification result, or an
    /// error string when the proof could not be fetched/decoded (a fetch
    /// failure is NOT a verification failure — a challenger cannot be slashed
    /// for an unavailable proof).
    pub async fn reverify_zk_proof_at_locator(
        &self,
        proof_locator: &str,
    ) -> std::result::Result<bool, String> {
        let resolver = self
            .iroh_resolver
            .as_ref()
            .ok_or_else(|| "no DA resolver bound; cannot fetch proof".to_string())?;
        let uri = tenzro_iroh::TenzroUri::parse(proof_locator)
            .map_err(|e| format!("invalid proof locator: {e}"))?;
        use tenzro_iroh::IrohResolver;
        let bytes = resolver
            .fetch_bytes(&uri)
            .await
            .map_err(|e| format!("proof fetch failed: {e}"))?;
        let envelope: tenzro_zk::Proof = serde_json::from_slice(&bytes)
            .map_err(|e| format!("proof decode failed: {e}"))?;
        let verify = tokio::task::spawn_blocking(move || {
            tenzro_zk::verify_proof_envelope(&envelope)
        })
        .await
        .map_err(|e| format!("verify task join error: {e}"))?;
        Ok(verify.is_ok())
    }

    /// Record a co-signature toward a commitment's quorum, and when quorum is
    /// reached, verify the certificate, attest the commitment to the on-chain
    /// registry, and open its fraud-proof window. Returns `true` iff the
    /// commitment was newly attested by this call. Shared by the RPC verify
    /// path (own initiating co-sign) and the gossip consumer (peer co-signs).
    pub fn record_zk_cosign_and_maybe_attest(
        &self,
        circuit_id: &str,
        cosign: tenzro_consensus::ZkCosign,
        proof_locator: &str,
    ) -> bool {
        let Some(store) = self.zk_quorum_store.as_ref() else {
            return false;
        };
        let Some(consensus) = self.consensus.as_ref() else {
            return false;
        };
        let validator_set = consensus.validator_set();
        let commitment = cosign.commitment;
        match store.record_cosign(circuit_id, cosign, &validator_set) {
            Ok(Some(cert)) => {
                if let Err(e) = cert.verify(&validator_set) {
                    warn!(error = %e, "zk-quorum: formed certificate failed verify; not attesting");
                    return false;
                }
                let hash: tenzro_vm::precompiles::ZkCommitmentHash = commitment;
                let newly = self.zk_commitment_registry.attest(hash);
                let height = consensus.current_finalized_height().0;
                store.open_fraud_window(cert, proof_locator.to_string(), height);
                info!(
                    commitment = %hex::encode(commitment),
                    height,
                    "zk-quorum: commitment attested under 2f+1 certificate; fraud window open"
                );
                newly
            }
            Ok(None) => false,
            Err(e) => {
                warn!(error = %e, "zk-quorum: record_cosign rejected");
                false
            }
        }
    }

    /// Resolve a fraud proof filed against an attested ZK commitment.
    ///
    /// Any staked party may challenge a commitment that is inside its fraud
    /// window. This node fetches the proof from the record's DA locator, re-runs
    /// `verify_proof_envelope` deterministically, and resolves:
    ///
    /// - re-verify succeeds (`Unfounded`): the commitment stands; the caller's
    ///   challenge bond is forfeit (bond handling is the RPC layer's concern).
    /// - re-verify fails (`Upheld`): the commitment is retracted from both the
    ///   quorum store and the on-chain [`ZkCommitmentRegistry`], and every
    ///   co-signer named on the certificate is slashed for a consensus offence.
    ///
    /// A proof that cannot be fetched is NOT a verification failure — no one is
    /// slashed for an unavailable proof; the challenge simply cannot be
    /// adjudicated and returns an error.
    pub async fn resolve_zk_fraud_proof(
        &self,
        commitment: &[u8; 32],
    ) -> std::result::Result<tenzro_consensus::FraudOutcome, String> {
        let store = self
            .zk_quorum_store
            .as_ref()
            .ok_or_else(|| "node holds no ZK quorum store".to_string())?;
        let consensus = self
            .consensus
            .as_ref()
            .ok_or_else(|| "consensus engine not initialized".to_string())?;
        let record = store
            .attested(commitment)
            .ok_or_else(|| "commitment is not inside any open fraud window".to_string())?;

        // Deterministic re-run over the proof bytes fetched from DA.
        let reverified = self
            .reverify_zk_proof_at_locator(&record.proof_locator)
            .await?;

        let validator_set = consensus.validator_set();
        let height = consensus.current_finalized_height().0;
        let (outcome, accountable) = store
            .resolve_fraud_proof(commitment, height, reverified, &validator_set)
            .map_err(|e| format!("fraud resolution rejected: {e}"))?;

        if let tenzro_consensus::FraudOutcome::Upheld = outcome {
            // Retract from the on-chain registry so the ZK_VERIFY precompile
            // stops treating the commitment as valid.
            let retracted = self.zk_commitment_registry.retract(commitment);
            warn!(
                commitment = %hex::encode(commitment),
                retracted,
                co_signers = accountable.len(),
                "zk-quorum: fraud proof UPHELD; commitment retracted, slashing co-signers"
            );
            // Slash every accountable co-signer through the consensus slash path.
            if let Some(staking) = self.staking.as_ref() {
                let mut cb = StakingSlashingCallback::new(staking.clone())
                    .with_epoch_manager(consensus.epoch_manager());
                if let Some(reg) = self.validator_registry.as_ref() {
                    cb = cb.with_validator_registry(reg.clone());
                }
                let reason = format!(
                    "ZK fraud proof upheld: co-signed an invalid commitment {}",
                    hex::encode(commitment)
                );
                for validator in &accountable {
                    cb.report_zk_fraud(validator, height, reason.clone());
                }
            } else {
                warn!("zk-quorum: no staking manager; cannot slash upheld-fraud co-signers");
            }
        } else {
            info!(
                commitment = %hex::encode(commitment),
                "zk-quorum: fraud proof UNFOUNDED; commitment stands, challenger bond forfeit"
            );
        }
        Ok(outcome)
    }

    /// Set the state-sync peer URL. Must be called BEFORE
    /// [`TenzroNode::start`]; the start sequence checks this field
    /// between `init_storage` and `init_network` and, if set, fetches
    /// the highest snapshot from that peer's JSON-RPC endpoint.
    pub fn set_state_sync_peer(&mut self, peer_url: String) {
        self.state_sync_peer = Some(peer_url);
    }

    /// Set the weak-subjectivity state-root anchor for state-sync.
    /// MUST be the 32-byte state root committed at the snapshot height
    /// the peer will serve. Operators obtain this value out of band
    /// (signed gossip from a known-good validator, a published
    /// checkpoint, or a personally-verified RPC). Without this anchor,
    /// `bootstrap_from_peer` refuses to apply any chunks.
    pub fn set_state_sync_anchor(&mut self, anchor: [u8; 32]) {
        self.state_sync_anchor = Some(anchor);
    }

    /// Set the weak-subjectivity checkpoint enforced on the *block-sync*
    /// path: `(height, state_root)`. A node that catches up by replaying
    /// blocks from peers (as opposed to snapshot bootstrap) verifies each
    /// imported block's commit-QC against the validator set for that
    /// height, but QC verification alone cannot defeat a *long-range*
    /// fork: an attacker holding an old validator supermajority's keys can
    /// forge a self-consistent alternate history from any past epoch. The
    /// anchor pins one finalized `(height, state_root)` the node trusts a
    /// priori; when the import path reaches `height`, the block's
    /// `state_root` must match `state_root` byte-for-byte or the import is
    /// rejected. Obtained out of band, identical to the snapshot anchor.
    pub fn set_weak_subjectivity_anchor(
        &mut self,
        height: u64,
        anchor: [u8; 32],
    ) {
        self.weak_subjectivity_anchor = Some((height, anchor));
    }

    /// Returns the consensus engine if initialized.
    ///
    /// RPC handlers use this to inspect the in-flight mempool — e.g.
    /// `tenzro_getTransaction` falls back to the mempool when a hash isn't yet
    /// in `CF_TRANSACTIONS`, so callers can distinguish "pending" from "unknown"
    /// without polling forever.
    pub fn consensus(&self) -> Option<&Arc<HotStuff2Engine>> {
        self.consensus.as_ref()
    }

    /// Returns the staking manager if initialized
    pub fn staking(&self) -> Option<&Arc<StakingManager>> {
        self.staking.as_ref()
    }

    /// Returns the network treasury if initialized
    pub fn treasury(&self) -> Option<&Arc<NetworkTreasury>> {
        self.treasury.as_ref()
    }

    /// Returns the storage-provider runtime if this node serves the
    /// StorageProvider role and the runtime was spawned at startup.
    pub fn storage_runtime(
        &self,
    ) -> Option<&Arc<crate::storage_provider_runtime::StorageProviderRuntime>> {
        self.storage_runtime.as_ref()
    }

    /// Returns the compute-rental runtime if this node serves AI and the
    /// runtime was spawned at startup.
    pub fn compute_runtime(
        &self,
    ) -> Option<&Arc<crate::compute_rental_runtime::ComputeRentalRuntime>> {
        self.compute_runtime.as_ref()
    }

    /// Returns the prepaid-balance ledger if a provider runtime was spawned with
    /// durable storage and the token subsystem available.
    pub fn prepaid_ledger(&self) -> Option<&Arc<tenzro_settlement::PrepaidLedger>> {
        self.prepaid_ledger.as_ref()
    }

    /// Returns the liquid staking pool (stTNZO) if initialized.
    pub fn liquid_staking_pool(
        &self,
    ) -> Option<&Arc<tenzro_token::LiquidStakingPool>> {
        self.liquid_staking_pool.as_ref()
    }

    /// Returns the Spec-2 admission controller if initialized. Wired
    /// during startup once consensus, identity, and staking are all up.
    pub fn admission(&self) -> Option<&Arc<tenzro_consensus::admission::AdmissionController>> {
        self.admission.as_ref()
    }

    /// Returns the token if initialized
    pub fn token(&self) -> Option<&Arc<TnzoToken>> {
        self.token.as_ref()
    }

    /// Returns the unified token registry if initialized
    pub fn token_registry(&self) -> Option<&Arc<TokenRegistry>> {
        self.token_registry.as_ref()
    }

    /// Returns the VM runtime if initialized
    pub fn vm_runtime(&self) -> Option<&Arc<MultiVmRuntime>> {
        self.vm_runtime.as_ref()
    }

    /// Returns the wallet service if initialized
    pub fn wallet_service(&self) -> Option<&Arc<TenzroWalletService>> {
        self.wallet_service.as_ref()
    }

    /// Returns the governance engine if initialized
    pub fn governance(&self) -> Option<&Arc<GovernanceEngine>> {
        self.governance.as_ref()
    }

    pub fn settlement(&self) -> Option<&Arc<SettlementEngine>> {
        self.settlement.as_ref()
    }

    pub fn channel_manager(&self) -> Option<&Arc<ChannelManager>> {
        self.channel_manager.as_ref()
    }

    pub fn escrow_manager(&self) -> Option<&Arc<EscrowManager>> {
        self.escrow_manager.as_ref()
    }

    /// Returns the ERC-7683 destination-side fill registry if initialized
    /// (Agent-Swarm Spec 4). Used by the destination settler precompile and
    /// the `tenzro_recordFill7683` / `tenzro_getFill7683` /
    /// `tenzro_listFills7683` RPCs.
    pub fn spec4_fill_registry(&self) -> Option<&Arc<Spec4FillRegistry>> {
        self.spec4_fill_registry.as_ref()
    }

    /// Returns the kill-switch receipt store if initialized.
    pub fn kill_switch_store(&self) -> Option<&Arc<tenzro_settlement::KillSwitchStore>> {
        self.kill_switch_store.as_ref()
    }

    /// Returns the AgentBond surety manager if initialized (Agent-Swarm Spec 9).
    pub fn bond_manager(&self) -> Option<&Arc<tenzro_token::bond::BondManager>> {
        self.bond_manager.as_ref()
    }

    /// Returns the ComputeBond surety manager if initialized (Phase A #153).
    pub fn compute_bond_manager(
        &self,
    ) -> Option<&Arc<tenzro_token::compute_bond::ComputeBondManager>> {
        self.compute_bond_manager.as_ref()
    }

    /// Returns the verifiable-inference commitment store + challenge
    /// manager if initialized. `Some` only when RocksDB storage is
    /// available. Read by the chat/inference handlers (commitment
    /// write path) and the `tenzro_*Inference{Commitment,Challenge}`
    /// RPC handlers.
    pub fn challenge_manager(
        &self,
    ) -> Option<&Arc<crate::inference_challenge::ChallengeManager>> {
        self.challenge_manager.as_ref()
    }

    /// Returns the SLA fault detector if initialized. `Some` only on
    /// validator-role nodes — the slashing authority requires consensus
    /// participation. Read by the `tenzro_sla*` RPC handlers.
    pub fn sla_manager(&self) -> Option<&Arc<tenzro_model::SlaManager>> {
        self.sla_manager.as_ref()
    }

    /// Returns the in-flight SLA probe correlator. Always present; empty on
    /// non-validator nodes. Probes inserted here by `tenzro_slaIssueProbe`
    /// are removed by the `tenzro/sla` gossipsub subscriber when a matching
    /// `SlaResponse` arrives.
    pub fn sla_outstanding_probes(
        &self,
    ) -> &Arc<DashMap<String, tenzro_model::SlaProbe>> {
        &self.sla_outstanding_probes
    }

    /// Returns the DKG session registry. Always present; populated by
    /// `tenzro_mpcKeygen` and polled by `tenzro_mpcKeygenStatus`.
    pub fn mpc_keygen_sessions(&self) -> &Arc<crate::mpc_keygen::KeygenSessionRegistry> {
        &self.mpc_keygen_sessions
    }

    /// Returns the WorkflowRuntime if initialized — typed mirror of the
    /// privileged-VM workflow selectors (`0x01000040`–`0x0100004B`).
    pub fn workflow_runtime(&self) -> Option<&Arc<crate::workflow_runtime::WorkflowRuntime>> {
        self.workflow_runtime.as_ref()
    }

    /// Returns the permissionless ValidatorRegistry if initialized.
    pub fn validator_registry(
        &self,
    ) -> Option<&Arc<tenzro_token::validator_registry::ValidatorRegistry>> {
        self.validator_registry.as_ref()
    }

    /// Returns the ERC-7579 AA modular validator registry if initialized
    /// (Phase B Thread 3 / B.3.5). Distinct from `validator_registry()`
    /// (consensus validators). Used by #164 to install
    /// `DelegationScopeValidator` per machine identity, and by #165 to
    /// route inbound AA UserOps through `EntryPoint::validate_user_op`.
    pub fn aa_validator_registry(
        &self,
    ) -> Option<&Arc<tenzro_vm::aa_validators::ValidatorRegistry>> {
        self.aa_validator_registry.as_ref()
    }

    /// Returns the ERC-4337 v0.8 EntryPoint singleton if initialized
    /// (Phase B Thread 3c / #165). Wired to `aa_validator_registry()` for
    /// signature validation and to `vm_runtime` for actual UserOp
    /// execution. Used by the `eth_sendUserOperation` /
    /// `eth_estimateUserOperationGas` / `eth_getUserOperationReceipt` /
    /// `eth_supportedEntryPoints` JSON-RPC handlers.
    pub fn aa_entry_point(&self) -> Option<&Arc<tenzro_vm::EntryPoint>> {
        self.aa_entry_point.as_ref()
    }

    /// Returns the TEE-key oracle for autonomous-machine custody if
    /// initialized. Consulted by the `TeeBoundValidator` (module 0x1021) and
    /// the `TnzoBootstrapPaymaster`; populated by the `tenzro_enrollTeeKey`
    /// RPC handler.
    pub fn tee_key_oracle(&self) -> Option<&Arc<tenzro_vm::InMemoryTeeKeyOracle>> {
        self.tee_key_oracle.as_ref()
    }

    /// Returns the TEE-bound validator (ERC-7579 module 0x1021) if
    /// initialized. Installed per autonomous-machine smart account so every
    /// UserOp is gated on a fresh key-bound TEE attestation.
    pub fn tee_bound_validator(&self) -> Option<&Arc<tenzro_vm::TeeBoundValidator>> {
        self.tee_bound_validator.as_ref()
    }

    /// Returns the shared `IdentityScopeOracle` if initialized
    /// (Phase B Thread 3 / B.3.5). Bound into every
    /// `DelegationScopeValidator` installed in `aa_validator_registry()`
    /// so revoked / expired `DelegationScope` fails the validator at
    /// signing time.
    pub fn identity_scope_oracle(
        &self,
    ) -> Option<&Arc<crate::delegation_scope_oracle::IdentityScopeOracle>> {
        self.identity_scope_oracle.as_ref()
    }

    /// Returns the shared ERC-4337 AccountFactory if initialized.
    /// All smart accounts deployed via `tenzro_enrollPasskey` live here.
    pub fn account_factory(&self) -> Option<&Arc<tenzro_vm::AccountFactory>> {
        self.account_factory.as_ref()
    }

    /// Returns the shared SocialRecoveryValidator (ERC-7579 module).
    pub fn social_recovery_validator(
        &self,
    ) -> Option<&Arc<tenzro_vm::SocialRecoveryValidator>> {
        self.social_recovery_validator.as_ref()
    }

    /// Returns the shared SessionKeyValidator (ERC-7579 module).
    pub fn session_key_validator(
        &self,
    ) -> Option<&Arc<tenzro_vm::SessionKeyValidator>> {
        self.session_key_validator.as_ref()
    }

    /// Returns the shared SpendingLimitValidator (ERC-7579 module).
    pub fn spending_limit_validator(
        &self,
    ) -> Option<&Arc<tenzro_vm::SpendingLimitValidator>> {
        self.spending_limit_validator.as_ref()
    }

    /// Returns the shared WebAuthnValidator (passkey-bound primary validator).
    pub fn webauthn_validator(
        &self,
    ) -> Option<&Arc<tenzro_vm::WebAuthnValidator>> {
        self.webauthn_validator.as_ref()
    }

    /// Returns the HardwareSignerValidator at the given module address (the
    /// 20-byte ERC-7579 module address — `HARDWARE_VALIDATOR_LEDGER` etc.).
    /// `tenzro_addHardwareSigner` looks up the validator for the chosen
    /// device slot and calls `install_for` so the per-account config is
    /// available to the validator chain.
    pub fn hardware_signer_validator(
        &self,
        module_addr: &[u8; 20],
    ) -> Option<Arc<tenzro_vm::erc7579::HardwareSignerValidator>> {
        use tenzro_vm::aa_validators::IValidator;
        self.hardware_signer_validators.as_ref().and_then(|vs| {
            vs.iter()
                .find(|v| &v.module_address() == module_addr)
                .cloned()
        })
    }

    /// Returns the pending-recovery store used by the social-recovery flow.
    pub fn recovery_pending(
        &self,
    ) -> Option<&Arc<crate::passkey_rpc::PendingRecoveryStore>> {
        self.recovery_pending.as_ref()
    }

    /// Returns the pending passkey auth-session store used by the
    /// browser-mediated CLI login flow.
    pub fn passkey_sessions(
        &self,
    ) -> Option<&Arc<crate::passkey_rpc::PasskeySessionStore>> {
        self.passkey_sessions.as_ref()
    }

    /// Returns the BurnQuota manager if initialized (Agent-Swarm Spec 3).
    pub fn burn_quota_manager(
        &self,
    ) -> Option<&Arc<tenzro_token::burn_quota::BurnQuotaManager>> {
        self.burn_quota_manager.as_ref()
    }

    /// Returns the adaptive burn governance dial manager (Agent-Swarm Spec 8).
    pub fn burn_rate_manager(
        &self,
    ) -> Option<&Arc<tenzro_token::adaptive_burn::BurnRateConfigManager>> {
        self.burn_rate_manager.as_ref()
    }

    /// Returns the SeedAgent treasury earmark manager (Agent-Swarm Spec 10).
    pub fn seed_agent_manager(
        &self,
    ) -> Option<&Arc<tenzro_token::seed_agent::SeedAgentEarmarkManager>> {
        self.seed_agent_manager.as_ref()
    }

    /// Returns the work-gated reward engine.
    pub fn reward_engine(&self) -> Option<&Arc<tenzro_token::RewardEngine>> {
        self.reward_engine.as_ref()
    }

    /// Returns the vesting manager (reward / grant / contributor schedules).
    pub fn vesting_manager(&self) -> Option<&Arc<tenzro_token::VestingManager>> {
        self.vesting_manager.as_ref()
    }

    /// Returns the foundation sponsorship manager.
    pub fn sponsorship_manager(&self) -> Option<&Arc<tenzro_token::SponsorshipManager>> {
        self.sponsorship_manager.as_ref()
    }

    /// Returns the SeedAgent provisioning daemon (Spec 10 Task #42). `None`
    /// on non-validator roles or when the earmark subsystem is disabled.
    pub fn seed_agent_daemon(
        &self,
    ) -> Option<&Arc<tenzro_token::SeedAgentDaemon>> {
        self.seed_agent_daemon.as_ref()
    }

    /// Returns the trainer auto-provisioning daemon (Task #41). `None` when
    /// `[training].enabled` is false or no Python trainer could be resolved.
    pub fn trainer_daemon(
        &self,
    ) -> Option<&Arc<crate::trainer_daemon::TrainerDaemon>> {
        self.trainer_daemon.as_ref()
    }

    /// Returns the OAuth 2.1 + DPoP + RAR auth engine if initialized.
    pub fn auth_engine(&self) -> Option<&Arc<tenzro_auth::AuthEngine>> {
        self.auth_engine.as_ref()
    }

    /// Returns the per-client API key manager, populated once storage is
    /// initialized. Used by the RPC dispatch path to gate scoped methods
    /// (currently `tenzro_*Canton*`) behind a valid `X-Tenzro-Api-Key`
    /// header.
    pub fn api_key_manager(&self) -> Option<&Arc<crate::api_key::ApiKeyManager>> {
        self.api_key_manager.as_ref()
    }

    /// Returns the permissionless application registry, populated once
    /// storage is initialized. Used by the app-registration RPCs and the
    /// developer-signed settlement path.
    pub fn app_registry(&self) -> Option<&Arc<crate::app_registry::AppRegistry>> {
        self.app_registry.as_ref()
    }

    /// Returns the MCP plugin host if initialized. The plugin host runs
    /// operator-curated stdio + remote MCPs, holds the sealed credential
    /// vault, and dispatches `tenzro_useTool` calls for non-native tools.
    /// `None` when storage is unavailable or the operator has not
    /// configured a vault root (no TEE-derived IKM + no
    /// `mcp_vault_master_secret_hex` in node config).
    pub fn mcp_plugin_host(
        &self,
    ) -> Option<&Arc<crate::mcp_plugin_host::McpPluginHost>> {
        self.mcp_plugin_host.as_ref()
    }

    /// Returns the workflow executor if initialized. The executor
    /// drives `WorkflowTemplate` sagas to completion against the
    /// node's RPC handlers. Constructed lazily via
    /// `ensure_workflow_executor()` since the executor needs an
    /// `Arc<TenzroNode>` (for the dispatcher) which only exists after
    /// node construction.
    pub fn workflow_executor(
        &self,
    ) -> Option<Arc<crate::workflow_executor::WorkflowExecutor>> {
        self.workflow_executor.lock().clone()
    }

    /// Initialize the workflow executor if not yet present. Idempotent.
    /// Called from the `tenzro_instantiateWorkflow` handler the first
    /// time a workflow is run; subsequent calls hit the cached arc.
    pub fn ensure_workflow_executor(
        self: &Arc<Self>,
    ) -> Result<Arc<crate::workflow_executor::WorkflowExecutor>> {
        if let Some(existing) = self.workflow_executor.lock().clone() {
            return Ok(existing);
        }
        let storage = self.storage.clone().ok_or_else(|| {
            NodeError::Internal("workflow executor: storage not available".to_string())
        })?;
        let dispatcher = crate::workflow_dispatcher::NodeStepDispatcher::new(self.clone())
            as Arc<dyn crate::workflow_executor::StepDispatcher>;
        let exec = crate::workflow_executor::WorkflowExecutor::new(
            storage as Arc<dyn tenzro_storage::KvStore>,
            dispatcher,
        )
        .map_err(|e| NodeError::Internal(format!("workflow executor init: {}", e)))?;
        *self.workflow_executor.lock() = Some(exec.clone());
        Ok(exec)
    }

    /// Returns the per-tenant Canton analytics manager, populated once
    /// storage is initialized. Used by the canton RPC dispatch path to
    /// increment per-key call counters and surfaced via
    /// `tenzro_canton_getMyAnalytics` (subject self-read) and
    /// `tenzro_canton_listApiKeyAnalytics` (operator admin-read).
    pub fn canton_analytics(
        &self,
    ) -> Option<&Arc<crate::canton_analytics::CantonAnalyticsManager>> {
        self.canton_analytics.as_ref()
    }

    /// Returns the per-tenant Chainlink/bridge analytics manager. Same
    /// pattern as `canton_analytics`. Used by the bridge RPC dispatch
    /// path to attribute CU consumption to each tenant.
    pub fn bridge_analytics(
        &self,
    ) -> Option<&Arc<crate::bridge_analytics::BridgeAnalyticsManager>> {
        self.bridge_analytics.as_ref()
    }

    /// Returns the GCRA rate limiter for chainlink-scoped API keys.
    pub fn chainlink_rate_limiter(&self) -> &Arc<crate::bridge_analytics::GcraLimiter> {
        &self.chainlink_rate_limiter
    }

    /// Returns the Stage 2.b tenant-IdP provisioner, if configured.
    /// `Some(_)` means the node will auto-mint a per-tenant Auth0
    /// client (and Canton IDP) on every `tenzro_createApiKey` call
    /// with a bound `canton_user_id`. `None` means Stage 1 shared-
    /// principal flow.
    pub fn tenant_idp_provisioner(
        &self,
    ) -> Option<&Arc<dyn tenzro_bridge::tenant_idp::TenantIdpProvisioner>> {
        self.tenant_idp_provisioner.as_ref()
    }

    /// Returns the operator admin token, if one is configured for this
    /// process. The token gates operator-only mutation RPCs and is loaded
    /// from `TENZRO_ADMIN_TOKEN` at startup. `None` means the gate is
    /// fail-closed and every gated handler must reject regardless of
    /// caller input — see [`crate::api_key::verify_admin_token`].
    pub fn admin_token(&self) -> Option<&str> {
        self.admin_token.as_deref()
    }

    /// Returns the active liveness sweeper config, if the sweeper is running.
    pub fn liveness_config(&self) -> Option<crate::liveness::LivenessConfig> {
        self.liveness_sweeper.as_ref().map(|s| s.config.clone())
    }

    pub fn agent_runtime(&self) -> Option<&Arc<AgentRuntime>> {
        self.agent_runtime.as_ref()
    }

    pub fn agent_kit(&self) -> Option<&Arc<tenzro_agent_kit::AgentKit>> {
        self.agent_kit.as_ref()
    }

    pub fn swarm_manager(&self) -> Option<&Arc<SwarmManager>> {
        self.swarm_manager.as_ref()
    }

    /// Returns the network service if initialized
    pub fn network(&self) -> Option<&Arc<TenzroNetworkService>> {
        self.network.as_ref()
    }

    /// Node iroh resolver (single content-addressed endpoint). `None` until
    /// startup binds it. Used by storage-provider producers to read the local
    /// `EndpointId` when broadcasting shard-replication requests.
    pub fn iroh_resolver(&self) -> Option<&Arc<tenzro_iroh::IrohBackedResolver>> {
        self.iroh_resolver.as_ref()
    }

    /// Node Ed25519 signer for outbound model + provider gossip
    /// announcements. `None` before startup step 6b has run.
    pub fn announce_signer(
        &self,
    ) -> Option<&Arc<dyn tenzro_crypto::signatures::Signer + Send + Sync>> {
        self.announce_signer.as_ref()
    }

    /// Returns the bridge router if initialized
    pub fn bridge_router(&self) -> Option<&Arc<BridgeRouter>> {
        self.bridge_router.as_ref()
    }

    /// Returns the asset USD price oracle if configured + enabled.
    pub fn price_oracle(&self) -> Option<&Arc<tenzro_bridge::PriceOracle>> {
        self.price_oracle.as_ref()
    }

    /// Returns the Canton bridge adapter for `net`, if that network is
    /// configured. Used by `tenzro_mirror*` / `tenzro_consumeDamlEvents`
    /// RPC handlers via `canton_adapter_or_err`, which resolves the
    /// network from the presenting API key.
    pub fn canton_adapter(
        &self,
        net: crate::config::CantonNetwork,
    ) -> Option<&Arc<tenzro_bridge::canton::CantonAdapter>> {
        self.canton_adapters.get(&net)
    }

    /// Every Canton network this node serves, in canonical order.
    pub fn canton_networks(&self) -> Vec<crate::config::CantonNetwork> {
        self.canton_adapters.keys().copied().collect()
    }

    /// Returns the TNZO CCT bridge if CCIP was enabled at init time.
    /// Used by `tenzro_cct*` RPC handlers that need to build CCT-formatted
    /// CCIP messages against the canonical TNZO pool registry.
    pub fn cct_bridge(&self) -> Option<&Arc<TnzoCctBridge>> {
        self.cct_bridge.as_ref()
    }

    /// Returns the Hyperlane V3 adapter. Used by `tenzro_hyperlane*` RPCs.
    pub fn hyperlane_adapter(&self) -> &Arc<HyperlaneAdapter> {
        &self.hyperlane_adapter
    }

    /// Returns the Axelar GMP adapter. Used by `tenzro_axelar*` RPCs.
    pub fn axelar_adapter(&self) -> &Arc<AxelarAdapter> {
        &self.axelar_adapter
    }

    /// Returns the Babylon BTC-staking adapter. Used by `tenzro_babylon*` RPCs.
    pub fn babylon_adapter(&self) -> &Arc<BabylonAdapter> {
        &self.babylon_adapter
    }

    /// Returns the node config
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Enforces the operator model-license acceptance policy for a multi-modal
    /// ONNX catalog entry. The multi-modal runtimes (vision / audio / detection
    /// / segmentation / text-embedding / forecast / video) load ONNX bundles
    /// directly into their own runtime rather than through
    /// [`tenzro_model::ModelRegistry::register_model`], so the license gate that
    /// `register_model` applies to LM catalog entries would otherwise be bypassed
    /// on these load paths. Returns `Ok(())` when the tier is admitted; otherwise
    /// `Err` with a caller-facing message naming the flag the operator must set.
    pub fn check_model_license(
        &self,
        model_id: &str,
        tier: tenzro_types::model::LicenseTier,
        license_id: Option<&str>,
    ) -> std::result::Result<(), String> {
        use tenzro_types::model::LicenseTier;
        if self.config.model_licensing.admits(tier, license_id) {
            return Ok(());
        }
        let remedy = match tier {
            LicenseTier::NonCommercial => "operator must set --accept-non-commercial".to_string(),
            LicenseTier::CommercialCustom => format!(
                "operator must set --accept-license {}",
                license_id.unwrap_or("<id>")
            ),
            LicenseTier::Permissive | LicenseTier::Attribution => {
                "license tier is admitted by default".to_string()
            }
        };
        Err(format!(
            "model '{model_id}' has license tier {tier:?} which is not accepted: {remedy}"
        ))
    }

    /// Submit a finalized block to the event loop for execution
    pub async fn submit_block(&self, block: Block) -> Result<()> {
        let event_sender = self.event_loop_tx.as_ref()
            .ok_or_else(|| NodeError::Internal("Event loop not initialized".to_string()))?;
        event_sender.send(NodeEvent::BlockFinalized(block)).await
            .map_err(|e| NodeError::Internal(format!("Failed to submit block: {}", e)))
    }

    /// Register a model service instance (local or network).
    ///
    /// The instance is paid out to this node's operator payee in both cases. For
    /// a `Local` instance that is the node serving its own weights; for a
    /// `Network` instance the operator is registering an external endpoint they
    /// broker, so they are the counterparty of record on-chain and settle with
    /// the upstream themselves.
    pub fn register_model_service(
        &self,
        model_id: &str,
        model_name: &str,
        provider_name: &str,
        location: ModelLocation,
        api_endpoint: &str,
        mcp_endpoint: &str,
        parameters: &str,
    ) -> String {
        use tenzro_types::model::PricingConfig;

        let instance_id = uuid::Uuid::new_v4().to_string();
        let pricing = self.provider_pricing.read();

        let instance = ModelServiceInstance {
            instance_id: instance_id.clone(),
            model_id: model_id.to_string(),
            model_name: model_name.to_string(),
            // Named so a routed call that pinned this node's own offer resolves
            // against this instance rather than being treated as a remote
            // provider's, and so the provider share has a real payee.
            provider_address: self.operator_payee().unwrap_or_default(),
            provider_name: provider_name.to_string(),
            location,
            api_endpoint: api_endpoint.to_string(),
            mcp_endpoint: mcp_endpoint.to_string(),
            status: ServiceStatus::Online,
            parameters: parameters.to_string(),
            pricing: PricingConfig {
                // PricingConfig is u64-wei. Cap at u64::MAX (would still be ~1.8e19 wei,
                // i.e. ~18 TNZO per token — far above any realistic per-token rate).
                price_per_input_token: pricing.input_price_per_token_wei.min(u64::MAX as u128) as u64,
                price_per_output_token: pricing.output_price_per_token_wei.min(u64::MAX as u128) as u64,
                // The operator's own card, not the type default: the token rates
                // above are wei and the defaults are nominal, so inheriting them
                // would quote audio seconds and denoising steps a billion times
                // under the rate a token is charged at.
                modality_rates: pricing.modality_rates.clone(),
                // The scheme the operator declared, so the listing quotes what
                // this node will actually settle the call on.
                pricing_model: pricing.pricing_model,
                ..PricingConfig::default()
            },
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            load_info: None,
            iroh_endpoint_id: self
                .iroh_resolver
                .as_ref()
                .map(|r| r.endpoint_id().to_string())
                .unwrap_or_default(),
        };

        self.model_services.insert(instance_id.clone(), instance.clone());

        // Persist to RocksDB
        if let Some(ref storage) = self.storage
            && let Ok(data) = serde_json::to_vec(&instance)
                && let Err(e) = storage.put(CF_MODEL_SERVICES, instance_id.as_bytes(), &data) {
                    warn!("Failed to persist model service {} to RocksDB: {}", instance_id, e);
                }

        info!("Registered model service: {} ({}) [{}]", model_id, instance_id, location);
        instance_id
    }

    /// Unregister a model service instance
    pub fn unregister_model_service(&self, instance_id: &str) {
        if let Some((_, instance)) = self.model_services.remove(instance_id) {
            if let Some(ref storage) = self.storage {
                let _ = storage.delete(CF_MODEL_SERVICES, instance_id.as_bytes());
            }
            info!("Unregistered model service: {} ({})", instance.model_id, instance_id);
        }
    }

    /// Unregister all model service instances for a given model_id
    pub fn unregister_model_services_by_model(&self, model_id: &str) {
        let ids: Vec<String> = self.model_services.iter()
            .filter(|entry| entry.value().model_id == model_id)
            .map(|entry| entry.key().clone())
            .collect();
        for id in &ids {
            self.model_services.remove(id);
            if let Some(ref storage) = self.storage {
                let _ = storage.delete(CF_MODEL_SERVICES, id.as_bytes());
            }
        }
        info!("Unregistered all services for model: {}", model_id);
    }

    /// Remove expired network model service instances (TTL-based cleanup).
    /// Called periodically from the event loop's heartbeat tick.
    pub fn cleanup_expired_model_services(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let ttl = 300; // 5 minutes
        let expired: Vec<String> = self.model_services.iter()
            .filter(|e| {
                let svc = e.value();
                matches!(svc.location, tenzro_types::model::ModelLocation::Network)
                    && svc.last_seen > 0
                    && now.saturating_sub(svc.last_seen) > ttl
            })
            .map(|e| e.key().clone())
            .collect();
        for id in &expired {
            self.model_services.remove(id);
            if let Some(ref storage) = self.storage {
                let _ = storage.delete(CF_MODEL_SERVICES, id.as_bytes());
            }
            info!("Removed expired network model service: {}", id);
        }
        if !expired.is_empty() {
            info!("Cleaned up {} expired model services", expired.len());
        }
    }

    /// Resolve the GGUF file path for a given model_id by checking all known
    /// storage locations. Returns the first existing path or None.
    ///
    /// Mirrors the path-resolution logic in handle_serve_model.
    pub fn resolve_gguf_path(&self, model_id: &str) -> Option<std::path::PathBuf> {
        // 1. HfDownloader storage path (node-managed models directory)
        if let Some(ref hf) = self.hf_downloader {
            let p = hf.model_path(model_id);
            if p.exists() {
                return Some(p);
            }
        }

        // 2. CLI flat file layout: ~/.tenzro/models/<model_id>.gguf
        let home_models = std::path::PathBuf::from(
                std::env::var("HOME").unwrap_or_else(|_| "/home/tenzro".to_string()),
            )
            .join(".tenzro/models");
        let flat = home_models.join(format!("{}.gguf", model_id));
        if flat.exists() {
            return Some(flat);
        }

        // 3. CLI subdirectory layout: ~/.tenzro/models/<model_id>/*.gguf
        let sub = home_models.join(model_id);
        if sub.is_dir()
            && let Ok(entries) = std::fs::read_dir(&sub) {
                for e in entries.flatten() {
                    let path = e.path();
                    if path.extension().map(|ext| ext == "gguf").unwrap_or(false) {
                        return Some(path);
                    }
                }
            }

        None
    }

    /// Load the speculative-decoding drafter declared by a catalog entry for a
    /// model that just started serving. Never fails the serve: on any problem
    /// the target keeps serving without speculative decoding.
    ///
    /// Returns a status string surfaced in the serve response:
    /// - `"none"`                — catalog entry declares no MTP support
    /// - `"inline"`              — single-file MTP model; the draft head lives
    ///   inside the target GGUF itself (no separate drafter to load)
    /// - `"drafter_loaded"`      — drafter GGUF found locally and loaded
    /// - `"drafter_downloading"` — drafter missing locally; background
    ///   download + load started, target serves non-speculatively until then
    /// - `"drafter_load_failed"` — local drafter present but the runtime
    ///   rejected it (e.g. memory admission)
    /// - `"drafter_unavailable"` — drafter_id doesn't resolve in the catalog
    ///   or no runtime/downloader is available
    pub async fn autoload_drafter(
        &self,
        target_model_id: &str,
        entry: &tenzro_model::HfModelEntry,
    ) -> &'static str {
        if entry.mtp_kind == MtpKind::None {
            return "none";
        }
        let Some(drafter_id) = entry.drafter_id.as_deref() else {
            return "inline";
        };
        let Some(runtime) = self.model_runtime.clone() else {
            return "drafter_unavailable";
        };
        if runtime.has_drafter(target_model_id) {
            return "drafter_loaded";
        }
        let Some(drafter_entry) = tenzro_model::get_model_by_id(drafter_id) else {
            warn!(
                target = %target_model_id,
                drafter = %drafter_id,
                "Catalog declares a drafter that does not resolve — serving without MTP",
            );
            return "drafter_unavailable";
        };

        if let Some(path) = self.resolve_gguf_path(drafter_id) {
            return match runtime
                .load_drafter(target_model_id, &path, Some(drafter_entry.context_length))
                .await
            {
                Ok(()) => {
                    info!(
                        target = %target_model_id,
                        drafter = %drafter_id,
                        "Loaded MTP drafter for speculative decoding",
                    );
                    "drafter_loaded"
                }
                Err(e) => {
                    warn!(
                        target = %target_model_id,
                        drafter = %drafter_id,
                        "MTP drafter load failed: {} — serving without speculative decoding",
                        e,
                    );
                    "drafter_load_failed"
                }
            };
        }

        // Drafter not on disk — download in the background, then load.
        let Some(hf) = self.hf_downloader.clone() else {
            return "drafter_unavailable";
        };
        let downloads = self.model_downloads.clone();
        downloads.insert(
            drafter_id.to_string(),
            ModelDownloadStatus {
                model_id: drafter_id.to_string(),
                status: "downloading".to_string(),
                progress_percent: 0.0,
                downloaded_bytes: 0,
                total_bytes: drafter_entry.size_bytes,
                error: None,
            },
        );
        let target = target_model_id.to_string();
        tokio::spawn(async move {
            let drafter_id = drafter_entry.id.clone();
            let (progress_tx, mut progress_rx) = tokio::sync::watch::channel(
                tenzro_model::DownloadProgress {
                    model_id: drafter_id.clone(),
                    status: tenzro_model::DownloadState::Pending,
                    progress_percent: 0.0,
                    downloaded_bytes: 0,
                    total_bytes: drafter_entry.size_bytes,
                },
            );
            let downloads_inner = downloads.clone();
            let drafter_id_inner = drafter_id.clone();
            tokio::spawn(async move {
                while progress_rx.changed().await.is_ok() {
                    let prog = progress_rx.borrow().clone();
                    if let Some(mut row) = downloads_inner.get_mut(&drafter_id_inner) {
                        row.status = prog.status.to_string();
                        row.progress_percent = prog.progress_percent;
                        row.downloaded_bytes = prog.downloaded_bytes;
                        row.total_bytes = prog.total_bytes;
                    }
                }
            });
            match hf
                .download_model(
                    &drafter_entry,
                    None,
                    tenzro_model::SourcePolicy::Auto,
                    progress_tx,
                )
                .await
            {
                Ok(path) => {
                    if let Some(mut row) = downloads.get_mut(&drafter_id) {
                        row.status = "completed".to_string();
                        row.progress_percent = 100.0;
                    }
                    match runtime
                        .load_drafter(&target, &path, Some(drafter_entry.context_length))
                        .await
                    {
                        Ok(()) => info!(
                            target = %target,
                            drafter = %drafter_id,
                            "Downloaded and loaded MTP drafter for speculative decoding",
                        ),
                        Err(e) => warn!(
                            target = %target,
                            drafter = %drafter_id,
                            "MTP drafter load failed after download: {}",
                            e,
                        ),
                    }
                }
                Err(e) => {
                    if let Some(mut row) = downloads.get_mut(&drafter_id) {
                        row.status = "failed".to_string();
                        row.error = Some(e.to_string());
                    }
                    warn!(
                        target = %target,
                        drafter = %drafter_id,
                        "MTP drafter download failed: {} — serving without speculative decoding",
                        e,
                    );
                }
            }
        });
        "drafter_downloading"
    }

    /// Evict Local ModelServiceInstance entries whose model is no longer loaded
    /// in the runtime AND have been idle (no `last_seen` update) for >= 1 hour.
    ///
    /// A model is considered "live" when `ModelRuntime::is_loaded()` returns true.
    /// If a local service still has a live runtime, its last_seen is refreshed
    /// (treated as liveness heartbeat). Otherwise, if it has been silent for
    /// more than 1 hour, the entry is removed from CF_MODEL_SERVICES and the
    /// served_models flag in CF_MODELS is cleared as well.
    ///
    /// Returns `(evicted_instance_count, cleared_served_models_count)` so
    /// callers (including the `tenzro_cleanupIdleLocalModelServices` RPC
    /// handler) can report how much state was reclaimed. The periodic
    /// EventLoop heartbeat also exercises this same logic inline; this
    /// method is the operator-callable on-demand entry point.
    pub fn cleanup_idle_local_model_services(&self) -> (usize, usize) {
        const IDLE_TTL_SECS: u64 = 3600; // 1 hour

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Collect candidates first to avoid holding DashMap refs across mutations
        let local_entries: Vec<(String, String, u64)> = self.model_services.iter()
            .filter(|e| matches!(e.value().location, tenzro_types::model::ModelLocation::Local))
            .map(|e| (e.key().clone(), e.value().model_id.clone(), e.value().last_seen))
            .collect();

        let mut evicted_instances: Vec<String> = Vec::new();
        let mut cleared_served: Vec<String> = Vec::new();

        for (instance_id, model_id, last_seen) in local_entries {
            let runtime_loaded = self
                .model_runtime
                .as_ref()
                .map(|rt| rt.is_loaded(&model_id))
                .unwrap_or(false);

            if runtime_loaded {
                // Live — refresh last_seen as a heartbeat so idle timer is bound
                // to the most recent successful liveness check, not registration.
                if let Some(mut svc) = self.model_services.get_mut(&instance_id)
                    && svc.last_seen < now {
                        svc.last_seen = now;
                        if let Some(ref storage) = self.storage
                            && let Ok(data) = serde_json::to_vec(svc.value()) {
                                let _ = storage.put(
                                    CF_MODEL_SERVICES,
                                    instance_id.as_bytes(),
                                    &data,
                                );
                            }
                    }
                continue;
            }

            // Runtime is not serving this model. If the entry has been silent
            // for >= IDLE_TTL_SECS (or has never been seen), evict it.
            let idle = last_seen == 0 || now.saturating_sub(last_seen) >= IDLE_TTL_SECS;
            if idle {
                self.model_services.remove(&instance_id);
                if let Some(ref storage) = self.storage {
                    let _ = storage.delete(CF_MODEL_SERVICES, instance_id.as_bytes());
                }
                evicted_instances.push(instance_id.clone());

                // If no other Local instance still exists for this model, clear
                // the served_models flag as well (CF_MODELS).
                let still_served_locally = self
                    .model_services
                    .iter()
                    .any(|e| {
                        e.value().model_id == model_id
                            && matches!(
                                e.value().location,
                                tenzro_types::model::ModelLocation::Local,
                            )
                    });
                if !still_served_locally {
                    self.served_models.remove(&model_id);
                    self.load_tracker.unregister_model(&model_id);
                    if let Some(ref storage) = self.storage {
                        let _ = storage.delete(CF_MODELS, format!("served:{}", model_id).as_bytes());
                    }
                    cleared_served.push(model_id);
                }
            }
        }

        if !evicted_instances.is_empty() {
            info!(
                "Evicted {} idle local model service(s); cleared {} served_models flag(s)",
                evicted_instances.len(),
                cleared_served.len(),
            );
        }
        (evicted_instances.len(), cleared_served.len())
    }

    /// Re-register an external OpenAI-compatible engine from its persisted
    /// CF_MODELS record after a restart. Health-probes the upstream; returns
    /// `false` (clear the serve flag) when the catalog entry is gone, the
    /// record is malformed, or the upstream is unreachable.
    async fn reconcile_external_engine(
        &self,
        model_id: &str,
        catalog: Option<&tenzro_model::HfModelEntry>,
        record: &serde_json::Value,
    ) -> bool {
        if catalog.is_none() {
            warn!(
                model_id = %model_id,
                "External-engine model not found in catalog — clearing serve flag",
            );
            return false;
        }

        let Some(runtime) = self.model_runtime.as_ref() else {
            warn!(
                model_id = %model_id,
                "ModelRuntime not initialized — clearing external serve flag",
            );
            return false;
        };

        if runtime.is_loaded(model_id) {
            return true;
        }

        let engine_kind_str = record.get("engine").and_then(|v| v.as_str()).unwrap_or("");
        let Some(kind) = ExternalEngineKind::parse_str(engine_kind_str) else {
            warn!(
                model_id = %model_id,
                engine = %engine_kind_str,
                "Unknown external engine kind in persisted record — clearing serve flag",
            );
            return false;
        };
        let Some(base_url) = record.get("base_url").and_then(|v| v.as_str()) else {
            warn!(
                model_id = %model_id,
                "External-engine record missing base_url — clearing serve flag",
            );
            return false;
        };
        let upstream_model = record
            .get("upstream_model")
            .and_then(|v| v.as_str())
            .unwrap_or(model_id)
            .to_string();
        let api_key = record
            .get("api_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let engine = match ExternalEngine::new(kind, base_url, upstream_model, api_key) {
            Ok(e) => e,
            Err(e) => {
                warn!(
                    model_id = %model_id,
                    "Invalid persisted external-engine config: {} — clearing serve flag",
                    e,
                );
                return false;
            }
        };

        match runtime.register_external_engine(model_id, engine).await {
            Ok(()) => {
                info!(
                    model_id = %model_id,
                    engine = %engine_kind_str,
                    base_url = %base_url,
                    "Re-registered external engine after restart",
                );
                true
            }
            Err(e) => {
                warn!(
                    model_id = %model_id,
                    base_url = %base_url,
                    "External engine unreachable on restart: {} — clearing serve flag",
                    e,
                );
                false
            }
        }
    }

    /// Register a served model with the load tracker, sizing max-concurrency
    /// against detected hardware. Shared by the serve path and the lazy loader
    /// so the concurrency budget is computed identically everywhere.
    fn register_load_tracker(&self, model_id: &str, entry: &tenzro_model::HfModelEntry) {
        let max_concurrent = {
            let hw = self.hardware_profile.read();
            if let Some(ref profile) = *hw {
                let gpu_vram = profile
                    .gpus
                    .first()
                    .map(|g| g.vram_gb as f64)
                    .unwrap_or(0.0);
                let has_gpu = !profile.gpus.is_empty() && gpu_vram > 0.0;
                tenzro_model::estimate_max_concurrent(
                    entry.min_ram_gb,
                    profile.total_ram_gb,
                    gpu_vram,
                    has_gpu,
                )
            } else {
                tenzro_model::estimate_max_concurrent(entry.min_ram_gb, 4.0, 0.0, false)
            }
        };
        self.load_tracker.register_model(model_id, max_concurrent);
    }

    /// Load a served model into the runtime on demand.
    ///
    /// Serving weights are loaded lazily on the first inference rather than at
    /// boot, so a node's boot-time RAM is independent of how many models it
    /// holds. A holder that never receives an inference request keeps its
    /// models purely on disk. Idempotent: a no-op when already loaded.
    ///
    /// Returns `Ok(true)` when the model is loaded and ready, `Ok(false)` when
    /// it is not a locally-servable model on this node (caller falls back to
    /// remote routing or a not-serving error), and `Err` when a load was
    /// attempted and failed (e.g. memory admission).
    pub async fn ensure_local_model_loaded(
        &self,
        model_id: &str,
    ) -> std::result::Result<bool, String> {
        let Some(runtime) = self.model_runtime.as_ref() else {
            return Ok(false);
        };
        if runtime.is_loaded(model_id) {
            return Ok(true);
        }
        // Only load models this node has flagged as served.
        if !self.served_models.contains_key(model_id) {
            return Ok(false);
        }
        let Some(entry) = tenzro_model::get_model_by_id(model_id) else {
            return Ok(false);
        };
        let Some(path) = self.resolve_gguf_path(model_id) else {
            return Ok(false);
        };
        runtime
            .load_model_with_context(model_id, &path, Some(entry.context_length))
            .await
            .map_err(|e| e.to_string())?;
        self.register_load_tracker(model_id, &entry);
        let _ = self.autoload_drafter(model_id, &entry).await;
        info!(model_id = %model_id, "Lazily loaded served model on first use");
        Ok(true)
    }

    /// Run a full reconciliation of the model registry against on-disk state
    /// and the in-memory runtime. Used both at startup and on-demand via
    /// `tenzro_pruneModelRegistry`.
    ///
    /// Behaviour:
    /// 1. For every entry in `served_models`:
    ///    - If the model is NOT in the catalog → clear the flag + remove any
    ///      matching ModelServiceInstance rows.
    ///    - If the model file is missing on disk → clear the flag + rows.
    ///    - If the model file exists on disk → keep the serve flag and register
    ///      the load tracker, but do NOT load weights into the runtime. The
    ///      llama.cpp load is deferred to the first inference request via
    ///      `ensure_local_model_loaded`, so boot RAM is independent of the
    ///      number of held models.
    /// 2. For every Local `ModelServiceInstance`:
    ///    - If the model_id is neither loaded nor flagged as served → remove
    ///      the row. (Orphaned endpoints from previous process lifetimes.)
    ///
    /// Returns a tuple `(reconciled, cleared_models, cleared_services)`.
    pub async fn reconcile_model_registry(&self) -> (usize, usize, usize) {
        use tenzro_model::get_model_by_id;

        let mut reloaded: usize = 0;
        let mut cleared_models: usize = 0;
        let mut cleared_services: usize = 0;

        // Snapshot the served_models keys to avoid holding a DashMap iterator
        // while we mutate the map.
        let served_ids: Vec<String> = self
            .served_models
            .iter()
            .map(|e| e.key().clone())
            .collect();

        for model_id in &served_ids {
            let catalog = get_model_by_id(model_id);

            // External-engine records carry an `engine` + `base_url` in their
            // CF_MODELS row instead of a local GGUF. Re-register the engine
            // (health-probing the upstream) rather than trying to reload
            // weights from disk. A dead upstream clears the serve flag.
            let external_record = self.storage.as_ref().and_then(|storage| {
                storage
                    .get(CF_MODELS, format!("served:{}", model_id).as_bytes())
                    .ok()
                    .flatten()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                    .filter(|rec| rec.get("engine").and_then(|v| v.as_str()).is_some())
            });

            if let Some(rec) = external_record {
                let ok = self
                    .reconcile_external_engine(model_id, catalog.as_ref(), &rec)
                    .await;
                if ok {
                    reloaded += 1;
                } else {
                    self.served_models.remove(model_id);
                    self.load_tracker.unregister_model(model_id);
                    if let Some(ref storage) = self.storage {
                        let _ = storage.delete(CF_MODELS, format!("served:{}", model_id).as_bytes());
                    }
                    cleared_models += 1;
                    let svc_ids: Vec<String> = self
                        .model_services
                        .iter()
                        .filter(|e| e.value().model_id == *model_id)
                        .map(|e| e.key().clone())
                        .collect();
                    for id in &svc_ids {
                        self.model_services.remove(id);
                        if let Some(ref storage) = self.storage {
                            let _ = storage.delete(CF_MODEL_SERVICES, id.as_bytes());
                        }
                        cleared_services += 1;
                    }
                }
                continue;
            }

            let gguf_path = self.resolve_gguf_path(model_id);

            let ok = match (catalog, gguf_path) {
                (Some(entry), Some(path)) => {
                    // Catalog entry + file present on disk. Keep the serve flag
                    // and register the load tracker, but do NOT warm the weights
                    // into the runtime here — the llama.cpp load is deferred to
                    // the first inference via `ensure_local_model_loaded`, so a
                    // node's boot RAM does not scale with the number of held
                    // models. A holder that never serves keeps them on disk.
                    if self.model_runtime.is_some() {
                        self.register_load_tracker(model_id, &entry);
                        reloaded += 1;
                        info!(
                            model_id = %model_id,
                            path = %path.display(),
                            "Reconciled served model (weights load lazily on first use)",
                        );
                        true
                    } else {
                        // No runtime available at all — can't serve. Keep file,
                        // but don't keep the flag advertising we serve it.
                        warn!(
                            model_id = %model_id,
                            "ModelRuntime not initialized — clearing serve flag",
                        );
                        false
                    }
                }
                (None, _) => {
                    warn!(
                        model_id = %model_id,
                        "Served model not found in catalog — clearing serve flag",
                    );
                    false
                }
                (_, None) => {
                    warn!(
                        model_id = %model_id,
                        "GGUF file missing for served model — clearing serve flag",
                    );
                    false
                }
            };

            if !ok {
                self.served_models.remove(model_id);
                self.load_tracker.unregister_model(model_id);
                if let Some(ref storage) = self.storage {
                    let _ = storage.delete(CF_MODELS, format!("served:{}", model_id).as_bytes());
                }
                // A hydrated ModelRegistry row from the previous process
                // lifetime would still say Active — flip it so routing stops
                // considering a model this node can no longer serve.
                if let Some(ref registry) = self.model_registry {
                    let _ = registry.deactivate_model(model_id);
                }
                cleared_models += 1;

                // Also clear any matching ModelServiceInstance rows for this model
                let svc_ids: Vec<String> = self
                    .model_services
                    .iter()
                    .filter(|e| e.value().model_id == *model_id)
                    .map(|e| e.key().clone())
                    .collect();
                for id in &svc_ids {
                    self.model_services.remove(id);
                    if let Some(ref storage) = self.storage {
                        let _ = storage.delete(CF_MODEL_SERVICES, id.as_bytes());
                    }
                    cleared_services += 1;
                }
            }
        }

        // Second pass: drop any orphaned Local ModelServiceInstance rows whose
        // model is not loaded and is no longer in served_models.
        let orphans: Vec<String> = self
            .model_services
            .iter()
            .filter(|e| {
                let svc = e.value();
                if !matches!(svc.location, tenzro_types::model::ModelLocation::Local) {
                    return false;
                }
                let loaded = self
                    .model_runtime
                    .as_ref()
                    .map(|rt| rt.is_loaded(&svc.model_id))
                    .unwrap_or(false);
                let flagged = self.served_models.contains_key(&svc.model_id);
                !loaded && !flagged
            })
            .map(|e| e.key().clone())
            .collect();

        for id in &orphans {
            self.model_services.remove(id);
            if let Some(ref storage) = self.storage {
                let _ = storage.delete(CF_MODEL_SERVICES, id.as_bytes());
            }
            cleared_services += 1;
            info!("Removed orphaned local model service: {}", id);
        }

        if reloaded > 0 || cleared_models > 0 || cleared_services > 0 {
            info!(
                "Model registry reconcile complete: reloaded={} cleared_models={} cleared_services={}",
                reloaded, cleared_models, cleared_services,
            );
        }

        (reloaded, cleared_models, cleared_services)
    }

    /// Refresh the `last_seen` timestamp of every Local ModelServiceInstance
    /// for the given model_id. Called from the tenzro_chat handler after a
    /// successful local inference so the 1-hour idle TTL is bound to actual
    /// usage, not registration time.
    pub fn touch_local_model_service(&self, model_id: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let ids: Vec<String> = self
            .model_services
            .iter()
            .filter(|e| {
                e.value().model_id == model_id
                    && matches!(
                        e.value().location,
                        tenzro_types::model::ModelLocation::Local,
                    )
            })
            .map(|e| e.key().clone())
            .collect();

        for id in ids {
            if let Some(mut svc) = self.model_services.get_mut(&id) {
                svc.last_seen = now;
                if let Some(ref storage) = self.storage
                    && let Ok(data) = serde_json::to_vec(svc.value()) {
                        let _ = storage.put(CF_MODEL_SERVICES, id.as_bytes(), &data);
                    }
            }
        }
    }

    /// List all model service instances
    pub fn list_model_services(&self) -> Vec<ModelServiceInstance> {
        self.model_services.iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get a model service instance by instance_id
    pub fn get_model_service(&self, instance_id: &str) -> Option<ModelServiceInstance> {
        self.model_services.get(instance_id).map(|entry| entry.value().clone())
    }

    /// Find a model service instance by model_id (returns first match)
    pub fn find_model_service_by_model_id(&self, model_id: &str) -> Option<ModelServiceInstance> {
        self.model_services.iter()
            .find(|entry| entry.value().model_id == model_id)
            .map(|entry| entry.value().clone())
    }

    /// Find a model service instance by model_id whose provider is not
    /// `exclude`. Used by the streaming re-prefill failover path to pick a
    /// different provider than the one that just dropped mid-stream.
    pub fn find_model_service_excluding(
        &self,
        model_id: &str,
        exclude: &tenzro_types::primitives::Address,
    ) -> Option<ModelServiceInstance> {
        self.model_services.iter()
            .find(|entry| {
                let svc = entry.value();
                svc.model_id == model_id && &svc.provider_address != exclude
            })
            .map(|entry| entry.value().clone())
    }

    /// Reconciles the task registry (CF_TASKS).
    ///
    /// For every persisted `TaskInfo`:
    ///   1. If the status is non-terminal (`Open | Assigned | InProgress | Disputed`)
    ///      and the task has a `deadline` in the past, transition it to `Expired`
    ///      and persist. This enforces the deadline that is otherwise never
    ///      acted on after `postTask`.
    ///   2. If the status is terminal (`Completed | Cancelled | Expired`) and the
    ///      task was created more than `purge_terminal_after_secs` ago, delete it.
    ///      Defaults: 30 days. Disputed tasks are never auto-purged.
    ///
    /// Returns `(expired, purged)`.
    pub fn reconcile_task_registry(&self, purge_terminal_after_secs: i64) -> (usize, usize) {
        match &self.storage {
            Some(s) => reconcile_task_registry_storage(s, purge_terminal_after_secs),
            None => (0, 0),
        }
    }

    /// Reconciles the tool registry (CF_TOOLS).
    ///
    /// Deletes entries whose status is `Inactive | Deprecated` and that were
    /// created more than `purge_after_secs` ago. Active tools are always
    /// retained.
    ///
    /// Returns the number of tool records purged.
    pub fn reconcile_tool_registry(&self, purge_after_secs: u64) -> usize {
        match &self.storage {
            Some(s) => reconcile_tool_registry_storage(s, purge_after_secs),
            None => 0,
        }
    }

    /// Reconciles the skill registry (CF_SKILLS).
    ///
    /// Same semantics as [`reconcile_tool_registry`]: drop Inactive/Deprecated
    /// skills that are older than `purge_after_secs`.
    pub fn reconcile_skill_registry(&self, purge_after_secs: u64) -> usize {
        match &self.storage {
            Some(s) => reconcile_skill_registry_storage(s, purge_after_secs),
            None => 0,
        }
    }

    /// Reconciles the agent registry (CF_AGENTS).
    ///
    /// Performs two actions:
    ///   1. Invokes the 1h idle-TTL sweep on the agent runtime so that any
    ///      Active agents without a recent heartbeat are auto-suspended (and
    ///      their lifecycle persisted). This is identical to the sweep driven
    ///      from `event_loop` but is also safe to call from admin RPC / CLI.
    ///   2. Returns the count of agents suspended in step (1).
    ///
    /// Terminated agents are preserved on purpose: the audit trail (state
    /// history, registration fee, DID) is retained indefinitely.
    pub async fn reconcile_agent_registry(&self) -> usize {
        if let Some(ref ar) = self.agent_runtime {
            ar.check_idle_agents(3600).await.len()
        } else {
            0
        }
    }
}

/// Fold a co-signature toward a commitment's quorum, and when quorum forms,
/// verify the certificate, attest the commitment, and open its fraud window.
///
/// Free-function variant of [`TenzroNode::record_zk_cosign_and_maybe_attest`]
/// so the gossip subscriber (which holds `Arc`s, not a `TenzroNode`) can drive
/// aggregation. The caller supplies the `proof_locator` that co-signers use to
/// fetch and re-verify the proof during the fraud window.
fn fold_zk_cosign(
    store: &Arc<tenzro_consensus::ZkQuorumStore>,
    consensus: &Arc<HotStuff2Engine>,
    registry: &Arc<tenzro_vm::precompiles::ZkCommitmentRegistry>,
    circuit_id: &str,
    cosign: tenzro_consensus::ZkCosign,
    proof_locator: &str,
) -> bool {
    let validator_set = consensus.validator_set();
    let commitment = cosign.commitment;
    match store.record_cosign(circuit_id, cosign, &validator_set) {
        Ok(Some(cert)) => {
            if let Err(e) = cert.verify(&validator_set) {
                warn!(error = %e, "zk-quorum: formed certificate failed verify; not attesting");
                return false;
            }
            let hash: tenzro_vm::precompiles::ZkCommitmentHash = commitment;
            let newly = registry.attest(hash);
            let height = consensus.current_finalized_height().0;
            store.open_fraud_window(cert, proof_locator.to_string(), height);
            info!(
                commitment = %hex::encode(commitment),
                height,
                "zk-quorum: commitment attested under 2f+1 certificate; fraud window open"
            );
            newly
        }
        Ok(None) => false,
        Err(e) => {
            debug!(error = %e, "zk-quorum: record_cosign rejected");
            false
        }
    }
}

/// Fold a co-signature toward a commitment's tally WITHOUT ever attesting.
///
/// Used on the `Cosign` gossip path by validators that never saw the original
/// claim and therefore hold no `proof_locator`. Attesting requires a locator
/// (co-signers must be able to fetch the proof to re-verify it during the fraud
/// window), so a locator-less node keeps its partial tally warm but leaves
/// attestation to the aggregator that carries the real locator. If quorum
/// happens to form here, the certificate is discarded rather than attested with
/// an empty locator — the aggregator's window is the authoritative one.
fn fold_zk_cosign_no_attest(
    store: &Arc<tenzro_consensus::ZkQuorumStore>,
    consensus: &Arc<HotStuff2Engine>,
    circuit_id: &str,
    cosign: tenzro_consensus::ZkCosign,
) {
    let validator_set = consensus.validator_set();
    match store.record_cosign(circuit_id, cosign, &validator_set) {
        Ok(Some(_cert)) => {
            debug!(
                "zk-quorum: quorum reached on a locator-less node; deferring attestation to the aggregator"
            );
        }
        Ok(None) => {}
        Err(e) => {
            debug!(error = %e, "zk-quorum: record_cosign (no-attest) rejected");
        }
    }
}

/// Storage-only task registry reconcile.
///
/// Free-function variant that runs the same logic as
/// [`TenzroNode::reconcile_task_registry`] against a raw storage handle, so it
/// can be driven from the node event loop (which holds only
/// `Arc<RocksDbStore>`, not a `TenzroNode`).
pub fn reconcile_task_registry_storage(
    storage: &Arc<RocksDbStore>,
    purge_terminal_after_secs: i64,
) -> (usize, usize) {
    use tenzro_storage::CF_TASKS;
    use tenzro_types::task::{TaskInfo, TaskStatus};

    let now = chrono::Utc::now().timestamp();
    let mut expired: usize = 0;
    let mut purged: usize = 0;

    let keys = match storage.get_keys_with_prefix(CF_TASKS, b"") {
        Ok(k) => k,
        Err(e) => {
            warn!("Failed to scan CF_TASKS during reconcile: {}", e);
            return (0, 0);
        }
    };

    for key in keys {
        let bytes = match storage.get(CF_TASKS, &key) {
            Ok(Some(b)) => b,
            _ => continue,
        };
        let mut task: TaskInfo = match serde_json::from_slice(&bytes) {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    "Corrupt task record {:?} — deleting: {}",
                    String::from_utf8_lossy(&key),
                    e
                );
                let _ = storage.delete(CF_TASKS, &key);
                purged += 1;
                continue;
            }
        };

        // 1. Deadline enforcement for non-terminal tasks.
        let non_terminal = matches!(
            task.status,
            TaskStatus::Open | TaskStatus::Assigned | TaskStatus::InProgress
        );
        if non_terminal
            && let Some(deadline) = task.deadline
                && (deadline as i64) < now {
                    task.status = TaskStatus::Expired;
                    if let Ok(updated) = serde_json::to_vec(&task) {
                        let _ = storage.put(CF_TASKS, &key, &updated);
                    }
                    expired += 1;
                    info!(
                        task_id = %task.task_id,
                        deadline,
                        "Task auto-expired by reconcile sweep",
                    );
                    continue;
                }

        // 2. Purge old terminal tasks (Completed / Cancelled / Expired).
        //    Disputed is retained until manually resolved.
        let is_purgeable_terminal = matches!(
            task.status,
            TaskStatus::Completed | TaskStatus::Cancelled | TaskStatus::Expired
        );
        if is_purgeable_terminal {
            let age_secs = now.saturating_sub(task.created_at.0);
            if age_secs > purge_terminal_after_secs {
                let _ = storage.delete(CF_TASKS, &key);
                purged += 1;
                info!(
                    task_id = %task.task_id,
                    age_secs,
                    "Purged stale terminal task",
                );
            }
        }
    }

    if expired > 0 || purged > 0 {
        info!(
            "Task registry reconcile complete: expired={} purged={}",
            expired, purged,
        );
    }

    (expired, purged)
}

/// Storage-only tool registry reconcile. See
/// [`TenzroNode::reconcile_tool_registry`] for semantics.
pub fn reconcile_tool_registry_storage(
    storage: &Arc<RocksDbStore>,
    purge_after_secs: u64,
) -> usize {
    use tenzro_types::tool::{ToolDefinition, ToolStatus};

    let now = chrono::Utc::now().timestamp() as u64;
    let mut purged: usize = 0;

    let keys = match storage.get_keys_with_prefix(CF_TOOLS, b"") {
        Ok(k) => k,
        Err(e) => {
            warn!("Failed to scan CF_TOOLS during reconcile: {}", e);
            return 0;
        }
    };

    for key in keys {
        let bytes = match storage.get(CF_TOOLS, &key) {
            Ok(Some(b)) => b,
            _ => continue,
        };
        let tool: ToolDefinition = match serde_json::from_slice(&bytes) {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    "Corrupt tool record {:?} — deleting: {}",
                    String::from_utf8_lossy(&key),
                    e
                );
                let _ = storage.delete(CF_TOOLS, &key);
                purged += 1;
                continue;
            }
        };

        let inactive = matches!(
            tool.status,
            ToolStatus::Inactive | ToolStatus::Deprecated
        );
        if !inactive {
            continue;
        }
        let age = now.saturating_sub(tool.created_at);
        if age > purge_after_secs {
            let _ = storage.delete(CF_TOOLS, &key);
            purged += 1;
            info!(
                tool_id = %tool.tool_id,
                age_secs = age,
                status = ?tool.status,
                "Purged stale tool",
            );
        }
    }

    if purged > 0 {
        info!("Tool registry reconcile complete: purged={}", purged);
    }
    purged
}

/// Storage-only skill registry reconcile. See
/// [`TenzroNode::reconcile_skill_registry`] for semantics.
pub fn reconcile_skill_registry_storage(
    storage: &Arc<RocksDbStore>,
    purge_after_secs: u64,
) -> usize {
    use tenzro_types::skill::{SkillDefinition, SkillStatus};

    let now = chrono::Utc::now().timestamp() as u64;
    let mut purged: usize = 0;

    let keys = match storage.get_keys_with_prefix(CF_SKILLS, b"") {
        Ok(k) => k,
        Err(e) => {
            warn!("Failed to scan CF_SKILLS during reconcile: {}", e);
            return 0;
        }
    };

    for key in keys {
        let bytes = match storage.get(CF_SKILLS, &key) {
            Ok(Some(b)) => b,
            _ => continue,
        };
        let skill: SkillDefinition = match serde_json::from_slice(&bytes) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "Corrupt skill record {:?} — deleting: {}",
                    String::from_utf8_lossy(&key),
                    e
                );
                let _ = storage.delete(CF_SKILLS, &key);
                purged += 1;
                continue;
            }
        };

        let inactive = matches!(
            skill.status,
            SkillStatus::Inactive | SkillStatus::Deprecated
        );
        if !inactive {
            continue;
        }
        let age = now.saturating_sub(skill.created_at);
        if age > purge_after_secs {
            let _ = storage.delete(CF_SKILLS, &key);
            purged += 1;
            info!(
                skill_id = %skill.skill_id,
                age_secs = age,
                status = ?skill.status,
                "Purged stale skill",
            );
        }
    }

    if purged > 0 {
        info!("Skill registry reconcile complete: purged={}", purged);
    }
    purged
}

/// Detect hardware profile of the current system
pub async fn detect_hardware(data_dir: &std::path::Path) -> Result<HardwareProfile> {
    use sysinfo::{System, Disks};

    // Initialize system info
    let mut sys = System::new_all();
    sys.refresh_all();

    // CPU info
    let cpu_model = sys.cpus().first()
        .map(|cpu| cpu.brand().to_string())
        .unwrap_or_else(|| "Unknown CPU".to_string());
    let cpu_cores = sys.physical_core_count().unwrap_or(1);
    let cpu_threads = sys.cpus().len();

    // RAM info (convert bytes to GB)
    let total_ram_gb = sys.total_memory() as f64 / 1_073_741_824.0; // 1024^3

    // Storage info
    let disks = Disks::new_with_refreshed_list();
    let storage_available_gb = disks.iter()
        .find(|disk| {
            data_dir.starts_with(disk.mount_point())
        })
        .map(|disk| disk.available_space() as f64 / 1_073_741_824.0)
        .unwrap_or(0.0);

    // OS and architecture
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();

    // GPU detection — shared probe (nvidia-smi / rocm-smi / Apple unified
    // memory) with vendor, compute capability, and FP8/FP4 derivation. The
    // probe shells out synchronously, so run it off the async executor.
    let gpus = tokio::task::spawn_blocking(tenzro_types::HardwareCapabilities::detect)
        .await
        .map(|caps| caps.gpus)
        .unwrap_or_default();

    // TEE detection
    let (tee_available, tee_vendor) = match detect_tee().await {
        Some(provider) => (true, Some(format!("{:?}", provider.vendor()))),
        None => (false, None),
    };

    // Device fingerprint (SHA-256 hash of hardware characteristics)
    let fingerprint_input = format!(
        "{}|{}|{}|{}|{}|{}",
        cpu_model,
        cpu_cores,
        total_ram_gb as u64,
        gpus.iter().map(|g| g.name.as_str()).collect::<Vec<_>>().join(","),
        os,
        arch
    );
    let mut hasher = Sha256::new();
    hasher.update(fingerprint_input.as_bytes());
    let device_fingerprint = format!("{:x}", hasher.finalize());

    Ok(HardwareProfile {
        cpu_model,
        cpu_cores,
        cpu_threads,
        total_ram_gb,
        gpus,
        storage_available_gb,
        tee_available,
        tee_vendor,
        os,
        arch,
        device_fingerprint,
    })
}

/// Node status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub state: String,
    pub roles: RoleSet,
    pub health_status: crate::health::OverallHealth,
    pub uptime_secs: u64,
    pub block_height: u64,
    pub peer_count: u64,
    pub data_dir: PathBuf,
    /// Whether this node has a TEE provider available.
    ///
    /// All nodes participate in consensus regardless. TEE-capable nodes
    /// additionally serve confidential-compute and custodial-key
    /// workloads on behalf of non-TEE peers — peers consult this field
    /// to discover routing targets for TEE-gated requests.
    pub tee_capable: bool,
    /// TEE vendor for this node, if any (`None` on commodity hardware).
    pub tee_vendor: Option<tenzro_types::tee::TeeVendor>,
    /// Whether the iroh QUIC + Pkarr substrate is bound on this node
    /// (controlled by `NodeConfig::iroh`). When `true`, the node serves
    /// the `iroh-blobs` data plane and (for the A2A dispatcher) the
    /// `tenzro/a2a` ALPN alongside its HTTPS surfaces.
    pub iroh_enabled: bool,
    /// Iroh `EndpointId` in z-base-32 form (matches the format printed by
    /// `iroh node id`). `None` when iroh is not enabled. When the node was
    /// started with a TDIP-anchored secret key seed, the byte-decoded form
    /// of this value is identical to the node's Ed25519 validator public key.
    pub iroh_endpoint_id: Option<String>,
    /// ALPNs registered on the shared iroh router. Empty when iroh is not
    /// enabled. Includes `iroh-blobs` always; `tenzro/a2a` once the A2A
    /// dispatcher has been wired in `main.rs`.
    pub iroh_alpns: Vec<String>,
    /// Sustained connectivity tier (`unreachable` / `relay_only` / `direct`),
    /// or `None` when the network service is not running. A serving role is
    /// only admitted once this reaches a tier that `can_serve`; the request
    /// router prefers `direct` providers over `relay_only` ones.
    pub reachability: Option<String>,
    /// libp2p peer id of this node in base-58 form, or `None` when the network
    /// service is not running. Dialers use this to construct a
    /// `/p2p/<peer_id>` boot-node multiaddr targeting this node.
    pub self_peer_id: Option<String>,
}
