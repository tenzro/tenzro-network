//! On-chain governance system
//!
//! This module implements on-chain governance with proposals, voting,
//! and execution for the Tenzro Network.

use crate::error::{Result, TokenError};
use crate::staking::StakingManager;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_storage::KvStore;
use tenzro_types::governance::{GovernanceVote, QuorumRequirements, VoteType, VotingDelegation};
use tenzro_types::primitives::{Address, Timestamp};
use tenzro_types::token::{GovernanceProposal, ProposalStatus, ProposalType};
use tracing::{debug, info, warn};

/// Column family for governance proposals
const CF_GOVERNANCE: &str = "metadata"; // reuse metadata CF with governance: prefix
/// Key prefix for proposals
const GOVERNANCE_PROPOSAL_PREFIX: &[u8] = b"gov:proposal:";
/// Key prefix for votes
const GOVERNANCE_VOTE_PREFIX: &[u8] = b"gov:votes:";
/// Key prefix for delegations
const GOVERNANCE_DELEGATION_PREFIX: &[u8] = b"gov:delegation:";

/// Voting record for tracking who voted on what
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingRecord {
    /// Proposal ID
    pub proposal_id: String,
    /// Voter address
    pub voter: Address,
    /// Vote cast
    pub vote: GovernanceVote,
}

/// Trait the node implements to dispatch a passed proposal to the right
/// subsystem (treasury, adaptive burn dial, supply targets, etc.).
///
/// Mirrors the `SlashingCallback` pattern in `tenzro-consensus`: the engine
/// calls `apply_proposal` once it has decided a proposal is `Passed` and the
/// executor is responsible for the side-effecting application. Keeps
/// `tenzro-token` free of node-level cross-crate references.
pub trait ProposalExecutor: Send + Sync {
    /// Apply a passed proposal. Called from `execute_proposal` exactly once
    /// before the proposal status flips to `Executed`. Returning `Err`
    /// surfaces as a `TokenError::ProposalExecutionFailed` and the proposal
    /// stays in `Passed` state for retry.
    fn apply_proposal(&self, proposal: &GovernanceProposal) -> Result<()>;
}

/// Governance engine
///
/// Manages governance proposals, voting, and execution.
/// Voting power is verified against actual staked balances to prevent sybil attacks.
/// Proposals and votes are persisted to RocksDB when storage is configured.
pub struct GovernanceEngine {
    /// Active proposals (ProposalId -> Proposal)
    proposals: DashMap<String, GovernanceProposal>,
    /// Votes by proposal (ProposalId -> Vec<GovernanceVote>)
    votes: DashMap<String, Vec<GovernanceVote>>,
    /// Voting delegations (Delegator -> Delegation)
    delegations: DashMap<Address, VotingDelegation>,
    /// Quorum requirements
    quorum_requirements: parking_lot::RwLock<QuorumRequirements>,
    /// Minimum stake to propose
    min_proposal_stake: parking_lot::RwLock<u128>,
    /// Reference to staking manager for voting power verification
    staking_manager: Option<Arc<StakingManager>>,
    /// Optional persistent storage backend
    storage: Option<Arc<dyn KvStore>>,
    /// Optional executor that applies a passed proposal to the right
    /// subsystem (e.g. `BurnRateConfigManager`, `NetworkTreasury`). When
    /// `None` `execute_proposal` only flips status — wired in production
    /// via `with_executor` or `attach_executor` after construction.
    ///
    /// Held behind `RwLock` so it can be installed after the engine is
    /// already wrapped in `Arc` (the node initializes governance before
    /// some of the subsystems the executor depends on).
    executor: parking_lot::RwLock<Option<Arc<dyn ProposalExecutor>>>,
}

impl std::fmt::Debug for GovernanceEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GovernanceEngine")
            .field("proposals_count", &self.proposals.len())
            .field("votes_count", &self.votes.len())
            .field("delegations_count", &self.delegations.len())
            .field("has_staking_manager", &self.staking_manager.is_some())
            .field("has_storage", &self.storage.is_some())
            .field("has_executor", &self.executor.read().is_some())
            .finish()
    }
}

impl GovernanceEngine {
    /// Creates a new governance engine without staking manager (voting power not verified)
    pub fn new() -> Self {
        Self {
            proposals: DashMap::new(),
            votes: DashMap::new(),
            delegations: DashMap::new(),
            quorum_requirements: parking_lot::RwLock::new(QuorumRequirements::default()),
            min_proposal_stake: parking_lot::RwLock::new(10_000 * 1_000_000_000_000_000_000), // 10k TNZO
            staking_manager: None,
            storage: None,
            executor: parking_lot::RwLock::new(None),
        }
    }

    /// Creates a new governance engine with staking manager for sybil resistance
    pub fn with_staking_manager(staking_manager: Arc<StakingManager>) -> Self {
        Self {
            proposals: DashMap::new(),
            votes: DashMap::new(),
            delegations: DashMap::new(),
            quorum_requirements: parking_lot::RwLock::new(QuorumRequirements::default()),
            min_proposal_stake: parking_lot::RwLock::new(10_000 * 1_000_000_000_000_000_000), // 10k TNZO
            staking_manager: Some(staking_manager),
            storage: None,
            executor: parking_lot::RwLock::new(None),
        }
    }

    /// Creates a new governance engine with persistent storage
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        let engine = Self {
            proposals: DashMap::new(),
            votes: DashMap::new(),
            delegations: DashMap::new(),
            quorum_requirements: parking_lot::RwLock::new(QuorumRequirements::default()),
            min_proposal_stake: parking_lot::RwLock::new(10_000 * 1_000_000_000_000_000_000),
            staking_manager: None,
            storage: Some(storage),
            executor: parking_lot::RwLock::new(None),
        };

        // Load existing state from storage
        if let Err(e) = engine.load_from_storage() {
            warn!("Failed to load governance state from storage: {}", e);
        }

        engine
    }

    /// Creates a new governance engine with both staking manager and storage
    pub fn with_staking_and_storage(
        staking_manager: Arc<StakingManager>,
        storage: Arc<dyn KvStore>,
    ) -> Self {
        let engine = Self {
            proposals: DashMap::new(),
            votes: DashMap::new(),
            delegations: DashMap::new(),
            quorum_requirements: parking_lot::RwLock::new(QuorumRequirements::default()),
            min_proposal_stake: parking_lot::RwLock::new(10_000 * 1_000_000_000_000_000_000),
            staking_manager: Some(staking_manager),
            storage: Some(storage),
            executor: parking_lot::RwLock::new(None),
        };

        if let Err(e) = engine.load_from_storage() {
            warn!("Failed to load governance state from storage: {}", e);
        }

        engine
    }

    /// Attach a `ProposalExecutor` so passed proposals get applied to the
    /// node's actual subsystems (burn-rate dial, supply targets, treasury,
    /// upgrade coordinator, etc.) when `execute_proposal` runs.
    pub fn with_executor(self, executor: Arc<dyn ProposalExecutor>) -> Self {
        *self.executor.write() = Some(executor);
        self
    }

    /// Install a `ProposalExecutor` after the engine is already wrapped in
    /// `Arc`. The node uses this because governance is initialized before
    /// `NetworkTreasury` and the per-subsystem managers the executor wires.
    pub fn attach_executor(&self, executor: Arc<dyn ProposalExecutor>) {
        *self.executor.write() = Some(executor);
    }

    /// True when a `ProposalExecutor` is currently installed.
    pub fn has_executor(&self) -> bool {
        self.executor.read().is_some()
    }

    /// Persists a proposal to storage
    fn persist_proposal(&self, proposal: &GovernanceProposal) {
        if let Some(ref storage) = self.storage {
            let key = [GOVERNANCE_PROPOSAL_PREFIX, proposal.proposal_id.as_bytes()].concat();
            match bincode::serialize(proposal) {
                Ok(data) => {
                    if let Err(e) = storage.put(CF_GOVERNANCE, &key, &data) {
                        warn!("Failed to persist proposal {}: {}", proposal.proposal_id, e);
                    }
                }
                Err(e) => warn!(
                    "Failed to serialize proposal {}: {}",
                    proposal.proposal_id, e
                ),
            }
        }
    }

    /// Persists votes for a proposal to storage
    fn persist_votes(&self, proposal_id: &str, votes: &[GovernanceVote]) {
        if let Some(ref storage) = self.storage {
            let key = [GOVERNANCE_VOTE_PREFIX, proposal_id.as_bytes()].concat();
            match bincode::serialize(votes) {
                Ok(data) => {
                    if let Err(e) = storage.put(CF_GOVERNANCE, &key, &data) {
                        warn!("Failed to persist votes for {}: {}", proposal_id, e);
                    }
                }
                Err(e) => warn!("Failed to serialize votes for {}: {}", proposal_id, e),
            }
        }
    }

    /// Persists a delegation to storage
    fn persist_delegation(&self, delegator: &Address, delegation: &VotingDelegation) {
        if let Some(ref storage) = self.storage {
            let key = [
                GOVERNANCE_DELEGATION_PREFIX,
                format!("{}", delegator).as_bytes(),
            ]
            .concat();
            match bincode::serialize(delegation) {
                Ok(data) => {
                    if let Err(e) = storage.put(CF_GOVERNANCE, &key, &data) {
                        warn!("Failed to persist delegation for {}: {}", delegator, e);
                    }
                }
                Err(e) => warn!("Failed to serialize delegation for {}: {}", delegator, e),
            }
        }
    }

    /// Loads governance state from storage
    fn load_from_storage(&self) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(()),
        };

        // Load proposals
        let proposal_keys =
            storage.get_keys_with_prefix(CF_GOVERNANCE, GOVERNANCE_PROPOSAL_PREFIX)?;
        for key in &proposal_keys {
            if let Ok(Some(data)) = storage.get(CF_GOVERNANCE, key)
                && let Ok(proposal) = bincode::deserialize::<GovernanceProposal>(&data)
            {
                let id = proposal.proposal_id.clone();
                self.proposals.insert(id, proposal);
            }
        }

        // Load votes
        let vote_keys = storage.get_keys_with_prefix(CF_GOVERNANCE, GOVERNANCE_VOTE_PREFIX)?;
        for key in &vote_keys {
            if let Ok(Some(data)) = storage.get(CF_GOVERNANCE, key)
                && let Ok(votes) = bincode::deserialize::<Vec<GovernanceVote>>(&data)
            {
                let proposal_id =
                    String::from_utf8_lossy(&key[GOVERNANCE_VOTE_PREFIX.len()..]).to_string();
                self.votes.insert(proposal_id, votes);
            }
        }

        // Load delegations
        let delegation_keys =
            storage.get_keys_with_prefix(CF_GOVERNANCE, GOVERNANCE_DELEGATION_PREFIX)?;
        for key in &delegation_keys {
            if let Ok(Some(data)) = storage.get(CF_GOVERNANCE, key)
                && let Ok(delegation) = bincode::deserialize::<VotingDelegation>(&data)
            {
                self.delegations.insert(delegation.delegator, delegation);
            }
        }

        info!(
            "Loaded governance state: {} proposals, {} vote sets, {} delegations",
            proposal_keys.len(),
            vote_keys.len(),
            delegation_keys.len(),
        );

        Ok(())
    }

    /// Returns total number of proposals
    pub fn proposal_count(&self) -> usize {
        self.proposals.len()
    }

    /// Returns total staked amount from staking manager
    pub fn total_staked(&self) -> u128 {
        self.staking_manager
            .as_ref()
            .map(|sm| sm.get_total_staked_all())
            .unwrap_or(0)
    }

    /// Creates a new governance proposal
    ///
    /// # Arguments
    ///
    /// * `title` - Proposal title
    /// * `description` - Proposal description
    /// * `proposer` - Proposer address
    /// * `proposal_type` - Type of proposal
    /// * `voting_duration_ms` - Voting period duration
    /// * `proposer_stake` - Amount of TNZO staked by proposer
    pub fn create_proposal(
        &self,
        title: String,
        description: String,
        proposer: Address,
        proposal_type: ProposalType,
        voting_duration_ms: i64,
        proposer_stake: u128,
    ) -> Result<String> {
        // Check minimum stake
        let min_stake = *self.min_proposal_stake.read();
        if proposer_stake < min_stake {
            return Err(TokenError::MinimumStakeNotMet {
                required: min_stake,
                provided: proposer_stake,
            });
        }

        // Create proposal
        let proposal = GovernanceProposal::new(
            title,
            description,
            proposer,
            proposal_type,
            voting_duration_ms,
        );

        let proposal_id = proposal.proposal_id.clone();

        // Persist to storage
        self.persist_proposal(&proposal);
        self.persist_votes(&proposal_id, &[]);

        self.proposals.insert(proposal_id.clone(), proposal);
        self.votes.insert(proposal_id.clone(), Vec::new());

        info!("Created proposal: {}", proposal_id);
        Ok(proposal_id)
    }

    /// Creates a protocol-issued governance proposal that bypasses the
    /// `min_proposal_stake` check.
    ///
    /// Used by autonomous on-chain machinery — currently the adaptive-burn
    /// `AutoProposalGenerator` (Spec 8) which drafts `AdaptiveBurnConfigUpdate`
    /// proposals when supply metrics drift outside the neutral band. The
    /// generator runs as a protocol component and has no stake of its own,
    /// so the proposer is recorded as `Address::default()` and the min-stake
    /// floor does not apply. Voters still need real stake to vote on the
    /// resulting proposal exactly like a regular one.
    pub fn create_system_proposal(
        &self,
        title: String,
        description: String,
        proposal_type: ProposalType,
        voting_duration_ms: i64,
    ) -> Result<String> {
        let proposal = GovernanceProposal::new(
            title,
            description,
            Address::default(),
            proposal_type,
            voting_duration_ms,
        );

        let proposal_id = proposal.proposal_id.clone();

        self.persist_proposal(&proposal);
        self.persist_votes(&proposal_id, &[]);

        self.proposals.insert(proposal_id.clone(), proposal);
        self.votes.insert(proposal_id.clone(), Vec::new());

        info!("Created system proposal: {}", proposal_id);
        Ok(proposal_id)
    }

    /// Casts a vote on a proposal
    ///
    /// # Arguments
    ///
    /// * `proposal_id` - Proposal to vote on
    /// * `voter` - Voter address
    /// * `vote_type` - Type of vote (For/Against/Abstain)
    /// * `voting_power` - Voting power (staked TNZO amount)
    ///
    /// Note: If a staking manager is configured, voting_power will be verified
    /// against the voter's actual staked balance to prevent sybil attacks.
    pub fn vote(
        &self,
        proposal_id: &str,
        voter: Address,
        vote_type: VoteType,
        voting_power: u128,
    ) -> Result<()> {
        // Get proposal
        let mut proposal =
            self.proposals
                .get_mut(proposal_id)
                .ok_or_else(|| TokenError::ProposalNotFound {
                    proposal_id: proposal_id.to_string(),
                })?;

        // Check if voting is open
        if !proposal.is_voting_open() {
            return Err(TokenError::VotingClosed {
                proposal_id: proposal_id.to_string(),
            });
        }

        // Check if already voted
        let votes = self.votes.get(proposal_id).unwrap();
        if votes.iter().any(|v| v.voter == voter) {
            return Err(TokenError::AlreadyVoted {
                proposal_id: proposal_id.to_string(),
            });
        }
        drop(votes);

        // Check voting power
        if voting_power == 0 {
            return Err(TokenError::InvalidVotingPower);
        }

        // Verify voting power against staked balance if staking manager is available
        let verified_power = if let Some(ref staking_manager) = self.staking_manager {
            match staking_manager.get_stake(&voter) {
                Some(stake_info) => {
                    // Only active stakes count for voting
                    if !stake_info.is_locked() {
                        warn!(
                            "Voter {} has no active stake (status: {:?})",
                            voter, stake_info.status
                        );
                        return Err(TokenError::InvalidVotingPower);
                    }

                    // Ensure claimed voting power doesn't exceed actual stake
                    if voting_power > stake_info.amount {
                        warn!(
                            "Voter {} claimed voting power {} exceeds staked amount {}",
                            voter, voting_power, stake_info.amount
                        );
                        return Err(TokenError::InvalidVotingPower);
                    }

                    // Use the actual staked amount (not the claimed amount)
                    stake_info.amount
                }
                None => {
                    warn!("Voter {} has no stake", voter);
                    return Err(TokenError::InvalidVotingPower);
                }
            }
        } else {
            // No staking manager - accept claimed voting power
            // (This is the legacy behavior for backward compatibility)
            voting_power
        };

        // Get effective voting power (including delegations)
        let effective_power = self.get_effective_voting_power(&voter, verified_power);

        // Create vote
        let vote = GovernanceVote::new(proposal_id.to_string(), voter, vote_type, effective_power);

        // Update proposal tallies
        match vote_type {
            VoteType::For => {
                proposal.votes_for =
                    proposal
                        .votes_for
                        .checked_add(effective_power)
                        .ok_or_else(|| TokenError::ArithmeticOverflow {
                            operation: "governance votes_for".to_string(),
                        })?;
            }
            VoteType::Against => {
                proposal.votes_against = proposal
                    .votes_against
                    .checked_add(effective_power)
                    .ok_or_else(|| TokenError::ArithmeticOverflow {
                        operation: "governance votes_against".to_string(),
                    })?;
            }
            VoteType::Abstain => {
                // Abstain votes count toward quorum but not approval
            }
        }
        proposal.total_voting_power = proposal
            .total_voting_power
            .checked_add(effective_power)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "governance total_voting_power".to_string(),
            })?;

        drop(proposal);

        // Record vote
        let mut votes = self.votes.get_mut(proposal_id).unwrap();
        votes.push(vote);

        // Persist updated votes and proposal tallies to storage
        self.persist_votes(proposal_id, &votes);
        drop(votes);
        if let Some(proposal) = self.proposals.get(proposal_id) {
            self.persist_proposal(&proposal);
        }

        debug!("Vote cast on proposal {} by {}", proposal_id, voter);
        Ok(())
    }

    /// Tallies votes for a proposal and updates status
    ///
    /// # Arguments
    ///
    /// * `proposal_id` - Proposal to tally
    /// * `total_supply` - Total TNZO supply for quorum calculation
    pub fn tally_votes(&self, proposal_id: &str, total_supply: u128) -> Result<ProposalStatus> {
        let mut proposal =
            self.proposals
                .get_mut(proposal_id)
                .ok_or_else(|| TokenError::ProposalNotFound {
                    proposal_id: proposal_id.to_string(),
                })?;

        // Check if voting period has ended
        if Timestamp::now() < proposal.voting_end {
            return Ok(proposal.status);
        }

        // Check quorum
        let quorum = self.quorum_requirements.read();
        let quorum_met = quorum.is_met(proposal.votes_for, proposal.votes_against, total_supply);

        if !quorum_met {
            proposal.status = ProposalStatus::Failed;
            info!("Proposal {} failed: quorum not met", proposal_id);
            return Ok(ProposalStatus::Failed);
        }

        // Check if passed
        let result = if proposal.votes_for > proposal.votes_against {
            proposal.status = ProposalStatus::Passed;
            info!("Proposal {} passed", proposal_id);
            ProposalStatus::Passed
        } else {
            proposal.status = ProposalStatus::Failed;
            info!("Proposal {} failed: more votes against", proposal_id);
            ProposalStatus::Failed
        };

        // Persist updated status
        self.persist_proposal(&proposal);

        Ok(result)
    }

    /// Executes a passed proposal
    ///
    /// # Arguments
    ///
    /// * `proposal_id` - Proposal to execute
    ///
    /// Note: This is a simplified version. In production, you'd have
    /// specific execution logic for each proposal type.
    pub fn execute_proposal(&self, proposal_id: &str) -> Result<()> {
        // Snapshot the proposal under a short-lived lock and drop the
        // `RefMut` before invoking the executor — keeping the dashmap
        // shard locked across the executor call risks deadlock if the
        // executor (or any path it calls) reads back into governance
        // state.
        let snapshot = {
            let proposal_ref =
                self.proposals
                    .get(proposal_id)
                    .ok_or_else(|| TokenError::ProposalNotFound {
                        proposal_id: proposal_id.to_string(),
                    })?;

            if proposal_ref.status == ProposalStatus::Executed {
                return Err(TokenError::ProposalAlreadyExecuted {
                    proposal_id: proposal_id.to_string(),
                });
            }
            if proposal_ref.status != ProposalStatus::Passed {
                return Err(TokenError::InvalidProposalType);
            }
            proposal_ref.clone()
        };

        // Dispatch to the node-supplied executor if one is wired. The
        // executor is responsible for the side effects (e.g. flipping the
        // burn-rate dial, transferring treasury funds). Returning Err here
        // leaves the proposal in `Passed` so it can be retried after the
        // operator fixes whatever blocked the apply.
        let executor_handle = self.executor.read().clone();
        if let Some(executor) = executor_handle {
            executor.apply_proposal(&snapshot).map_err(|e| {
                TokenError::ProposalExecutionFailed {
                    proposal_id: proposal_id.to_string(),
                    reason: e.to_string(),
                }
            })?;
        } else {
            warn!(
                "execute_proposal({}): no ProposalExecutor wired; status \
                 will flip to Executed but no side-effects applied",
                proposal_id
            );
        }

        // Mark as executed only after successful apply. Re-acquire the
        // shard lock just for the status flip.
        if let Some(mut proposal) = self.proposals.get_mut(proposal_id) {
            proposal.status = ProposalStatus::Executed;
            self.persist_proposal(&proposal);
        }

        info!("Executed proposal: {}", proposal_id);
        Ok(())
    }

    /// Returns a proposal by ID
    pub fn get_proposal(&self, proposal_id: &str) -> Option<GovernanceProposal> {
        self.proposals.get(proposal_id).map(|p| p.clone())
    }

    /// Lists all proposals
    pub fn list_proposals(&self) -> Vec<GovernanceProposal> {
        self.proposals
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Lists proposals with a specific status
    pub fn list_proposals_by_status(&self, status: ProposalStatus) -> Vec<GovernanceProposal> {
        self.proposals
            .iter()
            .filter(|entry| entry.value().status == status)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Delegates voting power to another address
    ///
    /// # Arguments
    ///
    /// * `delegator` - Address delegating voting power
    /// * `delegate` - Address receiving delegation
    /// * `voting_power` - Amount of voting power to delegate
    pub fn delegate(
        &self,
        delegator: Address,
        delegate: Address,
        voting_power: u128,
    ) -> Result<()> {
        if voting_power == 0 {
            return Err(TokenError::InvalidAmount(
                "Voting power must be greater than zero".to_string(),
            ));
        }

        let delegation = VotingDelegation::new(delegator, delegate, voting_power);
        self.persist_delegation(&delegator, &delegation);
        self.delegations.insert(delegator, delegation);

        info!(
            "Delegated {} voting power from {} to {}",
            voting_power, delegator, delegate
        );
        Ok(())
    }

    /// Revokes a voting delegation
    ///
    /// # Arguments
    ///
    /// * `delegator` - Address revoking delegation
    pub fn revoke_delegation(&self, delegator: &Address) -> Result<()> {
        self.delegations.remove(delegator);
        info!("Revoked delegation for {}", delegator);
        Ok(())
    }

    /// Gets the effective voting power including delegations
    fn get_effective_voting_power(&self, voter: &Address, base_power: u128) -> u128 {
        // Start with base power
        let mut total_power = base_power;

        // Add delegated power from others
        for delegation in self.delegations.iter() {
            if delegation.value().delegate == *voter && delegation.value().is_active() {
                total_power = total_power.saturating_add(delegation.value().voting_power);
            }
        }

        total_power
    }

    /// Updates quorum requirements
    pub fn set_quorum_requirements(&self, requirements: QuorumRequirements) {
        *self.quorum_requirements.write() = requirements;
        info!("Updated quorum requirements");
    }

    /// Updates minimum proposal stake
    pub fn set_min_proposal_stake(&self, min_stake: u128) {
        *self.min_proposal_stake.write() = min_stake;
        info!("Updated minimum proposal stake to {}", min_stake);
    }

    /// Returns votes for a proposal
    pub fn get_votes(&self, proposal_id: &str) -> Vec<GovernanceVote> {
        self.votes
            .get(proposal_id)
            .map(|v| v.clone())
            .unwrap_or_default()
    }
}

impl Default for GovernanceEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_proposal() {
        let engine = GovernanceEngine::new();
        let proposer = Address::new([1u8; 32]);
        let stake = 100_000 * 1_000_000_000_000_000_000u128; // 100k TNZO

        let proposal_id = engine
            .create_proposal(
                "Test Proposal".to_string(),
                "Description".to_string(),
                proposer,
                ProposalType::Custom {
                    proposal_data: vec![],
                },
                7 * 24 * 60 * 60 * 1000, // 7 days
                stake,
            )
            .unwrap();

        let proposal = engine.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Active);
    }

    #[test]
    fn test_vote() {
        let engine = GovernanceEngine::new();
        let proposer = Address::new([1u8; 32]);
        let voter = Address::new([2u8; 32]);
        let stake = 100_000 * 1_000_000_000_000_000_000u128;

        let proposal_id = engine
            .create_proposal(
                "Test Proposal".to_string(),
                "Description".to_string(),
                proposer,
                ProposalType::Custom {
                    proposal_data: vec![],
                },
                7 * 24 * 60 * 60 * 1000,
                stake,
            )
            .unwrap();

        engine
            .vote(&proposal_id, voter, VoteType::For, stake)
            .unwrap();

        let votes = engine.get_votes(&proposal_id);
        assert_eq!(votes.len(), 1);
    }
}
