//! Governance types for Tenzro Network
//!
//! This module defines types for on-chain governance, voting,
//! and proposal management.

use crate::primitives::{Address, Timestamp};
use serde::{Deserialize, Serialize};

/// A governance vote cast by a token holder
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceVote {
    /// Vote ID
    pub vote_id: String,
    /// Proposal being voted on
    pub proposal_id: String,
    /// Voter address
    pub voter: Address,
    /// Vote type
    pub vote_type: VoteType,
    /// Voting power used
    pub voting_power: u128,
    /// Vote timestamp
    pub voted_at: Timestamp,
    /// Optional vote justification
    pub justification: Option<String>,
}

impl GovernanceVote {
    /// Creates a new governance vote
    pub fn new(
        proposal_id: String,
        voter: Address,
        vote_type: VoteType,
        voting_power: u128,
    ) -> Self {
        Self {
            vote_id: uuid::Uuid::new_v4().to_string(),
            proposal_id,
            voter,
            vote_type,
            voting_power,
            voted_at: Timestamp::now(),
            justification: None,
        }
    }

    /// Adds a justification to the vote
    pub fn with_justification(mut self, justification: String) -> Self {
        self.justification = Some(justification);
        self
    }
}

/// Type of vote cast
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    /// Vote in favor
    For,
    /// Vote against
    Against,
    /// Abstain from voting
    Abstain,
}

impl VoteType {
    /// Returns true if this is a "for" vote
    pub fn is_for(&self) -> bool {
        matches!(self, Self::For)
    }

    /// Returns true if this is an "against" vote
    pub fn is_against(&self) -> bool {
        matches!(self, Self::Against)
    }

    /// Returns true if this is an abstain vote
    pub fn is_abstain(&self) -> bool {
        matches!(self, Self::Abstain)
    }
}

/// Voting power delegation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VotingDelegation {
    /// Delegator address
    pub delegator: Address,
    /// Delegate address
    pub delegate: Address,
    /// Amount of voting power delegated
    pub voting_power: u128,
    /// Delegation start time
    pub delegated_at: Timestamp,
    /// Optional delegation end time
    pub expires_at: Option<Timestamp>,
    /// Delegation status
    pub status: DelegationStatus,
}

impl VotingDelegation {
    /// Creates a new voting delegation
    pub fn new(delegator: Address, delegate: Address, voting_power: u128) -> Self {
        Self {
            delegator,
            delegate,
            voting_power,
            delegated_at: Timestamp::now(),
            expires_at: None,
            status: DelegationStatus::Active,
        }
    }

    /// Sets an expiration time
    pub fn with_expiration(mut self, expires_at: Timestamp) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Checks if the delegation is active
    pub fn is_active(&self) -> bool {
        if self.status != DelegationStatus::Active {
            return false;
        }

        if let Some(expires_at) = self.expires_at {
            Timestamp::now() < expires_at
        } else {
            true
        }
    }
}

/// Status of a voting delegation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelegationStatus {
    /// Delegation is active
    Active,
    /// Delegation has been revoked
    Revoked,
    /// Delegation has expired
    Expired,
}

/// Quorum requirements for proposals
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumRequirements {
    /// Minimum participation (basis points)
    pub minimum_participation_bps: u32,
    /// Minimum approval (basis points)
    pub minimum_approval_bps: u32,
    /// Absolute minimum votes required
    pub minimum_votes: u128,
}

impl Default for QuorumRequirements {
    fn default() -> Self {
        Self {
            minimum_participation_bps: 2000, // 20%
            minimum_approval_bps: 5000,      // 50%
            minimum_votes: 1000u128.saturating_mul(10u128.saturating_pow(18)), // 1000 TNZO
        }
    }
}

impl QuorumRequirements {
    /// Checks if quorum is met
    pub fn is_met(&self, votes_for: u128, votes_against: u128, total_supply: u128) -> bool {
        let total_votes = votes_for.saturating_add(votes_against);

        // Check minimum votes
        if total_votes < self.minimum_votes {
            return false;
        }

        // Check minimum participation
        let participation = (total_votes as f64 / total_supply as f64) * 10000.0;
        if (participation as u32) < self.minimum_participation_bps {
            return false;
        }

        // Check minimum approval
        let approval = (votes_for as f64 / total_votes as f64) * 10000.0;
        (approval as u32) >= self.minimum_approval_bps
    }
}

/// Voter information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoterInfo {
    /// Voter address
    pub address: Address,
    /// Direct voting power
    pub direct_voting_power: u128,
    /// Delegated voting power received
    pub delegated_voting_power: u128,
    /// Total proposals voted on
    pub total_votes_cast: u64,
    /// Participation rate (basis points)
    pub participation_rate: u32,
}

impl VoterInfo {
    /// Creates a new voter info
    pub fn new(address: Address, voting_power: u128) -> Self {
        Self {
            address,
            direct_voting_power: voting_power,
            delegated_voting_power: 0,
            total_votes_cast: 0,
            participation_rate: 0,
        }
    }

    /// Returns the total voting power
    pub fn total_voting_power(&self) -> u128 {
        self.direct_voting_power
            .saturating_add(self.delegated_voting_power)
    }

    /// Records a vote cast
    pub fn record_vote(&mut self) {
        self.total_votes_cast += 1;
    }
}
