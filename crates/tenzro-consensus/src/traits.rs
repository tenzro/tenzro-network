//! Consensus engine trait definitions

use crate::error::Result;
use crate::voter::Vote;
use async_trait::async_trait;
use tenzro_types::block::Block;
use tenzro_types::primitives::BlockHeight;
use tenzro_types::transaction::Transaction;

/// Trait for consensus engine implementations
///
/// This trait defines the interface that all consensus engines must implement
/// to participate in block production and finalization.
#[async_trait]
pub trait ConsensusEngine: Send + Sync {
    /// Starts the consensus engine
    ///
    /// Initializes the engine and begins participating in consensus.
    async fn start(&mut self) -> Result<()>;

    /// Stops the consensus engine
    ///
    /// Gracefully shuts down the engine and stops consensus participation.
    async fn stop(&mut self) -> Result<()>;

    /// Proposes a new block with the given transactions
    ///
    /// Only the designated leader for the current view can successfully propose.
    async fn propose_block(&self, transactions: Vec<Transaction>) -> Result<Block>;

    /// Handles a block proposal from another validator.
    ///
    /// `timeout_certificate` is `Some(_)` only when the leader is recovering
    /// from a view timeout — it carries 2f+1 timeout signatures from the
    /// previous view so the receiver can verify the new view was legitimately
    /// abandoned (Jolteon `safe_to_extend`, DiemBFT v4 §3.5).
    ///
    /// `no_endorsement_certificate` is `Some(_)` when the leader is proposing
    /// a fresh block after a view timeout for which no Prepare-QC was observed.
    /// It carries f+1 NoEndorsement signatures attesting that no validator saw
    /// a QC for the previous view (MonadBFT NEC, arXiv:2502.20692). When the
    /// previous view DID have a QC, the leader must instead repropose the
    /// `high_tip` block — in which case `no_endorsement_certificate` is `None`
    /// and the proposed block hash matches the existing high-QC block.
    ///
    /// `proposer_high_qc_view` is the proposer's local highest-Prepare-QC view
    /// at the moment of proposing (#171, Aptos SyncInfo). The receiver adopts
    /// it if higher than its own (and `< proposal_view`) so a lagging replica
    /// can fast-forward on the happy path.
    ///
    /// Returns a vote if the proposal is valid.
    async fn on_proposal(
        &self,
        block: &Block,
        timeout_certificate: Option<crate::timeout::TimeoutCertificate>,
        no_endorsement_certificate: Option<crate::timeout::NoEndorsementCertificate>,
        proposer_high_qc_view: u64,
    ) -> Result<Vote>;

    /// Handles a vote from another validator
    ///
    /// Collects votes and forms quorum certificates when threshold is reached.
    async fn on_vote(&self, vote: &Vote) -> Result<()>;

    /// Returns the height of the highest finalized block
    async fn finalized_height(&self) -> BlockHeight;

    /// Checks if this node is the leader for the current view
    async fn is_leader(&self) -> bool;
}

/// Trait for consensus network communication
///
/// Implementations of this trait handle broadcasting and receiving
/// consensus messages over the network.
#[async_trait]
pub trait ConsensusNetwork: Send + Sync {
    /// Broadcasts a block proposal to all validators
    async fn broadcast_proposal(&self, block: &Block) -> Result<()>;

    /// Sends a vote to the leader
    async fn send_vote(&self, vote: &Vote) -> Result<()>;

    /// Broadcasts a vote to all validators
    async fn broadcast_vote(&self, vote: &Vote) -> Result<()>;
}

/// Callback trait for slashing misbehaving validators
///
/// Implementations of this trait handle the economic punishment of validators
/// who are caught equivocating (voting for conflicting blocks in the same view).
/// This is defined as a trait to avoid circular dependencies between
/// tenzro-consensus and tenzro-token.
pub trait SlashingCallback: Send + Sync {
    /// Called when equivocation is detected for a validator.
    ///
    /// The implementation should slash the validator's stake and record
    /// the evidence for accountability.
    fn report_equivocation(
        &self,
        validator: &tenzro_types::primitives::Address,
        view: u64,
        evidence: &crate::validator::EquivocationEvidence,
    );
}

/// Trait for state management
///
/// The consensus engine uses this to interact with the blockchain state.
#[async_trait]
pub trait StateManager: Send + Sync {
    /// Executes a block and returns the new state root
    async fn execute_block(&self, block: &Block) -> Result<tenzro_types::primitives::Hash>;

    /// Validates a block against the current state
    async fn validate_block(&self, block: &Block) -> Result<()>;

    /// Commits a finalized block to persistent storage
    async fn commit_block(&self, block: &Block) -> Result<()>;

    /// Returns the current state root
    async fn state_root(&self) -> tenzro_types::primitives::Hash;
}
