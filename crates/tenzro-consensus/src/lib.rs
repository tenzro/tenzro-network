//! HotStuff-2 BFT Consensus Engine for Tenzro Network
//!
//! This crate implements the HotStuff-2 consensus protocol, a two-phase BFT
//! consensus algorithm with O(n) linear communication complexity per view.
//!
//! # Overview
//!
//! HotStuff-2 provides:
//! - **Fast Finality**: Two-phase protocol (PREPARE → COMMIT → DECIDE)
//! - **Linear Communication**: O(n) message complexity per view
//! - **Optimistic Responsiveness**: Commits in network delay time under good conditions
//! - **TEE Integration**: Validators with TEE attestation get priority in leader selection
//! - **Robust Liveness**: Automatic view changes on timeout
//!
//! # Architecture
//!
//! The consensus engine consists of several key components:
//!
//! - **HotStuff2Engine**: Main consensus engine implementing the protocol
//! - **ValidatorSet**: Manages the set of validators and their voting power
//! - **EpochManager**: Handles epoch transitions and validator set updates
//! - **VoteCollector**: Collects votes and forms quorum certificates
//! - **BlockProposer**: Creates block proposals with transaction selection
//! - **Mempool**: Transaction pool with priority ordering
//! - **FinalityTracker**: Tracks finalized blocks and sends notifications
//!
//! # Protocol Flow
//!
//! 1. **PREPARE Phase**:
//!    - Leader proposes a block
//!    - Validators vote on the proposal
//!    - Prepare QC formed when 2f+1 votes collected
//!
//! 2. **COMMIT Phase**:
//!    - Leader shares prepare QC
//!    - Validators vote to commit
//!    - Commit QC formed when 2f+1 votes collected
//!
//! 3. **DECIDE Phase**:
//!    - Block is finalized
//!    - Transactions removed from mempool
//!    - Advance to next height
//!
//! # TEE Integration
//!
//! Validators with valid TEE attestation receive priority in leader selection,
//! providing hardware-rooted trust. The leader selection algorithm gives
//! TEE-attested validators 2x voting weight for leader selection while
//! maintaining standard voting power for consensus.
//!
//! # Examples
//!
//! ```no_run
//! use tenzro_consensus::{
//!     HotStuff2Engine, ConsensusConfig, ConsensusEngine,
//!     EpochManager, ValidatorInfo,
//! };
//! use tenzro_crypto::pq::MlDsaSigningKey;
//! use tenzro_crypto::{KeyPair, KeyType};
//! use tenzro_types::primitives::Address;
//!
//! #[tokio::main]
//! async fn main() -> tenzro_consensus::Result<()> {
//!     // Generate validator hybrid keypair (classical + ML-DSA-65)
//!     let keypair = KeyPair::generate(KeyType::Ed25519)?;
//!     let pq_key = MlDsaSigningKey::generate();
//!
//!     // Convert address (tenzro_crypto::Address is 20 bytes, tenzro_types::Address is 32 bytes)
//!     let crypto_addr = keypair.address();
//!     let mut addr_bytes = [0u8; 32];
//!     addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
//!     let address = Address::new(addr_bytes);
//!
//!     // Create validators with mandatory PQ verifying keys
//!     let validators = vec![
//!         ValidatorInfo::new(
//!             address,
//!             keypair.public_key().clone(),
//!             pq_key.verifying_key_bytes().to_vec(),
//!             1000,
//!         ),
//!     ];
//!
//!     // Create epoch manager
//!     let epoch_manager = EpochManager::new(validators, 10000)?;
//!
//!     // Create consensus engine
//!     let config = ConsensusConfig::default()
//!         .with_block_time(400)
//!         .with_view_timeout(2000);
//!
//!     let mut engine = HotStuff2Engine::new(keypair, pq_key, config, epoch_manager);
//!
//!     // Start consensus
//!     engine.start().await?;
//!
//!     // Engine now participates in consensus...
//!
//!     Ok(())
//! }
//! ```

pub mod config;
pub mod epoch_manager;
pub mod error;
pub mod finality;
pub mod hotstuff2;
pub mod mempool;
pub mod proposer;
pub mod timeout;
pub mod traits;
pub mod validator;
pub mod vote_state;
pub mod voter;

// Re-export commonly used types
pub use config::{ConsensusConfig, BftThreshold, LeaderRotation};
pub use epoch_manager::{Epoch, EpochManager, EpochStats};
pub use error::{ConsensusError, Result};
pub use finality::{FinalityNotification, FinalityTracker, ForkChoice};
pub use hotstuff2::{
    BlockProvider, ConsensusOutMessage, HotStuff2Engine, Phase, StateRootProvider,
};
pub use mempool::{Mempool, MempoolStats};
pub use proposer::BlockProposer;
pub use timeout::{
    CollectOutcome, TcSigner, TimeoutCertificate, TimeoutCollector, TimeoutMsg,
    TIMEOUT_CERTIFICATE_FORMAT_VERSION, TIMEOUT_MSG_FORMAT_VERSION,
};
pub use traits::{ConsensusEngine, ConsensusNetwork, SlashingCallback, StateManager};
pub use validator::{
    EquivocationDetector, EquivocationEvidence, ValidatorInfo, ValidatorSet, ValidatorStatus,
};
pub use vote_state::{
    open_default_file_store, FileVoteStateStore, LastSignState, MemoryVoteStateStore,
    VoteStateStore, VoteStep, VrsDecision,
};
pub use voter::{QuorumCertificate, Vote, VoteCollector, VoteType};

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::{KeyPair, KeyType};

    #[test]
    fn test_crate_version() {
        // Basic smoke test to ensure the crate compiles
        let config = ConsensusConfig::default();
        assert_eq!(config.block_time_ms, 400);
    }

    fn convert_address(crypto_addr: tenzro_crypto::Address) -> tenzro_types::primitives::Address {
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        tenzro_types::primitives::Address::new(addr_bytes)
    }

    #[test]
    fn test_validator_creation() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let address = convert_address(keypair.address());
        let pq = MlDsaSigningKey::generate();
        let validator = ValidatorInfo::new(
            address,
            keypair.public_key().clone(),
            pq.verifying_key_bytes().to_vec(),
            1000,
        );

        assert_eq!(validator.stake, 1000);
        assert!(validator.is_active());
    }

    #[test]
    fn test_epoch_manager_creation() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let address = convert_address(keypair.address());
        let pq = MlDsaSigningKey::generate();
        let validators = vec![
            ValidatorInfo::new(
                address,
                keypair.public_key().clone(),
                pq.verifying_key_bytes().to_vec(),
                1000,
            ),
        ];

        let epoch_manager = EpochManager::new(validators, 100).unwrap();
        let epoch = epoch_manager.current_epoch();

        assert_eq!(epoch.number, 0);
        assert_eq!(epoch.duration(), 100);
    }

    #[tokio::test]
    async fn test_consensus_engine_creation() {
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let address = convert_address(keypair.address());
        let pq = MlDsaSigningKey::generate();
        let validators = vec![
            ValidatorInfo::new(
                address,
                keypair.public_key().clone(),
                pq.verifying_key_bytes().to_vec(),
                1000,
            ),
        ];

        let config = ConsensusConfig::default();
        let epoch_manager = EpochManager::new(validators, 100).unwrap();
        let pq_engine = MlDsaSigningKey::generate();
        let engine = HotStuff2Engine::new(keypair, pq_engine, config, epoch_manager);

        assert_eq!(engine.finalized_height().await, tenzro_types::primitives::BlockHeight::from(0));
    }
}
