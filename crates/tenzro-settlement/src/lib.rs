//! Payment settlement engine for Tenzro Network
//!
//! This crate provides the core payment settlement functionality for Tenzro Network:
//!
//! - **Settlement Engine**: Atomic settlements for inference/TEE services with automatic fee collection
//! - **Escrow System**: Pre-funded settlements with flexible release conditions
//! - **Fee Collection**: Multi-asset network fee collection and routing to treasury
//! - **Batch Processing**: Atomic multi-settlement operations
//! - **Micropayment Channels**: Off-chain payment channels for high-frequency small payments
//!
//! # Architecture
//!
//! The settlement system handles all payment flows on Tenzro Network:
//!
//! 1. **Immediate Settlements**: Single-shot payments for services rendered
//! 2. **Escrow-based Settlements**: Pre-funded escrow accounts with proof-based release
//! 3. **Batch Settlements**: Multiple settlements processed atomically
//! 4. **Streaming Payments**: Micropayment channels for per-token inference billing
//!
//! All settlements collect network fees (configurable, default 0.5%) which are routed
//! to the network treasury for ecosystem funding.
//!
//! # Examples
//!
//! ## Basic Settlement
//!
//! ```rust,no_run
//! use tenzro_settlement::{SettlementEngine, SettlementConfig};
//! use tenzro_token::NetworkTreasury;
//! use tenzro_types::primitives::Address;
//! use tenzro_types::settlement::{SettlementRequest, ServiceType, ServiceProof, ProofType};
//! use std::sync::Arc;
//!
//! # async fn example() -> tenzro_settlement::Result<()> {
//! // Create treasury and settlement engine
//! let treasury_addr = Address::default();
//! let treasury = Arc::new(NetworkTreasury::new(treasury_addr));
//! let config = SettlementConfig::new(treasury_addr);
//! let engine = SettlementEngine::new(config, treasury)?;
//!
//! // Create a settlement request
//! let provider = Address::default();
//! let customer = Address::default();
//! let proof = ServiceProof::new(ProofType::Cryptographic, vec![1, 2, 3]);
//! let request = SettlementRequest::new(
//!     provider,
//!     customer,
//!     ServiceType::ModelInference {
//!         model_id: "gpt-4".to_string(),
//!         tokens: 1000,
//!     },
//!     10000,
//!     proof,
//! );
//!
//! // Process settlement
//! let receipt = engine.settle(request).await?;
//! println!("Settlement completed: {}", receipt.receipt_id);
//! # Ok(())
//! # }
//! ```
//!
//! ## Escrow Settlement
//!
//! ```rust,no_run
//! use tenzro_settlement::EscrowManager;
//! use tenzro_types::primitives::{Address, Timestamp};
//! use tenzro_types::asset::AssetId;
//! use tenzro_types::settlement::{ReleaseConditions, ServiceProof, ProofType};
//! use std::sync::Arc;
//! use dashmap::DashMap;
//!
//! # fn example() -> tenzro_settlement::Result<()> {
//! // Create escrow manager
//! let balances = Arc::new(DashMap::new());
//! let manager = EscrowManager::new(balances);
//!
//! // Create escrow
//! let payer = Address::default();
//! let payee = Address::default();
//! let expires_at = Timestamp::now().as_millis() + 86400000; // 24 hours
//! let escrow = manager.create_escrow(
//!     payer,
//!     payee,
//!     5000,
//!     AssetId::tnzo(),
//!     Timestamp::new(expires_at),
//!     ReleaseConditions::ProviderSignature,
//! )?;
//!
//! // Later: release with proof
//! let proof = ServiceProof::new(ProofType::Cryptographic, vec![1, 2, 3]);
//! manager.release_escrow(&escrow.escrow_id, &proof)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Micropayment Channel
//!
//! ```rust,no_run
//! use tenzro_settlement::ChannelManager;
//! use tenzro_crypto::keys::{KeyPair, KeyType};
//! use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
//! use tenzro_types::primitives::{Address, Timestamp};
//! use tenzro_types::asset::AssetId;
//!
//! # fn example() -> tenzro_settlement::Result<()> {
//! let manager = ChannelManager::new();
//!
//! // Generate a payer keypair. The payer's `Address` is derived from
//! // the public key bytes so the channel verifier can recover the same
//! // key from `payer.as_bytes()` to check signatures.
//! let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
//! let pk = keypair.public_key().as_bytes();
//! let mut addr = [0u8; 32];
//! addr[..pk.len().min(32)].copy_from_slice(&pk[..pk.len().min(32)]);
//! let payer = Address::new(addr);
//! let payee = Address::default();
//!
//! let expires_at = Timestamp::now().as_millis() + 86400000;
//! let channel = manager.open_channel(
//!     payer,
//!     payee,
//!     10000,
//!     AssetId::tnzo(),
//!     Timestamp::new(expires_at),
//!     None, // app_wallet — no developer-margin attribution
//!     0,    // margin_bps
//! )?;
//!
//! // Each update is a real Ed25519 signature by the payer over the
//! // canonical state encoding (`nonce || payer_balance || payee_balance`)
//! // of the next state. The verifier in `update_channel` reconstructs
//! // the same encoding and rejects the call on signature mismatch.
//! let signer = Ed25519SignerImpl::new(keypair).unwrap();
//! let next1 = channel.state.next(9900, 100);
//! let sig1 = signer.sign(&next1.canonical_message()).unwrap();
//! manager.update_channel(&channel.channel_id, 100, sig1.as_bytes().to_vec())?;
//!
//! let next2 = next1.next(9850, 150);
//! let sig2 = signer.sign(&next2.canonical_message()).unwrap();
//! manager.update_channel(&channel.channel_id, 50, sig2.as_bytes().to_vec())?;
//!
//! // Close channel
//! manager.close_channel(&channel.channel_id)?;
//! # Ok(())
//! # }
//! ```

pub mod batch;
pub mod engine;
pub mod error;
pub mod escrow;
pub mod fee_collector;
pub mod intent_7683_fills;
pub mod kill_switch;
pub mod micropayments;
pub mod netting;
pub mod obligations;
pub mod prepaid;
pub mod rental;
pub mod saga;

// Re-export commonly used types
pub use batch::{BatchProcessor, BatchSettlementResult, BatchStats, BatchStatus, SettlementBatch};
pub use engine::{
    DefaultTeeVerifier, DefaultZkVerifier, SettlementConfig, SettlementEngine, SettlementStats,
    TeeAttestationVerifier, ZkProofVerifier,
};
pub use error::{Result, SettlementError};
pub use escrow::{EscrowAccount, EscrowManager, EscrowStats, EscrowStatus};
pub use fee_collector::{CollectionStats, FeeCollector, FeeRecord, PeriodStats};
pub use intent_7683_fills::Spec4FillRegistry;
pub use kill_switch::{KillSwitchStats, KillSwitchStore};
pub use micropayments::{
    ChannelDispute, ChannelManager, ChannelState, ChannelStats, ChannelStatus, ChannelStorage,
    DisputeStatus, InMemoryChannelStorage, MicropaymentChannel, NanopaymentBatchResult,
    NanopaymentBatcher, NanopaymentEntry, RocksDbChannelStorage,
};
pub use netting::{
    NettingBatch, NettingManager, NettingStatus, Obligation, SettlementInstruction,
    compute_batch_id, verify_netting_invariant,
};
pub use obligations::{ObligationSource, ProviderObligations};
pub use prepaid::{AccountLedger, PrepaidLedger};
pub use rental::{
    DEFAULT_MISS_TERMINATION_THRESHOLD, EpochOutcome, RentalAgreement, RentalManager, RentalStatus,
    StakeLedger, TerminationReason,
};
pub use saga::{
    DvpSaga, LegExecutor, LegOutcome, LegReceipt, LegResult, LegVenue, SagaLeg, SagaOrchestrator,
    SagaState, compute_saga_id,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_exports() {
        // Ensure main types are accessible
        let _ = SettlementConfig::default();
        let _ = ChannelManager::new();
        let _ = BatchProcessor::new(100);
    }
}
