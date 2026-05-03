//! # Tenzro Cortex
//!
//! Recurrent-depth reasoning as a first-class Tenzro Network primitive.
//!
//! Cortex treats the *loop depth* of recurrent-depth transformer models
//! (e.g. OpenMythos-style RDT/MoE architectures) as a schedulable, metered,
//! and cryptographically receipted resource on the Tenzro Ledger.
//!
//! ## Moving parts
//!
//! - [`traits::RecurrentDepthModel`] — backend trait that any reasoning model
//!   implements. Ship with [`sidecar::SidecarModel`] (HTTP sidecar client)
//!   and [`mock::MockCortexModel`] (deterministic test backend).
//! - [`worker::CortexWorker`] — network-facing worker combining a backend
//!   with pricing and budget enforcement.
//! - [`receipt`] — canonical input/output commitments and receipt signing.
//!
//! ## Design
//!
//! - **HTTP sidecar**: OpenMythos runs as a separate Python process
//!   exposing a small JSON API. The Rust worker handles metering, signing,
//!   policy, and settlement. This keeps the validator core free of PyTorch
//!   and GPU dependencies.
//! - **Loop depth as an economic primitive**: the worker charges
//!   `price_per_loop * loops_used` on top of base token fees, with optional
//!   TEE and ZK premiums.
//! - **Receipts bind execution to weights**: every inference produces a
//!   signed [`tenzro_types::cortex::CortexReceipt`] carrying input/output
//!   commitments, weights hash, runtime hash, loops used, and worker DID.
//!
//! Positioning: **Cortex reasons. Praecise governs. Tenzro settles.**
//! (Praecise is an open AI governance framework by Ipnops, used — not
//! owned — by Tenzro.)

pub mod advertisement;
pub mod attestation;
pub mod error;
pub mod metrics;
pub mod mock;
pub mod receipt;
pub mod sidecar;
pub mod signer;
pub mod traits;
pub mod worker;

pub use advertisement::{
    AdvertisementBroadcaster, CortexAdvertisement, CortexGossipPublisher, RemoteWorkerRegistry,
    CORTEX_TOPIC, DEFAULT_ADVERT_INTERVAL_SECS, DEFAULT_ADVERT_TTL_SECS,
};
pub use attestation::{AttestationSuite, TeeAttestationProvider, ZkProofProvider};
pub use error::{CortexError, Result};
pub use metrics::{
    CortexMetrics, CortexMetricsSnapshot, LatencyHistogramSnapshot, RejectionReason, TierSnapshot,
    LATENCY_BUCKETS_MS,
};
pub use mock::MockCortexModel;
pub use receipt::{canonicalize_input, canonicalize_output, hash_commitment, sign_receipt, verify_receipt};
pub use sidecar::{SidecarConfig, SidecarModel};
pub use signer::PersistentCortexSigner;
pub use traits::RecurrentDepthModel;
pub use worker::CortexWorker;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
    use tenzro_types::cortex::{
        AttestationRequirement, CortexModelFamily, CortexPricing, CortexRequest,
        ReasoningBudget, ReasoningTier,
    };
    use tenzro_types::primitives::Address;

    fn test_worker() -> CortexWorker {
        let signer: Arc<dyn Signer + Send + Sync> =
            Arc::new(Ed25519SignerImpl::generate().unwrap());
        // Worker address in Tenzro's 32-byte space; decoupled from the
        // 20-byte crypto Address derived from the signer.
        let addr = Address::default();
        let family = CortexModelFamily {
            arch: "rdt-moe".into(),
            max_loops: 32,
            moe_experts: 64,
            experts_per_token: 2,
            attn_type: "mla".into(),
            supported_tiers: vec![
                ReasoningTier::Fast,
                ReasoningTier::Standard,
                ReasoningTier::Deep,
            ],
        };
        let backend = Arc::new(MockCortexModel::new(
            "mythos-3b",
            family,
            "did:tenzro:machine:test-worker",
            addr,
            signer.clone(),
        ));
        CortexWorker::new(
            backend,
            CortexPricing::default(),
            signer,
            "did:tenzro:machine:test-worker",
            addr,
        )
    }

    #[tokio::test]
    async fn worker_executes_mock_and_signs_receipt() {
        let worker = test_worker();
        let budget = ReasoningBudget::for_tier(ReasoningTier::Standard);
        let req = CortexRequest {
            request_id: "req-1".into(),
            model_id: "mythos-3b".into(),
            requester: Address::default(),
            input: b"hello cortex".to_vec(),
            budget: ReasoningBudget {
                max_cost_tnzo: 10_000_000_000,
                ..budget
            },
            params: Default::default(),
            timestamp: tenzro_types::primitives::Timestamp::default(),
        };
        let resp = worker.execute(&req).await.unwrap();
        assert_eq!(resp.metadata.loops_used, 8);
        assert!(resp.price_tnzo > 0);
        verify_receipt(&resp.receipt).unwrap();
    }

    #[tokio::test]
    async fn worker_rejects_budget_overflow() {
        let worker = test_worker();
        let req = CortexRequest {
            request_id: "req-2".into(),
            model_id: "mythos-3b".into(),
            requester: Address::default(),
            input: b"hello".to_vec(),
            budget: ReasoningBudget {
                min_loops: 50,
                max_loops: 100,
                tier: ReasoningTier::Deep,
                max_cost_tnzo: 10_000_000_000,
                attestation: AttestationRequirement::None,
                deadline_ms: None,
            },
            params: Default::default(),
            timestamp: tenzro_types::primitives::Timestamp::default(),
        };
        let err = worker.execute(&req).await.unwrap_err();
        matches!(err, CortexError::InvalidBudget(_));
    }
}
