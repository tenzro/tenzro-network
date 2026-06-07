//! Bridges a Stripe SPT settlement-outcome webhook event to an ERC-8004
//! `ReputationRegistry::submitFeedback` row, written through a standard
//! EIP-1559 transaction against the canonical `ReputationRegistry` proxy
//! at [`tenzro_identity::erc8004::addresses::REPUTATION_REGISTRY`].
//!
//! Design (locked 2026-05-29 — see `project_erc8004_evm_architecture` memory):
//!
//! - **Feedback rows flow through the canonical proxy** via standard EVM
//!   transactions, with `msg.sender` = the node's `erc8004-system` key
//!   address.
//! - **Detached spawn.** The Stripe webhook handler is sync from the
//!   caller's perspective; we build calldata in-line, `tokio::spawn` the
//!   signed-tx submission via [`EvmTransactionSigner`], and return
//!   [`SptReputationOutcome`] immediately. Webhook delivery never blocks
//!   on an async eth_send round-trip.
//! - **System key signs.** The validator's `erc8004-system` secp256k1 key
//!   is the on-chain `rater`. Operators auditing the registry see "this
//!   row was authored by validator X (acting on a verified upstream Stripe
//!   signal)" — not by a peer agent.
//!
//! # Why a separate module
//!
//! `tenzro-payments` owns the wire types ([`SptWebhookEvent`],
//! [`SptOutcome`]) and `tenzro-bridge` owns the [`EvmTransactionSigner`].
//! This adapter, owned by `tenzro-node`, is the only place that pulls
//! both crates together — same split as [`crate::spt_revocation_dispatcher`]
//! and [`crate::spt_ceiling_bridge`].
//!
//! # What "cross-write" means
//!
//! When a Stripe-side settlement outcome lands (PaymentIntent succeeded,
//! payment failed, dispute created/closed) we don't *replace* on-chain
//! reputation with off-rail outcome data — we *append* it. Each webhook
//! event becomes one `submitFeedback(uint256 agentId, int8 rating,
//! string contextUri)` call against the canonical `ReputationRegistry`.
//! The dispatcher resolves the machine DID to its sequential ERC-8004
//! `agentId` via the [`OnChainAgentRegistry`] off-chain DID index.
//! Existing on-chain reputation from peer validators / counterparties is
//! preserved unchanged; the SPT outcome is one more voice in the
//! registry.
//!
//! # Unknown DIDs are rejected, not dropped
//!
//! If the machine DID has never been mirrored on-chain (no allocated
//! `agentId`), the dispatcher returns an error rather than fabricating
//! a synthetic subject key. This is the no-fallback discipline: an SPT
//! outcome targeting an unknown agent is a configuration bug at the
//! caller, not a silent data drop.

use std::sync::Arc;

use tracing::info;

use tenzro_bridge::evm_signer::EvmTransactionSigner;
use tenzro_identity::erc8004::{abi, addresses, selectors, OnChainAgentRegistry};
use tenzro_payments::mpp::stripe_spt::{SptOutcome, SptWebhookEvent};

use crate::error::{NodeError, Result};

/// Format the canonical `REPUTATION_REGISTRY` address as a `0x`-prefixed
/// hex string (the shape [`EvmTransactionSigner::send_transaction`]
/// expects for `to`).
fn reputation_registry_hex() -> String {
    let mut s = String::with_capacity(2 + 40);
    s.push_str("0x");
    s.push_str(&hex::encode(addresses::REPUTATION_REGISTRY));
    s
}

/// Outcome of a single dispatched cross-write. Returned to the RPC
/// caller so operators can audit which agents had reputation rows
/// appended.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SptReputationOutcome {
    /// The TDIP machine DID whose `agentId` was the feedback subject.
    pub machine_did: String,
    /// Stripe granted-token ID whose lifecycle event triggered the
    /// cross-write.
    pub granted_token_id: String,
    /// The settlement outcome derived from the webhook event.
    pub outcome: SptOutcome,
    /// ERC-8004 `agentId` (decimal `u64`) used as the `submitFeedback`
    /// subject. Matches the value `getFeedback` would key off.
    pub agent_id: u64,
    /// Rating written into the feedback row. 0..=100 scale, matches
    /// [`SptOutcome::reputation_score`] (cast to `i8` for the on-chain
    /// `int8` field — values are always non-negative for SPT outcomes).
    pub rating: i8,
    /// Always `true` if this struct is returned — the dispatcher errors
    /// on the unhappy paths. Present so JSON consumers don't have to
    /// special-case "missing means failure."
    ///
    /// Note: `true` means the tx was *accepted* for submission (calldata
    /// built, spawn enqueued). Inclusion / revert state must be looked
    /// up via `eth_getTransactionReceipt` against the tx hash logged at
    /// info level by the spawned task — we deliberately do not surface
    /// the tx hash here because returning it would require awaiting the
    /// spawn, defeating the detached-submission model.
    pub written: bool,
}

/// Maps a Stripe webhook event to the corresponding settlement outcome
/// and submits one `submitFeedback` transaction against the canonical
/// ERC-8004 `ReputationRegistry` proxy.
///
/// `event` must be a settlement-outcome event — i.e.
/// [`SptWebhookEvent::is_settlement_outcome`] returns `true`. SPT
/// lifecycle events (`created`/`activated`/`used`/`deactivated`) are
/// rejected: lifecycle goes to [`crate::spt_revocation_dispatcher`] (on
/// `deactivated`) or the SPT ceiling cache (on activation/use), not
/// here.
///
/// `dispute_status` is consulted only when `event` is
/// [`SptWebhookEvent::ChargeDisputeClosed`]: Stripe's `closed` event is
/// ambiguous on its own (won vs. lost) so the caller resolves it from
/// the `status` field on the dispute object (`won` →
/// [`SptOutcome::ChargebackWon`], `lost` →
/// [`SptOutcome::ChargebackLost`]). For the four unambiguous events we
/// pull the outcome straight from
/// [`SptWebhookEvent::settlement_outcome`].
///
/// `payment_intent_id` is recorded in the `contextUri` for audit
/// linking back to the Stripe object that triggered the cross-write.
/// `None` is fine — the `contextUri` just omits the field.
///
/// `agent_registry` is the [`OnChainAgentRegistry`] mirror used to
/// resolve `machine_did` to its allocated `agentId` via the off-chain
/// DID index. The dispatcher errors if the DID has no allocated id —
/// there is no fallback to a synthetic subject hash. This also means a
/// webhook arriving in the latency window between
/// `mirror_register_agent` and `Registered` event inclusion will be
/// rejected; the caller (Stripe webhook handler) is expected to retry
/// with backoff in that case.
///
/// `signer` is the node-held `erc8004-system` [`EvmTransactionSigner`].
/// `msg.sender` on the resulting `submitFeedback` call is the signer's
/// address — operators reading the on-chain registry see that the row
/// was authored by validator X acting on the upstream Stripe signal.
pub fn dispatch_settlement_outcome(
    event: &SptWebhookEvent,
    machine_did: &str,
    granted_token_id: &str,
    payment_intent_id: Option<&str>,
    dispute_status: Option<&str>,
    signer: &Arc<EvmTransactionSigner>,
    agent_registry: &Arc<dyn OnChainAgentRegistry>,
) -> Result<SptReputationOutcome> {
    // 1. Guard against accidental dispatch on non-settlement events.
    if !event.is_settlement_outcome() {
        return Err(NodeError::Other(format!(
            "ERC-8004 reputation dispatcher only accepts settlement-outcome events, \
             got {:?}",
            event
        )));
    }

    // 2. Resolve the outcome. Four of the five settlement events map
    //    deterministically; `dispute.closed` requires the dispute
    //    `status` field to disambiguate won vs. lost.
    let outcome = match event {
        SptWebhookEvent::ChargeDisputeClosed => match dispute_status {
            Some("won") => SptOutcome::ChargebackWon,
            Some("lost") => SptOutcome::ChargebackLost,
            other => {
                return Err(NodeError::Other(format!(
                    "charge.dispute.closed requires dispute_status='won' or 'lost', got {:?}",
                    other
                )));
            }
        },
        // Unambiguous events fall through to settlement_outcome().
        _ => event.settlement_outcome().ok_or_else(|| {
            NodeError::Other(format!(
                "settlement-outcome event {:?} produced no SptOutcome — \
                 settlement_outcome() returned None unexpectedly",
                event
            ))
        })?,
    };

    // 3. Resolve the outcome to a 0..=100 score and an audit context URI,
    //    then hand off to the protocol-neutral dispatch core (which resolves
    //    the agentId, builds calldata, and spawns the detached signed tx).
    let rating = outcome.reputation_score() as i8;
    let context_uri = match payment_intent_id {
        Some(pi) => format!(
            "stripe_spt:{} granted_token_id={} payment_intent_id={}",
            outcome.as_str(),
            granted_token_id,
            pi
        ),
        None => format!(
            "stripe_spt:{} granted_token_id={}",
            outcome.as_str(),
            granted_token_id
        ),
    };

    let agent_id =
        dispatch_reputation_feedback(machine_did, rating, &context_uri, signer, agent_registry)?;

    info!(
        machine_did = %machine_did,
        granted_token_id = %granted_token_id,
        outcome = %outcome.as_str(),
        agent_id = agent_id,
        rating,
        "Stripe SPT settlement outcome → ERC-8004 ReputationRegistry submit (tx spawned)"
    );

    Ok(SptReputationOutcome {
        machine_did: machine_did.to_string(),
        granted_token_id: granted_token_id.to_string(),
        outcome,
        agent_id,
        rating,
        written: true,
    })
}

/// Protocol-neutral ERC-8004 reputation-feedback dispatch — the shared core
/// beneath every settlement path that feeds reputation.
///
/// `dispatch_settlement_outcome` (Stripe SPT) is one caller; the native
/// task-marketplace `tenzro_completeTask` path, the x402 payment-receipt path,
/// the AP2 mandate-fulfilment path, and the A2A `tasks/complete` path are the
/// others (interop-bridge doc Layer 3 / Phase 7 — "broadcast the same dispatch
/// shape to non-Stripe outcomes"). All of them converge here so there is
/// exactly one place that resolves a DID → `agentId` and writes a
/// `submitFeedback(agentId, rating, contextUri)` row through the canonical
/// `ReputationRegistry` proxy with the node's `erc8004-system` key as
/// `msg.sender`.
///
/// `rating` is the 0..=100 reputation score cast to the on-chain `int8`
/// (always non-negative in our outcome model). `context_uri` is a free-form
/// audit string linking back to the originating event (task id, x402 tx hash,
/// AP2 mandate hash, …). Returns the resolved `agentId`.
///
/// No-fallback discipline: a DID with no allocated `agentId` is an error, not a
/// silent drop — the caller should register the machine identity and retry.
/// Submission is detached (`tokio::spawn`); transport/signing failures inside
/// the spawn are logged and dropped, decoupling the caller from inclusion
/// latency.
pub fn dispatch_reputation_feedback(
    machine_did: &str,
    rating: i8,
    context_uri: &str,
    signer: &Arc<EvmTransactionSigner>,
    agent_registry: &Arc<dyn OnChainAgentRegistry>,
) -> Result<u64> {
    let agent_id = agent_registry.lookup_agent_id_by_did(machine_did).ok_or_else(|| {
        NodeError::Other(format!(
            "ERC-8004 reputation dispatch: machine DID {} has no allocated \
             agentId on the on-chain mirror — register the machine identity \
             and wait for the Registered event before submitting feedback",
            machine_did
        ))
    })?;

    // Build calldata synchronously — pure, no I/O.
    let calldata =
        abi::encode_submit_feedback(selectors::SUBMIT_FEEDBACK, agent_id, rating, context_uri);

    // Detached signed-tx submission via the erc8004-system key.
    let signer = Arc::clone(signer);
    let to = reputation_registry_hex();
    let did_owned = machine_did.to_string();
    let ctx_owned = context_uri.to_string();

    tokio::spawn(async move {
        match signer.send_transaction(&to, &calldata, 0).await {
            Ok(tx_hash) => {
                tracing::info!(
                    target: "tenzro::erc8004::reputation",
                    machine_did = %did_owned,
                    agent_id = agent_id,
                    rating = rating,
                    context = %ctx_owned,
                    tx_hash = %tx_hash,
                    "ERC-8004 submitFeedback tx submitted"
                );
            }
            Err(e) => {
                tracing::warn!(
                    target: "tenzro::erc8004::reputation",
                    machine_did = %did_owned,
                    agent_id = agent_id,
                    error = %e,
                    "ERC-8004 submitFeedback tx submission failed"
                );
            }
        }
    });

    Ok(agent_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    use dashmap::DashMap;
    use tenzro_identity::erc8004::EthAddress;
    use tenzro_identity::error::Result as IdentityResult;

    /// In-test stub of [`OnChainAgentRegistry`] backed by a `DashMap`.
    /// Provides allocate-on-insert semantics for the DID index without
    /// going through the production signed-tx path. Tests pre-populate
    /// the index via [`StubMirror::allocate`] to simulate the post-event
    /// state where a `Registered(agentId, ...)` event has been observed
    /// and indexed.
    struct StubMirror {
        next_id: std::sync::atomic::AtomicU64,
        ids: DashMap<String, u64>,
    }

    impl StubMirror {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                next_id: std::sync::atomic::AtomicU64::new(1),
                ids: DashMap::new(),
            })
        }

        /// Convenience for tests: pre-populate the DID index as if the
        /// `Registered` event listener had already observed and indexed
        /// the agent.
        fn allocate(&self, did: &str) -> u64 {
            if let Some(existing) = self.ids.get(did) {
                return *existing;
            }
            let id = self
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.ids.insert(did.to_string(), id);
            id
        }
    }

    impl OnChainAgentRegistry for StubMirror {
        fn mirror_register_agent(
            &self,
            did: &str,
            _agent_address: &EthAddress,
            _metadata_uri: &str,
        ) -> IdentityResult<()> {
            self.allocate(did);
            Ok(())
        }

        fn lookup_agent_id_by_did(&self, did: &str) -> Option<u64> {
            self.ids.get(did).map(|v| *v)
        }
    }

    /// Build a stub [`EvmTransactionSigner`] pointed at a black-hole
    /// loopback RPC. The dispatcher returns `Accepted` after calldata
    /// build + `tokio::spawn`; the spawned `send_transaction` call will
    /// fail to connect (port 1 is reserved), logged + dropped. The
    /// dispatcher's `Result<SptReputationOutcome>` reflects only the
    /// calldata-build path, which is what these tests exercise.
    fn test_signer() -> Arc<EvmTransactionSigner> {
        Arc::new(
            EvmTransactionSigner::new(&[1u8; 32], 1337, "http://127.0.0.1:1".to_string())
                .expect("dev signer"),
        )
    }

    #[tokio::test]
    async fn rejects_lifecycle_events() {
        let signer = test_signer();
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let machine_did = "did:tenzro:machine:test:abc";

        // Pre-populate the DID index so the dispatcher's resolution
        // succeeds and we're actually testing the lifecycle-event
        // rejection branch, not the unknown-DID branch.
        mirror.mirror_register_agent(machine_did, &[0u8; 20], "ipfs://meta").unwrap();

        // Lifecycle events must not produce a feedback row — that path
        // belongs to the revocation dispatcher / ceiling cache.
        for event in [
            SptWebhookEvent::IssuedTokenCreated,
            SptWebhookEvent::IssuedTokenActivated,
            SptWebhookEvent::IssuedTokenUsed,
            SptWebhookEvent::GrantedTokenDeactivated,
        ] {
            let res = dispatch_settlement_outcome(
                &event,
                machine_did,
                "spt_grant_test",
                None,
                None,
                &signer,
                &mirror,
            );
            assert!(
                res.is_err(),
                "lifecycle event {:?} must be rejected",
                event
            );
        }
    }

    #[tokio::test]
    async fn rejects_unknown_machine_did() {
        // No-fallback discipline: an SPT outcome targeting a DID that
        // has never been mirrored on-chain (or whose Registered event
        // has not yet been indexed) is a configuration bug at the
        // caller — they should retry with backoff, not get a silent
        // data drop.
        let signer = test_signer();
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();

        let res = dispatch_settlement_outcome(
            &SptWebhookEvent::PaymentIntentSucceeded,
            "did:tenzro:machine:test:never-registered",
            "spt_grant_x",
            None,
            None,
            &signer,
            &mirror,
        );
        assert!(res.is_err(), "unknown DID must be rejected, not silently mapped");
    }

    #[tokio::test]
    async fn accepts_unambiguous_outcomes() {
        let signer = test_signer();
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let machine_did = "did:tenzro:machine:test:succeed";
        mirror.mirror_register_agent(machine_did, &[0u8; 20], "ipfs://meta").unwrap();
        let agent_id = mirror.lookup_agent_id_by_did(machine_did).unwrap();

        let outcome = dispatch_settlement_outcome(
            &SptWebhookEvent::PaymentIntentSucceeded,
            machine_did,
            "spt_grant_x",
            Some("pi_123"),
            None,
            &signer,
            &mirror,
        )
        .expect("succeeded event must spawn a feedback tx");

        assert_eq!(outcome.outcome, SptOutcome::Succeeded);
        assert_eq!(outcome.rating, 100);
        assert_eq!(outcome.agent_id, agent_id);
        assert!(outcome.written);
    }

    #[tokio::test]
    async fn dispute_closed_requires_status() {
        let signer = test_signer();
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let machine_did = "did:tenzro:machine:test:dispute";
        mirror.mirror_register_agent(machine_did, &[0u8; 20], "ipfs://meta").unwrap();

        // No dispute_status → reject.
        let res = dispatch_settlement_outcome(
            &SptWebhookEvent::ChargeDisputeClosed,
            machine_did,
            "spt_grant_d",
            None,
            None,
            &signer,
            &mirror,
        );
        assert!(res.is_err(), "dispute.closed without status must be rejected");

        // status="won" → ChargebackWon (75).
        let won = dispatch_settlement_outcome(
            &SptWebhookEvent::ChargeDisputeClosed,
            machine_did,
            "spt_grant_d",
            None,
            Some("won"),
            &signer,
            &mirror,
        )
        .expect("dispute.closed status=won must succeed");
        assert_eq!(won.outcome, SptOutcome::ChargebackWon);
        assert_eq!(won.rating, 75);

        // status="lost" → ChargebackLost (0).
        let lost = dispatch_settlement_outcome(
            &SptWebhookEvent::ChargeDisputeClosed,
            machine_did,
            "spt_grant_d",
            None,
            Some("lost"),
            &signer,
            &mirror,
        )
        .expect("dispute.closed status=lost must succeed");
        assert_eq!(lost.outcome, SptOutcome::ChargebackLost);
        assert_eq!(lost.rating, 0);

        // Unknown status → reject.
        let bogus = dispatch_settlement_outcome(
            &SptWebhookEvent::ChargeDisputeClosed,
            machine_did,
            "spt_grant_d",
            None,
            Some("pending"),
            &signer,
            &mirror,
        );
        assert!(bogus.is_err(), "unknown dispute_status must be rejected");
    }

    #[tokio::test]
    async fn payment_failed_maps_to_chargeback_lost() {
        let signer = test_signer();
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let machine_did = "did:tenzro:machine:test:fail";
        mirror.mirror_register_agent(machine_did, &[0u8; 20], "ipfs://meta").unwrap();

        let outcome = dispatch_settlement_outcome(
            &SptWebhookEvent::PaymentIntentFailed,
            machine_did,
            "spt_grant_f",
            None,
            None,
            &signer,
            &mirror,
        )
        .expect("payment_failed event must spawn a feedback tx");

        assert_eq!(outcome.outcome, SptOutcome::ChargebackLost);
        assert_eq!(outcome.rating, 0);
    }

    #[tokio::test]
    async fn dispute_created_maps_to_disputed() {
        let signer = test_signer();
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let machine_did = "did:tenzro:machine:test:disputed";
        mirror.mirror_register_agent(machine_did, &[0u8; 20], "ipfs://meta").unwrap();

        let outcome = dispatch_settlement_outcome(
            &SptWebhookEvent::ChargeDisputeCreated,
            machine_did,
            "spt_grant_dc",
            None,
            None,
            &signer,
            &mirror,
        )
        .expect("dispute.created event must spawn a feedback tx");

        assert_eq!(outcome.outcome, SptOutcome::Disputed);
        assert_eq!(outcome.rating, 50);
    }

    #[tokio::test]
    async fn multiple_outcomes_for_same_agent_each_spawn() {
        let signer = test_signer();
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let machine_did = "did:tenzro:machine:test:multi";
        mirror.mirror_register_agent(machine_did, &[0u8; 20], "ipfs://meta").unwrap();
        let agent_id = mirror.lookup_agent_id_by_did(machine_did).unwrap();

        // Three separate webhook events for the same agent → three
        // detached tx spawns. The dispatcher returns Accepted on each
        // (calldata-build succeeded); the registry's append-only
        // semantics are enforced on-chain by the canonical proxy.
        for event in [
            SptWebhookEvent::PaymentIntentSucceeded,
            SptWebhookEvent::ChargeDisputeCreated,
            SptWebhookEvent::PaymentIntentSucceeded,
        ] {
            let outcome = dispatch_settlement_outcome(
                &event,
                machine_did,
                "spt_grant_multi",
                None,
                None,
                &signer,
                &mirror,
            )
            .expect("each settlement-outcome event must spawn a tx");
            assert_eq!(outcome.agent_id, agent_id);
            assert!(outcome.written);
        }
    }
}
