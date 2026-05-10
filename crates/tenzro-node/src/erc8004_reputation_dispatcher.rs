//! Bridges a Stripe SPT settlement-outcome webhook event to an ERC-8004
//! `ReputationRegistry::submitFeedback` row, written through the native
//! precompile-backed registry at `0x101b`.
//!
//! # Why a separate module
//!
//! `tenzro-payments` owns the wire types ([`SptWebhookEvent`],
//! [`SptOutcome`]) and `tenzro-vm` owns the local
//! [`Erc8004ReputationRegistry`] entry point. This adapter, owned by
//! `tenzro-node`, is the only place that pulls both crates together —
//! same split as [`crate::spt_revocation_dispatcher`] and
//! [`crate::spt_ceiling_bridge`].
//!
//! # What "cross-write" means
//!
//! When a Stripe-side settlement outcome lands (PaymentIntent succeeded,
//! payment failed, dispute created/closed) we don't *replace* on-chain
//! reputation with off-rail outcome data — we *append* it. Each webhook
//! event becomes one append-only `FeedbackEntry { subject, rater,
//! rating, context_uri }` row keyed by the agent's `agentId`. The
//! dispatcher resolves the machine DID to its sequential ERC-8004
//! `agentId` via the [`OnChainAgentRegistry`] mirror and uses the
//! 32-byte big-endian encoding of that `u64` as the reputation
//! registry's subject key — matching the EVM precompile's wire shape.
//! Existing on-chain reputation from peer validators / counterparties
//! is preserved unchanged; the SPT outcome is one more voice in the
//! registry.
//!
//! # Unknown DIDs are rejected, not dropped
//!
//! If the machine DID has never been mirrored on-chain (no allocated
//! `agentId`), the dispatcher returns an error rather than fabricating
//! a synthetic subject key. This is the no-fallback discipline: an SPT
//! outcome targeting an unknown agent is a configuration bug at the
//! caller, not a silent data drop.
//!
//! # Authority model
//!
//! The local validator is the authority that takes the verified Stripe
//! signal and writes the feedback row. The `rater` field is set to the
//! validator's address — the same address that signs blocks — so a
//! later reader can see that the row was authored by a Tenzro
//! validator (acting on a Stripe webhook), not by a peer agent.
//!
//! # Bypass of the precompile dispatch path
//!
//! We call [`Erc8004ReputationRegistry::submit`] directly rather than
//! routing through the EVM `0x101b` precompile because:
//!
//! 1. No gas accounting needed for an internal write triggered by a
//!    trusted webhook (the gas model exists to bound *user* calldata).
//! 2. No round-trip through ABI encoding when we already have native
//!    types.
//! 3. Matches the existing pattern: [`crate::spt_revocation_dispatcher`]
//!    calls `IdentityRegistry::revoke` directly, not through any RPC.
//!
//! Callers that *do* want gas accounting + ABI encoding should drive
//! the registry through the precompile path with calldata built from
//! [`tenzro_identity::erc8004::abi::encode_submit_feedback`].

use std::sync::Arc;

use tracing::info;

use tenzro_identity::erc8004::OnChainAgentRegistry;
use tenzro_payments::mpp::stripe_spt::{SptOutcome, SptWebhookEvent};
use tenzro_vm::{Erc8004FeedbackEntry, Erc8004ReputationRegistry};

use crate::error::{NodeError, Result};

/// Encode a `u64` `agentId` as the 32-byte big-endian `uint256` word
/// used by the ERC-8004 ReputationRegistry to key feedback rows. This
/// matches `tenzro_identity::erc8004::agent_id_to_uint256_be` byte for
/// byte; we re-implement it locally to keep this dispatcher
/// self-contained on the `OnChainAgentRegistry` trait surface alone.
fn agent_id_to_subject_word(agent_id: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&agent_id.to_be_bytes());
    out
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
    /// 32-byte ERC-8004 `agentId`, hex-encoded, as written to the
    /// registry. Same value `getFeedback` would key off.
    pub agent_id_hex: String,
    /// Rating written into the `FeedbackEntry`. 0..=100 scale, matches
    /// [`SptOutcome::reputation_score`] (cast to `i8` for the on-chain
    /// `int8` field — values are always non-negative for SPT outcomes).
    pub rating: i8,
    /// Always `true` if this struct is returned (the dispatcher errors
    /// otherwise). Present so JSON consumers don't have to special-case
    /// "missing means failure."
    pub written: bool,
}

/// Maps a Stripe webhook event to the corresponding settlement outcome
/// and writes one `FeedbackEntry` row to the native ERC-8004
/// `ReputationRegistry`.
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
/// `payment_intent_id` is recorded in the `context_uri` for audit
/// linking back to the Stripe object that triggered the cross-write.
/// `None` is fine — the `context_uri` just omits the field.
///
/// `agent_registry` is the [`OnChainAgentRegistry`] mirror used to
/// resolve `machine_did` to its allocated `agentId`. The dispatcher
/// errors if the DID has no allocated id — there is no fallback to a
/// synthetic subject hash.
pub fn dispatch_settlement_outcome(
    event: &SptWebhookEvent,
    machine_did: &str,
    granted_token_id: &str,
    payment_intent_id: Option<&str>,
    dispute_status: Option<&str>,
    validator_address: &[u8; 20],
    registry: &Arc<Erc8004ReputationRegistry>,
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

    // 3. Resolve the machine DID to its allocated ERC-8004 `agentId`
    //    via the on-chain mirror, then encode it as the 32-byte BE
    //    `uint256` subject word the reputation registry uses for keying.
    //    No fallback: if the DID has not been mirrored, we error out.
    //    The rating is the unsigned 0..=100 score cast to i8 (always
    //    safe; SPT outcomes never produce negative ratings). The
    //    context_uri captures the Stripe-side trigger for audit linking.
    let agent_id = agent_registry.lookup_agent_id_by_did(machine_did).ok_or_else(|| {
        NodeError::Other(format!(
            "ERC-8004 reputation dispatcher: machine DID {} has no allocated \
             agentId on the on-chain mirror — register the machine identity \
             before submitting settlement outcomes",
            machine_did
        ))
    })?;
    let subject = agent_id_to_subject_word(agent_id);
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

    // `feedback_id` is overwritten inside `Erc8004ReputationRegistry::submit`
    // (derived from subject + index + context_uri). `revoked` and `response_uri`
    // start empty; they're toggled by later revokeFeedback / appendResponse calls.
    let entry = Erc8004FeedbackEntry {
        subject,
        rater: *validator_address,
        rating,
        context_uri: context_uri.clone(),
        feedback_id: [0u8; 32],
        revoked: false,
        response_uri: String::new(),
    };

    // 4. Append-only write. The registry never rejects a submit (no
    //    duplicate detection — multiple webhook deliveries of the same
    //    event each become a separate row, mirroring at-least-once
    //    delivery semantics).
    registry.submit(entry);

    let agent_id_hex = hex::encode(subject);

    info!(
        machine_did = %machine_did,
        granted_token_id = %granted_token_id,
        outcome = %outcome.as_str(),
        agent_id = %agent_id_hex,
        rating,
        "Stripe SPT settlement outcome → ERC-8004 ReputationRegistry cross-write"
    );

    Ok(SptReputationOutcome {
        machine_did: machine_did.to_string(),
        granted_token_id: granted_token_id.to_string(),
        outcome,
        agent_id_hex,
        rating,
        written: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use dashmap::DashMap;
    use tenzro_identity::erc8004::EthAddress;
    use tenzro_identity::error::Result as IdentityResult;

    /// In-test stub of [`OnChainAgentRegistry`] backed by a `DashMap`.
    /// Mirrors the production native mirror's idempotent-on-DID
    /// semantics: `mirror_register_agent` returns the existing id if the
    /// DID has been registered before, otherwise allocates the next
    /// sequential `u64`. `lookup_agent_id_by_did` returns `None` for
    /// unknown DIDs so we exercise the dispatcher's
    /// `Err`-on-unknown-DID path.
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

        /// Convenience for tests: register `did` and return its allocated
        /// id without going through `mirror_register_agent`'s address /
        /// metadata fields (which the dispatcher tests don't exercise).
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
        ) -> IdentityResult<u64> {
            Ok(self.allocate(did))
        }

        fn lookup_agent_id_by_did(&self, did: &str) -> Option<u64> {
            self.ids.get(did).map(|v| *v)
        }
    }

    fn test_validator_address() -> [u8; 20] {
        [0x11; 20]
    }

    #[test]
    fn rejects_lifecycle_events() {
        let registry = Arc::new(Erc8004ReputationRegistry::new());
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let validator = test_validator_address();
        let machine_did = "did:tenzro:machine:test:abc";

        // Pre-register so the dispatcher's DID-resolution check passes
        // and we're actually testing the lifecycle-event rejection
        // branch, not the unknown-DID branch.
        let agent_id =
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
                &validator,
                &registry,
                &mirror,
            );
            assert!(
                res.is_err(),
                "lifecycle event {:?} must be rejected",
                event
            );
        }

        assert_eq!(
            registry.count(&agent_id_to_subject_word(agent_id)),
            0,
            "no rows should have been written on rejected events"
        );
    }

    #[test]
    fn rejects_unknown_machine_did() {
        // No-fallback discipline: an SPT outcome targeting a DID that
        // has never been mirrored on-chain is a configuration bug at the
        // caller, not a silent data drop.
        let registry = Arc::new(Erc8004ReputationRegistry::new());
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let validator = test_validator_address();

        let res = dispatch_settlement_outcome(
            &SptWebhookEvent::PaymentIntentSucceeded,
            "did:tenzro:machine:test:never-registered",
            "spt_grant_x",
            None,
            None,
            &validator,
            &registry,
            &mirror,
        );
        assert!(res.is_err(), "unknown DID must be rejected, not silently mapped");
    }

    #[test]
    fn writes_feedback_for_unambiguous_outcomes() {
        let registry = Arc::new(Erc8004ReputationRegistry::new());
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let validator = test_validator_address();
        let machine_did = "did:tenzro:machine:test:succeed";
        let agent_id =
            mirror.mirror_register_agent(machine_did, &[0u8; 20], "ipfs://meta").unwrap();
        let subject = agent_id_to_subject_word(agent_id);

        let outcome = dispatch_settlement_outcome(
            &SptWebhookEvent::PaymentIntentSucceeded,
            machine_did,
            "spt_grant_x",
            Some("pi_123"),
            None,
            &validator,
            &registry,
            &mirror,
        )
        .expect("succeeded event must produce a feedback row");

        assert_eq!(outcome.outcome, SptOutcome::Succeeded);
        assert_eq!(outcome.rating, 100);
        assert!(outcome.written);
        assert_eq!(outcome.agent_id_hex, hex::encode(subject));

        assert_eq!(registry.count(&subject), 1);
        let row = registry.get_at(&subject, 0).expect("row must exist");
        assert_eq!(row.subject, subject);
        assert_eq!(row.rater, validator);
        assert_eq!(row.rating, 100);
        assert!(row.context_uri.contains("granted_token_id=spt_grant_x"));
        assert!(row.context_uri.contains("payment_intent_id=pi_123"));
        assert!(row.context_uri.starts_with("stripe_spt:succeeded"));
    }

    #[test]
    fn dispute_closed_requires_status() {
        let registry = Arc::new(Erc8004ReputationRegistry::new());
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let validator = test_validator_address();
        let machine_did = "did:tenzro:machine:test:dispute";
        mirror.mirror_register_agent(machine_did, &[0u8; 20], "ipfs://meta").unwrap();

        // No dispute_status → reject.
        let res = dispatch_settlement_outcome(
            &SptWebhookEvent::ChargeDisputeClosed,
            machine_did,
            "spt_grant_d",
            None,
            None,
            &validator,
            &registry,
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
            &validator,
            &registry,
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
            &validator,
            &registry,
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
            &validator,
            &registry,
            &mirror,
        );
        assert!(bogus.is_err(), "unknown dispute_status must be rejected");
    }

    #[test]
    fn payment_failed_writes_zero_rating() {
        let registry = Arc::new(Erc8004ReputationRegistry::new());
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let validator = test_validator_address();
        let machine_did = "did:tenzro:machine:test:fail";
        let agent_id =
            mirror.mirror_register_agent(machine_did, &[0u8; 20], "ipfs://meta").unwrap();
        let subject = agent_id_to_subject_word(agent_id);

        let outcome = dispatch_settlement_outcome(
            &SptWebhookEvent::PaymentIntentFailed,
            machine_did,
            "spt_grant_f",
            None,
            None,
            &validator,
            &registry,
            &mirror,
        )
        .expect("payment_failed event must produce a feedback row");

        assert_eq!(outcome.outcome, SptOutcome::ChargebackLost);
        assert_eq!(outcome.rating, 0);
        assert_eq!(registry.count(&subject), 1);
    }

    #[test]
    fn dispute_created_writes_disputed_rating() {
        let registry = Arc::new(Erc8004ReputationRegistry::new());
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let validator = test_validator_address();
        let machine_did = "did:tenzro:machine:test:disputed";
        let agent_id =
            mirror.mirror_register_agent(machine_did, &[0u8; 20], "ipfs://meta").unwrap();
        let subject = agent_id_to_subject_word(agent_id);

        let outcome = dispatch_settlement_outcome(
            &SptWebhookEvent::ChargeDisputeCreated,
            machine_did,
            "spt_grant_dc",
            None,
            None,
            &validator,
            &registry,
            &mirror,
        )
        .expect("dispute.created event must produce a feedback row");

        assert_eq!(outcome.outcome, SptOutcome::Disputed);
        assert_eq!(outcome.rating, 50);
        assert_eq!(registry.count(&subject), 1);
    }

    #[test]
    fn append_only_multiple_rows_per_agent() {
        let registry = Arc::new(Erc8004ReputationRegistry::new());
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let validator = test_validator_address();
        let machine_did = "did:tenzro:machine:test:multi";
        let agent_id =
            mirror.mirror_register_agent(machine_did, &[0u8; 20], "ipfs://meta").unwrap();
        let subject = agent_id_to_subject_word(agent_id);

        // Three separate webhook events for the same agent → three rows.
        for event in [
            SptWebhookEvent::PaymentIntentSucceeded,
            SptWebhookEvent::ChargeDisputeCreated,
            SptWebhookEvent::PaymentIntentSucceeded,
        ] {
            dispatch_settlement_outcome(
                &event,
                machine_did,
                "spt_grant_multi",
                None,
                None,
                &validator,
                &registry,
                &mirror,
            )
            .expect("each settlement-outcome event must append");
        }

        assert_eq!(
            registry.count(&subject),
            3,
            "registry must be append-only — three webhook events → three rows"
        );
    }

    #[test]
    fn agent_id_subject_word_is_big_endian() {
        // Sanity: the dispatcher's local encoder must agree with
        // tenzro_identity::erc8004::agent_id_to_uint256_be byte for
        // byte. If this test ever drifts, the on-chain reputation
        // registry will key under one word while the production mirror
        // emits another and reads will silently miss.
        for id in [1u64, 7, 0xdeadbeef, u64::MAX] {
            assert_eq!(
                agent_id_to_subject_word(id),
                tenzro_identity::erc8004::agent_id_to_uint256_be(id),
                "subject word divergence for agent_id={id}"
            );
        }
    }
}
