//! Bridges a Visa TAP `agent-payer-auth` verification outcome to an
//! ERC-8004 `ReputationRegistry::submitFeedback` row, written through a
//! standard EIP-1559 transaction against the canonical
//! `ReputationRegistry` proxy at
//! [`tenzro_identity::erc8004::addresses::REPUTATION_REGISTRY`].
//!
//! Design follows the SPT dispatcher one-for-one (see
//! [`crate::erc8004_reputation_dispatcher`] — same architecture decision
//! locked 2026-05-29):
//!
//! - **Feedback rows flow through the canonical proxy** via standard EVM
//!   transactions, with `msg.sender` = the node's `erc8004-system` key
//!   address.
//! - **Detached spawn.** The TAP success path is sync from the caller's
//!   perspective; we build calldata in-line, `tokio::spawn` the signed-tx
//!   submission via [`EvmTransactionSigner`], and return
//!   [`TapReputationOutcome`] immediately.
//! - **System key signs.** The validator's `erc8004-system` secp256k1 key
//!   is the on-chain `rater`. Operators see "this row was authored by
//!   validator X (acting on a verified Visa TAP signature)" — not by a
//!   peer agent.
//!
//! # Why a separate module from the SPT dispatcher
//!
//! Both dispatchers eventually call `submitFeedback`, but they consume
//! different upstream wire shapes:
//!
//! - SPT: [`SptWebhookEvent`] (multi-event family, ambiguous
//!   `dispute.closed`, lifecycle vs settlement split).
//! - TAP: [`VerificationResult`] (single-shot synchronous verifier
//!   outcome, tag-discriminated, no dispute lifecycle on the wire).
//!
//! Folding both into a shared `dispatch_feedback(rating, context_uri,
//! ...)` helper would hide the per-rail caller-side guards (lifecycle
//! rejection for SPT, `verified == false || verified_tag != PayerAuth`
//! rejection for TAP) and make the call sites less self-documenting. The
//! two share the address constant, the calldata encoder, and the
//! detached-spawn pattern — that level of overlap is fine.
//!
//! # What TAP outcomes mean
//!
//! Unlike SPT, Visa TAP does not emit asynchronous dispute or chargeback
//! events on the wire. The verifier-success path emits one of two
//! outcomes per checkout:
//!
//! - [`TapOutcome::Succeeded`] — the TAP signature verified at the CDN
//!   proxy AND the downstream merchant settlement landed. Rating 100.
//! - [`TapOutcome::SettlementFailed`] — TAP signature verified but the
//!   downstream settlement attempt failed (declined card, network error,
//!   etc.). Rating 0.
//!
//! Disputes and chargebacks for TAP-mediated payments flow through the
//! card network's existing dispute machinery and surface separately —
//! the TAP dispatcher is not the right seam for those. SPT, by contrast,
//! has Stripe-issued dispute lifecycle webhooks and so models the full
//! 4-outcome reputation space.
//!
//! # PayerAuth gate
//!
//! Reputation rows are only emitted for [`AgentTag::PayerAuth`]
//! verifications. `BrowserAuth` is the browse-tier tag (no settlement
//! intent), so writing a reputation row for it would conflate "this
//! agent successfully proved its identity" with "this agent successfully
//! completed a payment" — distinct signals that registry consumers
//! deserve to keep separate. The dispatcher rejects non-PayerAuth
//! results with a clear diagnostic rather than silently dropping them.
//!
//! # Unknown DIDs are rejected, not dropped
//!
//! Same no-fallback discipline as the SPT dispatcher: a TAP outcome
//! targeting an agent_did that has never been mirrored on-chain (no
//! allocated `agentId`) returns an error rather than fabricating a
//! synthetic subject key. The caller is expected to retry with backoff
//! in the latency window between `mirror_register_agent` and the
//! `Registered` event indexing.

use std::sync::Arc;

use tracing::info;

use tenzro_bridge::evm_signer::EvmTransactionSigner;
use tenzro_identity::erc8004::{abi, addresses, selectors, OnChainAgentRegistry};
use tenzro_payments::visa_tap::{AgentTag, VerificationResult};

use crate::error::{NodeError, Result};

/// Format the canonical `REPUTATION_REGISTRY` address as a `0x`-prefixed
/// hex string (the shape [`EvmTransactionSigner::send_transaction`]
/// expects for `to`). Mirrors the helper in
/// [`crate::erc8004_reputation_dispatcher`].
fn reputation_registry_hex() -> String {
    let mut s = String::with_capacity(2 + 40);
    s.push_str("0x");
    s.push_str(&hex::encode(addresses::REPUTATION_REGISTRY));
    s
}

/// Outcome of a Visa TAP-mediated payment, as seen by the merchant /
/// settlement seam that calls this dispatcher.
///
/// Unlike [`tenzro_payments::mpp::stripe_spt::SptOutcome`], TAP does not
/// surface dispute/chargeback lifecycle on the wire — those flow
/// through the card network's existing dispute machinery and would
/// arrive via a separate Stripe-style webhook stream if a TAP-mediated
/// charge were later disputed. For the TAP success path this two-state
/// enum captures everything the verifier knows at the point of
/// settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TapOutcome {
    /// TAP signature verified AND downstream settlement landed.
    Succeeded,
    /// TAP signature verified but downstream settlement failed (declined
    /// card, network error, merchant-side reject, etc.).
    SettlementFailed,
}

impl TapOutcome {
    /// Static label used in reputation feedback rows.
    pub fn as_str(&self) -> &'static str {
        match self {
            TapOutcome::Succeeded => "succeeded",
            TapOutcome::SettlementFailed => "settlement_failed",
        }
    }

    /// ERC-8004 feedback score on a 0..=100 scale. Mirrors the
    /// convention used by SPT: success → 100, settlement failure → 0.
    /// No mid-scale rating — TAP has no dispute/chargeback lifecycle on
    /// the wire, so the binary outcome is exact.
    pub fn reputation_score(&self) -> u8 {
        match self {
            TapOutcome::Succeeded => 100,
            TapOutcome::SettlementFailed => 0,
        }
    }
}

/// Outcome of a single dispatched cross-write. Returned to the RPC
/// caller so operators can audit which agents had reputation rows
/// appended.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TapReputationOutcome {
    /// The TDIP machine DID whose `agentId` was the feedback subject —
    /// extracted from [`VerificationResult::agent_did`].
    pub machine_did: String,
    /// Visa TAP `keyid` whose signature triggered the cross-write —
    /// extracted from [`VerificationResult::agent_key_id`]. Recorded in
    /// the `contextUri` for audit linking.
    pub agent_key_id: String,
    /// The settlement outcome the merchant/settler observed downstream
    /// of the TAP verification.
    pub outcome: TapOutcome,
    /// ERC-8004 `agentId` (decimal `u64`) used as the `submitFeedback`
    /// subject. Matches the value `getFeedback` would key off.
    pub agent_id: u64,
    /// Rating written into the feedback row. 0..=100 scale.
    pub rating: i8,
    /// Always `true` if this struct is returned — the dispatcher errors
    /// on the unhappy paths. Same semantics as
    /// [`crate::erc8004_reputation_dispatcher::SptReputationOutcome::written`]:
    /// the tx was *accepted* for submission (calldata built, spawn
    /// enqueued); inclusion / revert state must be looked up via
    /// `eth_getTransactionReceipt` against the tx hash logged at info
    /// level by the spawned task.
    pub written: bool,
}

/// Maps a TAP verification result + downstream settlement outcome to
/// one `submitFeedback` transaction against the canonical ERC-8004
/// `ReputationRegistry` proxy.
///
/// `result` must be a successful PayerAuth verification — i.e.
/// `result.verified == true && result.verified_tag == Some(AgentTag::PayerAuth)
/// && result.agent_did.is_some()`. Any other shape is rejected with a
/// clear diagnostic:
///
/// - `verified == false` → caller should not have invoked the
///   dispatcher; rejecting forces the bug to surface at the call site.
/// - `verified_tag != Some(PayerAuth)` → browse-tier tag, no settlement
///   semantics; reputation row would conflate identity proof with
///   payment outcome.
/// - `agent_did.is_none()` → the TAP signature did not resolve to a
///   TDIP machine DID, so we have no key under which to file the
///   feedback row.
///
/// `outcome` is the downstream settlement outcome — the merchant /
/// settler tells us whether the card actually moved value after the
/// TAP signature verified. See [`TapOutcome`].
///
/// `merchant_id` is recorded in the `contextUri` for audit linking
/// back to the merchant the agent was paying. Pass `None` if the
/// dispatcher is being driven from a generic settlement-outcome RPC
/// where the merchant identifier is not yet known.
///
/// `agent_registry` is the [`OnChainAgentRegistry`] mirror used to
/// resolve the `agent_did` to its allocated `agentId` via the
/// off-chain DID index. The dispatcher errors if the DID has no
/// allocated id — no fallback.
///
/// `signer` is the node-held `erc8004-system` [`EvmTransactionSigner`].
/// `msg.sender` on the resulting `submitFeedback` call is the signer's
/// address — operators reading the on-chain registry see that the row
/// was authored by validator X acting on the upstream TAP signal.
pub fn dispatch_payer_auth_outcome(
    result: &VerificationResult,
    outcome: TapOutcome,
    merchant_id: Option<&str>,
    signer: &Arc<EvmTransactionSigner>,
    agent_registry: &Arc<dyn OnChainAgentRegistry>,
) -> Result<TapReputationOutcome> {
    // 1. Verification must have succeeded. Dispatching on a failed
    //    verification is a caller bug.
    if !result.verified {
        return Err(NodeError::Other(
            "TAP reputation dispatcher: VerificationResult.verified == false; \
             only successful verifications produce reputation rows"
                .to_string(),
        ));
    }

    // 2. Tag must be PayerAuth. BrowserAuth verifications are identity
    //    proofs, not payment intents — they don't produce reputation
    //    rows. Untagged verifications are rejected to prevent silent
    //    drops (a strict verifier would refuse the request earlier,
    //    but the dispatcher guards in-depth).
    match result.verified_tag {
        Some(AgentTag::PayerAuth) => {}
        Some(AgentTag::BrowserAuth) => {
            return Err(NodeError::Other(
                "TAP reputation dispatcher: verified_tag == BrowserAuth; \
                 only PayerAuth verifications produce reputation rows \
                 (BrowserAuth is identity-only, not a settlement intent)"
                    .to_string(),
            ));
        }
        None => {
            return Err(NodeError::Other(
                "TAP reputation dispatcher: verified_tag is None; \
                 reputation rows require an explicit PayerAuth tag so \
                 registry consumers can distinguish payment outcomes \
                 from identity proofs"
                    .to_string(),
            ));
        }
    }

    // 3. agent_did must be present. TAP keys that don't resolve to a
    //    TDIP DID can't be filed under a registry subject.
    let machine_did = result.agent_did.as_deref().ok_or_else(|| {
        NodeError::Other(
            "TAP reputation dispatcher: VerificationResult.agent_did is None; \
             cannot file a reputation row without a DID-resolvable subject"
                .to_string(),
        )
    })?;

    // 4. Resolve the machine DID to its allocated ERC-8004 `agentId`
    //    via the off-chain DID index. No fallback.
    let agent_id = agent_registry.lookup_agent_id_by_did(machine_did).ok_or_else(|| {
        NodeError::Other(format!(
            "TAP reputation dispatcher: machine DID {} has no allocated \
             agentId on the on-chain mirror — register the machine identity \
             and wait for the Registered event before submitting TAP outcomes",
            machine_did
        ))
    })?;

    let rating = outcome.reputation_score() as i8;
    let context_uri = match merchant_id {
        Some(m) => format!(
            "visa_tap:{} keyid={} merchant_id={}",
            outcome.as_str(),
            result.agent_key_id,
            m
        ),
        None => format!(
            "visa_tap:{} keyid={}",
            outcome.as_str(),
            result.agent_key_id
        ),
    };

    // 5. Build calldata synchronously.
    let calldata = abi::encode_submit_feedback(
        selectors::SUBMIT_FEEDBACK,
        agent_id,
        rating,
        &context_uri,
    );

    // 6. Detached signed-tx submission.
    let signer = Arc::clone(signer);
    let to = reputation_registry_hex();
    let did_owned = machine_did.to_string();
    let key_id_owned = result.agent_key_id.clone();
    let outcome_str = outcome.as_str().to_string();

    tokio::spawn(async move {
        match signer.send_transaction(&to, &calldata, 0).await {
            Ok(tx_hash) => {
                tracing::info!(
                    target: "tenzro::erc8004::reputation",
                    machine_did = %did_owned,
                    agent_key_id = %key_id_owned,
                    agent_id = agent_id,
                    rating = rating,
                    outcome = %outcome_str,
                    tx_hash = %tx_hash,
                    "ERC-8004 submitFeedback tx submitted (Visa TAP source)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    target: "tenzro::erc8004::reputation",
                    machine_did = %did_owned,
                    agent_key_id = %key_id_owned,
                    agent_id = agent_id,
                    error = %e,
                    "ERC-8004 submitFeedback tx submission failed (TAP source; caller-visible result unaffected)"
                );
            }
        }
    });

    info!(
        machine_did = %machine_did,
        agent_key_id = %result.agent_key_id,
        outcome = %outcome.as_str(),
        agent_id = agent_id,
        rating,
        "Visa TAP PayerAuth outcome → ERC-8004 ReputationRegistry submit (tx spawned)"
    );

    Ok(TapReputationOutcome {
        machine_did: machine_did.to_string(),
        agent_key_id: result.agent_key_id.clone(),
        outcome,
        agent_id,
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

    /// In-test stub of [`OnChainAgentRegistry`] — same shape as the one
    /// in [`crate::erc8004_reputation_dispatcher`] tests. Tests pre-
    /// populate the index via [`StubMirror::allocate`] to simulate the
    /// post-event state where a `Registered(agentId, ...)` event has
    /// been observed and indexed.
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

    fn test_signer() -> Arc<EvmTransactionSigner> {
        Arc::new(
            EvmTransactionSigner::new(&[1u8; 32], 1337, "http://127.0.0.1:1".to_string())
                .expect("dev signer"),
        )
    }

    fn ok_payer_auth_result(did: &str, key_id: &str) -> VerificationResult {
        VerificationResult {
            verified: true,
            agent_key_id: key_id.to_string(),
            agent_did: Some(did.to_string()),
            verified_tag: Some(AgentTag::PayerAuth),
            stages_passed: vec!["all".to_string()],
        }
    }

    #[tokio::test]
    async fn rejects_unverified_result() {
        let signer = test_signer();
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let did = "did:tenzro:machine:test:unverified";
        mirror.mirror_register_agent(did, &[0u8; 20], "ipfs://meta").unwrap();

        let mut bad = ok_payer_auth_result(did, "key-1");
        bad.verified = false;

        let res = dispatch_payer_auth_outcome(
            &bad,
            TapOutcome::Succeeded,
            None,
            &signer,
            &mirror,
        );
        assert!(res.is_err(), "verified=false must be rejected");
    }

    #[tokio::test]
    async fn rejects_browser_auth_tag() {
        let signer = test_signer();
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let did = "did:tenzro:machine:test:browse";
        mirror.mirror_register_agent(did, &[0u8; 20], "ipfs://meta").unwrap();

        let mut browse = ok_payer_auth_result(did, "key-1");
        browse.verified_tag = Some(AgentTag::BrowserAuth);

        let res = dispatch_payer_auth_outcome(
            &browse,
            TapOutcome::Succeeded,
            None,
            &signer,
            &mirror,
        );
        assert!(res.is_err(), "BrowserAuth tag must be rejected — identity-only, no payment semantics");
    }

    #[tokio::test]
    async fn rejects_missing_tag() {
        let signer = test_signer();
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let did = "did:tenzro:machine:test:notag";
        mirror.mirror_register_agent(did, &[0u8; 20], "ipfs://meta").unwrap();

        let mut untagged = ok_payer_auth_result(did, "key-1");
        untagged.verified_tag = None;

        let res = dispatch_payer_auth_outcome(
            &untagged,
            TapOutcome::Succeeded,
            None,
            &signer,
            &mirror,
        );
        assert!(res.is_err(), "missing verified_tag must be rejected");
    }

    #[tokio::test]
    async fn rejects_missing_did() {
        let signer = test_signer();
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();

        let mut no_did = ok_payer_auth_result("did:tenzro:machine:test:placeholder", "key-1");
        no_did.agent_did = None;

        let res = dispatch_payer_auth_outcome(
            &no_did,
            TapOutcome::Succeeded,
            None,
            &signer,
            &mirror,
        );
        assert!(res.is_err(), "missing agent_did must be rejected");
    }

    #[tokio::test]
    async fn rejects_unknown_did() {
        let signer = test_signer();
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();

        let res = dispatch_payer_auth_outcome(
            &ok_payer_auth_result("did:tenzro:machine:test:never-registered", "key-1"),
            TapOutcome::Succeeded,
            None,
            &signer,
            &mirror,
        );
        assert!(res.is_err(), "unknown DID must be rejected, not silently mapped");
    }

    #[tokio::test]
    async fn accepts_succeeded_outcome() {
        let signer = test_signer();
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let did = "did:tenzro:machine:test:succeed";
        mirror.mirror_register_agent(did, &[0u8; 20], "ipfs://meta").unwrap();
        let agent_id = mirror.lookup_agent_id_by_did(did).unwrap();

        let outcome = dispatch_payer_auth_outcome(
            &ok_payer_auth_result(did, "key-good"),
            TapOutcome::Succeeded,
            Some("merchant-abc"),
            &signer,
            &mirror,
        )
        .expect("succeeded outcome must spawn a feedback tx");

        assert_eq!(outcome.outcome, TapOutcome::Succeeded);
        assert_eq!(outcome.rating, 100);
        assert_eq!(outcome.agent_id, agent_id);
        assert_eq!(outcome.agent_key_id, "key-good");
        assert_eq!(outcome.machine_did, did);
        assert!(outcome.written);
    }

    #[tokio::test]
    async fn accepts_settlement_failed_outcome() {
        let signer = test_signer();
        let mirror: Arc<dyn OnChainAgentRegistry> = StubMirror::new();
        let did = "did:tenzro:machine:test:declined";
        mirror.mirror_register_agent(did, &[0u8; 20], "ipfs://meta").unwrap();

        let outcome = dispatch_payer_auth_outcome(
            &ok_payer_auth_result(did, "key-fail"),
            TapOutcome::SettlementFailed,
            None,
            &signer,
            &mirror,
        )
        .expect("settlement_failed outcome must spawn a feedback tx");

        assert_eq!(outcome.outcome, TapOutcome::SettlementFailed);
        assert_eq!(outcome.rating, 0);
        assert!(outcome.written);
    }

    #[test]
    fn outcome_score_ordering() {
        assert!(TapOutcome::Succeeded.reputation_score() > TapOutcome::SettlementFailed.reputation_score());
        assert_eq!(TapOutcome::Succeeded.reputation_score(), 100);
        assert_eq!(TapOutcome::SettlementFailed.reputation_score(), 0);
    }
}
