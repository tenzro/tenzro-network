//! Bridges a Stripe SPT `granted_token.deactivated` webhook event to a TDIP
//! identity revocation, cascaded across the mesh via the validator's
//! [`HybridSigner`] and the configured [`RevocationBroadcaster`].
//!
//! # Why a separate module
//!
//! `tenzro-payments` owns the wire types ([`SptWebhookEvent`],
//! [`SharedPaymentGrantedToken`]) and `tenzro-identity` owns the local
//! [`IdentityRegistry::revoke`] entry point. This adapter, owned by
//! `tenzro-node`, is the only place that pulls both crates together — same
//! split as [`crate::spending_policy_bridge`] and
//! [`crate::spt_ceiling_bridge`].
//!
//! # Authority model
//!
//! Stripe-sourced revocation is *not* a peer-mesh broadcast — there is no
//! [`SignedRevocationEntry`] coming in over `tenzro/identity_revocations`.
//! Instead, this node is the local authority that takes the Stripe signal,
//! calls [`IdentityRegistry::revoke`] (which produces a fresh
//! `SignedRevocationEntry` signed by the validator's hybrid keys), and then
//! the broadcaster fans it out to peers. Peers receive it as an inbound
//! signed revocation and apply it via [`apply_remote_revocation`], same as
//! any other mesh-sourced revocation.
//!
//! # Cache invalidation
//!
//! On a successful revoke we also invalidate the [`SptCeilingResolver`]
//! cache via [`SptCeilingResolverAdapter::invalidate`] so subsequent gate
//! checks see the credential as missing rather than stale-active.

use std::sync::Arc;

use tracing::{info, warn};

use tenzro_crypto::composite::HybridSigner;
use tenzro_identity::IdentityRegistry;
use tenzro_payments::mpp::stripe_spt::SptWebhookEvent;

use crate::error::{NodeError, Result};
use crate::spt_ceiling_bridge::SptCeilingResolverAdapter;

/// Outcome of a single dispatched revocation. Returned to the RPC caller so
/// operators can audit which DIDs were affected.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SptRevocationOutcome {
    /// The TDIP machine DID that was revoked.
    pub machine_did: String,
    /// Stripe granted-token ID whose deactivation triggered the revoke.
    pub granted_token_id: String,
    /// Original Stripe event type, copied verbatim into the revocation
    /// reason and the on-chain audit trail.
    pub event_type: String,
    /// Always `true` if this struct is returned (the dispatcher errors
    /// otherwise). Present so JSON consumers don't have to special-case
    /// "missing means failure."
    pub revoked: bool,
}

/// Dispatches a parsed [`SptWebhookEvent`] to the local TDIP revocation
/// path.
///
/// This function is the single point of contact between the Stripe SPT
/// surface and the TDIP cascade. It enforces:
///
/// 1. Only [`SptWebhookEvent::GrantedTokenDeactivated`] triggers a
///    revocation. Lifecycle events (`created`/`activated`/`used`) are
///    informational and produce a `revoked = false` early return only when
///    the caller passes them through — currently this dispatcher rejects
///    non-deactivation events outright so an operator cannot accidentally
///    revoke an identity on a benign lifecycle signal.
/// 2. The `machine_did` MUST resolve in the local [`IdentityRegistry`] —
///    the bookkeeping is the caller's responsibility (the SPT-to-DID
///    binding lives in the SPT issuance flow, not here).
/// 3. The validator's [`HybridSigner`] is required; if it's `None`
///    (non-validator role) the dispatch fails with a clear error.
///
/// `revoker_did` is the DID recorded as the *authority* of the revoke —
/// typically `"did:tenzro:protocol/spt-webhook"` or the operator's DID.
pub fn dispatch_granted_token_deactivated(
    event: &SptWebhookEvent,
    machine_did: &str,
    granted_token_id: &str,
    revoker_did: &str,
    identity_registry: &Arc<IdentityRegistry>,
    hybrid_signer: &Arc<dyn HybridSigner>,
    spt_cache: Option<&Arc<SptCeilingResolverAdapter>>,
) -> Result<SptRevocationOutcome> {
    // 1. Guard against accidental dispatch on non-terminal events.
    if !matches!(event, SptWebhookEvent::GrantedTokenDeactivated) {
        return Err(NodeError::Other(format!(
            "SPT revocation dispatcher only accepts granted_token.deactivated events, \
             got {:?}",
            event
        )));
    }

    // 2. Build a reason string that captures the Stripe-side trigger so
    //    the on-chain audit trail tells the full story.
    let reason = format!(
        "stripe_spt:granted_token_deactivated granted_token_id={}",
        granted_token_id
    );
    let event_type = "shared_payment.granted_token.deactivated".to_string();

    // 3. Local revoke + signed broadcast.
    identity_registry
        .revoke(
            machine_did,
            reason.clone(),
            revoker_did.to_string(),
            hybrid_signer.as_ref(),
        )
        .map_err(|e| {
            NodeError::Other(format!(
                "IdentityRegistry::revoke failed for {}: {}",
                machine_did, e
            ))
        })?;

    info!(
        machine_did = %machine_did,
        granted_token_id = %granted_token_id,
        revoker_did = %revoker_did,
        "Stripe SPT granted_token.deactivated → TDIP revocation cascaded"
    );

    // 4. Drop the cached SPT snapshot so a racing payment-gate check does
    //    not see the credential as still-active. Best-effort: a missing
    //    cache adapter is not a fatal condition (the ceiling resolver
    //    falls back to Ok(None) anyway).
    if let Some(cache) = spt_cache {
        cache.invalidate(granted_token_id);
    } else {
        warn!(
            granted_token_id = %granted_token_id,
            "No SPT cache adapter wired — skipping invalidate; gate checks may \
             see a stale-active snapshot until the next refresh"
        );
    }

    Ok(SptRevocationOutcome {
        machine_did: machine_did.to_string(),
        granted_token_id: granted_token_id.to_string(),
        event_type,
        revoked: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_deactivation_event() {
        // We can't easily construct a real IdentityRegistry / HybridSigner
        // here without dragging in the full crypto stack, so this test
        // only exercises the early-return branch which fires before any
        // registry access.
        //
        // The pattern is the same as `spt_ceiling_bridge::tests` — narrow
        // unit coverage with full integration coverage living in
        // `crates/tenzro-node/tests/`.
        let event = SptWebhookEvent::IssuedTokenActivated;
        let machine_did = "did:tenzro:machine:test:abc";
        let granted_token_id = "spt_grant_test";

        // Build placeholder Arcs that we will never deref because the
        // event-kind guard fires first. The error path does not touch
        // them.
        let registry: Arc<IdentityRegistry> = Arc::new(IdentityRegistry::new());
        // Build a real (test-only) hybrid signer so the type system is
        // satisfied. We never call sign() — the kind-guard returns first.
        let classical = tenzro_crypto::signatures::Ed25519SignerImpl::generate().unwrap();
        let pq = tenzro_crypto::pq::MlDsaSigningKey::generate();
        let signer: Arc<dyn HybridSigner> = Arc::new(
            tenzro_crypto::composite::InMemoryHybridSigner::new(Box::new(classical), pq),
        );

        let res = dispatch_granted_token_deactivated(
            &event,
            machine_did,
            granted_token_id,
            "did:tenzro:protocol/spt-webhook",
            &registry,
            &signer,
            None,
        );
        assert!(res.is_err(), "non-deactivation events must be rejected");
    }
}
