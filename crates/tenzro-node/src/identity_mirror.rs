//! Mirror of consensus identity decisions into the node's read model.
//!
//! Every node re-executes the same ordered transactions, so the
//! `IdentityRegister` and `IdentityRevoked` logs a block emits are decisions
//! consensus has already made: a registration landed, or an identity was
//! revoked by its root or by a carried governance proposal. This applies them
//! to the local [`IdentityRegistry`] the resolve path reads, and for a
//! revocation drops the access tokens this node issued to or through the
//! revoked identity, so every node stops honouring them once consensus has
//! decided. Nothing here verifies or gossips: there is no author to distrust
//! and no peer to tell.
//!
//! Errors are logged and never abort the block: a divergent read model is
//! recoverable on restart via `load_from_storage`.

use tenzro_auth::AuthEngine;
use tenzro_identity::IdentityRegistry;
use tracing::{debug, info, warn};

/// What mirroring one transaction's identity logs changed on this node.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MirrorOutcome {
    /// The DIDs consensus revoked, in log order.
    pub revoked: Vec<String>,
    /// Access tokens this node revoked because of them.
    pub tokens_revoked: usize,
}

/// Apply the identity logs of one executed transaction to `registry`, and
/// for each revoked identity revoke the tokens `auth` issued: every token
/// whose act-chain names the DID, and every token it holds as bearer.
pub fn mirror_identity_logs(
    registry: &IdentityRegistry,
    auth: Option<&AuthEngine>,
    logs: &[tenzro_vm::Log],
) -> MirrorOutcome {
    let mut outcome = MirrorOutcome::default();
    for log in logs {
        let Some(topic) = log.topics.first().map(|t| t.as_slice()) else {
            continue;
        };
        match topic {
            b"IdentityRegister" => {
                match serde_json::from_slice::<tenzro_types::identity::RegisterIdentityPayload>(
                    &log.data,
                ) {
                    Ok(payload) => {
                        let did = payload.did.clone();
                        match registry.upsert_from_chain(&payload) {
                            Ok(true) => {
                                info!(%did, "Mirrored replicated identity from consensus")
                            }
                            Ok(false) => {
                                debug!(%did, "Identity already known locally; mirror is a no-op")
                            }
                            Err(e) => warn!(%did, "Failed to mirror replicated identity: {e}"),
                        }
                    }
                    Err(e) => warn!(
                        data_len = log.data.len(),
                        "Malformed IdentityRegister log payload, skipping: {e}"
                    ),
                }
            }
            // A TPM attestation consensus attached to a machine root: the
            // metadata it wrote to the chain record, mirrored onto the local
            // one.
            t if t
                == tenzro_vm::native::machine_attestation::MACHINE_ATTESTATION_ATTACHED_TOPIC =>
            {
                #[derive(serde::Deserialize)]
                struct Attached {
                    did: String,
                    metadata: std::collections::BTreeMap<String, String>,
                }
                match serde_json::from_slice::<Attached>(&log.data) {
                    Ok(a) => match registry.set_identity_metadata(&a.did, a.metadata) {
                        Ok(()) => info!(did = %a.did, "Mirrored attached TPM attestation"),
                        Err(e) => warn!(
                            did = %a.did,
                            "Consensus attached a TPM attestation to an identity this node does not hold: {e}"
                        ),
                    },
                    Err(e) => warn!(
                        data_len = log.data.len(),
                        "Malformed attestation attach log payload, skipping: {e}"
                    ),
                }
            }
            // A revocation approved by the identity's root, or a carried
            // governance proposal. Every node re-executed the same
            // transaction and wrote the same marker, so this is consensus
            // telling the read model what it already decided.
            b"IdentityRevoked" => {
                match serde_json::from_slice::<tenzro_types::identity::IdentityRevokedLog>(
                    &log.data,
                ) {
                    Ok(record) => {
                        let did = record.did.clone();
                        outcome.tokens_revoked += revoke_tokens(auth, &did, &record.reason);
                        crate::agent_delegation::forget_delivered_tokens(&did);
                        outcome.revoked.push(did.clone());
                        match registry.revoke_from_chain(
                            &record.did,
                            record.reason.clone(),
                            record.revoked_by.clone(),
                        ) {
                            Ok(true) => info!(
                                %did,
                                revoked_by = %record.revoked_by,
                                proposal = ?record.proposal_id,
                                reason = %record.reason,
                                "Identity revoked by consensus"
                            ),
                            Ok(false) => {
                                debug!(%did, "Identity already revoked locally; mirror is a no-op")
                            }
                            // A divergence worth seeing: consensus revoked
                            // something this node never mirrored. It does
                            // not abort the block — `load_from_storage`
                            // reconciles on restart — but it is an error,
                            // not a debug line.
                            Err(e) => warn!(
                                %did,
                                "Consensus revoked an identity this node does not hold: {e}"
                            ),
                        }
                    }
                    Err(e) => warn!(
                        data_len = log.data.len(),
                        "Malformed IdentityRevoked log payload, skipping: {e}"
                    ),
                }
            }
            _ => continue,
        }
    }
    outcome
}

/// Revoke the tokens `auth` issued that `did` roots or bears. Tokens are
/// this node's own records, so they are revoked even when the registry does
/// not hold the identity.
fn revoke_tokens(auth: Option<&AuthEngine>, did: &str, reason: &str) -> usize {
    let Some(engine) = auth else {
        return 0;
    };
    let rooted = engine.revoke_did(did, reason).unwrap_or_else(|e| {
        warn!(%did, "Revoking the act-chain tokens of a revoked identity failed: {e}");
        0
    });
    let now = chrono::Utc::now().timestamp() as u64;
    let borne = engine
        .live_tokens(now)
        .map(|live| {
            live.into_iter()
                .filter(|t| t.bearer_did == did)
                .filter(|t| engine.revoke_token(&t.jti, reason).is_ok())
                .count()
        })
        .unwrap_or(0);
    rooted + borne
}
