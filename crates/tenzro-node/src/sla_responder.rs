//! A storage or compute provider's answer to an SLA probe, the same whichever
//! way the probe arrived: on the `tenzro/sla` gossip topic or straight from
//! the validator over the `tenzro/sla` ALPN.

use std::sync::Arc;

use tenzro_identity::IdentityRegistry;
use tracing::{debug, warn};

use crate::node::{MachineOperator, resolve_operator_payee};

/// The most bytes a direct probe request may carry: a probe is a few
/// hundred bytes, and a bound keeps a hostile one from being decoded whole.
const MAX_SLA_REQUEST: usize = 64 * 1024;

/// What answering a probe needs, captured once when the responder starts.
#[derive(Clone)]
pub(crate) struct SlaResponder {
    pub(crate) identity_registry: Option<Arc<IdentityRegistry>>,
    pub(crate) machine_operator: Option<MachineOperator>,
    pub(crate) configured_operator_did: Option<String>,
    #[cfg(feature = "inference")]
    pub(crate) runtime: Option<Arc<tenzro_model::ModelRuntime>>,
    pub(crate) storage_runtime:
        Option<Arc<crate::storage_provider_runtime::StorageProviderRuntime>>,
    pub(crate) state_store: Option<Arc<dyn tenzro_storage::KvStore>>,
    pub(crate) service: Arc<tenzro_crypto::batch::BatchService>,
    /// The probes already answered under a beacon value, shared by every way
    /// a probe arrives.
    pub(crate) taken: Arc<parking_lot::Mutex<crate::sla_attest::TakenProbes>>,
}

/// What a probe earns from this node.
pub(crate) enum Answer {
    /// The signed answer.
    Signed(tenzro_model::SlaResponse),
    /// The probe names a beacon round this chain has not reached: the caller
    /// may hold it and ask again once the chain has.
    AwaitBeacon,
    /// Not answered: the node does not answer for the probe's subject, the
    /// probe does not verify, its beacon is refused or already answered, its
    /// deadline has passed or the answer could not be signed.
    Declined,
}

impl SlaResponder {
    /// This node's answer to `probe`.
    pub(crate) async fn answer(&self, probe: tenzro_model::SlaProbe) -> Answer {
        let identity_registry = &self.identity_registry;
        let machine_operator = &self.machine_operator;
        let configured_operator_did = &self.configured_operator_did;
        #[cfg(feature = "inference")]
        let runtime = &self.runtime;
        let storage_runtime = &self.storage_runtime;
        let state_store = &self.state_store;
        let service = &self.service;
        // The bond or role stake is the authority on which
        // subject this node answers for: its owner is the wallet
        // that funded it, so one funded by another wallet is
        // another operator's to answer.
        let payee = resolve_operator_payee(
            identity_registry.as_ref(),
            machine_operator.as_ref(),
            configured_operator_did.as_deref(),
        );
        let subject =
            crate::sla_attest::chain_sla_subject(state_store.as_ref(), &probe.provider_did);
        let (subject, payee) = match (subject, payee) {
            (Some(subject), Some(payee)) if subject.owner == payee.as_bytes() => (subject, payee),
            _ => return Answer::Declined,
        };
        // Validators only count answers signed by the identity
        // registered for the subject; answering as any other
        // identity is a miss.
        if subject.identity.as_ref() != Some(service.identity()) {
            warn!(
                provider = %probe.provider_did,
                "SLA probe for a bond this node runs, but the identity registered \
                 for it is not this machine's hardware identity"
            );
            return Answer::Declined;
        }

        // Verify before signing: the nonce is the issuer's VRF
        // output, so an unverified probe is one an issuer could
        // have ground to land an unmeetable deadline.
        if let Err(e) = tenzro_model::SlaManager::verify_probe(&probe) {
            warn!(
                issuer = %hex::encode(probe.issuer.to_bytes()),
                error = %e,
                "Rejecting SLA probe with an invalid VRF proof"
            );
            return Answer::Declined;
        }
        // The nonce must be drawn under the beacon value the chain holds
        // now, so its issuer could not have known it ahead of time or picked
        // among old values.
        use crate::sla_attest::BeaconStanding;
        let Some(store) = state_store.as_ref() else {
            return Answer::Declined;
        };
        // Read from chain state in one go: the reader is not held across the
        // answer's work.
        let (beacon_live, standing) = {
            let chain = tenzro_vm::StateAdapter::reader(store.clone());
            (
                crate::sla_attest::probe_beacon_live(&chain),
                probe
                    .beacon
                    .map(|b| crate::sla_attest::probe_beacon_standing(&chain, &b)),
            )
        };
        match probe.beacon.zip(standing) {
            // Until beacon-drawn probes are live a probe drawn without one is
            // answered as it always was.
            None if !beacon_live => {}
            None => {
                warn!(
                    issuer = %hex::encode(probe.issuer.to_bytes()),
                    "Rejecting SLA probe drawn under no beacon value"
                );
                return Answer::Declined;
            }
            Some((named, standing)) => {
                match standing {
                    BeaconStanding::Current => {}
                    BeaconStanding::NotYetSeen => return Answer::AwaitBeacon,
                    BeaconStanding::Refused => {
                        warn!(
                            issuer = %hex::encode(probe.issuer.to_bytes()),
                            beacon_round = named.round,
                            "Rejecting SLA probe drawn under a beacon value this chain does not hold now"
                        );
                        return Answer::Declined;
                    }
                }
                // One answer per issuer, subject and round under one beacon
                // value: no second draw with other work.
                if !self.taken.lock().take(&probe) {
                    debug!(
                        issuer = %hex::encode(probe.issuer.to_bytes()),
                        round = probe.round,
                        "SLA probe for a round already answered under this beacon value"
                    );
                    return Answer::Declined;
                }
            }
        }

        let now_ms = chrono::Utc::now().timestamp_millis();
        if now_ms > probe.deadline_ms {
            debug!(
                deadline_ms = probe.deadline_ms,
                now_ms, "SLA probe arrived past its deadline — not answering"
            );
            return Answer::Declined;
        }

        #[cfg(feature = "inference")]
        let result = crate::capacity_probe::perform(
            runtime.as_ref(),
            state_store.as_ref(),
            storage_runtime.as_ref(),
            &probe,
        )
        .await;
        #[cfg(not(feature = "inference"))]
        let result =
            crate::capacity_probe::perform(state_store.as_ref(), storage_runtime.as_ref(), &probe)
                .await;
        // The answer waits for its batch signature, but never
        // past the probe's deadline.
        let remaining = (probe.deadline_ms - chrono::Utc::now().timestamp_millis()).max(0) as u64;
        let wait = crate::batch_signing::BatchSigningParams::default()
            .receipt_wait()
            .min(std::time::Duration::from_millis(remaining));
        let probe_for_sign = probe.clone();
        let service_for_sign = service.clone();
        let signed = tokio::task::spawn_blocking(move || {
            tenzro_model::SlaManager::start_response(
                &probe_for_sign,
                payee,
                service_for_sign.as_ref(),
                chrono::Utc::now().timestamp_millis(),
                result,
                tenzro_crypto::session::now_ms(),
            )
            .and_then(|pending| pending.finish(wait))
        })
        .await;
        let response = match signed {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                warn!(error = %e, "SLA response signing failed");
                return Answer::Declined;
            }
            Err(e) => {
                warn!(error = %e, "SLA response signing task failed");
                return Answer::Declined;
            }
        };
        Answer::Signed(response)
    }
}

/// Serves SLA probes validators send over the `tenzro/sla` ALPN: the answer
/// is the bincode `SlaEnvelope::Response` the gossip topic would carry.
#[derive(Clone)]
pub(crate) struct SlaRequestHandler(pub(crate) SlaResponder);

impl std::fmt::Debug for SlaRequestHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SlaRequestHandler")
    }
}

#[async_trait::async_trait]
impl tenzro_iroh::RequestHandler for SlaRequestHandler {
    async fn handle(
        &self,
        _remote: tenzro_iroh::EndpointId,
        request: bytes::Bytes,
    ) -> tenzro_iroh::Reply {
        // The bytes a probe carries on its gossip topic: a plain probe or one
        // drawn under the beacon.
        let Some(probe) = tenzro_network::wire::decode_bounded::<tenzro_model::SlaEnvelope>(
            &request,
            MAX_SLA_REQUEST,
        )
        .ok()
        .and_then(tenzro_model::SlaEnvelope::into_probe)
        .or_else(|| {
            tenzro_network::wire::decode_bounded::<tenzro_model::BeaconProbe>(
                &request,
                MAX_SLA_REQUEST,
            )
            .ok()
            .map(tenzro_model::BeaconProbe::into_probe)
        }) else {
            return tenzro_iroh::Reply::full(400, "not an SLA probe");
        };
        match self.0.answer(probe).await {
            Answer::Signed(response) => {
                match bincode::serialize(&tenzro_model::SlaEnvelope::Response(response)) {
                    Ok(bytes) => tenzro_iroh::Reply::full(200, bytes),
                    Err(e) => tenzro_iroh::Reply::full(500, e.to_string()),
                }
            }
            Answer::AwaitBeacon | Answer::Declined => {
                tenzro_iroh::Reply::full(404, "this node does not answer that probe")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::batch::{BatchParams, BatchService};
    use tenzro_crypto::composite::testing::TestHybridSigner;

    fn responder() -> SlaResponder {
        let identity: Arc<dyn tenzro_crypto::composite::HybridSigner> =
            Arc::new(TestHybridSigner::hybrid(21));
        SlaResponder {
            identity_registry: None,
            machine_operator: None,
            configured_operator_did: None,
            #[cfg(feature = "inference")]
            runtime: None,
            storage_runtime: None,
            state_store: None,
            service: Arc::new(
                BatchService::new(
                    identity,
                    BatchParams {
                        max_batch: 1,
                        flush_interval_ms: 1_000,
                    },
                    0,
                )
                .unwrap(),
            ),
            taken: Arc::default(),
        }
    }

    #[tokio::test]
    async fn a_direct_probe_request_over_the_bound_is_refused_unread() {
        use tenzro_iroh::RequestHandler;
        let remote = tenzro_iroh::EndpointId::from_bytes(
            &ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        let reply = SlaRequestHandler(responder())
            .handle(remote, bytes::Bytes::from(vec![0u8; MAX_SLA_REQUEST + 1]))
            .await;
        assert_eq!(reply.status, 400);
    }

    #[tokio::test]
    async fn a_probe_for_a_subject_this_node_does_not_answer_for_gets_no_answer() {
        let probe = tenzro_model::SlaProbe {
            issuer: tenzro_crypto::Address::new([1u8; 20]),
            provider_did: "did:tenzro:provider:other".into(),
            epoch: 1,
            round: 1,
            beacon: None,
            challenge_nonce: [0; 32],
            deadline_ms: i64::MAX,
            vrf_proof: Vec::new(),
            vrf_pubkey: [0; 32],
            work: None,
        };
        assert!(matches!(responder().answer(probe).await, Answer::Declined));
    }
}
