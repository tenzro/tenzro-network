//! Provider heartbeats: the signed proof of life a serving node gossips on
//! `tenzro/providers` every [`HEARTBEAT_INTERVAL`], and how a receiver feeds
//! them into the router's liveness view.
//!
//! A heartbeat is signed as the provider's machine identity and accepted only
//! as the identity pinned by that provider's announcement, verified against
//! the key registered for it, so no peer can keep another provider alive or
//! mark it degraded. It carries the live load of each model the node serves,
//! which receivers keep beside the provider's announcement for discovery
//! (`tenzro_listProviders`).

pub use tenzro_model::provider_liveness::HEARTBEAT_INTERVAL;
use tenzro_model::provider_liveness::ProviderLiveness;
use tenzro_network::ProviderHeartbeatMessage;
use tenzro_types::primitives::Address;
use tenzro_types::provider_listing::{MAX_MODEL_LOADS, ModelLoad, ModelServingState};

/// What a heartbeat is held to: whether session-signed beats are accepted yet
/// and the limits governance sets for them, read from chain state.
#[derive(Debug, Clone, Copy)]
pub struct HeartbeatRules {
    /// True from the epoch of `feature.heartbeat_session`.
    pub session_forms_live: bool,
    /// `heartbeat.session_max_lifetime_ms` and `heartbeat.session_issue_skew_ms`.
    pub session: tenzro_crypto::heartbeat_session::SessionLimits,
    /// `heartbeat.max_skew_ms`. How far a heartbeat's send time may be from this node's clock, either
    /// way. The provider stamps it with its own clock, so the bound is the
    /// clock disagreement two machines are allowed, as for signed records and
    /// announcements, not the detection window: silence is judged by when this
    /// node received the last beat, and a beat no newer than the last one
    /// changes nothing, so a wider bound neither delays detection nor lets a
    /// replay undo a newer state.
    pub max_skew_ms: u64,
}

impl HeartbeatRules {
    /// The rules in force in `state`.
    pub fn read(state: &dyn tenzro_vm::VmState) -> Self {
        use tenzro_vm::governance as gov;
        let param = |key| tenzro_vm::native::network_param(state, key);
        Self {
            session_forms_live: tenzro_vm::feature_gate::is_live_now(
                state,
                gov::HEARTBEAT_SESSION_GATE,
            ),
            session: tenzro_crypto::heartbeat_session::SessionLimits {
                max_lifetime_ms: param(gov::HEARTBEAT_SESSION_MAX_LIFETIME_KEY),
                issue_skew_ms: param(gov::HEARTBEAT_SESSION_ISSUE_SKEW_KEY),
            },
            max_skew_ms: param(gov::HEARTBEAT_MAX_SKEW_KEY),
        }
    }
}

/// The live load of `models`: admitted requests and the admission ceiling
/// from the load tracker every inference path acquires a slot from, and the
/// load state and warm-up queue from the model lifecycle.
pub fn model_load(
    models: &[String],
    tracker: Option<&tenzro_model::LoadTracker>,
    lifecycle: Option<&tenzro_model::lifecycle::ModelLifecycle>,
) -> Vec<ModelLoad> {
    use tenzro_model::lifecycle::ModelState;
    models
        .iter()
        .take(MAX_MODEL_LOADS)
        .map(|m| {
            let slots = tracker.and_then(|t| t.snapshot(m));
            let (state, queue_depth, warm_eta_ms) = match lifecycle.map(|l| l.state(m)) {
                Some(ModelState::Warming {
                    remaining_ms,
                    waiters,
                    ..
                }) => (
                    ModelServingState::Warming,
                    waiters as u32,
                    Some(remaining_ms),
                ),
                Some(ModelState::Warm { .. }) => (ModelServingState::Warm, 0, None),
                Some(ModelState::Evicting) => (ModelServingState::Evicting, 0, None),
                Some(ModelState::Cold) | None => (
                    if slots.is_some() {
                        ModelServingState::Warm
                    } else {
                        ModelServingState::Cold
                    },
                    0,
                    None,
                ),
            };
            ModelLoad {
                model_id: m.clone(),
                state,
                in_flight: slots.as_ref().map_or(0, |s| s.active_requests),
                max_concurrent: slots.as_ref().map_or(0, |s| s.max_concurrent),
                queue_depth,
                warm_eta_ms,
            }
        })
        .collect()
}

/// Throttles the log of heartbeat signing failures: the first failure of a
/// streak and then every `every`-th, with a note when signing recovers. A
/// missed beat is retried by the next tick, so a streak needs no line per beat.
#[derive(Debug)]
pub struct SigningFailureLog {
    consecutive: std::sync::atomic::AtomicU64,
    every: u64,
}

impl SigningFailureLog {
    /// A log that reports every `every`-th consecutive failure (at least 1).
    pub fn new(every: u64) -> Self {
        Self {
            consecutive: std::sync::atomic::AtomicU64::new(0),
            every: every.max(1),
        }
    }

    /// Records a failure. `Some(n)` when it should be logged, `n` being the
    /// number of consecutive failures so far.
    pub fn failed(&self) -> Option<u64> {
        let n = self
            .consecutive
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        (n == 1 || n.is_multiple_of(self.every)).then_some(n)
    }

    /// Records a success. `Some(n)` when `n` failures preceded it.
    pub fn recovered(&self) -> Option<u64> {
        match self
            .consecutive
            .swap(0, std::sync::atomic::Ordering::Relaxed)
        {
            0 => None,
            n => Some(n),
        }
    }
}

/// This node's heartbeat, signed as its machine identity: by a hardware
/// batch, or, when `session` is given, by a session key the identity
/// certified (the form from the epoch `feature.heartbeat_session` names).
pub fn build(
    provider_address: &str,
    iroh_endpoint_id: &str,
    degraded: bool,
    model_load: Vec<ModelLoad>,
    signer: &crate::event_loop::AnnounceIdentity,
    session: Option<&tenzro_crypto::heartbeat_session::HeartbeatSessionSigner>,
) -> Result<ProviderHeartbeatMessage, String> {
    let mut hb = ProviderHeartbeatMessage {
        provider_address: provider_address.to_string(),
        iroh_endpoint_id: iroh_endpoint_id.to_string(),
        timestamp: chrono::Utc::now().timestamp_millis(),
        degraded,
        model_load,
        ..Default::default()
    };
    match session {
        None => tenzro_network::SignedAnnouncement::sign(
            &mut hb,
            signer.machine_did(),
            signer.signer(),
        )?,
        Some(session) => {
            hb.machine_did = signer.machine_did().to_string();
            hb.signature = None;
            let preimage = tenzro_network::SignedAnnouncement::signing_preimage(&hb)?;
            hb.signature = Some(
                session
                    .sign_heartbeat(&preimage)
                    .map_err(|e| e.to_string())?,
            );
        }
    }
    Ok(hb)
}

/// Verifies `hb` against the machine's registered `key`: a hardware batch
/// signature always, a session-signed one only when
/// `rules.session_forms_live` (before the epoch of `feature.heartbeat_session`
/// it is refused).
fn verify_signature(
    hb: &ProviderHeartbeatMessage,
    key: &tenzro_crypto::composite::CompositePublicKey,
    now_ms: i64,
    rules: &HeartbeatRules,
) -> Result<(), String> {
    use tenzro_crypto::heartbeat_session::SessionForm;
    let session = tenzro_network::SignedAnnouncement::signature(hb)
        .and_then(SessionForm::from_record_signature);
    let Some(form) = session else {
        return tenzro_network::SignedAnnouncement::verify(hb, key);
    };
    if !rules.session_forms_live {
        return Err("a session-signed heartbeat before its epoch".into());
    }
    let form = form.map_err(|e| e.to_string())?;
    let preimage = tenzro_network::SignedAnnouncement::signing_preimage(hb)?;
    form.verify(key, &preimage, now_ms.max(0) as u64, &rules.session)
        .map_err(|e| e.to_string())
}

/// Feeds `hb` into `liveness` if it verifies, is recent, and is signed as
/// `pinned`: the provider address and machine DID of the announcement this
/// node accepted for the endpoint the heartbeat names, with the identity key
/// registered for that DID.
pub fn accept(
    hb: &ProviderHeartbeatMessage,
    pinned: Option<(&str, &str, &tenzro_crypto::composite::CompositePublicKey)>,
    now_ms: i64,
    liveness: &ProviderLiveness,
    rules: &HeartbeatRules,
) -> Result<Address, String> {
    let Some((provider_address, machine_did, key)) = pinned else {
        return Err("no accepted announcement for this endpoint".into());
    };
    if hb.machine_did != machine_did || hb.provider_address != provider_address {
        return Err("not signed as the identity pinned for this provider".into());
    }
    verify_signature(hb, key, now_ms, rules)?;
    if hb.model_load.len() > MAX_MODEL_LOADS {
        return Err("reports more models than a heartbeat carries".into());
    }
    if (now_ms - hb.timestamp).unsigned_abs() > rules.max_skew_ms {
        return Err("sent too far from this node's clock".into());
    }
    let address =
        Address::from_hex(&hb.provider_address).map_err(|e| format!("provider address: {e}"))?;
    liveness.heartbeat(address, hb.timestamp, hb.degraded);
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES_SKEW: u64 = 60_000;
    const LIFETIME: u64 = 60 * 60 * 1000;

    fn rules(session_forms_live: bool) -> HeartbeatRules {
        HeartbeatRules {
            session_forms_live,
            session: tenzro_crypto::heartbeat_session::SessionLimits {
                max_lifetime_ms: LIFETIME,
                issue_skew_ms: 60_000,
            },
            max_skew_ms: RULES_SKEW,
        }
    }

    #[test]
    fn a_streak_of_signing_failures_logs_the_first_and_every_tenth_then_recovery() {
        let log = SigningFailureLog::new(10);
        assert_eq!(log.recovered(), None);
        let logged: Vec<u64> = (0..25).filter_map(|_| log.failed()).collect();
        assert_eq!(logged, vec![1, 10, 20]);
        assert_eq!(log.recovered(), Some(25));
        assert_eq!(log.recovered(), None);
        // A new streak starts over.
        assert_eq!(log.failed(), Some(1));
        assert_eq!(log.failed(), None);
    }

    fn signer() -> crate::event_loop::AnnounceIdentity {
        let hw = tenzro_crypto::composite::testing::TestHybridSigner::random();
        let signer = tenzro_crypto::batch::ImmediateRecordSigner::new(std::sync::Arc::new(hw));
        crate::event_loop::AnnounceIdentity::new(std::sync::Arc::new(signer))
    }

    #[test]
    fn only_the_pinned_key_can_keep_a_provider_alive_or_mark_it_down() {
        let liveness = ProviderLiveness::default();
        let provider = format!("0x{}", hex::encode([7u8; 32]));
        let key = signer();
        let pinned_key = key.signer().identity().clone();
        let pinned = Some((provider.as_str(), key.machine_did(), &pinned_key));

        let hb = build(&provider, "ep", true, Vec::new(), &key, None).unwrap();
        let now = hb.timestamp;
        let address = accept(&hb, pinned, now, &liveness, &rules(false)).unwrap();
        assert!(liveness.is_down(&address), "anomaly evidence marks it down");

        // Another identity naming the same provider is refused, and so is
        // another identity claiming the pinned machine DID.
        let other = signer();
        let forged = build(&provider, "ep", false, Vec::new(), &other, None).unwrap();
        assert!(accept(&forged, pinned, now, &liveness, &rules(false)).is_err());
        let mut forged = build(&provider, "ep", false, Vec::new(), &other, None).unwrap();
        tenzro_network::SignedAnnouncement::sign(&mut forged, key.machine_did(), other.signer())
            .unwrap();
        assert!(accept(&forged, pinned, now, &liveness, &rules(false)).is_err());
        assert!(liveness.is_down(&address));

        // A tampered heartbeat is refused.
        let mut tampered = build(&provider, "ep", true, Vec::new(), &key, None).unwrap();
        tampered.degraded = false;
        assert!(accept(&tampered, pinned, now, &liveness, &rules(false)).is_err());

        // A stale one is refused.
        let old = build(&provider, "ep", false, Vec::new(), &key, None).unwrap();
        assert!(
            accept(
                &old,
                pinned,
                old.timestamp + RULES_SKEW as i64 + 1,
                &liveness,
                &rules(false)
            )
            .is_err()
        );

        // A fresh clean heartbeat from the pinned key restores it.
        let mut clean = build(&provider, "ep", false, Vec::new(), &key, None).unwrap();
        clean.timestamp = now + 1;
        tenzro_network::SignedAnnouncement::sign(&mut clean, key.machine_did(), key.signer())
            .unwrap();
        accept(&clean, pinned, now + 1, &liveness, &rules(false)).unwrap();
        assert!(!liveness.is_down(&address));

        assert!(
            accept(&clean, None, now + 1, &liveness, &rules(false)).is_err(),
            "no announcement accepted"
        );
    }

    #[test]
    fn a_heartbeat_carries_signed_live_load() {
        let tracker = tenzro_model::LoadTracker::new();
        tracker.register_model("m1", 4);
        let _busy = tracker.try_acquire("m1").unwrap();
        let load = model_load(&["m1".to_string(), "m2".to_string()], Some(&tracker), None);
        assert_eq!(
            (
                load[0].in_flight,
                load[0].max_concurrent,
                load[0].available()
            ),
            (1, 4, 3)
        );
        assert_eq!(load[0].state, ModelServingState::Warm);
        assert_eq!(
            load[1].state,
            ModelServingState::Cold,
            "a model the tracker does not hold"
        );

        let liveness = ProviderLiveness::default();
        let provider = format!("0x{}", hex::encode([7u8; 32]));
        let key = signer();
        let pinned_key = key.signer().identity().clone();
        let pinned = Some((provider.as_str(), key.machine_did(), &pinned_key));
        let hb = build(&provider, "ep", false, load, &key, None).unwrap();
        accept(&hb, pinned, hb.timestamp, &liveness, &rules(false)).unwrap();
        // The load is covered by the signature.
        let mut lied = hb.clone();
        lied.model_load[0].in_flight = 0;
        assert!(accept(&lied, pinned, hb.timestamp, &liveness, &rules(false)).is_err());
        // And bounded.
        let flood = vec![hb.model_load[0].clone(); MAX_MODEL_LOADS + 1];
        let big = build(&provider, "ep", false, flood, &key, None).unwrap();
        assert!(accept(&big, pinned, big.timestamp, &liveness, &rules(false)).is_err());
    }

    /// A provider whose clock is a few seconds or half a minute off this
    /// node's, either way, is kept alive by its heartbeats: the
    /// detection window bounds silence, not the clocks' disagreement.
    #[test]
    fn a_provider_with_a_skewed_clock_stays_alive() {
        let provider = format!("0x{}", hex::encode([9u8; 32]));
        let key = signer();
        let pinned_key = key.signer().identity().clone();
        let pinned = Some((provider.as_str(), key.machine_did(), &pinned_key));
        for skew in [-30_000i64, -5_000, 5_000, 30_000] {
            let liveness = ProviderLiveness::default();
            let hb = build(&provider, "ep", false, Vec::new(), &key, None).unwrap();
            let here = hb.timestamp - skew;
            let address = accept(&hb, pinned, here, &liveness, &rules(false))
                .unwrap_or_else(|e| panic!("skew {skew} ms refused: {e}"));
            assert!(!liveness.is_down(&address), "skew {skew} ms");
            // A later beat keeps it alive; replaying the first changes nothing.
            let mut next = build(&provider, "ep", false, Vec::new(), &key, None).unwrap();
            next.timestamp = hb.timestamp + 2_000;
            tenzro_network::SignedAnnouncement::sign(&mut next, key.machine_did(), key.signer())
                .unwrap();
            accept(&next, pinned, here + 2_000, &liveness, &rules(false)).unwrap();
            accept(&hb, pinned, here + 2_000, &liveness, &rules(false)).unwrap();
            assert!(!liveness.is_down(&address), "skew {skew} ms");
        }
        // Past the bound the beat is refused.
        let liveness = ProviderLiveness::default();
        let hb = build(&provider, "ep", false, Vec::new(), &key, None).unwrap();
        assert!(
            accept(
                &hb,
                pinned,
                hb.timestamp + RULES_SKEW as i64 + 1,
                &liveness,
                &rules(false)
            )
            .is_err()
        );
    }

    fn session_for(
        key: &crate::event_loop::AnnounceIdentity,
    ) -> tenzro_crypto::heartbeat_session::HeartbeatSessionSigner {
        tenzro_crypto::heartbeat_session::HeartbeatSessionSigner::new(
            std::sync::Arc::new(key.signer().clone()),
            LIFETIME,
        )
        .unwrap()
    }

    /// Before the epoch of `feature.heartbeat_session` a session-signed
    /// heartbeat is refused and a batch-signed one accepted; from it both
    /// are accepted, so a network of both kinds of sender stays live.
    #[test]
    fn a_session_signed_heartbeat_is_accepted_only_from_its_epoch() {
        let liveness = ProviderLiveness::default();
        let provider = format!("0x{}", hex::encode([7u8; 32]));
        let key = signer();
        let pinned_key = key.signer().identity().clone();
        let pinned = Some((provider.as_str(), key.machine_did(), &pinned_key));
        let session = session_for(&key);

        let batch = build(&provider, "ep", false, Vec::new(), &key, None).unwrap();
        let signed = build(&provider, "ep", false, Vec::new(), &key, Some(&session)).unwrap();
        let now = signed.timestamp;

        assert!(accept(&signed, pinned, now, &liveness, &rules(false)).is_err());
        accept(&batch, pinned, now, &liveness, &rules(false)).unwrap();

        accept(&signed, pinned, now, &liveness, &rules(true)).unwrap();
        accept(&batch, pinned, now, &liveness, &rules(true)).unwrap();
    }

    #[test]
    fn a_session_signed_heartbeat_is_held_to_the_pinned_identity_and_its_body() {
        let liveness = ProviderLiveness::default();
        let provider = format!("0x{}", hex::encode([7u8; 32]));
        let key = signer();
        let pinned_key = key.signer().identity().clone();
        let pinned = Some((provider.as_str(), key.machine_did(), &pinned_key));

        // Another identity's session key, naming the pinned machine, is
        // refused: its certificate is signed by a key that is not pinned.
        let other = signer();
        let other_session = session_for(&other);
        let mut forged = build(
            &provider,
            "ep",
            false,
            Vec::new(),
            &other,
            Some(&other_session),
        )
        .unwrap();
        forged.machine_did = key.machine_did().to_string();
        let now = forged.timestamp;
        assert!(accept(&forged, pinned, now, &liveness, &rules(true)).is_err());

        // A tampered body no longer matches the session signature.
        let session = session_for(&key);
        let mut tampered = build(&provider, "ep", true, Vec::new(), &key, Some(&session)).unwrap();
        tampered.degraded = false;
        assert!(accept(&tampered, pinned, now, &liveness, &rules(true)).is_err());

        // A heartbeat sent too long ago is still refused.
        let old = build(&provider, "ep", false, Vec::new(), &key, Some(&session)).unwrap();
        assert!(
            accept(
                &old,
                pinned,
                old.timestamp + RULES_SKEW as i64 + 1,
                &liveness,
                &rules(true)
            )
            .is_err()
        );
    }

    /// A session-signed heartbeat costs the hardware nothing: the identity
    /// signs the certificate once, however many heartbeats follow.
    #[test]
    fn session_signed_heartbeats_ask_the_hardware_once() {
        struct Counting {
            inner: tenzro_crypto::batch::ImmediateRecordSigner,
            signed: std::sync::atomic::AtomicUsize,
        }
        impl tenzro_crypto::batch::RecordSigner for Counting {
            fn identity(&self) -> &tenzro_crypto::composite::CompositePublicKey {
                tenzro_crypto::batch::RecordSigner::identity(&self.inner)
            }
            fn sign_record(
                &self,
                message: &[u8],
            ) -> tenzro_crypto::Result<tenzro_crypto::batch::RecordSignature> {
                self.signed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tenzro_crypto::batch::RecordSigner::sign_record(&self.inner, message)
            }
        }
        let hw = tenzro_crypto::composite::testing::TestHybridSigner::random();
        let counting = std::sync::Arc::new(Counting {
            inner: tenzro_crypto::batch::ImmediateRecordSigner::new(std::sync::Arc::new(hw)),
            signed: std::sync::atomic::AtomicUsize::new(0),
        });
        let session = tenzro_crypto::heartbeat_session::HeartbeatSessionSigner::new(
            counting.clone(),
            LIFETIME,
        )
        .unwrap();
        for i in 0..20u8 {
            session.sign_heartbeat(&[i]).unwrap();
        }
        assert_eq!(
            counting.signed.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "one certificate, twenty heartbeats"
        );
    }
}
