//! A node registers its own machine identity on chain, by itself.
//!
//! A machine's identity is the DID its hardware identity key derives
//! (`did:tenzro:machine:...`). Peers resolve a validator's endpoint records
//! and its governance approvals through that identity, so every node must
//! have it on chain. Until now only `tenzro validator register-machine`
//! registered it: an operator ran it by hand on each host, from a separate
//! process that read the account nonce over RPC and raced the node's own
//! transactions for it.
//!
//! The node now does it. Once the chain has finalized a checkpoint it
//! submits the registration through its ledger submitter, the one component
//! that reserves nonces for the node account, and keeps trying until the
//! identity resolves on chain: a refusal (the account's ML-DSA-65 key not
//! enrolled yet, a full mempool) is retried with a growing delay, and a
//! transaction already submitted is given time to land before another is.
//!
//! This is distinct from `identity_bootstrap::maybe_register_machine`, which
//! submits `RegisterValidatorMachine` for a validator whose consensus key
//! does not itself name its machine. That one is governed by a lever and by
//! the consensus key scheme; this one concerns every node and has no lever,
//! because registering one's own identity is what the CLI command has always
//! done.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tenzro_crypto::composite::{HybridSigner, SignatureContext};
use tenzro_types::transaction::TransactionType;
use tokio::time::Instant;

use crate::node::TenzroNode;

/// Gas the registration is sent with (what the CLI sends).
pub const REGISTER_GAS: u64 = 200_000;

/// How often finality, and the identity, are looked at.
const POLL: Duration = Duration::from_secs(5);
/// The first delay after a refused submission; it doubles to [`BACKOFF_MAX`].
const BACKOFF_FIRST: Duration = Duration::from_secs(5);
const BACKOFF_MAX: Duration = Duration::from_secs(300);
/// How long an admitted registration is given to execute before another is
/// submitted.
const CONFIRM_WINDOW: Duration = Duration::from_secs(90);
/// Failed TPM attestations after which the identity registers without one
/// (`tenzro validator attach-attestation` adds it later).
const ATTESTATION_ATTEMPTS: u32 = 3;

/// What the chain shows about this machine's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// No checkpoint has been certified yet; nothing can execute.
    NotFinalized,
    /// The chain is finalizing and does not hold the identity.
    NotRegistered,
    /// The identity is on chain.
    Registered,
}

/// Drives `submit` until `observe` shows the identity on chain, never before
/// the chain has finalized. `submit` is told how many submissions failed in a
/// row (it may degrade, for instance register without an attestation) and
/// returns the transaction hash, or why it was not admitted. Returns how many
/// submissions were admitted.
pub async fn register_until_landed<O, S, Fut>(mut observe: O, mut submit: S) -> u32
where
    O: FnMut() -> Observation,
    S: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<String, String>>,
{
    let mut failures = 0u32;
    let mut admitted = 0u32;
    // The earliest moment the next submission may be made.
    let mut not_before: Option<Instant> = None;
    loop {
        match observe() {
            Observation::Registered => return admitted,
            Observation::NotFinalized => {}
            Observation::NotRegistered => {
                if not_before.is_none_or(|t| Instant::now() >= t) {
                    match submit(failures).await {
                        Ok(hash) => {
                            admitted += 1;
                            failures = 0;
                            not_before = Some(Instant::now() + CONFIRM_WINDOW);
                            tracing::info!(tx = %hash, "submitted this machine's identity registration");
                        }
                        Err(e) => {
                            let delay = backoff(failures);
                            failures += 1;
                            not_before = Some(Instant::now() + delay);
                            tracing::warn!(
                                error = %e,
                                attempt = failures,
                                retry_in_secs = delay.as_secs(),
                                "this machine's identity registration was not admitted"
                            );
                        }
                    }
                }
            }
        }
        tokio::time::sleep(POLL).await;
    }
}

/// The delay after `failures` refused submissions in a row.
fn backoff(failures: u32) -> Duration {
    BACKOFF_FIRST
        .saturating_mul(1u32.checked_shl(failures).unwrap_or(u32::MAX))
        .min(BACKOFF_MAX)
}

/// The `RegisterIdentity` transaction of the machine whose identity key is
/// `signer`, paying to `wallet`: the DID that key derives, with the
/// registration statement signed by that key. Returns the DID and the
/// transaction. The same registration `tenzro validator register-machine`
/// builds.
pub fn registration(
    signer: &dyn HybridSigner,
    wallet: [u8; 32],
    metadata: BTreeMap<String, String>,
) -> Result<(String, TransactionType), String> {
    use tenzro_types::account_signature::{ClassicalProof, CompositeSignature};
    use tenzro_types::identity::{RegisterIdentityPayload, RegistrationProof};

    let public = signer.public_key().clone();
    let sec1 = [&[0x04u8][..], &public.p256].concat();
    let did = tenzro_types::did_derivation::machine_did(&sec1);
    let mut payload = RegisterIdentityPayload {
        did: did.clone(),
        identity_type: "machine".into(),
        display_name: "machine root".into(),
        controller_pubkey: sec1,
        key_type: "P-256".into(),
        wallet_id: format!("0x{}", hex::encode(wallet)),
        wallet_address: tenzro_types::primitives::Address::new(wallet),
        pq_verifying_key: public.pq.clone().unwrap_or_default(),
        metadata,
        proof: RegistrationProof::Hardware {
            signature: CompositeSignature::classical(ClassicalProof::Raw {
                signature: Vec::new(),
            }),
        },
    };
    let statement = tenzro_types::identity::registration_statement(&payload);
    let signature = signer
        .sign(SignatureContext::IdentityRegistration, &statement)
        .map_err(|e| format!("signing the identity registration: {e}"))?;
    payload.proof = RegistrationProof::Hardware {
        signature: serde_json::from_value(
            serde_json::to_value(&signature).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?,
    };
    Ok((
        did,
        TransactionType::RegisterIdentity {
            did: payload.did,
            identity_type: payload.identity_type,
            display_name: payload.display_name,
            controller_pubkey: payload.controller_pubkey,
            key_type: payload.key_type,
            wallet_id: payload.wallet_id,
            wallet_address: payload.wallet_address,
            pq_verifying_key: payload.pq_verifying_key,
            metadata: payload.metadata,
            proof: payload.proof,
        },
    ))
}

/// The TPM attestation a machine root records with its registration, so the
/// chain admits the TPM under the machine's one identity.
#[cfg(any(target_os = "linux", windows))]
fn attestation_metadata(
    did: &str,
    identity_key: &[u8],
) -> Result<BTreeMap<String, String>, String> {
    let (_, att) = tenzro_tee::tpm_attest::attest_local_machine_as(Some(did), identity_key)
        .map_err(|e| format!("attesting this machine's TPM for {did}: {e}"))?;
    let mut metadata = BTreeMap::new();
    metadata.insert("machine_anchor".to_string(), "tpm_attested".to_string());
    metadata.insert(
        tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY.to_string(),
        serde_json::to_string(&att).map_err(|e| e.to_string())?,
    );
    Ok(metadata)
}

/// A Secure Enclave has no attestation for the machine root to record.
#[cfg(not(any(target_os = "linux", windows)))]
fn attestation_metadata(
    _did: &str,
    _identity_key: &[u8],
) -> Result<BTreeMap<String, String>, String> {
    Ok(BTreeMap::new())
}

/// Registers this node's machine identity, as soon as the chain has
/// finalized and for as long as it takes. Returns at once on a node that
/// cannot submit as itself (no consensus, or no hardware account key).
pub fn spawn(node: Arc<TenzroNode>) {
    tokio::spawn(async move {
        let Some(submitter) = node.ledger_submitter().cloned() else {
            tracing::debug!(
                "no ledger submitter: this node does not register its machine identity"
            );
            return;
        };
        let Ok(wallet) = <[u8; 32]>::try_from(submitter.address().as_bytes()) else {
            return;
        };
        let signer = match tokio::task::spawn_blocking(|| {
            tenzro_device_key::HardwareHybridSigner::open_or_create(
                tenzro_types::did_derivation::MACHINE_KEY_LABEL,
            )
            .map_err(|e| e.to_string())
        })
        .await
        {
            Ok(Ok(signer)) => Arc::new(signer),
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "no machine identity key: not registering the machine identity");
                return;
            }
            Err(e) => {
                tracing::warn!(error = %e, "opening the machine identity key failed");
                return;
            }
        };
        let did = {
            let sec1 = [&[0x04u8][..], &signer.public_key().p256].concat();
            tenzro_types::did_derivation::machine_did(&sec1)
        };
        let observe = {
            let (node, did) = (node.clone(), did.clone());
            move || observe(&node, &did)
        };
        let submit = {
            let (signer, submitter) = (signer.clone(), submitter.clone());
            move |failures: u32| {
                let (signer, submitter) = (signer.clone(), submitter.clone());
                async move {
                    let tx = tokio::task::spawn_blocking(move || {
                        let sec1 = [&[0x04u8][..], &signer.public_key().p256].concat();
                        let did = tenzro_types::did_derivation::machine_did(&sec1);
                        let metadata = match attestation_metadata(&did, &sec1) {
                            Ok(m) => m,
                            Err(e) if failures >= ATTESTATION_ATTEMPTS => {
                                tracing::warn!(error = %e, "registering without a TPM attestation");
                                BTreeMap::new()
                            }
                            Err(e) => return Err(e),
                        };
                        registration(&*signer, wallet, metadata).map(|(_, tx)| tx)
                    })
                    .await
                    .map_err(|e| e.to_string())??;
                    submitter
                        .submit_with_gas(
                            tenzro_types::primitives::Address::new([0u8; 32]),
                            tx,
                            REGISTER_GAS,
                        )
                        .await
                }
            }
        };
        register_until_landed(observe, submit).await;
        tracing::info!(%did, "this machine's identity is registered on chain");
    });
}

/// What this node's chain state shows about `did`.
fn observe(node: &TenzroNode, did: &str) -> Observation {
    use tenzro_vm::traits::VmState;
    if !node.consensus().is_some_and(|c| c.certified_height() > 0) {
        return Observation::NotFinalized;
    }
    let Some(state) = node.chain_state() else {
        return Observation::NotFinalized;
    };
    let slot = tenzro_types::identity::identity_slot(did);
    match state.get_storage(&tenzro_vm::native::SYSTEM_ADDRESS, slot.as_bytes()) {
        Some(record) if !record.is_empty() => Observation::Registered,
        _ => Observation::NotRegistered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A chain that finalizes after `finalizes_after` looks and holds the
    /// identity once `landed` is set.
    struct Chain {
        looks: AtomicU32,
        finalizes_after: u32,
        landed_at_submission: AtomicU32,
        submissions: AtomicU32,
        first_submission_look: AtomicU32,
    }

    impl Chain {
        fn new(finalizes_after: u32, landed_at_submission: u32) -> Arc<Self> {
            Arc::new(Self {
                looks: AtomicU32::new(0),
                finalizes_after,
                landed_at_submission: AtomicU32::new(landed_at_submission),
                submissions: AtomicU32::new(0),
                first_submission_look: AtomicU32::new(0),
            })
        }
        fn observe(&self) -> Observation {
            let look = self.looks.fetch_add(1, Ordering::SeqCst) + 1;
            if look <= self.finalizes_after {
                return Observation::NotFinalized;
            }
            let n = self.submissions.load(Ordering::SeqCst);
            if n >= self.landed_at_submission.load(Ordering::SeqCst) && n > 0 {
                Observation::Registered
            } else {
                Observation::NotRegistered
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_submitted_before_the_chain_finalizes_and_it_is_after() {
        let chain = Chain::new(10, 1);
        let c = chain.clone();
        let admitted = register_until_landed(
            {
                let c = chain.clone();
                move || c.observe()
            },
            move |_| {
                let c = c.clone();
                async move {
                    assert!(
                        c.looks.load(Ordering::SeqCst) > c.finalizes_after,
                        "submitted before the chain finalized"
                    );
                    c.first_submission_look
                        .compare_exchange(
                            0,
                            c.looks.load(Ordering::SeqCst),
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        )
                        .ok();
                    c.submissions.fetch_add(1, Ordering::SeqCst);
                    Ok("0xabc".to_string())
                }
            },
        )
        .await;
        assert_eq!(admitted, 1);
        assert_eq!(chain.submissions.load(Ordering::SeqCst), 1);
        assert_eq!(chain.first_submission_look.load(Ordering::SeqCst), 11);
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_submission_is_retried_with_growing_delays_until_it_lands() {
        // The key enrolment is pending for the first three attempts, as it is
        // on a node that has only just started finalizing.
        let chain = Chain::new(0, 1);
        let attempts = Arc::new(AtomicU32::new(0));
        let stamps = Arc::new(parking_lot::Mutex::new(Vec::<Instant>::new()));
        let (c, a, s) = (chain.clone(), attempts.clone(), stamps.clone());
        let admitted = register_until_landed(
            {
                let c = chain.clone();
                move || c.observe()
            },
            move |failures| {
                let (c, a, s) = (c.clone(), a.clone(), s.clone());
                async move {
                    s.lock().push(Instant::now());
                    let n = a.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(failures, n.min(3), "the submitter is told how many failed");
                    if n < 3 {
                        return Err(crate::payment_rails::PQ_ENROLMENT_PENDING.to_string());
                    }
                    c.submissions.fetch_add(1, Ordering::SeqCst);
                    Ok("0xdef".to_string())
                }
            },
        )
        .await;
        assert_eq!(admitted, 1);
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            4,
            "three refusals, then it landed"
        );
        let stamps = stamps.lock();
        let gaps: Vec<u64> = stamps.windows(2).map(|w| (w[1] - w[0]).as_secs()).collect();
        // 5s, 10s, 20s of backoff, each rounded up to the 5s poll.
        assert!(gaps[0] >= 5 && gaps[1] >= 10 && gaps[2] >= 20, "{gaps:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn an_admitted_registration_is_given_time_to_land_before_another_is_sent() {
        // The transaction is admitted but only executes after a long while:
        // the node must not submit a second one on top of it at once.
        let landed = Arc::new(AtomicU32::new(0));
        let sent = Arc::new(AtomicU32::new(0));
        let start = Instant::now();
        let (l, s) = (landed.clone(), sent.clone());
        let admitted = register_until_landed(
            move || {
                if Instant::now() - start > Duration::from_secs(200) {
                    l.store(1, Ordering::SeqCst);
                }
                if landed.load(Ordering::SeqCst) == 1 {
                    Observation::Registered
                } else {
                    Observation::NotRegistered
                }
            },
            move |_| {
                let s = s.clone();
                async move {
                    s.fetch_add(1, Ordering::SeqCst);
                    Ok("0x1".to_string())
                }
            },
        )
        .await;
        // 200s at one submission per 90s window: three, not forty.
        assert_eq!(admitted, 3);
        assert_eq!(sent.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn backoff_doubles_and_is_capped() {
        let secs: Vec<u64> = (0..9).map(|n| backoff(n).as_secs()).collect();
        assert_eq!(secs, [5, 10, 20, 40, 80, 160, 300, 300, 300]);
        assert_eq!(backoff(40).as_secs(), 300, "no shift overflow");
    }

    #[test]
    fn the_registration_is_the_one_the_vm_authorizes() {
        use tenzro_crypto::composite::testing::TestHybridSigner;
        let signer = TestHybridSigner::hybrid(7);
        let wallet = [9u8; 32];
        let (did, tx) = registration(&signer, wallet, BTreeMap::new()).unwrap();
        assert!(did.starts_with("did:tenzro:machine:"));
        let TransactionType::RegisterIdentity {
            identity_type,
            wallet_address,
            controller_pubkey,
            proof,
            ..
        } = tx
        else {
            panic!("not a RegisterIdentity")
        };
        assert_eq!(identity_type, "machine");
        assert_eq!(wallet_address.as_bytes(), &wallet[..]);
        assert_eq!(controller_pubkey[0], 0x04);
        assert!(matches!(
            proof,
            tenzro_types::identity::RegistrationProof::Hardware { .. }
        ));
    }
}
