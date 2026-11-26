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
//! A machine root registered without its TPM attestation (the TPM failed
//! [`ATTESTATION_ATTEMPTS`] times, or an earlier build registered it) gets
//! the attestation attached the same way once the registration is on chain:
//! the node quotes the chain challenge bound to its account's next nonce and
//! submits `AttachMachineAttestation` at exactly that nonce, until the
//! identity carries the attestation. Without it the machine's hardware level
//! stays at level 0 whatever TPM it holds. A machine whose identity key is
//! in another machine's TPM asks that machine for the attestation and the
//! quote: that TPM is the hardware the identity rests on.
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
/// (the node attaches it once the registration is on chain).
const ATTESTATION_ATTEMPTS: u32 = 3;

/// Attaches tried (refused, or sent without landing) before the node stops;
/// each one sent costs the node account gas. A restart tries again.
const ATTACH_ATTEMPTS: u32 = 6;

/// Why this machine's root got no TPM attestation.
#[derive(Debug)]
pub struct AttestError {
    message: String,
    /// The machine that holds the identity key does not attest for it (it
    /// names another client or none, or knows no attestation request);
    /// asking again changes nothing.
    holder_declines: bool,
}

/// What the chain shows about this machine's identity, or about the TPM
/// attestation it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// No checkpoint has been certified yet; nothing can execute.
    NotFinalized,
    /// The chain is finalizing and does not hold the identity (or its
    /// attestation).
    NotRegistered,
    /// The identity (or its attestation) is on chain.
    Registered,
}

/// Drives `submit` until `observe` shows `what` (the identity registration,
/// or the attestation attach) on chain, never before the chain has
/// finalized. `submit` is told how many submissions failed in a row (it may
/// degrade, for instance register without an attestation) and returns the
/// transaction hash, or why it was not admitted. Returns how many
/// submissions were admitted.
pub async fn register_until_landed<O, S, Fut>(what: &str, mut observe: O, mut submit: S) -> u32
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
                            tracing::info!(tx = %hash, "submitted this machine's {what}");
                        }
                        Err(e) => {
                            let delay = backoff(failures);
                            failures += 1;
                            not_before = Some(Instant::now() + delay);
                            tracing::warn!(
                                error = %e,
                                attempt = failures,
                                retry_in_secs = delay.as_secs(),
                                "this machine's {what} was not admitted"
                            );
                            if let Some(remedy) = remedy(&e) {
                                tracing::warn!("{remedy}");
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(POLL).await;
    }
}

/// What the operator can do about a refused submission, when the refusal
/// is one they can act on.
fn remedy(error: &str) -> Option<&'static str> {
    error.contains("Insufficient balance").then_some(
        "This machine's account cannot pay the registration fee yet; the error above names the \
         account and the amount. Send that much TNZO to it from any funded account: the node \
         keeps trying and registers by itself once the account can pay. On a network where \
         governance has turned on feature.first_registration_free, a first registration from \
         an account that cannot pay is admitted without funds.",
    )
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
fn attestation_metadata(
    signer: &tenzro_device_key::HardwareHybridSigner,
    did: &str,
    identity_key: &[u8],
) -> Result<BTreeMap<String, String>, AttestError> {
    if !tpm_backed(signer) {
        return Ok(BTreeMap::new());
    }
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let att = attest(signer, did, identity_key, nonce)?;
    let mut metadata = BTreeMap::new();
    metadata.insert("machine_anchor".to_string(), "tpm_attested".to_string());
    metadata.insert(
        tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY.to_string(),
        serde_json::to_string(&att).map_err(|e| AttestError {
            message: e.to_string(),
            holder_declines: false,
        })?,
    );
    Ok(metadata)
}

/// What this machine's root registers with after `failures` refused
/// submissions: its TPM attestation, or nothing when the machine that holds
/// its key does not attest for it or the TPM failed [`ATTESTATION_ATTEMPTS`]
/// times (the node attaches it later if it can).
fn registration_metadata(
    signer: &tenzro_device_key::HardwareHybridSigner,
    did: &str,
    identity_key: &[u8],
    failures: u32,
) -> Result<BTreeMap<String, String>, String> {
    match attestation_metadata(signer, did, identity_key) {
        Ok(metadata) => Ok(metadata),
        Err(e) if e.holder_declines => {
            tracing::info!(reason = %e.message, "registering without a TPM attestation");
            Ok(BTreeMap::new())
        }
        Err(e) if failures >= ATTESTATION_ATTEMPTS => {
            tracing::warn!(error = %e.message, "registering without a TPM attestation");
            Ok(BTreeMap::new())
        }
        Err(e) => Err(e.message),
    }
}

/// The admission attestation of the machine root `did` for `nonce`, by the
/// TPM that holds its identity key: this machine's, or the one of the
/// machine that holds the key for it.
fn attest(
    signer: &tenzro_device_key::HardwareHybridSigner,
    did: &str,
    identity_key: &[u8],
    nonce: [u8; 32],
) -> Result<tenzro_tee::tpm_attest::MachineAttestation, AttestError> {
    if held_elsewhere(signer) {
        let declines = std::cell::Cell::new(false);
        return tenzro_tee::holder_attest::admission(
            |request| {
                signer.holder_attestation(request).map_err(|e| {
                    declines.set(tenzro_device_key::remote::holder_does_not_attest(&e));
                    e.to_string()
                })
            },
            identity_key,
            nonce,
        )
        .map_err(|e| AttestError {
            message: format!("the TPM that holds {did}'s key attesting for it: {e}"),
            holder_declines: declines.get(),
        });
    }
    local_attestation(did, identity_key, nonce).map_err(|e| AttestError {
        message: format!("attesting this machine's TPM for {did}: {e}"),
        holder_declines: false,
    })
}

#[cfg(any(target_os = "linux", windows))]
fn local_attestation(
    did: &str,
    identity_key: &[u8],
    nonce: [u8; 32],
) -> tenzro_tee::error::Result<tenzro_tee::tpm_attest::MachineAttestation> {
    tenzro_tee::tpm_attest::attest_local_machine_over(Some(did), identity_key, Some(nonce))
        .map(|(_, att)| att)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn local_attestation(
    _did: &str,
    _identity_key: &[u8],
    _nonce: [u8; 32],
) -> tenzro_tee::error::Result<tenzro_tee::tpm_attest::MachineAttestation> {
    Err(tenzro_tee::error::TeeError::not_available(
        "this platform has no TPM 2.0",
    ))
}

/// Whether the identity key `signer` holds is in another machine's TPM.
fn held_elsewhere(signer: &tenzro_device_key::HardwareHybridSigner) -> bool {
    signer.backend() == tenzro_device_key::HardwareBackend::RemoteTpm
}

/// Whether a TPM stands behind `signer`: this machine's, on a platform that
/// has one, or the one of the machine that holds the key. A Secure Enclave
/// has no attestation for a machine root to record.
fn tpm_backed(signer: &tenzro_device_key::HardwareHybridSigner) -> bool {
    held_elsewhere(signer) || cfg!(any(target_os = "linux", windows))
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
                        let metadata = registration_metadata(&signer, &did, &sec1, failures)?;
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
        register_until_landed("identity registration", observe, submit).await;
        tracing::info!(%did, "this machine's identity is registered on chain");
        attach_attestation(&node, signer, submitter, did).await;
    });
}

/// Why an attach was not sent.
#[derive(Debug)]
pub enum AttachRefusal {
    /// A later try may succeed.
    Retry(String),
    /// No later try can: nothing more is sent.
    Final(String),
}

/// Drives `submit` until `observe` shows the attestation on chain, never
/// before the chain has finalized. Unlike a registration, an attach is given
/// up: when `submit` says no later try can succeed, and after
/// [`ATTACH_ATTEMPTS`] tries that were refused or were sent and did not
/// land (the chain refuses a sent attach only when it executes it, and each
/// one costs gas). Returns how many were sent, or why the node stopped.
pub async fn attach_until_landed<O, S, Fut>(mut observe: O, mut submit: S) -> Result<u32, String>
where
    O: FnMut() -> Observation,
    S: FnMut() -> Fut,
    Fut: Future<Output = Result<String, AttachRefusal>>,
{
    let mut tries = 0u32;
    let mut failures = 0u32;
    let mut sent = 0u32;
    let mut not_before: Option<Instant> = None;
    loop {
        match observe() {
            Observation::Registered => return Ok(sent),
            Observation::NotFinalized => {}
            Observation::NotRegistered => {
                if not_before.is_none_or(|t| Instant::now() >= t) {
                    if tries == ATTACH_ATTEMPTS {
                        return Err(format!("{ATTACH_ATTEMPTS} tries did not attach it"));
                    }
                    tries += 1;
                    match submit().await {
                        Ok(hash) => {
                            sent += 1;
                            failures = 0;
                            not_before = Some(Instant::now() + CONFIRM_WINDOW);
                            tracing::info!(tx = %hash, "submitted this machine's TPM attestation attach");
                        }
                        Err(AttachRefusal::Final(why)) => return Err(why),
                        Err(AttachRefusal::Retry(e)) => {
                            let delay = backoff(failures);
                            failures += 1;
                            not_before = Some(Instant::now() + delay);
                            tracing::warn!(
                                error = %e,
                                attempt = tries,
                                retry_in_secs = delay.as_secs(),
                                "this machine's TPM attestation attach was not admitted"
                            );
                        }
                    }
                }
            }
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Attaches this machine's TPM attestation to its registered identity when
/// the identity carries none. Nothing is sent when the machine that holds
/// the identity key does not attest for it, or when the chain already holds
/// that TPM under another identity: the chain would refuse the attach and
/// keep the gas.
async fn attach_attestation(
    node: &Arc<TenzroNode>,
    signer: Arc<tenzro_device_key::HardwareHybridSigner>,
    submitter: Arc<crate::payment_rails::LedgerSubmitter>,
    did: String,
) {
    if !tpm_backed(&signer) {
        return;
    }
    let observe = {
        let (node, did) = (node.clone(), did.clone());
        move || observe_attestation(&node, &did)
    };
    let submit = {
        let (node, did) = (node.clone(), did.clone());
        move || {
            let (signer, submitter) = (signer.clone(), submitter.clone());
            let (node, did) = (node.clone(), did.clone());
            async move {
                // The quote answers the challenge of the nonce the attach is
                // sent at, so the nonce is read first and the attach is
                // admitted only at that nonce; a nonce that moved meanwhile
                // is a refusal the next attempt builds again for.
                let nonce = submitter.next_nonce();
                let wallet = submitter.address();
                let (tx, att) = tokio::task::spawn_blocking(move || {
                    let mut refusal = None;
                    let mut attested = None;
                    let tx = attachment(
                        &*signer,
                        wallet.as_bytes(),
                        nonce,
                        |did, sec1, challenge| match attest(&signer, did, sec1, challenge) {
                            Ok(att) => {
                                attested = Some(att.clone());
                                Ok(att)
                            }
                            Err(e) => {
                                refusal = e.holder_declines.then(|| e.message.clone());
                                Err(e.message)
                            }
                        },
                    );
                    match (tx, refusal, attested) {
                        (_, Some(why), _) => Err(AttachRefusal::Final(why)),
                        (Ok(tx), _, Some(att)) => Ok((tx, att)),
                        (Ok(_), _, None) => Err(AttachRefusal::Retry(
                            "the attach was built without an attestation".into(),
                        )),
                        (Err(e), ..) => Err(AttachRefusal::Retry(e)),
                    }
                })
                .await
                .map_err(|e| AttachRefusal::Retry(e.to_string()))??;
                if let Some(holder) = crate::rpc::chain_state_of(&node).and_then(|chain| {
                    tenzro_vm::native::machine_attestation::other_holder(&chain, &did, &att)
                }) {
                    return Err(AttachRefusal::Final(format!(
                        "the TPM that attests for it is already admitted under {holder}, and a \
                         TPM answers for one identity"
                    )));
                }
                submitter
                    .submit_at_nonce(
                        tenzro_types::primitives::Address::new([0u8; 32]),
                        tx,
                        ATTACH_GAS,
                        nonce,
                    )
                    .await
                    .map_err(AttachRefusal::Retry)
            }
        }
    };
    match attach_until_landed(observe, submit).await {
        Ok(0) => {}
        Ok(_) => tracing::info!(%did, "this machine's TPM attestation is attached on chain"),
        Err(why) => tracing::warn!(
            %did,
            reason = %why,
            "this machine's identity carries no TPM attestation and the node has stopped trying"
        ),
    }
}

/// Gas the attach is sent with (what `tenzro validator attach-attestation`
/// sends).
pub const ATTACH_GAS: u64 = 300_000;

/// The `AttachMachineAttestation` transaction of the machine root whose
/// identity key is `signer`, sent by `sender` at `account_nonce`: `attest`
/// quotes the chain challenge for that nonce (DID, identity key, challenge).
pub fn attachment(
    signer: &dyn HybridSigner,
    sender: &[u8],
    account_nonce: u64,
    attest: impl FnOnce(
        &str,
        &[u8],
        [u8; 32],
    ) -> Result<tenzro_tee::tpm_attest::MachineAttestation, String>,
) -> Result<TransactionType, String> {
    let sec1 = [&[0x04u8][..], &signer.public_key().p256].concat();
    let did = tenzro_types::did_derivation::machine_did(&sec1);
    let challenge = tenzro_types::identity::attach_attestation_nonce(&did, sender, account_nonce);
    let att = attest(&did, &sec1, challenge)?;
    let attestation = serde_json::to_string(&att).map_err(|e| e.to_string())?;
    let statement = tenzro_types::identity::attach_attestation_statement(&did, &attestation);
    let signature = signer
        .sign(SignatureContext::IdentityRegistration, &statement)
        .map_err(|e| format!("signing the attestation attach: {e}"))?;
    Ok(TransactionType::AttachMachineAttestation {
        op: tenzro_types::identity::AttachMachineAttestationOp {
            did,
            attestation,
            signature: serde_json::from_value(
                serde_json::to_value(&signature).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?,
        },
    })
}

/// What this node's chain state shows about the TPM attestation of `did`.
fn observe_attestation(node: &TenzroNode, did: &str) -> Observation {
    use tenzro_vm::traits::VmState;
    if !node.consensus().is_some_and(|c| c.certified_height() > 0) {
        return Observation::NotFinalized;
    }
    let Some(state) = node.chain_state() else {
        return Observation::NotFinalized;
    };
    let slot = tenzro_types::identity::identity_slot(did);
    attestation_observation(
        state
            .get_storage(&tenzro_vm::native::SYSTEM_ADDRESS, slot.as_bytes())
            .as_deref(),
    )
}

/// Whether the identity record `record` still needs its TPM attestation: an
/// attach is due only for a record that carries none. A record this node
/// cannot read is left alone (nothing it sends could change it).
fn attestation_observation(record: Option<&[u8]>) -> Observation {
    let Some(record) = record.filter(|r| !r.is_empty()) else {
        return Observation::Registered;
    };
    match serde_json::from_slice::<tenzro_types::identity::RegisterIdentityPayload>(record) {
        Ok(r)
            if !r
                .metadata
                .contains_key(tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY) =>
        {
            Observation::NotRegistered
        }
        _ => Observation::Registered,
    }
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
            "identity registration",
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
            "identity registration",
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
            "identity registration",
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
    fn an_account_that_cannot_pay_is_told_what_to_do() {
        let e = "Insufficient balance for 0xab: balance 0 < required 800000000000000";
        assert!(remedy(e).is_some_and(|r| r.contains("Send that much TNZO")));
        assert!(remedy("mempool full").is_none());
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

    /// An attach is due only while the registered root carries no TPM
    /// attestation; a record that is absent or unreadable is left alone.
    #[test]
    fn an_attach_is_due_only_for_a_root_without_its_attestation() {
        use tenzro_crypto::composite::testing::TestHybridSigner;
        let signer = TestHybridSigner::hybrid(7);
        let (_, tx) = registration(&signer, [9u8; 32], BTreeMap::new()).unwrap();
        let TransactionType::RegisterIdentity {
            did,
            identity_type,
            display_name,
            controller_pubkey,
            key_type,
            wallet_id,
            wallet_address,
            pq_verifying_key,
            metadata,
            proof,
        } = tx
        else {
            panic!("not a RegisterIdentity")
        };
        let mut record = tenzro_types::identity::RegisterIdentityPayload {
            did,
            identity_type,
            display_name,
            controller_pubkey,
            key_type,
            wallet_id,
            wallet_address,
            pq_verifying_key,
            metadata,
            proof,
        };
        let bytes =
            |r: &tenzro_types::identity::RegisterIdentityPayload| serde_json::to_vec(r).unwrap();
        assert_eq!(
            attestation_observation(Some(&bytes(&record))),
            Observation::NotRegistered
        );
        record.metadata.insert(
            tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY.to_string(),
            "{}".to_string(),
        );
        assert_eq!(
            attestation_observation(Some(&bytes(&record))),
            Observation::Registered
        );
        assert_eq!(attestation_observation(None), Observation::Registered);
        assert_eq!(attestation_observation(Some(b"")), Observation::Registered);
        assert_eq!(
            attestation_observation(Some(b"not json")),
            Observation::Registered
        );
    }

    /// The attach quotes the chain challenge of the sender's nonce, for the
    /// DID and identity key of the signer, and the identity key signs the
    /// statement over that DID and attestation.
    #[test]
    fn the_attach_answers_the_challenge_of_the_nonce_it_is_sent_at() {
        use tenzro_crypto::composite::testing::TestHybridSigner;
        let signer = TestHybridSigner::hybrid(7);
        let sender = [5u8; 32];
        let sec1 = [&[0x04u8][..], &signer.public_key().p256].concat();
        let did = tenzro_types::did_derivation::machine_did(&sec1);
        let expected = tenzro_types::identity::attach_attestation_nonce(&did, &sender, 41);
        let tx = attachment(&signer, &sender, 41, |d, key, challenge| {
            assert_eq!(d, did);
            assert_eq!(key, &sec1[..]);
            assert_eq!(challenge, expected);
            Ok(tenzro_tee::tpm_attest::MachineAttestation {
                evidence: tenzro_tee::tpm_attest::TpmEvidence {
                    ek_public: vec![1],
                    ek_certificate: Vec::new(),
                    ek_intermediates: Vec::new(),
                    ak_public: vec![2],
                    quote: vec![3],
                    quote_signature: vec![4],
                },
                nonce: challenge.to_vec(),
                activated: true,
            })
        })
        .unwrap();
        let TransactionType::AttachMachineAttestation { op } = tx else {
            panic!("not an AttachMachineAttestation")
        };
        op.validate().unwrap();
        assert_eq!(op.did, did);
        let att: tenzro_tee::tpm_attest::MachineAttestation =
            serde_json::from_str(&op.attestation).unwrap();
        assert_eq!(att.nonce, expected.to_vec());
        let signature: tenzro_crypto::composite::CompositeSignature =
            serde_json::from_value(serde_json::to_value(&op.signature).unwrap()).unwrap();
        assert!(
            tenzro_crypto::composite::verify_composite(
                signer.public_key(),
                SignatureContext::IdentityRegistration,
                &op.statement(),
                &signature,
                tenzro_crypto::composite::PqPolicy::Required,
            )
            .is_ok(),
            "the identity key's signature over the attach statement verifies"
        );
        // An attestation the TPM could not make is not sent.
        let refused = attachment(&signer, &sender, 41, |_, _, _| Err("no TPM".into()));
        assert_eq!(refused.unwrap_err(), "no TPM");
    }

    /// An attach no later try can land is tried once and nothing more is
    /// sent.
    #[tokio::test(start_paused = true)]
    async fn an_attach_that_cannot_land_is_not_sent_again() {
        let tries = Arc::new(AtomicU32::new(0));
        let t = tries.clone();
        let stopped = attach_until_landed(
            || Observation::NotRegistered,
            move || {
                t.fetch_add(1, Ordering::SeqCst);
                async {
                    Err::<String, _>(AttachRefusal::Final(
                        "the TPM answers for another identity".into(),
                    ))
                }
            },
        )
        .await;
        assert_eq!(stopped.unwrap_err(), "the TPM answers for another identity");
        assert_eq!(tries.load(Ordering::SeqCst), 1);
    }

    /// Attaches that are sent and never land, or refused each time, end
    /// after a bounded number: the node account does not pay for them for
    /// ever.
    #[tokio::test(start_paused = true)]
    async fn attaches_that_never_land_end_after_a_bounded_number() {
        for sent in [true, false] {
            let tries = Arc::new(AtomicU32::new(0));
            let t = tries.clone();
            let stopped = attach_until_landed(
                || Observation::NotRegistered,
                move || {
                    t.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if sent {
                            Ok("0xabc".to_string())
                        } else {
                            Err(AttachRefusal::Retry("the key holder is unreachable".into()))
                        }
                    }
                },
            )
            .await;
            assert!(stopped.unwrap_err().contains("did not attach"));
            assert_eq!(tries.load(Ordering::SeqCst), ATTACH_ATTEMPTS);
        }
    }

    /// An attach that lands ends the loop with what was sent.
    #[tokio::test(start_paused = true)]
    async fn an_attach_that_lands_ends_the_loop() {
        let chain = Chain::new(3, 2);
        let c = chain.clone();
        let sent = attach_until_landed(
            {
                let c = chain.clone();
                move || c.observe()
            },
            move || {
                let c = c.clone();
                async move {
                    c.submissions.fetch_add(1, Ordering::SeqCst);
                    Ok("0xabc".to_string())
                }
            },
        )
        .await;
        assert_eq!(sent, Ok(2));
    }

    mod held_key {
        use super::*;
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use tenzro_device_key::remote::{
            Audit, Grant, KeyStore, Policy, Provider, RemoteTpmSigner, Transport, refusal,
        };
        use tenzro_device_key::{
            DeviceSignature, HardwareBackend, HardwareHybridSigner, HardwareSigner,
        };

        const LABEL: &str = "pi-1";

        struct Soft(SigningKey);
        impl HardwareSigner for Soft {
            fn backend(&self) -> HardwareBackend {
                HardwareBackend::Tpm
            }
            fn label(&self) -> &str {
                LABEL
            }
            fn public_key_sec1(&self) -> tenzro_device_key::Result<[u8; 65]> {
                Ok(self
                    .0
                    .verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .try_into()
                    .unwrap())
            }
            fn sign_prehash(
                &self,
                digest: &[u8; 32],
            ) -> tenzro_device_key::Result<DeviceSignature> {
                let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
                Ok(sig.to_bytes().into())
            }
        }

        struct Keys;
        impl KeyStore for Keys {
            fn open(&self, _label: &str) -> tenzro_device_key::Result<Box<dyn HardwareSigner>> {
                Ok(Box::new(Soft(SigningKey::from_slice(&[21u8; 32]).unwrap())))
            }
        }

        struct NoAudit;
        impl Audit for NoAudit {
            fn record(&self, _client: &[u8], _kind: &str, _outcome: &str) {}
        }

        /// A key holder's provider; `older` makes it refuse the attestation
        /// request kind (23) as a provider that predates it does.
        struct Holder {
            provider: Provider<Keys, NoAudit>,
            older: bool,
        }
        impl Transport for Holder {
            fn call(&self, request: &[u8]) -> tenzro_device_key::Result<Vec<u8>> {
                if self.older && request[1] == 23 {
                    return Ok(refusal("unknown request kind"));
                }
                Ok(self.provider.handle(b"client", request))
            }
        }

        /// The identity signer of a machine whose key `holder` holds.
        fn signer(attests_for: Option<&str>, older: bool) -> HardwareHybridSigner {
            let mut provider = Provider::new(
                Keys,
                NoAudit,
                Policy {
                    clients: std::collections::HashMap::from([(
                        b"client".to_vec(),
                        Grant {
                            label: LABEL.into(),
                            derived: false,
                        },
                    )]),
                    allowed_prefixes: vec![tenzro_crypto::composite::COMPOSITE_PREFIX.to_vec()],
                    allow_prehash: false,
                    per_minute: 10_000,
                    requests_per_minute: 100_000,
                    derived_prefixes: Vec::new(),
                },
            );
            if let Some(label) = attests_for {
                provider = provider.with_attestor(
                    label,
                    Arc::new(tenzro_tee::holder_attest::HolderAttestor(
                        tenzro_tee::tpm_attest::tests::SoftTpm::new(60),
                    )),
                );
            }
            let p256 = RemoteTpmSigner::open(Holder { provider, older }, LABEL).unwrap();
            HardwareHybridSigner::from_parts(Box::new(p256), None).unwrap()
        }

        fn root(signer: &HardwareHybridSigner) -> (String, Vec<u8>) {
            let sec1 = [&[0x04u8][..], &signer.public_key().p256].concat();
            (tenzro_types::did_derivation::machine_did(&sec1), sec1)
        }

        /// The holder's TPM attests the machine root at registration when
        /// its operator named this client.
        #[test]
        fn a_root_whose_holder_attests_registers_with_the_holders_attestation() {
            let signer = signer(Some(LABEL), false);
            let (did, key) = root(&signer);
            let metadata = registration_metadata(&signer, &did, &key, 0).unwrap();
            let att: tenzro_tee::tpm_attest::MachineAttestation =
                serde_json::from_str(&metadata[tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY])
                    .unwrap();
            assert!(att.activated);
            assert!(tenzro_tee::identity_evidence::tpm_evidence_binds(
                &did, &key, &att
            ));
        }

        /// A holder that predates attestation requests, one that names no
        /// client and one that names another all leave the root to register
        /// at once without an attestation, and the attach is told that no
        /// later try can succeed.
        #[test]
        fn a_root_whose_holder_does_not_attest_registers_without_an_attestation() {
            for signer in [
                signer(Some(LABEL), true),
                signer(None, false),
                signer(Some("pi-2"), false),
            ] {
                let (did, key) = root(&signer);
                let metadata = registration_metadata(&signer, &did, &key, 0).unwrap();
                assert!(metadata.is_empty(), "{metadata:?}");
                let (_, tx) = registration(&signer, [9u8; 32], metadata).unwrap();
                assert!(matches!(tx, TransactionType::RegisterIdentity { .. }));
                let refused = attest(&signer, &did, &key, [3u8; 32]).unwrap_err();
                assert!(refused.holder_declines, "{}", refused.message);
            }
        }
    }
}
