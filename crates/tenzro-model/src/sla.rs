//! SLA challenge pipeline — VRF-driven liveness probes for staked providers.
//!
//! Validators run [`SlaManager::issue_probe`] periodically. Each round:
//!
//! 1. The validator generates a VRF proof over `epoch || round || provider_did`
//!    using its own Ed25519-compatible VRF key. The 64-byte VRF output is
//!    folded into a deterministic per-provider challenge nonce.
//! 2. For every active provider, the validator emits an [`SlaProbe`] carrying
//!    `(challenge_nonce, deadline_ms, vrf_proof, vrf_pubkey)`. The proof lets
//!    any third party verify the challenge was not retroactively forged after
//!    the response was sampled.
//! 3. Providers reply with an [`SlaResponse`] signed over the canonical
//!    payload (`b"TENZRO_SLA_RESPONSE:" || nonce || deadline_le`) by a session
//!    key their hardware identity key certified; validators verify it against
//!    the key registered for the subject.
//! 4. Misses, signature failures, or expired-deadline responses score as
//!    unavailable. The validator's per-epoch tally becomes its `SlaAttest`
//!    outcome; a provider the bonded stake freezes unavailable pays the
//!    governed penalty out of its compute bond in consensus.
//!
//! The actual transport — gossip `tenzro/sla` for broadcast, optional HTTP
//! direct probes for low-latency confirmation — is wired at the node layer. This
//! crate owns the protocol types, the VRF derivation, and the fault detector.
//!
//! ## Why VRF
//!
//! A signed nonce alone would let a malicious validator selectively challenge
//! competitors with hard-to-meet deadlines. With VRF, the challenge nonce is
//! verifiable-deterministic: given the validator's VRF public key, anyone can
//! confirm the nonce matches `(epoch, round, provider_did)` for that issuer —
//! no grinding.

use crate::error::{ModelError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_crypto::composite::CompositePublicKey;
use tenzro_crypto::keys::Address;
use tenzro_crypto::batch::RecordSigner;
#[cfg(test)]
use tenzro_crypto::vrf::VrfSecretKey;
use tenzro_crypto::vrf::{self, OUTPUT_LEN, PROOF_LEN, VrfProof, VrfProver, VrfPublicKey};

/// Domain tag for the VRF probe seed. SHA-256 over
/// `SLA_PROBE_DOMAIN || epoch_be || round_be || issuer_addr || provider_did`
/// produces the per-(round, provider) input to the VRF.
pub const SLA_PROBE_DOMAIN: &[u8] = b"TENZRO_SLA_PROBE:";

/// Domain tag for the response signing payload.
pub const SLA_RESPONSE_DOMAIN: &[u8] = b"TENZRO_SLA_RESPONSE:";

/// Shortest time a probe may give a provider to answer. A probe whose
/// deadline is already past, or a few milliseconds out, is a miss nobody could
/// avoid; since misses count toward an unavailable verdict, allowing one would
/// let whoever issues probes fault an honest provider.
pub const MIN_SLA_RESPONSE_WINDOW_MS: i64 = 10_000;

/// One SLA probe issued by a validator. Carries the verifiable-random
/// challenge nonce + the VRF proof anyone can use to confirm the nonce was
/// not forged. Wire format is bincode-serializable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaProbe {
    /// Validator issuing the probe.
    pub issuer: Address,
    /// Target provider DID (e.g. `did:tenzro:provider:p1`).
    pub provider_did: String,
    /// Validator-derived round identifier — `(epoch, round)` tuple flattened.
    pub epoch: u64,
    pub round: u64,
    /// 32-byte challenge nonce derived from the VRF output (first 32 bytes of
    /// `proof_to_hash(vrf_proof)`). Provider signs this in their response.
    pub challenge_nonce: [u8; 32],
    /// Response deadline (unix millis). Responses received after this point
    /// count as misses regardless of validity.
    pub deadline_ms: i64,
    /// 80-byte VRF proof letting anyone verify the nonce. Carried as raw
    /// bytes on the wire because `VrfProof` doesn't implement serde.
    /// Length-checked at parse time.
    pub vrf_proof: Vec<u8>,
    /// 32-byte VRF public key of the issuing validator.
    pub vrf_pubkey: [u8; 32],
    /// Work that measures the provider's capacity, of its track's kind. Bound
    /// into the VRF input, so nobody but the issuer can set it.
    pub work: Option<CapacityWork>,
}

/// Verifiable work a capacity probe asks for. Every input is derived from the
/// challenge nonce, so the issuer cannot pick work the provider has seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapacityWork {
    /// Generate up to `max_tokens` greedy tokens for [`inference_prompt`]
    /// with `model_id`, committing to them with a TOPLOC commitment any
    /// holder of the weights can re-check through an inference challenge.
    Inference { model_id: String, max_tokens: u32 },
    /// Prove the entries at [`state_read_keys`] under the committed state root
    /// at `height`.
    StateReads { height: u64, count: u32 },
    /// Multiply the `n × n` matrices derived from the nonce and open `rows`
    /// rows of the product (see [`crate::freivalds`]).
    Matmul { n: u32, rows: u32 },
    /// Prove possession of `samples` chunks of each object held for a paying
    /// renter, at positions the nonce selects.
    Possession { samples: u32 },
}

impl CapacityWork {
    /// Digest bound into the probe's VRF input.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"TENZRO_SLA_WORK:");
        h.update(bincode::serialize(self).unwrap_or_default());
        h.finalize().into()
    }
}

/// Namespace capacity state reads are proved in.
pub const STATE_READ_NAMESPACE: &str = "accounts";

/// Most state reads one capacity probe may ask for.
pub const MAX_STATE_READS: u32 = 64;

/// Most tokens one inference capacity probe may ask for.
pub const MAX_PROBE_TOKENS: u32 = 256;

/// The prompt an inference capacity probe asks the provider to complete.
pub fn inference_prompt(nonce: &[u8; 32]) -> String {
    format!(
        "Continue this sequence of hexadecimal words, one per line, without commentary: {}",
        hex::encode(nonce)
    )
}

/// The keys a state-read capacity probe asks the provider to prove.
pub fn state_read_keys(nonce: &[u8; 32], count: u32) -> Vec<Vec<u8>> {
    (0..count.min(MAX_STATE_READS))
        .map(|i| {
            let mut h = Sha256::new();
            h.update(b"TENZRO_SLA_STATE_READ:");
            h.update(nonce);
            h.update(i.to_be_bytes());
            h.finalize()[..20].to_vec()
        })
        .collect()
}

/// What a provider returns for a capacity probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapacityResult {
    /// The bincode-encoded TOPLOC commitment over the generated tokens.
    Inference {
        commitment: Vec<u8>,
        output_tokens: u32,
    },
    /// The state root at the probe's height and each entry's value and
    /// bincode-encoded proof, in key order.
    StateReads {
        root: [u8; 32],
        entries: Vec<StateReadEntry>,
    },
    /// The committed product and its opened rows.
    Matmul(crate::freivalds::MatmulProof),
    /// One entry per storage claim proven.
    Possession { deals: Vec<PossessionDeal> },
}

/// Possession of one object stored under a held storage claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PossessionDeal {
    /// The storage claim that pays for the object.
    pub claim_id: String,
    /// bincode-encoded object descriptor, with its shard commitments.
    pub descriptor: Vec<u8>,
    /// bincode-encoded possession proof for the nonce's positions.
    pub proof: Vec<u8>,
}

/// Most storage claims one possession probe answer may carry.
pub const MAX_POSSESSION_DEALS: usize = 16;

/// The possession-challenge nonce for one storage claim of a probe.
pub fn possession_nonce(nonce: &[u8; 32], claim_id: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"TENZRO_SLA_POSSESSION:");
    h.update(nonce);
    h.update(claim_id.as_bytes());
    h.finalize().into()
}

/// One proved state entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateReadEntry {
    pub value: Option<Vec<u8>>,
    pub proof: Vec<u8>,
}

/// Provider response to an `SlaProbe`. The provider signs the canonical
/// payload `SLA_RESPONSE_DOMAIN || challenge_nonce || deadline_le` in a
/// hardware batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaResponse<S = tenzro_crypto::batch::BatchedSignature> {
    pub provider_did: String,
    /// The account answering for the subject: the bond or stake owner.
    pub provider_address: tenzro_types::primitives::Address,
    pub challenge_nonce: [u8; 32],
    pub deadline_ms: i64,
    /// Wall-clock receipt time (unix millis) at the responder. Validator
    /// records its own `received_at` separately when applying the response.
    pub responded_at_ms: i64,
    /// Batch signature over the canonical payload. Verified against the key
    /// registered for the subject, never against a key the response carries.
    pub signature: S,
    /// The work a capacity probe asked for, covered by `signature`.
    pub result: Option<CapacityResult>,
}

/// What travels on the `tenzro/sla` topic. Probes and responses share the
/// topic and bincode carries no type information, so without the variant tag
/// a probe would be handed to the response decoder and misparse into a
/// length prefix large enough to attempt a multi-gigabyte allocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlaEnvelope {
    Probe(SlaProbe),
    Response(SlaResponse),
}

/// A signature on an SLA response that can be checked against the
/// subject's registered hardware identity key.
pub trait SlaSignature {
    fn verified_by(&self, key: &CompositePublicKey, payload: &[u8]) -> bool;
}

impl SlaSignature for tenzro_crypto::batch::BatchedSignature {
    fn verified_by(&self, key: &CompositePublicKey, payload: &[u8]) -> bool {
        self.verify(
            key,
            payload,
            tenzro_crypto::session::now_ms(),
            tenzro_crypto::batch::batch_skew_ms(),
        )
        .is_ok()
    }
}

/// Marks a response whose signature was already checked. It cannot be read
/// from the wire; only [`AnySlaResponse::into_verified`] makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified;

impl SlaSignature for Verified {
    fn verified_by(&self, _key: &CompositePublicKey, _payload: &[u8]) -> bool {
        true
    }
}

impl SlaResponse {
    /// The response with its signature checked against `registered`, or
    /// `None` when it is not signed by that key.
    pub fn into_verified(
        self,
        registered: Option<&CompositePublicKey>,
    ) -> Option<SlaResponse<Verified>> {
        SlaManager::signed_by(&self, registered).then(|| self.strip())
    }
}

impl<S> SlaResponse<S> {
    fn strip(self) -> SlaResponse<Verified> {
        SlaResponse {
            provider_did: self.provider_did,
            provider_address: self.provider_address,
            challenge_nonce: self.challenge_nonce,
            deadline_ms: self.deadline_ms,
            responded_at_ms: self.responded_at_ms,
            signature: Verified,
            result: self.result,
        }
    }
}

impl SlaEnvelope {
    /// The response this payload carries; `None` for a probe.
    pub fn into_response(self) -> Option<SlaResponse> {
        match self {
            Self::Probe(_) => None,
            Self::Response(r) => Some(r),
        }
    }
}

/// An SLA response whose batch signature is not made yet.
pub struct PendingSlaResponse {
    provider_did: String,
    provider_address: tenzro_types::primitives::Address,
    challenge_nonce: [u8; 32],
    deadline_ms: i64,
    responded_at_ms: i64,
    result: Option<CapacityResult>,
    ticket: tenzro_crypto::batch::Ticket,
}

impl PendingSlaResponse {
    pub fn finish(self, timeout: std::time::Duration) -> Result<SlaResponse> {
        let signature = self
            .ticket
            .wait(timeout)
            .map_err(|e| ModelError::Other(format!("SLA response sign failed: {e}")))?;
        Ok(SlaResponse {
            provider_did: self.provider_did,
            provider_address: self.provider_address,
            challenge_nonce: self.challenge_nonce,
            deadline_ms: self.deadline_ms,
            responded_at_ms: self.responded_at_ms,
            signature,
            result: self.result,
        })
    }
}

/// Score of one probe response. Anything but `Ok` counts the provider
/// unavailable for that probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlaResult {
    /// Response valid and on time.
    Ok,
    /// Probe never answered before `deadline_ms`.
    Missed,
    /// Response received but signature didn't verify.
    InvalidSignature,
    /// Response received but the signed nonce/deadline didn't match the probe.
    Tampered,
    /// Response arrived after `deadline_ms`.
    Late,
}

impl SlaResult {
    /// `true` if this result counts the provider unavailable for the probe.
    pub fn is_failure(self) -> bool {
        !matches!(self, SlaResult::Ok)
    }

    /// Short structured code for logs and readers. Stable across releases.
    pub fn as_reason(self) -> &'static str {
        match self {
            SlaResult::Ok => "sla:ok",
            SlaResult::Missed => "sla:probe_timeout",
            SlaResult::InvalidSignature => "sla:probe_invalid_sig",
            SlaResult::Tampered => "sla:probe_tampered",
            SlaResult::Late => "sla:probe_late",
        }
    }
}

/// Validator-side SLA manager. Owns the VRF key, issues probes and scores
/// responses.
pub struct SlaManager {
    /// Validator's address (issuer on emitted probes).
    issuer: Address,
    /// VRF prover over the validator's Ed25519-compatible key (RFC 9381).
    vrf: Box<dyn VrfProver>,
    /// VRF public key (cached — derived once at construction).
    vrf_public: VrfPublicKey,
}

impl SlaManager {
    /// Construct a new manager. `vrf` proves with the validator's
    /// Ed25519-compatible VRF key. Its public key is cached so probe consumers
    /// can verify proofs without out-of-band key distribution.
    pub fn new(issuer: Address, vrf: impl VrfProver + 'static) -> Self {
        let vrf_public = vrf.public_key();
        Self {
            issuer,
            vrf: Box::new(vrf),
            vrf_public,
        }
    }

    /// Compute the VRF input bytes for one (epoch, round, provider) tuple.
    /// Exposed so verifiers can reconstruct the input independently.
    pub fn vrf_input_for(
        issuer: &Address,
        epoch: u64,
        round: u64,
        provider_did: &str,
        work: Option<&CapacityWork>,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(SLA_PROBE_DOMAIN);
        hasher.update(epoch.to_be_bytes());
        hasher.update(round.to_be_bytes());
        hasher.update(issuer.as_bytes());
        hasher.update(provider_did.as_bytes());
        if let Some(work) = work {
            hasher.update(work.digest());
        }
        hasher.finalize().to_vec()
    }

    /// Build the canonical payload that the provider signs in its response.
    /// `b"TENZRO_SLA_RESPONSE:" || challenge_nonce || deadline_le`.
    pub fn response_signing_payload(
        nonce: &[u8; 32],
        deadline_ms: i64,
        result: Option<&CapacityResult>,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(SLA_RESPONSE_DOMAIN.len() + 32 + 8 + 32);
        out.extend_from_slice(SLA_RESPONSE_DOMAIN);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&deadline_ms.to_le_bytes());
        if let Some(result) = result {
            let mut h = Sha256::new();
            h.update(bincode::serialize(result).unwrap_or_default());
            out.extend_from_slice(&h.finalize());
        }
        out
    }

    /// Issue one probe for `provider_did` at `(epoch, round)`. Generates the
    /// VRF proof, derives the 32-byte challenge nonce, and stamps the
    /// deadline. Does NOT broadcast — the caller is responsible for routing
    /// the probe over its preferred transport.
    pub fn issue_probe(
        &self,
        provider_did: &str,
        epoch: u64,
        round: u64,
        deadline_ms: i64,
        work: Option<CapacityWork>,
    ) -> Result<SlaProbe> {
        let input = Self::vrf_input_for(&self.issuer, epoch, round, provider_did, work.as_ref());
        let proof = self
            .vrf
            .prove(&input)
            .map_err(|e| ModelError::Other(format!("VRF prove failed: {e}")))?;
        // Issuer just produced the proof — extracting the output without
        // re-verifying is sound here; external observers re-verify via
        // `Self::verify_probe`.
        let hash = vrf::proof_output(&proof)
            .map_err(|e| ModelError::Other(format!("VRF proof_output failed: {e}")))?;
        let mut challenge_nonce = [0u8; 32];
        challenge_nonce.copy_from_slice(&hash.as_bytes()[..32]);
        Ok(SlaProbe {
            issuer: self.issuer,
            provider_did: provider_did.to_string(),
            epoch,
            round,
            challenge_nonce,
            deadline_ms,
            vrf_proof: proof.as_bytes().to_vec(),
            vrf_pubkey: self.vrf_public.0,
            work,
        })
    }

    /// Public verifier — given a probe, confirm that the VRF proof is valid
    /// and that the challenge_nonce matches the proof's deterministic output.
    /// Used by independent observers (other validators, light clients) to
    /// reject grindings.
    pub fn verify_probe(probe: &SlaProbe) -> Result<()> {
        if probe.vrf_proof.len() != PROOF_LEN {
            return Err(ModelError::Other(format!(
                "VRF proof must be {PROOF_LEN} bytes, got {}",
                probe.vrf_proof.len()
            )));
        }
        let proof = VrfProof::from_bytes(&probe.vrf_proof)
            .map_err(|e| ModelError::Other(format!("VRF proof decode failed: {e}")))?;
        let pk = VrfPublicKey(probe.vrf_pubkey);
        let input = Self::vrf_input_for(
            &probe.issuer,
            probe.epoch,
            probe.round,
            &probe.provider_did,
            probe.work.as_ref(),
        );
        let output = vrf::verify(&pk, &input, &proof)
            .map_err(|e| ModelError::Other(format!("VRF proof invalid: {e}")))?;
        if &output.as_bytes()[..32] != probe.challenge_nonce.as_slice() {
            return Err(ModelError::Other(
                "challenge_nonce does not match VRF output".to_string(),
            ));
        }
        // Sanity: declared output length is what we sliced.
        debug_assert_eq!(output.as_bytes().len(), OUTPUT_LEN);
        Ok(())
    }

    /// Provider-side helper: build an [`SlaResponse`] for a probe, signed at
    /// once by `signer`. The node answers through
    /// [`SlaManager::start_response`], which waits on the batch ticker.
    pub fn build_response(
        probe: &SlaProbe,
        provider_address: tenzro_types::primitives::Address,
        signer: &dyn RecordSigner,
        responded_at_ms: i64,
        result: Option<CapacityResult>,
    ) -> Result<SlaResponse> {
        let payload = Self::response_signing_payload(
            &probe.challenge_nonce,
            probe.deadline_ms,
            result.as_ref(),
        );
        let signature = signer
            .sign_record(&payload)
            .map_err(|e| ModelError::Other(format!("SLA response sign failed: {e}")))?
            .batched;
        Ok(SlaResponse {
            provider_did: probe.provider_did.clone(),
            provider_address,
            challenge_nonce: probe.challenge_nonce,
            deadline_ms: probe.deadline_ms,
            responded_at_ms,
            signature,
            result,
        })
    }

    /// Provider-side: an [`SlaResponse`] signed by the identity key's hardware
    /// in a batch. Finish it with [`PendingSlaResponse::finish`].
    pub fn start_response(
        probe: &SlaProbe,
        provider_address: tenzro_types::primitives::Address,
        service: &tenzro_crypto::batch::BatchService,
        responded_at_ms: i64,
        result: Option<CapacityResult>,
        now_ms: u64,
    ) -> Result<PendingSlaResponse> {
        let payload = Self::response_signing_payload(
            &probe.challenge_nonce,
            probe.deadline_ms,
            result.as_ref(),
        );
        let ticket = service
            .submit(payload, now_ms)
            .map_err(|e| ModelError::Other(format!("SLA response sign failed: {e}")))?;
        Ok(PendingSlaResponse {
            provider_did: probe.provider_did.clone(),
            provider_address,
            challenge_nonce: probe.challenge_nonce,
            deadline_ms: probe.deadline_ms,
            responded_at_ms,
            result,
            ticket,
        })
    }

    /// Whether `response` is signed by `registered`, the hardware identity
    /// key registered for its subject. A response that is not is ignored
    /// rather than scored: scoring it would let any peer answer badly first
    /// and get an honest provider marked failing.
    pub fn signed_by<S: SlaSignature>(
        response: &SlaResponse<S>,
        registered: Option<&CompositePublicKey>,
    ) -> bool {
        let Some(key) = registered else { return false };
        let payload = Self::response_signing_payload(
            &response.challenge_nonce,
            response.deadline_ms,
            response.result.as_ref(),
        );
        response.signature.verified_by(key, &payload)
    }

    /// Score one response against the probe that originated it, checking its
    /// signature against `registered`. Pure function — no callback side
    /// effects. The caller passes a `received_at_ms` separately so unit tests
    /// can simulate clock drift.
    pub fn score_response<S: SlaSignature>(
        probe: &SlaProbe,
        response: Option<&SlaResponse<S>>,
        received_at_ms: i64,
        registered: Option<&CompositePublicKey>,
    ) -> SlaResult {
        let response = match response {
            Some(r) => r,
            None => return SlaResult::Missed,
        };
        if response.challenge_nonce != probe.challenge_nonce
            || response.deadline_ms != probe.deadline_ms
            || response.provider_did != probe.provider_did
        {
            return SlaResult::Tampered;
        }
        if received_at_ms > probe.deadline_ms {
            return SlaResult::Late;
        }
        if Self::signed_by(response, registered) {
            SlaResult::Ok
        } else {
            SlaResult::InvalidSignature
        }
    }

    /// Issuer's VRF public key. Exposed so peers can pre-fetch and verify
    /// probes without trusting on-the-wire key bytes alone.
    pub fn vrf_public_key(&self) -> &VrfPublicKey {
        &self.vrf_public
    }
}

/// Helper for the issuer side — compute the response signing payload
/// without instantiating an `SlaManager`. Exposed at the module root for
/// SDK/test ergonomics.
pub fn response_signing_payload(
    nonce: &[u8; 32],
    deadline_ms: i64,
    result: Option<&CapacityResult>,
) -> Vec<u8> {
    SlaManager::response_signing_payload(nonce, deadline_ms, result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::batch::ImmediateRecordSigner;

    #[test]
    fn the_envelope_bytes_are_golden_and_a_batched_response_scores_ok() {
        use tenzro_crypto::batch::{BatchParams, BatchService};
        let (issuer, vrf) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf);
        let probe = mgr.issue_probe("p1", 0, 0, 10_000, None).unwrap();

        // A response travels as variant 1, scores Ok for the registered
        // identity, and not for another identity.
        let id = std::sync::Arc::new(tenzro_crypto::composite::testing::TestHybridSigner::hybrid(
            71,
        ));
        let registered = tenzro_crypto::composite::HybridSigner::public_key(id.as_ref()).clone();
        let svc = BatchService::new(
            id,
            BatchParams {
                max_batch: 1,
                flush_interval_ms: 1_000,
            },
            0,
        )
        .unwrap();
        let (paddr, _s, _p) = provider_keypair();
        let pending = SlaManager::start_response(
            &probe,
            paddr,
            &svc,
            5_000,
            None,
            tenzro_crypto::session::now_ms(),
        )
        .unwrap();
        let resp = pending
            .finish(std::time::Duration::from_millis(50))
            .unwrap();
        let bytes = bincode::serialize(&SlaEnvelope::Response(resp)).unwrap();
        assert_eq!(&bytes[..4], &1u32.to_le_bytes());
        let any = bincode::deserialize::<SlaEnvelope>(&bytes)
            .unwrap()
            .into_response()
            .unwrap();
        let verified = any.clone().into_verified(Some(&registered)).unwrap();
        assert_eq!(
            SlaManager::score_response(&probe, Some(&verified), 6_000, Some(&registered)),
            SlaResult::Ok
        );
        let (_a, _s, other) = provider_keypair();
        assert!(any.into_verified(Some(&other)).is_none());
    }

    fn validator_setup() -> (Address, VrfSecretKey) {
        // Deterministic seed for reproducible tests.
        (Address::new([1u8; 20]), VrfSecretKey([7u8; 32]))
    }

    /// A provider's record signer and the identity key registered for it.
    fn provider_keypair() -> (
        tenzro_types::primitives::Address,
        ImmediateRecordSigner,
        CompositePublicKey,
    ) {
        let signer = ImmediateRecordSigner::new(std::sync::Arc::new(
            tenzro_crypto::testing::TestHybridSigner::random(),
        ));
        let pk = signer.identity().clone();
        (
            tenzro_types::primitives::Address::new([3u8; 32]),
            signer,
            pk,
        )
    }

    #[test]
    fn a_clean_response_scores_ok() {
        let (issuer, vrf) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf);
        let (paddr, psigner, ppk) = provider_keypair();
        let probe = mgr.issue_probe("p1", 0, 0, 10_000, None).unwrap();
        let response = SlaManager::build_response(&probe, paddr, &psigner, 5_000, None).unwrap();
        assert_eq!(
            SlaManager::score_response(&probe, Some(&response), 6_000, Some(&ppk)),
            SlaResult::Ok
        );
    }

    #[test]
    fn a_missed_response_is_a_failure() {
        let (issuer, vrf) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf);
        let probe = mgr.issue_probe("p1", 0, 0, 1_000, None).unwrap();
        let result = SlaManager::score_response::<Verified>(&probe, None, 2_000, None);
        assert_eq!(result, SlaResult::Missed);
        assert!(result.is_failure());
    }

    #[test]
    fn a_late_response_is_a_failure() {
        let (issuer, vrf) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf);
        let (paddr, psigner, ppk) = provider_keypair();
        let probe = mgr.issue_probe("p1", 0, 0, 1_000, None).unwrap();
        let response = SlaManager::build_response(&probe, paddr, &psigner, 500, None).unwrap();
        assert_eq!(
            SlaManager::score_response(&probe, Some(&response), 2_000, Some(&ppk)),
            SlaResult::Late
        );
    }

    #[test]
    fn tampered_nonce_rejected() {
        let (issuer, vrf) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf);
        let (paddr, psigner, ppk) = provider_keypair();
        let probe = mgr.issue_probe("p1", 0, 0, 10_000, None).unwrap();
        let mut response =
            SlaManager::build_response(&probe, paddr, &psigner, 5_000, None).unwrap();
        response.challenge_nonce[0] ^= 0x01;
        assert_eq!(
            SlaManager::score_response(&probe, Some(&response), 6_000, Some(&ppk)),
            SlaResult::Tampered
        );
    }

    #[test]
    fn invalid_signature_rejected() {
        let (issuer, vrf) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf);
        let (paddr, psigner, ppk) = provider_keypair();
        let probe = mgr.issue_probe("p1", 0, 0, 10_000, None).unwrap();
        let response = SlaManager::build_response(&probe, paddr, &psigner, 5_000, None).unwrap();
        // Signed by an identity other than the one registered.
        let (_a, other_signer, _o) = provider_keypair();
        let bad_response =
            SlaManager::build_response(&probe, paddr, &other_signer, 5_000, None).unwrap();
        assert_eq!(
            SlaManager::score_response(&probe, Some(&bad_response), 6_000, Some(&ppk)),
            SlaResult::InvalidSignature
        );
        // Signed by the provider, but checked against another identity, or
        // against none: not the subject's answer.
        let (_, _, other) = provider_keypair();
        assert!(!SlaManager::signed_by(&response, Some(&other)));
        assert!(!SlaManager::signed_by(&response, None));
        assert!(SlaManager::signed_by(&response, Some(&ppk)));
    }

    #[test]
    fn probe_verifies_under_external_observer() {
        // Anyone with the probe can verify the VRF binding without holding
        // the issuer's secret key — closes the grinding attack class.
        let (issuer, vrf) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf);
        let probe = mgr.issue_probe("p1", 5, 2, 10_000, None).unwrap();
        SlaManager::verify_probe(&probe).expect("clean probe must verify");
    }

    #[test]
    fn tampered_probe_rejected_by_observer() {
        let (issuer, vrf) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf);
        let mut probe = mgr.issue_probe("p1", 5, 2, 10_000, None).unwrap();
        probe.challenge_nonce[0] ^= 0x01;
        assert!(SlaManager::verify_probe(&probe).is_err());
    }

    #[test]
    fn different_rounds_yield_different_nonces() {
        let (issuer, vrf) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf);
        let p0 = mgr.issue_probe("p1", 0, 0, 10_000, None).unwrap();
        let p1 = mgr.issue_probe("p1", 0, 1, 10_000, None).unwrap();
        let p2 = mgr.issue_probe("p1", 1, 0, 10_000, None).unwrap();
        assert_ne!(p0.challenge_nonce, p1.challenge_nonce);
        assert_ne!(p0.challenge_nonce, p2.challenge_nonce);
        assert_ne!(p1.challenge_nonce, p2.challenge_nonce);
    }

    #[test]
    fn different_providers_yield_different_nonces() {
        let (issuer, vrf) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf);
        let p_a = mgr.issue_probe("p_a", 0, 0, 10_000, None).unwrap();
        let p_b = mgr.issue_probe("p_b", 0, 0, 10_000, None).unwrap();
        assert_ne!(p_a.challenge_nonce, p_b.challenge_nonce);
    }

    #[test]
    fn sla_result_reason_codes_are_stable() {
        // Pin the reason strings so downstream parsers can rely on them.
        assert_eq!(SlaResult::Ok.as_reason(), "sla:ok");
        assert_eq!(SlaResult::Missed.as_reason(), "sla:probe_timeout");
        assert_eq!(
            SlaResult::InvalidSignature.as_reason(),
            "sla:probe_invalid_sig"
        );
        assert_eq!(SlaResult::Tampered.as_reason(), "sla:probe_tampered");
        assert_eq!(SlaResult::Late.as_reason(), "sla:probe_late");
    }

    #[test]
    fn capacity_work_is_bound_to_the_issuers_vrf() {
        let (issuer, vrf) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf);
        let work = CapacityWork::StateReads {
            height: 7,
            count: 8,
        };
        let mut probe = mgr.issue_probe("p1", 5, 2, 10_000, Some(work)).unwrap();
        SlaManager::verify_probe(&probe).expect("issuer's work verifies");
        // A peer relaying the probe cannot swap in heavier work.
        probe.work = Some(CapacityWork::StateReads {
            height: 7,
            count: 64,
        });
        assert!(SlaManager::verify_probe(&probe).is_err());
        probe.work = None;
        assert!(SlaManager::verify_probe(&probe).is_err());
    }

    #[test]
    fn a_capacity_result_is_covered_by_the_providers_signature() {
        let (issuer, vrf) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf);
        let (paddr, psigner, ppk) = provider_keypair();
        let probe = mgr
            .issue_probe(
                "p1",
                0,
                0,
                10_000,
                Some(CapacityWork::StateReads {
                    height: 1,
                    count: 2,
                }),
            )
            .unwrap();
        let result = CapacityResult::StateReads {
            root: [9; 32],
            entries: vec![],
        };
        let mut response =
            SlaManager::build_response(&probe, paddr, &psigner, 5_000, Some(result)).unwrap();
        assert_eq!(
            SlaManager::score_response(&probe, Some(&response), 6_000, Some(&ppk)),
            SlaResult::Ok
        );
        response.result = Some(CapacityResult::StateReads {
            root: [8; 32],
            entries: vec![],
        });
        assert_eq!(
            SlaManager::score_response(&probe, Some(&response), 6_000, Some(&ppk)),
            SlaResult::InvalidSignature
        );
    }

    #[test]
    fn probe_inputs_derive_from_the_nonce() {
        let a = state_read_keys(&[1; 32], 4);
        assert_eq!(a.len(), 4);
        assert_ne!(a, state_read_keys(&[2; 32], 4));
        assert_eq!(
            state_read_keys(&[1; 32], 1_000).len(),
            MAX_STATE_READS as usize
        );
        assert_ne!(inference_prompt(&[1; 32]), inference_prompt(&[2; 32]));
    }
}
