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
//! 3. Providers reply with an [`SlaResponse`] containing their Ed25519 sign
//!    over the canonical payload (`b"TENZRO_SLA_RESPONSE:" || nonce || deadline_le`).
//! 4. Misses, signature failures, or expired-deadline responses increment the
//!    bond's `failure_count` via [`ProviderSlashingCallback::record_probe_miss`].
//!    Once `failure_count` crosses the slash threshold, the manager calls
//!    [`ProviderSlashingCallback::slash_provider_bond`].
//!
//! The actual transport — gossipsub `tenzro/sla` for broadcast, optional HTTP
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

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tenzro_crypto::keys::{Address, PublicKey};
use tenzro_crypto::signatures::{verify, Signature, Signer};
use tenzro_crypto::vrf::{self, VrfProof, VrfPublicKey, VrfSecretKey, OUTPUT_LEN, PROOF_LEN};
use tracing::{debug, info, warn};

use crate::error::{ModelError, Result};

/// Domain tag for the VRF probe seed. SHA-256 over
/// `SLA_PROBE_DOMAIN || epoch_be || round_be || issuer_addr || provider_did`
/// produces the per-(round, provider) input to the VRF.
pub const SLA_PROBE_DOMAIN: &[u8] = b"TENZRO_SLA_PROBE:";

/// Domain tag for the response signing payload.
pub const SLA_RESPONSE_DOMAIN: &[u8] = b"TENZRO_SLA_RESPONSE:";

/// Default slash threshold — provider eats one slash per N consecutive misses.
pub const DEFAULT_SLA_SLASH_THRESHOLD: u32 = 5;

/// Default slash amount per crossing (in 1e18 TNZO units). Governance-tunable.
pub const DEFAULT_SLA_SLASH_AMOUNT: u128 = 10 * 1_000_000_000_000_000_000;

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
}

/// Provider response to an `SlaProbe`. Provider signs the canonical payload
/// `SLA_RESPONSE_DOMAIN || challenge_nonce || deadline_le` with their Ed25519
/// service key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaResponse {
    pub provider_did: String,
    pub provider_address: Address,
    pub challenge_nonce: [u8; 32],
    pub deadline_ms: i64,
    /// Wall-clock receipt time (unix millis) at the responder. Validator
    /// records its own `received_at` separately when applying the response.
    pub responded_at_ms: i64,
    /// Provider's Ed25519 signature over the canonical payload.
    pub signature: Signature,
    /// Provider's Ed25519 public key. Used to verify `signature`.
    pub public_key: PublicKey,
}

/// Outcome of applying one probe response. Drives the fault-detector state
/// machine: clean → reset counter; faulty → increment counter, possibly slash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlaResult {
    /// Response valid, on time — provider's failure counter is reset.
    Ok,
    /// Probe never answered before `deadline_ms`. Counter +1.
    Missed,
    /// Response received but signature didn't verify. Counter +1.
    InvalidSignature,
    /// Response received but the signed nonce/deadline didn't match the probe.
    /// Counter +1.
    Tampered,
    /// Response arrived after `deadline_ms`. Counter +1.
    Late,
}

impl SlaResult {
    /// `true` if this result counts as a probe failure for the bond's
    /// `failure_count` tally.
    pub fn is_failure(self) -> bool {
        !matches!(self, SlaResult::Ok)
    }

    /// Short structured code used as the `reason` parameter on
    /// `ComputeBondManager::slash`. Stable across releases.
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

/// Bridge between the SLA fault detector (lives in `tenzro-model`) and the
/// `ComputeBondManager` (lives in `tenzro-token`). Implementations live at
/// the node layer where both crates are in scope.
///
/// The async-trait shape mirrors `tenzro_consensus::SlashingCallback` so the
/// wiring at the node layer is symmetric across validator and provider
/// slashing paths.
#[async_trait]
pub trait ProviderSlashingCallback: Send + Sync {
    /// Record one probe miss against the provider's bond. Returns the
    /// updated failure counter. Hot path — called once per (provider, probe)
    /// that does NOT come back clean.
    async fn record_probe_miss(&self, provider_did: &str) -> Result<u32>;

    /// Reset the failure counter to zero. Called on every clean response.
    async fn reset_failure_count(&self, provider_did: &str) -> Result<()>;

    /// Slash the provider's bond by `amount` with the given structured
    /// reason code. Called once the failure counter crosses the threshold.
    /// On success the counter is reset; on terminal slash (bond exhausted)
    /// the provider is implicitly ejected.
    async fn slash_provider_bond(
        &self,
        provider_did: &str,
        amount: u128,
        reason: &str,
    ) -> Result<()>;
}

/// Validator-side SLA manager. Owns the VRF key, issues probes, applies
/// responses, escalates to slash through the injected callback.
pub struct SlaManager {
    /// Validator's address (issuer on emitted probes).
    issuer: Address,
    /// VRF signing key — Ed25519-compatible per RFC 9381.
    vrf_secret: VrfSecretKey,
    /// VRF public key (cached — derived once at construction).
    vrf_public: VrfPublicKey,
    /// Bridge into `ComputeBondManager` for failure tracking and slashing.
    bond_callback: Arc<dyn ProviderSlashingCallback>,
    /// Misses required before escalating to a slash. Default
    /// [`DEFAULT_SLA_SLASH_THRESHOLD`].
    slash_threshold: u32,
    /// Slash amount applied each time the threshold is crossed.
    slash_amount: u128,
}

impl SlaManager {
    /// Construct a new manager. `vrf_secret` must be the validator's
    /// Ed25519-compatible VRF signing key. The public key is derived
    /// internally so probe consumers can verify proofs without out-of-band
    /// key distribution.
    pub fn new(
        issuer: Address,
        vrf_secret: VrfSecretKey,
        bond_callback: Arc<dyn ProviderSlashingCallback>,
    ) -> Self {
        let vrf_public = vrf_secret.public_key();
        Self {
            issuer,
            vrf_secret,
            vrf_public,
            bond_callback,
            slash_threshold: DEFAULT_SLA_SLASH_THRESHOLD,
            slash_amount: DEFAULT_SLA_SLASH_AMOUNT,
        }
    }

    /// Override governance dials.
    pub fn with_governance(mut self, threshold: u32, slash_amount: u128) -> Self {
        self.slash_threshold = threshold;
        self.slash_amount = slash_amount;
        self
    }

    /// Compute the VRF input bytes for one (epoch, round, provider) tuple.
    /// Exposed so verifiers can reconstruct the input independently.
    pub fn vrf_input_for(
        issuer: &Address,
        epoch: u64,
        round: u64,
        provider_did: &str,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(SLA_PROBE_DOMAIN);
        hasher.update(epoch.to_be_bytes());
        hasher.update(round.to_be_bytes());
        hasher.update(issuer.as_bytes());
        hasher.update(provider_did.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Build the canonical payload that the provider signs in its response.
    /// `b"TENZRO_SLA_RESPONSE:" || challenge_nonce || deadline_le`.
    pub fn response_signing_payload(nonce: &[u8; 32], deadline_ms: i64) -> Vec<u8> {
        let mut out = Vec::with_capacity(SLA_RESPONSE_DOMAIN.len() + 32 + 8);
        out.extend_from_slice(SLA_RESPONSE_DOMAIN);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&deadline_ms.to_le_bytes());
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
    ) -> Result<SlaProbe> {
        let input = Self::vrf_input_for(&self.issuer, epoch, round, provider_did);
        let proof = vrf::prove(&self.vrf_secret, &input)
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

    /// Provider-side helper: build an [`SlaResponse`] for a probe by signing
    /// the canonical payload with the provider's Ed25519 service key. The
    /// signer is borrowed — caller decides how to manage the key (in-memory,
    /// TEE-sealed, etc).
    pub fn build_response<S: Signer>(
        probe: &SlaProbe,
        provider_address: Address,
        signer: &S,
        public_key: PublicKey,
        responded_at_ms: i64,
    ) -> Result<SlaResponse> {
        let payload = Self::response_signing_payload(&probe.challenge_nonce, probe.deadline_ms);
        let signature = signer
            .sign(&payload)
            .map_err(|e| ModelError::Other(format!("SLA response sign failed: {e}")))?;
        Ok(SlaResponse {
            provider_did: probe.provider_did.clone(),
            provider_address,
            challenge_nonce: probe.challenge_nonce,
            deadline_ms: probe.deadline_ms,
            responded_at_ms,
            signature,
            public_key,
        })
    }

    /// Score one response against the probe that originated it. Pure
    /// function — no callback side effects. The caller passes a
    /// `received_at_ms` separately so unit tests can simulate clock drift.
    pub fn score_response(
        probe: &SlaProbe,
        response: Option<&SlaResponse>,
        received_at_ms: i64,
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
        let payload = Self::response_signing_payload(&probe.challenge_nonce, probe.deadline_ms);
        match verify(&response.public_key, &payload, &response.signature) {
            Ok(()) => SlaResult::Ok,
            Err(_) => SlaResult::InvalidSignature,
        }
    }

    /// Apply one (probe, response) pair to the fault-detector state machine.
    /// Increments the failure counter on faults, resets on success, and
    /// escalates to a slash via the callback when the counter crosses
    /// `slash_threshold`.
    ///
    /// Returns the `SlaResult` for observability.
    pub async fn apply_response(
        &self,
        probe: &SlaProbe,
        response: Option<&SlaResponse>,
        received_at_ms: i64,
    ) -> Result<SlaResult> {
        let result = Self::score_response(probe, response, received_at_ms);
        if result.is_failure() {
            let new_count = self
                .bond_callback
                .record_probe_miss(&probe.provider_did)
                .await?;
            debug!(
                provider = %probe.provider_did,
                ?result,
                new_count,
                "SLA probe failure recorded"
            );
            if new_count >= self.slash_threshold {
                info!(
                    provider = %probe.provider_did,
                    threshold = self.slash_threshold,
                    "SLA slash threshold crossed — escalating"
                );
                self.bond_callback
                    .slash_provider_bond(
                        &probe.provider_did,
                        self.slash_amount,
                        result.as_reason(),
                    )
                    .await?;
                // The callback is responsible for resetting the counter on
                // a successful slash — we don't reset here to avoid a
                // double-decrement on TOCTOU races between detectors.
            }
        } else {
            // Clean response — reset the counter so a previously-flaky
            // provider gets credit for recovering.
            self.bond_callback
                .reset_failure_count(&probe.provider_did)
                .await
                .map_err(|e| {
                    warn!(
                        provider = %probe.provider_did,
                        error = %e,
                        "Failed to reset failure counter on clean SLA response"
                    );
                    e
                })?;
        }
        Ok(result)
    }

    /// Issuer's VRF public key. Exposed so peers can pre-fetch and verify
    /// probes without trusting on-the-wire key bytes alone.
    pub fn vrf_public_key(&self) -> &VrfPublicKey {
        &self.vrf_public
    }

    /// Currently configured slash threshold (probe failures).
    pub fn slash_threshold(&self) -> u32 {
        self.slash_threshold
    }

    /// Currently configured slash amount per crossing.
    pub fn slash_amount(&self) -> u128 {
        self.slash_amount
    }
}

/// Helper for the issuer side — compute the response signing payload
/// without instantiating an `SlaManager`. Exposed at the module root for
/// SDK/test ergonomics.
pub fn response_signing_payload(nonce: &[u8; 32], deadline_ms: i64) -> Vec<u8> {
    SlaManager::response_signing_payload(nonce, deadline_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use tenzro_crypto::keys::{KeyPair, KeyType};
    use tenzro_crypto::signatures::Ed25519SignerImpl;

    /// In-memory stub callback so the SlaManager unit tests can run without
    /// dragging `tenzro-token` into this crate's dev-deps.
    struct StubCallback {
        counts: Mutex<HashMap<String, u32>>,
        slashes: Mutex<Vec<(String, u128, String)>>,
    }

    impl StubCallback {
        fn new() -> Self {
            Self {
                counts: Mutex::new(HashMap::new()),
                slashes: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ProviderSlashingCallback for StubCallback {
        async fn record_probe_miss(&self, provider_did: &str) -> Result<u32> {
            let mut g = self.counts.lock();
            let c = g.entry(provider_did.to_string()).or_insert(0);
            *c += 1;
            Ok(*c)
        }

        async fn reset_failure_count(&self, provider_did: &str) -> Result<()> {
            let mut g = self.counts.lock();
            g.insert(provider_did.to_string(), 0);
            Ok(())
        }

        async fn slash_provider_bond(
            &self,
            provider_did: &str,
            amount: u128,
            reason: &str,
        ) -> Result<()> {
            self.slashes
                .lock()
                .push((provider_did.to_string(), amount, reason.to_string()));
            // Conventional reset after successful slash.
            self.counts.lock().insert(provider_did.to_string(), 0);
            Ok(())
        }
    }

    fn validator_setup() -> (Address, VrfSecretKey, Arc<StubCallback>) {
        // Deterministic seed for reproducible tests.
        let sk = VrfSecretKey([7u8; 32]);
        let issuer = Address::new([1u8; 20]);
        (issuer, sk, Arc::new(StubCallback::new()))
    }

    fn provider_keypair() -> (Address, Ed25519SignerImpl, PublicKey) {
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pk = kp.public_key().clone();
        let addr = pk.to_address();
        let signer = Ed25519SignerImpl::new(kp).unwrap();
        (addr, signer, pk)
    }

    #[tokio::test]
    async fn clean_response_resets_counter() {
        let (issuer, vrf, cb) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf, cb.clone());
        let (paddr, psigner, ppk) = provider_keypair();

        // Pre-populate a stale failure count so we can prove reset.
        cb.record_probe_miss("p1").await.unwrap();
        assert_eq!(cb.counts.lock().get("p1").copied().unwrap(), 1);

        let probe = mgr.issue_probe("p1", 0, 0, 10_000).unwrap();
        let response =
            SlaManager::build_response(&probe, paddr, &psigner, ppk, 5_000).unwrap();
        let result = mgr.apply_response(&probe, Some(&response), 6_000).await.unwrap();
        assert_eq!(result, SlaResult::Ok);
        assert_eq!(cb.counts.lock().get("p1").copied().unwrap(), 0);
        assert!(cb.slashes.lock().is_empty());
    }

    #[tokio::test]
    async fn missed_response_increments_counter() {
        let (issuer, vrf, cb) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf, cb.clone());
        let probe = mgr.issue_probe("p1", 0, 0, 1_000).unwrap();
        let result = mgr.apply_response(&probe, None, 2_000).await.unwrap();
        assert_eq!(result, SlaResult::Missed);
        assert_eq!(cb.counts.lock().get("p1").copied().unwrap(), 1);
        assert!(cb.slashes.lock().is_empty());
    }

    #[tokio::test]
    async fn late_response_counts_as_failure() {
        let (issuer, vrf, cb) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf, cb.clone());
        let (paddr, psigner, ppk) = provider_keypair();
        let probe = mgr.issue_probe("p1", 0, 0, 1_000).unwrap();
        let response =
            SlaManager::build_response(&probe, paddr, &psigner, ppk, 500).unwrap();
        // Receiver clock past the deadline.
        let result = mgr.apply_response(&probe, Some(&response), 2_000).await.unwrap();
        assert_eq!(result, SlaResult::Late);
        assert_eq!(cb.counts.lock().get("p1").copied().unwrap(), 1);
    }

    #[tokio::test]
    async fn tampered_nonce_rejected() {
        let (issuer, vrf, cb) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf, cb.clone());
        let (paddr, psigner, ppk) = provider_keypair();
        let probe = mgr.issue_probe("p1", 0, 0, 10_000).unwrap();
        let mut response =
            SlaManager::build_response(&probe, paddr, &psigner, ppk, 5_000).unwrap();
        response.challenge_nonce[0] ^= 0x01;
        let result = mgr.apply_response(&probe, Some(&response), 6_000).await.unwrap();
        assert_eq!(result, SlaResult::Tampered);
    }

    #[tokio::test]
    async fn invalid_signature_rejected() {
        let (issuer, vrf, cb) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf, cb.clone());
        let (paddr, psigner, ppk) = provider_keypair();
        let probe = mgr.issue_probe("p1", 0, 0, 10_000).unwrap();
        let response =
            SlaManager::build_response(&probe, paddr, &psigner, ppk, 5_000).unwrap();
        // Build a corrupted signature by flipping a byte in a re-constructed
        // Signature value.
        let mut sig_bytes = response.signature.to_bytes();
        sig_bytes[10] ^= 0x01;
        let bad_sig = Signature::new(KeyType::Ed25519, sig_bytes);
        let bad_response = SlaResponse {
            signature: bad_sig,
            ..response
        };
        let result = mgr.apply_response(&probe, Some(&bad_response), 6_000).await.unwrap();
        assert_eq!(result, SlaResult::InvalidSignature);
    }

    #[tokio::test]
    async fn threshold_crossing_triggers_slash() {
        let (issuer, vrf, cb) = validator_setup();
        // Threshold of 3 for fast test.
        let mgr = SlaManager::new(issuer, vrf, cb.clone()).with_governance(3, 100);
        for _ in 0..3 {
            let probe = mgr.issue_probe("p1", 0, 0, 1_000).unwrap();
            mgr.apply_response(&probe, None, 2_000).await.unwrap();
        }
        let slashes = cb.slashes.lock().clone();
        assert_eq!(slashes.len(), 1);
        assert_eq!(slashes[0].0, "p1");
        assert_eq!(slashes[0].1, 100);
        assert_eq!(slashes[0].2, "sla:probe_timeout");
        // Counter reset by callback after slash.
        assert_eq!(cb.counts.lock().get("p1").copied().unwrap(), 0);
    }

    #[test]
    fn probe_verifies_under_external_observer() {
        // Anyone with the probe can verify the VRF binding without holding
        // the issuer's secret key — closes the grinding attack class.
        let (issuer, vrf, cb) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf, cb);
        let probe = mgr.issue_probe("p1", 5, 2, 10_000).unwrap();
        SlaManager::verify_probe(&probe).expect("clean probe must verify");
    }

    #[test]
    fn tampered_probe_rejected_by_observer() {
        let (issuer, vrf, cb) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf, cb);
        let mut probe = mgr.issue_probe("p1", 5, 2, 10_000).unwrap();
        probe.challenge_nonce[0] ^= 0x01;
        assert!(SlaManager::verify_probe(&probe).is_err());
    }

    #[test]
    fn different_rounds_yield_different_nonces() {
        let (issuer, vrf, cb) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf, cb);
        let p0 = mgr.issue_probe("p1", 0, 0, 10_000).unwrap();
        let p1 = mgr.issue_probe("p1", 0, 1, 10_000).unwrap();
        let p2 = mgr.issue_probe("p1", 1, 0, 10_000).unwrap();
        assert_ne!(p0.challenge_nonce, p1.challenge_nonce);
        assert_ne!(p0.challenge_nonce, p2.challenge_nonce);
        assert_ne!(p1.challenge_nonce, p2.challenge_nonce);
    }

    #[test]
    fn different_providers_yield_different_nonces() {
        let (issuer, vrf, cb) = validator_setup();
        let mgr = SlaManager::new(issuer, vrf, cb);
        let p_a = mgr.issue_probe("p_a", 0, 0, 10_000).unwrap();
        let p_b = mgr.issue_probe("p_b", 0, 0, 10_000).unwrap();
        assert_ne!(p_a.challenge_nonce, p_b.challenge_nonce);
    }

    #[test]
    fn sla_result_reason_codes_are_stable() {
        // Pin the reason strings so downstream parsers can rely on them.
        assert_eq!(SlaResult::Ok.as_reason(), "sla:ok");
        assert_eq!(SlaResult::Missed.as_reason(), "sla:probe_timeout");
        assert_eq!(SlaResult::InvalidSignature.as_reason(), "sla:probe_invalid_sig");
        assert_eq!(SlaResult::Tampered.as_reason(), "sla:probe_tampered");
        assert_eq!(SlaResult::Late.as_reason(), "sla:probe_late");
    }
}
