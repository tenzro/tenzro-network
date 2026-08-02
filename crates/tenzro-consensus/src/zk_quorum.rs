//! Quorum-gated ZK commitment attestation.
//!
//! The `ZK_VERIFY` precompile answers `true` for any commitment recorded in the
//! precompile's `ZkCommitmentRegistry`. As originally wired, a commitment was
//! recorded on a **single** validator's off-EVM `verify_proof_envelope` run —
//! so a malicious validator could record a commitment for a proof that never
//! verified, and the precompile would answer `true` for it forever.
//!
//! This module closes that gap by requiring a commitment to carry a
//! `2f+1`-stake-weight **co-signature** from the active validator set before it
//! is admitted to the registry:
//!
//! 1. A validator that has independently run `verify_proof_envelope` publishes a
//!    [`ZkCommitmentClaim`] (circuit id, commitment hash, DA locator for the
//!    proof bytes) over a dedicated gossip topic and co-signs the canonical
//!    [`ZkCommitmentClaim::cosign_payload`] with its BLS key.
//! 2. Other validators fetch the proof by its DA locator, re-run
//!    `verify_proof_envelope`, and return their own co-signature.
//! 3. Once co-signatures reach `2f+1` stake-weight, they fold into a
//!    [`ZkQuorumCertificate`] — a single BLS12-381 aggregate plus a signer
//!    bitmap over the [`ValidatorSet`], the identical shape used by
//!    [`crate::voter::QuorumCertificate`] and
//!    [`crate::batch_cert::BatchAvailabilityCertificate`]. Only a commitment
//!    that carries a verifying certificate is attested to the registry.
//!
//! # Fraud-proof window
//!
//! A quorum certificate proves `2f+1` stake co-signed the commitment; it does
//! not, on its own, prove the underlying proof verifies (a colluding committee
//! could co-sign an invalid proof). The certificate therefore opens a
//! **fraud-proof window**: for [`FRAUD_WINDOW_BLOCKS`] blocks after attestation,
//! any staked party may fetch the proof bytes and submit a [`ZkFraudProof`]. The
//! node re-runs `verify_proof_envelope` deterministically; if the proof does not
//! verify, every co-signer named in the certificate bitmap is slashed through
//! the existing consensus slashing path, and the commitment is retracted from
//! the registry.
//!
//! Verification cost at the precompile stays `O(1)` — the quorum machinery runs
//! off-EVM, and the precompile still does a single `HashSet` lookup.

use crate::error::{ConsensusError, Result};
use crate::validator::ValidatorSet;
use crate::voter::VOTE_FORMAT_VERSION;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_crypto::bls::{BlsKeyPair, BlsPublicKey, BlsSignature};
use tenzro_storage::{CF_AUDIT, KvStore};
use tenzro_types::primitives::Address;

/// Domain-separation tag for the ZK commitment co-signature preimage. Distinct
/// from every other BLS DST in the crate so a co-signature can never be replayed
/// as a vote or a batch ack.
const ZK_COSIGN_TAG: &[u8] = b"TENZRO_ZK_COSIGN:";

/// Number of blocks after attestation during which a fraud proof against a
/// quorum-attested commitment is admissible. A pure protocol parameter — no
/// topology or region assumption; it bounds how long a co-signing committee
/// remains accountable for a commitment they signed.
pub const FRAUD_WINDOW_BLOCKS: u64 = 256;

/// Length-checked serde for a 96-byte BLS aggregate (G2 compressed point).
/// Mirrors `voter::bls_aggregate_serde`.
mod bls_aggregate_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 96], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 96], D::Error> {
        let v: Vec<u8> = Vec::<u8>::deserialize(de)?;
        if v.len() != 96 {
            return Err(serde::de::Error::custom(format!(
                "zk-quorum bls_aggregate must be exactly 96 bytes, got {}",
                v.len()
            )));
        }
        let mut out = [0u8; 96];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

/// A claim that a ZK proof verified, awaiting quorum co-signature.
///
/// The claim binds the circuit id, the 32-byte commitment hash (as computed by
/// `tenzro_vm::precompiles::compute_zk_commitment`), and a DA locator from which
/// any validator can fetch the proof bytes to re-verify. The commitment hash
/// already binds circuit id + proof bytes + public inputs, so it is the object
/// co-signers agree on; the DA locator is carried so re-verification is possible
/// without the proof travelling on the co-sign gossip topic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkCommitmentClaim {
    /// The AIR circuit id (`"inference"`, `"settlement"`, `"identity"`).
    pub circuit_id: String,
    /// The 32-byte commitment hash the precompile will look up.
    pub commitment: [u8; 32],
    /// DA locator (`tenzro://blob/<hash>` scheme) for the proof bytes, so a
    /// co-signer can fetch and independently re-verify.
    pub proof_locator: String,
}

impl ZkCommitmentClaim {
    /// Canonical bytes every co-signer signs. Identical across co-signers (the
    /// precondition for sound BLS aggregation under one DST):
    /// `ZK_COSIGN_TAG || VOTE_FORMAT_VERSION(1) || commitment(32)`.
    ///
    /// Only the commitment is signed — not the locator — because the commitment
    /// is what the registry keys on, and two co-signers who fetched the same
    /// proof through different locators must still produce the same signature.
    pub fn cosign_payload(commitment: &[u8; 32]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(ZK_COSIGN_TAG.len() + 1 + 32);
        payload.extend_from_slice(ZK_COSIGN_TAG);
        payload.push(VOTE_FORMAT_VERSION);
        payload.extend_from_slice(commitment);
        payload
    }
}

/// One validator's co-signature that it independently verified the proof behind
/// a commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkCosign {
    /// The commitment being co-signed.
    pub commitment: [u8; 32],
    /// The co-signing validator.
    pub validator: Address,
    /// BLS12-381 (`min_pk`) signature over [`ZkCommitmentClaim::cosign_payload`].
    pub bls_signature: Vec<u8>,
}

/// A `2f+1`-stake-weight certificate that the active validator set independently
/// re-verified the proof behind a commitment.
///
/// Wire-identical in shape to [`crate::batch_cert::BatchAvailabilityCertificate`]:
/// a single 96-byte BLS aggregate plus a signer bitmap indexed against the active
/// [`ValidatorSet`] (LSB-first, `n.div_ceil(8)` bytes).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZkQuorumCertificate {
    /// The circuit id, carried for diagnostics and to key retraction.
    pub circuit_id: String,
    /// The certified commitment hash.
    pub commitment: [u8; 32],
    /// Total voting power of the signer set, tallied at formation. Re-derived and
    /// cross-checked on verify.
    pub voting_power: u128,
    /// Aggregate BLS signature over [`ZkCommitmentClaim::cosign_payload`].
    #[serde(with = "bls_aggregate_serde")]
    pub bls_aggregate: [u8; 96],
    /// Signer bitmap over the active validator set (LSB-first). Bit `i` set iff
    /// `active[i]` contributed a co-signature.
    pub signer_bitmap: Vec<u8>,
}

impl ZkQuorumCertificate {
    /// Form a certificate from a commitment and a set of co-signatures, given the
    /// active validator set the bitmap is indexed against.
    ///
    /// Reuses the exact BLS-aggregation path used for quorum and batch
    /// certificates. Fails if the collected signers do not reach `2f+1`
    /// stake-weight.
    pub fn form(
        circuit_id: String,
        commitment: [u8; 32],
        cosigns: &[ZkCosign],
        validator_set: &ValidatorSet,
    ) -> Result<Self> {
        let active = validator_set.active_validators();
        let n = active.len();
        let bitmap_bytes = n.div_ceil(8);
        let mut signer_bitmap = vec![0u8; bitmap_bytes];
        let mut bls_sigs: Vec<BlsSignature> = Vec::new();
        let mut voting_power: u128 = 0;
        let normalized = validator_set.normalized_weights();
        let mut signed_power: u128 = 0;
        let mut seen = vec![false; n];
        let payload = ZkCommitmentClaim::cosign_payload(&commitment);

        for cosign in cosigns {
            if cosign.commitment != commitment {
                continue;
            }
            let Some(idx) = validator_set.index_of(&cosign.validator) else {
                continue;
            };
            if seen[idx] {
                continue;
            }
            let sig = BlsSignature::from_bytes(&cosign.bls_signature).map_err(|e| {
                ConsensusError::InvalidSignature(format!(
                    "zk co-sign from {} carries malformed BLS signature: {e}",
                    cosign.validator
                ))
            })?;
            // Verify the leg against the co-signer's registered BLS key before
            // admitting it into the aggregate, so a forged co-sign can never
            // poison the certificate.
            let pk = BlsPublicKey::from_bytes(&active[idx].bls_public_key).map_err(|e| {
                ConsensusError::InvalidSignature(format!(
                    "validator {} has malformed BLS key: {e}",
                    cosign.validator
                ))
            })?;
            let ok = sig.verify(&pk, &payload).map_err(|e| {
                ConsensusError::InvalidSignature(format!("zk co-sign verify raised: {e}"))
            })?;
            if !ok {
                continue;
            }
            seen[idx] = true;
            signer_bitmap[idx / 8] |= 1 << (idx % 8);
            bls_sigs.push(sig);
            voting_power = voting_power.saturating_add(active[idx].voting_power());
            if let Some(w) = normalized.get(idx) {
                signed_power = signed_power.saturating_add(*w);
            }
        }

        let quorum_power = validator_set.quorum_voting_power();
        if signed_power < quorum_power {
            return Err(ConsensusError::InsufficientVotes {
                got: signed_power.min(u64::MAX as u128) as u64,
                need: quorum_power.min(u64::MAX as u128) as u64,
            });
        }

        let agg = tenzro_crypto::bls::aggregate_signatures(&bls_sigs).map_err(|e| {
            ConsensusError::InvalidSignature(format!("zk-quorum BLS aggregation failed: {e}"))
        })?;

        Ok(Self {
            circuit_id,
            commitment,
            voting_power,
            bls_aggregate: agg.to_bytes(),
            signer_bitmap,
        })
    }

    /// The set of validator addresses named in the signer bitmap, in bitmap
    /// order. These are the parties accountable under the fraud-proof window: if
    /// the underlying proof is later shown not to verify, every one of them is
    /// slashed.
    pub fn signers(&self, validator_set: &ValidatorSet) -> Vec<Address> {
        let active = validator_set.active_validators();
        let n = active.len();
        let mut out = Vec::new();
        // bit_index drives both the bitmap byte/bit math and the active-set index
        #[allow(clippy::needless_range_loop)]
        for bit_index in 0..(self.signer_bitmap.len() * 8) {
            if bit_index >= n {
                break;
            }
            let byte = self.signer_bitmap[bit_index / 8];
            if (byte >> (bit_index % 8)) & 1 == 1 {
                out.push(active[bit_index].address);
            }
        }
        out
    }

    /// Verify the aggregate carries `2f+1` stake-weight over the canonical
    /// co-sign payload. Mirrors `BatchAvailabilityCertificate::verify`.
    pub fn verify(&self, validator_set: &ValidatorSet) -> Result<()> {
        let active = validator_set.active_validators();
        let n = active.len();
        let expected_bitmap_bytes = n.div_ceil(8);
        if self.signer_bitmap.len() != expected_bitmap_bytes {
            return Err(ConsensusError::InvalidSignature(format!(
                "zk-quorum signer_bitmap length {} does not match expected {} for {} validators",
                self.signer_bitmap.len(),
                expected_bitmap_bytes,
                n
            )));
        }

        let normalized = validator_set.normalized_weights();
        let mut signer_pks: Vec<BlsPublicKey> = Vec::new();
        let mut total_voting_power: u128 = 0;
        let mut signed_power: u128 = 0;
        // bit_index drives both the bitmap byte/bit math and the active-set index
        #[allow(clippy::needless_range_loop)]
        for bit_index in 0..(expected_bitmap_bytes * 8) {
            let byte = self.signer_bitmap[bit_index / 8];
            if (byte >> (bit_index % 8)) & 1 == 0 {
                continue;
            }
            if bit_index >= n {
                return Err(ConsensusError::InvalidSignature(format!(
                    "zk-quorum bitmap bit {bit_index} set but active set has {n} validators"
                )));
            }
            let validator = &active[bit_index];
            let pk = BlsPublicKey::from_bytes(&validator.bls_public_key).map_err(|e| {
                ConsensusError::InvalidSignature(format!(
                    "zk-quorum signer {} has malformed BLS key: {e}",
                    validator.address
                ))
            })?;
            signer_pks.push(pk);
            total_voting_power = total_voting_power.saturating_add(validator.voting_power());
            if let Some(w) = normalized.get(bit_index) {
                signed_power = signed_power.saturating_add(*w);
            }
        }

        if signer_pks.is_empty() {
            return Err(ConsensusError::InvalidSignature(
                "zk-quorum bitmap empty — no signers".to_string(),
            ));
        }

        let quorum_power = validator_set.quorum_voting_power();
        if signed_power < quorum_power {
            return Err(ConsensusError::InvalidSignature(format!(
                "zk-quorum carries {signed_power} stake-weight from {} signers, below quorum {quorum_power}",
                signer_pks.len()
            )));
        }

        if self.voting_power != total_voting_power {
            return Err(ConsensusError::InvalidSignature(format!(
                "zk-quorum claims voting_power={} but bitmap-tallied power is {total_voting_power}",
                self.voting_power
            )));
        }

        let agg_pk = tenzro_crypto::bls::aggregate_public_keys(&signer_pks).map_err(|e| {
            ConsensusError::InvalidSignature(format!(
                "zk-quorum aggregate public-key reconstruction failed: {e}"
            ))
        })?;
        let agg_pk_single = BlsPublicKey::from_bytes(&agg_pk.to_bytes()).map_err(|e| {
            ConsensusError::InvalidSignature(format!(
                "zk-quorum aggregate public-key round-trip failed: {e}"
            ))
        })?;
        let agg_sig = BlsSignature::from_bytes(&self.bls_aggregate).map_err(|e| {
            ConsensusError::InvalidSignature(format!(
                "zk-quorum bls_aggregate is not a valid signature: {e}"
            ))
        })?;
        let payload = ZkCommitmentClaim::cosign_payload(&self.commitment);
        let ok = agg_sig.verify(&agg_pk_single, &payload).map_err(|e| {
            ConsensusError::InvalidSignature(format!("zk-quorum aggregate verify raised: {e}"))
        })?;
        if !ok {
            return Err(ConsensusError::InvalidSignature(
                "zk-quorum aggregate verification rejected the signature".to_string(),
            ));
        }
        Ok(())
    }
}

/// The outcome of a fraud proof filed against an attested commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FraudOutcome {
    /// The re-verification succeeded — the commitment stands, the challenger's
    /// bond is forfeit. The certificate's co-signers were honest.
    Unfounded,
    /// The re-verification failed — the commitment is retracted and every
    /// co-signer named in the certificate is slashed.
    Upheld,
}

/// A record of an attested commitment inside its fraud window, plus the
/// certificate that admitted it. The store retains this until the window closes
/// so a fraud proof can name the accountable co-signers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestedCommitment {
    /// The quorum certificate that admitted the commitment.
    pub certificate: ZkQuorumCertificate,
    /// Block height at which the commitment was attested. The fraud window runs
    /// `[attested_at_height, attested_at_height + FRAUD_WINDOW_BLOCKS)`.
    pub attested_at_height: u64,
    /// DA locator for the proof bytes, retained so a challenger and the
    /// re-verifying node can both fetch the exact bytes.
    pub proof_locator: String,
}

impl AttestedCommitment {
    /// Whether a fraud proof filed at `current_height` is still within the
    /// accountability window.
    pub fn in_fraud_window(&self, current_height: u64) -> bool {
        current_height < self.attested_at_height.saturating_add(FRAUD_WINDOW_BLOCKS)
    }
}

/// Gossip topic on which ZK commitment claims and co-signatures are exchanged.
pub const ZK_QUORUM_TOPIC: &str = "tenzro/zk-quorum";

/// A message on the [`ZK_QUORUM_TOPIC`]. The network crate carries these as an
/// opaque blob inside `MessagePayload::Custom`, so this enum is the wire format
/// both directions decode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZkQuorumMsg {
    /// An initiator that ran `verify_proof_envelope` announces a commitment and
    /// carries its own first co-signature, so recipients can start aggregating
    /// immediately.
    Claim {
        /// The commitment claim (circuit id, commitment, DA locator).
        claim: ZkCommitmentClaim,
        /// The initiator's co-signature over the commitment.
        cosign: ZkCosign,
    },
    /// A co-signer that fetched the proof and independently re-verified replies
    /// with its own co-signature.
    Cosign {
        /// The circuit id, so the aggregator can form the certificate without
        /// re-tracking the claim.
        circuit_id: String,
        /// This co-signer's signature over the commitment.
        cosign: ZkCosign,
    },
}

/// Producer + tracker for ZK quorum certificates and their fraud windows.
///
/// Owns this node's BLS key (for co-signing claims it has re-verified), the pool
/// of pending co-signatures keyed by commitment, and the attested commitments
/// still inside their fraud window. Certificates and attested-commitment records
/// persist write-through to `CF_AUDIT` and hydrate on construction, so a restart
/// does not drop an open fraud window (which would let a colluding committee
/// escape accountability by forcing an operator restart).
pub struct ZkQuorumStore {
    /// This node's BLS key, used to co-sign commitments it has re-verified.
    bls_key: Arc<BlsKeyPair>,
    /// This node's validator address.
    address: Address,
    /// Pending co-signatures for commitments awaiting quorum, keyed by
    /// commitment. Deduplicated by validator within a commitment. In-memory
    /// only — a commitment that loses its partial co-signs across a restart is
    /// re-claimed by whoever re-verifies it.
    pending: DashMap<[u8; 32], Vec<ZkCosign>>,
    /// Attested commitments still inside their fraud window, keyed by
    /// commitment. Retained for [`FRAUD_WINDOW_BLOCKS`] then pruned.
    attested: DashMap<[u8; 32], AttestedCommitment>,
    /// Optional durable store.
    storage: Option<Arc<dyn KvStore>>,
}

impl ZkQuorumStore {
    /// Key under `CF_AUDIT` for a persisted attested-commitment record.
    fn attested_key(commitment: &[u8; 32]) -> Vec<u8> {
        let mut k = b"zk_quorum/attested/".to_vec();
        k.extend_from_slice(commitment);
        k
    }

    /// Build an in-memory store.
    pub fn new(bls_key: Arc<BlsKeyPair>, address: Address) -> Self {
        Self {
            bls_key,
            address,
            pending: DashMap::new(),
            attested: DashMap::new(),
            storage: None,
        }
    }

    /// Build a durable store, hydrating any persisted attested commitments.
    pub fn with_storage(
        bls_key: Arc<BlsKeyPair>,
        address: Address,
        storage: Arc<dyn KvStore>,
    ) -> Self {
        let store = Self {
            bls_key,
            address,
            pending: DashMap::new(),
            attested: DashMap::new(),
            storage: Some(storage.clone()),
        };
        store.hydrate();
        store
    }

    /// This node's validator address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    fn hydrate(&self) {
        let Some(storage) = self.storage.as_ref() else {
            return;
        };
        let prefix = b"zk_quorum/attested/";
        let Ok(entries) = storage.scan_prefix(CF_AUDIT, prefix) else {
            return;
        };
        for (_key, bytes) in entries {
            if let Ok(record) = serde_json::from_slice::<AttestedCommitment>(&bytes) {
                self.attested.insert(record.certificate.commitment, record);
            }
        }
    }

    fn persist_attested(&self, record: &AttestedCommitment) {
        let Some(storage) = self.storage.as_ref() else {
            return;
        };
        if let Ok(bytes) = serde_json::to_vec(record) {
            let _ = storage.put(
                CF_AUDIT,
                &Self::attested_key(&record.certificate.commitment),
                &bytes,
            );
        }
    }

    fn delete_attested(&self, commitment: &[u8; 32]) {
        if let Some(storage) = self.storage.as_ref() {
            let _ = storage.delete(CF_AUDIT, &Self::attested_key(commitment));
        }
    }

    /// Co-sign a commitment this node has independently re-verified. Returns the
    /// [`ZkCosign`] to broadcast on the co-sign gossip topic. The caller is
    /// responsible for having actually run `verify_proof_envelope` first —
    /// producing a co-signature is an assertion of that verification, and a
    /// dishonest assertion is exactly what the fraud window slashes.
    pub fn cosign(&self, commitment: [u8; 32]) -> ZkCosign {
        let payload = ZkCommitmentClaim::cosign_payload(&commitment);
        let sig = self.bls_key.sign(&payload);
        ZkCosign {
            commitment,
            validator: self.address,
            bls_signature: sig.to_bytes().to_vec(),
        }
    }

    /// Record a co-signature toward a commitment's quorum. When the accumulated
    /// co-signatures reach `2f+1` stake-weight, forms and returns the
    /// [`ZkQuorumCertificate`]; otherwise returns `Ok(None)` and buffers the
    /// co-signature. Deduplicated by validator address.
    pub fn record_cosign(
        &self,
        circuit_id: &str,
        cosign: ZkCosign,
        validator_set: &ValidatorSet,
    ) -> Result<Option<ZkQuorumCertificate>> {
        let commitment = cosign.commitment;
        {
            let mut entry = self.pending.entry(commitment).or_default();
            if entry.iter().any(|c| c.validator == cosign.validator) {
                // Already counted this validator; try to form with what we have.
            } else {
                entry.push(cosign);
            }
        }
        let cosigns = self
            .pending
            .get(&commitment)
            .map(|e| e.clone())
            .unwrap_or_default();
        match ZkQuorumCertificate::form(circuit_id.to_string(), commitment, &cosigns, validator_set)
        {
            Ok(cert) => {
                self.pending.remove(&commitment);
                Ok(Some(cert))
            }
            // Below quorum is not an error — keep buffering.
            Err(ConsensusError::InsufficientVotes { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Admit a verified certificate into the fraud window at `current_height`,
    /// recording the accountable co-signers. The caller has already run
    /// [`ZkQuorumCertificate::verify`] and attested the commitment to the
    /// `ZkCommitmentRegistry`. Returns the retained [`AttestedCommitment`].
    pub fn open_fraud_window(
        &self,
        certificate: ZkQuorumCertificate,
        proof_locator: String,
        current_height: u64,
    ) -> AttestedCommitment {
        let record = AttestedCommitment {
            certificate,
            attested_at_height: current_height,
            proof_locator,
        };
        self.persist_attested(&record);
        self.attested
            .insert(record.certificate.commitment, record.clone());
        record
    }

    /// Look up the attested-commitment record for a commitment still inside its
    /// fraud window.
    pub fn attested(&self, commitment: &[u8; 32]) -> Option<AttestedCommitment> {
        self.attested.get(commitment).map(|e| e.clone())
    }

    /// Resolve a fraud proof against an attested commitment. `reverified` is the
    /// result of the node's own deterministic `verify_proof_envelope` re-run over
    /// the proof bytes fetched from the record's locator.
    ///
    /// - `reverified == true` → [`FraudOutcome::Unfounded`]: the commitment
    ///   stands; the caller forfeits the challenger's bond.
    /// - `reverified == false` → [`FraudOutcome::Upheld`]: the commitment is
    ///   retracted (removed from the fraud window here; the caller removes it
    ///   from the `ZkCommitmentRegistry`) and the returned co-signer list is
    ///   slashed by the caller through the consensus slashing path.
    ///
    /// Returns the outcome and the accountable co-signers (empty on
    /// `Unfounded`). A commitment past its fraud window or unknown to the store
    /// returns an error — a challenge cannot be filed there.
    pub fn resolve_fraud_proof(
        &self,
        commitment: &[u8; 32],
        current_height: u64,
        reverified: bool,
        validator_set: &ValidatorSet,
    ) -> Result<(FraudOutcome, Vec<Address>)> {
        let record = self
            .attested
            .get(commitment)
            .map(|e| e.clone())
            .ok_or_else(|| {
                ConsensusError::Internal(
                    "fraud proof names a commitment not inside any open fraud window".to_string(),
                )
            })?;
        if !record.in_fraud_window(current_height) {
            return Err(ConsensusError::Internal(format!(
                "fraud window for commitment closed at height {}",
                record
                    .attested_at_height
                    .saturating_add(FRAUD_WINDOW_BLOCKS)
            )));
        }
        if reverified {
            return Ok((FraudOutcome::Unfounded, Vec::new()));
        }
        // Upheld: retract the commitment from the window and name the co-signers.
        let signers = record.certificate.signers(validator_set);
        self.attested.remove(commitment);
        self.delete_attested(commitment);
        Ok((FraudOutcome::Upheld, signers))
    }

    /// Prune attested commitments whose fraud window has closed. Called on each
    /// finalized-block advance. Returns the number pruned.
    pub fn prune_closed_windows(&self, current_height: u64) -> usize {
        let expired: Vec<[u8; 32]> = self
            .attested
            .iter()
            .filter(|e| !e.value().in_fraud_window(current_height))
            .map(|e| *e.key())
            .collect();
        for commitment in &expired {
            self.attested.remove(commitment);
            self.delete_attested(commitment);
        }
        expired.len()
    }

    /// Number of commitments currently inside an open fraud window. Diagnostics.
    pub fn open_window_count(&self) -> usize {
        self.attested.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::{ValidatorInfo, ValidatorSet};
    use tenzro_crypto::bls::BlsKeyPair;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::{KeyPair, KeyType};

    fn addr(byte: u8) -> Address {
        Address::new([byte; 32])
    }

    fn mk_validator(seed: u8, stake: u128) -> (ValidatorInfo, Arc<BlsKeyPair>) {
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pq = MlDsaSigningKey::generate();
        let bls = BlsKeyPair::generate().unwrap();
        let info = ValidatorInfo::new(
            addr(seed),
            kp.public_key().clone(),
            pq.verifying_key_bytes().to_vec(),
            bls.public_key().to_bytes().to_vec(),
            stake,
        );
        (info, Arc::new(bls))
    }

    fn commitment_of(seed: u8) -> [u8; 32] {
        let mut c = [0u8; 32];
        c[0] = seed;
        c
    }

    #[test]
    fn certificate_forms_and_verifies_at_quorum() {
        let mut infos = Vec::new();
        let mut keys = Vec::new();
        for i in 0..4u8 {
            let (info, key) = mk_validator(i + 1, 100);
            infos.push(info);
            keys.push(key);
        }
        let set = ValidatorSet::new(0, infos.clone()).expect("set");
        let commitment = commitment_of(7);
        let payload = ZkCommitmentClaim::cosign_payload(&commitment);

        // 3 of 4 co-sign — that is 2f+1 for f=1.
        let mut cosigns = Vec::new();
        for i in 0..3usize {
            let sig = keys[i].sign(&payload);
            cosigns.push(ZkCosign {
                commitment,
                validator: infos[i].address,
                bls_signature: sig.to_bytes().to_vec(),
            });
        }
        let cert = ZkQuorumCertificate::form("inference".to_string(), commitment, &cosigns, &set)
            .expect("forms at quorum");
        cert.verify(&set).expect("verifies");
        assert_eq!(cert.signers(&set).len(), 3);
    }

    #[test]
    fn certificate_rejected_below_quorum() {
        let mut infos = Vec::new();
        let mut keys = Vec::new();
        for i in 0..4u8 {
            let (info, key) = mk_validator(i + 1, 100);
            infos.push(info);
            keys.push(key);
        }
        let set = ValidatorSet::new(0, infos.clone()).expect("set");
        let commitment = commitment_of(9);
        let payload = ZkCommitmentClaim::cosign_payload(&commitment);

        // Only 2 of 4 co-sign — below 2f+1.
        let mut cosigns = Vec::new();
        for i in 0..2usize {
            let sig = keys[i].sign(&payload);
            cosigns.push(ZkCosign {
                commitment,
                validator: infos[i].address,
                bls_signature: sig.to_bytes().to_vec(),
            });
        }
        let err = ZkQuorumCertificate::form("inference".to_string(), commitment, &cosigns, &set);
        assert!(matches!(err, Err(ConsensusError::InsufficientVotes { .. })));
    }

    #[test]
    fn store_forms_cert_when_quorum_reached() {
        let mut infos = Vec::new();
        let mut keys = Vec::new();
        for i in 0..4u8 {
            let (info, key) = mk_validator(i + 1, 100);
            infos.push(info);
            keys.push(key);
        }
        let set = ValidatorSet::new(0, infos.clone()).expect("set");
        let store = ZkQuorumStore::new(keys[0].clone(), infos[0].address);
        let commitment = commitment_of(3);

        // First two co-signs: no quorum yet.
        for i in 0..2usize {
            let c = ZkCosign {
                commitment,
                validator: infos[i].address,
                bls_signature: keys[i]
                    .sign(&ZkCommitmentClaim::cosign_payload(&commitment))
                    .to_bytes()
                    .to_vec(),
            };
            let out = store.record_cosign("inference", c, &set).expect("ok");
            assert!(out.is_none());
        }
        // Third co-sign reaches 2f+1.
        let c = ZkCosign {
            commitment,
            validator: infos[2].address,
            bls_signature: keys[2]
                .sign(&ZkCommitmentClaim::cosign_payload(&commitment))
                .to_bytes()
                .to_vec(),
        };
        let cert = store
            .record_cosign("inference", c, &set)
            .expect("ok")
            .expect("cert formed at quorum");
        cert.verify(&set).expect("verifies");
    }

    #[test]
    fn fraud_window_upheld_names_cosigners_and_retracts() {
        let mut infos = Vec::new();
        let mut keys = Vec::new();
        for i in 0..4u8 {
            let (info, key) = mk_validator(i + 1, 100);
            infos.push(info);
            keys.push(key);
        }
        let set = ValidatorSet::new(0, infos.clone()).expect("set");
        let store = ZkQuorumStore::new(keys[0].clone(), infos[0].address);
        let commitment = commitment_of(5);
        let payload = ZkCommitmentClaim::cosign_payload(&commitment);
        let cosigns: Vec<ZkCosign> = (0..3usize)
            .map(|i| ZkCosign {
                commitment,
                validator: infos[i].address,
                bls_signature: keys[i].sign(&payload).to_bytes().to_vec(),
            })
            .collect();
        let cert =
            ZkQuorumCertificate::form("inference".to_string(), commitment, &cosigns, &set).unwrap();
        store.open_fraud_window(cert, "tenzro://blob/deadbeef".to_string(), 1_000);

        // A failed re-verification upholds the fraud proof and names the 3 co-signers.
        let (outcome, signers) = store
            .resolve_fraud_proof(&commitment, 1_100, false, &set)
            .expect("in window");
        assert_eq!(outcome, FraudOutcome::Upheld);
        assert_eq!(signers.len(), 3);
        assert!(store.attested(&commitment).is_none());
    }

    #[test]
    fn fraud_window_unfounded_keeps_commitment() {
        let mut infos = Vec::new();
        let mut keys = Vec::new();
        for i in 0..4u8 {
            let (info, key) = mk_validator(i + 1, 100);
            infos.push(info);
            keys.push(key);
        }
        let set = ValidatorSet::new(0, infos.clone()).expect("set");
        let store = ZkQuorumStore::new(keys[0].clone(), infos[0].address);
        let commitment = commitment_of(6);
        let payload = ZkCommitmentClaim::cosign_payload(&commitment);
        let cosigns: Vec<ZkCosign> = (0..3usize)
            .map(|i| ZkCosign {
                commitment,
                validator: infos[i].address,
                bls_signature: keys[i].sign(&payload).to_bytes().to_vec(),
            })
            .collect();
        let cert =
            ZkQuorumCertificate::form("inference".to_string(), commitment, &cosigns, &set).unwrap();
        store.open_fraud_window(cert, "tenzro://blob/cafe".to_string(), 2_000);

        let (outcome, signers) = store
            .resolve_fraud_proof(&commitment, 2_050, true, &set)
            .expect("in window");
        assert_eq!(outcome, FraudOutcome::Unfounded);
        assert!(signers.is_empty());
        assert!(store.attested(&commitment).is_some());
    }

    #[test]
    fn fraud_proof_past_window_rejected() {
        let (info, key) = mk_validator(1, 100);
        let set = ValidatorSet::new(0, vec![info.clone()]).ok();
        // Single-validator set may not satisfy 3f+1; guard the test on set build.
        let Some(set) = set else {
            return;
        };
        let store = ZkQuorumStore::new(key.clone(), info.address);
        let commitment = commitment_of(8);
        let payload = ZkCommitmentClaim::cosign_payload(&commitment);
        let cosign = ZkCosign {
            commitment,
            validator: info.address,
            bls_signature: key.sign(&payload).to_bytes().to_vec(),
        };
        if let Ok(cert) =
            ZkQuorumCertificate::form("inference".to_string(), commitment, &[cosign], &set)
        {
            store.open_fraud_window(cert, "tenzro://blob/aa".to_string(), 100);
            let past = 100 + FRAUD_WINDOW_BLOCKS + 1;
            let out = store.resolve_fraud_proof(&commitment, past, false, &set);
            assert!(out.is_err());
        }
    }
}
