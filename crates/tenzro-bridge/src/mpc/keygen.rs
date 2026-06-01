//! DKG session adapter producing per-party [`KeyshareEnvelope`] records.
//!
//! Wraps `dkls23_core::protocols::dkg_session::DkgSession` under a
//! Tenzro-shaped [`KeygenSession`] surface that:
//!
//! 1. Pulls round messages from a [`Transport`].
//! 2. Drives the dkls23-core state machine through phases 1 → 4.
//! 3. Hands the finalised `Party<C>` to a [`KeyshareSealer`] for sealing.
//! 4. Persists the sealed envelope through a [`KeyshareStore`] at
//!    `epoch = 0` (subsequent epochs are issued by `refresh`).
//!
//! ## Wire encoding ([`KeygenRoundPayload`])
//!
//! The opaque `payload` field on [`MpcRoundMessage`] carries a bincode-
//! serialized [`KeygenRoundPayload`] enum. The enum discriminates the
//! three logical message classes the dkls23 DKG state machine emits:
//!
//! - **Phase 1 polynomial fragment (`PolyFragment`)** — broadcast from every
//!   party `i` to every party `j` (each `j` receives `n` fragments — one per
//!   party including itself; the driver indexes by `from_index`).
//! - **Phase 2 packet (`Phase2`)** — broadcasts `(ProofCommitment,
//!   BroadcastDerivationPhase2to4)` to all parties, and transmits one
//!   `TransmitInitZeroSharePhase2to4` per other receiver.
//! - **Phase 3 packet (`Phase3`)** — broadcasts `BroadcastDerivationPhase3to4`
//!   to all parties, and transmits one
//!   `TransmitInitZeroSharePhase3to4` plus one `TransmitInitMulPhase3to4` per
//!   other receiver.
//!
//! Each enum variant carries the **sender's** point-to-point output for a
//! single receiver alongside the broadcast packet; the driver unrolls
//! `phase2`/`phase3` outputs into one `MpcRoundMessage` per `(sender, receiver)`
//! pair so the [`Transport`] sees only point-to-point envelopes.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::mpc::abort::{MpcAbortEvidence, MpcAbortReporter};

use dkls23_core::protocols::dkg::{
    BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4, ProofCommitment,
    TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4,
    TransmitInitZeroSharePhase3to4,
};
use dkls23_core::protocols::dkg_session::DkgSession;
use dkls23_core::protocols::{Abort, AbortKind, Parameters, PartyIndex};
use dkls23_secp256k1::{compute_eth_address, Party};
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::Secp256k1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::mpc::sealing::{KeyshareSealer, KeyshareSealerError};
use crate::mpc::setup::{InstanceId, MpcCurve, MpcParameters};
use crate::mpc::store::{
    GroupId, KeyshareEnvelope, KeyshareError, KeyshareStore, GROUP_DOMAIN_TAG,
};
use crate::mpc::transport::{MpcPhase, MpcRoundMessage, Transport, TransportError};

/// Initial epoch for a freshly minted group. Re-keys and refreshes increment
/// from here.
const EPOCH_ZERO: u64 = 0;

/// Bincode wire format for DKG round payloads carried in
/// [`MpcRoundMessage::payload`].
///
/// One variant per logical message class. The driver bincode-serializes the
/// enum into the opaque transport payload; the receiving driver deserializes
/// and dispatches on the discriminant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum KeygenRoundPayload {
    /// Phase 1 polynomial fragment for a specific receiver. The dkls23
    /// `phase1` API returns one `Scalar` per receiver including the sender
    /// itself; the driver routes each fragment to its target.
    PolyFragment {
        /// 1-based sender party index.
        from_index: u8,
        /// 1-based receiver party index.
        to_index: u8,
        /// Bincode-serialized `k256::Scalar` (fixed 32 bytes).
        fragment: Vec<u8>,
    },
    /// Phase 2 packet — broadcast component plus one point-to-point
    /// zero-share transmit for this receiver.
    Phase2 {
        from_index: u8,
        to_index: u8,
        /// Broadcast: proof of polynomial-point commitment.
        proof_commitment: ProofCommitment<Secp256k1>,
        /// Broadcast: BIP-derivation chain-code commitment.
        broadcast_derivation: BroadcastDerivationPhase2to4,
        /// Point-to-point: zero-share kept material targeted at this receiver.
        zero_transmit: TransmitInitZeroSharePhase2to4,
    },
    /// Phase 3 packet — broadcast component plus one point-to-point
    /// zero-share + one point-to-point multiplication transmit for this
    /// receiver.
    Phase3 {
        from_index: u8,
        to_index: u8,
        /// Broadcast: BIP-derivation chain-code reveal.
        broadcast_derivation: BroadcastDerivationPhase3to4,
        /// Point-to-point: zero-share material targeted at this receiver.
        zero_transmit: TransmitInitZeroSharePhase3to4,
        /// Point-to-point: 2PC multiplication material targeted at this
        /// receiver.
        mul_transmit: TransmitInitMulPhase3to4<Secp256k1>,
    },
}

/// Configuration for a single DKG session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeygenConfig {
    /// Session identifier (chain-anchored, see [`InstanceId::derive`]).
    pub instance_id: InstanceId,
    /// Threshold shape requested for the new group.
    pub parameters: MpcParameters,
    /// DIDs of all participants, sorted ascending. The local party's index
    /// into this list (+1) is its DKLS23 `PartyIndex`.
    pub participant_dids: Vec<String>,
    /// DID of the local party — must appear exactly once in
    /// `participant_dids`.
    pub local_did: String,
}

impl KeygenConfig {
    /// 1-based DKLS23 party index of the local participant within
    /// `participant_dids`.
    pub fn local_party_index(&self) -> Result<u8, KeygenError> {
        let pos = self
            .participant_dids
            .iter()
            .position(|d| d == &self.local_did)
            .ok_or(KeygenError::LocalNotInParticipants)?;
        Ok((pos + 1) as u8)
    }

    /// Validate that participant DIDs are unique and sorted ascending. The
    /// `GroupId` derivation depends on the canonical ordering — accepting
    /// out-of-order input would yield diverging group IDs across parties.
    pub fn validate(&self) -> Result<(), KeygenError> {
        if self.participant_dids.len() != self.parameters.total_parties as usize {
            return Err(KeygenError::ParticipantCountMismatch {
                expected: self.parameters.total_parties as usize,
                got: self.participant_dids.len(),
            });
        }
        for window in self.participant_dids.windows(2) {
            match window[0].cmp(&window[1]) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    return Err(KeygenError::DuplicateParticipant(window[0].clone()));
                }
                std::cmp::Ordering::Greater => {
                    return Err(KeygenError::UnsortedParticipants);
                }
            }
        }
        self.local_party_index()?;
        Ok(())
    }
}

/// Outcome of a successful DKG session — surface for the caller to inspect
/// before reaching for the persisted envelope via
/// [`KeyshareStore::get`](crate::mpc::store::KeyshareStore::get).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeygenOutput {
    /// Derived group identifier (stable across refresh epochs).
    pub group_id: GroupId,
    /// SEC1-compressed group public key (33 bytes for secp256k1).
    pub group_public_key_compressed: Vec<u8>,
    /// 1-based local party index within the group.
    pub local_party_index: u8,
    /// Initial epoch (always 0 for fresh DKG output).
    pub epoch: u64,
    /// EVM (EIP-55) address derived from the group public key — recorded
    /// here for callers that want to display / log it without re-deriving.
    pub address: String,
}

/// Errors raised during DKG.
#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    /// Local DID not present in participant list.
    #[error("local DID not in participant list")]
    LocalNotInParticipants,
    /// Participant DIDs are not unique.
    #[error("duplicate participant DID: {0}")]
    DuplicateParticipant(String),
    /// Participant DIDs are not in canonical ascending order.
    #[error("participant DIDs must be sorted ascending")]
    UnsortedParticipants,
    /// `participant_dids.len()` does not match `parameters.total_parties`.
    #[error("participant count mismatch: expected {expected}, got {got}")]
    ParticipantCountMismatch { expected: usize, got: usize },
    /// `MpcParameters` carried a non-secp256k1 curve discriminant — DKG is
    /// secp256k1-only for the bridge signer.
    #[error("unsupported curve for DKG: {0:?}")]
    UnsupportedCurve(MpcCurve),
    /// dkls23-core rejected the threshold parameters at the upstream
    /// `Parameters::new` boundary.
    #[error("dkls23 rejected parameters: {0}")]
    InvalidParameters(String),
    /// dkls23-core protocol abort (recoverable or ban). Translated to the
    /// on-chain [`crate::mpc::abort::MpcAbortEvidence`] by the session
    /// driver.
    #[error("dkls23 protocol abort: party={party} kind={kind:?} reason={reason}")]
    ProtocolAbort {
        party: u8,
        kind: AbortKindWire,
        reason: String,
    },
    /// Wire payload could not be bincode-decoded into [`KeygenRoundPayload`].
    #[error("malformed round payload from {from_did}: {detail}")]
    MalformedPayload { from_did: String, detail: String },
    /// Inbound message arrived in the wrong logical phase (driver state
    /// machine guard).
    #[error("unexpected payload kind in {expected:?}: got {got}")]
    UnexpectedPayloadKind { expected: MpcPhase, got: &'static str },
    /// Inbound message did not match the active `InstanceId` — cross-session
    /// splice attempt or routing bug.
    #[error("instance id mismatch on inbound message")]
    InstanceIdMismatch,
    /// Inbound message claimed an unknown sender DID.
    #[error("unknown sender DID: {0}")]
    UnknownSender(String),
    /// Underlying transport failure.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    /// Sealer error.
    #[error("sealing error: {0}")]
    Sealing(#[from] KeyshareSealerError),
    /// Keyshare store error.
    #[error("keyshare store error: {0}")]
    Store(#[from] KeyshareError),
    /// bincode encode error on `Party<C>`.
    #[error("party encode error: {0}")]
    PartyEncode(String),
}

/// Mirror of [`dkls23_core::protocols::AbortKind`] that crosses our error
/// boundary without leaking the upstream type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbortKindWire {
    /// Recoverable abort — retry the session.
    Recoverable,
    /// Counterparty must be permanently excluded.
    BanCounterparty(u8),
}

impl From<AbortKind> for AbortKindWire {
    fn from(k: AbortKind) -> Self {
        match k {
            AbortKind::Recoverable => Self::Recoverable,
            AbortKind::BanCounterparty(pi) => Self::BanCounterparty(pi.as_u8()),
        }
    }
}

impl From<Abort> for KeygenError {
    fn from(a: Abort) -> Self {
        Self::ProtocolAbort {
            party: a.index.as_u8(),
            kind: a.kind.clone().into(),
            reason: a.reason.to_string(),
        }
    }
}

/// Drives a single DKG run on the local party. Owns the
/// `DkgSession<Secp256k1>`, the [`Transport`], the [`KeyshareSealer`], and the
/// [`KeyshareStore`] for the duration of the session.
pub struct KeygenSession<T, S, K> {
    cfg: KeygenConfig,
    transport: T,
    sealer: S,
    store: K,
    /// Optional reporter for locally-observed identifiable aborts. When set,
    /// any `dkls23_core::protocols::Abort` raised by the upstream state
    /// machine is projected into [`MpcAbortEvidence`] and handed off to the
    /// reporter before being returned to the caller as `ProtocolAbort`.
    abort_reporter: Option<Arc<dyn MpcAbortReporter>>,
}

impl<T, S, K> KeygenSession<T, S, K>
where
    T: Transport,
    S: KeyshareSealer,
    K: KeyshareStore,
{
    /// Construct a session. Validates `cfg` eagerly so the run loop can
    /// assume invariants.
    pub fn new(cfg: KeygenConfig, transport: T, sealer: S, store: K) -> Result<Self, KeygenError> {
        cfg.validate()?;
        if cfg.parameters.curve != MpcCurve::Secp256k1 {
            return Err(KeygenError::UnsupportedCurve(cfg.parameters.curve));
        }
        Ok(Self {
            cfg,
            transport,
            sealer,
            store,
            abort_reporter: None,
        })
    }

    /// Install an [`MpcAbortReporter`] to receive evidence packets for
    /// locally-observed identifiable aborts.
    #[must_use]
    pub fn with_abort_reporter(mut self, reporter: Arc<dyn MpcAbortReporter>) -> Self {
        self.abort_reporter = Some(reporter);
        self
    }

    /// Resolve a 1-based DKLS23 party index to a participant DID using the
    /// canonical-sorted `participant_dids` list. Returns `None` for indices
    /// outside `1..=total_parties`.
    fn did_for_party(&self, party_index: u8) -> Option<String> {
        if party_index == 0 {
            return None;
        }
        self.cfg
            .participant_dids
            .get((party_index - 1) as usize)
            .cloned()
    }

    /// Project a `dkls23_core::protocols::Abort` into [`MpcAbortEvidence`]
    /// and hand it to the installed reporter (if any). Always returns the
    /// abort so the caller can convert to `KeygenError::ProtocolAbort` and
    /// surface it.
    fn emit_abort_evidence(&self, abort: Abort) -> Abort {
        if let Some(reporter) = &self.abort_reporter {
            if let Some(evidence) = MpcAbortEvidence::from_protocol_abort(
                &abort,
                self.cfg.instance_id.clone(),
                self.cfg.parameters.clone(),
                |pi| self.did_for_party(pi),
            ) {
                reporter.report_local_observation(evidence);
            }
        }
        abort
    }

    /// Run the full DKG and persist the sealed envelope.
    ///
    /// On success the local party's [`KeyshareEnvelope`] is written to the
    /// store at `(group_id, epoch=0)` and a [`KeygenOutput`] is returned.
    pub async fn run(self) -> Result<KeygenOutput, KeygenError> {
        let local_index = self.cfg.local_party_index()?;
        let local_pi = PartyIndex::new(local_index)
            .map_err(|e| KeygenError::InvalidParameters(e.to_string()))?;
        let total = self.cfg.parameters.total_parties as usize;
        let dkls_params = Parameters::new(
            self.cfg.parameters.threshold,
            self.cfg.parameters.total_parties,
        )
        .map_err(|e| KeygenError::InvalidParameters(e.to_string()))?;
        let session_id = self.cfg.instance_id.as_bytes().to_vec();

        let mut session: DkgSession<Secp256k1> =
            DkgSession::new(dkls_params, local_pi, session_id);

        // -------------------- Phase 1: poly fragment exchange ---------------
        let local_fragments = session.phase1();
        // Send one fragment per receiver (including self — collect locally).
        let mut received_fragments: BTreeMap<u8, k256::Scalar> = BTreeMap::new();
        for (receiver_idx0, fragment) in local_fragments.iter().enumerate() {
            let to_index = (receiver_idx0 + 1) as u8;
            if to_index == local_index {
                received_fragments.insert(local_index, *fragment);
                continue;
            }
            let payload = KeygenRoundPayload::PolyFragment {
                from_index: local_index,
                to_index,
                fragment: bincode::serialize(fragment)
                    .map_err(|e| KeygenError::PartyEncode(e.to_string()))?,
            };
            self.send_payload(&payload, MpcPhase::Dkg, 0, to_index).await?;
        }
        // Receive fragments from all other parties.
        while received_fragments.len() < total {
            let msg = self.transport.recv().await?;
            let (from_index, payload) = self.decode_inbound(&msg, MpcPhase::Dkg, 0)?;
            match payload {
                KeygenRoundPayload::PolyFragment { fragment, .. } => {
                    let scalar: k256::Scalar = bincode::deserialize(&fragment).map_err(|e| {
                        KeygenError::MalformedPayload {
                            from_did: msg.from_did.clone(),
                            detail: e.to_string(),
                        }
                    })?;
                    received_fragments.insert(from_index, scalar);
                }
                other => {
                    return Err(KeygenError::UnexpectedPayloadKind {
                        expected: MpcPhase::Dkg,
                        got: other.variant_name(),
                    });
                }
            }
        }
        // dkls23 phase2 wants the fragments in 1..=n order, including own.
        let mut poly_fragments_vec: Vec<k256::Scalar> = Vec::with_capacity(total);
        for i in 1..=total as u8 {
            poly_fragments_vec.push(
                *received_fragments
                    .get(&i)
                    .ok_or(KeygenError::ProtocolAbort {
                        party: local_index,
                        kind: AbortKindWire::Recoverable,
                        reason: format!("missing poly fragment from party {i}"),
                    })?,
            );
        }

        // -------------------- Phase 2 -------------------------------------
        let (local_proof_commit, local_zero_transmit_p2, local_bcast_p2) = session
            .phase2(&poly_fragments_vec)
            .map_err(|a| KeygenError::from(self.emit_abort_evidence(a)))?;

        // Send one Phase2 packet per other receiver, pairing the broadcast
        // (proof commitment + BIP broadcast) with the zero-transmit destined
        // for that receiver.
        let mut routed_zero_p2: BTreeMap<u8, &TransmitInitZeroSharePhase2to4> = BTreeMap::new();
        for z in &local_zero_transmit_p2 {
            routed_zero_p2.insert(z.parties.receiver.as_u8(), z);
        }
        for to_index in 1..=total as u8 {
            if to_index == local_index {
                continue;
            }
            let zero = routed_zero_p2.get(&to_index).cloned().ok_or_else(|| {
                KeygenError::ProtocolAbort {
                    party: local_index,
                    kind: AbortKindWire::Recoverable,
                    reason: format!("phase2 produced no zero-transmit for party {to_index}"),
                }
            })?;
            let payload = KeygenRoundPayload::Phase2 {
                from_index: local_index,
                to_index,
                proof_commitment: local_proof_commit.clone(),
                broadcast_derivation: local_bcast_p2.clone(),
                zero_transmit: zero.clone(),
            };
            self.send_payload(&payload, MpcPhase::Dkg, 1, to_index).await?;
        }

        // Collect inbound Phase2 from every other party.
        let mut proofs_commitments_map: BTreeMap<u8, ProofCommitment<Secp256k1>> = BTreeMap::new();
        proofs_commitments_map.insert(local_index, local_proof_commit.clone());
        let mut bip_broadcast_p2: BTreeMap<PartyIndex, BroadcastDerivationPhase2to4> =
            BTreeMap::new();
        bip_broadcast_p2.insert(local_pi, local_bcast_p2.clone());
        let mut inbound_zero_p2: Vec<TransmitInitZeroSharePhase2to4> = Vec::new();
        while proofs_commitments_map.len() < total {
            let msg = self.transport.recv().await?;
            let (from_index, payload) = self.decode_inbound(&msg, MpcPhase::Dkg, 1)?;
            match payload {
                KeygenRoundPayload::Phase2 {
                    proof_commitment,
                    broadcast_derivation,
                    zero_transmit,
                    ..
                } => {
                    proofs_commitments_map.insert(from_index, proof_commitment);
                    bip_broadcast_p2.insert(
                        PartyIndex::new(from_index)
                            .map_err(|e| KeygenError::InvalidParameters(e.to_string()))?,
                        broadcast_derivation,
                    );
                    inbound_zero_p2.push(zero_transmit);
                }
                other => {
                    return Err(KeygenError::UnexpectedPayloadKind {
                        expected: MpcPhase::Dkg,
                        got: other.variant_name(),
                    });
                }
            }
        }

        // -------------------- Phase 3 -------------------------------------
        let (local_zero_transmit_p3, local_mul_transmit_p3, local_bcast_p3) = session
            .phase3()
            .map_err(|a| KeygenError::from(self.emit_abort_evidence(a)))?;

        let mut routed_zero_p3: BTreeMap<u8, &TransmitInitZeroSharePhase3to4> = BTreeMap::new();
        for z in &local_zero_transmit_p3 {
            routed_zero_p3.insert(z.parties.receiver.as_u8(), z);
        }
        let mut routed_mul_p3: BTreeMap<u8, &TransmitInitMulPhase3to4<Secp256k1>> =
            BTreeMap::new();
        for m in &local_mul_transmit_p3 {
            routed_mul_p3.insert(m.parties.receiver.as_u8(), m);
        }
        for to_index in 1..=total as u8 {
            if to_index == local_index {
                continue;
            }
            let zero = routed_zero_p3.get(&to_index).cloned().ok_or_else(|| {
                KeygenError::ProtocolAbort {
                    party: local_index,
                    kind: AbortKindWire::Recoverable,
                    reason: format!("phase3 produced no zero-transmit for party {to_index}"),
                }
            })?;
            let mul = routed_mul_p3.get(&to_index).cloned().ok_or_else(|| {
                KeygenError::ProtocolAbort {
                    party: local_index,
                    kind: AbortKindWire::Recoverable,
                    reason: format!("phase3 produced no mul-transmit for party {to_index}"),
                }
            })?;
            let payload = KeygenRoundPayload::Phase3 {
                from_index: local_index,
                to_index,
                broadcast_derivation: local_bcast_p3.clone(),
                zero_transmit: zero.clone(),
                mul_transmit: mul.clone(),
            };
            self.send_payload(&payload, MpcPhase::Dkg, 2, to_index).await?;
        }

        let mut bip_broadcast_p3: BTreeMap<PartyIndex, BroadcastDerivationPhase3to4> =
            BTreeMap::new();
        bip_broadcast_p3.insert(local_pi, local_bcast_p3.clone());
        let mut inbound_zero_p3: Vec<TransmitInitZeroSharePhase3to4> = Vec::new();
        let mut inbound_mul_p3: Vec<TransmitInitMulPhase3to4<Secp256k1>> = Vec::new();
        while bip_broadcast_p3.len() < total {
            let msg = self.transport.recv().await?;
            let (from_index, payload) = self.decode_inbound(&msg, MpcPhase::Dkg, 2)?;
            match payload {
                KeygenRoundPayload::Phase3 {
                    broadcast_derivation,
                    zero_transmit,
                    mul_transmit,
                    ..
                } => {
                    bip_broadcast_p3.insert(
                        PartyIndex::new(from_index)
                            .map_err(|e| KeygenError::InvalidParameters(e.to_string()))?,
                        broadcast_derivation,
                    );
                    inbound_zero_p3.push(zero_transmit);
                    inbound_mul_p3.push(mul_transmit);
                }
                other => {
                    return Err(KeygenError::UnexpectedPayloadKind {
                        expected: MpcPhase::Dkg,
                        got: other.variant_name(),
                    });
                }
            }
        }

        // -------------------- Phase 4 (finalise) ---------------------------
        // Reassemble proofs_commitments in 1..=n order — phase4 expects a
        // dense slice indexed by party.
        let mut proofs_commitments: Vec<ProofCommitment<Secp256k1>> = Vec::with_capacity(total);
        for i in 1..=total as u8 {
            proofs_commitments.push(
                proofs_commitments_map
                    .remove(&i)
                    .ok_or(KeygenError::ProtocolAbort {
                        party: local_index,
                        kind: AbortKindWire::Recoverable,
                        reason: format!("missing phase2 proof commitment from party {i}"),
                    })?,
            );
        }

        let (party, pk_package) = session
            .phase4(
                &proofs_commitments,
                &inbound_zero_p2,
                &inbound_zero_p3,
                &inbound_mul_p3,
                &bip_broadcast_p2,
                &bip_broadcast_p3,
                compute_eth_address,
            )
            .map_err(|a| KeygenError::from(self.emit_abort_evidence(a)))?;

        // -------------------- Seal + persist envelope ----------------------
        let pk_compressed = party.pk.to_sec1_point(true).as_bytes().to_vec();
        let group_id = derive_group_id(
            &pk_compressed,
            &self.cfg.participant_dids,
            self.cfg.parameters.threshold,
            self.cfg.parameters.total_parties,
        );
        let address = party.address.clone();

        // bincode-serialize the entire `Party<Secp256k1>` for sealing.
        let party_bytes = bincode::serialize(&party)
            .map_err(|e| KeygenError::PartyEncode(e.to_string()))?;
        let share_hash = {
            let mut h = Sha256::new();
            h.update(&party_bytes);
            let d = h.finalize();
            tenzro_types::Hash::from_bytes(&d).expect("sha256 produces 32 bytes")
        };
        let sealed_payload = self
            .sealer
            .seal(&group_id, local_index, &party_bytes)
            .await?;
        drop(party_bytes); // best-effort scrub the encoded plaintext

        let envelope = KeyshareEnvelope {
            group_id,
            epoch: EPOCH_ZERO,
            party_index: local_index,
            parameters: self.cfg.parameters,
            group_public_key_compressed: pk_compressed.clone(),
            share_hash,
            sealed_payload,
            created_at_ms: chrono::Utc::now().timestamp_millis(),
        };
        self.store.insert(envelope).await?;

        // pk_package is the public artifact; the driver itself does not
        // persist it (consensus owns that record). Drop explicitly so the
        // compiler does not warn about it being unused.
        let _ = pk_package;

        Ok(KeygenOutput {
            group_id,
            group_public_key_compressed: pk_compressed,
            local_party_index: local_index,
            epoch: EPOCH_ZERO,
            address,
        })
    }

    /// Wrap a `KeygenRoundPayload` into an `MpcRoundMessage` and push it
    /// onto the transport.
    async fn send_payload(
        &self,
        payload: &KeygenRoundPayload,
        phase: MpcPhase,
        round_index: u32,
        to_index: u8,
    ) -> Result<(), KeygenError> {
        let bytes = bincode::serialize(payload)
            .map_err(|e| KeygenError::PartyEncode(e.to_string()))?;
        let to_did = self.cfg.participant_dids[(to_index - 1) as usize].clone();
        let msg = MpcRoundMessage {
            instance_id: self.cfg.instance_id,
            phase,
            round_index,
            from_did: self.cfg.local_did.clone(),
            to_did,
            payload: bytes,
        };
        self.transport.send(msg).await.map_err(Into::into)
    }

    /// Validate envelope headers and decode the bincode payload.
    fn decode_inbound(
        &self,
        msg: &MpcRoundMessage,
        expected_phase: MpcPhase,
        expected_round: u32,
    ) -> Result<(u8, KeygenRoundPayload), KeygenError> {
        if msg.instance_id != self.cfg.instance_id {
            return Err(KeygenError::InstanceIdMismatch);
        }
        if msg.phase != expected_phase || msg.round_index != expected_round {
            return Err(KeygenError::UnexpectedPayloadKind {
                expected: expected_phase,
                got: "wrong phase/round",
            });
        }
        let from_index0 = self
            .cfg
            .participant_dids
            .iter()
            .position(|d| d == &msg.from_did)
            .ok_or_else(|| KeygenError::UnknownSender(msg.from_did.clone()))?;
        let from_index = (from_index0 + 1) as u8;
        let payload: KeygenRoundPayload =
            bincode::deserialize(&msg.payload).map_err(|e| KeygenError::MalformedPayload {
                from_did: msg.from_did.clone(),
                detail: e.to_string(),
            })?;
        Ok((from_index, payload))
    }
}

impl KeygenRoundPayload {
    fn variant_name(&self) -> &'static str {
        match self {
            Self::PolyFragment { .. } => "PolyFragment",
            Self::Phase2 { .. } => "Phase2",
            Self::Phase3 { .. } => "Phase3",
        }
    }
}

/// Derive `GroupId` from the group public key + sorted participant DIDs +
/// threshold shape. Mirrors the `GROUP_DOMAIN_TAG` doc on
/// [`crate::mpc::store::GroupId`].
fn derive_group_id(
    group_pk_compressed: &[u8],
    sorted_dids: &[String],
    threshold: u8,
    total_parties: u8,
) -> GroupId {
    let mut h = Sha256::new();
    h.update(GROUP_DOMAIN_TAG);
    h.update(group_pk_compressed);
    let mut first = true;
    for d in sorted_dids {
        if !first {
            h.update([0u8]);
        }
        first = false;
        h.update(d.as_bytes());
    }
    h.update([0u8]); // terminator
    h.update([threshold, total_parties]);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    GroupId(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::sealing::InMemoryKeyshareSealer;
    use crate::mpc::setup::{MpcCurve, SESSION_NONCE_LEN};
    use crate::mpc::transport::MpcRoundMessage;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tenzro_types::Hash;
    use tokio::sync::Mutex;
    use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

    fn make_instance_id() -> InstanceId {
        let block = Hash::from_bytes(&[1u8; 32]).unwrap();
        InstanceId::derive(&block, &[0u8; 32], &[2u8; SESSION_NONCE_LEN])
    }

    fn sorted_dids(n: u8) -> Vec<String> {
        (1..=n)
            .map(|i| format!("did:tenzro:machine:p{:02}", i))
            .collect()
    }

    /// In-process broadcast transport: each party owns one `MockTransport`
    /// holding an inbox receiver + a shared map of inbox senders (keyed by
    /// DID) for routing.
    struct MockTransport {
        local_did: String,
        inboxes: Arc<HashMap<String, UnboundedSender<MpcRoundMessage>>>,
        inbox: Mutex<UnboundedReceiver<MpcRoundMessage>>,
    }

    #[async_trait::async_trait]
    impl Transport for MockTransport {
        async fn send(&self, message: MpcRoundMessage) -> Result<(), TransportError> {
            let to_did = message.to_did.clone();
            self.inboxes
                .get(&to_did)
                .ok_or_else(|| TransportError::Send(format!("unknown peer {to_did}")))?
                .send(message)
                .map_err(|e| TransportError::Send(e.to_string()))?;
            Ok(())
        }

        async fn recv(&self) -> Result<MpcRoundMessage, TransportError> {
            let mut rx = self.inbox.lock().await;
            rx.recv().await.ok_or(TransportError::Closed)
        }
    }

    impl MockTransport {
        fn fan_out(dids: &[String]) -> Vec<Self> {
            let mut inboxes_map: HashMap<String, UnboundedSender<MpcRoundMessage>> =
                HashMap::new();
            let mut transports = Vec::with_capacity(dids.len());
            // First pass: create channels and remember receivers.
            let mut my_rxs: Vec<(String, UnboundedReceiver<MpcRoundMessage>)> =
                Vec::with_capacity(dids.len());
            for d in dids {
                let (tx, rx) = mpsc::unbounded_channel();
                inboxes_map.insert(d.clone(), tx);
                my_rxs.push((d.clone(), rx));
            }
            let inboxes_arc = Arc::new(inboxes_map);
            for (d, rx) in my_rxs {
                transports.push(Self {
                    local_did: d,
                    inboxes: inboxes_arc.clone(),
                    inbox: Mutex::new(rx),
                });
            }
            transports
        }
    }

    #[test]
    fn config_serdes() {
        let cfg = KeygenConfig {
            instance_id: make_instance_id(),
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            participant_dids: sorted_dids(3),
            local_did: "did:tenzro:machine:p01".to_string(),
        };
        let encoded = serde_json::to_vec(&cfg).unwrap();
        let decoded: KeygenConfig = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(cfg, decoded);
    }

    #[test]
    fn config_rejects_unsorted() {
        let cfg = KeygenConfig {
            instance_id: make_instance_id(),
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            participant_dids: vec![
                "did:tenzro:machine:p03".to_string(),
                "did:tenzro:machine:p01".to_string(),
                "did:tenzro:machine:p02".to_string(),
            ],
            local_did: "did:tenzro:machine:p01".to_string(),
        };
        assert!(matches!(
            cfg.validate(),
            Err(KeygenError::UnsortedParticipants)
        ));
    }

    #[test]
    fn config_rejects_count_mismatch() {
        let cfg = KeygenConfig {
            instance_id: make_instance_id(),
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            participant_dids: sorted_dids(2),
            local_did: "did:tenzro:machine:p01".to_string(),
        };
        assert!(matches!(
            cfg.validate(),
            Err(KeygenError::ParticipantCountMismatch { expected: 3, got: 2 })
        ));
    }

    #[test]
    fn local_party_index_is_one_based() {
        let cfg = KeygenConfig {
            instance_id: make_instance_id(),
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            participant_dids: sorted_dids(3),
            local_did: "did:tenzro:machine:p02".to_string(),
        };
        assert_eq!(cfg.local_party_index().unwrap(), 2);
    }

    #[test]
    fn group_id_is_deterministic() {
        let dids = sorted_dids(3);
        let pk = vec![0x02; 33];
        let a = derive_group_id(&pk, &dids, 2, 3);
        let b = derive_group_id(&pk, &dids, 2, 3);
        assert_eq!(a, b);
    }

    #[test]
    fn group_id_differs_with_threshold() {
        let dids = sorted_dids(3);
        let pk = vec![0x02; 33];
        let a = derive_group_id(&pk, &dids, 2, 3);
        let b = derive_group_id(&pk, &dids, 3, 3);
        assert_ne!(a, b);
    }

    /// Full 3-party DKG round-trip: drive `KeygenSession` for all three
    /// parties in-process over `MockTransport`, then assert all three
    /// agree on the group public key and each persisted a sealed envelope
    /// that round-trips through their sealer.
    #[tokio::test]
    async fn three_party_dkg_roundtrip() {
        let dids = sorted_dids(3);
        let instance_id = make_instance_id();
        let parameters = MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap();
        let transports = MockTransport::fan_out(&dids);

        let mut handles = Vec::with_capacity(3);
        for (i, transport) in transports.into_iter().enumerate() {
            let local_did = transport.local_did.clone();
            let cfg = KeygenConfig {
                instance_id,
                parameters,
                participant_dids: dids.clone(),
                local_did,
            };
            let sealer = InMemoryKeyshareSealer::new([0x42u8; 32]);
            let store = crate::mpc::store::tests::MemKeyshareStore::default();
            let store_handle = store.clone();
            let session = KeygenSession::new(cfg, transport, sealer, store).unwrap();
            handles.push((
                tokio::spawn(async move { session.run().await }),
                store_handle,
                i as u8 + 1,
            ));
        }

        let mut outputs = Vec::new();
        let mut stores = Vec::new();
        for (h, s, idx) in handles {
            let out = h.await.unwrap().unwrap();
            assert_eq!(out.local_party_index, idx);
            assert_eq!(out.epoch, 0);
            outputs.push(out);
            stores.push(s);
        }

        // All three parties agree on group pubkey + group id + EVM address.
        let first_pk = outputs[0].group_public_key_compressed.clone();
        let first_gid = outputs[0].group_id;
        let first_addr = outputs[0].address.clone();
        for o in &outputs[1..] {
            assert_eq!(o.group_public_key_compressed, first_pk);
            assert_eq!(o.group_id, first_gid);
            assert_eq!(o.address, first_addr);
        }

        // Every party persisted its own envelope at epoch 0.
        for (store, out) in stores.iter().zip(outputs.iter()) {
            let env = store.get(&out.group_id, 0).await.unwrap();
            assert_eq!(env.party_index, out.local_party_index);
            assert_eq!(env.group_public_key_compressed, out.group_public_key_compressed);
            assert_eq!(env.parameters, parameters);
            // Sealed payload non-empty, share_hash matches sha256(party bytes).
            assert!(!env.sealed_payload.is_empty());
        }
    }
}
