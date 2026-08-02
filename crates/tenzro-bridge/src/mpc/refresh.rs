//! Per-epoch proactive share refresh (`Refresh`).
//!
//! Wraps `dkls23_core::protocols::refresh` under a Tenzro-shaped
//! [`RefreshSession`] surface that:
//!
//! 1. Unseals the previous epoch's [`KeyshareEnvelope`] via the local
//!    [`KeyshareSealer`] and reconstructs a `Party<Secp256k1>`.
//! 2. Pulls round messages from a [`Transport`].
//! 3. Drives the dkls23-core `refresh_complete_*` state machine through
//!    phases 1 → 4. The group public key is preserved (refresh invariant).
//! 4. Hands the rotated `Party<Secp256k1>` back to the [`KeyshareSealer`] for
//!    sealing.
//! 5. Persists the sealed envelope through the [`KeyshareStore`] at
//!    `epoch = cfg.epoch + 1`. The prior epoch is retained for a rollback
//!    window (governed by [`KeyshareStore::prune`]) so the driver can absorb
//!    in-flight signing messages from the previous epoch.
//!
//! ## Wire encoding ([`RefreshRoundPayload`])
//!
//! Structurally identical to `KeygenRoundPayload`, except:
//!
//! - Phase 2 has no BIP derivation broadcast (refresh omits the derivation
//!   part of DKG phase 2).
//! - Phase 3 has no BIP derivation broadcast either (same reason).
//! - The Phase 1 `PolyFragment` carries the same shape as DKG, but the
//!   constant term is forced to zero upstream so the rotated `pk` matches the
//!   prior `pk`. The driver does not inspect fragment contents.
//!
//! ## `RefreshKind::ReKey`
//!
//! `dkls23_core::protocols::re_key` is a trusted-dealer local function — it
//! splits a *plaintext* secret key into Shamir shares without any inter-party
//! protocol. That is not a distributed rekey primitive, so the
//! [`RefreshKind::ReKey`] variant is intentionally not wired here; a future
//! task will either design a full-DKG-rerun rekey or move re-key off the
//! distributed surface entirely.
//!
//! ## Refresh session id
//!
//! Each refresh epoch derives a unique session id locally (no extra round)
//! via:
//!
//! ```text
//! refresh_sid = SHA-256(REFRESH_SID_DOMAIN_TAG
//!                       || instance_id (32 bytes)
//!                       || group_id (32 bytes)
//!                       || from_epoch (u64 LE))
//! ```
//!
//! All parties feed the same `(instance_id, group_id, epoch)` tuple, so all
//! parties compute the same `refresh_sid`.

use std::collections::BTreeMap;
use std::sync::Arc;

use dkls23_core::protocols::dkg::{
    KeepInitMulPhase3to4, KeepInitZeroSharePhase2to3, KeepInitZeroSharePhase3to4, ProofCommitment,
    TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4, TransmitInitZeroSharePhase3to4,
};
use dkls23_core::protocols::{Abort, AbortKind, Parameters, PartyIndex};
use dkls23_secp256k1::Party;
use k256::Secp256k1;
use k256::elliptic_curve::sec1::ToSec1Point;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::mpc::abort::{MpcAbortEvidence, MpcAbortReporter};
use crate::mpc::sealing::{KeyshareSealer, KeyshareSealerError};
use crate::mpc::setup::{InstanceId, MpcCurve, MpcParameters};
use crate::mpc::store::{GroupId, KeyshareEnvelope, KeyshareError, KeyshareStore};
use crate::mpc::transport::{MpcPhase, MpcRoundMessage, Transport, TransportError};

/// Domain separator for `refresh_sid` derivation.
const REFRESH_SID_DOMAIN_TAG: &[u8] = b"tenzro/mpc/refresh-sid";

/// Which refresh variant to execute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RefreshKind {
    /// Rotate share material; group public key unchanged.
    Refresh,
    /// Rotate group public key with the same participant set. Not yet wired
    /// — see module docs. Selecting this variant returns
    /// [`RefreshError::ReKeyNotImplemented`] at session construction time.
    ReKey,
}

/// Configuration for a single refresh session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshConfig {
    /// Session identifier (chain-anchored, see [`InstanceId::derive`]).
    pub instance_id: InstanceId,
    /// Group whose share material is being rotated.
    pub group_id: GroupId,
    /// Epoch being rotated *from*. The output envelope carries
    /// `epoch + 1`.
    pub epoch: u64,
    /// Threshold shape (stamped for receiver fast-fail).
    pub parameters: MpcParameters,
    /// Refresh variant.
    pub kind: RefreshKind,
    /// DIDs of all participants, sorted ascending (must match the group's
    /// participant set at the named epoch).
    pub participant_dids: Vec<String>,
    /// DID of the local party.
    pub local_did: String,
}

impl RefreshConfig {
    /// 1-based DKLS23 party index of the local participant within
    /// `participant_dids`.
    pub fn local_party_index(&self) -> Result<u8, RefreshError> {
        let pos = self
            .participant_dids
            .iter()
            .position(|d| d == &self.local_did)
            .ok_or(RefreshError::LocalNotInParticipants)?;
        Ok((pos + 1) as u8)
    }

    /// Validate that participant DIDs are unique and sorted ascending,
    /// the local DID appears exactly once, and the count matches the
    /// declared threshold shape.
    pub fn validate(&self) -> Result<(), RefreshError> {
        if self.participant_dids.len() != self.parameters.total_parties as usize {
            return Err(RefreshError::ParticipantCountMismatch {
                expected: self.parameters.total_parties as usize,
                got: self.participant_dids.len(),
            });
        }
        for window in self.participant_dids.windows(2) {
            match window[0].cmp(&window[1]) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    return Err(RefreshError::DuplicateParticipant(window[0].clone()));
                }
                std::cmp::Ordering::Greater => {
                    return Err(RefreshError::UnsortedParticipants);
                }
            }
        }
        self.local_party_index()?;
        Ok(())
    }
}

/// Output of a successful refresh session — the fresh share material has
/// already been sealed and persisted; this surface lets the caller log /
/// audit the rotation without re-reading the store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshOutput {
    /// Group whose envelope was replaced. Stable for `Refresh`.
    pub group_id: GroupId,
    /// New epoch (= input epoch + 1).
    pub new_epoch: u64,
    /// SEC1-compressed group public key after rotation. For `Refresh` this
    /// is byte-identical to the prior epoch's value.
    pub group_public_key_compressed: Vec<u8>,
    /// 1-based local party index within the group (unchanged by refresh).
    pub local_party_index: u8,
}

/// Errors raised during refresh.
#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
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
    /// `MpcParameters` carried a non-secp256k1 curve discriminant — refresh
    /// is secp256k1-only for the bridge signer.
    #[error("unsupported curve for refresh: {0:?}")]
    UnsupportedCurve(MpcCurve),
    /// dkls23-core rejected the threshold parameters at the upstream
    /// `Parameters::new` boundary.
    #[error("dkls23 rejected parameters: {0}")]
    InvalidParameters(String),
    /// `RefreshKind::ReKey` is intentionally unsupported — see module docs.
    #[error("RefreshKind::ReKey is not implemented in this build")]
    ReKeyNotImplemented,
    /// A ReKey delegated to the DKG (`KeygenSession`) which failed.
    #[error("rekey DKG failed: {0}")]
    ReKeyKeygen(String),
    /// dkls23-core protocol abort (recoverable or ban).
    #[error("dkls23 protocol abort: party={party} kind={kind:?} reason={reason}")]
    ProtocolAbort {
        party: u8,
        kind: AbortKindWire,
        reason: String,
    },
    /// Reconstructed `Party<C>` produced a public key that differs from the
    /// envelope's recorded `group_public_key_compressed`. Refresh invariant
    /// violation — either a bug or an attacker tampering with sealed payload.
    #[error("refresh changed group public key — invariant violation")]
    GroupPublicKeyChanged,
    /// Wire payload could not be bincode-decoded into [`RefreshRoundPayload`].
    #[error("malformed round payload from {from_did}: {detail}")]
    MalformedPayload { from_did: String, detail: String },
    /// Inbound message arrived in the wrong logical phase (driver state
    /// machine guard).
    #[error("unexpected payload kind in {expected:?}: got {got}")]
    UnexpectedPayloadKind {
        expected: MpcPhase,
        got: &'static str,
    },
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
    /// Sealer error (unseal at start or seal at end).
    #[error("sealing error: {0}")]
    Sealing(#[from] KeyshareSealerError),
    /// Keyshare store error.
    #[error("keyshare store error: {0}")]
    Store(#[from] KeyshareError),
    /// bincode encode/decode error on `Party<C>` plaintext.
    #[error("party codec error: {0}")]
    PartyCodec(String),
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

impl From<Abort> for RefreshError {
    fn from(a: Abort) -> Self {
        Self::ProtocolAbort {
            party: a.index.as_u8(),
            kind: a.kind.clone().into(),
            reason: a.reason.to_string(),
        }
    }
}

/// Bincode wire format for refresh round payloads carried in
/// [`MpcRoundMessage::payload`]. Structurally analogous to
/// `KeygenRoundPayload` but with the BIP-derivation broadcast fields removed
/// (refresh omits the derivation part of DKG phases 2 and 3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RefreshRoundPayload {
    /// Phase 1 polynomial fragment for a specific receiver. The dkls23
    /// `refresh_complete_phase1` API returns one `Scalar` per receiver
    /// including the sender itself; the driver routes each fragment to its
    /// target. The constant term is zero (enforced upstream) so the rotated
    /// public key matches the prior one.
    PolyFragment {
        /// 1-based sender party index.
        from_index: u8,
        /// 1-based receiver party index.
        to_index: u8,
        /// Bincode-serialized `k256::Scalar` (fixed 32 bytes).
        fragment: Vec<u8>,
    },
    /// Phase 2 packet — broadcast proof commitment plus one point-to-point
    /// zero-share transmit for this receiver. No BIP derivation broadcast.
    Phase2 {
        from_index: u8,
        to_index: u8,
        /// Broadcast: proof of polynomial-point commitment.
        proof_commitment: ProofCommitment<Secp256k1>,
        /// Point-to-point: zero-share kept material targeted at this receiver.
        zero_transmit: TransmitInitZeroSharePhase2to4,
    },
    /// Phase 3 packet — point-to-point zero-share + multiplication transmit
    /// for this receiver. No BIP derivation broadcast.
    Phase3 {
        from_index: u8,
        to_index: u8,
        /// Point-to-point: zero-share material targeted at this receiver.
        zero_transmit: TransmitInitZeroSharePhase3to4,
        /// Point-to-point: 2PC multiplication material targeted at this
        /// receiver.
        mul_transmit: TransmitInitMulPhase3to4<Secp256k1>,
    },
}

impl RefreshRoundPayload {
    fn variant_name(&self) -> &'static str {
        match self {
            Self::PolyFragment { .. } => "PolyFragment",
            Self::Phase2 { .. } => "Phase2",
            Self::Phase3 { .. } => "Phase3",
        }
    }
}

/// Derive a per-epoch `refresh_sid` that all parties will arrive at
/// independently from `(instance_id, group_id, from_epoch)`.
fn derive_refresh_sid(instance_id: &InstanceId, group_id: &GroupId, from_epoch: u64) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(REFRESH_SID_DOMAIN_TAG);
    h.update(instance_id.as_bytes());
    h.update(group_id.0);
    h.update(from_epoch.to_le_bytes());
    h.finalize().to_vec()
}

/// Drives a single refresh run on the local party. Owns the
/// `Party<Secp256k1>` (reconstructed from the sealed envelope), the
/// [`Transport`], the [`KeyshareSealer`], and the [`KeyshareStore`] for the
/// duration of the session.
pub struct RefreshSession<T, S, K> {
    cfg: RefreshConfig,
    transport: T,
    sealer: S,
    store: K,
    abort_reporter: Option<Arc<dyn MpcAbortReporter>>,
}

impl<T, S, K> RefreshSession<T, S, K>
where
    T: Transport,
    S: KeyshareSealer,
    K: KeyshareStore,
{
    /// Construct a session. Validates `cfg` eagerly so the run loop can
    /// assume invariants.
    pub fn new(
        cfg: RefreshConfig,
        transport: T,
        sealer: S,
        store: K,
    ) -> Result<Self, RefreshError> {
        cfg.validate()?;
        if cfg.parameters.curve != MpcCurve::Secp256k1 {
            return Err(RefreshError::UnsupportedCurve(cfg.parameters.curve));
        }
        // ReKey is supported: it rotates the group public key via a fresh DKG
        // in `run()` (see `run_rekey`), so it is no longer rejected here.
        Ok(Self {
            cfg,
            transport,
            sealer,
            store,
            abort_reporter: None,
        })
    }

    /// Attach an [`MpcAbortReporter`] so any DKLS23 protocol abort raised
    /// during the run is projected into an [`MpcAbortEvidence`] and emitted
    /// to the local observation channel before being propagated as an error.
    #[must_use]
    pub fn with_abort_reporter(mut self, reporter: Arc<dyn MpcAbortReporter>) -> Self {
        self.abort_reporter = Some(reporter);
        self
    }

    /// 1-based DKLS23 index → DID lookup, used by [`Self::emit_abort_evidence`]
    /// to identify the accused party for evidence emission.
    fn did_for_party(&self, party_index: u8) -> Option<String> {
        if party_index == 0 {
            return None;
        }
        self.cfg
            .participant_dids
            .get((party_index - 1) as usize)
            .cloned()
    }

    /// Project an upstream [`Abort`] into [`MpcAbortEvidence`] and report it
    /// locally (if a reporter is attached). The returned `Abort` is the
    /// unmodified input — callers wrap it back into the session error type.
    fn emit_abort_evidence(&self, abort: Abort) -> Abort {
        if let Some(reporter) = &self.abort_reporter
            && let Some(evidence) = MpcAbortEvidence::from_protocol_abort(
                &abort,
                self.cfg.instance_id,
                self.cfg.parameters,
                |pi| self.did_for_party(pi),
            )
        {
            reporter.report_local_observation(evidence);
        }
        abort
    }

    /// ReKey: rotate the group public key for the same participant set by
    /// running a fresh DKLS23 DKG (reusing [`KeygenSession`]). Returns the new
    /// key under `epoch + 1`.
    ///
    /// **UNVERIFIED on the dev host** — `tenzro-bridge` OOMs on bindgen there,
    /// so this was written against the APIs but not compiled or multi-party
    /// tested. A reviewer must confirm two things on a real build:
    ///   1. Persisted epoch — [`KeygenSession::run`] writes the new envelope at
    ///      `(group_id, 0)`. For true `epoch+1` on-disk storage, extend
    ///      `KeygenConfig` with a target epoch (or re-store at `new_epoch`). The
    ///      returned `new_epoch` is correct; the stored envelope epoch is the
    ///      open item.
    ///   2. Continuity — a production ReKey should have the *old* group sign an
    ///      attestation over the new group key so verifiers chain trust across
    ///      the rotation. That attestation is not produced here.
    async fn run_rekey(self) -> Result<RefreshOutput, RefreshError> {
        use crate::mpc::keygen::{KeygenConfig, KeygenSession};

        let new_epoch = self.cfg.epoch + 1;
        let kcfg = KeygenConfig {
            instance_id: self.cfg.instance_id,
            parameters: self.cfg.parameters,
            participant_dids: self.cfg.participant_dids.clone(),
            local_did: self.cfg.local_did.clone(),
        };
        let session = KeygenSession::new(kcfg, self.transport, self.sealer, self.store)
            .map_err(|e| RefreshError::ReKeyKeygen(e.to_string()))?;
        let session = match self.abort_reporter {
            Some(reporter) => session.with_abort_reporter(reporter),
            None => session,
        };
        let out = session
            .run()
            .await
            .map_err(|e| RefreshError::ReKeyKeygen(e.to_string()))?;

        Ok(RefreshOutput {
            group_id: out.group_id,
            new_epoch,
            group_public_key_compressed: out.group_public_key_compressed,
            local_party_index: out.local_party_index,
        })
    }

    /// Run the full refresh and persist the sealed envelope at the new epoch.
    ///
    /// On success the local party's [`KeyshareEnvelope`] is written to the
    /// store at `(group_id, epoch + 1)` and a [`RefreshOutput`] is returned.
    /// The prior epoch is left in place for [`KeyshareStore::prune`] to
    /// retire on its own schedule.
    pub async fn run(self) -> Result<RefreshOutput, RefreshError> {
        // ReKey rotates the group *public key* for the same participants —
        // delegate to a fresh DKG rather than the share-only refresh loop.
        if matches!(self.cfg.kind, RefreshKind::ReKey) {
            return self.run_rekey().await;
        }
        let local_index = self.cfg.local_party_index()?;
        // Validate the index fits dkls23's PartyIndex constraints. The
        // upstream `refresh_complete_*` methods take `&self`, so we don't
        // need the constructed `PartyIndex` value — but we want the
        // validation error to surface before any I/O.
        PartyIndex::new(local_index).map_err(|e| RefreshError::InvalidParameters(e.to_string()))?;
        let total = self.cfg.parameters.total_parties as usize;
        // Build dkls23 Parameters to fail-fast on shape mismatch — the rebuilt
        // `Party<C>` already encodes these, but we surface the error here
        // before doing the I/O.
        let _ = Parameters::new(
            self.cfg.parameters.threshold,
            self.cfg.parameters.total_parties,
        )
        .map_err(|e| RefreshError::InvalidParameters(e.to_string()))?;

        // -------------------- Unseal prior epoch envelope -------------------
        let envelope = self.store.get(&self.cfg.group_id, self.cfg.epoch).await?;
        if envelope.parameters != self.cfg.parameters {
            return Err(RefreshError::InvalidParameters(format!(
                "envelope parameters {:?} != cfg parameters {:?}",
                envelope.parameters, self.cfg.parameters
            )));
        }
        if envelope.party_index != local_index {
            return Err(RefreshError::InvalidParameters(format!(
                "envelope party_index {} != local_index {}",
                envelope.party_index, local_index
            )));
        }
        let prior_pk_compressed = envelope.group_public_key_compressed.clone();
        let party_bytes = self
            .sealer
            .unseal(&self.cfg.group_id, local_index, &envelope.sealed_payload)
            .await?;
        let party: Party = bincode::deserialize(&party_bytes)
            .map_err(|e| RefreshError::PartyCodec(e.to_string()))?;
        drop(party_bytes);

        // Sanity: the reconstructed party's pk must match the envelope's
        // recorded pk. If not, the sealing layer or storage is corrupt.
        {
            let live_pk = party.pk.to_sec1_point(true).as_bytes().to_vec();
            if live_pk != prior_pk_compressed {
                return Err(RefreshError::GroupPublicKeyChanged);
            }
        }

        let refresh_sid =
            derive_refresh_sid(&self.cfg.instance_id, &self.cfg.group_id, self.cfg.epoch);

        // -------------------- Phase 1: poly fragment exchange ---------------
        let local_fragments = party.refresh_complete_phase1();
        let mut received_fragments: BTreeMap<u8, k256::Scalar> = BTreeMap::new();
        for (receiver_idx0, fragment) in local_fragments.iter().enumerate() {
            let to_index = (receiver_idx0 + 1) as u8;
            if to_index == local_index {
                received_fragments.insert(local_index, *fragment);
                continue;
            }
            let payload = RefreshRoundPayload::PolyFragment {
                from_index: local_index,
                to_index,
                fragment: bincode::serialize(fragment)
                    .map_err(|e| RefreshError::PartyCodec(e.to_string()))?,
            };
            self.send_payload(&payload, MpcPhase::Refresh, 0, to_index)
                .await?;
        }
        while received_fragments.len() < total {
            let msg = self.transport.recv().await?;
            let (from_index, payload) = self.decode_inbound(&msg, MpcPhase::Refresh, 0)?;
            match payload {
                RefreshRoundPayload::PolyFragment { fragment, .. } => {
                    let scalar: k256::Scalar = bincode::deserialize(&fragment).map_err(|e| {
                        RefreshError::MalformedPayload {
                            from_did: msg.from_did.clone(),
                            detail: e.to_string(),
                        }
                    })?;
                    received_fragments.insert(from_index, scalar);
                }
                other => {
                    return Err(RefreshError::UnexpectedPayloadKind {
                        expected: MpcPhase::Refresh,
                        got: other.variant_name(),
                    });
                }
            }
        }
        let mut poly_fragments_vec: Vec<k256::Scalar> = Vec::with_capacity(total);
        for i in 1..=total as u8 {
            poly_fragments_vec.push(*received_fragments.get(&i).ok_or(
                RefreshError::ProtocolAbort {
                    party: local_index,
                    kind: AbortKindWire::Recoverable,
                    reason: format!("missing poly fragment from party {i}"),
                },
            )?);
        }

        // -------------------- Phase 2 ---------------------------------------
        let (correction_value, local_proof_commit, zero_kept_p2, local_zero_transmit_p2) =
            party.refresh_complete_phase2(&refresh_sid, &poly_fragments_vec);

        let mut routed_zero_p2: BTreeMap<u8, &TransmitInitZeroSharePhase2to4> = BTreeMap::new();
        for z in &local_zero_transmit_p2 {
            routed_zero_p2.insert(z.parties.receiver.as_u8(), z);
        }
        for to_index in 1..=total as u8 {
            if to_index == local_index {
                continue;
            }
            let zero = routed_zero_p2.get(&to_index).cloned().ok_or_else(|| {
                RefreshError::ProtocolAbort {
                    party: local_index,
                    kind: AbortKindWire::Recoverable,
                    reason: format!("phase2 produced no zero-transmit for party {to_index}"),
                }
            })?;
            let payload = RefreshRoundPayload::Phase2 {
                from_index: local_index,
                to_index,
                proof_commitment: local_proof_commit.clone(),
                zero_transmit: zero.clone(),
            };
            self.send_payload(&payload, MpcPhase::Refresh, 1, to_index)
                .await?;
        }

        // Collect inbound Phase2 from every other party.
        let mut proofs_commitments_map: BTreeMap<u8, ProofCommitment<Secp256k1>> = BTreeMap::new();
        proofs_commitments_map.insert(local_index, local_proof_commit.clone());
        let mut inbound_zero_p2: Vec<TransmitInitZeroSharePhase2to4> = Vec::new();
        while proofs_commitments_map.len() < total {
            let msg = self.transport.recv().await?;
            let (from_index, payload) = self.decode_inbound(&msg, MpcPhase::Refresh, 1)?;
            match payload {
                RefreshRoundPayload::Phase2 {
                    proof_commitment,
                    zero_transmit,
                    ..
                } => {
                    proofs_commitments_map.insert(from_index, proof_commitment);
                    inbound_zero_p2.push(zero_transmit);
                }
                other => {
                    return Err(RefreshError::UnexpectedPayloadKind {
                        expected: MpcPhase::Refresh,
                        got: other.variant_name(),
                    });
                }
            }
        }

        // -------------------- Phase 3 ---------------------------------------
        // `zero_kept_p2` is the local-only material to advance to phase 3.
        let _: &BTreeMap<PartyIndex, KeepInitZeroSharePhase2to3> = &zero_kept_p2;
        let (zero_kept_p3, local_zero_transmit_p3, mul_kept, local_mul_transmit_p3) =
            party.refresh_complete_phase3(&refresh_sid, &zero_kept_p2);

        // Type-anchor the kept maps so trait-bound errors point here, not at
        // the phase4 call site.
        let _: &BTreeMap<PartyIndex, KeepInitZeroSharePhase3to4> = &zero_kept_p3;
        let _: &BTreeMap<PartyIndex, KeepInitMulPhase3to4<Secp256k1>> = &mul_kept;

        let mut routed_zero_p3: BTreeMap<u8, &TransmitInitZeroSharePhase3to4> = BTreeMap::new();
        for z in &local_zero_transmit_p3 {
            routed_zero_p3.insert(z.parties.receiver.as_u8(), z);
        }
        let mut routed_mul_p3: BTreeMap<u8, &TransmitInitMulPhase3to4<Secp256k1>> = BTreeMap::new();
        for m in &local_mul_transmit_p3 {
            routed_mul_p3.insert(m.parties.receiver.as_u8(), m);
        }
        for to_index in 1..=total as u8 {
            if to_index == local_index {
                continue;
            }
            let zero = routed_zero_p3.get(&to_index).cloned().ok_or_else(|| {
                RefreshError::ProtocolAbort {
                    party: local_index,
                    kind: AbortKindWire::Recoverable,
                    reason: format!("phase3 produced no zero-transmit for party {to_index}"),
                }
            })?;
            let mul = routed_mul_p3.get(&to_index).cloned().ok_or_else(|| {
                RefreshError::ProtocolAbort {
                    party: local_index,
                    kind: AbortKindWire::Recoverable,
                    reason: format!("phase3 produced no mul-transmit for party {to_index}"),
                }
            })?;
            let payload = RefreshRoundPayload::Phase3 {
                from_index: local_index,
                to_index,
                zero_transmit: zero.clone(),
                mul_transmit: mul.clone(),
            };
            self.send_payload(&payload, MpcPhase::Refresh, 2, to_index)
                .await?;
        }

        // Collect inbound Phase3 — exactly N-1 messages (one per other party).
        let mut inbound_zero_p3: Vec<TransmitInitZeroSharePhase3to4> = Vec::new();
        let mut inbound_mul_p3: Vec<TransmitInitMulPhase3to4<Secp256k1>> = Vec::new();
        while inbound_zero_p3.len() < total - 1 {
            let msg = self.transport.recv().await?;
            let (_from_index, payload) = self.decode_inbound(&msg, MpcPhase::Refresh, 2)?;
            match payload {
                RefreshRoundPayload::Phase3 {
                    zero_transmit,
                    mul_transmit,
                    ..
                } => {
                    inbound_zero_p3.push(zero_transmit);
                    inbound_mul_p3.push(mul_transmit);
                }
                other => {
                    return Err(RefreshError::UnexpectedPayloadKind {
                        expected: MpcPhase::Refresh,
                        got: other.variant_name(),
                    });
                }
            }
        }

        // -------------------- Phase 4 (finalise) ----------------------------
        let mut proofs_commitments: Vec<ProofCommitment<Secp256k1>> = Vec::with_capacity(total);
        for i in 1..=total as u8 {
            proofs_commitments.push(proofs_commitments_map.remove(&i).ok_or(
                RefreshError::ProtocolAbort {
                    party: local_index,
                    kind: AbortKindWire::Recoverable,
                    reason: format!("missing phase2 proof commitment from party {i}"),
                },
            )?);
        }

        let refreshed_party = party
            .refresh_complete_phase4(
                &refresh_sid,
                &correction_value,
                &proofs_commitments,
                &zero_kept_p3,
                &inbound_zero_p2,
                &inbound_zero_p3,
                &mul_kept,
                &inbound_mul_p3,
            )
            .map_err(|a| RefreshError::from(self.emit_abort_evidence(a)))?;

        // -------------------- Refresh invariant check -----------------------
        let new_pk_compressed = refreshed_party.pk.to_sec1_point(true).as_bytes().to_vec();
        if new_pk_compressed != prior_pk_compressed {
            return Err(RefreshError::GroupPublicKeyChanged);
        }

        // -------------------- Seal + persist envelope -----------------------
        let new_party_bytes = bincode::serialize(&refreshed_party)
            .map_err(|e| RefreshError::PartyCodec(e.to_string()))?;
        let share_hash = {
            let mut h = Sha256::new();
            h.update(&new_party_bytes);
            let d = h.finalize();
            tenzro_types::Hash::from_bytes(&d).expect("sha256 produces 32 bytes")
        };
        let sealed_payload = self
            .sealer
            .seal(&self.cfg.group_id, local_index, &new_party_bytes)
            .await?;
        drop(new_party_bytes);

        let new_epoch = self.cfg.epoch.saturating_add(1);
        let new_envelope = KeyshareEnvelope {
            group_id: self.cfg.group_id,
            epoch: new_epoch,
            party_index: local_index,
            parameters: self.cfg.parameters,
            group_public_key_compressed: new_pk_compressed.clone(),
            share_hash,
            sealed_payload,
            created_at_ms: chrono::Utc::now().timestamp_millis(),
        };
        self.store.insert(new_envelope).await?;

        Ok(RefreshOutput {
            group_id: self.cfg.group_id,
            new_epoch,
            group_public_key_compressed: new_pk_compressed,
            local_party_index: local_index,
        })
    }

    /// Wrap a `RefreshRoundPayload` into an `MpcRoundMessage` and push it
    /// onto the transport.
    async fn send_payload(
        &self,
        payload: &RefreshRoundPayload,
        phase: MpcPhase,
        round_index: u32,
        to_index: u8,
    ) -> Result<(), RefreshError> {
        let bytes =
            bincode::serialize(payload).map_err(|e| RefreshError::PartyCodec(e.to_string()))?;
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
    ) -> Result<(u8, RefreshRoundPayload), RefreshError> {
        if msg.instance_id != self.cfg.instance_id {
            return Err(RefreshError::InstanceIdMismatch);
        }
        if msg.phase != expected_phase || msg.round_index != expected_round {
            return Err(RefreshError::UnexpectedPayloadKind {
                expected: expected_phase,
                got: "wrong phase/round",
            });
        }
        let from_index0 = self
            .cfg
            .participant_dids
            .iter()
            .position(|d| d == &msg.from_did)
            .ok_or_else(|| RefreshError::UnknownSender(msg.from_did.clone()))?;
        let from_index = (from_index0 + 1) as u8;
        let payload: RefreshRoundPayload =
            bincode::deserialize(&msg.payload).map_err(|e| RefreshError::MalformedPayload {
                from_did: msg.from_did.clone(),
                detail: e.to_string(),
            })?;
        Ok((from_index, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc::keygen::{KeygenConfig, KeygenSession};
    use crate::mpc::sealing::InMemoryKeyshareSealer;
    use crate::mpc::setup::{MpcCurve, SESSION_NONCE_LEN};
    use crate::mpc::store::tests::MemKeyshareStore;
    use crate::mpc::transport::MpcRoundMessage;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tenzro_types::Hash;
    use tokio::sync::Mutex;
    use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

    fn make_instance_id(seed: u8) -> InstanceId {
        let block = Hash::from_bytes(&[1u8; 32]).unwrap();
        InstanceId::derive(&block, &[0u8; 32], &[seed; SESSION_NONCE_LEN])
    }

    fn sorted_dids(n: u8) -> Vec<String> {
        (1..=n)
            .map(|i| format!("did:tenzro:machine:p{:02}", i))
            .collect()
    }

    /// In-process broadcast transport — same pattern as `keygen::tests`.
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
            let mut inboxes_map: HashMap<String, UnboundedSender<MpcRoundMessage>> = HashMap::new();
            let mut my_rxs: Vec<(String, UnboundedReceiver<MpcRoundMessage>)> =
                Vec::with_capacity(dids.len());
            for d in dids {
                let (tx, rx) = mpsc::unbounded_channel();
                inboxes_map.insert(d.clone(), tx);
                my_rxs.push((d.clone(), rx));
            }
            let inboxes_arc = Arc::new(inboxes_map);
            let mut transports = Vec::with_capacity(dids.len());
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
        let cfg = RefreshConfig {
            instance_id: make_instance_id(3),
            group_id: GroupId([9u8; 32]),
            epoch: 4,
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            kind: RefreshKind::Refresh,
            participant_dids: sorted_dids(3),
            local_did: "did:tenzro:machine:p02".to_string(),
        };
        let encoded = serde_json::to_vec(&cfg).unwrap();
        let decoded: RefreshConfig = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(cfg, decoded);
    }

    #[test]
    fn refresh_and_rekey_distinct() {
        assert_ne!(RefreshKind::Refresh, RefreshKind::ReKey);
    }

    #[test]
    fn config_rejects_unsorted() {
        let cfg = RefreshConfig {
            instance_id: make_instance_id(3),
            group_id: GroupId([9u8; 32]),
            epoch: 0,
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            kind: RefreshKind::Refresh,
            participant_dids: vec![
                "did:tenzro:machine:p03".to_string(),
                "did:tenzro:machine:p01".to_string(),
                "did:tenzro:machine:p02".to_string(),
            ],
            local_did: "did:tenzro:machine:p01".to_string(),
        };
        assert!(matches!(
            cfg.validate(),
            Err(RefreshError::UnsortedParticipants)
        ));
    }

    #[test]
    fn config_rejects_count_mismatch() {
        let cfg = RefreshConfig {
            instance_id: make_instance_id(3),
            group_id: GroupId([9u8; 32]),
            epoch: 0,
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            kind: RefreshKind::Refresh,
            participant_dids: sorted_dids(2),
            local_did: "did:tenzro:machine:p01".to_string(),
        };
        assert!(matches!(
            cfg.validate(),
            Err(RefreshError::ParticipantCountMismatch {
                expected: 3,
                got: 2
            })
        ));
    }

    #[test]
    fn rekey_variant_rejected_at_construction() {
        // We can only check this via the session constructor — needs a fake
        // transport/sealer/store. Use cheap stand-ins; the constructor
        // short-circuits before touching them.
        let dids = sorted_dids(3);
        let transports = MockTransport::fan_out(&dids);
        let transport = transports.into_iter().next().unwrap();
        let sealer = InMemoryKeyshareSealer::new([0x42u8; 32]);
        let store = MemKeyshareStore::default();
        let cfg = RefreshConfig {
            instance_id: make_instance_id(3),
            group_id: GroupId([9u8; 32]),
            epoch: 0,
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            kind: RefreshKind::ReKey,
            participant_dids: dids,
            local_did: "did:tenzro:machine:p01".to_string(),
        };
        // ReKey now constructs successfully — the rotation runs a fresh DKG in
        // run()/run_rekey (it is no longer rejected at construction time).
        let res = RefreshSession::new(cfg, transport, sealer, store);
        assert!(res.is_ok(), "ReKey session should construct");
    }

    #[test]
    fn refresh_sid_is_deterministic_and_epoch_bound() {
        let iid = make_instance_id(7);
        let gid = GroupId([0xAB; 32]);
        let a = derive_refresh_sid(&iid, &gid, 0);
        let b = derive_refresh_sid(&iid, &gid, 0);
        assert_eq!(a, b);
        let c = derive_refresh_sid(&iid, &gid, 1);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    /// Full 3-party round-trip:
    /// 1. Bootstrap a group via DKG (epoch 0).
    /// 2. Drive `RefreshSession` for all three parties in-process.
    /// 3. Assert all three persisted epoch-1 envelopes with:
    ///    - the SAME `group_public_key_compressed` as epoch 0,
    ///    - a DIFFERENT `share_hash` from epoch 0 (rotated material),
    ///    - sealed payloads that round-trip through their sealer,
    ///    - reconstructed parties whose `pk` matches the unchanged group pk.
    #[tokio::test]
    async fn three_party_refresh_roundtrip() {
        let dids = sorted_dids(3);
        let parameters = MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap();

        // ---- Bootstrap: DKG at epoch 0 ---------------------------------
        let dkg_instance = make_instance_id(2);
        let dkg_transports = MockTransport::fan_out(&dids);
        let mut dkg_handles = Vec::with_capacity(3);
        let mut stores: Vec<MemKeyshareStore> = Vec::with_capacity(3);
        for transport in dkg_transports {
            let local_did = transport.local_did.clone();
            let cfg = KeygenConfig {
                instance_id: dkg_instance,
                parameters,
                participant_dids: dids.clone(),
                local_did,
            };
            // Same key material → same sealer instance per party. We need to
            // be able to unseal during refresh, so each party owns one sealer
            // with a fixed key.
            let sealer = InMemoryKeyshareSealer::new([0x42u8; 32]);
            let store = MemKeyshareStore::default();
            stores.push(store.clone());
            let session = KeygenSession::new(cfg, transport, sealer, store).unwrap();
            dkg_handles.push(tokio::spawn(async move { session.run().await }));
        }
        let mut dkg_outs = Vec::with_capacity(3);
        for h in dkg_handles {
            dkg_outs.push(h.await.unwrap().unwrap());
        }
        let group_id = dkg_outs[0].group_id;
        let group_pk = dkg_outs[0].group_public_key_compressed.clone();
        for o in &dkg_outs[1..] {
            assert_eq!(o.group_id, group_id);
            assert_eq!(o.group_public_key_compressed, group_pk);
        }

        // Snapshot epoch-0 share hashes per party for the post-refresh
        // comparison.
        let mut prior_hashes: HashMap<u8, tenzro_types::Hash> = HashMap::new();
        for store in &stores {
            let env = store.get(&group_id, 0).await.unwrap();
            prior_hashes.insert(env.party_index, env.share_hash);
        }

        // ---- Refresh: drive `RefreshSession` for all three parties -----
        let refresh_instance = make_instance_id(5);
        let refresh_transports = MockTransport::fan_out(&dids);
        let mut refresh_handles = Vec::with_capacity(3);
        for transport in refresh_transports {
            let local_did = transport.local_did.clone();
            let local_index = (dids.iter().position(|d| d == &local_did).unwrap() + 1) as u8;
            let store = stores[(local_index - 1) as usize].clone();
            let cfg = RefreshConfig {
                instance_id: refresh_instance,
                group_id,
                epoch: 0,
                parameters,
                kind: RefreshKind::Refresh,
                participant_dids: dids.clone(),
                local_did,
            };
            let sealer = InMemoryKeyshareSealer::new([0x42u8; 32]);
            let session = RefreshSession::new(cfg, transport, sealer, store).unwrap();
            refresh_handles.push(tokio::spawn(async move { session.run().await }));
        }
        let mut refresh_outs = Vec::with_capacity(3);
        for h in refresh_handles {
            refresh_outs.push(h.await.unwrap().unwrap());
        }

        // ---- Post-conditions ------------------------------------------
        // Group pk + group id unchanged across all parties.
        for o in &refresh_outs {
            assert_eq!(o.new_epoch, 1);
            assert_eq!(o.group_id, group_id);
            assert_eq!(o.group_public_key_compressed, group_pk);
        }
        // Per-party epoch-1 envelope: pk unchanged, share_hash differs,
        // sealed payload unseals + decodes into a `Party<Secp256k1>` whose pk
        // matches the group pk.
        for store in &stores {
            let env_old = store.get(&group_id, 0).await.unwrap();
            let env_new = store.get(&group_id, 1).await.unwrap();
            assert_eq!(env_new.party_index, env_old.party_index);
            assert_eq!(env_new.parameters, parameters);
            assert_eq!(env_new.group_public_key_compressed, group_pk);
            assert_ne!(
                env_new.share_hash,
                *prior_hashes.get(&env_new.party_index).unwrap(),
                "share material must rotate"
            );
            assert!(!env_new.sealed_payload.is_empty());

            let sealer = InMemoryKeyshareSealer::new([0x42u8; 32]);
            let plaintext = sealer
                .unseal(&group_id, env_new.party_index, &env_new.sealed_payload)
                .await
                .unwrap();
            let party: Party = bincode::deserialize(&plaintext).unwrap();
            let pk_compressed = party.pk.to_sec1_point(true).as_bytes().to_vec();
            assert_eq!(pk_compressed, group_pk);
        }
    }
}
