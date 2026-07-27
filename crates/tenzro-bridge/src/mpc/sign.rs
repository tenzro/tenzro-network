//! Distributed signing session driver producing a recoverable secp256k1
//! signature ready for EVM transaction submission.
//!
//! Wraps `dkls23_core::protocols::sign_session::SignSession<Secp256k1>` under
//! a Tenzro-shaped [`SignSession`] surface that:
//!
//! 1. Unseals the local party's [`KeyshareEnvelope`] at session start via a
//!    [`KeyshareSealer`], holding the recovered `Party<Secp256k1>` for the
//!    session's lifetime (the upstream `SignSession<'a, C>` borrows
//!    `&'a Party<C>`).
//! 2. Pulls round messages from a [`Transport`].
//! 3. Drives the dkls23-core state machine through phases 1 → 4.
//! 4. Converts the resulting `EcdsaSignature { r, s, recovery_id }` to a
//!    Tenzro-shaped [`SignOutput`] (`r, s, v`) and verifies it against the
//!    group public key before returning.
//!
//! The output is a 65-byte `(r, s, v)` triple compatible with the existing
//! [`crate::evm_signer::EvmTransactionSigner`] return type, so swapping the
//! single-key signer for the threshold signer is a backend change invisible
//! to bridge adapters.
//!
//! ## Wire encoding ([`SigningRoundPayload`])
//!
//! The opaque `payload` field on [`MpcRoundMessage`] carries a bincode-
//! serialized [`SigningRoundPayload`] enum. The enum discriminates the three
//! logical message classes the dkls23 sign state machine emits:
//!
//! - **Phase 1 → 2 (`Phase1to2`)** — point-to-point: each party sends one
//!   `TransmitPhase1to2` to every counterparty (excluding self).
//! - **Phase 2 → 3 (`Phase2to3`)** — point-to-point: each party sends one
//!   `TransmitPhase2to3<Secp256k1>` to every counterparty.
//! - **Phase 3 → 4 (`Phase3to4`)** — broadcast: each party broadcasts one
//!   `Broadcast3to4<Secp256k1>` to all counterparties. The driver unrolls
//!   the broadcast into one [`MpcRoundMessage`] per recipient so the
//!   [`Transport`] only ever sees point-to-point envelopes.
//!
//! ## Counterparties vs participants
//!
//! `SignData::counterparties` is the quorum **excluding self** (DKLS23
//! convention); [`SignConfig::quorum_dids`] is the full quorum **including
//! self**. The driver derives counterparties internally from `quorum_dids`
//! and `local_did`.

use std::collections::BTreeMap;
use std::sync::Arc;

use dkls23_core::protocols::sign_session::SignSession as DklsSignSession;
use dkls23_core::protocols::signature::EcdsaSignature;
use dkls23_core::protocols::signing::{
    verify_ecdsa_signature, Broadcast3to4, SignData, TransmitPhase1to2, TransmitPhase2to3,
};
use dkls23_core::protocols::{Abort, AbortKind, Party, PartyIndex};
use k256::elliptic_curve::sec1::{FromSec1Point, Sec1Point};
use k256::Secp256k1;
use serde::{Deserialize, Serialize};

use crate::mpc::abort::{MpcAbortEvidence, MpcAbortReporter};
use crate::mpc::keygen::AbortKindWire;
use crate::mpc::sealing::{KeyshareSealer, KeyshareSealerError};
use crate::mpc::setup::{InstanceId, MpcCurve, MpcParameters};
use crate::mpc::store::{GroupId, KeyshareError, KeyshareStore};
use crate::mpc::transport::{MpcPhase, MpcRoundMessage, Transport, TransportError};

/// Bincode wire format for sign round payloads carried in
/// [`MpcRoundMessage::payload`].
///
/// One variant per inter-phase message class. The driver bincode-serializes
/// the enum into the opaque transport payload; the receiving driver
/// deserializes and dispatches on the discriminant.
#[derive(Clone, Debug, Serialize, Deserialize)]
// Wire-format enum; variants are always heap-allocated in transit, boxing gains nothing.
#[allow(clippy::large_enum_variant)]
pub enum SigningRoundPayload {
    /// Phase 1 → 2 point-to-point: one `TransmitPhase1to2` from sender to
    /// receiver. Both `from_index` and `to_index` are 1-based DKLS23 party
    /// indices.
    Phase1to2 {
        from_index: u8,
        to_index: u8,
        transmit: TransmitPhase1to2,
    },
    /// Phase 2 → 3 point-to-point: one `TransmitPhase2to3<Secp256k1>` from
    /// sender to receiver.
    Phase2to3 {
        from_index: u8,
        to_index: u8,
        transmit: TransmitPhase2to3<Secp256k1>,
    },
    /// Phase 3 → 4 broadcast: each party's `Broadcast3to4<Secp256k1>` packet
    /// is unrolled into one envelope per peer.
    Phase3to4 {
        from_index: u8,
        to_index: u8,
        broadcast: Broadcast3to4<Secp256k1>,
    },
}

impl SigningRoundPayload {
    fn variant_name(&self) -> &'static str {
        match self {
            Self::Phase1to2 { .. } => "Phase1to2",
            Self::Phase2to3 { .. } => "Phase2to3",
            Self::Phase3to4 { .. } => "Phase3to4",
        }
    }
}

/// Configuration for a single signing session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignConfig {
    /// Session identifier (chain-anchored, see [`InstanceId::derive`]).
    pub instance_id: InstanceId,
    /// Group whose share material backs this signature.
    pub group_id: GroupId,
    /// Group epoch at session start. The session driver rejects on
    /// mid-session epoch advance.
    pub epoch: u64,
    /// Threshold shape (stamped for receiver fast-fail).
    pub parameters: MpcParameters,
    /// SEC1-compressed group public key. Used for output verification
    /// before returning the signature to the bridge adapter.
    pub group_public_key_compressed: Vec<u8>,
    /// SHA-256 of the payload to sign (EVM transaction hash for the
    /// bridge signer).
    pub message_hash: [u8; 32],
    /// DIDs of the quorum members participating in this session (drawn by
    /// [`crate::mpc::committee::select_signing_quorum`]). Sorted ascending
    /// so all parties derive the same DKLS23 `PartyIndex` mapping. Length
    /// must equal `parameters.threshold`.
    pub quorum_dids: Vec<String>,
    /// DID of the local party — must appear in `quorum_dids`.
    pub local_did: String,
}

impl SignConfig {
    /// 1-based DKLS23 party index of the local participant within
    /// `quorum_dids`.
    pub fn local_party_index(&self) -> Result<u8, SignError> {
        let pos = self
            .quorum_dids
            .iter()
            .position(|d| d == &self.local_did)
            .ok_or(SignError::LocalNotInQuorum)?;
        Ok((pos + 1) as u8)
    }

    /// Validate quorum size, sort order, and local presence. The session
    /// driver assumes all three.
    pub fn validate(&self) -> Result<(), SignError> {
        if self.quorum_dids.len() != self.parameters.threshold as usize {
            return Err(SignError::QuorumSizeMismatch {
                got: self.quorum_dids.len(),
                expected: self.parameters.threshold,
            });
        }
        for window in self.quorum_dids.windows(2) {
            match window[0].cmp(&window[1]) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    return Err(SignError::DuplicateQuorumMember(window[0].clone()));
                }
                std::cmp::Ordering::Greater => {
                    return Err(SignError::UnsortedQuorum);
                }
            }
        }
        self.local_party_index()?;
        Ok(())
    }
}

/// Output of a successful signing session: an EVM-compatible recoverable
/// secp256k1 signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignOutput {
    /// 32-byte big-endian `r`.
    pub r: [u8; 32],
    /// 32-byte big-endian `s` (low-s normalized per EIP-2).
    pub s: [u8; 32],
    /// 1-byte recovery id (0 or 1 — the 27/28/35+chain_id offset is
    /// applied by the EVM transaction encoder, not here).
    pub v: u8,
}

impl SignOutput {
    /// Encode as 65-byte `(r || s || v)` blob.
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = self.v;
        out
    }
}

impl From<EcdsaSignature> for SignOutput {
    fn from(sig: EcdsaSignature) -> Self {
        Self {
            r: sig.r,
            s: sig.s,
            v: sig.recovery_id,
        }
    }
}

/// Errors raised during distributed signing.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// Local DID not present in quorum.
    #[error("local DID not in quorum")]
    LocalNotInQuorum,
    /// Quorum DIDs are not unique.
    #[error("duplicate quorum member DID: {0}")]
    DuplicateQuorumMember(String),
    /// Quorum DIDs are not in canonical ascending order. Required so all
    /// parties derive the same DKLS23 `PartyIndex` mapping.
    #[error("quorum DIDs must be sorted ascending")]
    UnsortedQuorum,
    /// Quorum size does not match `parameters.threshold`.
    #[error("quorum size {got} does not match threshold {expected}")]
    QuorumSizeMismatch { got: usize, expected: u8 },
    /// `MpcParameters` carried a non-secp256k1 curve discriminant — signing
    /// is secp256k1-only for the bridge signer.
    #[error("unsupported curve for signing: {0:?}")]
    UnsupportedCurve(MpcCurve),
    /// dkls23-core rejected the threshold parameters at the upstream
    /// `Parameters::new` boundary.
    #[error("dkls23 rejected parameters: {0}")]
    InvalidParameters(String),
    /// Group public key carried by [`SignConfig`] could not be decoded as a
    /// SEC1-compressed secp256k1 point — used for output verification.
    #[error("malformed group public key: {0}")]
    MalformedGroupPublicKey(String),
    /// dkls23-core protocol abort. Translated to the on-chain
    /// [`crate::mpc::abort::MpcAbortEvidence`] by the session driver.
    #[error("dkls23 protocol abort: party={party} kind={kind:?} reason={reason}")]
    ProtocolAbort {
        party: u8,
        kind: AbortKindWire,
        reason: String,
    },
    /// Output signature failed verification against the group public key.
    /// Indicates a protocol-internal bug, not a counterparty fault — abort
    /// and do not publish the signature.
    #[error("output signature did not verify against group public key")]
    OutputSignatureInvalid,
    /// Wire payload could not be bincode-decoded into [`SigningRoundPayload`].
    #[error("malformed round payload from {from_did}: {detail}")]
    MalformedPayload { from_did: String, detail: String },
    /// Inbound message arrived in the wrong logical phase or round.
    #[error("unexpected payload kind in {expected:?}: got {got}")]
    UnexpectedPayloadKind { expected: MpcPhase, got: &'static str },
    /// Inbound message did not match the active `InstanceId` — cross-session
    /// splice attempt or routing bug.
    #[error("instance id mismatch on inbound message")]
    InstanceIdMismatch,
    /// Inbound message claimed an unknown sender DID.
    #[error("unknown sender DID: {0}")]
    UnknownSender(String),
    /// Stored envelope's group does not match `SignConfig::group_id`.
    #[error("envelope group id mismatch")]
    EnvelopeGroupMismatch,
    /// Stored envelope's epoch does not match `SignConfig::epoch`.
    #[error("envelope epoch mismatch: expected {expected}, got {got}")]
    EnvelopeEpochMismatch { expected: u64, got: u64 },
    /// Stored envelope's parameters do not match `SignConfig::parameters`.
    #[error("envelope parameters mismatch")]
    EnvelopeParametersMismatch,
    /// Stored envelope's group public key does not match
    /// `SignConfig::group_public_key_compressed`.
    #[error("envelope group public key mismatch")]
    EnvelopeGroupPublicKeyMismatch,
    /// Sealer error.
    #[error("sealing error: {0}")]
    Sealing(#[from] KeyshareSealerError),
    /// Keyshare store error.
    #[error("keyshare store error: {0}")]
    Store(#[from] KeyshareError),
    /// bincode encode/decode error on `Party<Secp256k1>` or wire payload.
    #[error("party encode/decode error: {0}")]
    PartyCodec(String),
    /// Underlying transport failure.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
}

impl From<Abort> for SignError {
    fn from(a: Abort) -> Self {
        Self::ProtocolAbort {
            party: a.index.as_u8(),
            kind: match a.kind {
                AbortKind::Recoverable => AbortKindWire::Recoverable,
                AbortKind::BanCounterparty(pi) => AbortKindWire::BanCounterparty(pi.as_u8()),
            },
            reason: a.reason.to_string(),
        }
    }
}

/// Object-safe async handle that produces a recoverable secp256k1 signature
/// over a 32-byte prehash via the DKLS23 threshold signing protocol.
///
/// One handle is bound to a single MPC group (and the storage / sealer /
/// transport / chain-entropy plumbing needed to drive a `SignSession`). The
/// bridge crate is intentionally chain-agnostic and transport-agnostic: the
/// node layer constructs the concrete impl, fixing the group identity, the
/// `Arc<dyn KeyshareStore>`, the `Arc<dyn KeyshareSealer>`, the libp2p
/// transport factory, the optional [`MpcAbortReporter`], and the
/// finalized-block-hash source used as `chain_entropy` for committee draw.
///
/// The bridge's [`crate::evm_signer::EvmTransactionSigner`] holds an
/// `Arc<dyn ThresholdSigner>` in the `ThresholdKey` backend variant and
/// invokes `sign_prehash` from `encode_eip1559_transaction`. Adapter code
/// (LayerZero / Chainlink CCIP / deBridge / Wormhole / Li.Fi) sees no
/// difference between raw-key, TEE-sealed, and threshold backends — all
/// three return the same `SignOutput` shape.
#[async_trait::async_trait]
pub trait ThresholdSigner: Send + Sync {
    /// Sender address derived from the group public key. Returned as the
    /// 20-byte Ethereum address (Keccak-256 of the uncompressed secp256k1
    /// point tail, low 20 bytes). The bridge signer caches this at
    /// construction so RLP and nonce-sync paths do not need to call back
    /// into the trait.
    fn sender_address(&self) -> [u8; 20];

    /// Drive a full DKLS23 sign run for `msg_hash` and return the resulting
    /// recoverable signature. The implementation is responsible for:
    ///
    /// 1. Resolving the current group epoch.
    /// 2. Fetching the finalized block hash (used as `chain_entropy`).
    /// 3. Running [`crate::mpc::committee::build_committee_bound_sign_config`]
    ///    to decide Participant / Observer / UnderQuorum.
    /// 4. On Participant, constructing a [`SignSession`] over the libp2p
    ///    transport and awaiting [`SignSession::run`].
    /// 5. On Observer or UnderQuorum, returning the appropriate
    ///    [`SignError`] without burning round numbers.
    async fn sign_prehash(&self, msg_hash: [u8; 32]) -> Result<SignOutput, SignError>;
}

/// Drives a single distributed signing run on the local party. Owns the
/// [`Transport`], the [`KeyshareSealer`], and the [`KeyshareStore`] for the
/// duration of the session. The unsealed `Party<Secp256k1>` is held on the
/// stack inside [`run`](Self::run) since the upstream
/// `SignSession<'a, C>` borrows `&'a Party<C>` for the whole protocol.
pub struct SignSession<T, S, K> {
    cfg: SignConfig,
    transport: T,
    sealer: S,
    store: K,
    /// Optional reporter for locally-observed identifiable aborts.
    abort_reporter: Option<Arc<dyn MpcAbortReporter>>,
}

impl<T, S, K> SignSession<T, S, K>
where
    T: Transport,
    S: KeyshareSealer,
    K: KeyshareStore,
{
    /// Construct a session. Validates `cfg` eagerly so the run loop can
    /// assume invariants.
    pub fn new(cfg: SignConfig, transport: T, sealer: S, store: K) -> Result<Self, SignError> {
        cfg.validate()?;
        if cfg.parameters.curve != MpcCurve::Secp256k1 {
            return Err(SignError::UnsupportedCurve(cfg.parameters.curve));
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

    /// Resolve a 1-based DKLS23 party index to a quorum-member DID. Returns
    /// `None` for indices outside `1..=threshold`.
    fn did_for_party(&self, party_index: u8) -> Option<String> {
        if party_index == 0 {
            return None;
        }
        self.cfg
            .quorum_dids
            .get((party_index - 1) as usize)
            .cloned()
    }

    /// Project a `dkls23_core::protocols::Abort` into [`MpcAbortEvidence`]
    /// and hand it to the installed reporter (if any). Always returns the
    /// abort so the caller can convert to `SignError::ProtocolAbort`.
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

    /// Run the full signing protocol and return the resulting recoverable
    /// signature.
    ///
    /// Steps:
    ///
    /// 1. Fetch + unseal the local party's envelope.
    /// 2. Reconstruct `Party<Secp256k1>` and create a `DklsSignSession`.
    /// 3. Drive phases 1 → 4 over the [`Transport`].
    /// 4. Convert the resulting `EcdsaSignature` to [`SignOutput`] and
    ///    verify it against the group public key.
    pub async fn run(self) -> Result<SignOutput, SignError> {
        let local_index = self.cfg.local_party_index()?;

        // -------------------- Fetch + unseal local share -------------------
        let envelope = self
            .store
            .get(&self.cfg.group_id, self.cfg.epoch)
            .await?;
        if envelope.group_id != self.cfg.group_id {
            return Err(SignError::EnvelopeGroupMismatch);
        }
        if envelope.epoch != self.cfg.epoch {
            return Err(SignError::EnvelopeEpochMismatch {
                expected: self.cfg.epoch,
                got: envelope.epoch,
            });
        }
        if envelope.parameters != self.cfg.parameters {
            return Err(SignError::EnvelopeParametersMismatch);
        }
        if envelope.group_public_key_compressed != self.cfg.group_public_key_compressed {
            return Err(SignError::EnvelopeGroupPublicKeyMismatch);
        }
        let party_bytes = self
            .sealer
            .unseal(
                &envelope.group_id,
                envelope.party_index,
                &envelope.sealed_payload,
            )
            .await?;
        let party: Party<Secp256k1> = bincode::deserialize(&party_bytes)
            .map_err(|e| SignError::PartyCodec(e.to_string()))?;
        drop(party_bytes); // best-effort scrub the encoded plaintext

        // -------------------- Build SignData -------------------------------
        // counterparties = quorum_dids minus self, mapped to PartyIndex via
        // the envelope's party_index for each quorum member. The DKG output
        // guarantees envelope.party_index is the same 1-based index every
        // party uses; the quorum DIDs in this signing session are a subset
        // of the original participants, but their PartyIndex is whatever
        // their DKG-assigned index is — that index is what's bound into
        // the share material. For task #18 we use the simplification that
        // `quorum_dids` is the canonical sort that produced the DKG
        // PartyIndex mapping; cross-session quorum subselection lands with
        // committee selection in task #22.
        let counterparties: Vec<PartyIndex> = (1..=self.cfg.parameters.threshold)
            .filter(|&i| i != local_index)
            .map(|i| {
                PartyIndex::new(i).map_err(|e| SignError::InvalidParameters(e.to_string()))
            })
            .collect::<Result<_, _>>()?;
        let sign_data = SignData {
            sign_id: self.cfg.instance_id.as_bytes().to_vec(),
            counterparties,
            message_hash: self.cfg.message_hash,
        };

        // -------------------- Phase 1 → 2 ----------------------------------
        let (mut session, transmit_1to2) = DklsSignSession::<Secp256k1>::new(&party, sign_data)?;

        // Route each TransmitPhase1to2 to its receiver. Phase 1 outputs are
        // already point-to-point; index by `parties.receiver`.
        for t in &transmit_1to2 {
            let to_index = t.parties.receiver.as_u8();
            let payload = SigningRoundPayload::Phase1to2 {
                from_index: local_index,
                to_index,
                transmit: t.clone(),
            };
            self.send_payload(&payload, MpcPhase::Sign, 0, to_index)
                .await?;
        }

        // Collect inbound TransmitPhase1to2 from every other party.
        let mut received_1to2: Vec<TransmitPhase1to2> =
            Vec::with_capacity((self.cfg.parameters.threshold - 1) as usize);
        while received_1to2.len() < (self.cfg.parameters.threshold - 1) as usize {
            let msg = self.transport.recv().await?;
            let (_from_index, payload) = self.decode_inbound(&msg, MpcPhase::Sign, 0)?;
            match payload {
                SigningRoundPayload::Phase1to2 { transmit, .. } => {
                    received_1to2.push(transmit);
                }
                other => {
                    return Err(SignError::UnexpectedPayloadKind {
                        expected: MpcPhase::Sign,
                        got: other.variant_name(),
                    });
                }
            }
        }

        // -------------------- Phase 2 → 3 ----------------------------------
        let transmit_2to3 = session
            .phase2(&received_1to2)
            .map_err(|a| SignError::from(self.emit_abort_evidence(a)))?;
        for t in &transmit_2to3 {
            let to_index = t.parties.receiver.as_u8();
            let payload = SigningRoundPayload::Phase2to3 {
                from_index: local_index,
                to_index,
                transmit: t.clone(),
            };
            self.send_payload(&payload, MpcPhase::Sign, 1, to_index)
                .await?;
        }

        let mut received_2to3: Vec<TransmitPhase2to3<Secp256k1>> =
            Vec::with_capacity((self.cfg.parameters.threshold - 1) as usize);
        while received_2to3.len() < (self.cfg.parameters.threshold - 1) as usize {
            let msg = self.transport.recv().await?;
            let (_from_index, payload) = self.decode_inbound(&msg, MpcPhase::Sign, 1)?;
            match payload {
                SigningRoundPayload::Phase2to3 { transmit, .. } => {
                    received_2to3.push(transmit);
                }
                other => {
                    return Err(SignError::UnexpectedPayloadKind {
                        expected: MpcPhase::Sign,
                        got: other.variant_name(),
                    });
                }
            }
        }

        // -------------------- Phase 3 → 4 ----------------------------------
        let local_broadcast = session
            .phase3(&received_2to3)
            .map_err(|a| SignError::from(self.emit_abort_evidence(a)))?;

        // Broadcast: unroll into one envelope per other quorum member.
        for to_index in 1..=self.cfg.parameters.threshold {
            if to_index == local_index {
                continue;
            }
            let payload = SigningRoundPayload::Phase3to4 {
                from_index: local_index,
                to_index,
                broadcast: local_broadcast.clone(),
            };
            self.send_payload(&payload, MpcPhase::Sign, 2, to_index)
                .await?;
        }

        // Phase 4 needs the broadcast from every party (including self).
        // BTreeMap keyed by from_index so we end with a stable, deduplicated
        // collection regardless of receive order.
        let mut broadcasts_map: BTreeMap<u8, Broadcast3to4<Secp256k1>> = BTreeMap::new();
        broadcasts_map.insert(local_index, local_broadcast);
        while broadcasts_map.len() < self.cfg.parameters.threshold as usize {
            let msg = self.transport.recv().await?;
            let (from_index, payload) = self.decode_inbound(&msg, MpcPhase::Sign, 2)?;
            match payload {
                SigningRoundPayload::Phase3to4 { broadcast, .. } => {
                    broadcasts_map.insert(from_index, broadcast);
                }
                other => {
                    return Err(SignError::UnexpectedPayloadKind {
                        expected: MpcPhase::Sign,
                        got: other.variant_name(),
                    });
                }
            }
        }
        let broadcasts: Vec<Broadcast3to4<Secp256k1>> = broadcasts_map.into_values().collect();

        // -------------------- Phase 4 (finalise) ---------------------------
        // `normalize = true` applies low-s normalization per EIP-2 — the
        // bridge signer is consumed by EVM tx encoders that reject high-s.
        let ecdsa_sig: EcdsaSignature = session
            .phase4(&broadcasts, true)
            .map_err(|a| SignError::from(self.emit_abort_evidence(a)))?;

        // -------------------- Verify output --------------------------------
        // Decompress the SEC1-compressed group public key into an
        // `AffinePoint<Secp256k1>` so we can run the upstream verifier.
        let encoded = Sec1Point::<Secp256k1>::from_bytes(&self.cfg.group_public_key_compressed)
            .map_err(|e| SignError::MalformedGroupPublicKey(e.to_string()))?;
        let pk_affine_opt: Option<k256::AffinePoint> =
            k256::AffinePoint::from_sec1_point(&encoded).into();
        let pk_affine = pk_affine_opt
            .ok_or_else(|| SignError::MalformedGroupPublicKey("not on curve".to_string()))?;
        let r_hex = hex::encode(ecdsa_sig.r);
        let s_hex = hex::encode(ecdsa_sig.s);
        if !verify_ecdsa_signature::<Secp256k1>(
            &self.cfg.message_hash,
            &pk_affine,
            &r_hex,
            &s_hex,
        ) {
            return Err(SignError::OutputSignatureInvalid);
        }

        Ok(SignOutput::from(ecdsa_sig))
    }

    /// Wrap a `SigningRoundPayload` into an `MpcRoundMessage` and push it
    /// onto the transport.
    async fn send_payload(
        &self,
        payload: &SigningRoundPayload,
        phase: MpcPhase,
        round_index: u32,
        to_index: u8,
    ) -> Result<(), SignError> {
        let bytes = bincode::serialize(payload)
            .map_err(|e| SignError::PartyCodec(e.to_string()))?;
        let to_did = self.cfg.quorum_dids[(to_index - 1) as usize].clone();
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
    ) -> Result<(u8, SigningRoundPayload), SignError> {
        if msg.instance_id != self.cfg.instance_id {
            return Err(SignError::InstanceIdMismatch);
        }
        if msg.phase != expected_phase || msg.round_index != expected_round {
            return Err(SignError::UnexpectedPayloadKind {
                expected: expected_phase,
                got: "wrong phase/round",
            });
        }
        let from_index0 = self
            .cfg
            .quorum_dids
            .iter()
            .position(|d| d == &msg.from_did)
            .ok_or_else(|| SignError::UnknownSender(msg.from_did.clone()))?;
        let from_index = (from_index0 + 1) as u8;
        let payload: SigningRoundPayload =
            bincode::deserialize(&msg.payload).map_err(|e| SignError::MalformedPayload {
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
    use std::collections::HashMap;
    use std::sync::Arc;
    use tenzro_types::Hash;
    use tokio::sync::Mutex;
    use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

    fn make_instance_id(tag: u8) -> InstanceId {
        let block = Hash::from_bytes(&[tag; 32]).unwrap();
        InstanceId::derive(&block, &[0u8; 32], &[tag.wrapping_add(1); SESSION_NONCE_LEN])
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
        let cfg = SignConfig {
            instance_id: make_instance_id(1),
            group_id: GroupId([0xAB; 32]),
            epoch: 0,
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            group_public_key_compressed: vec![0x02; 33],
            message_hash: [0x33; 32],
            quorum_dids: sorted_dids(2),
            local_did: "did:tenzro:machine:p01".to_string(),
        };
        let encoded = serde_json::to_vec(&cfg).unwrap();
        let decoded: SignConfig = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(cfg, decoded);
    }

    #[test]
    fn config_rejects_unsorted() {
        let cfg = SignConfig {
            instance_id: make_instance_id(1),
            group_id: GroupId([0xAB; 32]),
            epoch: 0,
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            group_public_key_compressed: vec![0x02; 33],
            message_hash: [0x33; 32],
            quorum_dids: vec![
                "did:tenzro:machine:p02".to_string(),
                "did:tenzro:machine:p01".to_string(),
            ],
            local_did: "did:tenzro:machine:p02".to_string(),
        };
        assert!(matches!(cfg.validate(), Err(SignError::UnsortedQuorum)));
    }

    #[test]
    fn config_rejects_size_mismatch() {
        let cfg = SignConfig {
            instance_id: make_instance_id(1),
            group_id: GroupId([0xAB; 32]),
            epoch: 0,
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            group_public_key_compressed: vec![0x02; 33],
            message_hash: [0x33; 32],
            quorum_dids: sorted_dids(3), // threshold is 2, not 3
            local_did: "did:tenzro:machine:p01".to_string(),
        };
        assert!(matches!(
            cfg.validate(),
            Err(SignError::QuorumSizeMismatch { got: 3, expected: 2 })
        ));
    }

    #[test]
    fn output_to_bytes_is_65_long() {
        let out = SignOutput {
            r: [1u8; 32],
            s: [2u8; 32],
            v: 0,
        };
        let bytes = out.to_bytes();
        assert_eq!(bytes.len(), 65);
        assert_eq!(&bytes[..32], &[1u8; 32]);
        assert_eq!(&bytes[32..64], &[2u8; 32]);
        assert_eq!(bytes[64], 0);
    }

    #[test]
    fn output_from_ecdsa_signature() {
        let ecdsa = EcdsaSignature {
            r: [0xAA; 32],
            s: [0xBB; 32],
            recovery_id: 1,
        };
        let out: SignOutput = ecdsa.into();
        assert_eq!(out.r, [0xAA; 32]);
        assert_eq!(out.s, [0xBB; 32]);
        assert_eq!(out.v, 1);
    }

    /// Full round-trip: drive a 2-of-2 DKG, then drive a 2-of-2 sign on the
    /// resulting envelopes. Asserts the returned signature verifies against
    /// the DKG-output group public key.
    ///
    /// 2-of-2 keeps the test fast while still exercising the full signing
    /// pipeline (DKLS23 requires `threshold == quorum_size` parties to
    /// cooperate; the 2-of-3 case requires quorum subselection, which is
    /// covered by committee selection in task #22).
    #[tokio::test]
    async fn two_party_sign_roundtrip() {
        let dids = sorted_dids(2);
        let parameters = MpcParameters::new(MpcCurve::Secp256k1, 2, 2).unwrap();

        // -------- DKG --------
        let dkg_transports = MockTransport::fan_out(&dids);
        let mut dkg_handles = Vec::with_capacity(2);
        let mut shared_stores: Vec<MemKeyshareStore> = Vec::with_capacity(2);
        for transport in dkg_transports {
            let local_did = transport.local_did.clone();
            let cfg = KeygenConfig {
                instance_id: make_instance_id(1),
                parameters,
                participant_dids: dids.clone(),
                local_did,
            };
            let sealer = InMemoryKeyshareSealer::new([0x42u8; 32]);
            let store = MemKeyshareStore::default();
            shared_stores.push(store.clone());
            let session = KeygenSession::new(cfg, transport, sealer, store).unwrap();
            dkg_handles.push(tokio::spawn(async move { session.run().await }));
        }
        let mut dkg_outputs = Vec::with_capacity(2);
        for h in dkg_handles {
            dkg_outputs.push(h.await.unwrap().unwrap());
        }
        let group_id = dkg_outputs[0].group_id;
        let group_pk = dkg_outputs[0].group_public_key_compressed.clone();
        for o in &dkg_outputs[1..] {
            assert_eq!(o.group_id, group_id);
            assert_eq!(o.group_public_key_compressed, group_pk);
        }

        // -------- Sign --------
        // Fresh InstanceId for the sign session (different message hash +
        // session_nonce from the DKG instance — chain-anchoring lives in
        // `InstanceId::derive` per setup.rs).
        let message_hash = [0xCDu8; 32];
        let sign_instance = {
            let block = Hash::from_bytes(&[2u8; 32]).unwrap();
            InstanceId::derive(&block, &message_hash, &[5u8; SESSION_NONCE_LEN])
        };
        let sign_transports = MockTransport::fan_out(&dids);
        let mut sign_handles = Vec::with_capacity(2);
        for (i, transport) in sign_transports.into_iter().enumerate() {
            let local_did = transport.local_did.clone();
            let cfg = SignConfig {
                instance_id: sign_instance,
                group_id,
                epoch: 0,
                parameters,
                group_public_key_compressed: group_pk.clone(),
                message_hash,
                quorum_dids: dids.clone(),
                local_did,
            };
            let sealer = InMemoryKeyshareSealer::new([0x42u8; 32]);
            let store = shared_stores[i].clone();
            let session = SignSession::new(cfg, transport, sealer, store).unwrap();
            sign_handles.push(tokio::spawn(async move { session.run().await }));
        }
        let mut sign_outputs = Vec::with_capacity(2);
        for h in sign_handles {
            sign_outputs.push(h.await.unwrap().unwrap());
        }

        // All parties produced the same (r, s) — only v may differ
        // (recovery_id depends on the local view, though for a normalized
        // low-s signature both parties should agree).
        let r0 = sign_outputs[0].r;
        let s0 = sign_outputs[0].s;
        for o in &sign_outputs[1..] {
            assert_eq!(o.r, r0, "r divergence across parties");
            assert_eq!(o.s, s0, "s divergence across parties");
        }

        // Cross-verify externally against the group pubkey to confirm the
        // driver's internal verification matches a standalone check.
        let encoded = Sec1Point::<Secp256k1>::from_bytes(&group_pk).unwrap();
        let pk_affine: k256::AffinePoint =
            k256::AffinePoint::from_sec1_point(&encoded).unwrap();
        assert!(verify_ecdsa_signature::<Secp256k1>(
            &message_hash,
            &pk_affine,
            &hex::encode(r0),
            &hex::encode(s0),
        ));
    }

    #[test]
    fn local_party_index_is_one_based_position_in_sorted_quorum() {
        let cfg = SignConfig {
            instance_id: make_instance_id(7),
            group_id: GroupId([0xCC; 32]),
            epoch: 0,
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 3, 5).unwrap(),
            group_public_key_compressed: vec![0x02; 33],
            message_hash: [0x44; 32],
            // sorted_dids returns p01..pNN ascending; this matches the
            // canonical 1-based DKLS23 PartyIndex mapping the driver
            // assumes.
            quorum_dids: sorted_dids(3),
            local_did: "did:tenzro:machine:p02".to_string(),
        };
        assert_eq!(cfg.local_party_index().unwrap(), 2);
    }

    #[test]
    fn validate_rejects_local_not_in_quorum() {
        let cfg = SignConfig {
            instance_id: make_instance_id(8),
            group_id: GroupId([0xDD; 32]),
            epoch: 0,
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            group_public_key_compressed: vec![0x02; 33],
            message_hash: [0x55; 32],
            quorum_dids: sorted_dids(2),
            local_did: "did:tenzro:machine:p99".to_string(),
        };
        assert!(matches!(cfg.validate(), Err(SignError::LocalNotInQuorum)));
    }

    #[test]
    fn validate_rejects_duplicate_quorum_member() {
        let cfg = SignConfig {
            instance_id: make_instance_id(9),
            group_id: GroupId([0xEE; 32]),
            epoch: 0,
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            group_public_key_compressed: vec![0x02; 33],
            message_hash: [0x66; 32],
            quorum_dids: vec![
                "did:tenzro:machine:p01".to_string(),
                "did:tenzro:machine:p01".to_string(),
            ],
            local_did: "did:tenzro:machine:p01".to_string(),
        };
        assert!(matches!(
            cfg.validate(),
            Err(SignError::DuplicateQuorumMember(_))
        ));
    }

}
