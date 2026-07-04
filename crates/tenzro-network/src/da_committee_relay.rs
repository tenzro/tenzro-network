//! Committee data-availability wire protocol for Tenzro Network.
//!
//! A single `libp2p::request_response` behaviour multiplexes the two committee
//! DA RPC methods — `StoreSliver` (writer → member: "hold this sliver, sign
//! for it") and `FetchSliver` (reader → member: "return the sliver you hold")
//! — as variants on [`DaCommitteeRequest`] / [`DaCommitteeResponse`].
//!
//! ## Why this shape (vs. the MPC relay's Ack-only pattern)
//!
//! The MPC relay (`mpc_relay.rs`) is fire-and-forget: the response is a bare
//! `Ack` and real replies flow back over a *separate* subscriber channel. The
//! committee DA path is genuinely request→**reply-carrying**: a `StoreSliver`
//! must return the member's signed [`WireMemberAttestation`] and a
//! `FetchSliver` must return the actual sliver bytes. So the outbound side of
//! this protocol uses per-request `oneshot` correlation (keyed by
//! `OutboundRequestId`) — the caller awaits its own reply — rather than the
//! block-sync-style broadcast result channel.
//!
//! ## Why the payloads are opaque bytes
//!
//! `tenzro-network` does **not** depend on `tenzro-storage`, so it cannot name
//! `redstuff::SliverPair` / `redstuff::CommitteeShape`. The node-layer adapter
//! (`tenzro_node::da_committee` — the only crate that depends on both storage
//! and network) bincode-encodes those types into the `sliver` / `shape_blob`
//! byte fields here and decodes them on the far side. This mirrors how
//! `MpcRelayRequest` carries `payload: Vec<u8>` and the node adapter maps it to
//! the typed `MpcRoundMessage`. The scalar fields the transport itself needs
//! (`commitment`, `blob_len`, `symbol_len`, the member index/address) travel in
//! the clear.
//!
//! ## Concurrency limits
//!   * Per-peer inbound concurrent stream cap: 8 (reject overflow, do not queue).
//!   * Max request / response size: 16 MiB each — a single primary+secondary
//!     sliver pair for a large blob, plus its Merkle proofs, comfortably fits.
//!   * Outbound request timeout: 30 s (store + fetch both cross the wire once).

use libp2p::{
    request_response::{self, ProtocolSupport},
    StreamProtocol,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use tenzro_crypto::signatures::Signature;
use tenzro_types::primitives::Address;

/// Stream-protocol identifier for the committee DA RPC.
///
/// The version segment is required by libp2p's `StreamProtocol` rules
/// (third-party / external surface). Internal Tenzro identifiers (gossipsub
/// topics, JSON-RPC methods, the `DA_COMMITTEE_PROTOCOL` tag in the node layer)
/// intentionally omit version segments per the project's identifier
/// conventions; this constant is the libp2p exception.
pub const DA_COMMITTEE_PROTOCOL: &str = "/tenzro/da/committee/1.0.0";

/// Per-peer inbound concurrent stream cap. Overflow MUST be rejected with
/// `ServerBusy`, not queued — queueing causes the requester's response timeout
/// to fire while the request still sits in our backlog.
pub const MAX_INBOUND_STREAMS_PER_PEER: usize = 8;

/// Outbound request timeout for both store and fetch.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Max request size (16 MiB) — a primary+secondary sliver pair plus proofs.
pub const MAX_REQUEST_SIZE: usize = 16 * 1024 * 1024;

/// Max response size (16 MiB) — a fetched sliver pair plus proofs.
pub const MAX_RESPONSE_SIZE: usize = 16 * 1024 * 1024;

/// Committee DA request envelope. All variants are size-bounded by the codec's
/// [`MAX_REQUEST_SIZE`] cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaCommitteeRequest {
    /// Writer asks this member to durably store `sliver` for the blob whose
    /// 32-byte commitment is `commitment`. On success the member replies
    /// [`DaCommitteeResponse::Attestation`].
    StoreSliver {
        /// 32-byte blob commitment.
        commitment: [u8; 32],
        /// bincode-encoded `redstuff::CommitteeShape` (opaque to the network layer).
        shape_blob: Vec<u8>,
        /// True byte length of the blob.
        blob_len: u64,
        /// Symbol length of the encoding.
        symbol_len: u64,
        /// bincode-encoded `redstuff::SliverPair` (opaque to the network layer).
        sliver: Vec<u8>,
    },

    /// Reader asks this member for the sliver it holds for `commitment`. The
    /// member replies [`DaCommitteeResponse::Sliver`] — `Some(bytes)` if held,
    /// `None` otherwise.
    FetchSliver {
        /// 32-byte blob commitment.
        commitment: [u8; 32],
    },
}

/// Committee DA response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaCommitteeResponse {
    /// Response to `StoreSliver`: the member stored its sliver and signed for
    /// custody.
    Attestation(WireMemberAttestation),

    /// Response to `FetchSliver`: `Some` bincode-encoded `redstuff::SliverPair`
    /// if the member holds it, `None` otherwise.
    Sliver(Option<Vec<u8>>),

    /// Server-side error for any request variant. The requester treats this the
    /// same as a missing attestation / missing sliver and moves on.
    Error(DaCommitteeError),
}

/// One committee member's signed acknowledgment that it stored its sliver.
///
/// Structurally identical to the node-layer `MemberAttestation`; the adapter
/// maps between the two. Carried on the wire so the writer can assemble the
/// availability certificate without a second round-trip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMemberAttestation {
    /// Committee index of the attesting member.
    pub index: u64,
    /// The member's on-chain address (bound into the signed message).
    pub address: Address,
    /// Ed25519 signature over the node-layer canonical attestation message.
    pub signature: Signature,
}

/// Errors a serving member reports back to the requester.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum DaCommitteeError {
    /// Server is at its inbound concurrency cap. Caller should retry against a
    /// different member or back off.
    #[error("server busy — exceeded {limit} concurrent inbound streams from this peer")]
    ServerBusy { limit: usize },

    /// No committee-DA handler is attached on the serving side (bootstrap
    /// window, or handler dropped). Requester scores us down and retries.
    #[error("no committee-DA handler attached")]
    NoHandler,

    /// The member could not verify or persist the sliver (bad proof, wrong
    /// commitment binding, storage failure). The message preserves the
    /// serving-side detail.
    #[error("committee-DA storage error: {0}")]
    Storage(String),
}

/// Type alias for the libp2p request-response behaviour parameterized with our
/// wire types. Uses CBOR (`cbor4ii`) framing — the production default.
pub type DaCommitteeBehaviour =
    request_response::cbor::Behaviour<DaCommitteeRequest, DaCommitteeResponse>;

/// Constructs a fresh committee-DA `Behaviour` with production-tuned config.
pub fn new_behaviour() -> DaCommitteeBehaviour {
    let protocol = StreamProtocol::new(DA_COMMITTEE_PROTOCOL);
    let cfg = request_response::Config::default().with_request_timeout(REQUEST_TIMEOUT);
    request_response::cbor::Behaviour::new(
        std::iter::once((protocol, ProtocolSupport::Full)),
        cfg,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::{keys::KeyPair, signatures::Signer, KeyType};

    fn sample_attestation() -> WireMemberAttestation {
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let crypto_addr = kp.public_key().to_address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let signer = tenzro_crypto::signatures::Ed25519SignerImpl::new(kp).unwrap();
        let sig = signer.sign(b"tenzro/da/committee/attest test").unwrap();
        WireMemberAttestation {
            index: 3,
            address: Address::new(addr_bytes),
            signature: sig,
        }
    }

    #[test]
    fn request_round_trip() {
        let cases = vec![
            DaCommitteeRequest::StoreSliver {
                commitment: [7u8; 32],
                shape_blob: vec![1, 2, 3, 4],
                blob_len: 4096,
                symbol_len: 64,
                sliver: vec![9u8; 128],
            },
            DaCommitteeRequest::FetchSliver {
                commitment: [42u8; 32],
            },
        ];
        for req in cases {
            let bytes = bincode::serialize(&req).expect("encode");
            let decoded: DaCommitteeRequest = bincode::deserialize(&bytes).expect("decode");
            assert_eq!(req, decoded);
        }
    }

    #[test]
    fn response_round_trip() {
        let cases = vec![
            DaCommitteeResponse::Attestation(sample_attestation()),
            DaCommitteeResponse::Sliver(Some(vec![5u8; 96])),
            DaCommitteeResponse::Sliver(None),
            DaCommitteeResponse::Error(DaCommitteeError::ServerBusy {
                limit: MAX_INBOUND_STREAMS_PER_PEER,
            }),
            DaCommitteeResponse::Error(DaCommitteeError::NoHandler),
            DaCommitteeResponse::Error(DaCommitteeError::Storage("disk full".to_string())),
        ];
        for resp in cases {
            let bytes = bincode::serialize(&resp).expect("encode");
            let decoded: DaCommitteeResponse = bincode::deserialize(&bytes).expect("decode");
            assert_eq!(resp, decoded);
        }
    }

    #[test]
    fn behaviour_constructs() {
        let _ = new_behaviour();
    }
}
