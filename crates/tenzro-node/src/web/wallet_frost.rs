//! FROST (RFC 9591) round-coordination wallet endpoints.
//!
//! Exposed at `/wallet/frost/{ed25519,secp256k1}/*` on the public Web
//! API (port 8080, `api.tenzro.network`). Used by Tenzro-aware wallets
//! — through the Tenzro SDKs — to coordinate a 2-of-2 threshold
//! Schnorr signature where one share lives on the wallet device
//! (typically passkey-bound) and the other share lives on this node
//! (in production, sealed by a TEE; on testnet, deterministically
//! derived per the stub described below).
//!
//! ## Why a coordinator
//!
//! FROST is a coordinated 2-round protocol: each participant publishes
//! a Round 1 nonce commitment, the coordinator aggregates them into a
//! `SigningPackage`, each participant produces a Round 2 signature
//! share, and the coordinator aggregates the shares into a Schnorr
//! signature. This module is that coordinator.
//!
//! On testnet we run with `threshold = 2, max_signers = 2` (one
//! device + one node). The endpoint surface, however, is generic over
//! larger signer sets — the wallet decides the participant list at
//! pairing time and the node only ever signs for itself.
//!
//! ## Endpoints — six per scheme
//!
//! Both `ed25519` and `secp256k1` schemes mount the same six routes;
//! the path segment selects the curve. Per the project's "no dead
//! code" rule, both are mounted unconditionally because both are
//! reachable from the wallet kernel today.
//!
//! | Endpoint | Method | Purpose |
//! |----------|--------|---------|
//! | `/wallet/frost/{scheme}/start` | POST | Open a session; node publishes its Round 1 commitments. |
//! | `/wallet/frost/{scheme}/commit` | POST | Device publishes its Round 1 commitments. |
//! | `/wallet/frost/{scheme}/await-challenge` | POST | Long-poll (5s) for the `SigningPackage` to sign. |
//! | `/wallet/frost/{scheme}/respond` | POST | Device publishes its Round 2 signature share; node aggregates. |
//! | `/wallet/frost/{scheme}/finalize` | POST | Long-poll (5s) for the aggregated 64-byte Schnorr signature. |
//! | `/wallet/frost/{scheme}/abort` | POST | Idempotently mark the session aborted. |
//!
//! ## State machine
//!
//! ```text
//! pending  ──commit──▶  committed  ──respond──▶  finalized
//!     │                     │
//!     └──abort──▶ aborted   └──abort──▶ aborted
//!                                   │
//!                          (TTL 5min)──▶ expired
//! ```
//!
//! Sessions live in an in-memory [`FrostCoordinator`] keyed by
//! `session_id`. A background sweeper drops sessions older than 5
//! minutes (`SESSION_TTL_SECS`). Durable persistence is a follow-up
//! once we're ready to survive node restarts mid-signing.
//!
//! ## Auth
//!
//! Every endpoint requires:
//! - `Authorization: DPoP <jwt>` (RFC 9449)
//! - `DPoP: <proof>` over the request's `(method, full_uri)`
//! - `claims.aap_capabilities` includes action `wallet.frost.sign`
//!
//! The capability string is shared across both curves — the wallet
//! pairs once and the node-side authority is "may participate in any
//! 2-of-2 FROST round on this node." If we later need per-curve
//! granularity we can split into `wallet.frost.ed25519.sign` and
//! `wallet.frost.secp256k1.sign`; today both go through
//! [`REQUIRED_ACTION`].
//!
//! ## Wire format
//!
//! All bytes are base64url, no padding (RFC 4648 §5). FROST byte
//! structures (`SigningCommitments`, `SigningPackage`,
//! `SignatureShare`, the final `Signature`) are serialized via the
//! crate's own `.serialize()` / `.deserialize()` methods so the wire
//! shape is whatever the upstream crate version deems canonical. We
//! deliberately do not re-derive Lagrange coefficients or binding
//! factors at the wire boundary — those live inside `SigningPackage`
//! and `aggregate()` respectively.
//!
//! ## Key material (testnet stub)
//!
//! `(did, surface_key, scheme)` deterministically maps to a
//! `SigningKey` via
//! `seed = SHA-256("tenzro/wallet/frost/v1" || did || 0x00
//!                 || surface_key || 0x00 || scheme_tag)`.
//! The seed is fed into [`SigningKey::deserialize`] (Ed25519: 32-byte
//! scalar; secp256k1: 32-byte scalar) and split via `keys::split` with
//! threshold 2, max signers 2, fixed identifiers `node` / `device`.
//! This reproduces the same KeyPackage on every call so the wallet
//! and node — both running the same derivation — agree on the joint
//! verifying key without out-of-band setup.
//!
//! Production replaces [`derive_node_key_package`] with a TEE-sealed
//! lookup; the wire shape stays identical.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dashmap::DashMap;
use parking_lot::Mutex;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::handlers::WebState;
use super::oauth::{full_request_uri, validate_wallet_auth};

/// Capability action enforced on every `/wallet/frost/*` request.
const REQUIRED_ACTION: &str = "wallet.frost.sign";

/// Domain-separation tag for the deterministic seed-derivation stub.
/// Distinct from `tenzro/wallet/mldsa/v1` so a `(did, surface_key)`
/// pair cannot accidentally produce the same seed across protocols.
const SEED_DOMAIN_TAG: &[u8] = b"tenzro/wallet/frost/v1";

/// Sessions are evicted this long after creation regardless of state.
/// The wallet retries with a fresh `start` if it overruns.
const SESSION_TTL_SECS: u64 = 5 * 60;

/// Long-poll wait budget. Matches the wallet kernel's request-timeout
/// for `await-challenge` / `finalize`. Beyond this the handler returns
/// 200 with the current state and the wallet retries.
const LONG_POLL_TIMEOUT: Duration = Duration::from_secs(5);

/// Fixed participant identifiers for the 2-of-2 testnet stub.
/// Wallet kernel uses the same byte-strings via `Identifier::derive`.
const NODE_IDENTIFIER_TAG: &[u8] = b"node";
const DEVICE_IDENTIFIER_TAG: &[u8] = b"device";

// ---------------------------------------------------------------------------
// Scheme dispatch
// ---------------------------------------------------------------------------

/// Curve discriminator pulled from the `:scheme` URL path segment.
/// We dispatch on this once per request rather than templating the
/// whole module, because each scheme uses a different concrete crate
/// (`frost_ed25519` / `frost_secp256k1`) with no shared trait surface
/// at the wire-bytes level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrostScheme {
    Ed25519,
    Secp256k1,
}

impl FrostScheme {
    fn from_path(s: &str) -> Option<Self> {
        match s {
            "ed25519" => Some(FrostScheme::Ed25519),
            "secp256k1" => Some(FrostScheme::Secp256k1),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            FrostScheme::Ed25519 => "ed25519",
            FrostScheme::Secp256k1 => "secp256k1",
        }
    }

    /// Domain-separation tag mixed into the seed derivation so that
    /// the same `(did, surface_key)` produces independent keys on
    /// different curves.
    fn domain_tag(self) -> &'static [u8] {
        match self {
            FrostScheme::Ed25519 => b"ed25519",
            FrostScheme::Secp256k1 => b"secp256k1",
        }
    }
}

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

/// State machine — see module docs for the transition diagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrostSessionState {
    /// Created by `start`; awaiting device commitments.
    Pending,
    /// Device commitments received; signing package built; waiting
    /// for the device's signature share.
    Committed,
    /// Aggregated; signature ready to be picked up by `finalize`.
    Finalized,
    /// Explicitly aborted; idempotent.
    Aborted,
}

/// One in-flight FROST session. All FROST byte-blobs are stored in
/// already-serialized form so the coordinator never has to keep a
/// curve-specific type alive across awaits.
struct FrostSession {
    scheme: FrostScheme,
    did: String,
    surface_key: String,
    /// Message preimage — the bytes that will be signed.
    preimage: Vec<u8>,
    state: FrostSessionState,
    expires_at_ms: u64,
    /// Node's own SigningCommitments (Round 1 output), serialized.
    /// Populated at `start`. Used to build the SigningPackage at `commit`.
    node_commitments: Vec<u8>,
    /// Node's SigningNonces from Round 1. Serialized so we can move
    /// the session across DashMap shards without lifetime drama.
    /// Required input to `round2::sign` later.
    node_nonces: Vec<u8>,
    /// Device's SigningCommitments, serialized. Populated by `commit`.
    device_commitments: Option<Vec<u8>>,
    /// SigningPackage built once both commitments are present.
    /// Populated at `commit`. Returned to the device at `await-challenge`.
    signing_package: Option<Vec<u8>>,
    /// Aggregated 64-byte (or 65-byte for secp) signature.
    /// Populated at `respond`. Returned at `finalize`.
    signature: Option<Vec<u8>>,
}

impl FrostSession {
    fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }

    /// Mutate to `Aborted` if the TTL has elapsed. Returns the
    /// effective state. Called on every endpoint hit so a session
    /// that idled past its TTL surfaces as `aborted` rather than
    /// silently disappearing on the next sweeper tick.
    fn effective_state(&mut self, now_ms: u64) -> FrostSessionState {
        if self.is_expired(now_ms) && self.state != FrostSessionState::Finalized {
            self.state = FrostSessionState::Aborted;
        }
        self.state
    }
}

/// Keyed by `session_id`. `parking_lot::Mutex` per session keeps the
/// long-poll endpoints from blocking other sessions. The outer
/// `DashMap` is fine for cross-session concurrency.
pub struct FrostCoordinator {
    sessions: DashMap<String, Arc<Mutex<FrostSession>>>,
}

impl FrostCoordinator {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    /// Drop sessions strictly older than `SESSION_TTL_SECS`. Called on
    /// every coordinator interaction; we don't run a separate task
    /// for testnet load.
    fn sweep(&self, now_ms: u64) {
        self.sessions
            .retain(|_, sess| !sess.lock().is_expired(now_ms));
    }
}

impl Default for FrostCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn coordinator(state: &Arc<WebState>) -> &FrostCoordinator {
    &state.frost_coordinator
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct StartRequest {
    pub did: String,
    pub surface_key: String,
    pub preimage_b64: String,
}

#[derive(Debug, Serialize)]
pub struct StartResponse {
    pub session_id: String,
    /// Unix-millis at which the session will be evicted regardless of state.
    pub expires_at_ms: u64,
    /// Stable participant identifier for the node (matches `Identifier::derive("node")`).
    pub node_identifier_b64: String,
    /// Stable participant identifier the wallet must use for itself.
    pub device_identifier_b64: String,
    /// Node's Round 1 SigningCommitments, serialized via the FROST
    /// crate's own `.serialize()`.
    pub node_commitments_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct CommitRequest {
    pub session_id: String,
    /// Device's Round 1 SigningCommitments, serialized via the same
    /// FROST crate's `.serialize()` as the node uses.
    pub device_commitments_b64: String,
}

#[derive(Debug, Serialize)]
pub struct CommitResponse {
    pub state: FrostSessionState,
}

#[derive(Debug, Deserialize)]
pub struct PollRequest {
    pub session_id: String,
}

#[derive(Debug, Serialize)]
pub struct AwaitChallengeResponse {
    pub state: FrostSessionState,
    /// Present only when `state == "committed"`.
    /// Serialized `SigningPackage` — feed straight into the FROST
    /// crate's `round2::sign(signing_package, signer_nonces, key_package)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_package_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RespondRequest {
    pub session_id: String,
    /// Device's Round 2 SignatureShare, serialized.
    pub device_signature_share_b64: String,
}

#[derive(Debug, Serialize)]
pub struct RespondResponse {
    pub state: FrostSessionState,
}

#[derive(Debug, Serialize)]
pub struct FinalizeResponse {
    pub state: FrostSessionState,
    /// Present only when `state == "finalized"`. The aggregated
    /// Schnorr signature (64 bytes for Ed25519, 65 for secp256k1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AbortRequest {
    pub session_id: String,
}

#[derive(Debug, Serialize)]
pub struct AbortResponse {
    pub state: FrostSessionState,
}

#[derive(Debug, Serialize)]
struct WalletError {
    error: &'static str,
    error_description: String,
}

fn wallet_error(status: StatusCode, code: &'static str, description: &str) -> Response {
    (
        status,
        Json(WalletError {
            error: code,
            error_description: description.to_string(),
        }),
    )
        .into_response()
}

fn invalid_scheme() -> Response {
    wallet_error(
        StatusCode::NOT_FOUND,
        "invalid_scheme",
        "scheme path segment must be 'ed25519' or 'secp256k1'",
    )
}

fn parse_b64(field: &str, value: &str) -> Result<Vec<u8>, Response> {
    URL_SAFE_NO_PAD.decode(value.as_bytes()).map_err(|e| {
        wallet_error(
            StatusCode::BAD_REQUEST,
            "invalid_b64",
            &format!("{} must be base64url no-pad: {}", field, e),
        )
    })
}

fn session_not_found() -> Response {
    wallet_error(
        StatusCode::NOT_FOUND,
        "session_not_found",
        "no FROST session for that session_id (possibly expired)",
    )
}

// ---------------------------------------------------------------------------
// Per-scheme helpers
//
// We keep the FROST crate-specific code behind two narrow helper sets,
// one per ciphersuite. Each set runs the protocol locally for the
// node's own share, returning serialized bytes ready for storage.
// This keeps the handler bodies curve-agnostic.
// ---------------------------------------------------------------------------

/// Result of running the node side of FROST Round 1: serialized
/// `SigningCommitments` + serialized `SigningNonces` for the node.
struct NodeRound1 {
    commitments: Vec<u8>,
    nonces: Vec<u8>,
}

/// Run Round 1 on the node side using the deterministic stub
/// KeyPackage. Returns wire-ready bytes.
fn node_round1(scheme: FrostScheme, did: &str, surface_key: &str) -> Result<NodeRound1, Response> {
    match scheme {
        FrostScheme::Ed25519 => ed25519_ops::node_round1(did, surface_key),
        FrostScheme::Secp256k1 => secp256k1_ops::node_round1(did, surface_key),
    }
}

/// Build the SigningPackage from the two participants' serialized
/// commitments + the message. Result is serialized SigningPackage.
fn build_signing_package(
    scheme: FrostScheme,
    node_commitments: &[u8],
    device_commitments: &[u8],
    preimage: &[u8],
) -> Result<Vec<u8>, Response> {
    match scheme {
        FrostScheme::Ed25519 => {
            ed25519_ops::build_signing_package(node_commitments, device_commitments, preimage)
        }
        FrostScheme::Secp256k1 => {
            secp256k1_ops::build_signing_package(node_commitments, device_commitments, preimage)
        }
    }
}

/// Compute the node's Round 2 signature share, then aggregate with
/// the device share to produce the final Schnorr signature.
/// Returns the serialized Signature.
fn aggregate_with_node_share(
    scheme: FrostScheme,
    did: &str,
    surface_key: &str,
    signing_package: &[u8],
    node_nonces: &[u8],
    device_signature_share: &[u8],
) -> Result<Vec<u8>, Response> {
    match scheme {
        FrostScheme::Ed25519 => ed25519_ops::aggregate_with_node_share(
            did,
            surface_key,
            signing_package,
            node_nonces,
            device_signature_share,
        ),
        FrostScheme::Secp256k1 => secp256k1_ops::aggregate_with_node_share(
            did,
            surface_key,
            signing_package,
            node_nonces,
            device_signature_share,
        ),
    }
}

/// Common 32-byte seed derivation. Mirrors the wallet kernel's
/// derivation byte-for-byte so both ends produce the same keys on
/// the testnet stub.
fn derive_seed(did: &str, surface_key: &str, scheme: FrostScheme) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SEED_DOMAIN_TAG);
    hasher.update(did.as_bytes());
    hasher.update([0x00]);
    hasher.update(surface_key.as_bytes());
    hasher.update([0x00]);
    hasher.update(scheme.domain_tag());
    let out = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out);
    seed
}

// ---------------------------------------------------------------------------
// Ed25519 ops (FROST(Ed25519, SHA-512))
// ---------------------------------------------------------------------------

mod ed25519_ops {
    use super::*;
    use frost_ed25519::keys::{IdentifierList, KeyPackage, PublicKeyPackage, SigningShare};
    use frost_ed25519::round1::{SigningCommitments, SigningNonces};
    use frost_ed25519::round2::SignatureShare;
    use frost_ed25519::{aggregate, keys, round1, round2, Identifier, SigningKey, SigningPackage};

    fn frost_err(stage: &'static str) -> impl Fn(frost_ed25519::Error) -> Response + 'static {
        move |e| {
            wallet_error(
                StatusCode::BAD_REQUEST,
                "frost_protocol_error",
                &format!("ed25519 {}: {}", stage, e),
            )
        }
    }

    fn internal_err(stage: &'static str) -> impl Fn(frost_ed25519::Error) -> Response + 'static {
        move |e| {
            wallet_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "frost_internal_error",
                &format!("ed25519 {}: {}", stage, e),
            )
        }
    }

    fn node_identifier() -> Result<Identifier, Response> {
        Identifier::derive(NODE_IDENTIFIER_TAG).map_err(internal_err("derive node id"))
    }

    fn device_identifier() -> Result<Identifier, Response> {
        Identifier::derive(DEVICE_IDENTIFIER_TAG).map_err(internal_err("derive device id"))
    }

    /// Deterministic 2-of-2 key split. Returns the node's KeyPackage
    /// and the joint PublicKeyPackage. The wallet, given the same
    /// `(did, surface_key)`, derives the device's KeyPackage by
    /// running the same split locally.
    fn split_keys(did: &str, surface_key: &str) -> Result<(KeyPackage, PublicKeyPackage), Response> {
        let seed = derive_seed(did, surface_key, FrostScheme::Ed25519);

        // Derive both the SigningKey and the polynomial coefficients
        // from the same deterministic StubRng so that this function
        // returns identical KeyPackages on every call across both
        // wallet and node. We use `SigningKey::new(&mut rng)` rather
        // than `deserialize(&seed)` because raw SHA-256 output is
        // not guaranteed to be a valid (nonzero, < group order) field
        // element — `new()` rejects-and-retries internally so the
        // returned scalar is always well-formed.
        let mut rng = StubRng::from_seed(seed);
        let signing_key = SigningKey::new(&mut rng);

        let identifiers: Vec<Identifier> = vec![node_identifier()?, device_identifier()?];
        let (shares, pubkey_package) = keys::split(
            &signing_key,
            2,
            2,
            IdentifierList::Custom(&identifiers),
            &mut rng,
        )
        .map_err(internal_err("split keys"))?;

        let node_secret_share = shares
            .get(&node_identifier()?)
            .ok_or_else(|| {
                wallet_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "frost_internal_error",
                    "node secret share missing from split output",
                )
            })?
            .clone();
        let key_package: KeyPackage = node_secret_share
            .try_into()
            .map_err(internal_err("verify secret share"))?;

        Ok((key_package, pubkey_package))
    }

    pub(super) fn node_round1(did: &str, surface_key: &str) -> Result<NodeRound1, Response> {
        let (key_package, _pubkey_package) = split_keys(did, surface_key)?;
        let signing_share: &SigningShare = key_package.signing_share();

        let mut rng = OsRng;
        let (nonces, commitments) = round1::commit(signing_share, &mut rng);

        let commitments_bytes = commitments
            .serialize()
            .map_err(internal_err("serialize commitments"))?;
        let nonces_bytes = nonces
            .serialize()
            .map_err(internal_err("serialize nonces"))?;
        Ok(NodeRound1 {
            commitments: commitments_bytes,
            nonces: nonces_bytes,
        })
    }

    pub(super) fn build_signing_package(
        node_commitments: &[u8],
        device_commitments: &[u8],
        preimage: &[u8],
    ) -> Result<Vec<u8>, Response> {
        let node_id = node_identifier()?;
        let device_id = device_identifier()?;

        let node_c =
            SigningCommitments::deserialize(node_commitments).map_err(frost_err("deserialize node commitments"))?;
        let device_c = SigningCommitments::deserialize(device_commitments)
            .map_err(frost_err("deserialize device commitments"))?;

        let mut commitments_map = BTreeMap::new();
        commitments_map.insert(node_id, node_c);
        commitments_map.insert(device_id, device_c);

        let signing_package = SigningPackage::new(commitments_map, preimage);
        signing_package
            .serialize()
            .map_err(internal_err("serialize signing package"))
    }

    pub(super) fn aggregate_with_node_share(
        did: &str,
        surface_key: &str,
        signing_package: &[u8],
        node_nonces: &[u8],
        device_signature_share: &[u8],
    ) -> Result<Vec<u8>, Response> {
        let (key_package, pubkey_package) = split_keys(did, surface_key)?;

        let signing_package = SigningPackage::deserialize(signing_package)
            .map_err(frost_err("deserialize signing package"))?;
        let nonces = SigningNonces::deserialize(node_nonces)
            .map_err(internal_err("deserialize node nonces"))?;

        let node_share = round2::sign(&signing_package, &nonces, &key_package)
            .map_err(frost_err("round2 sign (node)"))?;
        let device_share = SignatureShare::deserialize(device_signature_share)
            .map_err(frost_err("deserialize device signature share"))?;

        let mut shares = BTreeMap::new();
        shares.insert(node_identifier()?, node_share);
        shares.insert(device_identifier()?, device_share);

        let signature = aggregate(&signing_package, &shares, &pubkey_package)
            .map_err(frost_err("aggregate"))?;
        signature
            .serialize()
            .map_err(internal_err("serialize signature"))
    }
}

// ---------------------------------------------------------------------------
// Secp256k1 ops (FROST(secp256k1, SHA-256))
// ---------------------------------------------------------------------------

mod secp256k1_ops {
    use super::*;
    use frost_secp256k1::keys::{IdentifierList, KeyPackage, PublicKeyPackage, SigningShare};
    use frost_secp256k1::round1::{SigningCommitments, SigningNonces};
    use frost_secp256k1::round2::SignatureShare;
    use frost_secp256k1::{aggregate, keys, round1, round2, Identifier, SigningKey, SigningPackage};

    fn frost_err(stage: &'static str) -> impl Fn(frost_secp256k1::Error) -> Response + 'static {
        move |e| {
            wallet_error(
                StatusCode::BAD_REQUEST,
                "frost_protocol_error",
                &format!("secp256k1 {}: {}", stage, e),
            )
        }
    }

    fn internal_err(stage: &'static str) -> impl Fn(frost_secp256k1::Error) -> Response + 'static {
        move |e| {
            wallet_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "frost_internal_error",
                &format!("secp256k1 {}: {}", stage, e),
            )
        }
    }

    fn node_identifier() -> Result<Identifier, Response> {
        Identifier::derive(NODE_IDENTIFIER_TAG).map_err(internal_err("derive node id"))
    }

    fn device_identifier() -> Result<Identifier, Response> {
        Identifier::derive(DEVICE_IDENTIFIER_TAG).map_err(internal_err("derive device id"))
    }

    fn split_keys(did: &str, surface_key: &str) -> Result<(KeyPackage, PublicKeyPackage), Response> {
        let seed = derive_seed(did, surface_key, FrostScheme::Secp256k1);

        // Same rationale as the ed25519 path: feed the StubRng to
        // both `SigningKey::new` and `keys::split` so the entire
        // process is deterministic and field-element-valid.
        let mut rng = StubRng::from_seed(seed);
        let signing_key = SigningKey::new(&mut rng);

        let identifiers: Vec<Identifier> = vec![node_identifier()?, device_identifier()?];
        let (shares, pubkey_package) = keys::split(
            &signing_key,
            2,
            2,
            IdentifierList::Custom(&identifiers),
            &mut rng,
        )
        .map_err(internal_err("split keys"))?;

        let node_secret_share = shares
            .get(&node_identifier()?)
            .ok_or_else(|| {
                wallet_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "frost_internal_error",
                    "node secret share missing from split output",
                )
            })?
            .clone();
        let key_package: KeyPackage = node_secret_share
            .try_into()
            .map_err(internal_err("verify secret share"))?;

        Ok((key_package, pubkey_package))
    }

    pub(super) fn node_round1(did: &str, surface_key: &str) -> Result<NodeRound1, Response> {
        let (key_package, _pubkey_package) = split_keys(did, surface_key)?;
        let signing_share: &SigningShare = key_package.signing_share();

        let mut rng = OsRng;
        let (nonces, commitments) = round1::commit(signing_share, &mut rng);

        let commitments_bytes = commitments
            .serialize()
            .map_err(internal_err("serialize commitments"))?;
        let nonces_bytes = nonces
            .serialize()
            .map_err(internal_err("serialize nonces"))?;
        Ok(NodeRound1 {
            commitments: commitments_bytes,
            nonces: nonces_bytes,
        })
    }

    pub(super) fn build_signing_package(
        node_commitments: &[u8],
        device_commitments: &[u8],
        preimage: &[u8],
    ) -> Result<Vec<u8>, Response> {
        let node_id = node_identifier()?;
        let device_id = device_identifier()?;

        let node_c = SigningCommitments::deserialize(node_commitments)
            .map_err(frost_err("deserialize node commitments"))?;
        let device_c = SigningCommitments::deserialize(device_commitments)
            .map_err(frost_err("deserialize device commitments"))?;

        let mut commitments_map = BTreeMap::new();
        commitments_map.insert(node_id, node_c);
        commitments_map.insert(device_id, device_c);

        let signing_package = SigningPackage::new(commitments_map, preimage);
        signing_package
            .serialize()
            .map_err(internal_err("serialize signing package"))
    }

    pub(super) fn aggregate_with_node_share(
        did: &str,
        surface_key: &str,
        signing_package: &[u8],
        node_nonces: &[u8],
        device_signature_share: &[u8],
    ) -> Result<Vec<u8>, Response> {
        let (key_package, pubkey_package) = split_keys(did, surface_key)?;

        let signing_package = SigningPackage::deserialize(signing_package)
            .map_err(frost_err("deserialize signing package"))?;
        let nonces = SigningNonces::deserialize(node_nonces)
            .map_err(internal_err("deserialize node nonces"))?;

        let node_share = round2::sign(&signing_package, &nonces, &key_package)
            .map_err(frost_err("round2 sign (node)"))?;
        let device_share = SignatureShare::deserialize(device_signature_share)
            .map_err(frost_err("deserialize device signature share"))?;

        let mut shares = BTreeMap::new();
        shares.insert(node_identifier()?, node_share);
        shares.insert(device_identifier()?, device_share);

        let signature = aggregate(&signing_package, &shares, &pubkey_package)
            .map_err(frost_err("aggregate"))?;
        signature
            .serialize()
            .map_err(internal_err("serialize signature"))
    }
}

// ---------------------------------------------------------------------------
// Deterministic RNG for `keys::split` reproducibility on the testnet stub
//
// `keys::split` requires a `RngCore + CryptoRng`. To make both wallet
// and node produce *identical* polynomial coefficients (and thus the
// same KeyPackage) without out-of-band setup, we feed it a SHAKE-style
// expansion of the same 32-byte seed both sides already derive.
// Production drops this entirely — the KeyPackage is delivered at
// pairing instead of being re-derived per call.
// ---------------------------------------------------------------------------

/// SHA-256-based counter-mode "RNG" — bit-for-bit reproducible from
/// the same seed. Marked `CryptoRng` because the underlying primitive
/// (SHA-256) is cryptographically secure; this is *not* a
/// general-purpose RNG and is used only to satisfy the FROST API's
/// `RngCore + CryptoRng` bound on the testnet stub. Production
/// replaces the call site entirely.
struct StubRng {
    seed: [u8; 32],
    counter: u64,
    buffer: [u8; 32],
    buffer_pos: usize,
}

impl StubRng {
    fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            buffer: [0u8; 32],
            buffer_pos: 32, // force refill on first read
        }
    }

    fn refill(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(b"tenzro/wallet/frost/rng/v1");
        hasher.update(self.seed);
        hasher.update(self.counter.to_le_bytes());
        let out = hasher.finalize();
        self.buffer.copy_from_slice(&out);
        self.counter = self.counter.wrapping_add(1);
        self.buffer_pos = 0;
    }
}

impl rand::RngCore for StubRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut written = 0;
        while written < dest.len() {
            if self.buffer_pos >= self.buffer.len() {
                self.refill();
            }
            let take = (self.buffer.len() - self.buffer_pos).min(dest.len() - written);
            dest[written..written + take]
                .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + take]);
            self.buffer_pos += take;
            written += take;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand::CryptoRng for StubRng {}

// ---------------------------------------------------------------------------
// Handlers — six endpoints, scheme dispatched via path segment.
// ---------------------------------------------------------------------------

/// `POST /wallet/frost/{scheme}/start`
pub async fn start_handler(
    State(state): State<Arc<WebState>>,
    Path(scheme): Path<String>,
    headers: HeaderMap,
    Json(body): Json<StartRequest>,
) -> Response {
    let scheme = match FrostScheme::from_path(&scheme) {
        Some(s) => s,
        None => return invalid_scheme(),
    };
    let path = format!("/wallet/frost/{}/start", scheme.as_str());
    let full_uri = full_request_uri(&headers, &path);
    if let Err(resp) = validate_wallet_auth(&state, &headers, "POST", &full_uri, REQUIRED_ACTION).await {
        return resp;
    }

    let preimage = match parse_b64("preimage_b64", &body.preimage_b64) {
        Ok(p) => p,
        Err(r) => return r,
    };

    let round1 = match node_round1(scheme, &body.did, &body.surface_key) {
        Ok(r) => r,
        Err(r) => return r,
    };

    let session_id = new_session_id();
    let now = now_ms();
    let expires_at_ms = now + SESSION_TTL_SECS * 1000;
    let session = FrostSession {
        scheme,
        did: body.did.clone(),
        surface_key: body.surface_key.clone(),
        preimage,
        state: FrostSessionState::Pending,
        expires_at_ms,
        node_commitments: round1.commitments.clone(),
        node_nonces: round1.nonces,
        device_commitments: None,
        signing_package: None,
        signature: None,
    };

    let coord = coordinator(&state);
    coord.sweep(now);
    coord
        .sessions
        .insert(session_id.clone(), Arc::new(Mutex::new(session)));

    // Identifier bytes — serialize each side so the wallet can match
    // them verbatim instead of re-deriving (cheap, but explicit is
    // friendlier to debug).
    let node_id_b64 = match scheme {
        FrostScheme::Ed25519 => URL_SAFE_NO_PAD.encode(
            frost_ed25519::Identifier::derive(NODE_IDENTIFIER_TAG)
                .map(|i| i.serialize())
                .unwrap_or_default(),
        ),
        FrostScheme::Secp256k1 => URL_SAFE_NO_PAD.encode(
            frost_secp256k1::Identifier::derive(NODE_IDENTIFIER_TAG)
                .map(|i| i.serialize())
                .unwrap_or_default(),
        ),
    };
    let device_id_b64 = match scheme {
        FrostScheme::Ed25519 => URL_SAFE_NO_PAD.encode(
            frost_ed25519::Identifier::derive(DEVICE_IDENTIFIER_TAG)
                .map(|i| i.serialize())
                .unwrap_or_default(),
        ),
        FrostScheme::Secp256k1 => URL_SAFE_NO_PAD.encode(
            frost_secp256k1::Identifier::derive(DEVICE_IDENTIFIER_TAG)
                .map(|i| i.serialize())
                .unwrap_or_default(),
        ),
    };

    Json(StartResponse {
        session_id,
        expires_at_ms,
        node_identifier_b64: node_id_b64,
        device_identifier_b64: device_id_b64,
        node_commitments_b64: URL_SAFE_NO_PAD.encode(&round1.commitments),
    })
    .into_response()
}

/// `POST /wallet/frost/{scheme}/commit`
pub async fn commit_handler(
    State(state): State<Arc<WebState>>,
    Path(scheme): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CommitRequest>,
) -> Response {
    let scheme = match FrostScheme::from_path(&scheme) {
        Some(s) => s,
        None => return invalid_scheme(),
    };
    let path = format!("/wallet/frost/{}/commit", scheme.as_str());
    let full_uri = full_request_uri(&headers, &path);
    if let Err(resp) = validate_wallet_auth(&state, &headers, "POST", &full_uri, REQUIRED_ACTION).await {
        return resp;
    }

    let device_commitments = match parse_b64("device_commitments_b64", &body.device_commitments_b64) {
        Ok(b) => b,
        Err(r) => return r,
    };

    let coord = coordinator(&state);
    let now = now_ms();
    coord.sweep(now);
    let sess_arc = match coord.sessions.get(&body.session_id) {
        Some(s) => s.clone(),
        None => return session_not_found(),
    };

    // Compute the SigningPackage *before* taking the session lock for
    // mutation so we don't hold both at once. This is fine because
    // `node_commitments` is immutable for the lifetime of the session.
    let (node_commitments, preimage, sess_scheme) = {
        let sess = sess_arc.lock();
        (
            sess.node_commitments.clone(),
            sess.preimage.clone(),
            sess.scheme,
        )
    };
    if sess_scheme != scheme {
        return wallet_error(
            StatusCode::BAD_REQUEST,
            "scheme_mismatch",
            "session scheme does not match request path",
        );
    }

    let signing_package =
        match build_signing_package(scheme, &node_commitments, &device_commitments, &preimage) {
            Ok(b) => b,
            Err(r) => return r,
        };

    let mut sess = sess_arc.lock();
    if sess.effective_state(now) != FrostSessionState::Pending {
        return wallet_error(
            StatusCode::CONFLICT,
            "invalid_state",
            &format!(
                "commit requires state=pending, got state={:?}",
                sess.state
            ),
        );
    }
    sess.device_commitments = Some(device_commitments);
    sess.signing_package = Some(signing_package);
    sess.state = FrostSessionState::Committed;

    Json(CommitResponse { state: sess.state }).into_response()
}

/// `POST /wallet/frost/{scheme}/await-challenge` — long-poll up to
/// `LONG_POLL_TIMEOUT` for `state == committed`.
pub async fn await_challenge_handler(
    State(state): State<Arc<WebState>>,
    Path(scheme): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PollRequest>,
) -> Response {
    let scheme = match FrostScheme::from_path(&scheme) {
        Some(s) => s,
        None => return invalid_scheme(),
    };
    let path = format!("/wallet/frost/{}/await-challenge", scheme.as_str());
    let full_uri = full_request_uri(&headers, &path);
    if let Err(resp) = validate_wallet_auth(&state, &headers, "POST", &full_uri, REQUIRED_ACTION).await {
        return resp;
    }

    let coord = coordinator(&state);
    let deadline = SystemTime::now() + LONG_POLL_TIMEOUT;
    loop {
        let sess_arc = match coord.sessions.get(&body.session_id) {
            Some(s) => s.clone(),
            None => return session_not_found(),
        };
        let now = now_ms();
        let (effective, package, sess_scheme) = {
            let mut sess = sess_arc.lock();
            (
                sess.effective_state(now),
                sess.signing_package.clone(),
                sess.scheme,
            )
        };
        if sess_scheme != scheme {
            return wallet_error(
                StatusCode::BAD_REQUEST,
                "scheme_mismatch",
                "session scheme does not match request path",
            );
        }

        match effective {
            FrostSessionState::Committed
            | FrostSessionState::Finalized
            | FrostSessionState::Aborted => {
                return Json(AwaitChallengeResponse {
                    state: effective,
                    signing_package_b64: package.map(|p| URL_SAFE_NO_PAD.encode(p)),
                })
                .into_response();
            }
            FrostSessionState::Pending => {
                if SystemTime::now() >= deadline {
                    return Json(AwaitChallengeResponse {
                        state: effective,
                        signing_package_b64: None,
                    })
                    .into_response();
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// `POST /wallet/frost/{scheme}/respond`
pub async fn respond_handler(
    State(state): State<Arc<WebState>>,
    Path(scheme): Path<String>,
    headers: HeaderMap,
    Json(body): Json<RespondRequest>,
) -> Response {
    let scheme = match FrostScheme::from_path(&scheme) {
        Some(s) => s,
        None => return invalid_scheme(),
    };
    let path = format!("/wallet/frost/{}/respond", scheme.as_str());
    let full_uri = full_request_uri(&headers, &path);
    if let Err(resp) = validate_wallet_auth(&state, &headers, "POST", &full_uri, REQUIRED_ACTION).await {
        return resp;
    }

    let device_share = match parse_b64(
        "device_signature_share_b64",
        &body.device_signature_share_b64,
    ) {
        Ok(b) => b,
        Err(r) => return r,
    };

    let coord = coordinator(&state);
    let now = now_ms();
    coord.sweep(now);
    let sess_arc = match coord.sessions.get(&body.session_id) {
        Some(s) => s.clone(),
        None => return session_not_found(),
    };

    // Snapshot the inputs needed for aggregation, drop the lock,
    // run the crypto, then take the lock again to mutate.
    let (sess_scheme, did, surface_key, signing_package, node_nonces, current_state) = {
        let mut sess = sess_arc.lock();
        let eff = sess.effective_state(now);
        if eff != FrostSessionState::Committed {
            return wallet_error(
                StatusCode::CONFLICT,
                "invalid_state",
                &format!(
                    "respond requires state=committed, got state={:?}",
                    eff
                ),
            );
        }
        let pkg = match sess.signing_package.clone() {
            Some(p) => p,
            None => {
                return wallet_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "missing_signing_package",
                    "session is committed but signing_package is absent",
                );
            }
        };
        (
            sess.scheme,
            sess.did.clone(),
            sess.surface_key.clone(),
            pkg,
            sess.node_nonces.clone(),
            eff,
        )
    };
    if sess_scheme != scheme {
        return wallet_error(
            StatusCode::BAD_REQUEST,
            "scheme_mismatch",
            "session scheme does not match request path",
        );
    }
    let _ = current_state; // already validated above

    let signature = match aggregate_with_node_share(
        scheme,
        &did,
        &surface_key,
        &signing_package,
        &node_nonces,
        &device_share,
    ) {
        Ok(s) => s,
        Err(r) => return r,
    };

    let mut sess = sess_arc.lock();
    // Re-check state in case of a concurrent abort.
    if sess.effective_state(now) != FrostSessionState::Committed {
        return wallet_error(
            StatusCode::CONFLICT,
            "invalid_state",
            "session left committed state during aggregation",
        );
    }
    sess.signature = Some(signature);
    sess.state = FrostSessionState::Finalized;

    Json(RespondResponse { state: sess.state }).into_response()
}

/// `POST /wallet/frost/{scheme}/finalize` — long-poll up to
/// `LONG_POLL_TIMEOUT` for `state == finalized`.
pub async fn finalize_handler(
    State(state): State<Arc<WebState>>,
    Path(scheme): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PollRequest>,
) -> Response {
    let scheme = match FrostScheme::from_path(&scheme) {
        Some(s) => s,
        None => return invalid_scheme(),
    };
    let path = format!("/wallet/frost/{}/finalize", scheme.as_str());
    let full_uri = full_request_uri(&headers, &path);
    if let Err(resp) = validate_wallet_auth(&state, &headers, "POST", &full_uri, REQUIRED_ACTION).await {
        return resp;
    }

    let coord = coordinator(&state);
    let deadline = SystemTime::now() + LONG_POLL_TIMEOUT;
    loop {
        let sess_arc = match coord.sessions.get(&body.session_id) {
            Some(s) => s.clone(),
            None => return session_not_found(),
        };
        let now = now_ms();
        let (effective, signature, sess_scheme) = {
            let mut sess = sess_arc.lock();
            (
                sess.effective_state(now),
                sess.signature.clone(),
                sess.scheme,
            )
        };
        if sess_scheme != scheme {
            return wallet_error(
                StatusCode::BAD_REQUEST,
                "scheme_mismatch",
                "session scheme does not match request path",
            );
        }

        match effective {
            FrostSessionState::Finalized | FrostSessionState::Aborted => {
                return Json(FinalizeResponse {
                    state: effective,
                    signature_b64: signature.map(|s| URL_SAFE_NO_PAD.encode(s)),
                })
                .into_response();
            }
            FrostSessionState::Pending | FrostSessionState::Committed => {
                if SystemTime::now() >= deadline {
                    return Json(FinalizeResponse {
                        state: effective,
                        signature_b64: None,
                    })
                    .into_response();
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// `POST /wallet/frost/{scheme}/abort` — idempotent.
pub async fn abort_handler(
    State(state): State<Arc<WebState>>,
    Path(scheme): Path<String>,
    headers: HeaderMap,
    Json(body): Json<AbortRequest>,
) -> Response {
    let scheme = match FrostScheme::from_path(&scheme) {
        Some(s) => s,
        None => return invalid_scheme(),
    };
    let path = format!("/wallet/frost/{}/abort", scheme.as_str());
    let full_uri = full_request_uri(&headers, &path);
    if let Err(resp) = validate_wallet_auth(&state, &headers, "POST", &full_uri, REQUIRED_ACTION).await {
        return resp;
    }

    let coord = coordinator(&state);
    let now = now_ms();
    coord.sweep(now);
    let sess_arc = match coord.sessions.get(&body.session_id) {
        Some(s) => s.clone(),
        None => return session_not_found(),
    };

    let mut sess = sess_arc.lock();
    if sess.scheme != scheme {
        return wallet_error(
            StatusCode::BAD_REQUEST,
            "scheme_mismatch",
            "session scheme does not match request path",
        );
    }
    // Finalized sessions stay Finalized — we don't undo a successful
    // signature. Everything else collapses to Aborted (idempotent).
    if sess.state != FrostSessionState::Finalized {
        sess.state = FrostSessionState::Aborted;
    }

    Json(AbortResponse { state: sess.state }).into_response()
}

// ---------------------------------------------------------------------------
// Session ID generation
// ---------------------------------------------------------------------------

/// Format: `frost-<24 base64url chars>` (18 random bytes). The prefix
/// is just for log greppability; the bytes are CSPRNG-fresh.
fn new_session_id() -> String {
    let mut bytes = [0u8; 18];
    OsRng.fill_bytes(&mut bytes);
    format!("frost-{}", URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_derivation_is_curve_separated() {
        let s_ed = derive_seed("did:tenzro:human:alice", "vault.0", FrostScheme::Ed25519);
        let s_sec = derive_seed("did:tenzro:human:alice", "vault.0", FrostScheme::Secp256k1);
        assert_ne!(s_ed, s_sec, "ed25519 and secp256k1 seeds must diverge");
    }

    #[test]
    fn seed_derivation_separator_prevents_concat_collision() {
        // ("ab","cd") vs ("abcd","") — without the 0x00 separators
        // these would hash to the same input. The two separator bytes
        // (one between did|surface_key, one between surface_key|tag)
        // make collisions impossible.
        let a = derive_seed("ab", "cd", FrostScheme::Ed25519);
        let b = derive_seed("abcd", "", FrostScheme::Ed25519);
        assert_ne!(a, b);
    }

    #[test]
    fn stub_rng_is_reproducible() {
        let seed = [42u8; 32];
        let mut rng_a = StubRng::from_seed(seed);
        let mut rng_b = StubRng::from_seed(seed);
        let mut buf_a = [0u8; 256];
        let mut buf_b = [0u8; 256];
        rand::RngCore::fill_bytes(&mut rng_a, &mut buf_a);
        rand::RngCore::fill_bytes(&mut rng_b, &mut buf_b);
        assert_eq!(buf_a, buf_b);
    }

    #[test]
    fn stub_rng_diverges_for_different_seeds() {
        let mut rng_a = StubRng::from_seed([1u8; 32]);
        let mut rng_b = StubRng::from_seed([2u8; 32]);
        let mut buf_a = [0u8; 64];
        let mut buf_b = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rng_a, &mut buf_a);
        rand::RngCore::fill_bytes(&mut rng_b, &mut buf_b);
        assert_ne!(buf_a, buf_b);
    }

    /// End-to-end: run a full FROST(Ed25519) round entirely
    /// in-process, simulating both the device and the node sides via
    /// the same testnet stub derivation. Verifies that the produced
    /// signature passes Ed25519 verification against the joint public
    /// key derived from the same `(did, surface_key)`.
    #[test]
    fn ed25519_full_round_produces_valid_signature() {
        use ed25519_dalek::Verifier as _;
        use frost_ed25519::keys::{IdentifierList, KeyPackage};
        use frost_ed25519::{keys, round1, round2, Identifier, SigningKey, SigningPackage};

        let did = "did:tenzro:human:alice";
        let surface = "vault.0";
        let preimage = b"transaction preimage bytes";

        // Both sides derive the same KeyPackage set deterministically.
        let seed = derive_seed(did, surface, FrostScheme::Ed25519);
        let mut rng = StubRng::from_seed(seed);
        let signing_key = SigningKey::new(&mut rng);
        let node_id = Identifier::derive(NODE_IDENTIFIER_TAG).unwrap();
        let device_id = Identifier::derive(DEVICE_IDENTIFIER_TAG).unwrap();
        let identifiers = vec![node_id, device_id];

        let (shares, pubkey_package) =
            keys::split(&signing_key, 2, 2, IdentifierList::Custom(&identifiers), &mut rng).unwrap();
        let node_kp: KeyPackage = shares.get(&node_id).unwrap().clone().try_into().unwrap();
        let device_kp: KeyPackage = shares.get(&device_id).unwrap().clone().try_into().unwrap();

        // Both sides run Round 1.
        let mut os = OsRng;
        let (node_nonces, node_commitments) = round1::commit(node_kp.signing_share(), &mut os);
        let (device_nonces, device_commitments) =
            round1::commit(device_kp.signing_share(), &mut os);

        // Coordinator builds the SigningPackage.
        let mut commitments = BTreeMap::new();
        commitments.insert(node_id, node_commitments);
        commitments.insert(device_id, device_commitments);
        let signing_package = SigningPackage::new(commitments, preimage);

        // Both sides run Round 2.
        let node_share = round2::sign(&signing_package, &node_nonces, &node_kp).unwrap();
        let device_share = round2::sign(&signing_package, &device_nonces, &device_kp).unwrap();

        // Aggregate.
        let mut shares_map = BTreeMap::new();
        shares_map.insert(node_id, node_share);
        shares_map.insert(device_id, device_share);
        let signature = frost_ed25519::aggregate(&signing_package, &shares_map, &pubkey_package).unwrap();

        // Verify against the joint VK using stock ed25519-dalek so
        // we know the signature is wire-compatible with the broader
        // ecosystem, not just `frost_ed25519::VerifyingKey::verify`.
        let vk_bytes = pubkey_package.verifying_key().serialize().unwrap();
        let dalek_vk =
            ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes.as_slice().try_into().unwrap())
                .unwrap();
        let sig_bytes = signature.serialize().unwrap();
        let dalek_sig =
            ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        dalek_vk.verify(preimage, &dalek_sig).unwrap();
    }
}
