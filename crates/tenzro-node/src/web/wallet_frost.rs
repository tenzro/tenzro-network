//! FROST (RFC 9591) round-coordination wallet endpoints.
//!
//! Exposed at `/wallet/frost/{ed25519,secp256k1}/*` on the public Web
//! API (port 8080, `api.tenzro.xyz`). Used by Tenzro-aware wallets
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
//! Sessions live in a [`FrostCoordinator`] keyed by `session_id`. The
//! coordinator keeps a `DashMap` of live sessions (each behind its own
//! `Mutex` so long-polls don't block sibling sessions) backed by a
//! durable `KvStore` row under `CF_VALIDATOR_MODULES`. Every state
//! transition writes through to storage; aborts and TTL expiry delete
//! the row. A restart mid-ceremony repopulates the in-memory cache
//! lazily: the first handler that touches a `session_id` not in the
//! `DashMap` reloads it from storage, so a signing round survives a
//! node restart without the wallet having to start over. A background
//! sweeper drops sessions older than 5 minutes (`SESSION_TTL_SECS`).
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
//! `seed = SHA-256("tenzro/wallet/frost" || did || 0x00
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
use tenzro_storage::{KvStore, CF_VALIDATOR_MODULES};

use super::error::WalletApiError;
use super::handlers::WebState;
use super::oauth::{full_request_uri, validate_wallet_auth};

/// Capability action enforced on every `/wallet/frost/*` request.
const REQUIRED_ACTION: &str = "wallet.frost.sign";

/// Domain-separation tag for the deterministic seed-derivation stub.
/// Distinct from `tenzro/wallet/mldsa` so a `(did, surface_key)`
/// pair cannot accidentally produce the same seed across protocols.
const SEED_DOMAIN_TAG: &[u8] = b"tenzro/wallet/frost";

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
/// curve-specific type alive across awaits — and so the whole session
/// serializes to a single durable `KvStore` row without any
/// curve-specific `serde` glue.
#[derive(Serialize, Deserialize)]
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
    /// JWT `sub` claim of the bearer that opened this session via
    /// `start`. Every subsequent endpoint (commit / await-challenge /
    /// respond / finalize / abort) constant-time compares the
    /// presenter's `sub` against this and rejects on mismatch.
    ///
    /// Why bind to `sub` and not just the capability: a leaked refresh
    /// token can mint a new access JWT with the same capabilities but
    /// a different `sub` is impossible without compromising the wallet
    /// itself. Binding the session to the originating subject means a
    /// second, unrelated bearer that happens to hold `wallet.sign` on
    /// a different DID cannot hijack an in-flight signing session.
    initiating_sub: String,
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
/// `DashMap` is the live cache; the durable copy lives in a
/// `KvStore` row (see [`SessionStore`]). The cache is repopulated
/// lazily from storage — a session absent from the map is reloaded on
/// first touch, so a node restart mid-round doesn't drop it.
pub struct FrostCoordinator {
    sessions: DashMap<String, Arc<Mutex<FrostSession>>>,
}

impl FrostCoordinator {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    /// Drop expired sessions from the in-memory cache. Storage rows for
    /// the same sessions are pruned by [`SessionStore::sweep`], which
    /// the handlers invoke alongside this. Called on every coordinator
    /// interaction; no separate task for testnet load.
    fn sweep(&self, now_ms: u64) {
        self.sessions
            .retain(|_, sess| !sess.lock().is_expired(now_ms));
    }

    /// Return the live session for `session_id`, loading it from
    /// durable storage into the cache if it isn't resident (e.g. after
    /// a restart). Expired rows are treated as absent and their storage
    /// row is deleted. `None` means genuinely unknown / expired.
    fn resolve(
        &self,
        store: Option<&SessionStore>,
        session_id: &str,
        now_ms: u64,
    ) -> Option<Arc<Mutex<FrostSession>>> {
        if let Some(existing) = self.sessions.get(session_id) {
            return Some(existing.clone());
        }
        // Cold cache — try to rehydrate from storage.
        let store = store?;
        match store.get(session_id) {
            Ok(Some(sess)) if !sess.is_expired(now_ms) => {
                let arc = Arc::new(Mutex::new(sess));
                self.sessions
                    .insert(session_id.to_string(), arc.clone());
                Some(arc)
            }
            Ok(Some(_)) => {
                // Expired: evict the stale row so it can't be replayed.
                store.delete(session_id);
                None
            }
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(error = %e.description, "frost session hydrate failed");
                None
            }
        }
    }
}

impl Default for FrostCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Durable session store (KvStore-backed, MAC-tagged — mirrors
// wallet_new.rs::SessionStore and passkey_rpc.rs::PendingRecoveryStore)
// ---------------------------------------------------------------------------

/// Key prefix for FROST session rows in `CF_VALIDATOR_MODULES`.
const SESSION_PREFIX: &[u8] = b"wallet/frost/session/";

struct SessionStore {
    storage: Arc<dyn KvStore>,
}

impl SessionStore {
    fn new(storage: Arc<dyn KvStore>) -> Self {
        Self { storage }
    }

    fn key(session_id: &str) -> Vec<u8> {
        let mut k = SESSION_PREFIX.to_vec();
        k.extend_from_slice(session_id.as_bytes());
        k
    }

    fn put(&self, session_id: &str, sess: &FrostSession) -> Result<(), WalletApiError> {
        let bytes = serde_json::to_vec(sess).map_err(|e| {
            internal("frost_session_serialize", format!("serialize session: {e}"))
        })?;
        let tagged = mac_wrap(&bytes);
        self.storage
            .put(CF_VALIDATOR_MODULES, &Self::key(session_id), &tagged)
            .map_err(|e| internal("frost_session_persist", format!("persist session: {e}")))
    }

    fn get(&self, session_id: &str) -> Result<Option<FrostSession>, WalletApiError> {
        let bytes = self
            .storage
            .get(CF_VALIDATOR_MODULES, &Self::key(session_id))
            .map_err(|e| internal("frost_session_read", format!("read session: {e}")))?;
        match bytes {
            Some(b) => {
                let payload = mac_verify(&b).map_err(|e| {
                    internal("frost_session_tampered", format!("tampered session row: {e}"))
                })?;
                let sess: FrostSession = serde_json::from_slice(payload).map_err(|e| {
                    internal("frost_session_deserialize", format!("deserialize session: {e}"))
                })?;
                Ok(Some(sess))
            }
            None => Ok(None),
        }
    }

    fn delete(&self, session_id: &str) {
        let _ = self
            .storage
            .delete(CF_VALIDATOR_MODULES, &Self::key(session_id));
    }

    /// Drop every persisted session whose TTL has elapsed. Keeps the
    /// column family from accumulating rows for sessions the wallet
    /// never came back to finalize/abort.
    fn sweep(&self, now_ms: u64) {
        let keys = match self
            .storage
            .get_keys_with_prefix(CF_VALIDATOR_MODULES, SESSION_PREFIX)
        {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(error = %e, "frost session sweep scan failed");
                return;
            }
        };
        for key in keys {
            let sid = match std::str::from_utf8(&key[SESSION_PREFIX.len()..]) {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };
            if let Ok(Some(sess)) = self.get(&sid)
                && sess.is_expired(now_ms)
            {
                self.delete(&sid);
            }
        }
    }
}

/// Per-process MAC key at `~/.tenzro/local_state_mac.key` (0600) —
/// the same file and threat model as `wallet_new` / `passkey_rpc`:
/// detects accidental corruption + cross-process tampering of session
/// rows; does not defend against in-process malware inside the same
/// trust boundary.
fn local_mac_key() -> &'static [u8; 32] {
    use std::sync::OnceLock;
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let home = match std::env::var("HOME").ok().map(std::path::PathBuf::from) {
            Some(p) => p,
            None => {
                tracing::warn!("wallet_frost local_mac_key: no $HOME — using zero key (tests only)");
                return [0u8; 32];
            }
        };
        let path = home.join(".tenzro").join("local_state_mac.key");
        if let Ok(bytes) = std::fs::read(&path)
            && bytes.len() == 32
        {
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            return k;
        }
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&path, k) {
            tracing::warn!(error = %e, "wallet_frost local_mac_key: failed to persist MAC key");
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
        k
    })
}

fn mac_wrap(payload: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(local_mac_key());
    h.update(payload);
    let tag = h.finalize();
    let mut out = Vec::with_capacity(32 + payload.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(payload);
    out
}

fn mac_verify(blob: &[u8]) -> Result<&[u8], &'static str> {
    if blob.len() < 32 {
        return Err("row too short");
    }
    let (tag, payload) = blob.split_at(32);
    let mut h = Sha256::new();
    h.update(local_mac_key());
    h.update(payload);
    let expected = h.finalize();
    if &expected[..] != tag {
        return Err("tag mismatch (row tampered or foreign)");
    }
    Ok(payload)
}

fn internal(code: &'static str, msg: impl Into<String>) -> WalletApiError {
    WalletApiError::new(StatusCode::INTERNAL_SERVER_ERROR, code, msg.into())
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

/// Resolve the durable session store from the node's `KvStore`. Returns
/// `None` when storage isn't wired (light client, boot race) — in that
/// case the coordinator degrades to an in-memory-only cache, matching
/// prior behaviour, but a full node always has storage.
fn frost_store(state: &Arc<WebState>) -> Option<SessionStore> {
    let storage = state.node.as_ref()?.storage()?;
    Some(SessionStore::new(storage.clone() as Arc<dyn KvStore>))
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

fn wallet_error(status: StatusCode, code: &'static str, description: &str) -> WalletApiError {
    WalletApiError::new(status, code, description.to_string())
}

fn invalid_scheme() -> WalletApiError {
    wallet_error(
        StatusCode::NOT_FOUND,
        "invalid_scheme",
        "scheme path segment must be 'ed25519' or 'secp256k1'",
    )
}

fn parse_b64(field: &str, value: &str) -> Result<Vec<u8>, WalletApiError> {
    URL_SAFE_NO_PAD.decode(value.as_bytes()).map_err(|e| {
        wallet_error(
            StatusCode::BAD_REQUEST,
            "invalid_b64",
            &format!("{} must be base64url no-pad: {}", field, e),
        )
    })
}

fn session_not_found() -> WalletApiError {
    wallet_error(
        StatusCode::NOT_FOUND,
        "session_not_found",
        "no FROST session for that session_id (possibly expired)",
    )
}

/// Constant-time compare the presenter's JWT `sub` against the
/// session's `initiating_sub`. On mismatch returns a coarse
/// 403 — deliberately the same shape as a missing session would
/// have been (NOT_FOUND), to avoid leaking session existence to a
/// bearer that doesn't own it. (FROST callers know their own
/// session IDs; an honest caller never hits this path.)
fn require_session_owner(
    session_initiating_sub: &str,
    presenter_sub: &str,
) -> Result<(), WalletApiError> {
    use subtle::ConstantTimeEq;
    let a = session_initiating_sub.as_bytes();
    let b = presenter_sub.as_bytes();
    // Length-mismatch is a definite reject; ct_eq's docs note that
    // length is leaked anyway because the slices have differing
    // lengths at the call site, so an early-out is fine.
    if a.len() != b.len() || !bool::from(a.ct_eq(b)) {
        return Err(wallet_error(
            StatusCode::NOT_FOUND,
            "session_not_found",
            "no FROST session for that session_id (possibly expired)",
        ));
    }
    Ok(())
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

/// Output of the deterministic provisioning split for one curve.
/// `verifying_key` is the joint (public) group verifying key that
/// becomes the DID's on-surface key material; `device_key_package` is
/// wrapped under the passkey and handed to the wallet as the device leg
/// of the 2-of-2. The node's own leg is re-derived on demand from
/// `(did, surface_key, scheme)` at sign time, so it is not carried here.
pub(crate) struct ProvisionedShares {
    pub verifying_key: Vec<u8>,
    pub device_key_package: Vec<u8>,
}

/// Signing scheme selector exposed to the provisioning path so
/// `wallet_new` can request a split per curve without touching the
/// private `FrostScheme`. Ed25519 covers native/SVM/Canton surfaces;
/// Secp256k1 covers the EVM surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProvisionScheme {
    Ed25519,
    Secp256k1,
}

impl ProvisionScheme {
    fn to_frost(self) -> FrostScheme {
        match self {
            ProvisionScheme::Ed25519 => FrostScheme::Ed25519,
            ProvisionScheme::Secp256k1 => FrostScheme::Secp256k1,
        }
    }
}

/// Shared "share missing from split output" error used by both
/// per-curve provisioning helpers.
fn missing_share() -> WalletApiError {
    wallet_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "frost_internal_error",
        "secret share missing from split output",
    )
}

/// Deterministically split a fresh joint key into the node + device
/// 2-of-2 for `(did, surface_key, scheme)`, returning both legs'
/// serialized `KeyPackage`s and the joint verifying key. Delegates to
/// the same `keys::split` used by the signing path.
pub(crate) fn provision_split(
    scheme: ProvisionScheme,
    did: &str,
    surface_key: &str,
) -> Result<ProvisionedShares, WalletApiError> {
    match scheme.to_frost() {
        FrostScheme::Ed25519 => ed25519_ops::provision_split(did, surface_key),
        FrostScheme::Secp256k1 => secp256k1_ops::provision_split(did, surface_key),
    }
}

/// Run Round 1 on the node side using the deterministic stub
/// KeyPackage. Returns wire-ready bytes.
fn node_round1(scheme: FrostScheme, did: &str, surface_key: &str) -> Result<NodeRound1, WalletApiError> {
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
) -> Result<Vec<u8>, WalletApiError> {
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
) -> Result<Vec<u8>, WalletApiError> {
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

    fn frost_err(stage: &'static str) -> impl Fn(frost_ed25519::Error) -> WalletApiError + 'static {
        move |e| {
            wallet_error(
                StatusCode::BAD_REQUEST,
                "frost_protocol_error",
                &format!("ed25519 {}: {}", stage, e),
            )
        }
    }

    fn internal_err(stage: &'static str) -> impl Fn(frost_ed25519::Error) -> WalletApiError + 'static {
        move |e| {
            wallet_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "frost_internal_error",
                &format!("ed25519 {}: {}", stage, e),
            )
        }
    }

    fn node_identifier() -> Result<Identifier, WalletApiError> {
        Identifier::derive(NODE_IDENTIFIER_TAG).map_err(internal_err("derive node id"))
    }

    fn device_identifier() -> Result<Identifier, WalletApiError> {
        Identifier::derive(DEVICE_IDENTIFIER_TAG).map_err(internal_err("derive device id"))
    }

    /// Deterministic 2-of-2 key split. Returns the node's KeyPackage
    /// and the joint PublicKeyPackage. The wallet, given the same
    /// `(did, surface_key)`, derives the device's KeyPackage by
    /// running the same split locally.
    fn split_keys(did: &str, surface_key: &str) -> Result<(KeyPackage, PublicKeyPackage), WalletApiError> {
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

    /// Run the deterministic split and return both legs' material for
    /// provisioning: the joint verifying key (public), the node's
    /// serialized `KeyPackage` (retained by the node), and the device's
    /// serialized `KeyPackage` (wrapped under the passkey and handed
    /// back to the device). Same `keys::split` primitive as the signing
    /// path — no separate keygen.
    pub(super) fn provision_split(
        did: &str,
        surface_key: &str,
    ) -> Result<ProvisionedShares, WalletApiError> {
        let seed = derive_seed(did, surface_key, FrostScheme::Ed25519);
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

        let device_share = shares
            .get(&device_identifier()?)
            .ok_or_else(missing_share)?
            .clone();

        let device_key_package: KeyPackage = device_share
            .try_into()
            .map_err(internal_err("verify device secret share"))?;

        let verifying_key = pubkey_package
            .verifying_key()
            .serialize()
            .map_err(internal_err("serialize verifying key"))?;
        let device_key_package_bytes = device_key_package
            .serialize()
            .map_err(internal_err("serialize device key package"))?;

        Ok(ProvisionedShares {
            verifying_key,
            device_key_package: device_key_package_bytes,
        })
    }

    pub(super) fn node_round1(did: &str, surface_key: &str) -> Result<NodeRound1, WalletApiError> {
        let (key_package, _pubkey_package) = split_keys(did, surface_key)?;
        let signing_share: &SigningShare = key_package.signing_share();

        let (nonces, commitments) = round1::commit(signing_share, &mut OsRng);

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
    ) -> Result<Vec<u8>, WalletApiError> {
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
    ) -> Result<Vec<u8>, WalletApiError> {
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

    fn frost_err(stage: &'static str) -> impl Fn(frost_secp256k1::Error) -> WalletApiError + 'static {
        move |e| {
            wallet_error(
                StatusCode::BAD_REQUEST,
                "frost_protocol_error",
                &format!("secp256k1 {}: {}", stage, e),
            )
        }
    }

    fn internal_err(stage: &'static str) -> impl Fn(frost_secp256k1::Error) -> WalletApiError + 'static {
        move |e| {
            wallet_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "frost_internal_error",
                &format!("secp256k1 {}: {}", stage, e),
            )
        }
    }

    fn node_identifier() -> Result<Identifier, WalletApiError> {
        Identifier::derive(NODE_IDENTIFIER_TAG).map_err(internal_err("derive node id"))
    }

    fn device_identifier() -> Result<Identifier, WalletApiError> {
        Identifier::derive(DEVICE_IDENTIFIER_TAG).map_err(internal_err("derive device id"))
    }

    fn split_keys(did: &str, surface_key: &str) -> Result<(KeyPackage, PublicKeyPackage), WalletApiError> {
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

    /// See `ed25519_ops::provision_split`. Same shape for the
    /// secp256k1 ciphersuite (FROST-secp256k1 / threshold ECDSA).
    pub(super) fn provision_split(
        did: &str,
        surface_key: &str,
    ) -> Result<ProvisionedShares, WalletApiError> {
        let seed = derive_seed(did, surface_key, FrostScheme::Secp256k1);
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

        let device_share = shares
            .get(&device_identifier()?)
            .ok_or_else(missing_share)?
            .clone();

        let device_key_package: KeyPackage = device_share
            .try_into()
            .map_err(internal_err("verify device secret share"))?;

        let verifying_key = pubkey_package
            .verifying_key()
            .serialize()
            .map_err(internal_err("serialize verifying key"))?;
        let device_key_package_bytes = device_key_package
            .serialize()
            .map_err(internal_err("serialize device key package"))?;

        Ok(ProvisionedShares {
            verifying_key,
            device_key_package: device_key_package_bytes,
        })
    }

    pub(super) fn node_round1(did: &str, surface_key: &str) -> Result<NodeRound1, WalletApiError> {
        let (key_package, _pubkey_package) = split_keys(did, surface_key)?;
        let signing_share: &SigningShare = key_package.signing_share();

        let (nonces, commitments) = round1::commit(signing_share, &mut OsRng);

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
    ) -> Result<Vec<u8>, WalletApiError> {
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
    ) -> Result<Vec<u8>, WalletApiError> {
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
        hasher.update(b"tenzro/wallet/frost/rng");
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
        None => return invalid_scheme().into_response(),
    };
    let path = format!("/wallet/frost/{}/start", scheme.as_str());
    let full_uri = full_request_uri(&headers, &path);
    let claims = match validate_wallet_auth(&state, &headers, "POST", &full_uri, REQUIRED_ACTION).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let preimage = match parse_b64("preimage_b64", &body.preimage_b64) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let round1 = match node_round1(scheme, &body.did, &body.surface_key) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
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
        initiating_sub: claims.sub.clone(),
    };

    let coord = coordinator(&state);
    let store = frost_store(&state);
    coord.sweep(now);
    if let Some(s) = store.as_ref() {
        s.sweep(now);
        if let Err(e) = s.put(&session_id, &session) {
            return e.into_response();
        }
    }
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
        None => return invalid_scheme().into_response(),
    };
    let path = format!("/wallet/frost/{}/commit", scheme.as_str());
    let full_uri = full_request_uri(&headers, &path);
    let claims = match validate_wallet_auth(&state, &headers, "POST", &full_uri, REQUIRED_ACTION).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let device_commitments = match parse_b64("device_commitments_b64", &body.device_commitments_b64) {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };

    let coord = coordinator(&state);
    let store = frost_store(&state);
    let now = now_ms();
    coord.sweep(now);
    let sess_arc = match coord.resolve(store.as_ref(), &body.session_id, now) {
        Some(s) => s,
        None => return session_not_found().into_response(),
    };

    // Compute the SigningPackage *before* taking the session lock for
    // mutation so we don't hold both at once. This is fine because
    // `node_commitments` is immutable for the lifetime of the session.
    let (node_commitments, preimage, sess_scheme, sess_sub) = {
        let sess = sess_arc.lock();
        (
            sess.node_commitments.clone(),
            sess.preimage.clone(),
            sess.scheme,
            sess.initiating_sub.clone(),
        )
    };
    if let Err(e) = require_session_owner(&sess_sub, &claims.sub) {
        return e.into_response();
    }
    if sess_scheme != scheme {
        return wallet_error(StatusCode::BAD_REQUEST,
            "scheme_mismatch",
            "session scheme does not match request path",).into_response();
    }

    let signing_package =
        match build_signing_package(scheme, &node_commitments, &device_commitments, &preimage) {
            Ok(b) => b,
            Err(e) => return e.into_response(),
        };

    let mut sess = sess_arc.lock();
    if sess.effective_state(now) != FrostSessionState::Pending {
        return wallet_error(StatusCode::CONFLICT,
            "invalid_state",
            &format!(
                "commit requires state=pending, got state={:?}",
                sess.state
            ),).into_response();
    }
    sess.device_commitments = Some(device_commitments);
    sess.signing_package = Some(signing_package);
    sess.state = FrostSessionState::Committed;
    if let Some(s) = store.as_ref()
        && let Err(e) = s.put(&body.session_id, &sess)
    {
        return e.into_response();
    }

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
        None => return invalid_scheme().into_response(),
    };
    let path = format!("/wallet/frost/{}/await-challenge", scheme.as_str());
    let full_uri = full_request_uri(&headers, &path);
    let claims = match validate_wallet_auth(&state, &headers, "POST", &full_uri, REQUIRED_ACTION).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let coord = coordinator(&state);
    let store = frost_store(&state);
    let deadline = SystemTime::now() + LONG_POLL_TIMEOUT;
    loop {
        let now = now_ms();
        let sess_arc = match coord.resolve(store.as_ref(), &body.session_id, now) {
            Some(s) => s,
            None => return session_not_found().into_response(),
        };
        let (effective, package, sess_scheme, sess_sub, expired) = {
            let mut sess = sess_arc.lock();
            let expired = sess.is_expired(now);
            (
                sess.effective_state(now),
                sess.signing_package.clone(),
                sess.scheme,
                sess.initiating_sub.clone(),
                expired,
            )
        };
        if let Err(e) = require_session_owner(&sess_sub, &claims.sub) {
            return e.into_response();
        }
        if sess_scheme != scheme {
            return wallet_error(StatusCode::BAD_REQUEST,
                "scheme_mismatch",
                "session scheme does not match request path",).into_response();
        }
        // A session that lapsed its TTL was just flipped to Aborted
        // in-memory by `effective_state`; drop its durable row so it
        // can't be rehydrated later.
        if expired && let Some(s) = store.as_ref() {
            s.delete(&body.session_id);
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
        None => return invalid_scheme().into_response(),
    };
    let path = format!("/wallet/frost/{}/respond", scheme.as_str());
    let full_uri = full_request_uri(&headers, &path);
    let claims = match validate_wallet_auth(&state, &headers, "POST", &full_uri, REQUIRED_ACTION).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let device_share = match parse_b64(
        "device_signature_share_b64",
        &body.device_signature_share_b64,
    ) {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };

    let coord = coordinator(&state);
    let store = frost_store(&state);
    let now = now_ms();
    coord.sweep(now);
    let sess_arc = match coord.resolve(store.as_ref(), &body.session_id, now) {
        Some(s) => s,
        None => return session_not_found().into_response(),
    };

    // Snapshot the inputs needed for aggregation, drop the lock,
    // run the crypto, then take the lock again to mutate.
    let (sess_scheme, did, surface_key, signing_package, node_nonces, current_state, sess_sub) = {
        let mut sess = sess_arc.lock();
        let eff = sess.effective_state(now);
        if eff != FrostSessionState::Committed {
            return wallet_error(StatusCode::CONFLICT,
                "invalid_state",
                &format!(
                    "respond requires state=committed, got state={:?}",
                    eff
                ),).into_response();
        }
        let pkg = match sess.signing_package.clone() {
            Some(p) => p,
            None => {
                return wallet_error(StatusCode::INTERNAL_SERVER_ERROR,
                    "missing_signing_package",
                    "session is committed but signing_package is absent",).into_response();
            }
        };
        (
            sess.scheme,
            sess.did.clone(),
            sess.surface_key.clone(),
            pkg,
            sess.node_nonces.clone(),
            eff,
            sess.initiating_sub.clone(),
        )
    };
    if let Err(e) = require_session_owner(&sess_sub, &claims.sub) {
        return e.into_response();
    }
    if sess_scheme != scheme {
        return wallet_error(StatusCode::BAD_REQUEST,
            "scheme_mismatch",
            "session scheme does not match request path",).into_response();
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
        Err(e) => return e.into_response(),
    };

    let mut sess = sess_arc.lock();
    // Re-check state in case of a concurrent abort.
    if sess.effective_state(now) != FrostSessionState::Committed {
        return wallet_error(StatusCode::CONFLICT,
            "invalid_state",
            "session left committed state during aggregation",).into_response();
    }
    sess.signature = Some(signature);
    sess.state = FrostSessionState::Finalized;
    if let Some(s) = store.as_ref()
        && let Err(e) = s.put(&body.session_id, &sess)
    {
        return e.into_response();
    }

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
        None => return invalid_scheme().into_response(),
    };
    let path = format!("/wallet/frost/{}/finalize", scheme.as_str());
    let full_uri = full_request_uri(&headers, &path);
    let claims = match validate_wallet_auth(&state, &headers, "POST", &full_uri, REQUIRED_ACTION).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let coord = coordinator(&state);
    let store = frost_store(&state);
    let deadline = SystemTime::now() + LONG_POLL_TIMEOUT;
    loop {
        let now = now_ms();
        let sess_arc = match coord.resolve(store.as_ref(), &body.session_id, now) {
            Some(s) => s,
            None => return session_not_found().into_response(),
        };
        let (effective, signature, sess_scheme, sess_sub, expired) = {
            let mut sess = sess_arc.lock();
            let expired = sess.is_expired(now);
            (
                sess.effective_state(now),
                sess.signature.clone(),
                sess.scheme,
                sess.initiating_sub.clone(),
                expired,
            )
        };
        if let Err(e) = require_session_owner(&sess_sub, &claims.sub) {
            return e.into_response();
        }
        if sess_scheme != scheme {
            return wallet_error(StatusCode::BAD_REQUEST,
                "scheme_mismatch",
                "session scheme does not match request path",).into_response();
        }
        // TTL-lapsed session was flipped to Aborted in-memory; evict
        // its durable row.
        if expired && let Some(s) = store.as_ref() {
            s.delete(&body.session_id);
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
        None => return invalid_scheme().into_response(),
    };
    let path = format!("/wallet/frost/{}/abort", scheme.as_str());
    let full_uri = full_request_uri(&headers, &path);
    let claims = match validate_wallet_auth(&state, &headers, "POST", &full_uri, REQUIRED_ACTION).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let coord = coordinator(&state);
    let store = frost_store(&state);
    let now = now_ms();
    coord.sweep(now);
    let sess_arc = match coord.resolve(store.as_ref(), &body.session_id, now) {
        Some(s) => s,
        None => return session_not_found().into_response(),
    };

    let final_state = {
        let mut sess = sess_arc.lock();
        if let Err(e) = require_session_owner(&sess.initiating_sub, &claims.sub) {
            return e.into_response();
        }
        if sess.scheme != scheme {
            return wallet_error(StatusCode::BAD_REQUEST,
                "scheme_mismatch",
                "session scheme does not match request path",).into_response();
        }
        // Finalized sessions stay Finalized — we don't undo a successful
        // signature. Everything else collapses to Aborted (idempotent).
        if sess.state != FrostSessionState::Finalized {
            sess.state = FrostSessionState::Aborted;
        }
        sess.state
    };

    // An aborted session is terminal and carries no reusable material —
    // drop it from both the cache and durable storage. A finalized
    // session keeps its row so a re-`finalize` can still fetch the
    // signature.
    if final_state == FrostSessionState::Aborted {
        coord.sessions.remove(&body.session_id);
        if let Some(s) = store.as_ref() {
            s.delete(&body.session_id);
        }
    }

    Json(AbortResponse { state: final_state }).into_response()
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

    /// Full round: run a FROST(Ed25519) round entirely
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
