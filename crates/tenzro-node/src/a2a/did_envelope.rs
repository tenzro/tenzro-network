//! A2A Tenzro DID Envelope — caller-bound signature on every task method.
//!
//! Every A2A method that opens, changes or reads a task (`SendMessage`,
//! `SendStreamingMessage`, `CancelTask`, `GetTask`, `ListTasks`) must carry
//! this envelope. A task holds what its sender wrote and what the node
//! answered, so a read names its reader as surely as a write names its
//! writer, and the node answers only for the sender's own tasks.
//!
//! ## Wire keys (all live in `metadata`)
//!
//! For `SendMessage` / `SendStreamingMessage` the keys sit in
//! `params.message.metadata`; for `CancelTask`, `GetTask` and `ListTasks` in
//! `params.metadata`.
//!
//! | Key                              | Payload                                  |
//! |----------------------------------|------------------------------------------|
//! | `tenzro.a2a.envelope.sender`     | DID string (`did:tenzro:...`)            |
//! | `tenzro.a2a.envelope.public_key` | hex (32 = Ed25519, 33 = Secp256k1, 64 = hardware P-256 `x \|\| y`) |
//! | `tenzro.a2a.envelope.signature`  | hex signature bytes                      |
//! | `tenzro.a2a.envelope.nonce`      | hex (16 random bytes, replay defense)    |
//! | `tenzro.a2a.envelope.timestamp`  | unix milliseconds (i64)                  |
//! | `tenzro.a2a.envelope.pq_signature` | hex ML-DSA-65 signature (see below)    |
//!
//! ## Signed message
//!
//! The signature is over the UTF-8 bytes of:
//!
//! ```text
//! tenzro:a2a:{audience_did}:{method}:{task_id_or_empty}:{sender_did}:{nonce_hex}:{timestamp_ms}:{params_sha256_hex}
//! ```
//!
//! `audience_did` is the machine DID of the node the request is addressed
//! to, the DID its signed agent card names. An envelope made for one node
//! does not verify on another, so a request captured in transit cannot be
//! replayed to a different node within its skew window.
//!
//! `params_sha256_hex` is the lowercase hex SHA-256 of the RFC 8785
//! canonical form of the request `params` with the envelope keys
//! removed from the metadata object they were carried in (and that object
//! dropped if nothing else is left in it). Binding the body
//! means a captured envelope cannot be re-attached to different message
//! parts, a different transfer, or a different task within its skew window.
//!
//! The verifier:
//!
//! 1. Decodes and length-checks the five classical fields.
//! 2. Auto-detects key type by length (32 = Ed25519, 33 = Secp256k1, 64 =
//!    the P-256 key of a hardware-held account, signing `r || s` over the
//!    SHA-256 of the preimage).
//! 3. Resolves `sender` DID via the node's `IdentityRegistry`, and refuses a
//!    sender whose identity is suspended or revoked.
//! 4. Derives the address from `public_key` and constant-time compares it
//!    against the DID's `wallet_address` (for a P-256 key, the account slot
//!    of that key). A P-256 account key its account retired in chain state
//!    is refused.
//! 5. Checks timestamp skew is within ±60s of the local clock.
//! 6. Recomputes the params digest and verifies the signature.
//! 7. Verifies the ML-DSA-65 leg against the sender's enrolled key: for a
//!    P-256 account key, the one its account enrolled in chain state; for
//!    any other key, the one on the identity record.
//! 8. Records the nonce in the replay cache.
//!
//! The verified sender is returned to the dispatcher, which passes it to
//! the method handler as the request's principal.
//!
//! ## The ML-DSA-65 leg
//!
//! A sender whose identity enrolled an ML-DSA-65 key also signs the
//! preimage with it, under the [`SignatureContext::A2aEnvelope`] context, and
//! sends that signature as `tenzro.a2a.envelope.pq_signature`. The leg is
//! then required: an envelope without it is refused, so a forger of the
//! classical key cannot strip it. A sender with no enrolled key sends no leg,
//! and one that sends a leg anyway is refused.
//!
//! [`SignatureContext::A2aEnvelope`]: tenzro_crypto::composite::SignatureContext::A2aEnvelope

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::OnceLock;

use tenzro_trust::jcs;

/// Reserved metadata keys for the Tenzro DID envelope.
pub const KEY_SENDER: &str = "tenzro.a2a.envelope.sender";
pub const KEY_PUBLIC_KEY: &str = "tenzro.a2a.envelope.public_key";
pub const KEY_SIGNATURE: &str = "tenzro.a2a.envelope.signature";
pub const KEY_NONCE: &str = "tenzro.a2a.envelope.nonce";
pub const KEY_TIMESTAMP: &str = "tenzro.a2a.envelope.timestamp";
pub const KEY_PQ_SIGNATURE: &str = "tenzro.a2a.envelope.pq_signature";

const ENVELOPE_KEYS: [&str; 6] = [
    KEY_SENDER,
    KEY_PUBLIC_KEY,
    KEY_SIGNATURE,
    KEY_NONCE,
    KEY_TIMESTAMP,
    KEY_PQ_SIGNATURE,
];

/// Maximum allowed clock skew between client and server, in milliseconds.
pub const MAX_SKEW_MS: i64 = 60_000;

/// Replay-cache TTL. Slightly larger than `MAX_SKEW_MS` so an envelope's
/// nonce cannot be replayed inside the still-valid skew window after a
/// brief restart or cache evict.
pub const REPLAY_TTL_MS: i64 = 90_000;

/// Whether an envelope stamped `timestamp_ms` predates a node that began
/// serving at `started_at_ms`. The replay cache lives in memory while tasks
/// persist, so an envelope signed before a restart and still inside its skew
/// window would verify again once; none stamped before the start is accepted.
fn predates_start(started_at_ms: i64, timestamp_ms: i64) -> bool {
    timestamp_ms < started_at_ms
}

/// Maximum entries in the process-local replay cache. A burst above this
/// triggers FIFO eviction of the oldest entries. 65k entries × ~64 bytes
/// each ≈ 4 MiB — bounded and fits comfortably in any node footprint.
pub const REPLAY_CACHE_CAPACITY: usize = 65_536;

/// Process-local replay cache. Keyed by `(sender_did, nonce_hex_lower)`;
/// value is the wall-clock millisecond timestamp at insertion. The
/// `VecDeque` records insertion order so the eviction sweep can walk it
/// in O(1) per entry without scanning the HashMap.
#[derive(Default)]
struct ReplayCache {
    seen: HashMap<(String, String), i64>,
    order: VecDeque<(String, String)>,
}

impl ReplayCache {
    /// Atomically check that `(sender_did, nonce_hex)` is unseen within the
    /// replay window AND record it. Returns `true` on first occurrence
    /// (proceed), `false` if the nonce was already in the cache (reject as
    /// replay). Lazily expires stale entries and enforces FIFO capacity
    /// bounds in the same pass.
    fn check_and_record(&mut self, sender_did: &str, nonce_hex: &str, now_ms: i64) -> bool {
        let key = (sender_did.to_string(), nonce_hex.to_lowercase());

        while let Some(front) = self.order.front().cloned() {
            match self.seen.get(&front).copied() {
                Some(ts) if now_ms.saturating_sub(ts) > REPLAY_TTL_MS => {
                    self.order.pop_front();
                    self.seen.remove(&front);
                }
                _ => break,
            }
        }

        if self.seen.contains_key(&key) {
            return false;
        }

        if self.order.len() >= REPLAY_CACHE_CAPACITY
            && let Some(victim) = self.order.pop_front()
        {
            self.seen.remove(&victim);
        }

        self.seen.insert(key.clone(), now_ms);
        self.order.push_back(key);
        true
    }
}

fn replay_cache() -> &'static Mutex<ReplayCache> {
    static CACHE: OnceLock<Mutex<ReplayCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(ReplayCache::default()))
}

/// Records `(sender_did, nonce)` in the node-wide replay cache, returning
/// `false` when the pair was already seen inside the TTL window. Shared by the
/// A2A mutation surface and the managed-database DID-envelope auth path so one
/// cache covers every envelope-authenticated entry point.
pub fn check_and_record_nonce(sender_did: &str, nonce_hex: &str, now_ms: i64) -> bool {
    match replay_cache().lock() {
        Ok(mut cache) => cache.check_and_record(sender_did, nonce_hex, now_ms),
        // Poisoned mutex: fail closed rather than silently weakening replay
        // protection.
        Err(_) => false,
    }
}

/// Outcome of envelope verification. The error variants are intentionally
/// coarse — the verifier returns the same `InvalidEnvelope` for "wrong
/// key", "wrong body" and "wrong signature" so the caller can't use it as
/// an oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Required field absent or wrong type.
    Missing(&'static str),
    /// Signature, public key, address binding or body digest failed.
    InvalidEnvelope(String),
    /// The sender enrolled an ML-DSA-65 key and the envelope lacks its leg,
    /// or the sender enrolled none and the envelope carries one.
    PqLeg(String),
    /// Timestamp outside the ±MAX_SKEW_MS window.
    StaleOrFuture { skew_ms: i64 },
    /// The envelope was stamped before this node started, when its replay
    /// cache was empty.
    BeforeStart,
    /// The sender DID is not registered with this node's identity registry.
    UnknownSender(String),
    /// The sender DID is registered but suspended or revoked.
    SenderNotActive { did: String, status: String },
    /// Identity registry not initialized on this node.
    NoIdentityRegistry,
    /// The nonce was already seen within the replay window.
    NonceReplayed,
    /// The envelope's P-256 account key was retired in consensus.
    KeyRetired,
    /// A P-256 account key signed and this node holds no chain state to read
    /// that account's keys from.
    NoChainState,
    /// This node has no machine DID, so no envelope is addressed to it.
    NoAudience,
}

impl EnvelopeError {
    /// Render as a short message suitable for a JSON-RPC `error.message`.
    pub fn message(&self) -> String {
        match self {
            Self::Missing(field) => format!("Missing required A2A envelope field: {}", field),
            Self::InvalidEnvelope(_) => {
                "Invalid A2A envelope (signature, body digest or public_key binding failed)"
                    .to_string()
            }
            Self::PqLeg(reason) => format!("A2A envelope ML-DSA-65 leg refused: {reason}"),
            Self::StaleOrFuture { skew_ms } => format!(
                "A2A envelope timestamp out of window (skew {} ms, max ±{} ms)",
                skew_ms, MAX_SKEW_MS
            ),
            Self::BeforeStart => {
                "A2A envelope was signed before this node started; sign it again".to_string()
            }
            Self::UnknownSender(did) => format!("Unknown sender DID: {}", did),
            Self::SenderNotActive { did, status } => {
                format!("Sender DID {did} is {status}; only an active identity may act")
            }
            Self::NoIdentityRegistry => {
                "Identity registry not initialized — cannot verify A2A envelope".to_string()
            }
            Self::NonceReplayed => {
                "A2A envelope nonce was already used (replay rejected)".to_string()
            }
            Self::KeyRetired => "A2A envelope key was retired by its account".to_string(),
            Self::NoChainState => {
                "This node holds no chain state to read the sender's account keys from".to_string()
            }
            Self::NoAudience => {
                "This node has no machine DID to address an A2A envelope to".to_string()
            }
        }
    }
}

/// The authenticated principal of an A2A request: the DID whose wallet key
/// signed the envelope, and that wallet's address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSender {
    pub did: String,
    pub wallet_address: tenzro_types::Address,
}

/// Whether a given A2A method opens, changes or reads a task and so
/// requires the DID envelope.
pub fn requires_envelope(method: &str) -> bool {
    matches!(
        method,
        "SendMessage" | "SendStreamingMessage" | "CancelTask" | "GetTask" | "ListTasks"
    )
}

/// Build the canonical preimage that the sender signs for `audience_did`.
pub fn canonical_preimage(
    audience_did: &str,
    method: &str,
    task_id: &str,
    sender_did: &str,
    nonce_hex: &str,
    timestamp_ms: i64,
    params_sha256_hex: &str,
) -> String {
    format!(
        "tenzro:a2a:{}:{}:{}:{}:{}:{}:{}",
        audience_did, method, task_id, sender_did, nonce_hex, timestamp_ms, params_sha256_hex
    )
}

/// The metadata object that carries the envelope for `method`, if present.
fn envelope_metadata_mut<'a>(method: &str, params: &'a mut Value) -> Option<&'a mut Value> {
    match method {
        "SendMessage" | "SendStreamingMessage" => params
            .get_mut("message")
            .and_then(|m| m.get_mut("metadata")),
        _ => params.get_mut("metadata"),
    }
}

/// The metadata map that carries the envelope for `method`. Empty when the
/// request has none, so verification reports the precise missing field.
pub fn envelope_metadata(method: &str, params: &Value) -> HashMap<String, Value> {
    let candidate = match method {
        "SendMessage" | "SendStreamingMessage" => {
            params.get("message").and_then(|m| m.get("metadata"))
        }
        _ => params.get("metadata"),
    };
    match candidate {
        Some(Value::Object(map)) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        _ => HashMap::new(),
    }
}

/// The task id the envelope binds to: `params.message.taskId` for the
/// message methods (empty when the message opens a new task), `params.id`
/// for `CancelTask` and `GetTask`, empty for `ListTasks`.
pub fn envelope_task_id(method: &str, params: &Value) -> String {
    let found = match method {
        "SendMessage" | "SendStreamingMessage" => {
            params.get("message").and_then(|m| m.get("taskId"))
        }
        _ => params.get("id"),
    };
    found.and_then(Value::as_str).unwrap_or("").to_string()
}

/// Lowercase hex SHA-256 of the RFC 8785 canonical `params` with the
/// envelope keys removed. A `metadata` object left empty by that removal is
/// dropped too, so the digest a sender computes before attaching the
/// envelope equals the one the receiver computes after stripping it.
pub fn params_digest_hex(method: &str, params: &Value) -> Result<String, EnvelopeError> {
    let mut body = params.clone();
    let mut emptied = false;
    if let Some(Value::Object(map)) = envelope_metadata_mut(method, &mut body) {
        for key in ENVELOPE_KEYS {
            map.remove(key);
        }
        emptied = map.is_empty();
    }
    if emptied {
        let holder = match method {
            "SendMessage" | "SendStreamingMessage" => body.get_mut("message"),
            _ => Some(&mut body),
        };
        if let Some(Value::Object(obj)) = holder {
            obj.remove("metadata");
        }
    }
    let canonical = jcs::canonicalize(&body)
        .map_err(|e| EnvelopeError::InvalidEnvelope(format!("params canonical form: {e}")))?;
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}

/// Verify the DID envelope on an A2A mutation request.
///
/// Resolves the sender DID through the node's identity registry, then runs
/// [`verify_against_wallet`] against that identity's wallet address.
pub fn verify_envelope(
    node: &crate::node::TenzroNode,
    audience_did: Option<&str>,
    started_at_ms: i64,
    method: &str,
    params: &Value,
) -> Result<VerifiedSender, EnvelopeError> {
    let metadata = envelope_metadata(method, params);
    if metadata
        .get(KEY_TIMESTAMP)
        .and_then(Value::as_i64)
        .is_some_and(|timestamp_ms| predates_start(started_at_ms, timestamp_ms))
    {
        return Err(EnvelopeError::BeforeStart);
    }
    let sender = metadata
        .get(KEY_SENDER)
        .and_then(Value::as_str)
        .ok_or(EnvelopeError::Missing(KEY_SENDER))?
        .to_string();
    let registry = node
        .identity_registry()
        .ok_or(EnvelopeError::NoIdentityRegistry)?;
    let identity = registry
        .resolve(&sender)
        .map_err(|_| EnvelopeError::UnknownSender(sender.clone()))?;
    // The registry answers for a suspended or revoked identity too; its key
    // still signs, so the signature alone would let it keep acting.
    if identity.status != tenzro_identity::IdentityStatus::Active {
        return Err(EnvelopeError::SenderNotActive {
            did: sender,
            status: identity.status.to_string(),
        });
    }
    // A hardware-held P-256 account key answers to chain state, where its
    // account retires it and enrols its ML-DSA-65 key; any other key answers
    // to the identity record.
    let p256_xy = metadata
        .get(KEY_PUBLIC_KEY)
        .and_then(Value::as_str)
        .and_then(|h| hex::decode(h.trim_start_matches("0x")).ok())
        .filter(|pk| pk.len() == 64);
    let enrolled_pq = match p256_xy {
        Some(xy) => {
            let storage = node.storage().cloned().ok_or(EnvelopeError::NoChainState)?;
            let state = tenzro_vm::StateAdapter::with_storage(
                storage as std::sync::Arc<dyn tenzro_storage::KvStore>,
            );
            account_pq_key(&state, &xy)?
        }
        None => (!identity.pq_verifying_key.is_empty()).then(|| identity.pq_verifying_key.clone()),
    };
    verify_against_wallet(
        audience_did.ok_or(EnvelopeError::NoAudience)?,
        method,
        params,
        identity.wallet_address,
        enrolled_pq.as_deref(),
        chrono::Utc::now().timestamp_millis(),
    )
}

/// The ML-DSA-65 key the account named by `p256_xy` enrolled in `state`,
/// refused once that account retired the key.
fn account_pq_key(
    state: &dyn tenzro_vm::traits::VmState,
    p256_xy: &[u8],
) -> Result<Option<Vec<u8>>, EnvelopeError> {
    if tenzro_vm::account_keys::p256_retired(state, p256_xy) {
        return Err(EnvelopeError::KeyRetired);
    }
    Ok(tenzro_vm::account_keys::enrolled_pq_key(state, p256_xy))
}

/// Whether `wallet` is the 32-byte wallet slot of `pk`.
///
/// Identities store the wallet address in one of two deterministic
/// encodings of the key: the 20-byte derived address left-aligned in the
/// slot with zero padding, or, for Ed25519 hardware-rooted identities, the
/// full SHA-256 of the verifying key. Either binds the slot to exactly one
/// key; anything else is a different key.
fn wallet_slot_matches(
    pk: &tenzro_crypto::keys::PublicKey,
    wallet: &tenzro_types::Address,
) -> bool {
    use subtle::ConstantTimeEq;
    let mut left_aligned = [0u8; 32];
    left_aligned[..20].copy_from_slice(pk.to_address().as_bytes());
    let mut matched = left_aligned.ct_eq(wallet.as_bytes());
    if pk.key_type() == tenzro_crypto::keys::KeyType::Ed25519 {
        let full: [u8; 32] = Sha256::digest(pk.as_bytes()).into();
        matched |= full.ct_eq(wallet.as_bytes());
    }
    bool::from(matched)
}

/// Verify an envelope addressed to `audience_did` against the wallet
/// address its sender DID resolves to and the ML-DSA-65 key it enrolled, if
/// any. Split from
/// [`verify_envelope`] so the signature, body-digest, skew and replay rules
/// are checkable without a node.
pub fn verify_against_wallet(
    audience_did: &str,
    method: &str,
    params: &Value,
    wallet_address: tenzro_types::Address,
    enrolled_pq: Option<&[u8]>,
    now_ms: i64,
) -> Result<VerifiedSender, EnvelopeError> {
    use tenzro_crypto::keys::{KeyType, PublicKey};
    use tenzro_crypto::signatures::{Signature, verify};

    let metadata = envelope_metadata(method, params);
    let get_str = |key: &'static str| -> Result<String, EnvelopeError> {
        metadata
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(EnvelopeError::Missing(key))
    };

    let sender = get_str(KEY_SENDER)?;
    let pk_hex = get_str(KEY_PUBLIC_KEY)?;
    let sig_hex = get_str(KEY_SIGNATURE)?;
    let nonce_hex = get_str(KEY_NONCE)?;
    let timestamp_ms = metadata
        .get(KEY_TIMESTAMP)
        .and_then(|v| v.as_i64())
        .ok_or(EnvelopeError::Missing(KEY_TIMESTAMP))?;

    let skew = (now_ms - timestamp_ms).abs();
    if skew > MAX_SKEW_MS {
        return Err(EnvelopeError::StaleOrFuture { skew_ms: skew });
    }

    let pk_bytes = hex::decode(pk_hex.trim_start_matches("0x"))
        .map_err(|_| EnvelopeError::InvalidEnvelope("public_key hex".to_string()))?;
    let sig_bytes = hex::decode(sig_hex.trim_start_matches("0x"))
        .map_err(|_| EnvelopeError::InvalidEnvelope("signature hex".to_string()))?;
    let task_id = envelope_task_id(method, params);
    let digest = params_digest_hex(method, params)?;
    let preimage = canonical_preimage(
        audience_did,
        method,
        &task_id,
        &sender,
        &nonce_hex,
        timestamp_ms,
        &digest,
    );
    let wrong_wallet = || {
        EnvelopeError::InvalidEnvelope(
            "public_key does not match sender DID's wallet address".to_string(),
        )
    };
    let key_type = match pk_bytes.len() {
        32 => Some(KeyType::Ed25519),
        33 => Some(KeyType::Secp256k1),
        // The P-256 key of an account held in a TPM or Secure Enclave.
        64 => None,
        _ => {
            return Err(EnvelopeError::InvalidEnvelope(
                "public_key length".to_string(),
            ));
        }
    };
    match key_type {
        Some(key_type) => {
            let pk = PublicKey::new(key_type, pk_bytes);
            if !wallet_slot_matches(&pk, &wallet_address) {
                return Err(wrong_wallet());
            }
            let sig = Signature::new(key_type, sig_bytes);
            verify(&pk, preimage.as_bytes(), &sig)
                .map_err(|_| EnvelopeError::InvalidEnvelope("signature".to_string()))?;
        }
        None => {
            use subtle::ConstantTimeEq;
            let slot = tenzro_crypto::composite::account_slot(&pk_bytes);
            if !bool::from(slot.ct_eq(wallet_address.as_bytes())) {
                return Err(wrong_wallet());
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(&pk_bytes);
            if !tenzro_device_key::signer::verify_p256(&sec1, preimage.as_bytes(), &sig_bytes) {
                return Err(EnvelopeError::InvalidEnvelope("signature".to_string()));
            }
        }
    }

    let pq_sig = match metadata.get(KEY_PQ_SIGNATURE) {
        None => None,
        Some(v) => Some(
            v.as_str()
                .and_then(|h| hex::decode(h.trim_start_matches("0x")).ok())
                .ok_or_else(|| EnvelopeError::PqLeg("pq_signature hex".to_string()))?,
        ),
    };
    tenzro_crypto::composite::verify_pq_component(
        enrolled_pq,
        tenzro_crypto::composite::SignatureContext::A2aEnvelope,
        preimage.as_bytes(),
        pq_sig.as_deref(),
        tenzro_crypto::composite::PqPolicy::WhenPresent,
    )
    .map_err(|e| EnvelopeError::PqLeg(e.to_string()))?;

    // Recorded only after the signature verifies, so unsigned spam cannot
    // fill the cache and evict legitimate entries.
    if !check_and_record_nonce(&sender, &nonce_hex, now_ms) {
        return Err(EnvelopeError::NonceReplayed);
    }

    Ok(VerifiedSender {
        did: sender,
        wallet_address,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The machine DID test envelopes are addressed to, and the test nodes'
    /// A2A state answers to.
    pub(crate) const TEST_AUDIENCE: &str = "did:tenzro:machine:test-node";
    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer as _};

    /// A signer and the wallet address its DID resolves to.
    pub(crate) struct TestSender {
        pub(crate) did: String,
        signer: Ed25519SignerImpl,
    }

    impl TestSender {
        pub(crate) fn new(did: &str) -> Self {
            Self {
                did: did.to_string(),
                signer: Ed25519SignerImpl::generate().unwrap(),
            }
        }

        pub(crate) fn wallet(&self) -> tenzro_types::Address {
            let mut slot = [0u8; 32];
            slot[..20].copy_from_slice(self.signer.public_key().to_address().as_bytes());
            tenzro_types::Address::new(slot)
        }

        /// Attach a signed envelope for `method` to `params`, using a fresh
        /// random nonce.
        pub(crate) fn sign(&self, method: &str, params: &mut Value, now_ms: i64) {
            let nonce = hex::encode(uuid::Uuid::new_v4().as_bytes());
            let task_id = envelope_task_id(method, params);
            let digest = params_digest_hex(method, params).unwrap();
            let preimage = canonical_preimage(
                TEST_AUDIENCE,
                method,
                &task_id,
                &self.did,
                &nonce,
                now_ms,
                &digest,
            );
            let sig = self.signer.sign(preimage.as_bytes()).unwrap();
            let fields = serde_json::json!({
                KEY_SENDER: self.did,
                KEY_PUBLIC_KEY: hex::encode(self.signer.public_key().as_bytes()),
                KEY_SIGNATURE: hex::encode(sig.as_bytes()),
                KEY_NONCE: nonce,
                KEY_TIMESTAMP: now_ms,
            });
            let target = match method {
                "SendMessage" | "SendStreamingMessage" => params
                    .get_mut("message")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .entry("metadata")
                    .or_insert_with(|| serde_json::json!({})),
                _ => params
                    .as_object_mut()
                    .unwrap()
                    .entry("metadata")
                    .or_insert_with(|| serde_json::json!({})),
            };
            for (k, v) in fields.as_object().unwrap() {
                target.as_object_mut().unwrap().insert(k.clone(), v.clone());
            }
        }
    }

    /// `params` carrying this sender's envelope for `method`, signed now.
    pub(crate) fn signed(sender: &TestSender, method: &str, mut params: Value) -> Value {
        sender.sign(method, &mut params, chrono::Utc::now().timestamp_millis());
        params
    }

    /// Registers `sender` in `registry` as an identity whose wallet is its
    /// key's.
    pub(crate) fn register(registry: &tenzro_identity::IdentityRegistry, sender: &TestSender) {
        use tenzro_identity::{IdentityData, IdentityStatus, TenzroDid, TenzroIdentity};
        registry.upsert_identity_for_test(TenzroIdentity {
            did: TenzroDid::parse(&sender.did).expect("DID"),
            public_keys: Vec::new(),
            identity_data: IdentityData::Machine {
                capabilities: Vec::new(),
                controller_did: None,
                reputation: 0,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
            },
            status: IdentityStatus::Active,
            wallet_address: sender.wallet(),
            wallet_id: String::new(),
            pq_verifying_key: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: Default::default(),
        });
    }

    fn message_params(text: &str) -> Value {
        serde_json::json!({
            "message": {
                "messageId": "m-1",
                "role": "ROLE_USER",
                "parts": [{"text": text}],
            }
        })
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp_millis()
    }

    #[test]
    fn preimage_carries_the_params_digest() {
        let p = canonical_preimage(
            TEST_AUDIENCE,
            "SendMessage",
            "task-123",
            "did:tenzro:human:abc",
            "deadbeef",
            1_700_000_000_000,
            "00ff",
        );
        assert_eq!(
            p,
            "tenzro:a2a:did:tenzro:machine:test-node:SendMessage:task-123:did:tenzro:human:abc:deadbeef:1700000000000:00ff"
        );
    }

    #[test]
    fn an_envelope_made_for_one_node_does_not_verify_on_another() {
        let sender = TestSender::new("did:tenzro:machine:env-audience");
        let t = now();
        let mut params = message_params("hello");
        sender.sign("SendMessage", &mut params, t);
        assert!(matches!(
            verify_against_wallet(
                "did:tenzro:machine:another-node",
                "SendMessage",
                &params,
                sender.wallet(),
                None,
                t
            ),
            Err(EnvelopeError::InvalidEnvelope(_))
        ));
        let verified = verify_against_wallet(
            TEST_AUDIENCE,
            "SendMessage",
            &params,
            sender.wallet(),
            None,
            t,
        )
        .unwrap();
        assert_eq!(verified.did, sender.did);
    }

    #[test]
    fn every_task_method_requires_the_envelope() {
        assert!(requires_envelope("SendMessage"));
        assert!(requires_envelope("SendStreamingMessage"));
        assert!(requires_envelope("CancelTask"));
        assert!(requires_envelope("GetTask"));
        assert!(requires_envelope("ListTasks"));
        assert!(!requires_envelope("GetExtendedAgentCard"));
    }

    #[test]
    fn signed_envelope_verifies_and_names_the_sender() {
        let sender = TestSender::new("did:tenzro:human:env-ok");
        let mut params = message_params("balance of 0xabc");
        let t = now();
        sender.sign("SendMessage", &mut params, t);
        let verified = verify_against_wallet(
            TEST_AUDIENCE,
            "SendMessage",
            &params,
            sender.wallet(),
            None,
            t,
        )
        .unwrap();
        assert_eq!(verified.did, sender.did);
        assert_eq!(verified.wallet_address, sender.wallet());
    }

    #[test]
    fn an_envelope_stamped_before_the_node_started_is_refused() {
        assert!(predates_start(1_000, 999));
        assert!(!predates_start(1_000, 1_000));
        assert!(!predates_start(1_000, 2_000));
    }

    #[test]
    fn the_machine_did_vector_the_sdks_are_held_to_is_the_ledgers_derivation() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../sdk/fixtures/machine-did/vector.json"
        ))
        .unwrap();
        let mut sec1 = vec![4u8];
        sec1.extend(hex::decode(v["p256_xy"].as_str().unwrap()).unwrap());
        assert_eq!(
            tenzro_types::did_derivation::machine_did(&sec1),
            v["machine_did"].as_str().unwrap()
        );
    }

    #[test]
    fn envelope_replayed_with_a_different_body_is_rejected() {
        let sender = TestSender::new("did:tenzro:human:env-body");
        let mut params = message_params("send 1 TNZO to 0x01");
        let t = now();
        sender.sign("SendMessage", &mut params, t);
        // Same envelope, different message parts.
        params["message"]["parts"][0]["text"] = Value::from("send 1000 TNZO to 0x02");
        assert!(matches!(
            verify_against_wallet(
                TEST_AUDIENCE,
                "SendMessage",
                &params,
                sender.wallet(),
                None,
                t
            ),
            Err(EnvelopeError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn envelope_moved_to_another_task_is_rejected() {
        let sender = TestSender::new("did:tenzro:human:env-task");
        let mut params = message_params("continue");
        params["message"]["taskId"] = Value::from("task-a");
        let t = now();
        sender.sign("SendMessage", &mut params, t);
        params["message"]["taskId"] = Value::from("task-b");
        assert!(matches!(
            verify_against_wallet(
                TEST_AUDIENCE,
                "SendMessage",
                &params,
                sender.wallet(),
                None,
                t
            ),
            Err(EnvelopeError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn envelope_for_one_method_does_not_authorize_another() {
        let sender = TestSender::new("did:tenzro:human:env-method");
        let mut params = message_params("hello");
        let t = now();
        sender.sign("SendMessage", &mut params, t);
        assert!(matches!(
            verify_against_wallet(
                TEST_AUDIENCE,
                "SendStreamingMessage",
                &params,
                sender.wallet(),
                None,
                t
            ),
            Err(EnvelopeError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn envelope_signed_by_a_key_outside_the_senders_wallet_is_rejected() {
        let sender = TestSender::new("did:tenzro:human:env-victim");
        let attacker = TestSender::new("did:tenzro:human:env-victim");
        let mut params = message_params("hello");
        let t = now();
        attacker.sign("SendMessage", &mut params, t);
        assert!(matches!(
            verify_against_wallet(
                TEST_AUDIENCE,
                "SendMessage",
                &params,
                sender.wallet(),
                None,
                t
            ),
            Err(EnvelopeError::InvalidEnvelope(_))
        ));
    }

    /// An account whose key is a hardware P-256 key signs the envelope with
    /// that key: `r || s` over SHA-256 of the preimage, the public key sent
    /// as `x || y`, and the wallet is that key's account slot.
    #[test]
    fn a_hardware_p256_account_key_signs_the_envelope() {
        use tenzro_crypto::p256::{P256KeyPair, P256Signer};
        let pair = P256KeyPair::generate();
        let signer = P256Signer::from_keypair(&pair);
        let xy = signer.public_key_bytes();
        let wallet = tenzro_types::Address::new(tenzro_crypto::composite::account_slot(&xy));
        let did = "did:tenzro:machine:p256-holder";
        let sign = |method: &str, mut params: Value, signer: &P256Signer| {
            let nonce = hex::encode(uuid::Uuid::new_v4().as_bytes());
            let at = now();
            let preimage = canonical_preimage(
                TEST_AUDIENCE,
                method,
                &envelope_task_id(method, &params),
                did,
                &nonce,
                at,
                &params_digest_hex(method, &params).unwrap(),
            );
            params["metadata"] = serde_json::json!({
                KEY_SENDER: did,
                KEY_PUBLIC_KEY: hex::encode(xy),
                KEY_SIGNATURE: hex::encode(signer.sign_sha256(preimage.as_bytes()).as_bytes()),
                KEY_NONCE: nonce,
                KEY_TIMESTAMP: at,
            });
            params
        };

        let list = sign("ListTasks", serde_json::json!({"contextId": "c"}), &signer);
        let sender =
            verify_against_wallet(TEST_AUDIENCE, "ListTasks", &list, wallet, None, now()).unwrap();
        assert_eq!(sender.did, did);
        let get = sign("GetTask", serde_json::json!({"id": "t-1"}), &signer);
        verify_against_wallet(TEST_AUDIENCE, "GetTask", &get, wallet, None, now()).unwrap();

        // Another task id, another wallet and another key are each refused.
        let mut moved = sign("GetTask", serde_json::json!({"id": "t-1"}), &signer);
        moved["id"] = serde_json::json!("t-2");
        assert!(
            verify_against_wallet(TEST_AUDIENCE, "GetTask", &moved, wallet, None, now()).is_err()
        );
        let fresh = sign("GetTask", serde_json::json!({"id": "t-1"}), &signer);
        let elsewhere = tenzro_types::Address::new([9u8; 32]);
        assert!(
            verify_against_wallet(TEST_AUDIENCE, "GetTask", &fresh, elsewhere, None, now())
                .is_err()
        );
        let other = P256Signer::from_keypair(&P256KeyPair::generate());
        let forged = sign("GetTask", serde_json::json!({"id": "t-1"}), &other);
        assert!(
            verify_against_wallet(TEST_AUDIENCE, "GetTask", &forged, wallet, None, now()).is_err()
        );
    }

    #[test]
    fn full_digest_wallet_slot_binds_the_same_key() {
        let sender = TestSender::new("did:tenzro:machine:env-hw");
        let slot: [u8; 32] = Sha256::digest(sender.signer.public_key().as_bytes()).into();
        let mut params = message_params("hello");
        let t = now();
        sender.sign("SendMessage", &mut params, t);
        assert!(
            verify_against_wallet(
                TEST_AUDIENCE,
                "SendMessage",
                &params,
                tenzro_types::Address::new(slot),
                None,
                t
            )
            .is_ok()
        );
    }

    #[test]
    fn identical_envelope_is_accepted_once() {
        let sender = TestSender::new("did:tenzro:human:env-replay");
        let mut params = message_params("hello");
        let t = now();
        sender.sign("SendMessage", &mut params, t);
        assert!(
            verify_against_wallet(
                TEST_AUDIENCE,
                "SendMessage",
                &params,
                sender.wallet(),
                None,
                t
            )
            .is_ok()
        );
        assert_eq!(
            verify_against_wallet(
                TEST_AUDIENCE,
                "SendMessage",
                &params,
                sender.wallet(),
                None,
                t
            ),
            Err(EnvelopeError::NonceReplayed)
        );
    }

    #[test]
    fn stale_envelope_is_rejected() {
        let sender = TestSender::new("did:tenzro:human:env-stale");
        let mut params = message_params("hello");
        let t = now();
        sender.sign("SendMessage", &mut params, t - MAX_SKEW_MS - 1);
        assert!(matches!(
            verify_against_wallet(
                TEST_AUDIENCE,
                "SendMessage",
                &params,
                sender.wallet(),
                None,
                t
            ),
            Err(EnvelopeError::StaleOrFuture { .. })
        ));
    }

    #[test]
    fn cancel_task_envelope_lives_in_params_metadata() {
        let sender = TestSender::new("did:tenzro:human:env-cancel");
        let mut params = serde_json::json!({"id": "task-9"});
        let t = now();
        sender.sign("CancelTask", &mut params, t);
        assert!(
            verify_against_wallet(
                TEST_AUDIENCE,
                "CancelTask",
                &params,
                sender.wallet(),
                None,
                t
            )
            .is_ok()
        );
    }

    #[test]
    fn replay_cache_first_admit_then_reject() {
        let mut cache = ReplayCache::default();
        let now = chrono::Utc::now().timestamp_millis();
        let did = "did:tenzro:test:replay-1";
        let nonce = "deadbeefcafef00d";
        assert!(cache.check_and_record(did, nonce, now));
        assert!(!cache.check_and_record(did, nonce, now));
        assert!(cache.check_and_record(did, "1234567890abcdef", now));
        assert!(!cache.check_and_record(did, "DEADBEEFCAFEF00D", now));
    }

    #[test]
    fn replay_cache_expires_after_ttl() {
        let mut cache = ReplayCache::default();
        let did = "did:tenzro:test:replay-2";
        let nonce = "aaaaaaaabbbbbbbb";
        let t0 = chrono::Utc::now().timestamp_millis();
        assert!(cache.check_and_record(did, nonce, t0));
        let t1 = t0 + REPLAY_TTL_MS + 1;
        assert!(cache.check_and_record(did, nonce, t1));
    }

    /// Attach to an envelope `sign` made the ML-DSA-65 leg of `key`.
    fn add_pq_leg(method: &str, params: &mut Value, key: &tenzro_crypto::pq::MlDsaSigningKey) {
        use tenzro_crypto::composite::{SignatureContext, message_representative};
        let meta = envelope_metadata(method, params);
        let preimage = canonical_preimage(
            TEST_AUDIENCE,
            method,
            &envelope_task_id(method, params),
            meta[KEY_SENDER].as_str().unwrap(),
            meta[KEY_NONCE].as_str().unwrap(),
            meta[KEY_TIMESTAMP].as_i64().unwrap(),
            &params_digest_hex(method, params).unwrap(),
        );
        let m_prime = message_representative(SignatureContext::A2aEnvelope, preimage.as_bytes());
        let leg = key.sign(
            tenzro_types::signature_scheme::SignatureScheme::default().label(),
            &m_prime,
        );
        envelope_metadata_mut(method, params)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(KEY_PQ_SIGNATURE.to_string(), hex::encode(leg).into());
    }

    #[test]
    fn a_sender_with_an_enrolled_ml_dsa_key_must_send_its_leg() {
        let sender = TestSender::new("did:tenzro:machine:env-pq");
        let key = tenzro_crypto::pq::MlDsaSigningKey::generate();
        let enrolled = Some(key.verifying_key_bytes());
        let t = now();

        let mut stripped = message_params("hello");
        sender.sign("SendMessage", &mut stripped, t);
        assert!(matches!(
            verify_against_wallet(
                TEST_AUDIENCE,
                "SendMessage",
                &stripped,
                sender.wallet(),
                enrolled,
                t
            ),
            Err(EnvelopeError::PqLeg(_))
        ));

        let mut whole = message_params("hello");
        sender.sign("SendMessage", &mut whole, t);
        add_pq_leg("SendMessage", &mut whole, &key);
        let verified = verify_against_wallet(
            TEST_AUDIENCE,
            "SendMessage",
            &whole,
            sender.wallet(),
            enrolled,
            t,
        )
        .unwrap();
        assert_eq!(verified.did, sender.did);

        // A leg by another ML-DSA key, or moved to another body, is refused.
        let mut other = message_params("hello");
        sender.sign("SendMessage", &mut other, t);
        add_pq_leg(
            "SendMessage",
            &mut other,
            &tenzro_crypto::pq::MlDsaSigningKey::generate(),
        );
        assert!(matches!(
            verify_against_wallet(
                TEST_AUDIENCE,
                "SendMessage",
                &other,
                sender.wallet(),
                enrolled,
                t
            ),
            Err(EnvelopeError::PqLeg(_))
        ));
        let mut moved = message_params("hello");
        sender.sign("SendMessage", &mut moved, t);
        add_pq_leg("SendMessage", &mut moved, &key);
        let leg = envelope_metadata("SendMessage", &moved)[KEY_PQ_SIGNATURE].clone();
        let mut fresh = message_params("goodbye");
        sender.sign("SendMessage", &mut fresh, t);
        envelope_metadata_mut("SendMessage", &mut fresh)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(KEY_PQ_SIGNATURE.to_string(), leg);
        assert!(matches!(
            verify_against_wallet(
                TEST_AUDIENCE,
                "SendMessage",
                &fresh,
                sender.wallet(),
                enrolled,
                t
            ),
            Err(EnvelopeError::PqLeg(_))
        ));
    }

    #[test]
    fn a_p256_account_key_answers_to_the_keys_its_account_holds_in_chain_state() {
        let mut state = tenzro_vm::StateAdapter::new();
        let xy = [0x42u8; 64];
        assert_eq!(account_pq_key(&state, &xy).unwrap(), None);

        let key = tenzro_crypto::pq::MlDsaSigningKey::generate();
        tenzro_vm::account_keys::set_enrolled_pq_key(
            &mut state,
            &xy,
            key.verifying_key_bytes().to_vec(),
            &mut Vec::new(),
        );
        let enrolled = account_pq_key(&state, &xy).unwrap();
        assert_eq!(enrolled.as_deref(), Some(key.verifying_key_bytes()));

        // The enrolled account's envelope without its ML-DSA-65 leg is refused.
        let sender = TestSender::new("did:tenzro:machine:env-chain");
        let t = now();
        let mut stripped = message_params("hello");
        sender.sign("SendMessage", &mut stripped, t);
        assert!(matches!(
            verify_against_wallet(
                TEST_AUDIENCE,
                "SendMessage",
                &stripped,
                sender.wallet(),
                enrolled.as_deref(),
                t
            ),
            Err(EnvelopeError::PqLeg(_))
        ));

        tenzro_vm::account_keys::retire_p256(&mut state, &xy, &mut Vec::new());
        assert!(matches!(
            account_pq_key(&state, &xy),
            Err(EnvelopeError::KeyRetired)
        ));
    }

    #[test]
    fn a_sender_with_no_enrolled_ml_dsa_key_signs_classically_and_sends_no_leg() {
        let sender = TestSender::new("did:tenzro:machine:env-classical");
        let t = now();

        let mut plain = message_params("hello");
        sender.sign("SendMessage", &mut plain, t);
        assert!(
            verify_against_wallet(
                TEST_AUDIENCE,
                "SendMessage",
                &plain,
                sender.wallet(),
                None,
                t
            )
            .is_ok()
        );

        let mut with_leg = message_params("hello");
        sender.sign("SendMessage", &mut with_leg, t);
        add_pq_leg(
            "SendMessage",
            &mut with_leg,
            &tenzro_crypto::pq::MlDsaSigningKey::generate(),
        );
        assert!(matches!(
            verify_against_wallet(
                TEST_AUDIENCE,
                "SendMessage",
                &with_leg,
                sender.wallet(),
                None,
                t
            ),
            Err(EnvelopeError::PqLeg(_))
        ));
    }
}
