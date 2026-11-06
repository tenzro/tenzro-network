//! A2A Tenzro DID Envelope — caller-bound signature on mutation methods.
//!
//! Every A2A method that changes state (`SendMessage`,
//! `SendStreamingMessage`, `CancelTask`) must carry this envelope. Read
//! methods (`GetTask`, `ListTasks`) are not gated.
//!
//! ## Wire keys (all live in `metadata`)
//!
//! For `SendMessage` / `SendStreamingMessage` the keys sit in
//! `params.message.metadata`; for `CancelTask` in `params.metadata`.
//!
//! | Key                              | Payload                                  |
//! |----------------------------------|------------------------------------------|
//! | `tenzro.a2a.envelope.sender`     | DID string (`did:tenzro:...`)            |
//! | `tenzro.a2a.envelope.public_key` | hex (32 = Ed25519, 33 = Secp256k1)       |
//! | `tenzro.a2a.envelope.signature`  | hex signature bytes                      |
//! | `tenzro.a2a.envelope.nonce`      | hex (16 random bytes, replay defense)    |
//! | `tenzro.a2a.envelope.timestamp`  | unix milliseconds (i64)                  |
//!
//! ## Signed message
//!
//! The signature is over the UTF-8 bytes of:
//!
//! ```text
//! tenzro:a2a:{method}:{task_id_or_empty}:{sender_did}:{nonce_hex}:{timestamp_ms}:{params_sha256_hex}
//! ```
//!
//! `params_sha256_hex` is the lowercase hex SHA-256 of the RFC 8785
//! canonical form of the request `params` with the five envelope keys
//! removed from the metadata object they were carried in (and that object
//! dropped if nothing else is left in it). Binding the body
//! means a captured envelope cannot be re-attached to different message
//! parts, a different transfer, or a different task within its skew window.
//!
//! The verifier:
//!
//! 1. Decodes and length-checks all five fields.
//! 2. Auto-detects key type by length (32 = Ed25519, 33 = Secp256k1).
//! 3. Resolves `sender` DID via the node's `IdentityRegistry`.
//! 4. Derives the address from `public_key` and constant-time compares it
//!    against the DID's `wallet_address`.
//! 5. Checks timestamp skew is within ±60s of the local clock.
//! 6. Recomputes the params digest and verifies the signature.
//! 7. Records the nonce in the replay cache.
//!
//! The verified sender is returned to the dispatcher, which passes it to
//! the method handler as the request's principal.

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

const ENVELOPE_KEYS: [&str; 5] = [
    KEY_SENDER,
    KEY_PUBLIC_KEY,
    KEY_SIGNATURE,
    KEY_NONCE,
    KEY_TIMESTAMP,
];

/// Maximum allowed clock skew between client and server, in milliseconds.
pub const MAX_SKEW_MS: i64 = 60_000;

/// Replay-cache TTL. Slightly larger than `MAX_SKEW_MS` so an envelope's
/// nonce cannot be replayed inside the still-valid skew window after a
/// brief restart or cache evict.
pub const REPLAY_TTL_MS: i64 = 90_000;

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
    /// Timestamp outside the ±MAX_SKEW_MS window.
    StaleOrFuture { skew_ms: i64 },
    /// The sender DID is not registered with this node's identity registry.
    UnknownSender(String),
    /// Identity registry not initialized on this node.
    NoIdentityRegistry,
    /// The nonce was already seen within the replay window.
    NonceReplayed,
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
            Self::StaleOrFuture { skew_ms } => format!(
                "A2A envelope timestamp out of window (skew {} ms, max ±{} ms)",
                skew_ms, MAX_SKEW_MS
            ),
            Self::UnknownSender(did) => format!("Unknown sender DID: {}", did),
            Self::NoIdentityRegistry => {
                "Identity registry not initialized — cannot verify A2A envelope".to_string()
            }
            Self::NonceReplayed => {
                "A2A envelope nonce was already used (replay rejected)".to_string()
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

/// Whether a given A2A method is a mutation that requires the DID envelope.
pub fn requires_envelope(method: &str) -> bool {
    matches!(
        method,
        "SendMessage" | "SendStreamingMessage" | "CancelTask"
    )
}

/// Build the canonical preimage that the sender signs.
pub fn canonical_preimage(
    method: &str,
    task_id: &str,
    sender_did: &str,
    nonce_hex: &str,
    timestamp_ms: i64,
    params_sha256_hex: &str,
) -> String {
    format!(
        "tenzro:a2a:{}:{}:{}:{}:{}:{}",
        method, task_id, sender_did, nonce_hex, timestamp_ms, params_sha256_hex
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
/// for `CancelTask`.
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
    method: &str,
    params: &Value,
) -> Result<VerifiedSender, EnvelopeError> {
    let metadata = envelope_metadata(method, params);
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
    verify_against_wallet(
        method,
        params,
        identity.wallet_address,
        chrono::Utc::now().timestamp_millis(),
    )
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

/// Verify an envelope against the wallet address its sender DID resolves
/// to. Split from [`verify_envelope`] so the signature, body-digest, skew
/// and replay rules are checkable without a node.
pub fn verify_against_wallet(
    method: &str,
    params: &Value,
    wallet_address: tenzro_types::Address,
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
    let key_type = match pk_bytes.len() {
        32 => KeyType::Ed25519,
        33 => KeyType::Secp256k1,
        _ => {
            return Err(EnvelopeError::InvalidEnvelope(
                "public_key length".to_string(),
            ));
        }
    };

    let pk = PublicKey::new(key_type, pk_bytes);
    if !wallet_slot_matches(&pk, &wallet_address) {
        return Err(EnvelopeError::InvalidEnvelope(
            "public_key does not match sender DID's wallet address".to_string(),
        ));
    }

    let task_id = envelope_task_id(method, params);
    let digest = params_digest_hex(method, params)?;
    let preimage = canonical_preimage(method, &task_id, &sender, &nonce_hex, timestamp_ms, &digest);
    let sig = Signature::new(key_type, sig_bytes);
    verify(&pk, preimage.as_bytes(), &sig)
        .map_err(|_| EnvelopeError::InvalidEnvelope("signature".to_string()))?;

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
            let preimage = canonical_preimage(method, &task_id, &self.did, &nonce, now_ms, &digest);
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
            "SendMessage",
            "task-123",
            "did:tenzro:human:abc",
            "deadbeef",
            1_700_000_000_000,
            "00ff",
        );
        assert_eq!(
            p,
            "tenzro:a2a:SendMessage:task-123:did:tenzro:human:abc:deadbeef:1700000000000:00ff"
        );
    }

    #[test]
    fn mutation_methods_require_the_envelope() {
        assert!(requires_envelope("SendMessage"));
        assert!(requires_envelope("SendStreamingMessage"));
        assert!(requires_envelope("CancelTask"));
        assert!(!requires_envelope("GetTask"));
        assert!(!requires_envelope("ListTasks"));
    }

    #[test]
    fn signed_envelope_verifies_and_names_the_sender() {
        let sender = TestSender::new("did:tenzro:human:env-ok");
        let mut params = message_params("balance of 0xabc");
        let t = now();
        sender.sign("SendMessage", &mut params, t);
        let verified = verify_against_wallet("SendMessage", &params, sender.wallet(), t).unwrap();
        assert_eq!(verified.did, sender.did);
        assert_eq!(verified.wallet_address, sender.wallet());
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
            verify_against_wallet("SendMessage", &params, sender.wallet(), t),
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
            verify_against_wallet("SendMessage", &params, sender.wallet(), t),
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
            verify_against_wallet("SendStreamingMessage", &params, sender.wallet(), t),
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
            verify_against_wallet("SendMessage", &params, sender.wallet(), t),
            Err(EnvelopeError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn full_digest_wallet_slot_binds_the_same_key() {
        let sender = TestSender::new("did:tenzro:machine:env-hw");
        let slot: [u8; 32] = Sha256::digest(sender.signer.public_key().as_bytes()).into();
        let mut params = message_params("hello");
        let t = now();
        sender.sign("SendMessage", &mut params, t);
        assert!(
            verify_against_wallet("SendMessage", &params, tenzro_types::Address::new(slot), t)
                .is_ok()
        );
    }

    #[test]
    fn identical_envelope_is_accepted_once() {
        let sender = TestSender::new("did:tenzro:human:env-replay");
        let mut params = message_params("hello");
        let t = now();
        sender.sign("SendMessage", &mut params, t);
        assert!(verify_against_wallet("SendMessage", &params, sender.wallet(), t).is_ok());
        assert_eq!(
            verify_against_wallet("SendMessage", &params, sender.wallet(), t),
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
            verify_against_wallet("SendMessage", &params, sender.wallet(), t),
            Err(EnvelopeError::StaleOrFuture { .. })
        ));
    }

    #[test]
    fn cancel_task_envelope_lives_in_params_metadata() {
        let sender = TestSender::new("did:tenzro:human:env-cancel");
        let mut params = serde_json::json!({"id": "task-9"});
        let t = now();
        sender.sign("CancelTask", &mut params, t);
        assert!(verify_against_wallet("CancelTask", &params, sender.wallet(), t).is_ok());
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
}
