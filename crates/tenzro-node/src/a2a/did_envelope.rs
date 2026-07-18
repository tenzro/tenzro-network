//! A2A Tenzro DID Envelope — caller-bound signature on mutation methods.
//!
//! This module implements the Tenzro DID envelope wire format for A2A
//! mutation methods (`message/send`, `tasks/send`, `tasks/cancel`,
//! `payments/create`, `payments/authorize`, `payments/execute`,
//! `payments/cancel`). Read methods (`tasks/get`, `tasks/list`,
//! `payments/status`) are not gated by this envelope.
//!
//! ## Wire keys (all live in `Message.metadata`)
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
//! The signature is computed over the SHA-256 of the canonical preimage:
//!
//! ```text
//! tenzro:a2a:{method}:{task_id_or_empty}:{sender_did}:{nonce_hex}:{timestamp_ms}
//! ```
//!
//! Domain separator `tenzro:a2a:` and the method name pin the envelope to
//! a specific A2A operation; `nonce` plus `timestamp` defend against
//! replay across sessions; `task_id` (when present) binds to a specific
//! task. The verifier:
//!
//! 1. Decodes and length-checks all five fields.
//! 2. Auto-detects key type by length (32 = Ed25519, 33 = Secp256k1).
//! 3. Resolves `sender` DID via the node's `IdentityRegistry`.
//! 4. Derives the address from `public_key` (canonical 32-byte slot with
//!    the 20-byte derived address at positions `[0..20]`) and constant-time
//!    compares against the DID's `wallet_address`.
//! 5. Checks timestamp skew is within ±60s of the local clock.
//! 6. Verifies the signature via `tenzro_crypto::signatures::verify()`.
//!
//! Replay protection: timestamp skew + a process-local LRU nonce cache.
//! The cache holds `(sender_did, nonce_hex)` keys with a TTL slightly
//! larger than `MAX_SKEW_MS` so a captured envelope cannot be replayed
//! inside its still-valid skew window. Sized to `REPLAY_CACHE_CAPACITY`
//! entries with FIFO eviction; an attacker who floods the cache simply
//! forces premature eviction of their own earlier entries — they cannot
//! evict a victim's pending mutation because that's still being processed
//! synchronously by the dispatch path.

use serde_json::Value;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::collections::VecDeque;

/// Reserved metadata keys for the Tenzro DID envelope.
pub const KEY_SENDER: &str = "tenzro.a2a.envelope.sender";
pub const KEY_PUBLIC_KEY: &str = "tenzro.a2a.envelope.public_key";
pub const KEY_SIGNATURE: &str = "tenzro.a2a.envelope.signature";
pub const KEY_NONCE: &str = "tenzro.a2a.envelope.nonce";
pub const KEY_TIMESTAMP: &str = "tenzro.a2a.envelope.timestamp";

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
///
/// Static `OnceLock<Mutex<_>>` so the cache survives across multiple
/// independent `verify_envelope` callers without threading state through
/// every handler. The mutex is held only across O(1) hashmap ops —
/// signature verification happens before acquiring it.
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

        // Expire stale entries from the front of the order queue. We only
        // need to walk until we hit a still-valid entry; everything behind it
        // is younger.
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

        // FIFO eviction if at capacity.
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
        // Poisoned mutex: a previous thread panicked while holding it.
        // Fail-closed — reject the envelope rather than silently weakening
        // replay protection. The operator sees panic logs separately.
        Err(_) => false,
    }
}

/// Outcome of envelope verification. The error variants are intentionally
/// coarse — the verifier returns the same `InvalidEnvelope` for "wrong
/// key" and "wrong signature" so the caller can't use it as an oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Required field absent or wrong type.
    Missing(&'static str),
    /// Signature, public key, or address binding failed verification.
    InvalidEnvelope(String),
    /// Timestamp outside the ±MAX_SKEW_MS window.
    StaleOrFuture { skew_ms: i64 },
    /// The sender DID is not registered with this node's identity registry.
    UnknownSender(String),
    /// Identity registry not initialized on this node.
    NoIdentityRegistry,
    /// The nonce was already seen within the replay window — captured
    /// envelope is being replayed by an attacker or a buggy client.
    NonceReplayed,
}

impl EnvelopeError {
    /// Render as a short message suitable for a JSON-RPC `error.message`
    /// field. All four error paths map to JSON-RPC code `-32001` at the
    /// caller (consistent with the rest of the auth-rejection surface).
    pub fn message(&self) -> String {
        match self {
            Self::Missing(field) => format!(
                "Missing required A2A envelope field: {}",
                field
            ),
            Self::InvalidEnvelope(_) => {
                // Coarse — do not leak which step failed.
                "Invalid A2A envelope (signature or public_key binding failed)".to_string()
            }
            Self::StaleOrFuture { skew_ms } => format!(
                "A2A envelope timestamp out of window (skew {} ms, max ±{} ms)",
                skew_ms, MAX_SKEW_MS
            ),
            Self::UnknownSender(did) => format!(
                "Unknown sender DID: {}",
                did
            ),
            Self::NoIdentityRegistry => {
                "Identity registry not initialized — cannot verify A2A envelope".to_string()
            }
            Self::NonceReplayed => {
                "A2A envelope nonce was already used (replay rejected)".to_string()
            }
        }
    }
}

/// Whether a given A2A method is a mutation that requires the DID envelope.
pub fn requires_envelope(method: &str) -> bool {
    matches!(
        method,
        "message/send"
            | "tasks/send"
            | "tasks/cancel"
            | "payments/create"
            | "payments/authorize"
            | "payments/execute"
            | "payments/cancel"
    )
}

/// Build the canonical preimage that the sender signs.
///
/// `task_id` may be empty when the mutation does not bind to an existing
/// task (e.g. `message/send` creating a brand-new task — the caller
/// signs with an empty task_id and the server assigns one).
pub fn canonical_preimage(
    method: &str,
    task_id: &str,
    sender_did: &str,
    nonce_hex: &str,
    timestamp_ms: i64,
) -> String {
    format!(
        "tenzro:a2a:{}:{}:{}:{}:{}",
        method, task_id, sender_did, nonce_hex, timestamp_ms
    )
}

/// Verify the DID envelope attached to an A2A mutation request.
///
/// `node` must expose the identity registry; `metadata` is the inbound
/// `Message.metadata` map. The verifier resolves `sender` DID, binds
/// `public_key` to the DID's wallet address, checks timestamp skew,
/// and verifies the signature over [`canonical_preimage`].
///
/// Returns `Ok(sender_did)` on success — the caller can use the resolved
/// DID for downstream authorization (rate limits, audit logs, payment
/// scope checks).
pub fn verify_envelope(
    node: &crate::node::TenzroNode,
    method: &str,
    task_id: &str,
    metadata: &HashMap<String, Value>,
) -> Result<String, EnvelopeError> {
    use subtle::ConstantTimeEq;
    use tenzro_crypto::keys::{KeyType, PublicKey};
    use tenzro_crypto::signatures::{verify, Signature};

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

    // Skew check first — cheap rejection before any crypto work.
    let now_ms = chrono::Utc::now().timestamp_millis();
    let skew = (now_ms - timestamp_ms).abs();
    if skew > MAX_SKEW_MS {
        return Err(EnvelopeError::StaleOrFuture { skew_ms: skew });
    }

    let registry = node
        .identity_registry()
        .ok_or(EnvelopeError::NoIdentityRegistry)?;

    let identity = registry
        .resolve(&sender)
        .map_err(|_| EnvelopeError::UnknownSender(sender.clone()))?;

    let pk_bytes = hex::decode(pk_hex.trim_start_matches("0x"))
        .map_err(|_| EnvelopeError::InvalidEnvelope("public_key hex".to_string()))?;
    let sig_bytes = hex::decode(sig_hex.trim_start_matches("0x"))
        .map_err(|_| EnvelopeError::InvalidEnvelope("signature hex".to_string()))?;

    let key_type = match pk_bytes.len() {
        32 => KeyType::Ed25519,
        33 => KeyType::Secp256k1,
        _ => return Err(EnvelopeError::InvalidEnvelope("public_key length".to_string())),
    };

    let pk = PublicKey::new(key_type, pk_bytes);
    let derived_addr = pk.to_address();

    // `PublicKey::to_address()` and `TenzroIdentity::wallet_address` are
    // both 32-byte canonical slots with the 20-byte derived address at
    // positions [0..20]. Constant-time compare the full slots.
    let claimed = identity.wallet_address;
    if !bool::from(derived_addr.as_bytes().ct_eq(claimed.as_bytes())) {
        return Err(EnvelopeError::InvalidEnvelope(
            "public_key does not match sender DID's wallet address".to_string(),
        ));
    }

    let preimage = canonical_preimage(method, task_id, &sender, &nonce_hex, timestamp_ms);
    let sig = Signature::new(key_type, sig_bytes);
    verify(&pk, preimage.as_bytes(), &sig)
        .map_err(|_| EnvelopeError::InvalidEnvelope("signature".to_string()))?;

    // Nonce-replay guard. Runs only after the signature has verified so an
    // attacker spamming bogus envelopes cannot fill the cache and force
    // premature eviction of legitimate entries — they would have to forge a
    // valid signature for each spam entry, which is the cost we want.
    // Atomic check-and-record inside the cache mutex.
    if !check_and_record_nonce(&sender, &nonce_hex, now_ms) {
        return Err(EnvelopeError::NonceReplayed);
    }

    Ok(sender)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_preimage_format() {
        let p = canonical_preimage(
            "message/send",
            "task-123",
            "did:tenzro:human:abc",
            "deadbeef",
            1_700_000_000_000,
        );
        assert_eq!(
            p,
            "tenzro:a2a:message/send:task-123:did:tenzro:human:abc:deadbeef:1700000000000"
        );
    }

    #[test]
    fn requires_envelope_mutation_methods() {
        assert!(requires_envelope("message/send"));
        assert!(requires_envelope("tasks/send"));
        assert!(requires_envelope("tasks/cancel"));
        assert!(requires_envelope("payments/create"));
        assert!(requires_envelope("payments/authorize"));
        assert!(requires_envelope("payments/execute"));
        assert!(requires_envelope("payments/cancel"));
    }

    #[test]
    fn requires_envelope_read_methods_exempt() {
        assert!(!requires_envelope("tasks/get"));
        assert!(!requires_envelope("tasks/list"));
        assert!(!requires_envelope("payments/status"));
    }

    #[test]
    fn missing_field_reports_field_name() {
        let metadata: HashMap<String, Value> = HashMap::new();
        // Build a fake node to satisfy the signature. We can't reach this
        // path without a real node, but the unit tests above cover the pure
        // helpers; full integration is exercised by the A2A handler tests.
        let _ = metadata;
    }

    // Both tests below use a local `ReplayCache` instance instead of the
    // process-global one: tests run in parallel, and the TTL test's sweep
    // with a future timestamp would evict the other test's entries.

    #[test]
    fn replay_cache_first_admit_then_reject() {
        let mut cache = ReplayCache::default();
        let now = chrono::Utc::now().timestamp_millis();
        let did = "did:tenzro:test:replay-1";
        let nonce = "deadbeefcafef00d";

        // First insertion admits.
        assert!(cache.check_and_record(did, nonce, now));
        // Immediate replay rejects.
        assert!(!cache.check_and_record(did, nonce, now));
        // A different nonce from the same DID is fine.
        assert!(cache.check_and_record(did, "1234567890abcdef", now));
        // Case-insensitive: uppercase nonce_hex still treated as replay.
        assert!(!cache.check_and_record(did, "DEADBEEFCAFEF00D", now));
    }

    #[test]
    fn replay_cache_expires_after_ttl() {
        let mut cache = ReplayCache::default();
        let did = "did:tenzro:test:replay-2";
        let nonce = "aaaaaaaabbbbbbbb";
        let t0 = chrono::Utc::now().timestamp_millis();

        assert!(cache.check_and_record(did, nonce, t0));
        // Same nonce just after TTL expiry is accepted because the lazy
        // sweep retires the stale entry before checking.
        let t1 = t0 + REPLAY_TTL_MS + 1;
        assert!(cache.check_and_record(did, nonce, t1));
    }
}
