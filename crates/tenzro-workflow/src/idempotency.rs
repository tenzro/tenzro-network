//! Workflow step idempotency keys.
//!
//! Long-running multi-party workflows retry steps for many reasons: a
//! participant times out, gossipsub re-delivers a step-execute envelope,
//! the saga compensator runs alongside the forward leg. Without an
//! idempotency key, repeated `StepExecute` calls execute the underlying
//! action twice — debiting two payments, opening two L/Cs, signing two
//! DAML choices.
//!
//! The canonical fix is the Stripe / AWS Step Functions pattern: every
//! step-execute envelope carries an `idempotency_key` (any 32-byte value
//! the caller chooses, typically `SHA-256(workflow_id || step_id ||
//! caller_did || attempt_nonce)`). The runtime stores
//! `key -> first_result_hash` in `CF_AGENTS` under
//! `workflow/idempotency/{workflow_id}/{step_id}/{key}`. A second call
//! with the same key returns the stored result instead of re-executing.
//!
//! # Key derivation guidance
//!
//! Callers SHOULD derive the key deterministically from the inputs they
//! are committing to. Recommended:
//!
//! ```ignore
//! let key = sha256("tenzro/idempotency"
//!   || workflow_id
//!   || step_id
//!   || caller_did
//!   || canonical_payload_hash);
//! ```
//!
//! This way, every retry of the SAME logical operation produces the
//! SAME key, while a different logical operation (different payload)
//! produces a different key.
//!
//! # Result hash, not result body
//!
//! We persist only `result_hash = SHA-256(canonical_result_payload)`,
//! not the result itself. This keeps the CF small (32 bytes per key)
//! and prevents the runtime from accidentally serving stale large
//! payloads. The caller re-derives the canonical payload and verifies
//! the hash matches before treating the call as a no-op.

use crate::error::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A 32-byte idempotency key. Generated deterministically by the
/// caller from `(workflow_id, step_id, caller_did, payload_hash)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdempotencyKey(pub [u8; 32]);

impl IdempotencyKey {
    /// Canonical key derivation (Stripe / AWS Step Functions pattern).
    /// Domain-separated SHA-256 over the bound inputs.
    pub fn derive(
        workflow_id: &[u8],
        step_id: &[u8],
        caller_did: &[u8],
        payload_hash: &[u8],
    ) -> Self {
        let mut h = Sha256::new();
        h.update(b"tenzro/idempotency/v1");
        h.update((workflow_id.len() as u32).to_le_bytes());
        h.update(workflow_id);
        h.update((step_id.len() as u32).to_le_bytes());
        h.update(step_id);
        h.update((caller_did.len() as u32).to_le_bytes());
        h.update(caller_did);
        h.update(payload_hash);
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        IdempotencyKey(out)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// The persisted record for an idempotency key — the first-write-wins
/// observation of a step's execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    pub key_hex: String,
    pub workflow_id_hex: String,
    pub step_id_hex: String,
    pub result_hash: [u8; 32],
    pub executed_at_ms: u64,
}

/// Outcome of checking an idempotency key against the store.
#[derive(Debug, Clone)]
pub enum IdempotencyCheck {
    /// First time we've seen this key. Caller MUST execute the step
    /// and record the result via `IdempotencyStore::record`.
    NotSeen,
    /// We have a record for this key. Caller MUST NOT re-execute; the
    /// recorded result hash should be returned to the caller.
    SeenWithResult(IdempotencyRecord),
}

/// Storage interface for idempotency records. Wired against the
/// node's `KvStore` via the `with_storage` constructor on
/// `WorkflowManager`. Pure trait so tests can use an in-memory impl.
pub trait IdempotencyStore: Send + Sync {
    fn lookup(&self, key: &IdempotencyKey) -> Result<Option<IdempotencyRecord>>;
    fn record(&self, record: IdempotencyRecord) -> Result<()>;
}

/// In-memory idempotency store for tests.
pub struct InMemoryIdempotencyStore {
    inner: dashmap::DashMap<[u8; 32], IdempotencyRecord>,
}

impl InMemoryIdempotencyStore {
    pub fn new() -> Self {
        Self {
            inner: dashmap::DashMap::new(),
        }
    }
}

impl Default for InMemoryIdempotencyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl IdempotencyStore for InMemoryIdempotencyStore {
    fn lookup(&self, key: &IdempotencyKey) -> Result<Option<IdempotencyRecord>> {
        Ok(self.inner.get(&key.0).map(|r| r.value().clone()))
    }

    fn record(&self, record: IdempotencyRecord) -> Result<()> {
        let key = match hex::decode(&record.key_hex) {
            Ok(b) if b.len() == 32 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&b);
                k
            }
            _ => {
                return Err(crate::error::WorkflowError::InvalidWorkflow(format!(
                    "idempotency key_hex is not a valid 32-byte hex string: {}",
                    record.key_hex
                )));
            }
        };
        // First-write-wins: never overwrite an existing record (that
        // would defeat the purpose of the dedup).
        self.inner.entry(key).or_insert(record);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic() {
        let k1 = IdempotencyKey::derive(b"wf1", b"step1", b"did:tn:human:alice", b"payload-hash");
        let k2 = IdempotencyKey::derive(b"wf1", b"step1", b"did:tn:human:alice", b"payload-hash");
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_differs_per_input() {
        let base = IdempotencyKey::derive(b"wf1", b"step1", b"alice", b"p");
        assert_ne!(
            base,
            IdempotencyKey::derive(b"wf2", b"step1", b"alice", b"p")
        );
        assert_ne!(
            base,
            IdempotencyKey::derive(b"wf1", b"step2", b"alice", b"p")
        );
        assert_ne!(
            base,
            IdempotencyKey::derive(b"wf1", b"step1", b"bob", b"p")
        );
        assert_ne!(
            base,
            IdempotencyKey::derive(b"wf1", b"step1", b"alice", b"different")
        );
    }

    #[test]
    fn in_memory_store_first_write_wins() {
        let store = InMemoryIdempotencyStore::new();
        let key = IdempotencyKey::derive(b"w", b"s", b"c", b"p");
        assert!(store.lookup(&key).unwrap().is_none());

        let r1 = IdempotencyRecord {
            key_hex: key.to_hex(),
            workflow_id_hex: hex::encode(b"w"),
            step_id_hex: hex::encode(b"s"),
            result_hash: [1u8; 32],
            executed_at_ms: 1000,
        };
        store.record(r1.clone()).unwrap();

        let got = store.lookup(&key).unwrap().unwrap();
        assert_eq!(got.result_hash, [1u8; 32]);

        // Second record with same key MUST NOT overwrite the first.
        let r2 = IdempotencyRecord {
            key_hex: key.to_hex(),
            workflow_id_hex: hex::encode(b"w"),
            step_id_hex: hex::encode(b"s"),
            result_hash: [2u8; 32],
            executed_at_ms: 2000,
        };
        store.record(r2).unwrap();

        let got2 = store.lookup(&key).unwrap().unwrap();
        assert_eq!(got2.result_hash, [1u8; 32], "first-write-wins must hold");
        assert_eq!(got2.executed_at_ms, 1000);
    }

    #[test]
    fn record_rejects_malformed_hex_key() {
        let store = InMemoryIdempotencyStore::new();
        let bad = IdempotencyRecord {
            key_hex: "not-hex".into(),
            workflow_id_hex: "00".into(),
            step_id_hex: "00".into(),
            result_hash: [0u8; 32],
            executed_at_ms: 1000,
        };
        assert!(store.record(bad).is_err());
    }
}
