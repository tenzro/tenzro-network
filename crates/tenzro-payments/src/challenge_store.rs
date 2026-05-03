//! Challenge storage for payment protocols
//!
//! Provides a shared challenge store used by both MPP and x402 servers
//! to store challenges on creation and look them up during settlement.

use crate::error::{PaymentError, Result};
use crate::types::PaymentChallenge;
use chrono::Utc;
use dashmap::DashMap;
use std::sync::Arc;
use tenzro_storage::kv::{KvStore, CF_CHANNELS};
use tracing::{debug, info, warn};

/// Key prefix for challenges in CF_CHANNELS
const CHALLENGE_KEY_PREFIX: &str = "challenge:";

/// Thread-safe challenge store for payment protocols with optional
/// RocksDB persistence (MEDIUM #127).
///
/// Both MPP and x402 servers use this to:
/// 1. Store challenges when they are created
/// 2. Look up challenges during credential verification and settlement
/// 3. Clean up expired challenges
///
/// When constructed with `with_storage()`, every mutation is written through
/// to `CF_CHANNELS` and all existing challenges are hydrated on startup.
#[derive(Clone)]
pub struct ChallengeStore {
    challenges: Arc<DashMap<String, PaymentChallenge>>,
    /// Optional persistent storage
    storage: Option<Arc<dyn KvStore>>,
}

impl ChallengeStore {
    /// Creates a new empty challenge store (in-memory only)
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(DashMap::new()),
            storage: None,
        }
    }

    /// Creates a challenge store backed by persistent storage.
    ///
    /// On construction, hydrates all existing challenges from `CF_CHANNELS`
    /// using the `challenge:` key prefix. Expired challenges are skipped
    /// during hydration. Every subsequent store/remove is written through.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        let challenges = Arc::new(DashMap::new());
        let now = Utc::now();

        match storage.get_keys_with_prefix(CF_CHANNELS, CHALLENGE_KEY_PREFIX.as_bytes()) {
            Ok(keys) => {
                let mut loaded = 0usize;
                let mut expired = 0usize;
                for key in &keys {
                    if let Ok(Some(bytes)) = storage.get(CF_CHANNELS, key) {
                        match serde_json::from_slice::<PaymentChallenge>(&bytes) {
                            Ok(challenge) => {
                                if challenge.expires_at > now {
                                    challenges.insert(challenge.challenge_id.clone(), challenge);
                                    loaded += 1;
                                } else {
                                    expired += 1;
                                    // Clean up expired entry from storage
                                    let _ = storage.delete(CF_CHANNELS, key);
                                }
                            }
                            Err(e) => {
                                warn!("Failed to deserialize challenge from storage: {}", e);
                            }
                        }
                    }
                }
                if loaded > 0 || expired > 0 {
                    info!(
                        "Loaded {} challenges from storage ({} expired entries cleaned)",
                        loaded, expired
                    );
                }
            }
            Err(e) => {
                warn!("Failed to load challenges from storage: {}", e);
            }
        }

        Self {
            challenges,
            storage: Some(storage),
        }
    }

    /// Persists a challenge to storage (write-through)
    fn persist_challenge(&self, challenge: &PaymentChallenge) {
        if let Some(ref store) = self.storage {
            let key = format!("{}{}", CHALLENGE_KEY_PREFIX, challenge.challenge_id);
            match serde_json::to_vec(challenge) {
                Ok(bytes) => {
                    if let Err(e) = store.put(CF_CHANNELS, key.as_bytes(), &bytes) {
                        warn!("Failed to persist challenge {}: {}", challenge.challenge_id, e);
                    }
                }
                Err(e) => {
                    warn!("Failed to serialize challenge {}: {}", challenge.challenge_id, e);
                }
            }
        }
    }

    /// Removes a challenge from persistent storage
    fn delete_from_storage(&self, challenge_id: &str) {
        if let Some(ref store) = self.storage {
            let key = format!("{}{}", CHALLENGE_KEY_PREFIX, challenge_id);
            if let Err(e) = store.delete(CF_CHANNELS, key.as_bytes()) {
                warn!("Failed to delete challenge {} from storage: {}", challenge_id, e);
            }
        }
    }

    /// Stores a challenge for later lookup
    pub fn store(&self, challenge: &PaymentChallenge) {
        debug!("Storing challenge: {}", challenge.challenge_id);
        self.persist_challenge(challenge);
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
    }

    /// Retrieves a challenge by ID
    pub fn get(&self, challenge_id: &str) -> Result<PaymentChallenge> {
        self.challenges
            .get(challenge_id)
            .map(|c| c.clone())
            .ok_or_else(|| {
                PaymentError::ChallengeError(format!(
                    "Challenge not found: {}",
                    challenge_id
                ))
            })
    }

    /// Removes a challenge (e.g., after settlement)
    pub fn remove(&self, challenge_id: &str) -> Option<PaymentChallenge> {
        let removed = self.challenges.remove(challenge_id).map(|(_, c)| c);
        if removed.is_some() {
            self.delete_from_storage(challenge_id);
        }
        removed
    }

    /// Removes all expired challenges, returns count removed
    pub fn cleanup_expired(&self) -> usize {
        let now = Utc::now();
        let before = self.challenges.len();
        // Collect expired IDs first to delete from storage
        let expired_ids: Vec<String> = self
            .challenges
            .iter()
            .filter(|entry| entry.value().expires_at <= now)
            .map(|entry| entry.key().clone())
            .collect();
        for id in &expired_ids {
            self.delete_from_storage(id);
        }
        self.challenges.retain(|_, c| c.expires_at > now);
        let removed = before - self.challenges.len();
        if removed > 0 {
            info!("Cleaned up {} expired challenges", removed);
        }
        removed
    }

    /// Returns the number of stored challenges
    pub fn len(&self) -> usize {
        self.challenges.len()
    }

    /// Returns true if no challenges stored
    pub fn is_empty(&self) -> bool {
        self.challenges.is_empty()
    }
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_challenge(id: &str, amount: u128, minutes_until_expiry: i64) -> PaymentChallenge {
        PaymentChallenge {
            challenge_id: id.to_string(),
            protocol: "mpp".to_string(),
            resource: "/api/test".to_string(),
            amount,
            asset: "USDC".to_string(),
            recipient: "0xrecipient".to_string(),
            chain: "tempo".to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(minutes_until_expiry),
            extra: HashMap::new(),
        }
    }

    #[test]
    fn test_store_and_get() {
        let store = ChallengeStore::new();
        let challenge = make_challenge("ch-1", 1000, 5);
        store.store(&challenge);

        let retrieved = store.get("ch-1").unwrap();
        assert_eq!(retrieved.challenge_id, "ch-1");
        assert_eq!(retrieved.amount, 1000);
    }

    #[test]
    fn test_get_missing() {
        let store = ChallengeStore::new();
        assert!(store.get("nonexistent").is_err());
    }

    #[test]
    fn test_remove() {
        let store = ChallengeStore::new();
        let challenge = make_challenge("ch-2", 500, 5);
        store.store(&challenge);

        let removed = store.remove("ch-2");
        assert!(removed.is_some());
        assert!(store.get("ch-2").is_err());
    }

    #[test]
    fn test_cleanup_expired() {
        let store = ChallengeStore::new();
        store.store(&make_challenge("fresh", 100, 5));
        store.store(&make_challenge("expired", 200, -1));

        assert_eq!(store.len(), 2);
        let removed = store.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(store.len(), 1);
        assert!(store.get("fresh").is_ok());
        assert!(store.get("expired").is_err());
    }

    #[test]
    fn test_clone_shares_state() {
        let store1 = ChallengeStore::new();
        let store2 = store1.clone();

        store1.store(&make_challenge("shared", 100, 5));
        assert!(store2.get("shared").is_ok());
    }
}
