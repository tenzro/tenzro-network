//! Challenge storage for payment protocols
//!
//! Provides a shared challenge store used by both MPP and x402 servers
//! to store challenges on creation and look them up during settlement.

use crate::error::{PaymentError, Result};
use crate::types::PaymentChallenge;
use chrono::Utc;
use dashmap::DashMap;
use std::sync::Arc;
use tenzro_storage::kv::{CF_CHANNELS, KvStore};
use tracing::{debug, info, warn};

/// Key prefix for challenges in CF_CHANNELS
const CHALLENGE_KEY_PREFIX: &str = "challenge:";

/// Thread-safe challenge store for payment protocols with optional
/// RocksDB persistence.
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
    /// Challenge ids with a verification or settlement in flight. A challenge
    /// is claimed before its credential is verified and stays claimed until
    /// it is either consumed (settled) or released (verification failed), so
    /// two concurrent submissions of one credential cannot both settle.
    claims: Arc<DashMap<String, ()>>,
    /// Optional persistent storage
    storage: Option<Arc<dyn KvStore>>,
}

/// Upper bound on live challenges held by one store. Minting is open, so the
/// store refuses new challenges past this bound (after sweeping expired ones)
/// rather than growing without limit.
pub const MAX_LIVE_CHALLENGES: usize = 100_000;

impl ChallengeStore {
    /// Creates a new empty challenge store (in-memory only)
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(DashMap::new()),
            claims: Arc::new(DashMap::new()),
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
            claims: Arc::new(DashMap::new()),
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
                        warn!(
                            "Failed to persist challenge {}: {}",
                            challenge.challenge_id, e
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to serialize challenge {}: {}",
                        challenge.challenge_id, e
                    );
                }
            }
        }
    }

    /// Removes a challenge from persistent storage
    fn delete_from_storage(&self, challenge_id: &str) {
        if let Some(ref store) = self.storage {
            let key = format!("{}{}", CHALLENGE_KEY_PREFIX, challenge_id);
            if let Err(e) = store.delete(CF_CHANNELS, key.as_bytes()) {
                warn!(
                    "Failed to delete challenge {} from storage: {}",
                    challenge_id, e
                );
            }
        }
    }

    /// Stores a newly minted challenge for later lookup.
    ///
    /// Refuses once [`MAX_LIVE_CHALLENGES`] unexpired challenges are held,
    /// after first sweeping expired ones.
    pub fn store(&self, challenge: &PaymentChallenge) -> Result<()> {
        if self.challenges.len() >= MAX_LIVE_CHALLENGES {
            self.cleanup_expired();
            if self.challenges.len() >= MAX_LIVE_CHALLENGES {
                return Err(PaymentError::ChallengeError(format!(
                    "challenge store is full ({} live challenges); retry after some expire",
                    MAX_LIVE_CHALLENGES
                )));
            }
        }
        debug!("Storing challenge: {}", challenge.challenge_id);
        self.persist_challenge(challenge);
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
        Ok(())
    }

    /// Claim a challenge for verification and settlement.
    ///
    /// Atomic: of any number of concurrent callers presenting the same
    /// challenge id, exactly one gets the challenge back; the rest get an
    /// error until the winner either [`consume`](Self::consume)s it (it was
    /// settled, so it is gone) or [`release`](Self::release)s it (its
    /// credential failed, so another credential may try).
    pub fn claim(&self, challenge_id: &str) -> Result<PaymentChallenge> {
        let challenge = self.get(challenge_id)?;
        if challenge.expires_at <= Utc::now() {
            return Err(PaymentError::ChallengeError(format!(
                "Challenge {} has expired",
                challenge_id
            )));
        }
        match self.claims.entry(challenge_id.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(_) => Err(PaymentError::ReplayDetected(
                format!("Challenge {} is already being settled", challenge_id),
            )),
            dashmap::mapref::entry::Entry::Vacant(v) => {
                v.insert(());
                // Re-read under the claim: a settlement that finished between
                // `get` and the claim removed the challenge.
                match self.get(challenge_id) {
                    Ok(c) => Ok(c),
                    Err(e) => {
                        self.claims.remove(challenge_id);
                        Err(e)
                    }
                }
            }
        }
    }

    /// Release a claim without settling, so the challenge can be paid by a
    /// valid credential later.
    pub fn release(&self, challenge_id: &str) {
        self.claims.remove(challenge_id);
    }

    /// Consume a claimed challenge: it has been settled and can never be
    /// presented again.
    pub fn consume(&self, challenge_id: &str) {
        self.remove(challenge_id);
        self.claims.remove(challenge_id);
    }

    /// Retrieves a challenge by ID
    pub fn get(&self, challenge_id: &str) -> Result<PaymentChallenge> {
        self.challenges
            .get(challenge_id)
            .map(|c| c.clone())
            .ok_or_else(|| {
                PaymentError::ChallengeError(format!("Challenge not found: {}", challenge_id))
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
        store.store(&challenge).unwrap();

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
        store.store(&challenge).unwrap();

        let removed = store.remove("ch-2");
        assert!(removed.is_some());
        assert!(store.get("ch-2").is_err());
    }

    #[test]
    fn test_cleanup_expired() {
        let store = ChallengeStore::new();
        store.store(&make_challenge("fresh", 100, 5)).unwrap();
        store.store(&make_challenge("expired", 200, -1)).unwrap();

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

        store1.store(&make_challenge("shared", 100, 5)).unwrap();
        assert!(store2.get("shared").is_ok());
    }

    #[test]
    fn a_claimed_challenge_cannot_be_claimed_again() {
        let store = ChallengeStore::new();
        store.store(&make_challenge("c", 100, 5)).unwrap();
        assert!(store.claim("c").is_ok());
        assert!(matches!(
            store.claim("c"),
            Err(PaymentError::ReplayDetected(_))
        ));
    }

    #[test]
    fn a_released_claim_can_be_claimed_again() {
        let store = ChallengeStore::new();
        store.store(&make_challenge("c", 100, 5)).unwrap();
        store.claim("c").unwrap();
        store.release("c");
        assert!(store.claim("c").is_ok());
    }

    #[test]
    fn a_consumed_challenge_is_gone_for_good() {
        let store = ChallengeStore::new();
        store.store(&make_challenge("c", 100, 5)).unwrap();
        store.claim("c").unwrap();
        store.consume("c");
        assert!(store.claim("c").is_err());
        assert!(store.get("c").is_err());
    }

    #[test]
    fn an_expired_challenge_cannot_be_claimed() {
        let store = ChallengeStore::new();
        store.store(&make_challenge("old", 100, -1)).unwrap();
        assert!(store.claim("old").is_err());
    }

    #[test]
    fn concurrent_claims_admit_exactly_one_winner() {
        let store = ChallengeStore::new();
        store.store(&make_challenge("race", 100, 5)).unwrap();
        let wins = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let handles: Vec<_> = (0..32)
            .map(|_| {
                let s = store.clone();
                let w = wins.clone();
                std::thread::spawn(move || {
                    if s.claim("race").is_ok() {
                        w.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(wins.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
