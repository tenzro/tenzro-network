//! Nonce cache for replay attack prevention
//!
//! Implements a time-based nonce cache that stores seen nonces and prevents their reuse
//! within a configurable time-to-live (TTL) window.

use crate::error::{PaymentError, Result};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use tracing::debug;

/// Nonce cache for preventing replay attacks
///
/// Stores nonces with timestamps and automatically rejects duplicate nonces
/// within the configured TTL window.
#[derive(Debug)]
pub struct NonceCache {
    /// Map of nonce -> timestamp of first observation
    nonces: DashMap<String, DateTime<Utc>>,
    /// Time-to-live for nonce entries in seconds
    ttl_secs: u64,
}

impl NonceCache {
    /// Create a new nonce cache with default TTL of 480 seconds (8 minutes)
    ///
    /// This matches the recommended nonce expiration time in RFC 9421.
    pub fn new() -> Self {
        Self {
            nonces: DashMap::new(),
            ttl_secs: 480,
        }
    }

    /// Create a new nonce cache with custom TTL
    ///
    /// # Arguments
    ///
    /// * `ttl_secs` - Time-to-live in seconds for nonce entries
    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            nonces: DashMap::new(),
            ttl_secs,
        }
    }

    /// Check if a nonce has been seen before and store it if not
    ///
    /// # Arguments
    ///
    /// * `nonce` - The nonce to check and store
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the nonce was not seen before (now stored)
    /// * `Err(PaymentError::ReplayDetected)` if the nonce was already seen within TTL
    pub fn check_and_store(&self, nonce: &str) -> Result<()> {
        // Cleanup expired first
        self.cleanup_expired();

        // Check if nonce already exists
        if self.nonces.contains_key(nonce) {
            debug!("Replay attack detected: nonce {} already seen", nonce);
            return Err(PaymentError::ReplayDetected(format!(
                "Nonce already used: {}",
                nonce
            )));
        }

        // Store nonce with current timestamp
        self.nonces.insert(nonce.to_string(), Utc::now());
        Ok(())
    }

    /// Clean up expired nonce entries
    ///
    /// Returns the number of entries removed.
    pub fn cleanup_expired(&self) -> usize {
        let now = Utc::now();
        let ttl_duration = chrono::Duration::seconds(self.ttl_secs as i64);
        let mut removed = 0;

        // Collect expired keys first to avoid holding locks during iteration
        let expired_keys: Vec<String> = self.nonces
            .iter()
            .filter_map(|entry| {
                let timestamp = *entry.value();
                if now.signed_duration_since(timestamp) > ttl_duration {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();

        // Remove expired entries
        for key in expired_keys {
            if self.nonces.remove(&key).is_some() {
                removed += 1;
            }
        }

        if removed > 0 {
            debug!("Cleaned up {} expired nonce entries", removed);
        }

        removed
    }

    /// Get the number of nonces currently cached
    pub fn len(&self) -> usize {
        self.nonces.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.nonces.is_empty()
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_new_cache() {
        let cache = NonceCache::new();
        assert_eq!(cache.ttl_secs, 480);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_custom_ttl() {
        let cache = NonceCache::with_ttl(300);
        assert_eq!(cache.ttl_secs, 300);
    }

    #[test]
    fn test_check_and_store_new_nonce() {
        let cache = NonceCache::new();
        let result = cache.check_and_store("nonce-123");
        assert!(result.is_ok());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_check_and_store_duplicate_nonce() {
        let cache = NonceCache::new();

        // First use should succeed
        let result1 = cache.check_and_store("nonce-456");
        assert!(result1.is_ok());

        // Second use should fail with replay error
        let result2 = cache.check_and_store("nonce-456");
        assert!(result2.is_err());
        assert!(matches!(result2, Err(PaymentError::ReplayDetected(_))));
    }

    #[test]
    fn test_multiple_different_nonces() {
        let cache = NonceCache::new();

        assert!(cache.check_and_store("nonce-1").is_ok());
        assert!(cache.check_and_store("nonce-2").is_ok());
        assert!(cache.check_and_store("nonce-3").is_ok());

        assert_eq!(cache.len(), 3);

        // Duplicates should fail
        assert!(cache.check_and_store("nonce-1").is_err());
        assert!(cache.check_and_store("nonce-2").is_err());
    }

    #[test]
    fn test_cleanup_expired() {
        let cache = NonceCache::with_ttl(1); // 1 second TTL

        // Add some nonces
        cache.check_and_store("nonce-old-1").unwrap();
        cache.check_and_store("nonce-old-2").unwrap();
        assert_eq!(cache.len(), 2);

        // Wait for expiration
        thread::sleep(Duration::from_secs(2));

        // Manually call cleanup (this should remove the 2 expired nonces)
        let removed = cache.cleanup_expired();
        assert_eq!(removed, 2);
        assert_eq!(cache.len(), 0);

        // Add a fresh nonce after cleanup
        cache.check_and_store("nonce-fresh").unwrap();
        assert_eq!(cache.len(), 1);

        // Fresh nonce should still be present (replay should fail)
        assert!(cache.check_and_store("nonce-fresh").is_err());
    }

    #[test]
    fn test_cleanup_no_expired() {
        let cache = NonceCache::new();

        cache.check_and_store("nonce-1").unwrap();
        cache.check_and_store("nonce-2").unwrap();

        // Cleanup immediately should not remove anything
        let removed = cache.cleanup_expired();
        assert_eq!(removed, 0);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_default_cache() {
        let cache = NonceCache::default();
        assert_eq!(cache.ttl_secs, 480);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;

        let cache = Arc::new(NonceCache::new());
        let mut handles = vec![];

        // Spawn multiple threads adding nonces
        for i in 0..10 {
            let cache_clone = Arc::clone(&cache);
            let handle = thread::spawn(move || {
                for j in 0..10 {
                    let nonce = format!("nonce-{}-{}", i, j);
                    let _ = cache_clone.check_and_store(&nonce);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Should have 100 unique nonces
        assert_eq!(cache.len(), 100);
    }
}
