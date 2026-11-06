//! Verifier-issued, single-use attestation nonces.
//!
//! A report proves freshness only by answering a challenge the verifier chose
//! after the fact. The issuer hands out random 32-byte nonces, remembers each
//! one with its purpose and an expiry, and accepts it back exactly once.
//! Replaying a report means replaying a consumed or expired nonce, which is
//! refused.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rand::RngCore;

use crate::error::{Result, TeeError};

/// Outstanding nonces are capped so an unauthenticated caller cannot grow the
/// table without bound; the oldest are evicted first.
const MAX_OUTSTANDING: usize = 10_000;

struct Issued {
    purpose: String,
    expires: Instant,
}

/// Issues and redeems attestation nonces.
pub struct NonceIssuer {
    ttl: Duration,
    issued: Mutex<HashMap<[u8; 32], Issued>>,
}

impl NonceIssuer {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            issued: Mutex::new(HashMap::new()),
        }
    }

    /// A fresh nonce for `purpose`, valid until the issuer's TTL elapses.
    pub fn issue(&self, purpose: &str) -> Result<[u8; 32]> {
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|e| TeeError::CryptoError(format!("OS RNG failed: {e}")))?;
        let now = Instant::now();
        let mut issued = self.issued.lock();
        issued.retain(|_, v| v.expires > now);
        if issued.len() >= MAX_OUTSTANDING
            && let Some(oldest) = issued
                .iter()
                .min_by_key(|(_, v)| v.expires)
                .map(|(k, _)| *k)
        {
            issued.remove(&oldest);
        }
        issued.insert(
            nonce,
            Issued {
                purpose: purpose.to_string(),
                expires: now + self.ttl,
            },
        );
        Ok(nonce)
    }

    /// Redeem `nonce` for `purpose`. True exactly once per issued nonce, and
    /// only before it expires and only for the purpose it was issued for.
    pub fn redeem(&self, nonce: &[u8; 32], purpose: &str) -> bool {
        let mut issued = self.issued.lock();
        match issued.remove(nonce) {
            Some(i) => i.purpose == purpose && i.expires > Instant::now(),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonce_redeems_once() {
        let n = NonceIssuer::new(Duration::from_secs(60));
        let a = n.issue("admission").unwrap();
        assert!(n.redeem(&a, "admission"));
        assert!(
            !n.redeem(&a, "admission"),
            "a replayed nonce must be refused"
        );
    }

    #[test]
    fn a_nonce_for_another_purpose_is_refused() {
        let n = NonceIssuer::new(Duration::from_secs(60));
        let a = n.issue("admission").unwrap();
        assert!(!n.redeem(&a, "settlement"));
        assert!(
            !n.redeem(&a, "admission"),
            "a wrong-purpose attempt consumes the nonce"
        );
    }

    #[test]
    fn an_expired_or_unknown_nonce_is_refused() {
        let n = NonceIssuer::new(Duration::from_millis(0));
        let a = n.issue("x").unwrap();
        assert!(!n.redeem(&a, "x"));
        assert!(!n.redeem(&[7; 32], "x"));
    }
}
