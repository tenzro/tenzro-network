//! Secure-Mint registry — 1:1 reserve-attestation binding for tokenized
//! assets on Tenzro EVM.
//!
//! Tokenized equities, treasuries, and other RWA-class assets require
//! that the on-chain circulating supply never exceed the attested
//! off-chain reserve. This module records, per-token, the latest
//! `(reserve, circulating, feed)` triple and exposes a single
//! `check_mint(token, amount)` invariant the EVM mint path consults via
//! the precompile at [`crate::precompiles::PRECOMPILE_SECURE_MINT`].

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use tenzro_types::primitives::{Address, Hash};

/// Errors raised by the Secure-Mint registry.
#[derive(Debug, Error)]
pub enum SecureMintError {
    /// The token has no Secure-Mint policy registered. Tokens without a
    /// policy are pass-through — the mint proceeds without a reserve
    /// check.
    #[error("token {0} has no Secure-Mint policy")]
    NotConfigured(String),

    /// The token's latest reserve attestation has expired (stale data).
    #[error("attestation expired: attested_at {attested_at}, now {now}, ttl {ttl_secs}")]
    AttestationExpired {
        /// Unix-seconds attestation timestamp.
        attested_at: u64,
        /// Current unix-seconds clock.
        now: u64,
        /// Allowed staleness window.
        ttl_secs: u64,
    },

    /// The mint would push `circulating + amount` above the attested
    /// `reserve`.
    #[error(
        "mint would exceed reserve: circulating {circulating}, requested {amount}, reserve {reserve}"
    )]
    ExceedsReserve {
        /// Current circulating supply.
        circulating: u128,
        /// Requested mint amount.
        amount: u128,
        /// Latest attested reserve.
        reserve: u128,
    },
}

/// Per-token Secure-Mint policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureMintPolicy {
    /// Asset class identifier (CAIP-19 string is the canonical form).
    pub asset_id: String,
    /// Latest attested reserve, smallest-unit u128.
    pub reserve: u128,
    /// Latest attested circulating supply on this chain.
    pub circulating: u128,
    /// PoR feed id. The format is opaque to the registry; canonical
    /// adapters are `chainlink:<feed_address>` and `tenzro:<attester_did>`.
    pub por_feed_id: String,
    /// DID of the attester who signed the last attestation.
    pub attester_did: String,
    /// Hash of the signed attestation payload.
    pub attestation_hash: Hash,
    /// Unix-seconds timestamp of the last attestation update.
    pub attested_at: u64,
    /// Maximum allowed staleness in seconds. `0` disables the check.
    pub ttl_secs: u64,
}

impl SecureMintPolicy {
    /// Whether the policy's attestation is still fresh per `now`.
    pub fn is_fresh(&self, now: u64) -> bool {
        self.ttl_secs == 0 || now.saturating_sub(self.attested_at) <= self.ttl_secs
    }
}

/// In-memory registry of Secure-Mint policies keyed by token address.
#[derive(Default)]
pub struct SecureMintRegistry {
    inner: RwLock<HashMap<[u8; 20], SecureMintPolicy>>,
    storage: Option<std::sync::Arc<dyn tenzro_storage::KvStore>>,
}

impl std::fmt::Debug for SecureMintRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureMintRegistry")
            .field("policies", &self.inner.read().len())
            .field("persistent", &self.storage.is_some())
            .finish()
    }
}

impl SecureMintRegistry {
    /// Build an empty registry (test-only; production should use
    /// `with_storage`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Production constructor: write-through to `CF_TOKENS` under
    /// `secure_mint:<token20>` with hydration on startup. Without
    /// persistence, every restart drops policies and either bricks
    /// reserve-backed assets (mint refuses with NotConfigured) or
    /// silently passes mints that should have failed if the operator
    /// set a more conservative `circulating` cap.
    pub fn with_storage(storage: std::sync::Arc<dyn tenzro_storage::KvStore>) -> Self {
        let r = Self {
            inner: RwLock::new(HashMap::new()),
            storage: Some(storage),
        };
        r.hydrate();
        r
    }

    fn key(token: &[u8; 20]) -> Vec<u8> {
        let mut k = b"secure_mint:".to_vec();
        k.extend_from_slice(token);
        k
    }

    fn hydrate(&self) {
        let Some(ref storage) = self.storage else {
            return;
        };
        let entries = match storage.scan_prefix(tenzro_storage::CF_TOKENS, b"secure_mint:") {
            Ok(e) => e,
            Err(_) => return,
        };
        let prefix_len = "secure_mint:".len();
        let mut map = self.inner.write();
        for (key, value) in entries {
            if key.len() < prefix_len + 20 {
                continue;
            }
            let mut token = [0u8; 20];
            token.copy_from_slice(&key[prefix_len..prefix_len + 20]);
            if let Ok(policy) = serde_json::from_slice::<SecureMintPolicy>(&value) {
                map.insert(token, policy);
            }
        }
    }

    fn persist(&self, token: &[u8; 20], policy: &SecureMintPolicy) {
        if let Some(ref storage) = self.storage {
            if let Ok(bytes) = serde_json::to_vec(policy) {
                let _ = storage.put(tenzro_storage::CF_TOKENS, &Self::key(token), &bytes);
            }
        }
    }

    fn forget(&self, token: &[u8; 20]) {
        if let Some(ref storage) = self.storage {
            let _ = storage.delete(tenzro_storage::CF_TOKENS, &Self::key(token));
        }
    }

    /// Install or refresh the policy for `token`. Returns the prior policy
    /// for downstream auditing if one existed.
    pub fn set_policy(
        &self,
        token: [u8; 20],
        policy: SecureMintPolicy,
    ) -> Option<SecureMintPolicy> {
        self.persist(&token, &policy);
        self.inner.write().insert(token, policy)
    }

    /// Drop the policy for `token`. Returns true if a policy was removed.
    pub fn clear(&self, token: &[u8; 20]) -> bool {
        let removed = self.inner.write().remove(token).is_some();
        if removed {
            self.forget(token);
        }
        removed
    }

    /// Snapshot the current policy for `token`.
    pub fn policy(&self, token: &[u8; 20]) -> Option<SecureMintPolicy> {
        self.inner.read().get(token).cloned()
    }

    /// Returns the active policy count.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Returns `true` iff no policy is installed.
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    /// Apply the Secure-Mint invariant: `circulating + amount ≤ reserve`.
    ///
    /// `now` is the current unix-seconds clock; the attestation must be
    /// fresh relative to its `ttl_secs`. On success, atomically increments
    /// `circulating` by `amount` and returns the resulting policy.
    pub fn check_and_mint(
        &self,
        token: &[u8; 20],
        amount: u128,
        now: u64,
    ) -> Result<SecureMintPolicy, SecureMintError> {
        let mut inner = self.inner.write();
        let policy = inner
            .get_mut(token)
            .ok_or_else(|| SecureMintError::NotConfigured(hex::encode(token)))?;
        if !policy.is_fresh(now) {
            return Err(SecureMintError::AttestationExpired {
                attested_at: policy.attested_at,
                now,
                ttl_secs: policy.ttl_secs,
            });
        }
        let new_circulating = policy
            .circulating
            .checked_add(amount)
            .ok_or(SecureMintError::ExceedsReserve {
                circulating: policy.circulating,
                amount,
                reserve: policy.reserve,
            })?;
        if new_circulating > policy.reserve {
            return Err(SecureMintError::ExceedsReserve {
                circulating: policy.circulating,
                amount,
                reserve: policy.reserve,
            });
        }
        policy.circulating = new_circulating;
        let snapshot = policy.clone();
        drop(inner);
        self.persist(token, &snapshot);
        Ok(snapshot)
    }

    /// Subtract `amount` from circulating supply on burn / redemption.
    /// Saturates at zero to guard against accounting errors but does not
    /// fail the operation.
    pub fn record_burn(&self, token: &[u8; 20], amount: u128) -> Option<SecureMintPolicy> {
        let mut inner = self.inner.write();
        let policy = inner.get_mut(token)?;
        policy.circulating = policy.circulating.saturating_sub(amount);
        let snapshot = policy.clone();
        drop(inner);
        self.persist(token, &snapshot);
        Some(snapshot)
    }

    /// Convenience read-only check (used by callers that want to know
    /// whether a mint would succeed without mutating state).
    pub fn would_mint_succeed(
        &self,
        token: &[u8; 20],
        amount: u128,
        now: u64,
    ) -> Result<(), SecureMintError> {
        let policy = self
            .policy(token)
            .ok_or_else(|| SecureMintError::NotConfigured(hex::encode(token)))?;
        if !policy.is_fresh(now) {
            return Err(SecureMintError::AttestationExpired {
                attested_at: policy.attested_at,
                now,
                ttl_secs: policy.ttl_secs,
            });
        }
        let new_circulating = policy
            .circulating
            .checked_add(amount)
            .ok_or(SecureMintError::ExceedsReserve {
                circulating: policy.circulating,
                amount,
                reserve: policy.reserve,
            })?;
        if new_circulating > policy.reserve {
            return Err(SecureMintError::ExceedsReserve {
                circulating: policy.circulating,
                amount,
                reserve: policy.reserve,
            });
        }
        Ok(())
    }
}

/// Optional tokenized-equity profile sidecar that can be attached to a
/// [`SecureMintPolicy`]. The registry itself stays asset-class-neutral
/// — equity-class profiles, treasury-class profiles, and stablecoin
/// profiles all share the same Secure-Mint invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenizedEquityProfile {
    /// CCT pool address on this chain (if bridged).
    pub cct_pool_address: Option<Address>,
    /// PoR feed id (mirrors `SecureMintPolicy::por_feed_id`).
    pub por_feed_id: String,
    /// Underlying CAIP-19 asset id of the reference equity.
    pub underlying_caip19: String,
    /// ISIN (12 chars) and CUSIP (9 chars) — empty when unset.
    pub isin: String,
    /// CUSIP code.
    pub cusip: String,
    /// Per-share ratio expressed as `(numerator, denominator)`.
    pub per_share_ratio: (u128, u128),
    /// Hash of the latest corporate-action event applied.
    pub last_corporate_action: Option<Hash>,
}

/// Shareable handle around a [`SecureMintRegistry`].
pub type SharedSecureMintRegistry = Arc<SecureMintRegistry>;

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with_reserve(reserve: u128) -> SecureMintPolicy {
        SecureMintPolicy {
            asset_id: "tenzro:539/erc20:0xtest".into(),
            reserve,
            circulating: 0,
            por_feed_id: "chainlink:0x0000".into(),
            attester_did: "did:tenzro:human:tester".into(),
            attestation_hash: Hash::default(),
            attested_at: 1_700_000_000,
            ttl_secs: 86_400,
        }
    }

    #[test]
    fn mint_within_reserve_succeeds() {
        let reg = SecureMintRegistry::new();
        let token = [1u8; 20];
        reg.set_policy(token, policy_with_reserve(1_000));
        let updated = reg.check_and_mint(&token, 600, 1_700_000_000).unwrap();
        assert_eq!(updated.circulating, 600);
        let updated2 = reg.check_and_mint(&token, 400, 1_700_000_000).unwrap();
        assert_eq!(updated2.circulating, 1_000);
    }

    #[test]
    fn mint_exceeding_reserve_rejected() {
        let reg = SecureMintRegistry::new();
        let token = [2u8; 20];
        reg.set_policy(token, policy_with_reserve(500));
        let err = reg.check_and_mint(&token, 501, 1_700_000_000).unwrap_err();
        assert!(matches!(err, SecureMintError::ExceedsReserve { .. }));
    }

    #[test]
    fn stale_attestation_rejected() {
        let reg = SecureMintRegistry::new();
        let token = [3u8; 20];
        let mut policy = policy_with_reserve(1_000);
        policy.ttl_secs = 60;
        reg.set_policy(token, policy);
        let err = reg.check_and_mint(&token, 1, 1_700_000_000 + 120).unwrap_err();
        assert!(matches!(err, SecureMintError::AttestationExpired { .. }));
    }

    #[test]
    fn burn_records_reduction() {
        let reg = SecureMintRegistry::new();
        let token = [4u8; 20];
        reg.set_policy(token, policy_with_reserve(1_000));
        reg.check_and_mint(&token, 800, 1_700_000_000).unwrap();
        let after = reg.record_burn(&token, 300).unwrap();
        assert_eq!(after.circulating, 500);
    }
}
