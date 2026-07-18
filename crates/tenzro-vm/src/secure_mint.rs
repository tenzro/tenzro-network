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

    /// The proof-of-reserve feed has not refreshed within its heartbeat
    /// window. Distinct from `AttestationExpired`: a feed can be inside its
    /// attestation TTL yet frozen (the classic stale-oracle infinite-mint
    /// vector), so mint authority gates on feed liveness independently.
    #[error("PoR feed stale: last update {attested_at}, now {now}, heartbeat {heartbeat_secs}")]
    FeedStale {
        /// Unix-seconds of the last feed update.
        attested_at: u64,
        /// Current unix-seconds clock.
        now: u64,
        /// Allowed feed-liveness window.
        heartbeat_secs: u64,
    },

    /// Issuance is paused for this token (circuit breaker). No mint may
    /// proceed until an operator clears the pause.
    #[error("issuance paused for token {0}")]
    Paused(String),

    /// The mint would exceed the per-window velocity cap.
    #[error(
        "mint exceeds velocity cap: window-minted {window_minted}, requested {amount}, cap {cap}"
    )]
    VelocityExceeded {
        /// Amount already minted in the current window.
        window_minted: u128,
        /// Requested mint amount.
        amount: u128,
        /// Per-window cap.
        cap: u128,
    },

    /// A redeem/burn would exceed the circulating supply — a desync or
    /// double-burn. Bounded rather than silently saturated so accounting
    /// errors surface instead of masking reserve drift.
    #[error("redeem exceeds circulating: circulating {circulating}, requested {amount}")]
    ExceedsCirculating {
        /// Current circulating supply.
        circulating: u128,
        /// Requested burn amount.
        amount: u128,
    },

    /// A corporate-action supply scale had a zero term or overflowed u128.
    #[error("invalid supply scale: num {num}, den {den}")]
    InvalidScale {
        /// Scale numerator.
        num: u32,
        /// Scale denominator.
        den: u32,
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
    /// PoR feed-liveness window in seconds. A mint is refused when the feed
    /// has not refreshed within this window, even if the attestation is
    /// inside its `ttl_secs`. `0` disables the check.
    #[serde(default)]
    pub heartbeat_secs: u64,
    /// Per-window mint velocity cap (smallest units). `0` disables the cap.
    /// Bounds how fast supply can ramp independent of the reserve floor — a
    /// debt-ceiling-style guard against a rapid legitimate-looking mint.
    #[serde(default)]
    pub mint_window_cap: u128,
    /// Length of the velocity window in seconds. Required when
    /// `mint_window_cap > 0`.
    #[serde(default)]
    pub mint_window_secs: u64,
    /// Amount minted in the current velocity window (running tally).
    #[serde(default)]
    pub window_minted: u128,
    /// Unix-seconds start of the current velocity window.
    #[serde(default)]
    pub window_started_at: u64,
    /// Circuit breaker: when true, no mint proceeds until cleared.
    #[serde(default)]
    pub paused: bool,
}

impl SecureMintPolicy {
    /// Whether the policy's attestation is still fresh per `now`.
    pub fn is_fresh(&self, now: u64) -> bool {
        self.ttl_secs == 0 || now.saturating_sub(self.attested_at) <= self.ttl_secs
    }

    /// Whether the PoR feed is live per its heartbeat window.
    pub fn feed_live(&self, now: u64) -> bool {
        self.heartbeat_secs == 0 || now.saturating_sub(self.attested_at) <= self.heartbeat_secs
    }
}

/// In-memory registry of Secure-Mint policies keyed by token address.
#[derive(Default)]
pub struct SecureMintRegistry {
    inner: RwLock<HashMap<[u8; 20], SecureMintPolicy>>,
    storage: Option<std::sync::Arc<dyn tenzro_storage::KvStore>>,
    /// Global issuance circuit breaker. Trips all tokens at once for
    /// incident response; not persisted (a restart clears it deliberately,
    /// so a node never boots wedged on a forgotten pause).
    global_pause: std::sync::atomic::AtomicBool,
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
            global_pause: std::sync::atomic::AtomicBool::new(false),
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
        if let Some(ref storage) = self.storage
            && let Ok(bytes) = serde_json::to_vec(policy)
        {
            let _ = storage.put(tenzro_storage::CF_TOKENS, &Self::key(token), &bytes);
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

    /// Run every pre-mint gate against a snapshot, returning the velocity
    /// tally that would apply at `now`. Shared by `check_and_mint` (which
    /// then commits) and `would_mint_succeed` (which does not) so the two
    /// can never drift. `global_pause` short-circuits all tokens.
    fn evaluate_mint(
        policy: &SecureMintPolicy,
        amount: u128,
        now: u64,
        token: &[u8; 20],
        global_pause: bool,
    ) -> Result<u128, SecureMintError> {
        if global_pause || policy.paused {
            return Err(SecureMintError::Paused(hex::encode(token)));
        }
        if !policy.is_fresh(now) {
            return Err(SecureMintError::AttestationExpired {
                attested_at: policy.attested_at,
                now,
                ttl_secs: policy.ttl_secs,
            });
        }
        if !policy.feed_live(now) {
            return Err(SecureMintError::FeedStale {
                attested_at: policy.attested_at,
                now,
                heartbeat_secs: policy.heartbeat_secs,
            });
        }
        // Velocity cap. A window older than `mint_window_secs` has rolled
        // over, so the tally resets to zero before this mint is counted.
        let window_minted = if policy.mint_window_cap == 0 {
            0
        } else {
            let rolled = policy.mint_window_secs > 0
                && now.saturating_sub(policy.window_started_at) >= policy.mint_window_secs;
            let base = if rolled { 0 } else { policy.window_minted };
            let next = base.checked_add(amount).ok_or(SecureMintError::VelocityExceeded {
                window_minted: base,
                amount,
                cap: policy.mint_window_cap,
            })?;
            if next > policy.mint_window_cap {
                return Err(SecureMintError::VelocityExceeded {
                    window_minted: base,
                    amount,
                    cap: policy.mint_window_cap,
                });
            }
            next
        };
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
        Ok(window_minted)
    }

    /// Apply the full Secure-Mint gate, in order: circuit breaker →
    /// attestation freshness → PoR feed liveness → velocity cap → reserve
    /// floor (`circulating + amount ≤ reserve`). On success, atomically
    /// increments `circulating` (and the velocity tally) and returns the
    /// resulting policy. A token with no policy hard-fails with
    /// `NotConfigured` — mint is fail-closed, never pass-through.
    pub fn check_and_mint(
        &self,
        token: &[u8; 20],
        amount: u128,
        now: u64,
    ) -> Result<SecureMintPolicy, SecureMintError> {
        let global_pause = self.global_pause.load(std::sync::atomic::Ordering::Relaxed);
        let mut inner = self.inner.write();
        let policy = inner
            .get_mut(token)
            .ok_or_else(|| SecureMintError::NotConfigured(hex::encode(token)))?;
        let window_minted = Self::evaluate_mint(policy, amount, now, token, global_pause)?;
        policy.circulating += amount;
        if policy.mint_window_cap > 0 {
            // Restart the window at `now` when it rolled over or was empty.
            if (window_minted == amount && policy.window_minted != 0)
                || policy.window_minted == 0
            {
                policy.window_started_at = now;
            }
            policy.window_minted = window_minted;
        }
        let snapshot = policy.clone();
        drop(inner);
        self.persist(token, &snapshot);
        Ok(snapshot)
    }

    /// Subtract `amount` from circulating supply on burn / redemption.
    /// Bounded: a burn exceeding circulating is rejected with
    /// `ExceedsCirculating` rather than silently saturated, so a desync or
    /// double-burn surfaces instead of masking reserve drift.
    pub fn record_burn(
        &self,
        token: &[u8; 20],
        amount: u128,
    ) -> Result<SecureMintPolicy, SecureMintError> {
        let mut inner = self.inner.write();
        let policy = inner
            .get_mut(token)
            .ok_or_else(|| SecureMintError::NotConfigured(hex::encode(token)))?;
        if amount > policy.circulating {
            return Err(SecureMintError::ExceedsCirculating {
                circulating: policy.circulating,
                amount,
            });
        }
        policy.circulating -= amount;
        let snapshot = policy.clone();
        drop(inner);
        self.persist(token, &snapshot);
        Ok(snapshot)
    }

    /// Set or clear the circuit breaker for a single token. Returns the
    /// updated policy, or `None` if the token has no policy.
    pub fn set_paused(&self, token: &[u8; 20], paused: bool) -> Option<SecureMintPolicy> {
        let mut inner = self.inner.write();
        let policy = inner.get_mut(token)?;
        policy.paused = paused;
        let snapshot = policy.clone();
        drop(inner);
        self.persist(token, &snapshot);
        Some(snapshot)
    }

    /// Set or clear the global issuance circuit breaker. When set, every
    /// token's mint is refused regardless of per-token state.
    pub fn set_global_pause(&self, paused: bool) {
        self.global_pause
            .store(paused, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether global issuance is currently paused.
    pub fn global_paused(&self) -> bool {
        self.global_pause.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Scale `circulating` and `reserve` by `num/den` for a stock split
    /// (called by the corporate-action engine, never directly by mint).
    /// Rounding is adversarial to the issuer: circulating rounds up
    /// (supply is never under-counted), reserve rounds down (backing is
    /// never over-credited). A post-scale `circulating > reserve` rejects
    /// with `ExceedsReserve` and leaves the policy untouched. The velocity
    /// tally and cap scale the same way (tally up, cap down) so a split
    /// never widens the remaining window headroom.
    pub fn apply_supply_scale(
        &self,
        token: &[u8; 20],
        num: u32,
        den: u32,
    ) -> Result<SecureMintPolicy, SecureMintError> {
        if num == 0 || den == 0 {
            return Err(SecureMintError::InvalidScale { num, den });
        }
        let scale_up = |v: u128| -> Result<u128, SecureMintError> {
            v.checked_mul(num as u128)
                .and_then(|x| x.checked_add(den as u128 - 1))
                .map(|x| x / den as u128)
                .ok_or(SecureMintError::InvalidScale { num, den })
        };
        let scale_down = |v: u128| -> Result<u128, SecureMintError> {
            v.checked_mul(num as u128)
                .map(|x| x / den as u128)
                .ok_or(SecureMintError::InvalidScale { num, den })
        };
        let mut inner = self.inner.write();
        let policy = inner
            .get_mut(token)
            .ok_or_else(|| SecureMintError::NotConfigured(hex::encode(token)))?;
        let new_circulating = scale_up(policy.circulating)?;
        let new_reserve = scale_down(policy.reserve)?;
        let new_window_minted = scale_up(policy.window_minted)?;
        let new_window_cap = scale_down(policy.mint_window_cap)?;
        if new_circulating > new_reserve {
            return Err(SecureMintError::ExceedsReserve {
                circulating: new_circulating,
                amount: 0,
                reserve: new_reserve,
            });
        }
        policy.circulating = new_circulating;
        policy.reserve = new_reserve;
        policy.window_minted = new_window_minted;
        policy.mint_window_cap = new_window_cap;
        let snapshot = policy.clone();
        drop(inner);
        self.persist(token, &snapshot);
        Ok(snapshot)
    }

    /// Convenience read-only check (used by callers that want to know
    /// whether a mint would succeed without mutating state).
    pub fn would_mint_succeed(
        &self,
        token: &[u8; 20],
        amount: u128,
        now: u64,
    ) -> Result<(), SecureMintError> {
        let global_pause = self.global_pause.load(std::sync::atomic::Ordering::Relaxed);
        let policy = self
            .policy(token)
            .ok_or_else(|| SecureMintError::NotConfigured(hex::encode(token)))?;
        Self::evaluate_mint(&policy, amount, now, token, global_pause).map(|_| ())
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
    /// Ticker symbol of the reference equity — empty when unset.
    pub symbol: String,
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
            heartbeat_secs: 0,
            mint_window_cap: 0,
            mint_window_secs: 0,
            window_minted: 0,
            window_started_at: 0,
            paused: false,
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

    #[test]
    fn burn_exceeding_circulating_rejected() {
        let reg = SecureMintRegistry::new();
        let token = [5u8; 20];
        reg.set_policy(token, policy_with_reserve(1_000));
        reg.check_and_mint(&token, 400, 1_700_000_000).unwrap();
        let err = reg.record_burn(&token, 401).unwrap_err();
        assert!(matches!(err, SecureMintError::ExceedsCirculating { .. }));
        // Circulating unchanged after a rejected burn.
        assert_eq!(reg.policy(&token).unwrap().circulating, 400);
    }

    #[test]
    fn mint_without_policy_is_fail_closed() {
        let reg = SecureMintRegistry::new();
        let err = reg.check_and_mint(&[6u8; 20], 1, 1_700_000_000).unwrap_err();
        assert!(matches!(err, SecureMintError::NotConfigured(_)));
    }

    #[test]
    fn frozen_feed_blocks_mint_within_ttl() {
        let reg = SecureMintRegistry::new();
        let token = [7u8; 20];
        let mut policy = policy_with_reserve(1_000);
        policy.ttl_secs = 86_400; // attestation still valid for a day
        policy.heartbeat_secs = 60; // but feed must refresh each minute
        reg.set_policy(token, policy);
        // 120s later: inside TTL, past heartbeat → FeedStale.
        let err = reg.check_and_mint(&token, 1, 1_700_000_000 + 120).unwrap_err();
        assert!(matches!(err, SecureMintError::FeedStale { .. }));
    }

    #[test]
    fn paused_token_blocks_mint() {
        let reg = SecureMintRegistry::new();
        let token = [8u8; 20];
        reg.set_policy(token, policy_with_reserve(1_000));
        reg.set_paused(&token, true);
        let err = reg.check_and_mint(&token, 1, 1_700_000_000).unwrap_err();
        assert!(matches!(err, SecureMintError::Paused(_)));
        reg.set_paused(&token, false);
        assert!(reg.check_and_mint(&token, 1, 1_700_000_000).is_ok());
    }

    #[test]
    fn global_pause_blocks_all_mints() {
        let reg = SecureMintRegistry::new();
        let token = [9u8; 20];
        reg.set_policy(token, policy_with_reserve(1_000));
        reg.set_global_pause(true);
        assert!(matches!(
            reg.check_and_mint(&token, 1, 1_700_000_000).unwrap_err(),
            SecureMintError::Paused(_)
        ));
        reg.set_global_pause(false);
        assert!(reg.check_and_mint(&token, 1, 1_700_000_000).is_ok());
    }

    #[test]
    fn supply_scale_rounds_against_issuer() {
        let reg = SecureMintRegistry::new();
        let token = [11u8; 20];
        let mut policy = policy_with_reserve(1_001);
        policy.circulating = 999;
        reg.set_policy(token, policy);
        // 1:2 reverse split: circulating ceil(999/2)=500, reserve floor(1001/2)=500.
        let after = reg.apply_supply_scale(&token, 1, 2).unwrap();
        assert_eq!(after.circulating, 500);
        assert_eq!(after.reserve, 500);
        // Zero terms rejected.
        assert!(matches!(
            reg.apply_supply_scale(&token, 0, 2).unwrap_err(),
            SecureMintError::InvalidScale { .. }
        ));
    }

    #[test]
    fn supply_scale_reserve_invariant_rejected() {
        let reg = SecureMintRegistry::new();
        let token = [12u8; 20];
        let mut policy = policy_with_reserve(3);
        policy.circulating = 3;
        reg.set_policy(token, policy);
        // 1:2 reverse split: circulating ceil(3/2)=2 > reserve floor(3/2)=1.
        let err = reg.apply_supply_scale(&token, 1, 2).unwrap_err();
        assert!(matches!(err, SecureMintError::ExceedsReserve { .. }));
        // Policy untouched after rejection.
        let p = reg.policy(&token).unwrap();
        assert_eq!(p.circulating, 3);
        assert_eq!(p.reserve, 3);
    }

    #[test]
    fn velocity_cap_enforced_and_rolls_over() {
        let reg = SecureMintRegistry::new();
        let token = [10u8; 20];
        let mut policy = policy_with_reserve(1_000_000);
        policy.mint_window_cap = 1_000;
        policy.mint_window_secs = 3_600;
        reg.set_policy(token, policy);
        let t0 = 1_700_000_000;
        reg.check_and_mint(&token, 600, t0).unwrap();
        reg.check_and_mint(&token, 400, t0 + 10).unwrap(); // tally = 1_000 (at cap)
        let err = reg.check_and_mint(&token, 1, t0 + 20).unwrap_err();
        assert!(matches!(err, SecureMintError::VelocityExceeded { .. }));
        // After the window rolls, the tally resets.
        let after = reg.check_and_mint(&token, 800, t0 + 3_600).unwrap();
        assert_eq!(after.window_minted, 800);
    }
}
