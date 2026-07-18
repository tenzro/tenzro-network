//! Corporate-action engine for tokenized equities.
//!
//! Owns the per-token action schedule and the [`TokenizedEquityProfile`]
//! sidecar, and is the only writer of split-driven supply changes on the
//! [`SecureMintRegistry`] (via `apply_supply_scale`). Every applied action
//! extends a per-asset hash chain (`event_hash = SHA-256(domain ||
//! prev_event_hash || action bytes)`) whose head is mirrored into
//! `profile.last_corporate_action`, so an auditor can replay the full
//! action history from any trusted point.
//!
//! Fail-closed: scheduling against a token with no Secure-Mint policy
//! rejects; applying against a token with no equity profile rejects; a split
//! whose conservative rounding (circulating up, reserve down) would break
//! `circulating <= reserve` rejects and stops the apply sweep.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;

use tenzro_types::primitives::Hash;

use crate::secure_mint::{
    SecureMintError, SecureMintPolicy, SecureMintRegistry, TokenizedEquityProfile,
};

/// Domain-separation tag for action ids and the per-asset event hash chain.
pub const CORPORATE_ACTION_DOMAIN: &str = "tenzro/vm/corporate-action";

/// Errors raised by the corporate-action engine.
#[derive(Debug, Error)]
pub enum CorporateActionError {
    /// The token has no Secure-Mint policy — corporate actions only apply
    /// to reserve-governed assets.
    #[error("token {0} has no Secure-Mint policy")]
    NoPolicy(String),

    /// The token has no tokenized-equity profile to mutate.
    #[error("token {0} has no tokenized-equity profile")]
    NoProfile(String),

    /// Split ratio has a zero term or the wrong direction for its variant.
    #[error("invalid split ratio for {kind}: num {num}, den {den}")]
    InvalidRatio {
        kind: &'static str,
        num: u32,
        den: u32,
    },

    /// Scaling the per-share ratio overflowed u128.
    #[error("per-share ratio scaling overflow (num {num}, den {den})")]
    RatioOverflow { num: u32, den: u32 },

    /// The Secure-Mint registry rejected the supply mutation (reserve
    /// invariant, overflow, or missing policy).
    #[error("secure-mint rejection: {0}")]
    SecureMint(#[from] SecureMintError),

    /// Action payload could not be serialized for hashing/persistence.
    #[error("serialization failure: {0}")]
    Serialization(String),
}

/// One corporate action on a tokenized equity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorporateAction {
    /// N-for-M forward split (`num > den`): holders end with more shares.
    ForwardSplit { num: u32, den: u32 },
    /// N-for-M reverse split (`num < den`): holders end with fewer shares.
    ReverseSplit { num: u32, den: u32 },
    /// Cash dividend. The engine records it on the chain; payout execution
    /// is node-layer.
    CashDividend {
        amount_per_share: u128,
        payment_asset: String,
    },
    /// Ticker symbol change on the reference equity.
    SymbolChange { new_symbol: String },
    /// ISIN change on the reference equity.
    IsinChange { new_isin: String },
}

impl CorporateAction {
    fn validate(&self) -> Result<(), CorporateActionError> {
        match self {
            CorporateAction::ForwardSplit { num, den } => {
                if *num == 0 || *den == 0 || num <= den {
                    return Err(CorporateActionError::InvalidRatio {
                        kind: "forward split",
                        num: *num,
                        den: *den,
                    });
                }
            }
            CorporateAction::ReverseSplit { num, den } => {
                if *num == 0 || *den == 0 || num >= den {
                    return Err(CorporateActionError::InvalidRatio {
                        kind: "reverse split",
                        num: *num,
                        den: *den,
                    });
                }
            }
            CorporateAction::CashDividend { .. }
            | CorporateAction::SymbolChange { .. }
            | CorporateAction::IsinChange { .. } => {}
        }
        Ok(())
    }

    fn split_ratio(&self) -> Option<(u32, u32)> {
        match self {
            CorporateAction::ForwardSplit { num, den }
            | CorporateAction::ReverseSplit { num, den } => Some((*num, *den)),
            _ => None,
        }
    }
}

/// Scheduled (and eventually applied) corporate-action record. Records are
/// hash-chained per asset in `seq` order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorporateActionRecord {
    /// `SHA-256(domain || asset_id || seq_le || action bytes)`.
    pub action_id: Hash,
    /// Asset id copied from the token's Secure-Mint policy at schedule time.
    pub asset_id: String,
    /// EVM token address the action applies to.
    pub token: [u8; 20],
    /// Monotonic per-asset sequence number, starting at 0.
    pub seq: u64,
    pub action: CorporateAction,
    /// Unix-seconds the action becomes due.
    pub effective_at: u64,
    /// Unix-seconds the action was applied; `None` while pending.
    pub applied_at: Option<u64>,
    /// Event hash of the prior record for this asset (zero hash for seq 0).
    pub prev_event_hash: Hash,
    /// `SHA-256(domain || prev_event_hash || action bytes)`.
    pub event_hash: Hash,
}

fn action_bytes(action: &CorporateAction) -> Result<Vec<u8>, CorporateActionError> {
    serde_json::to_vec(action).map_err(|e| CorporateActionError::Serialization(e.to_string()))
}

fn hash_event(prev: &Hash, action_bytes: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(CORPORATE_ACTION_DOMAIN.as_bytes());
    h.update(prev.as_bytes());
    h.update(action_bytes);
    Hash::new(h.finalize().into())
}

fn hash_action_id(asset_id: &str, seq: u64, action_bytes: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(CORPORATE_ACTION_DOMAIN.as_bytes());
    h.update(asset_id.as_bytes());
    h.update(seq.to_le_bytes());
    h.update(action_bytes);
    Hash::new(h.finalize().into())
}

fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a.max(1)
}

fn scale_ratio(
    ratio: (u128, u128),
    num: u32,
    den: u32,
) -> Result<(u128, u128), CorporateActionError> {
    let overflow = || CorporateActionError::RatioOverflow { num, den };
    let n = ratio.0.checked_mul(num as u128).ok_or_else(overflow)?;
    let d = ratio.1.checked_mul(den as u128).ok_or_else(overflow)?;
    if n == 0 || d == 0 {
        return Err(overflow());
    }
    let g = gcd(n, d);
    Ok((n / g, d / g))
}

/// Corporate-action engine. One per node, composed alongside the
/// [`SecureMintRegistry`] it mutates.
pub struct CorporateActionEngine {
    registry: Arc<SecureMintRegistry>,
    /// Per-token records, `seq`-ordered.
    actions: DashMap<[u8; 20], Vec<CorporateActionRecord>>,
    /// Per-token equity profiles.
    profiles: DashMap<[u8; 20], TokenizedEquityProfile>,
    storage: Option<Arc<dyn tenzro_storage::KvStore>>,
}

impl std::fmt::Debug for CorporateActionEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CorporateActionEngine")
            .field("tokens_with_actions", &self.actions.len())
            .field("profiles", &self.profiles.len())
            .field("persistent", &self.storage.is_some())
            .finish()
    }
}

impl CorporateActionEngine {
    /// In-memory engine (test-only; production uses `with_storage`).
    pub fn new(registry: Arc<SecureMintRegistry>) -> Self {
        Self {
            registry,
            actions: DashMap::new(),
            profiles: DashMap::new(),
            storage: None,
        }
    }

    /// Write-through to `CF_TOKENS` under `corp_action:<token20><seq_be8>`
    /// (records) and `corp_profile:<token20>` (profiles), hydrated on
    /// construction.
    pub fn with_storage(
        registry: Arc<SecureMintRegistry>,
        storage: Arc<dyn tenzro_storage::KvStore>,
    ) -> Self {
        let engine = Self {
            registry,
            actions: DashMap::new(),
            profiles: DashMap::new(),
            storage: Some(storage),
        };
        engine.hydrate();
        engine
    }

    fn action_key(token: &[u8; 20], seq: u64) -> Vec<u8> {
        let mut k = b"corp_action:".to_vec();
        k.extend_from_slice(token);
        k.extend_from_slice(&seq.to_be_bytes());
        k
    }

    fn profile_key(token: &[u8; 20]) -> Vec<u8> {
        let mut k = b"corp_profile:".to_vec();
        k.extend_from_slice(token);
        k
    }

    fn hydrate(&self) {
        let Some(ref storage) = self.storage else {
            return;
        };
        if let Ok(entries) = storage.scan_prefix(tenzro_storage::CF_TOKENS, b"corp_action:") {
            for (key, value) in entries {
                // "corp_action:"(12) || token(20) || seq_be(8)
                if key.len() != 12 + 20 + 8 {
                    continue;
                }
                let mut token = [0u8; 20];
                token.copy_from_slice(&key[12..32]);
                if let Ok(record) = serde_json::from_slice::<CorporateActionRecord>(&value) {
                    self.actions.entry(token).or_default().push(record);
                }
            }
            for mut entry in self.actions.iter_mut() {
                entry.value_mut().sort_by_key(|r| r.seq);
            }
        }
        if let Ok(entries) = storage.scan_prefix(tenzro_storage::CF_TOKENS, b"corp_profile:") {
            for (key, value) in entries {
                // "corp_profile:"(13) || token(20)
                if key.len() != 13 + 20 {
                    continue;
                }
                let mut token = [0u8; 20];
                token.copy_from_slice(&key[13..33]);
                if let Ok(profile) = serde_json::from_slice::<TokenizedEquityProfile>(&value) {
                    self.profiles.insert(token, profile);
                }
            }
        }
    }

    fn persist_record(&self, record: &CorporateActionRecord) {
        if let Some(ref storage) = self.storage
            && let Ok(bytes) = serde_json::to_vec(record)
        {
            let _ = storage.put(
                tenzro_storage::CF_TOKENS,
                &Self::action_key(&record.token, record.seq),
                &bytes,
            );
        }
    }

    fn persist_profile(&self, token: &[u8; 20], profile: &TokenizedEquityProfile) {
        if let Some(ref storage) = self.storage
            && let Ok(bytes) = serde_json::to_vec(profile)
        {
            let _ = storage.put(
                tenzro_storage::CF_TOKENS,
                &Self::profile_key(token),
                &bytes,
            );
        }
    }

    /// Install or replace the equity profile for `token`.
    pub fn set_profile(
        &self,
        token: [u8; 20],
        profile: TokenizedEquityProfile,
    ) -> Option<TokenizedEquityProfile> {
        self.persist_profile(&token, &profile);
        self.profiles.insert(token, profile)
    }

    /// Snapshot the equity profile for `token`.
    pub fn profile(&self, token: &[u8; 20]) -> Option<TokenizedEquityProfile> {
        self.profiles.get(token).map(|p| p.value().clone())
    }

    /// Snapshot every record for `token`, `seq`-ordered.
    pub fn records(&self, token: &[u8; 20]) -> Vec<CorporateActionRecord> {
        self.actions
            .get(token)
            .map(|v| v.value().clone())
            .unwrap_or_default()
    }

    /// Schedule an action against `token`. Requires an installed
    /// Secure-Mint policy (the record's `asset_id` is copied from it) and a
    /// well-formed split ratio. Extends the per-asset hash chain at
    /// schedule time; `apply_due` later consumes records in `seq` order.
    pub fn schedule(
        &self,
        token: [u8; 20],
        action: CorporateAction,
        effective_at: u64,
    ) -> Result<CorporateActionRecord, CorporateActionError> {
        action.validate()?;
        let policy: SecureMintPolicy = self
            .registry
            .policy(&token)
            .ok_or_else(|| CorporateActionError::NoPolicy(hex::encode(token)))?;
        let bytes = action_bytes(&action)?;
        let mut chain = self.actions.entry(token).or_default();
        let (seq, prev_event_hash) = match chain.last() {
            Some(last) => (last.seq + 1, last.event_hash),
            None => (0, Hash::zero()),
        };
        let record = CorporateActionRecord {
            action_id: hash_action_id(&policy.asset_id, seq, &bytes),
            asset_id: policy.asset_id,
            token,
            seq,
            action,
            effective_at,
            applied_at: None,
            prev_event_hash,
            event_hash: hash_event(&prev_event_hash, &bytes),
        };
        self.persist_record(&record);
        chain.push(record.clone());
        tracing::info!(
            token = %hex::encode(token),
            seq,
            effective_at,
            "corporate action scheduled"
        );
        Ok(record)
    }

    /// Apply every due, still-pending action for `token` in strict `seq`
    /// order, stopping at the first not-yet-due record (a later due record
    /// never jumps an earlier pending one). Splits mutate the Secure-Mint
    /// policy through `apply_supply_scale` and rescale the profile's
    /// per-share ratio; symbol/ISIN changes mutate the profile; dividends
    /// record only. Every apply advances `profile.last_corporate_action`
    /// to the record's `event_hash`. A rejection (missing profile, ratio
    /// overflow, reserve invariant) aborts the sweep; prior applies in the
    /// same call remain applied.
    pub fn apply_due(
        &self,
        token: &[u8; 20],
        now: u64,
    ) -> Result<Vec<CorporateActionRecord>, CorporateActionError> {
        let mut applied = Vec::new();
        let Some(mut chain) = self.actions.get_mut(token) else {
            return Ok(applied);
        };
        for record in chain.value_mut().iter_mut() {
            if record.applied_at.is_some() {
                continue;
            }
            if record.effective_at > now {
                break;
            }
            let mut profile = self
                .profiles
                .get(token)
                .map(|p| p.value().clone())
                .ok_or_else(|| CorporateActionError::NoProfile(hex::encode(token)))?;
            if let Some((num, den)) = record.action.split_ratio() {
                let new_ratio = scale_ratio(profile.per_share_ratio, num, den)?;
                self.registry.apply_supply_scale(token, num, den)?;
                profile.per_share_ratio = new_ratio;
            }
            match &record.action {
                CorporateAction::SymbolChange { new_symbol } => {
                    profile.symbol = new_symbol.clone();
                }
                CorporateAction::IsinChange { new_isin } => {
                    profile.isin = new_isin.clone();
                }
                CorporateAction::ForwardSplit { .. }
                | CorporateAction::ReverseSplit { .. }
                | CorporateAction::CashDividend { .. } => {}
            }
            profile.last_corporate_action = Some(record.event_hash);
            self.persist_profile(token, &profile);
            self.profiles.insert(*token, profile);
            record.applied_at = Some(now);
            self.persist_record(record);
            applied.push(record.clone());
            tracing::info!(
                token = %hex::encode(token),
                seq = record.seq,
                "corporate action applied"
            );
        }
        Ok(applied)
    }

    /// Verify the per-asset hash chain: each record's `prev_event_hash`
    /// must equal the prior record's `event_hash` (zero hash at seq 0) and
    /// each `event_hash` must recompute from its action bytes.
    pub fn verify_chain(&self, token: &[u8; 20]) -> Result<bool, CorporateActionError> {
        let records = self.records(token);
        let mut prev = Hash::zero();
        for (i, record) in records.iter().enumerate() {
            if record.seq != i as u64 || record.prev_event_hash != prev {
                return Ok(false);
            }
            let bytes = action_bytes(&record.action)?;
            if hash_event(&prev, &bytes) != record.event_hash {
                return Ok(false);
            }
            prev = record.event_hash;
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_mint::SecureMintPolicy;

    const T0: u64 = 1_700_000_000;

    fn setup(reserve: u128, circulating: u128) -> (Arc<SecureMintRegistry>, [u8; 20]) {
        let registry = Arc::new(SecureMintRegistry::new());
        let token = [0xab; 20];
        registry.set_policy(
            token,
            SecureMintPolicy {
                asset_id: "tenzro:539/erc20:0xequity".into(),
                reserve,
                circulating,
                por_feed_id: "chainlink:0xfeed".into(),
                attester_did: "did:tenzro:human:tester".into(),
                attestation_hash: Hash::default(),
                attested_at: T0,
                ttl_secs: 0,
                heartbeat_secs: 0,
                mint_window_cap: 0,
                mint_window_secs: 0,
                window_minted: 0,
                window_started_at: 0,
                paused: false,
            },
        );
        (registry, token)
    }

    fn profile() -> TokenizedEquityProfile {
        TokenizedEquityProfile {
            cct_pool_address: None,
            por_feed_id: "chainlink:0xfeed".into(),
            underlying_caip19: "eip155:1/erc20:0xunderlying".into(),
            isin: "US0000000001".into(),
            cusip: "000000000".into(),
            symbol: "TNZQ".into(),
            per_share_ratio: (1, 1),
            last_corporate_action: None,
        }
    }

    #[test]
    fn schedule_without_policy_fails_closed() {
        let engine = CorporateActionEngine::new(Arc::new(SecureMintRegistry::new()));
        let err = engine
            .schedule([1u8; 20], CorporateAction::SymbolChange { new_symbol: "X".into() }, T0)
            .unwrap_err();
        assert!(matches!(err, CorporateActionError::NoPolicy(_)));
    }

    #[test]
    fn invalid_split_ratios_rejected() {
        let (registry, token) = setup(1_000, 100);
        let engine = CorporateActionEngine::new(registry);
        // Forward split must have num > den.
        assert!(matches!(
            engine
                .schedule(token, CorporateAction::ForwardSplit { num: 1, den: 2 }, T0)
                .unwrap_err(),
            CorporateActionError::InvalidRatio { .. }
        ));
        // Reverse split must have num < den.
        assert!(matches!(
            engine
                .schedule(token, CorporateAction::ReverseSplit { num: 2, den: 1 }, T0)
                .unwrap_err(),
            CorporateActionError::InvalidRatio { .. }
        ));
        // Zero terms rejected.
        assert!(matches!(
            engine
                .schedule(token, CorporateAction::ForwardSplit { num: 2, den: 0 }, T0)
                .unwrap_err(),
            CorporateActionError::InvalidRatio { .. }
        ));
    }

    #[test]
    fn forward_split_scales_supply_and_ratio() {
        let (registry, token) = setup(1_000, 300);
        let engine = CorporateActionEngine::new(registry.clone());
        engine.set_profile(token, profile());
        engine
            .schedule(token, CorporateAction::ForwardSplit { num: 2, den: 1 }, T0)
            .unwrap();
        let applied = engine.apply_due(&token, T0).unwrap();
        assert_eq!(applied.len(), 1);
        let policy = registry.policy(&token).unwrap();
        assert_eq!(policy.circulating, 600);
        assert_eq!(policy.reserve, 2_000);
        let p = engine.profile(&token).unwrap();
        assert_eq!(p.per_share_ratio, (2, 1));
        assert_eq!(p.last_corporate_action, Some(applied[0].event_hash));
    }

    #[test]
    fn reverse_split_reserve_invariant_rejected() {
        // circulating == reserve == 3: ceil(3/2)=2 > floor(3/2)=1.
        let (registry, token) = setup(3, 3);
        let engine = CorporateActionEngine::new(registry.clone());
        engine.set_profile(token, profile());
        engine
            .schedule(token, CorporateAction::ReverseSplit { num: 1, den: 2 }, T0)
            .unwrap();
        let err = engine.apply_due(&token, T0).unwrap_err();
        assert!(matches!(
            err,
            CorporateActionError::SecureMint(SecureMintError::ExceedsReserve { .. })
        ));
        // Nothing mutated on rejection.
        let policy = registry.policy(&token).unwrap();
        assert_eq!(policy.circulating, 3);
        assert_eq!(policy.reserve, 3);
        assert_eq!(engine.profile(&token).unwrap().per_share_ratio, (1, 1));
        assert!(engine.records(&token)[0].applied_at.is_none());
    }

    #[test]
    fn apply_without_profile_fails_closed() {
        let (registry, token) = setup(1_000, 100);
        let engine = CorporateActionEngine::new(registry);
        engine
            .schedule(token, CorporateAction::CashDividend {
                amount_per_share: 5,
                payment_asset: "USDC".into(),
            }, T0)
            .unwrap();
        assert!(matches!(
            engine.apply_due(&token, T0).unwrap_err(),
            CorporateActionError::NoProfile(_)
        ));
    }

    #[test]
    fn symbol_and_isin_changes_mutate_profile() {
        let (registry, token) = setup(1_000, 100);
        let engine = CorporateActionEngine::new(registry);
        engine.set_profile(token, profile());
        engine
            .schedule(token, CorporateAction::SymbolChange { new_symbol: "NEWQ".into() }, T0)
            .unwrap();
        engine
            .schedule(token, CorporateAction::IsinChange { new_isin: "US0000000002".into() }, T0)
            .unwrap();
        let applied = engine.apply_due(&token, T0).unwrap();
        assert_eq!(applied.len(), 2);
        let p = engine.profile(&token).unwrap();
        assert_eq!(p.symbol, "NEWQ");
        assert_eq!(p.isin, "US0000000002");
        assert_eq!(p.last_corporate_action, Some(applied[1].event_hash));
    }

    #[test]
    fn hash_chain_continuity() {
        let (registry, token) = setup(1_000, 100);
        let engine = CorporateActionEngine::new(registry);
        engine.set_profile(token, profile());
        let r0 = engine
            .schedule(token, CorporateAction::ForwardSplit { num: 3, den: 1 }, T0)
            .unwrap();
        let r1 = engine
            .schedule(token, CorporateAction::CashDividend {
                amount_per_share: 1,
                payment_asset: "USDC".into(),
            }, T0 + 10)
            .unwrap();
        assert_eq!(r0.seq, 0);
        assert_eq!(r0.prev_event_hash, Hash::zero());
        assert_eq!(r1.seq, 1);
        assert_eq!(r1.prev_event_hash, r0.event_hash);
        // Recompute r1's event hash independently.
        let bytes = serde_json::to_vec(&r1.action).unwrap();
        assert_eq!(hash_event(&r0.event_hash, &bytes), r1.event_hash);
        assert!(engine.verify_chain(&token).unwrap());
    }

    #[test]
    fn apply_due_preserves_seq_order() {
        let (registry, token) = setup(1_000, 100);
        let engine = CorporateActionEngine::new(registry);
        engine.set_profile(token, profile());
        // seq 0 due later than seq 1.
        engine
            .schedule(token, CorporateAction::SymbolChange { new_symbol: "A".into() }, T0 + 100)
            .unwrap();
        engine
            .schedule(token, CorporateAction::SymbolChange { new_symbol: "B".into() }, T0)
            .unwrap();
        // At T0, seq 0 is not yet due — seq 1 must not jump it.
        assert!(engine.apply_due(&token, T0).unwrap().is_empty());
        // At T0+100 both apply, in order: final symbol is B.
        let applied = engine.apply_due(&token, T0 + 100).unwrap();
        assert_eq!(applied.len(), 2);
        assert_eq!(engine.profile(&token).unwrap().symbol, "B");
    }

    #[test]
    fn dividend_records_only() {
        let (registry, token) = setup(1_000, 100);
        let engine = CorporateActionEngine::new(registry.clone());
        engine.set_profile(token, profile());
        engine
            .schedule(token, CorporateAction::CashDividend {
                amount_per_share: 7,
                payment_asset: "USDC".into(),
            }, T0)
            .unwrap();
        let applied = engine.apply_due(&token, T0).unwrap();
        assert_eq!(applied.len(), 1);
        // Supply untouched; chain head advanced.
        let policy = registry.policy(&token).unwrap();
        assert_eq!(policy.circulating, 100);
        assert_eq!(policy.reserve, 1_000);
        assert_eq!(
            engine.profile(&token).unwrap().last_corporate_action,
            Some(applied[0].event_hash)
        );
    }
}
