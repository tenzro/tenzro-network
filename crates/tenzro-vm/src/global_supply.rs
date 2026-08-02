//! Global supply accounting registry (precompile 0x1021).
//!
//! Tenzro-issued tokens (TNZO, wrapped stables, tokenized equities, OFT-
//! style mirrors) can move across rails: LayerZero V2, Wormhole NTT,
//! Chainlink CCT, deBridge, IBC-Eureka, Stargate V2 Hydra. Each rail
//! independently mints + burns its own representation. Without a single
//! global accounting log, a misbehaving relayer (or a compromised rail)
//! could mint more than the canonical supply and the chain would have no
//! way to notice.
//!
//! This registry is that single log. Every cross-rail mint/burn submits a
//! signed delta:
//!
//! ```text
//! GlobalSupplyDelta {
//!     asset_id, rail, sequence, kind: Mint|Burn, amount, source_chain,
//! }
//! ```
//!
//! and the registry enforces:
//!
//!   - **Monotone-per-(asset,rail) sequence**: a delta whose sequence ≤ the
//!     last-applied is rejected (replay guard).
//!   - **Σ mints − Σ burns ≤ max_supply**: any mint that would push the
//!     net circulating above the configured cap is rejected.
//!   - **No underflow on burn**: a burn that would push net negative is
//!     rejected.
//!
//! Read-only callers consult `circulating(asset_id)` / `last_seq(asset,
//! rail)` to track integrity. The on-EVM precompile is a thin lookup over
//! these accessors plus a deterministic delta-application path.

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result as VmResult, VmError};
use tenzro_types::primitives::Hash;

/// Bridge rail id. Same wire shape as `tenzro_bridge::traits::BridgeAdapterId`
/// — duplicated here to keep `tenzro-vm` free of a `tenzro-bridge`
/// dependency. The registry compares this opaquely.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GlobalSupplyRail(pub String);

impl GlobalSupplyRail {
    /// Convenience constructor.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// Direction of the delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GlobalSupplyKind {
    /// Mint event observed on `rail` (issuance increases).
    Mint,
    /// Burn event observed on `rail` (issuance decreases).
    Burn,
}

/// A single cross-rail mint/burn record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSupplyDelta {
    /// Tenzro-side asset id (e.g. CAIP-19 string or 32-byte token id hex).
    pub asset_id: String,
    /// Rail this delta originated on.
    pub rail: GlobalSupplyRail,
    /// Monotone per (asset, rail) sequence number.
    pub sequence: u64,
    /// Direction.
    pub kind: GlobalSupplyKind,
    /// Amount in base units.
    pub amount: u128,
    /// Source chain id (informational — CAIP-2 or the bridge's chain id).
    pub source_chain: String,
}

impl GlobalSupplyDelta {
    /// Stable hash of this delta. Used both as a dedup key on top of
    /// sequence (helps detect bit-flipped retries) and as the on-EVM
    /// commitment when the precompile records the delta.
    pub fn digest(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(b"tenzro/global-supply/delta");
        h.update(self.asset_id.as_bytes());
        h.update(b"|");
        h.update(self.rail.0.as_bytes());
        h.update(b"|");
        h.update(self.sequence.to_le_bytes());
        h.update([match self.kind {
            GlobalSupplyKind::Mint => 0u8,
            GlobalSupplyKind::Burn => 1u8,
        }]);
        h.update(self.amount.to_le_bytes());
        h.update(b"|");
        h.update(self.source_chain.as_bytes());
        let digest: [u8; 32] = h.finalize().into();
        Hash::new(digest)
    }
}

/// Per-asset policy. Updates require governance (precompile path).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSupplyPolicy {
    /// Canonical asset id.
    pub asset_id: String,
    /// Hard cap on circulating supply across all rails.
    pub max_supply: u128,
    /// Optional grace window: deltas older than this sequence are
    /// rejected even if higher than `last_seq`. Used to recover from a
    /// rail compromise by jumping the sequence cursor forward via
    /// governance.
    pub min_accepted_seq: u64,
}

/// Per-asset in-memory accounting state.
#[derive(Debug, Default, Clone)]
struct AssetAccount {
    circulating: u128,
    last_seq: BTreeMap<GlobalSupplyRail, u64>,
}

/// The global accounting registry.
#[derive(Debug, Default)]
pub struct GlobalSupplyRegistry {
    policies: RwLock<BTreeMap<String, GlobalSupplyPolicy>>,
    state: RwLock<BTreeMap<String, AssetAccount>>,
}

impl GlobalSupplyRegistry {
    /// Build a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Install or overwrite a per-asset policy.
    pub fn set_policy(&self, policy: GlobalSupplyPolicy) {
        self.policies
            .write()
            .insert(policy.asset_id.clone(), policy);
    }

    /// Look up a policy.
    pub fn get_policy(&self, asset_id: &str) -> Option<GlobalSupplyPolicy> {
        self.policies.read().get(asset_id).cloned()
    }

    /// Current circulating supply for an asset.
    pub fn circulating(&self, asset_id: &str) -> u128 {
        self.state
            .read()
            .get(asset_id)
            .map(|a| a.circulating)
            .unwrap_or(0)
    }

    /// Last applied sequence on `(asset, rail)`.
    pub fn last_seq(&self, asset_id: &str, rail: &GlobalSupplyRail) -> u64 {
        self.state
            .read()
            .get(asset_id)
            .and_then(|a| a.last_seq.get(rail).copied())
            .unwrap_or(0)
    }

    /// Apply a delta. Fails on replay, sequence regression, unknown
    /// policy, supply-cap breach, or burn underflow.
    pub fn apply(&self, delta: &GlobalSupplyDelta) -> VmResult<Hash> {
        let policy = self.get_policy(&delta.asset_id).ok_or_else(|| {
            VmError::InvalidTransaction(format!(
                "global-supply: no policy for asset {}",
                delta.asset_id
            ))
        })?;
        if delta.sequence < policy.min_accepted_seq {
            return Err(VmError::InvalidTransaction(format!(
                "global-supply: sequence {} below min_accepted_seq {}",
                delta.sequence, policy.min_accepted_seq
            )));
        }
        let mut state = self.state.write();
        let account = state.entry(delta.asset_id.clone()).or_default();
        let last = account.last_seq.get(&delta.rail).copied().unwrap_or(0);
        if delta.sequence <= last && last != 0 {
            return Err(VmError::InvalidTransaction(format!(
                "global-supply: sequence {} ≤ last {} for rail {}",
                delta.sequence, last, delta.rail.0
            )));
        }
        match delta.kind {
            GlobalSupplyKind::Mint => {
                let projected = account
                    .circulating
                    .checked_add(delta.amount)
                    .ok_or_else(|| VmError::InvalidTransaction("global-supply: overflow".into()))?;
                if projected > policy.max_supply {
                    return Err(VmError::InvalidTransaction(format!(
                        "global-supply: mint would breach max_supply ({}+{}>{})",
                        account.circulating, delta.amount, policy.max_supply
                    )));
                }
                account.circulating = projected;
            }
            GlobalSupplyKind::Burn => {
                if delta.amount > account.circulating {
                    return Err(VmError::InvalidTransaction(format!(
                        "global-supply: burn underflow ({}-{})",
                        account.circulating, delta.amount
                    )));
                }
                account.circulating -= delta.amount;
            }
        }
        account.last_seq.insert(delta.rail.clone(), delta.sequence);
        Ok(delta.digest())
    }

    /// Dry-run: would this delta succeed?
    pub fn would_apply(&self, delta: &GlobalSupplyDelta) -> bool {
        let Some(policy) = self.get_policy(&delta.asset_id) else {
            return false;
        };
        if delta.sequence < policy.min_accepted_seq {
            return false;
        }
        let state = self.state.read();
        let account = state.get(&delta.asset_id).cloned().unwrap_or_default();
        let last = account.last_seq.get(&delta.rail).copied().unwrap_or(0);
        if delta.sequence <= last && last != 0 {
            return false;
        }
        match delta.kind {
            GlobalSupplyKind::Mint => account
                .circulating
                .checked_add(delta.amount)
                .map(|p| p <= policy.max_supply)
                .unwrap_or(false),
            GlobalSupplyKind::Burn => delta.amount <= account.circulating,
        }
    }
}

/// Shared handle used by VM precompile + node-layer RPCs.
pub type SharedGlobalSupplyRegistry = Arc<GlobalSupplyRegistry>;

#[cfg(test)]
mod tests {
    use super::*;

    fn rail(s: &str) -> GlobalSupplyRail {
        GlobalSupplyRail::new(s)
    }

    fn delta(
        asset: &str,
        rail_str: &str,
        seq: u64,
        kind: GlobalSupplyKind,
        amt: u128,
    ) -> GlobalSupplyDelta {
        GlobalSupplyDelta {
            asset_id: asset.into(),
            rail: rail(rail_str),
            sequence: seq,
            kind,
            amount: amt,
            source_chain: "test".into(),
        }
    }

    fn policy(asset: &str, max: u128) -> GlobalSupplyPolicy {
        GlobalSupplyPolicy {
            asset_id: asset.into(),
            max_supply: max,
            min_accepted_seq: 0,
        }
    }

    #[test]
    fn apply_mint_then_burn() {
        let r = GlobalSupplyRegistry::new();
        r.set_policy(policy("TNZO", 1_000_000));
        r.apply(&delta("TNZO", "layerzero", 1, GlobalSupplyKind::Mint, 100))
            .unwrap();
        r.apply(&delta("TNZO", "layerzero", 2, GlobalSupplyKind::Burn, 30))
            .unwrap();
        assert_eq!(r.circulating("TNZO"), 70);
    }

    #[test]
    fn mint_breaching_cap_rejected() {
        let r = GlobalSupplyRegistry::new();
        r.set_policy(policy("TNZO", 100));
        let err = r
            .apply(&delta("TNZO", "lz", 1, GlobalSupplyKind::Mint, 1_000))
            .unwrap_err();
        assert!(matches!(err, VmError::InvalidTransaction(_)));
    }

    #[test]
    fn burn_underflow_rejected() {
        let r = GlobalSupplyRegistry::new();
        r.set_policy(policy("TNZO", 1_000_000));
        let err = r
            .apply(&delta("TNZO", "lz", 1, GlobalSupplyKind::Burn, 1))
            .unwrap_err();
        assert!(matches!(err, VmError::InvalidTransaction(_)));
    }

    #[test]
    fn replay_rejected() {
        let r = GlobalSupplyRegistry::new();
        r.set_policy(policy("TNZO", 1_000_000));
        r.apply(&delta("TNZO", "lz", 5, GlobalSupplyKind::Mint, 50))
            .unwrap();
        let err = r
            .apply(&delta("TNZO", "lz", 5, GlobalSupplyKind::Mint, 50))
            .unwrap_err();
        assert!(matches!(err, VmError::InvalidTransaction(_)));
    }

    #[test]
    fn out_of_order_within_same_rail_rejected() {
        let r = GlobalSupplyRegistry::new();
        r.set_policy(policy("TNZO", 1_000_000));
        r.apply(&delta("TNZO", "lz", 10, GlobalSupplyKind::Mint, 100))
            .unwrap();
        let err = r
            .apply(&delta("TNZO", "lz", 5, GlobalSupplyKind::Mint, 50))
            .unwrap_err();
        assert!(matches!(err, VmError::InvalidTransaction(_)));
    }

    #[test]
    fn distinct_rails_have_independent_sequences() {
        let r = GlobalSupplyRegistry::new();
        r.set_policy(policy("TNZO", 1_000_000));
        r.apply(&delta("TNZO", "lz", 10, GlobalSupplyKind::Mint, 100))
            .unwrap();
        r.apply(&delta("TNZO", "ccip", 1, GlobalSupplyKind::Mint, 50))
            .unwrap();
        assert_eq!(r.last_seq("TNZO", &rail("lz")), 10);
        assert_eq!(r.last_seq("TNZO", &rail("ccip")), 1);
        assert_eq!(r.circulating("TNZO"), 150);
    }

    #[test]
    fn unknown_asset_rejected() {
        let r = GlobalSupplyRegistry::new();
        let err = r
            .apply(&delta("UNK", "lz", 1, GlobalSupplyKind::Mint, 1))
            .unwrap_err();
        assert!(matches!(err, VmError::InvalidTransaction(_)));
    }

    #[test]
    fn would_apply_matches_apply() {
        let r = GlobalSupplyRegistry::new();
        r.set_policy(policy("TNZO", 100));
        let d = delta("TNZO", "lz", 1, GlobalSupplyKind::Mint, 50);
        assert!(r.would_apply(&d));
        r.apply(&d).unwrap();
        let d2 = delta("TNZO", "lz", 2, GlobalSupplyKind::Mint, 100);
        assert!(!r.would_apply(&d2));
    }

    #[test]
    fn digest_is_deterministic() {
        let d = delta("TNZO", "lz", 5, GlobalSupplyKind::Mint, 100);
        assert_eq!(d.digest(), d.digest());
    }
}
