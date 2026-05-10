//! Fee routing for workflow settlements.
//!
//! A `FeeRoute` describes how a single settlement payout is split across
//! multiple recipients (counterparties, treasury, network, oracle providers).
//! Splits are expressed in basis points and must sum to 10_000 (100%).
//!
//! ## Why this lives in `tenzro-workflow`
//!
//! The settlement engine (`tenzro-settlement`) handles the on-chain payout
//! mechanics. The *policy* of who gets paid how much is a workflow concern —
//! it is signed by participants as part of `Workflow::canonical_hash` (via
//! the `fee_route: Option<FeeRouteId>` reference), surfaces in receipts via
//! the privacy domain, and is auditable per the workflow's auditor set.
//!
//! ## Persistence
//!
//! Routes are persisted in `CF_SETTLEMENTS` under the `wf_feeroute:` prefix
//! via `KvStore::put` calls wrapped in a `WriteOp::Put` batch and committed
//! through `write_batch_sync` for fsync durability.

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_storage::kv::{KvStore, WriteOp, CF_SETTLEMENTS};
use tenzro_types::primitives::Hash;

use crate::error::{Result, WorkflowError};
use crate::workflow::FeeRouteId;

/// A single recipient + its share in basis points (1 bp = 0.01%).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeSplit {
    /// Recipient DID. Resolved against the workflow's participants at
    /// settlement time — must match a participant or a well-known
    /// network DID (e.g. `did:tenzro:treasury:network`).
    pub recipient_did: String,
    /// Share in basis points. Sum across all splits MUST equal 10_000.
    pub share_bps: u32,
    /// Free-form label surfaced in receipts (e.g. `"seller_payout"`,
    /// `"network_fee"`, `"verifier_fee"`).
    pub label: String,
}

/// A named fee route — a set of splits that totals 10_000 bps.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeRoute {
    pub fee_route_id: FeeRouteId,
    /// Human-readable label, surfaced in receipts.
    pub label: String,
    pub splits: Vec<FeeSplit>,
    /// Unix seconds.
    pub created_at: i64,
}

impl FeeRoute {
    /// Deterministic id derived from the label + ordered splits.
    pub fn derive_id(label: &str, splits: &[FeeSplit]) -> FeeRouteId {
        let mut h = Sha256::new();
        h.update(b"tenzro/workflow/feeroute/id");
        h.update((label.len() as u32).to_le_bytes());
        h.update(label.as_bytes());
        h.update((splits.len() as u32).to_le_bytes());
        for s in splits {
            h.update((s.recipient_did.len() as u32).to_le_bytes());
            h.update(s.recipient_did.as_bytes());
            h.update(s.share_bps.to_le_bytes());
            h.update((s.label.len() as u32).to_le_bytes());
            h.update(s.label.as_bytes());
        }
        Hash::from(<[u8; 32]>::from(h.finalize()))
    }

    /// Validate that splits sum to exactly 10_000 bps and that every split
    /// has a non-empty recipient.
    pub fn validate(&self) -> Result<()> {
        if self.splits.is_empty() {
            return Err(WorkflowError::Invalid(
                "fee route has no splits".into(),
            ));
        }
        let total: u32 = self.splits.iter().map(|s| s.share_bps).sum();
        if total != 10_000 {
            return Err(WorkflowError::FeeSplitOverflow(total));
        }
        for s in &self.splits {
            if s.recipient_did.is_empty() {
                return Err(WorkflowError::Invalid(
                    "fee split recipient_did is empty".into(),
                ));
            }
            if s.share_bps == 0 {
                return Err(WorkflowError::Invalid(format!(
                    "fee split '{}' has zero share",
                    s.label
                )));
            }
        }
        Ok(())
    }

    /// Compute the per-recipient payout for a gross amount in wei.
    ///
    /// Returns `(recipient_did, label, amount_wei)` triples in the same
    /// order as `self.splits`. Uses checked u128 arithmetic — overflow
    /// returns `WorkflowError::Invalid`. Rounding is **truncation**;
    /// any remainder accrues to the LAST split (typically the network
    /// fee or treasury) so the sum equals `gross_wei` exactly.
    pub fn compute_payouts(
        &self,
        gross_wei: u128,
    ) -> Result<Vec<(String, String, u128)>> {
        self.validate()?;
        let mut out = Vec::with_capacity(self.splits.len());
        let mut allocated: u128 = 0;
        let last_idx = self.splits.len() - 1;
        for (i, s) in self.splits.iter().enumerate() {
            let amount = if i == last_idx {
                // Drain the remainder into the last split.
                gross_wei
                    .checked_sub(allocated)
                    .ok_or_else(|| WorkflowError::Invalid(
                        "fee route arithmetic underflow".into(),
                    ))?
            } else {
                let bps = s.share_bps as u128;
                let amt = gross_wei
                    .checked_mul(bps)
                    .ok_or_else(|| WorkflowError::Invalid(
                        "fee route arithmetic overflow".into(),
                    ))?
                    / 10_000u128;
                allocated = allocated.checked_add(amt).ok_or_else(|| {
                    WorkflowError::Invalid(
                        "fee route allocated overflow".into(),
                    )
                })?;
                amt
            };
            out.push((s.recipient_did.clone(), s.label.clone(), amount));
        }
        Ok(out)
    }
}

const KEY_PREFIX: &[u8] = b"wf_feeroute:";

fn key_for(id: &FeeRouteId) -> Vec<u8> {
    let mut k = Vec::with_capacity(KEY_PREFIX.len() + 32);
    k.extend_from_slice(KEY_PREFIX);
    k.extend_from_slice(id.as_bytes());
    k
}

/// Thread-safe registry of `FeeRoute`s with write-through persistence to
/// `CF_SETTLEMENTS`.
pub struct FeeRouteRegistry {
    routes: DashMap<FeeRouteId, FeeRoute>,
    storage: Option<Arc<dyn KvStore>>,
}

impl FeeRouteRegistry {
    pub fn new() -> Self {
        Self {
            routes: DashMap::new(),
            storage: None,
        }
    }

    /// Construct with persistence; hydrates the in-memory index from
    /// `CF_SETTLEMENTS` under the `wf_feeroute:` prefix.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> {
        let routes: DashMap<FeeRouteId, FeeRoute> = DashMap::new();
        for k in storage.get_keys_with_prefix(CF_SETTLEMENTS, KEY_PREFIX)? {
            if let Some(bytes) = storage.get(CF_SETTLEMENTS, &k)? {
                let r: FeeRoute = bincode::deserialize(&bytes)?;
                routes.insert(r.fee_route_id, r);
            }
        }
        Ok(Self {
            routes,
            storage: Some(storage),
        })
    }

    /// Register a route. Validates the splits before insertion. Returns
    /// the id for cross-referencing from `Workflow::fee_route`.
    pub fn register(&self, route: FeeRoute) -> Result<FeeRouteId> {
        route.validate()?;
        let id = route.fee_route_id;
        if let Some(s) = &self.storage {
            let bytes = bincode::serialize(&route)?;
            s.write_batch_sync(vec![WriteOp::Put {
                cf: CF_SETTLEMENTS.to_string(),
                key: key_for(&id),
                value: bytes,
            }])?;
        }
        self.routes.insert(id, route);
        Ok(id)
    }

    pub fn get(&self, id: &FeeRouteId) -> Option<FeeRoute> {
        self.routes.get(id).map(|r| r.clone())
    }

    pub fn list(&self) -> Vec<FeeRoute> {
        self.routes.iter().map(|r| r.clone()).collect()
    }

    pub fn remove(&self, id: &FeeRouteId) -> Result<Option<FeeRoute>> {
        let prev = self.routes.remove(id).map(|(_, v)| v);
        if prev.is_some() {
            if let Some(s) = &self.storage {
                s.write_batch_sync(vec![WriteOp::Delete {
                    cf: CF_SETTLEMENTS.to_string(),
                    key: key_for(id),
                }])?;
            }
        }
        Ok(prev)
    }
}

impl Default for FeeRouteRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_route(label: &str, splits: Vec<FeeSplit>) -> FeeRoute {
        let id = FeeRoute::derive_id(label, &splits);
        FeeRoute {
            fee_route_id: id,
            label: label.into(),
            splits,
            created_at: 1700000000,
        }
    }

    #[test]
    fn validate_rejects_non_10000_bps() {
        let r = mk_route(
            "bad",
            vec![
                FeeSplit { recipient_did: "did:a".into(), share_bps: 4000, label: "x".into() },
                FeeSplit { recipient_did: "did:b".into(), share_bps: 5000, label: "y".into() },
            ],
        );
        assert!(matches!(r.validate(), Err(WorkflowError::FeeSplitOverflow(9000))));
    }

    #[test]
    fn validate_rejects_empty_splits() {
        let r = mk_route("empty", vec![]);
        assert!(r.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_share() {
        let r = mk_route(
            "zero",
            vec![
                FeeSplit { recipient_did: "did:a".into(), share_bps: 10_000, label: "x".into() },
                FeeSplit { recipient_did: "did:b".into(), share_bps: 0, label: "y".into() },
            ],
        );
        // Total is 10_000 but one split is zero — rejected.
        assert!(r.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_recipient() {
        let r = mk_route(
            "noempty",
            vec![FeeSplit { recipient_did: "".into(), share_bps: 10_000, label: "x".into() }],
        );
        assert!(r.validate().is_err());
    }

    #[test]
    fn compute_payouts_distributes_remainder_to_last() {
        let r = mk_route(
            "split",
            vec![
                FeeSplit { recipient_did: "did:a".into(), share_bps: 8000, label: "seller".into() },
                FeeSplit { recipient_did: "did:b".into(), share_bps: 1500, label: "treasury".into() },
                FeeSplit { recipient_did: "did:c".into(), share_bps: 500, label: "network".into() },
            ],
        );
        // 1001 wei: 800.8 → 800; 150.15 → 150; remainder = 51 to last
        let p = r.compute_payouts(1001).unwrap();
        let total: u128 = p.iter().map(|(_, _, a)| *a).sum();
        assert_eq!(total, 1001, "payouts must sum to gross");
        assert_eq!(p[0].2, 800);
        assert_eq!(p[1].2, 150);
        assert_eq!(p[2].2, 51); // includes remainder
    }

    #[test]
    fn compute_payouts_round_amount_no_remainder() {
        let r = mk_route(
            "round",
            vec![
                FeeSplit { recipient_did: "did:a".into(), share_bps: 8000, label: "seller".into() },
                FeeSplit { recipient_did: "did:b".into(), share_bps: 2000, label: "buyer".into() },
            ],
        );
        let p = r.compute_payouts(1_000_000).unwrap();
        assert_eq!(p[0].2, 800_000);
        assert_eq!(p[1].2, 200_000);
    }

    #[test]
    fn registry_register_and_get() {
        let reg = FeeRouteRegistry::new();
        let r = mk_route(
            "memreg",
            vec![FeeSplit { recipient_did: "did:a".into(), share_bps: 10_000, label: "all".into() }],
        );
        let id = reg.register(r.clone()).unwrap();
        assert_eq!(reg.get(&id).unwrap(), r);
        assert_eq!(reg.list().len(), 1);
    }

    #[test]
    fn derive_id_deterministic() {
        let splits = vec![
            FeeSplit { recipient_did: "did:a".into(), share_bps: 10_000, label: "x".into() },
        ];
        let a = FeeRoute::derive_id("lbl", &splits);
        let b = FeeRoute::derive_id("lbl", &splits);
        assert_eq!(a, b);
        let c = FeeRoute::derive_id("lbl2", &splits);
        assert_ne!(a, c);
    }
}
