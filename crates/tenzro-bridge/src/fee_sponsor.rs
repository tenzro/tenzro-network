//! BridgeFeeSponsor — debit user TNZO, sponsor destination-native fee.
//!
//! The sponsorship surface on Tenzro:
//!
//! 1. User obtains a [`BridgeFeeQuote`](crate::fee_oracle::BridgeFeeQuote)
//!    from the `BridgeFeeOracle` via `tenzro_quoteBridgeFeeInTnzo`.
//! 2. User signs a transaction debiting `tnzo_amount_wei` from their
//!    account; the sponsor RPC `tenzro_sponsorBridgeFee` validates the
//!    quote (TTL + signature), transfers TNZO to the per-bridge
//!    sponsorship-pool vault, and emits a [`BridgeSponsorshipReceipt`]
//!    mirrored to `CF_SETTLEMENTS / bridge_sponsorship:<adapter>:<id>`.
//! 3. The destination-native fee is fronted by one of:
//!    - A registered solver / relayer with stake bonded — pulls from
//!      the sponsorship vault asynchronously after delivery proof.
//!    - The network's per-adapter relay treasury (operator-funded,
//!      drained for the destination call, periodically rebalanced).
//!
//! The receipt is the on-chain audit anchor — every cross-chain
//! sponsored fee has a `MandateRef { protocol: "bridge-sponsorship" }`
//! receipt that lets the receipt-consumer trace user → quote →
//! destination-native debit → relayer/solver claim.
//!
//! # Status
//!
//! This module provides the trait, the receipt, and an in-memory pool.
//! Pool balances are not yet drawn from the live `NetworkTreasury`, and the
//! per-adapter solver claim path is not yet connected, so a restart resets
//! every pool to its configured starting balance.

use crate::error::{BridgeError, Result};
use crate::fee_oracle::{BridgeAdapterId, BridgeFeeQuote};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Receipt anchored on-chain after a successful sponsorship.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeSponsorshipReceipt {
    /// Globally unique sponsorship id. SHA-256 over the canonical
    /// preimage (quote_id, payer_did, sponsored_at_ms).
    pub sponsorship_id_hex: String,
    pub quote_id_hex: String,
    pub adapter: BridgeAdapterId,
    pub dest_chain: String,
    pub payer_did: String,
    pub tnzo_paid_wei: u128,
    /// Destination-native fee committed (the amount the relayer / pool
    /// is authorised to claim from the sponsorship vault on delivery
    /// proof).
    pub native_committed_smallest_unit: u128,
    pub sponsored_at_ms: u64,
    /// Pool address that received the TNZO debit. Hex.
    pub pool_address_hex: String,
}

/// Per-adapter sponsorship pool record. Persisted to
/// `CF_TOKENS / bridge_sponsorship_pool:<adapter>` by the production
/// `NetworkTreasury` integration; held in-memory by this struct.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SponsorshipPool {
    pub adapter: BridgeAdapterId,
    /// 20-byte pool vault address (Tenzro EVM). Computed
    /// deterministically as `SHA-256("tenzro/bridge/sponsorship-vault"
    /// || adapter_str)[0..20]`.
    pub vault_address: [u8; 20],
    /// Current TNZO balance held in the vault. Accumulates as users
    /// sponsor; drains as the relayer/pool claims for destination
    /// fees.
    pub tnzo_balance_wei: u128,
    /// Threshold (bps over expected daily outflow) below which the
    /// governance treasury auto-refills. 0 = no auto-refill.
    pub refill_threshold_bps: u32,
    /// Total destination-native committed but not yet claimed.
    pub native_outstanding_smallest_unit: u128,
}

impl SponsorshipPool {
    /// Compute the canonical vault address for an adapter.
    pub fn vault_for(adapter: BridgeAdapterId) -> [u8; 20] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"tenzro/bridge/sponsorship-vault");
        h.update(adapter.as_str().as_bytes());
        let d = h.finalize();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&d[..20]);
        addr
    }

    pub fn new(adapter: BridgeAdapterId) -> Self {
        Self {
            adapter,
            vault_address: Self::vault_for(adapter),
            tnzo_balance_wei: 0,
            refill_threshold_bps: 0,
            native_outstanding_smallest_unit: 0,
        }
    }
}

/// The sponsor surface. `record_sponsorship` is the structural primitive;
/// the production integration wires it to debit TNZO from
/// `tenzro-token::TnzoToken` and credit the pool vault.
pub struct BridgeFeeSponsor {
    pools: DashMap<BridgeAdapterId, SponsorshipPool>,
    receipts: DashMap<String, BridgeSponsorshipReceipt>,
    /// Default validity tolerance — quotes whose `valid_until_ms` lies
    /// in the past by more than this margin are rejected. Default 0 ms
    /// (strict).
    pub clock_skew_tolerance_ms: u64,
}

impl Default for BridgeFeeSponsor {
    fn default() -> Self {
        Self::new()
    }
}

impl BridgeFeeSponsor {
    pub fn new() -> Self {
        Self {
            pools: DashMap::new(),
            receipts: DashMap::new(),
            clock_skew_tolerance_ms: 0,
        }
    }

    /// Get-or-create the per-adapter pool. Production callers should
    /// preregister via `register_pool` so refill thresholds + initial
    /// balances are honoured.
    pub fn get_or_create_pool(&self, adapter: BridgeAdapterId) -> SponsorshipPool {
        self.pools
            .entry(adapter)
            .or_insert_with(|| SponsorshipPool::new(adapter))
            .value()
            .clone()
    }

    pub fn register_pool(&self, pool: SponsorshipPool) {
        self.pools.insert(pool.adapter, pool);
    }

    pub fn get_receipt(&self, sponsorship_id_hex: &str) -> Option<BridgeSponsorshipReceipt> {
        self.receipts
            .get(sponsorship_id_hex)
            .map(|r| r.value().clone())
    }

    /// Validate a [`BridgeFeeQuote`], record the sponsorship, and emit
    /// the receipt. The caller (RPC handler) is responsible for the
    /// actual TNZO debit + on-chain mirror.
    pub fn record_sponsorship(
        &self,
        quote: &BridgeFeeQuote,
        payer_did: impl Into<String>,
    ) -> Result<BridgeSponsorshipReceipt> {
        let now_ms = current_ms();
        if quote
            .valid_until_ms
            .saturating_add(self.clock_skew_tolerance_ms)
            < now_ms
        {
            return Err(BridgeError::AdapterError(format!(
                "quote expired: valid_until={} now={}",
                quote.valid_until_ms, now_ms
            )));
        }
        let payer_did = payer_did.into();

        // Update the pool: add TNZO, add native commitment.
        let pool = {
            let mut entry = self
                .pools
                .entry(quote.adapter)
                .or_insert_with(|| SponsorshipPool::new(quote.adapter));
            entry.tnzo_balance_wei = entry.tnzo_balance_wei.saturating_add(quote.tnzo_amount_wei);
            entry.native_outstanding_smallest_unit = entry
                .native_outstanding_smallest_unit
                .saturating_add(quote.native_fee_smallest_unit);
            entry.value().clone()
        };

        let sponsorship_id_hex = compute_sponsorship_id(&quote.quote_id_hex, &payer_did, now_ms);

        let receipt = BridgeSponsorshipReceipt {
            sponsorship_id_hex: sponsorship_id_hex.clone(),
            quote_id_hex: quote.quote_id_hex.clone(),
            adapter: quote.adapter,
            dest_chain: quote.dest_chain.clone(),
            payer_did,
            tnzo_paid_wei: quote.tnzo_amount_wei,
            native_committed_smallest_unit: quote.native_fee_smallest_unit,
            sponsored_at_ms: now_ms,
            pool_address_hex: format!("0x{}", hex::encode(pool.vault_address)),
        };
        self.receipts
            .insert(sponsorship_id_hex.clone(), receipt.clone());
        Ok(receipt)
    }

    /// Called when the destination-side fee is claimed by the relayer/
    /// pool (delivery proof verified). Drains the pool's commitment.
    pub fn record_claim(&self, sponsorship_id_hex: &str) -> Result<()> {
        let receipt = self.receipts.get(sponsorship_id_hex).ok_or_else(|| {
            BridgeError::AdapterError(format!("unknown sponsorship_id: {}", sponsorship_id_hex))
        })?;
        let receipt = receipt.value().clone();
        if let Some(mut entry) = self.pools.get_mut(&receipt.adapter) {
            entry.native_outstanding_smallest_unit = entry
                .native_outstanding_smallest_unit
                .saturating_sub(receipt.native_committed_smallest_unit);
        }
        Ok(())
    }
}

fn current_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn compute_sponsorship_id(quote_id_hex: &str, payer_did: &str, ts_ms: u64) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tenzro/bridge-fee-sponsorship/v1");
    h.update(quote_id_hex.as_bytes());
    h.update(payer_did.as_bytes());
    h.update(ts_ms.to_le_bytes());
    let d = h.finalize();
    format!("0x{}", hex::encode(d))
}

/// Wired sponsor that pairs a `BridgeFeeOracle` with a `BridgeFeeSponsor`,
/// exposing the canonical "quote then sponsor" flow in one call.
pub struct WiredBridgeFeeSurface {
    pub oracle: Arc<dyn crate::fee_oracle::BridgeFeeOracle>,
    pub sponsor: Arc<BridgeFeeSponsor>,
}

impl WiredBridgeFeeSurface {
    pub fn new(
        oracle: Arc<dyn crate::fee_oracle::BridgeFeeOracle>,
        sponsor: Arc<BridgeFeeSponsor>,
    ) -> Self {
        Self { oracle, sponsor }
    }

    /// Quote + sponsor in one call. Used by RPC consumers who already
    /// hold a signed payer_did.
    pub async fn quote_and_sponsor(
        &self,
        adapter: BridgeAdapterId,
        dest_chain: &str,
        native_fee_smallest_unit: u128,
        payer_did: impl Into<String>,
    ) -> Result<BridgeSponsorshipReceipt> {
        let quote = self
            .oracle
            .quote(adapter, dest_chain, native_fee_smallest_unit)
            .await?;
        self.sponsor.record_sponsorship(&quote, payer_did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fee_oracle::{GovernanceFeeRow, GovernanceSetFeeOracle, OracleBacking};

    fn quote_for_test(adapter: BridgeAdapterId, dest_chain: &str, tnzo: u128) -> BridgeFeeQuote {
        BridgeFeeQuote {
            quote_id_hex: "0x".to_string() + &"ab".repeat(32),
            adapter,
            dest_chain: dest_chain.to_string(),
            native_fee_smallest_unit: 1_000_000,
            tnzo_amount_wei: tnzo,
            rate_q18_hex: "0x0".to_string(),
            issued_at_ms: current_ms(),
            valid_until_ms: current_ms() + 60_000,
            oracle_backing: OracleBacking::Governance,
        }
    }

    #[test]
    fn vault_address_is_deterministic() {
        let v1 = SponsorshipPool::vault_for(BridgeAdapterId::Hyperlane);
        let v2 = SponsorshipPool::vault_for(BridgeAdapterId::Hyperlane);
        assert_eq!(v1, v2);
        let v3 = SponsorshipPool::vault_for(BridgeAdapterId::ChainlinkCcip);
        assert_ne!(v1, v3);
    }

    #[test]
    fn sponsor_records_receipt_and_updates_pool() {
        let s = BridgeFeeSponsor::new();
        let q = quote_for_test(BridgeAdapterId::Wormhole, "eip155:1", 1_000_000_000);
        let r = s.record_sponsorship(&q, "did:tn:human:alice").unwrap();
        assert_eq!(r.tnzo_paid_wei, 1_000_000_000);
        assert_eq!(r.adapter, BridgeAdapterId::Wormhole);
        assert!(r.sponsorship_id_hex.starts_with("0x"));
        let pool = s.get_or_create_pool(BridgeAdapterId::Wormhole);
        assert_eq!(pool.tnzo_balance_wei, 1_000_000_000);
        assert_eq!(pool.native_outstanding_smallest_unit, 1_000_000);
    }

    #[test]
    fn sponsor_rejects_expired_quote() {
        let s = BridgeFeeSponsor::new();
        let mut q = quote_for_test(BridgeAdapterId::Wormhole, "eip155:1", 1);
        q.valid_until_ms = 0;
        let err = s.record_sponsorship(&q, "did:tn:human:alice").unwrap_err();
        match err {
            BridgeError::AdapterError(msg) => assert!(msg.contains("expired")),
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn record_claim_drains_outstanding() {
        let s = BridgeFeeSponsor::new();
        let q = quote_for_test(BridgeAdapterId::Hyperlane, "eip155:1", 100);
        let r = s.record_sponsorship(&q, "did:tn:human:bob").unwrap();
        let before = s.get_or_create_pool(BridgeAdapterId::Hyperlane);
        assert_eq!(before.native_outstanding_smallest_unit, 1_000_000);
        s.record_claim(&r.sponsorship_id_hex).unwrap();
        let after = s.get_or_create_pool(BridgeAdapterId::Hyperlane);
        assert_eq!(after.native_outstanding_smallest_unit, 0);
        // TNZO balance remains — that's the relayer-claim accounting; the
        // actual TNZO drain to the relayer happens in a separate step.
        assert_eq!(after.tnzo_balance_wei, 100);
    }

    #[tokio::test]
    async fn wired_surface_quote_and_sponsor_end_to_end() {
        let oracle = Arc::new(GovernanceSetFeeOracle::new());
        oracle.set_rate(GovernanceFeeRow {
            adapter: BridgeAdapterId::ChainlinkCcip,
            dest_chain: "eip155:1".into(),
            rate_q18: 5 * 1_000_000_000_000_000_000u128, // 5.0
            markup_bps: 200,                             // 2%
            valid_window_ms: 60_000,
            updated_at_ms: 0,
        });
        let sponsor = Arc::new(BridgeFeeSponsor::new());
        let surface = WiredBridgeFeeSurface::new(oracle, sponsor.clone());

        let receipt = surface
            .quote_and_sponsor(
                BridgeAdapterId::ChainlinkCcip,
                "eip155:1",
                1_000_000,
                "did:tn:human:e2e-tester",
            )
            .await
            .unwrap();
        // 1_000_000 * 5 = 5_000_000; +2% = 5_100_000.
        assert_eq!(receipt.tnzo_paid_wei, 5_100_000);
        let pool = sponsor.get_or_create_pool(BridgeAdapterId::ChainlinkCcip);
        assert_eq!(pool.tnzo_balance_wei, 5_100_000);
    }
}
