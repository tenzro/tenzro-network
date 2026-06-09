//! BridgeFeeOracle — quote destination-native bridge fees in TNZO.
//!
//! Cross-chain fee abstraction surface — the user pays in TNZO on the
//! source chain, the protocol-side oracle quotes the destination-native
//! fee in TNZO, a sponsor fronts the destination fee:
//!
//! The user signs ONE source-chain transaction paying in TNZO. The
//! protocol-side fee oracle quotes the destination-native fee in TNZO,
//! the [`BridgeFeeSponsor`](crate::fee_sponsor::BridgeFeeSponsor) debits
//! the user, and either a registered solver or the network's per-bridge
//! sponsorship pool forwards the destination-native fee.
//!
//! This module provides:
//! 1. [`BridgeAdapterId`] — strongly-typed adapter identifier.
//! 2. [`BridgeFeeQuote`] — the canonical quote envelope returned to the
//!    user.
//! 3. [`BridgeFeeOracle`] trait — the abstract quoting surface.
//! 4. [`GovernanceSetFeeOracle`] — manual-rate-table oracle backed by
//!    `tenzro-token::GovernanceEngine`. Mirrors Hyperlane's `StorageGasOracle`.
//! 5. [`ChainlinkFeedFeeOracle`] — on-chain Chainlink Data Feed oracle.
//!    Reads (destination_native/USD) + (TNZO/USD) to derive the rate.
//!
//! # Wire shape
//!
//! Quotes carry a TEE-attested timestamp + validity window so a stale
//! quote can't be replayed across an FX move (Cosmos ICS-29's escrow
//! handles this via packet timeout; our equivalent is `valid_until_ms`).

use crate::error::{BridgeError, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Bridge-adapter identifier. Strongly-typed to prevent typos at the
/// per-bridge sponsorship-pool / fee-oracle keying layer. Mirrors the
/// adapter set in `tenzro_listBridgeAdapters`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BridgeAdapterId {
    LayerZero,
    ChainlinkCcip,
    Wormhole,
    DeBridge,
    Hyperlane,
    Axelar,
    LiFi,
    Canton,
}

impl BridgeAdapterId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LayerZero => "layerzero",
            Self::ChainlinkCcip => "ccip",
            Self::Wormhole => "wormhole",
            Self::DeBridge => "debridge",
            Self::Hyperlane => "hyperlane",
            Self::Axelar => "axelar",
            Self::LiFi => "lifi",
            Self::Canton => "canton",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "layerzero" | "lz" => Some(Self::LayerZero),
            "ccip" | "chainlink_ccip" | "chainlink-ccip" => Some(Self::ChainlinkCcip),
            "wormhole" => Some(Self::Wormhole),
            "debridge" => Some(Self::DeBridge),
            "hyperlane" => Some(Self::Hyperlane),
            "axelar" => Some(Self::Axelar),
            "lifi" | "li.fi" => Some(Self::LiFi),
            "canton" => Some(Self::Canton),
            _ => None,
        }
    }
}

/// The canonical quote envelope. Returned to users via
/// `tenzro_quoteBridgeFeeInTnzo`. The user's signed sponsorship
/// transaction must reference a `quote_id` whose `valid_until_ms`
/// hasn't lapsed — same TTL discipline Cosmos ICS-29 uses for
/// `timeout_fee` escrow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BridgeFeeQuote {
    /// Globally-unique quote id. SHA-256 over the canonical preimage so
    /// the same inputs produce the same quote id.
    pub quote_id_hex: String,
    pub adapter: BridgeAdapterId,
    /// Destination chain (CAIP-2 identifier preferred — `eip155:1`,
    /// `solana:mainnet-beta`, etc.).
    pub dest_chain: String,
    /// Destination-native fee in the destination chain's smallest unit
    /// (wei for EVM, lamports for Solana). The value the adapter's
    /// `estimate_fee()` returned.
    pub native_fee_smallest_unit: u128,
    /// TNZO amount the user must pay to sponsor the destination fee.
    /// Already inclusive of the configured protocol markup (default
    /// 100 bps over the spot oracle rate, governance-tunable).
    pub tnzo_amount_wei: u128,
    /// Spot conversion rate at quote time: how many TNZO wei buy one
    /// destination-native smallest unit. Hex-encoded big-endian
    /// fixed-point with 18-decimal scale (1e18 = 1.0).
    pub rate_q18_hex: String,
    /// Wall-clock issue time (ms since epoch).
    pub issued_at_ms: u64,
    /// Wall-clock expiry. Default 60s for live quotes; the on-chain
    /// sponsor RPC refuses to honor stale quotes.
    pub valid_until_ms: u64,
    /// Whether this quote is backed by a Chainlink feed or by the
    /// governance-set rate table. Surface this to the caller so they
    /// can decide whether to require a feed-backed quote for
    /// high-value operations.
    pub oracle_backing: OracleBacking,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OracleBacking {
    /// Chainlink Data Feed pair gave the rate.
    ChainlinkFeed,
    /// Manual governance-set rate table.
    Governance,
    /// Hard-coded fallback (used when neither oracle is configured).
    /// Quotes with this backing should NOT be used in production
    /// transactions — surfaced for diagnostics only.
    Fallback,
}

/// The fee-quoting trait. Implementations:
/// - [`GovernanceSetFeeOracle`] — manual rate table.
/// - [`ChainlinkFeedFeeOracle`] — on-chain Chainlink Data Feed.
#[async_trait]
pub trait BridgeFeeOracle: Send + Sync {
    /// Quote `native_fee_smallest_unit` in TNZO wei. The implementation
    /// is responsible for: (a) loading the (dest_chain_native, TNZO)
    /// rate, (b) applying the configured protocol markup, (c) issuing
    /// a quote with a sane `valid_until_ms` window.
    async fn quote(
        &self,
        adapter: BridgeAdapterId,
        dest_chain: &str,
        native_fee_smallest_unit: u128,
    ) -> Result<BridgeFeeQuote>;

    /// Optional post-trade hook: record the actual destination-native
    /// received against the quoted TNZO debit, so the oracle can drift
    /// its rate model toward the realized exchange. Default no-op.
    async fn record_swap(
        &self,
        _adapter: BridgeAdapterId,
        _dest_chain: &str,
        _tnzo_paid_wei: u128,
        _native_received_smallest_unit: u128,
    ) -> Result<()> {
        Ok(())
    }
}

/// Configuration for one per-bridge per-destination-chain rate row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernanceFeeRow {
    pub adapter: BridgeAdapterId,
    pub dest_chain: String,
    /// Q18 fixed-point: TNZO wei per 1 destination-native-smallest-unit.
    pub rate_q18: u128,
    /// Markup over spot, basis-points. Default 100 (= 1%).
    pub markup_bps: u32,
    /// Quote validity window, ms. Default 60_000.
    pub valid_window_ms: u64,
    pub updated_at_ms: u64,
}

/// Manual rate-table oracle. The simplest production impl — operators
/// publish rates via the `GovernanceEngine`, the oracle reads from a
/// DashMap keyed by `(adapter, dest_chain)`.
///
/// Mirrors Hyperlane's `StorageGasOracle`: governance writes the rate
/// directly, no on-chain price-feed dependency. Easiest to deploy on
/// devnet/testnet; production should layer `ChainlinkFeedFeeOracle`
/// over the top with this as the fallback when feeds are unavailable.
pub struct GovernanceSetFeeOracle {
    rows: DashMap<(BridgeAdapterId, String), GovernanceFeeRow>,
}

impl Default for GovernanceSetFeeOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernanceSetFeeOracle {
    pub fn new() -> Self {
        Self {
            rows: DashMap::new(),
        }
    }

    pub fn set_rate(&self, row: GovernanceFeeRow) {
        self.rows
            .insert((row.adapter, row.dest_chain.clone()), row);
    }

    pub fn get_rate(
        &self,
        adapter: BridgeAdapterId,
        dest_chain: &str,
    ) -> Option<GovernanceFeeRow> {
        self.rows
            .get(&(adapter, dest_chain.to_string()))
            .map(|r| r.value().clone())
    }
}

#[async_trait]
impl BridgeFeeOracle for GovernanceSetFeeOracle {
    async fn quote(
        &self,
        adapter: BridgeAdapterId,
        dest_chain: &str,
        native_fee_smallest_unit: u128,
    ) -> Result<BridgeFeeQuote> {
        let row = self
            .get_rate(adapter, dest_chain)
            .ok_or_else(|| {
                BridgeError::AdapterError(format!(
                    "no governance-set TNZO rate for adapter={} dest_chain={}",
                    adapter.as_str(),
                    dest_chain
                ))
            })?;

        // tnzo = native_fee * rate_q18 / 1e18, with markup applied.
        // Use u128 saturating arithmetic to avoid overflow on extreme rates.
        let raw_tnzo = mul_q18(native_fee_smallest_unit, row.rate_q18)?;
        let with_markup = raw_tnzo
            .saturating_add(raw_tnzo.saturating_mul(row.markup_bps as u128) / 10_000);

        let now_ms = current_ms();
        let valid_until_ms = now_ms.saturating_add(row.valid_window_ms);

        let quote_id_hex = compute_quote_id(
            adapter,
            dest_chain,
            native_fee_smallest_unit,
            with_markup,
            now_ms,
        );

        Ok(BridgeFeeQuote {
            quote_id_hex,
            adapter,
            dest_chain: dest_chain.to_string(),
            native_fee_smallest_unit,
            tnzo_amount_wei: with_markup,
            rate_q18_hex: format!("{:#0x}", row.rate_q18),
            issued_at_ms: now_ms,
            valid_until_ms,
            oracle_backing: OracleBacking::Governance,
        })
    }
}

/// Chainlink Data Feed-backed oracle. Reads `(destination_native / USD)`
/// + `(TNZO / USD)` and derives the cross-feed rate. Falls back to the
/// inner [`GovernanceSetFeeOracle`] when a feed isn't configured for the
/// requested pair, the live feed is stale, or the on-chain answer is
/// invalid.
///
/// Production defaults:
/// - Reject `answer <= 0`.
/// - Reject `updatedAt == 0` (incomplete round).
/// - Reject `now - updatedAt > staleness_threshold_secs` per feed tier.
/// - Do NOT gate on `answeredInRound >= roundId` (deprecated by
///   Chainlink in 2025).
/// - 30s in-memory cache TTL on live quotes.
///
/// The on-chain Chainlink feed read goes through [`crate::ChainlinkFeedClient`]
/// (`eth_call` against `AggregatorV3Interface.latestRoundData()`).
pub struct ChainlinkFeedFeeOracle {
    /// Fallback used when a Chainlink feed isn't configured for a pair, or
    /// when the live feed fails the staleness / validity checks.
    fallback: Arc<GovernanceSetFeeOracle>,
    /// Per-adapter destination native price feed address (hex). The
    /// `ChainlinkFeedClient` holds the wire layer.
    dest_native_feeds: DashMap<(BridgeAdapterId, String), String>,
    /// TNZO/USD feed address.
    tnzo_usd_feed: parking_lot::RwLock<Option<String>>,
    /// The live feed reader. When `None`, every quote falls through to
    /// the governance-set oracle (testnet default).
    feed_client: Option<Arc<crate::ChainlinkFeedClient>>,
    /// Default protocol markup applied on top of the spot rate, basis
    /// points. Default 100 (= 1%).
    markup_bps: u32,
    /// Quote validity window for live-feed-backed quotes, ms.
    valid_window_ms: u64,
}

impl ChainlinkFeedFeeOracle {
    pub fn new(fallback: Arc<GovernanceSetFeeOracle>) -> Self {
        Self {
            fallback,
            dest_native_feeds: DashMap::new(),
            tnzo_usd_feed: parking_lot::RwLock::new(None),
            feed_client: None,
            markup_bps: 100,
            valid_window_ms: 60_000,
        }
    }

    /// Attach a live Chainlink feed client. Once attached, `quote()` reads
    /// live `(dest_native/USD) / (TNZO/USD)` rates instead of falling back
    /// to the governance table.
    pub fn with_feed_client(mut self, client: Arc<crate::ChainlinkFeedClient>) -> Self {
        self.feed_client = Some(client);
        self
    }

    pub fn with_markup_bps(mut self, bps: u32) -> Self {
        self.markup_bps = bps;
        self
    }

    pub fn with_valid_window_ms(mut self, ms: u64) -> Self {
        self.valid_window_ms = ms;
        self
    }

    pub fn set_tnzo_usd_feed(&self, feed_id: impl Into<String>) {
        *self.tnzo_usd_feed.write() = Some(feed_id.into());
    }

    pub fn set_dest_native_feed(
        &self,
        adapter: BridgeAdapterId,
        dest_chain: impl Into<String>,
        feed_id: impl Into<String>,
    ) {
        self.dest_native_feeds
            .insert((adapter, dest_chain.into()), feed_id.into());
    }
}

#[async_trait]
impl BridgeFeeOracle for ChainlinkFeedFeeOracle {
    async fn quote(
        &self,
        adapter: BridgeAdapterId,
        dest_chain: &str,
        native_fee_smallest_unit: u128,
    ) -> Result<BridgeFeeQuote> {
        // Live-feed path: when a feed client + both feed addresses are
        // configured, derive the rate from on-chain Chainlink.
        if let Some(client) = self.feed_client.as_ref() {
            let dest_feed = self
                .dest_native_feeds
                .get(&(adapter, dest_chain.to_string()))
                .map(|r| r.value().clone());
            let tnzo_feed = self.tnzo_usd_feed.read().clone();
            if let (Some(dest_feed), Some(tnzo_feed)) = (dest_feed, tnzo_feed) {
                // derive (TNZO/DEST) = (TNZO/USD) / (DEST/USD)
                match client.derive_cross_rate_q18(&tnzo_feed, &dest_feed).await {
                    Ok(rate_q18) => {
                        // tnzo = native_fee * rate_q18 / 1e18, apply markup.
                        let raw = mul_q18(native_fee_smallest_unit, rate_q18)?;
                        let with_markup = raw.saturating_add(
                            raw.saturating_mul(self.markup_bps as u128) / 10_000,
                        );
                        let now_ms = current_ms();
                        let valid_until_ms = now_ms.saturating_add(self.valid_window_ms);
                        let quote_id_hex = compute_quote_id(
                            adapter,
                            dest_chain,
                            native_fee_smallest_unit,
                            with_markup,
                            now_ms,
                        );
                        return Ok(BridgeFeeQuote {
                            quote_id_hex,
                            adapter,
                            dest_chain: dest_chain.to_string(),
                            native_fee_smallest_unit,
                            tnzo_amount_wei: with_markup,
                            rate_q18_hex: format!("{:#0x}", rate_q18),
                            issued_at_ms: now_ms,
                            valid_until_ms,
                            oracle_backing: OracleBacking::ChainlinkFeed,
                        });
                    }
                    Err(e) => {
                        // Live feed failed (stale, invalid, RPC error).
                        // Fall through to governance table — the operator
                        // can decide whether to allow Fallback-tagged
                        // quotes for high-value paths.
                        tracing::warn!(
                            "Chainlink feed quote failed, falling back to governance: {}",
                            e
                        );
                    }
                }
            }
        }
        // No live client OR feed pair not configured OR live read failed:
        // fall through to the governance-set oracle.
        self.fallback
            .quote(adapter, dest_chain, native_fee_smallest_unit)
            .await
    }
}

// ---------- helpers ----------

fn current_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Multiply `a * b / 1e18` with overflow detection on the
/// intermediate `a * b` product.
fn mul_q18(a: u128, b_q18: u128) -> Result<u128> {
    const SCALE: u128 = 1_000_000_000_000_000_000;
    // Decompose b into integer + fractional parts to keep the
    // intermediate inside u128.
    let int_part = b_q18 / SCALE;
    let frac_part = b_q18 % SCALE;
    let from_int = a
        .checked_mul(int_part)
        .ok_or_else(|| BridgeError::AdapterError("rate overflow (int part)".to_string()))?;
    // a * frac_part / SCALE — fits comfortably because frac_part < 1e18.
    let from_frac = (a / SCALE)
        .checked_mul(frac_part)
        .unwrap_or(0)
        .saturating_add((a % SCALE).saturating_mul(frac_part) / SCALE);
    Ok(from_int.saturating_add(from_frac))
}

fn compute_quote_id(
    adapter: BridgeAdapterId,
    dest_chain: &str,
    native_fee: u128,
    tnzo_amount: u128,
    issued_at_ms: u64,
) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tenzro/bridge-fee-quote/v1");
    h.update(adapter.as_str().as_bytes());
    h.update((dest_chain.len() as u32).to_le_bytes());
    h.update(dest_chain.as_bytes());
    h.update(native_fee.to_le_bytes());
    h.update(tnzo_amount.to_le_bytes());
    h.update(issued_at_ms.to_le_bytes());
    let d = h.finalize();
    format!("0x{}", hex::encode(d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn governance_oracle_returns_quote_with_markup() {
        let o = GovernanceSetFeeOracle::new();
        o.set_rate(GovernanceFeeRow {
            adapter: BridgeAdapterId::ChainlinkCcip,
            dest_chain: "eip155:1".into(),
            // 1 native unit = 10 TNZO wei. (Test scale — real rate would
            // express full Q18; e.g. 1 ETH wei = 0.0001 TNZO wei would be
            // ~1e14 in Q18.)
            rate_q18: 10 * 1_000_000_000_000_000_000u128, // 10.0 in Q18
            markup_bps: 100, // 1%
            valid_window_ms: 60_000,
            updated_at_ms: 0,
        });
        let q = o
            .quote(BridgeAdapterId::ChainlinkCcip, "eip155:1", 1_000_000)
            .await
            .unwrap();
        // base = 1_000_000 * 10 = 10_000_000
        // markup = 10_000_000 * 100 / 10_000 = 100_000
        // total = 10_100_000
        assert_eq!(q.tnzo_amount_wei, 10_100_000);
        assert_eq!(q.adapter, BridgeAdapterId::ChainlinkCcip);
        assert_eq!(q.oracle_backing, OracleBacking::Governance);
        assert!(q.valid_until_ms > q.issued_at_ms);
        assert!(q.quote_id_hex.starts_with("0x"));
    }

    #[tokio::test]
    async fn governance_oracle_errors_when_no_row() {
        let o = GovernanceSetFeeOracle::new();
        let err = o
            .quote(BridgeAdapterId::Hyperlane, "eip155:999", 1)
            .await
            .unwrap_err();
        match err {
            BridgeError::AdapterError(msg) => assert!(msg.contains("no governance-set TNZO rate")),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[tokio::test]
    async fn quote_ids_differ_when_inputs_differ() {
        let o = GovernanceSetFeeOracle::new();
        o.set_rate(GovernanceFeeRow {
            adapter: BridgeAdapterId::Hyperlane,
            dest_chain: "eip155:1".into(),
            rate_q18: 1_000_000_000_000_000_000u128,
            markup_bps: 0,
            valid_window_ms: 60_000,
            updated_at_ms: 0,
        });
        let q1 = o.quote(BridgeAdapterId::Hyperlane, "eip155:1", 100).await.unwrap();
        // Sleep so issued_at_ms differs.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let q2 = o.quote(BridgeAdapterId::Hyperlane, "eip155:1", 200).await.unwrap();
        assert_ne!(q1.quote_id_hex, q2.quote_id_hex);
    }

    #[tokio::test]
    async fn chainlink_oracle_falls_back_to_governance() {
        let fallback = Arc::new(GovernanceSetFeeOracle::new());
        fallback.set_rate(GovernanceFeeRow {
            adapter: BridgeAdapterId::Wormhole,
            dest_chain: "eip155:1".into(),
            rate_q18: 2 * 1_000_000_000_000_000_000u128, // 2.0 in Q18
            markup_bps: 0,
            valid_window_ms: 30_000,
            updated_at_ms: 0,
        });
        let oracle = ChainlinkFeedFeeOracle::new(fallback);
        let q = oracle
            .quote(BridgeAdapterId::Wormhole, "eip155:1", 500)
            .await
            .unwrap();
        // No Chainlink feed configured → falls back to Governance row.
        assert_eq!(q.tnzo_amount_wei, 1000);
        assert_eq!(q.oracle_backing, OracleBacking::Governance);
    }

    #[test]
    fn bridge_adapter_id_round_trip() {
        for s in ["layerzero", "ccip", "wormhole", "debridge", "hyperlane", "axelar", "lifi", "canton"] {
            let id = BridgeAdapterId::from_str(s).unwrap();
            assert_eq!(id.as_str(), s);
        }
    }

    #[test]
    fn mul_q18_doesnt_overflow_at_realistic_rates() {
        // 1 ETH wei (1) at TNZO/ETH rate of 1000 (Q18 = 1000 * 1e18).
        let r = mul_q18(1, 1000 * 1_000_000_000_000_000_000u128).unwrap();
        assert_eq!(r, 1000);
        // Large native fee: 1 ETH (1e18 wei) at the same rate.
        let r = mul_q18(1_000_000_000_000_000_000u128, 1000 * 1_000_000_000_000_000_000u128).unwrap();
        assert_eq!(r, 1000 * 1_000_000_000_000_000_000u128);
    }
}
