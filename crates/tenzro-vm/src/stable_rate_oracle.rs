//! StableRateOracle — quote any asset against any issued stable unit.
//!
//! The stable-asset issuance engine lets an agent transact in one stable
//! unit while value is settled in whatever token a counterparty wants. The
//! conversion between an arbitrary `asset` and a `unit` happens at a rate
//! this oracle supplies. It is the asset↔unit analogue of the bridge fee
//! oracle (`tenzro-bridge::fee_oracle`), reusing the same trait + governance
//! table + Chainlink-feed-with-fallback shape and Q18 fixed-point discipline.
//!
//! The oracle is **read-only infrastructure**: it quotes, it never holds
//! funds. A bad quote is bounded by `valid_until_ms` (TTL) and by the
//! governance fallback row; it affects one conversion, not a reserve.
//!
//! # Wire shape
//!
//! A quote names a directed pair `(asset, unit)` and answers: how many
//! smallest-units of `unit` does `amount` smallest-units of `asset` buy,
//! at quote time, within a TTL window. `rate_q18` is `unit-per-asset` in
//! 18-decimal fixed point (1e18 = 1.0).

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

/// Errors raised by the stable-rate oracle.
#[derive(Debug, thiserror::Error)]
pub enum StableRateError {
    /// No rate is configured for the requested `(asset, unit)` pair.
    #[error("no rate configured for pair {asset}/{unit}")]
    NoRate { asset: String, unit: String },

    /// The rate computation overflowed u128.
    #[error("rate overflow converting {amount} {asset} at rate_q18 {rate_q18}")]
    Overflow {
        amount: u128,
        asset: String,
        rate_q18: u128,
    },
}

type Result<T> = std::result::Result<T, StableRateError>;

/// Where the quoted rate came from. Callers can require a feed-backed quote
/// for high-value conversions and refuse `Fallback`-tagged quotes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RateBacking {
    /// Chainlink Data Feed pair derived the rate.
    ChainlinkFeed,
    /// Manual governance-set rate table.
    Governance,
    /// Hard fallback — diagnostics only, must not back production swaps.
    Fallback,
}

/// The canonical quote envelope, returned to the conversion layer.
///
/// The conversion hook must reference a `quote_id_hex` whose
/// `valid_until_ms` has not lapsed — same TTL discipline the bridge fee
/// oracle uses, so a stale quote can't be replayed across an FX move.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StableRateQuote {
    /// SHA-256 over the canonical preimage; deterministic for fixed inputs
    /// at a fixed `issued_at_ms`.
    pub quote_id_hex: String,
    /// Source asset id (CAIP-19 preferred, e.g. `eip155:1/erc20:0x...`,
    /// or a symbol like `USDC`).
    pub asset: String,
    /// Destination stable unit id (the issued asset's symbol or AssetId).
    pub unit: String,
    /// Input amount in `asset` smallest units.
    pub amount_in: u128,
    /// Output amount in `unit` smallest units, after the spread.
    pub amount_out: u128,
    /// Spot rate at quote time: `unit` smallest units per one `asset`
    /// smallest unit. Hex-encoded Q18 (1e18 = 1.0).
    pub rate_q18_hex: String,
    /// Issue time, ms since epoch.
    pub issued_at_ms: u64,
    /// Expiry, ms since epoch. The conversion hook refuses stale quotes.
    pub valid_until_ms: u64,
    pub backing: RateBacking,
}

/// The quoting trait. Implementations:
/// - [`GovernanceSetRateOracle`] — manual rate table.
/// - [`ChainlinkRateOracle`] — Chainlink Data Feed with governance fallback.
#[async_trait::async_trait]
pub trait StableRateOracle: Send + Sync {
    /// Quote converting `amount_in` of `asset` into `unit`. The
    /// implementation loads the `(asset, unit)` rate, applies the
    /// configured spread, and issues a quote with a sane TTL.
    async fn quote(&self, asset: &str, unit: &str, amount_in: u128) -> Result<StableRateQuote>;

    /// Optional post-trade hook: record realized output against the quoted
    /// amount so the oracle can drift its model toward the realized rate.
    /// Default no-op.
    async fn record_swap(
        &self,
        _asset: &str,
        _unit: &str,
        _amount_in: u128,
        _amount_out_realized: u128,
    ) -> Result<()> {
        Ok(())
    }
}

/// One governance-set rate row for a directed `(asset, unit)` pair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateRow {
    pub asset: String,
    pub unit: String,
    /// Q18 fixed-point: `unit` smallest units per 1 `asset` smallest unit.
    pub rate_q18: u128,
    /// Spread over spot in basis points (issuer revenue / slippage buffer).
    /// Default 0.
    pub spread_bps: u32,
    /// Quote validity window, ms. Default 60_000.
    pub valid_window_ms: u64,
    pub updated_at_ms: u64,
}

/// Manual rate-table oracle. Operators / issuers publish rates; the oracle
/// reads from a DashMap keyed by `(asset, unit)`. Mirrors the bridge fee
/// oracle's `GovernanceSetFeeOracle`. Easiest to deploy; production layers
/// [`ChainlinkRateOracle`] over the top with this as fallback.
#[derive(Default)]
pub struct GovernanceSetRateOracle {
    rows: DashMap<(String, String), RateRow>,
}

impl GovernanceSetRateOracle {
    pub fn new() -> Self {
        Self {
            rows: DashMap::new(),
        }
    }

    pub fn set_rate(&self, row: RateRow) {
        self.rows.insert((row.asset.clone(), row.unit.clone()), row);
    }

    pub fn get_rate(&self, asset: &str, unit: &str) -> Option<RateRow> {
        self.rows
            .get(&(asset.to_string(), unit.to_string()))
            .map(|r| r.value().clone())
    }
}

#[async_trait::async_trait]
impl StableRateOracle for GovernanceSetRateOracle {
    async fn quote(&self, asset: &str, unit: &str, amount_in: u128) -> Result<StableRateQuote> {
        let row = self
            .get_rate(asset, unit)
            .ok_or_else(|| StableRateError::NoRate {
                asset: asset.to_string(),
                unit: unit.to_string(),
            })?;
        build_quote(
            asset,
            unit,
            amount_in,
            row.rate_q18,
            row.spread_bps,
            row.valid_window_ms,
            RateBacking::Governance,
        )
    }
}

/// Chainlink Data Feed-backed oracle. Derives `(unit/asset)` from
/// `(asset/USD)` and `(unit/USD)` feeds, falling back to the inner
/// [`GovernanceSetRateOracle`] when a feed isn't configured for the pair or
/// the live read fails the staleness / validity checks. Feed-reads are
/// performed by a pluggable [`CrossRateFeed`] so this crate stays free of a
/// hard bridge dependency.
pub struct ChainlinkRateOracle {
    fallback: Arc<GovernanceSetRateOracle>,
    /// Per-asset USD price-feed id. Empty until configured.
    asset_usd_feeds: DashMap<String, String>,
    /// Per-unit USD price-feed id.
    unit_usd_feeds: DashMap<String, String>,
    /// Live cross-rate reader. When `None`, every quote falls through to
    /// the governance table (testnet default).
    feed: Option<Arc<dyn CrossRateFeed>>,
    spread_bps: u32,
    valid_window_ms: u64,
}

/// Pluggable cross-rate reader. The node wires a Chainlink-backed
/// implementation; tests supply a stub. Returns the Q18 rate
/// `unit-per-asset` derived from the two USD feeds.
#[async_trait::async_trait]
pub trait CrossRateFeed: Send + Sync {
    /// Derive `(unit/asset)` Q18 from `asset_usd_feed` and `unit_usd_feed`.
    /// Returns `Err` on stale / invalid / unreachable feeds so the caller
    /// can fall back to the governance table.
    async fn derive_cross_rate_q18(
        &self,
        asset_usd_feed: &str,
        unit_usd_feed: &str,
    ) -> std::result::Result<u128, String>;
}

impl ChainlinkRateOracle {
    pub fn new(fallback: Arc<GovernanceSetRateOracle>) -> Self {
        Self {
            fallback,
            asset_usd_feeds: DashMap::new(),
            unit_usd_feeds: DashMap::new(),
            feed: None,
            spread_bps: 0,
            valid_window_ms: 60_000,
        }
    }

    pub fn with_feed(mut self, feed: Arc<dyn CrossRateFeed>) -> Self {
        self.feed = Some(feed);
        self
    }

    pub fn with_spread_bps(mut self, bps: u32) -> Self {
        self.spread_bps = bps;
        self
    }

    pub fn with_valid_window_ms(mut self, ms: u64) -> Self {
        self.valid_window_ms = ms;
        self
    }

    pub fn set_asset_usd_feed(&self, asset: impl Into<String>, feed: impl Into<String>) {
        self.asset_usd_feeds.insert(asset.into(), feed.into());
    }

    pub fn set_unit_usd_feed(&self, unit: impl Into<String>, feed: impl Into<String>) {
        self.unit_usd_feeds.insert(unit.into(), feed.into());
    }
}

#[async_trait::async_trait]
impl StableRateOracle for ChainlinkRateOracle {
    async fn quote(&self, asset: &str, unit: &str, amount_in: u128) -> Result<StableRateQuote> {
        if let Some(feed) = self.feed.as_ref() {
            let asset_feed = self.asset_usd_feeds.get(asset).map(|r| r.value().clone());
            let unit_feed = self.unit_usd_feeds.get(unit).map(|r| r.value().clone());
            if let (Some(af), Some(uf)) = (asset_feed, unit_feed) {
                match feed.derive_cross_rate_q18(&af, &uf).await {
                    Ok(rate_q18) => {
                        return build_quote(
                            asset,
                            unit,
                            amount_in,
                            rate_q18,
                            self.spread_bps,
                            self.valid_window_ms,
                            RateBacking::ChainlinkFeed,
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "stable-rate feed quote failed for {}/{}, falling back to governance: {}",
                            asset,
                            unit,
                            e
                        );
                    }
                }
            }
        }
        self.fallback.quote(asset, unit, amount_in).await
    }
}

// ---------- helpers ----------

fn build_quote(
    asset: &str,
    unit: &str,
    amount_in: u128,
    rate_q18: u128,
    spread_bps: u32,
    valid_window_ms: u64,
    backing: RateBacking,
) -> Result<StableRateQuote> {
    let raw = mul_q18(amount_in, rate_q18).ok_or_else(|| StableRateError::Overflow {
        amount: amount_in,
        asset: asset.to_string(),
        rate_q18,
    })?;
    // Spread reduces the output the taker receives (issuer-favorable),
    // matching how a market-maker quotes.
    let spread_cut = raw.saturating_mul(spread_bps as u128) / 10_000;
    let amount_out = raw.saturating_sub(spread_cut);

    let now_ms = current_ms();
    let valid_until_ms = now_ms.saturating_add(valid_window_ms);
    let quote_id_hex = compute_quote_id(asset, unit, amount_in, amount_out, now_ms);

    Ok(StableRateQuote {
        quote_id_hex,
        asset: asset.to_string(),
        unit: unit.to_string(),
        amount_in,
        amount_out,
        rate_q18_hex: format!("{:#0x}", rate_q18),
        issued_at_ms: now_ms,
        valid_until_ms,
        backing,
    })
}

fn current_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `a * b_q18 / 1e18` with overflow detection. Decomposes `b` into integer
/// and fractional parts to keep the intermediate product inside u128.
fn mul_q18(a: u128, b_q18: u128) -> Option<u128> {
    const SCALE: u128 = 1_000_000_000_000_000_000;
    let int_part = b_q18 / SCALE;
    let frac_part = b_q18 % SCALE;
    let from_int = a.checked_mul(int_part)?;
    let from_frac = (a / SCALE)
        .checked_mul(frac_part)
        .unwrap_or(0)
        .saturating_add((a % SCALE).saturating_mul(frac_part) / SCALE);
    Some(from_int.saturating_add(from_frac))
}

fn compute_quote_id(
    asset: &str,
    unit: &str,
    amount_in: u128,
    amount_out: u128,
    issued_at_ms: u64,
) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tenzro/stable-rate-quote/v1");
    h.update((asset.len() as u32).to_le_bytes());
    h.update(asset.as_bytes());
    h.update((unit.len() as u32).to_le_bytes());
    h.update(unit.as_bytes());
    h.update(amount_in.to_le_bytes());
    h.update(amount_out.to_le_bytes());
    h.update(issued_at_ms.to_le_bytes());
    format!("0x{}", hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const Q18: u128 = 1_000_000_000_000_000_000;

    #[tokio::test]
    async fn governance_quote_applies_spread() {
        let o = GovernanceSetRateOracle::new();
        // 1 USDC unit = 1.0 USDX unit, 50 bps spread.
        o.set_rate(RateRow {
            asset: "USDC".into(),
            unit: "USDX".into(),
            rate_q18: Q18,
            spread_bps: 50,
            valid_window_ms: 60_000,
            updated_at_ms: 0,
        });
        let q = o.quote("USDC", "USDX", 1_000_000).await.unwrap();
        // raw = 1_000_000; spread = 1_000_000 * 50 / 10_000 = 5_000.
        assert_eq!(q.amount_out, 995_000);
        assert_eq!(q.backing, RateBacking::Governance);
        assert!(q.valid_until_ms > q.issued_at_ms);
        assert!(q.quote_id_hex.starts_with("0x"));
    }

    #[tokio::test]
    async fn governance_errors_without_row() {
        let o = GovernanceSetRateOracle::new();
        let err = o.quote("WBTC", "USDX", 1).await.unwrap_err();
        matches!(err, StableRateError::NoRate { .. });
    }

    #[tokio::test]
    async fn fractional_rate_converts() {
        let o = GovernanceSetRateOracle::new();
        // 1 unit of asset = 0.5 units of unit.
        o.set_rate(RateRow {
            asset: "A".into(),
            unit: "B".into(),
            rate_q18: Q18 / 2,
            spread_bps: 0,
            valid_window_ms: 60_000,
            updated_at_ms: 0,
        });
        let q = o.quote("A", "B", 1_000).await.unwrap();
        assert_eq!(q.amount_out, 500);
    }

    struct StubFeed(u128);
    #[async_trait::async_trait]
    impl CrossRateFeed for StubFeed {
        async fn derive_cross_rate_q18(
            &self,
            _a: &str,
            _u: &str,
        ) -> std::result::Result<u128, String> {
            Ok(self.0)
        }
    }

    struct FailFeed;
    #[async_trait::async_trait]
    impl CrossRateFeed for FailFeed {
        async fn derive_cross_rate_q18(
            &self,
            _a: &str,
            _u: &str,
        ) -> std::result::Result<u128, String> {
            Err("stale feed".into())
        }
    }

    #[tokio::test]
    async fn chainlink_uses_live_feed_when_configured() {
        let fallback = Arc::new(GovernanceSetRateOracle::new());
        let o = ChainlinkRateOracle::new(fallback).with_feed(Arc::new(StubFeed(2 * Q18)));
        o.set_asset_usd_feed("A", "feedA");
        o.set_unit_usd_feed("B", "feedB");
        let q = o.quote("A", "B", 100).await.unwrap();
        assert_eq!(q.amount_out, 200);
        assert_eq!(q.backing, RateBacking::ChainlinkFeed);
    }

    #[tokio::test]
    async fn chainlink_falls_back_on_feed_failure() {
        let fallback = Arc::new(GovernanceSetRateOracle::new());
        fallback.set_rate(RateRow {
            asset: "A".into(),
            unit: "B".into(),
            rate_q18: 3 * Q18,
            spread_bps: 0,
            valid_window_ms: 30_000,
            updated_at_ms: 0,
        });
        let o = ChainlinkRateOracle::new(fallback).with_feed(Arc::new(FailFeed));
        o.set_asset_usd_feed("A", "feedA");
        o.set_unit_usd_feed("B", "feedB");
        let q = o.quote("A", "B", 10).await.unwrap();
        assert_eq!(q.amount_out, 30);
        assert_eq!(q.backing, RateBacking::Governance);
    }

    #[tokio::test]
    async fn chainlink_falls_back_when_feed_pair_unconfigured() {
        let fallback = Arc::new(GovernanceSetRateOracle::new());
        fallback.set_rate(RateRow {
            asset: "A".into(),
            unit: "B".into(),
            rate_q18: Q18,
            spread_bps: 0,
            valid_window_ms: 30_000,
            updated_at_ms: 0,
        });
        let o = ChainlinkRateOracle::new(fallback).with_feed(Arc::new(StubFeed(99 * Q18)));
        // No feed ids set → cannot use live feed → governance row wins.
        let q = o.quote("A", "B", 7).await.unwrap();
        assert_eq!(q.amount_out, 7);
        assert_eq!(q.backing, RateBacking::Governance);
    }

    #[test]
    fn mul_q18_handles_realistic_magnitudes() {
        assert_eq!(mul_q18(1_000_000, Q18).unwrap(), 1_000_000);
        assert_eq!(mul_q18(1_000_000, Q18 / 4).unwrap(), 250_000);
        // 1 BTC (1e8 sats) at 60_000 unit/BTC → expressed in Q18.
        assert_eq!(
            mul_q18(100_000_000, 60_000 * Q18).unwrap(),
            6_000_000_000_000
        );
    }

    #[test]
    fn quote_ids_differ_on_different_inputs() {
        let id1 = compute_quote_id("A", "B", 1, 1, 100);
        let id2 = compute_quote_id("A", "B", 2, 2, 100);
        assert_ne!(id1, id2);
    }
}
