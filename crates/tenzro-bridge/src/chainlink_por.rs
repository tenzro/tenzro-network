//! Chainlink Proof-of-Reserve pull adapter.
//!
//! Reads PoR aggregator feeds (same `AggregatorV3Interface.latestRoundData()`
//! wire shape as price feeds — selector `0xfeaf968c`) and projects the decoded
//! reserve into a [`PorAttestationInput`] that the node layer feeds into the
//! Secure-Mint attestation path (`tenzro-vm::secure_mint`). This closes the
//! pull side of the `por_feed_id = "chainlink:<feed>"` contract: attestations
//! no longer have to be push-only.
//!
//! Fail-closed throughout: an unregistered asset, a negative or
//! u128-overflowing `int256` answer, an incomplete round (`updatedAt == 0`),
//! or a reading older than the per-feed `max_staleness_secs` all reject with
//! a typed [`PorError`].

use crate::chainlink_feed::{u64_from_be_32, u128_from_be_32, SELECTOR_LATEST_ROUND_DATA};
use crate::error::BridgeError;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use thiserror::Error;

/// Typed failures of the PoR pull path.
#[derive(Debug, Error)]
pub enum PorError {
    /// No feed is registered for the asset — the read rejects instead of
    /// silently returning nothing.
    #[error("no PoR feed registered for asset {0}")]
    NotConfigured(String),

    /// The aggregator answered with a negative `int256` reserve.
    #[error("PoR feed {feed} returned negative answer")]
    NegativeAnswer { feed: String },

    /// The `int256` answer does not fit in `u128`.
    #[error("PoR feed {feed} answer exceeds u128 range")]
    AnswerOutOfRange { feed: String },

    /// `updatedAt == 0` — the round never completed.
    #[error("PoR feed {feed} round incomplete (updatedAt == 0)")]
    IncompleteRound { feed: String },

    /// The reading is older than the feed's `max_staleness_secs`.
    #[error("PoR feed {feed} stale: updated_at {updated_at}, now {now}, max {max_staleness_secs}s")]
    Stale {
        feed: String,
        updated_at: u64,
        now: u64,
        max_staleness_secs: u64,
    },

    /// JSON-RPC transport or `eth_call` failure.
    #[error("PoR RPC failure: {0}")]
    Rpc(String),

    /// Malformed / short calldata return.
    #[error("PoR decode failure: {0}")]
    Decode(String),
}

impl From<PorError> for BridgeError {
    fn from(e: PorError) -> Self {
        BridgeError::AdapterError(e.to_string())
    }
}

/// Per-asset PoR feed registration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PorFeedConfig {
    /// AggregatorV3 proxy address (`0x...` hex).
    pub aggregator_address: String,
    /// CAIP-2 chain identifier of the chain the aggregator lives on
    /// (e.g. `eip155:1`).
    pub chain_caip2: String,
    /// Feed decimals (PoR feeds report in the underlying's smallest unit
    /// scale; recorded for the node layer's unit conversion).
    pub decimals: u8,
    /// Maximum accepted reading age in seconds. Readings older than this
    /// reject with [`PorError::Stale`].
    pub max_staleness_secs: u64,
}

/// One decoded, validated PoR reading.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PorReading {
    /// Attested reserve in the feed's smallest unit (non-negative,
    /// fits u128 by construction).
    pub reserve: u128,
    /// On-chain `updatedAt` unix-seconds timestamp.
    pub updated_at: u64,
    /// Aggregator `roundId`.
    pub round_id: u128,
    /// Feed decimals copied from the registration.
    pub decimals: u8,
}

/// Projection of a [`PorReading`] into the shape the node layer feeds into
/// `SecureMintRegistry`'s attestation path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PorAttestationInput {
    pub asset_id: String,
    pub reserve: u128,
    /// Unix-seconds of the feed's last update (becomes `attested_at`).
    pub attested_at: u64,
    /// `chainlink:<aggregator_address>@<caip2>`.
    pub source: String,
}

/// Pull adapter over Chainlink PoR aggregators, keyed by Secure-Mint
/// `asset_id`.
pub struct ChainlinkPorAdapter {
    rpc_url: String,
    http: reqwest::Client,
    feeds: DashMap<String, PorFeedConfig>,
}

impl ChainlinkPorAdapter {
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client build"),
            feeds: DashMap::new(),
        }
    }

    /// Builder-style feed registration.
    pub fn with_feed(self, asset_id: impl Into<String>, config: PorFeedConfig) -> Self {
        self.feeds.insert(asset_id.into(), config);
        self
    }

    /// Register or replace the feed for `asset_id`. Returns the prior
    /// registration if one existed.
    pub fn register_feed(
        &self,
        asset_id: impl Into<String>,
        config: PorFeedConfig,
    ) -> Option<PorFeedConfig> {
        self.feeds.insert(asset_id.into(), config)
    }

    /// Snapshot the registration for `asset_id`.
    pub fn feed(&self, asset_id: &str) -> Option<PorFeedConfig> {
        self.feeds.get(asset_id).map(|e| e.value().clone())
    }

    /// Read `latestRoundData()` from the asset's PoR aggregator and validate
    /// it against the registration. Every failure path is a typed
    /// [`PorError`]; nothing degrades to a permissive default.
    pub async fn read_reserve(&self, asset_id: &str) -> Result<PorReading, PorError> {
        let config = self
            .feed(asset_id)
            .ok_or_else(|| PorError::NotConfigured(asset_id.to_string()))?;
        let bytes = self.eth_call_latest_round_data(&config.aggregator_address).await?;
        let reading = decode_por_round(&bytes, &config.aggregator_address, config.decimals)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        validate_freshness(&reading, now, &config)?;
        tracing::debug!(
            asset_id,
            feed = %config.aggregator_address,
            reserve = reading.reserve,
            updated_at = reading.updated_at,
            "PoR reading accepted"
        );
        Ok(reading)
    }

    /// Project a validated reading into the node-layer attestation input.
    /// Rejects when the asset has no registration (the `source` string is
    /// derived from it).
    pub fn to_attestation(
        &self,
        reading: &PorReading,
        asset_id: &str,
    ) -> Result<PorAttestationInput, PorError> {
        let config = self
            .feed(asset_id)
            .ok_or_else(|| PorError::NotConfigured(asset_id.to_string()))?;
        Ok(PorAttestationInput {
            asset_id: asset_id.to_string(),
            reserve: reading.reserve,
            attested_at: reading.updated_at,
            source: format!(
                "chainlink:{}@{}",
                config.aggregator_address.to_lowercase(),
                config.chain_caip2
            ),
        })
    }

    async fn eth_call_latest_round_data(&self, aggregator: &str) -> Result<Vec<u8>, PorError> {
        let calldata = format!("0x{}", hex::encode(SELECTOR_LATEST_ROUND_DATA));
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [
                { "to": aggregator, "data": calldata },
                "latest"
            ]
        });
        let resp: serde_json::Value = self
            .http
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| PorError::Rpc(format!("latestRoundData send: {}", e)))?
            .json()
            .await
            .map_err(|e| PorError::Rpc(format!("latestRoundData body: {}", e)))?;
        let result = resp
            .get("result")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PorError::Rpc("latestRoundData: no result".to_string()))?;
        hex::decode(result.trim_start_matches("0x"))
            .map_err(|e| PorError::Decode(format!("latestRoundData hex: {}", e)))
    }
}

impl std::fmt::Debug for ChainlinkPorAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainlinkPorAdapter")
            .field("rpc_url", &self.rpc_url)
            .field("feeds", &self.feeds.len())
            .finish()
    }
}

/// Decode a `latestRoundData()` return into a [`PorReading`].
///
/// Wire layout (5 × 32-byte words): `roundId | answer | startedAt |
/// updatedAt | answeredInRound`. The `int256` answer must be non-negative and
/// fit `u128`: the high 16 bytes of the answer word must be all-zero
/// (a set sign bit shows up there as `0xFF` sign extension, an oversized
/// positive value as non-zero high bytes — both reject).
pub fn decode_por_round(bytes: &[u8], feed: &str, decimals: u8) -> Result<PorReading, PorError> {
    if bytes.len() < 160 {
        return Err(PorError::Decode(format!(
            "latestRoundData: short response {} bytes",
            bytes.len()
        )));
    }
    let answer_word = &bytes[32..64];
    if (answer_word[0] & 0x80) != 0 || answer_word[..16] != [0u8; 16] {
        if (answer_word[0] & 0x80) != 0 {
            return Err(PorError::NegativeAnswer {
                feed: feed.to_string(),
            });
        }
        return Err(PorError::AnswerOutOfRange {
            feed: feed.to_string(),
        });
    }
    let reserve = u128_from_be_32(answer_word);
    let round_id = u128_from_be_32(&bytes[0..32]);
    let updated_at = u64_from_be_32(&bytes[96..128]);
    if updated_at == 0 {
        return Err(PorError::IncompleteRound {
            feed: feed.to_string(),
        });
    }
    Ok(PorReading {
        reserve,
        updated_at,
        round_id,
        decimals,
    })
}

/// Reject readings older than the feed's `max_staleness_secs`.
pub fn validate_freshness(
    reading: &PorReading,
    now: u64,
    config: &PorFeedConfig,
) -> Result<(), PorError> {
    if now.saturating_sub(reading.updated_at) > config.max_staleness_secs {
        return Err(PorError::Stale {
            feed: config.aggregator_address.clone(),
            updated_at: reading.updated_at,
            now,
            max_staleness_secs: config.max_staleness_secs,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> PorFeedConfig {
        PorFeedConfig {
            aggregator_address: "0x1111111111111111111111111111111111111111".to_string(),
            chain_caip2: "eip155:1".to_string(),
            decimals: 8,
            max_staleness_secs: 3600,
        }
    }

    /// Construct a 160-byte latestRoundData return:
    /// roundId | answer | startedAt | updatedAt | answeredInRound.
    fn round_data(round_id: u128, answer_word: [u8; 32], updated_at: u64) -> Vec<u8> {
        let mut out = vec![0u8; 160];
        out[16..32].copy_from_slice(&round_id.to_be_bytes());
        out[32..64].copy_from_slice(&answer_word);
        out[120..128].copy_from_slice(&updated_at.to_be_bytes());
        out
    }

    fn positive_answer(v: u128) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..32].copy_from_slice(&v.to_be_bytes());
        w
    }

    #[test]
    fn decodes_valid_round() {
        let bytes = round_data(7, positive_answer(1_234_567_890), 1_700_000_000);
        let r = decode_por_round(&bytes, "0xfeed", 8).unwrap();
        assert_eq!(r.round_id, 7);
        assert_eq!(r.reserve, 1_234_567_890);
        assert_eq!(r.updated_at, 1_700_000_000);
        assert_eq!(r.decimals, 8);
    }

    #[test]
    fn negative_answer_rejected() {
        // int256(-1) = all 0xFF.
        let bytes = round_data(1, [0xFF; 32], 1_700_000_000);
        assert!(matches!(
            decode_por_round(&bytes, "0xfeed", 8).unwrap_err(),
            PorError::NegativeAnswer { .. }
        ));
    }

    #[test]
    fn answer_exceeding_u128_rejected() {
        // Positive value with a non-zero byte above the low 128 bits.
        let mut w = [0u8; 32];
        w[15] = 1; // 2^128
        let bytes = round_data(1, w, 1_700_000_000);
        assert!(matches!(
            decode_por_round(&bytes, "0xfeed", 8).unwrap_err(),
            PorError::AnswerOutOfRange { .. }
        ));
    }

    #[test]
    fn incomplete_round_rejected() {
        let bytes = round_data(1, positive_answer(100), 0);
        assert!(matches!(
            decode_por_round(&bytes, "0xfeed", 8).unwrap_err(),
            PorError::IncompleteRound { .. }
        ));
    }

    #[test]
    fn short_response_rejected() {
        assert!(matches!(
            decode_por_round(&[0u8; 96], "0xfeed", 8).unwrap_err(),
            PorError::Decode(_)
        ));
    }

    #[test]
    fn staleness_rejected_past_threshold() {
        let cfg = config();
        let r = PorReading {
            reserve: 100,
            updated_at: 1_700_000_000,
            round_id: 1,
            decimals: 8,
        };
        // Exactly at threshold: fresh.
        assert!(validate_freshness(&r, 1_700_000_000 + 3600, &cfg).is_ok());
        // One past: stale.
        assert!(matches!(
            validate_freshness(&r, 1_700_000_000 + 3601, &cfg).unwrap_err(),
            PorError::Stale { .. }
        ));
    }

    #[test]
    fn unregistered_asset_fails_closed() {
        let adapter = ChainlinkPorAdapter::new("http://localhost:8545");
        let r = PorReading {
            reserve: 1,
            updated_at: 1,
            round_id: 1,
            decimals: 8,
        };
        assert!(matches!(
            adapter.to_attestation(&r, "unknown").unwrap_err(),
            PorError::NotConfigured(_)
        ));
    }

    #[test]
    fn attestation_projection_source_format() {
        let adapter = ChainlinkPorAdapter::new("http://localhost:8545")
            .with_feed("tenzro:539/erc20:0xabc", config());
        let r = PorReading {
            reserve: 42,
            updated_at: 1_700_000_000,
            round_id: 3,
            decimals: 8,
        };
        let att = adapter.to_attestation(&r, "tenzro:539/erc20:0xabc").unwrap();
        assert_eq!(att.reserve, 42);
        assert_eq!(att.attested_at, 1_700_000_000);
        assert_eq!(
            att.source,
            "chainlink:0x1111111111111111111111111111111111111111@eip155:1"
        );
    }
}
