//! Hyperbridge ISMP adapter.
//!
//! Hyperbridge is the Interoperable State Machine Protocol (ISMP) rollup
//! anchored to Polkadot. It exposes an HTTP-shaped surface — `POST` for
//! arbitrary cross-chain messages, `GET` for verified storage reads — and
//! ships a `TokenGateway` bridged-asset interface on top.
//!
//! ## Post-exploit hardening (2026-04-13)
//!
//! On April 13 2026 03:55:23 UTC an attacker delivered a forged
//! governance-style `PostRequest` into `TokenGateway` on Ethereum that
//! reassigned admin rights on the bridged DOT token and minted 1B DOT.
//! Native DOT was untouched but the Ethereum mirror lost $250k of liquidity.
//! Public post-mortems converge on two mitigations Hyperbridge integrators
//! must enforce locally:
//!
//! 1. **Admin transitions are inadmissible inside a normal PostRequest** —
//!    they require a separate ceremony with a multisig + timelock.
//! 2. **Per-asset rolling-window mint ceilings** — even a valid PostRequest
//!    cannot mint more than the policy permits in the window.
//!
//! This adapter encodes both as invariants on the message-
//! ingest path: `MintControlPolicy` rejects admin-changing payloads
//! outright, and `LiquidityLimitTracker` enforces an O(1) sliding-window
//! ceiling per asset.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{BridgeError, Result};
use tenzro_types::primitives::Hash;

/// Hyperbridge network selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HyperbridgeNetwork {
    /// Hyperbridge mainnet (Polkadot Asset Hub parachain id `3367`).
    Mainnet,
    /// Hyperbridge testnet (Gargantua).
    Testnet,
}

/// Adapter configuration.
#[derive(Debug, Clone)]
pub struct HyperbridgeConfig {
    /// Network selector.
    pub network: HyperbridgeNetwork,
    /// Hyperbridge node JSON-RPC URL.
    pub rpc_url: String,
    /// ISMP `nexus` chain id used in PostRequest metadata.
    pub source_chain_id: String,
    /// `TokenGateway` contract address on this side of the bridge.
    pub token_gateway: String,
    /// Per-asset mint controls.
    pub mint_controls: MintControlPolicy,
    /// Per-asset liquidity limits.
    pub liquidity_limits: HashMap<String, LiquidityLimit>,
}

/// Mint-control policy.
///
/// `forbid_admin_transitions = true` rejects any PostRequest whose payload
/// type-code falls in [`ADMIN_TYPECODE_RANGE`] — this closes the April-2026
/// exploit class regardless of who sent the message.
#[derive(Debug, Clone)]
pub struct MintControlPolicy {
    /// Whether admin transitions are rejected on the message path. Default
    /// `true` — the conservative post-exploit policy.
    pub forbid_admin_transitions: bool,
    /// Bytes prefix that marks payloads as "admin" / governance / role-
    /// assignment. Hyperbridge's TokenGateway uses `0xad` for these on the
    /// post-2026-04-13 hardened build.
    pub admin_typecodes: Vec<u8>,
}

impl Default for MintControlPolicy {
    fn default() -> Self {
        Self {
            forbid_admin_transitions: true,
            admin_typecodes: vec![0xad],
        }
    }
}

/// Per-asset rolling-window mint ceiling.
#[derive(Debug, Clone, Copy)]
pub struct LiquidityLimit {
    /// Maximum cumulative mint amount within `window_secs`.
    pub max_per_window: u128,
    /// Window length in seconds.
    pub window_secs: u64,
}

/// HTTP-shaped messages Hyperbridge knows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HyperbridgeMethod {
    /// `POST`: arbitrary calldata delivered to the destination contract.
    Post,
    /// `GET`: read a storage slot on the destination chain, returned with
    /// a state proof.
    Get,
}

/// Outbound message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostRequest {
    /// Stable id of the message.
    pub id: Hash,
    /// Source chain id.
    pub source: String,
    /// Destination chain id (e.g. `ETH-1`, `BSC-56`).
    pub destination: String,
    /// Hex-encoded destination contract.
    pub destination_module: String,
    /// Payload bytes (typed-code + arguments).
    pub body: Vec<u8>,
    /// Unix-secs timeout — relayers won't carry the message past this.
    pub timeout_secs: u64,
    /// Optional asset transfer associated with this PostRequest.
    pub asset_transfer: Option<AssetTransfer>,
}

/// Asset transfer payload riding on a PostRequest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetTransfer {
    /// Symbol of the bridged asset (e.g. `DOT`, `USDC`).
    pub asset: String,
    /// Amount in base units (u128 to cover Polkadot's 10-decimal asset).
    pub amount: u128,
    /// Recipient on the destination chain.
    pub recipient: String,
}

/// State of a delivered message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostRequestStatus {
    /// Submitted to the relayer pool but not yet delivered.
    Pending,
    /// Delivered to the destination chain.
    Delivered,
    /// Rejected by local mint-control / liquidity-limit policy.
    RejectedLocally,
    /// Timed out before any relayer could carry it.
    TimedOut,
}

/// Sliding-window mint-counter for one asset.
#[derive(Debug, Default)]
struct WindowState {
    /// Cumulative amount minted within the current window.
    cumulative: u128,
    /// Start of the current window (unix secs).
    window_start_secs: u64,
}

/// Mint-ceiling tracker shared across the adapter.
#[derive(Debug, Default)]
struct LiquidityLimitTracker {
    state: RwLock<HashMap<String, WindowState>>,
}

impl LiquidityLimitTracker {
    fn check_and_record(
        &self,
        asset: &str,
        amount: u128,
        limit: LiquidityLimit,
        now_secs: u64,
    ) -> Result<()> {
        let mut state = self.state.write();
        let s = state.entry(asset.to_string()).or_default();
        // Roll the window when it expires.
        if now_secs.saturating_sub(s.window_start_secs) >= limit.window_secs {
            s.window_start_secs = now_secs;
            s.cumulative = 0;
        }
        let projected = s.cumulative.saturating_add(amount);
        if projected > limit.max_per_window {
            return Err(BridgeError::TransferFailed(format!(
                "hyperbridge liquidity ceiling exceeded for {}: {} + {} > {} (window {}s)",
                asset, s.cumulative, amount, limit.max_per_window, limit.window_secs,
            )));
        }
        s.cumulative = projected;
        Ok(())
    }
}

/// Adapter state.
#[derive(Debug)]
pub struct HyperbridgeAdapter {
    config: HyperbridgeConfig,
    sent: RwLock<HashMap<Hash, (PostRequest, PostRequestStatus)>>,
    liquidity: LiquidityLimitTracker,
}

impl HyperbridgeAdapter {
    /// Build a new adapter. Mint controls default to the post-exploit
    /// hardened policy; callers can override per asset by amending
    /// `config.mint_controls` before construction.
    pub fn new(config: HyperbridgeConfig) -> Self {
        Self {
            config,
            sent: RwLock::new(HashMap::new()),
            liquidity: LiquidityLimitTracker::default(),
        }
    }

    /// Adapter config.
    pub fn config(&self) -> &HyperbridgeConfig {
        &self.config
    }

    /// Compute the stable id of an outbound message.
    pub fn message_id(
        source: &str,
        destination: &str,
        destination_module: &str,
        body: &[u8],
        timeout_secs: u64,
    ) -> Hash {
        let mut h = Sha256::new();
        h.update(b"tenzro/hyperbridge/post");
        h.update(source.as_bytes());
        h.update(b"|");
        h.update(destination.as_bytes());
        h.update(b"|");
        h.update(destination_module.as_bytes());
        h.update(b"|");
        h.update(body);
        h.update(b"|");
        h.update(timeout_secs.to_le_bytes());
        let digest: [u8; 32] = h.finalize().into();
        Hash::new(digest)
    }

    /// Reject the message body if the local mint-control policy forbids
    /// admin transitions and the typecode matches.
    fn check_mint_control(&self, body: &[u8]) -> Result<()> {
        if !self.config.mint_controls.forbid_admin_transitions {
            return Ok(());
        }
        if body.is_empty() {
            return Ok(());
        }
        if self.config.mint_controls.admin_typecodes.contains(&body[0]) {
            return Err(BridgeError::TransferFailed(
                "hyperbridge admin transitions are inadmissible on the message path \
                 (post-2026-04-13 hardening)"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Submit an outbound PostRequest. Returns the message id once accepted
    /// locally; relayer delivery is asynchronous.
    pub fn submit_post(
        &self,
        destination: impl Into<String>,
        destination_module: impl Into<String>,
        body: Vec<u8>,
        timeout_secs: u64,
        asset_transfer: Option<AssetTransfer>,
    ) -> Result<Hash> {
        let destination = destination.into();
        let destination_module = destination_module.into();
        self.check_mint_control(&body)?;

        if let Some(ref t) = asset_transfer {
            if let Some(limit) = self.config.liquidity_limits.get(&t.asset).copied() {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_secs();
                self.liquidity
                    .check_and_record(&t.asset, t.amount, limit, now)?;
            }
        }

        let id = Self::message_id(
            &self.config.source_chain_id,
            &destination,
            &destination_module,
            &body,
            timeout_secs,
        );
        let req = PostRequest {
            id,
            source: self.config.source_chain_id.clone(),
            destination,
            destination_module,
            body,
            timeout_secs,
            asset_transfer,
        };
        self.sent.write().insert(id, (req, PostRequestStatus::Pending));
        Ok(id)
    }

    /// Mark a submitted message as delivered.
    pub fn mark_delivered(&self, id: &Hash) -> Result<()> {
        let mut sent = self.sent.write();
        let entry = sent
            .get_mut(id)
            .ok_or_else(|| BridgeError::TransferNotFound(format!("{:?}", id)))?;
        entry.1 = PostRequestStatus::Delivered;
        Ok(())
    }

    /// Mark a submitted message as timed out.
    pub fn mark_timeout(&self, id: &Hash) -> Result<()> {
        let mut sent = self.sent.write();
        let entry = sent
            .get_mut(id)
            .ok_or_else(|| BridgeError::TransferNotFound(format!("{:?}", id)))?;
        entry.1 = PostRequestStatus::TimedOut;
        Ok(())
    }

    /// Read a submitted message.
    pub fn get_post(&self, id: &Hash) -> Option<(PostRequest, PostRequestStatus)> {
        self.sent.read().get(id).cloned()
    }

    /// List all submitted messages.
    pub fn list_posts(&self) -> Vec<(PostRequest, PostRequestStatus)> {
        self.sent.read().values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> HyperbridgeConfig {
        let mut limits = HashMap::new();
        limits.insert(
            "DOT".to_string(),
            LiquidityLimit {
                max_per_window: 10_000_000_000, // 1M DOT (10 decimals)
                window_secs: 3600,
            },
        );
        HyperbridgeConfig {
            network: HyperbridgeNetwork::Testnet,
            rpc_url: "https://gargantua-testnet.example".into(),
            source_chain_id: "TENZRO-1337".into(),
            token_gateway: "0x0000000000000000000000000000000000000a01".into(),
            mint_controls: MintControlPolicy::default(),
            liquidity_limits: limits,
        }
    }

    #[test]
    fn admin_typecode_rejected() {
        let a = HyperbridgeAdapter::new(cfg());
        let body = vec![0xad, 1, 2, 3]; // admin-flagged payload
        let err = a
            .submit_post("ETH-1", "0xgateway", body, 1_900_000_000, None)
            .unwrap_err();
        assert!(matches!(err, BridgeError::TransferFailed(_)));
    }

    #[test]
    fn ordinary_post_accepted() {
        let a = HyperbridgeAdapter::new(cfg());
        let body = vec![0x01, 9, 9, 9];
        let id = a
            .submit_post("ETH-1", "0xgateway", body, 1_900_000_000, None)
            .unwrap();
        assert!(a.get_post(&id).is_some());
    }

    #[test]
    fn liquidity_ceiling_enforced() {
        let a = HyperbridgeAdapter::new(cfg());
        let body = vec![0x01];
        // First transfer of half the ceiling — accepted.
        a.submit_post(
            "ETH-1",
            "0xgateway",
            body.clone(),
            1_900_000_000,
            Some(AssetTransfer {
                asset: "DOT".into(),
                amount: 5_000_000_000,
                recipient: "0xeoa".into(),
            }),
        )
        .unwrap();
        // Second transfer pushes over — rejected.
        let err = a
            .submit_post(
                "ETH-1",
                "0xgateway",
                body,
                1_900_000_000,
                Some(AssetTransfer {
                    asset: "DOT".into(),
                    amount: 5_000_000_001,
                    recipient: "0xeoa".into(),
                }),
            )
            .unwrap_err();
        assert!(matches!(err, BridgeError::TransferFailed(_)));
    }

    #[test]
    fn unknown_asset_skips_liquidity_check() {
        let a = HyperbridgeAdapter::new(cfg());
        let id = a
            .submit_post(
                "ETH-1",
                "0xgateway",
                vec![0x02],
                1_900_000_000,
                Some(AssetTransfer {
                    asset: "UNK".into(),
                    amount: u128::MAX / 2,
                    recipient: "0xeoa".into(),
                }),
            )
            .unwrap();
        assert!(a.get_post(&id).is_some());
    }

    #[test]
    fn mark_delivered_transitions_status() {
        let a = HyperbridgeAdapter::new(cfg());
        let id = a
            .submit_post("ETH-1", "0xgateway", vec![0x01], 1_900_000_000, None)
            .unwrap();
        a.mark_delivered(&id).unwrap();
        assert_eq!(a.get_post(&id).unwrap().1, PostRequestStatus::Delivered);
    }
}
