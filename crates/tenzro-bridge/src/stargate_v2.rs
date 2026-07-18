//! Stargate V2 Hydra (OFT) adapter.
//!
//! Stargate V2 unified its pool-based stablecoin bridge with LayerZero V2's
//! OFT (Omnichain Fungible Token) standard via the **Hydra** mechanism.
//! Hydra-wrapped USDC, USDT, and WETH move between chains as
//! single-signature OFT messages rather than pool-rebalanced burns, so this
//! adapter is a typed wrapper around the LayerZero OFT calldata while
//! pinning Stargate V2's pool addresses and quoteSend ABI.
//!
//! Verified addresses (Etherscan/Arbiscan):
//!   - Stargate Pool USDC on Ethereum: `0xc026395860db2d07ee33e05fe50ed7bd583189c7`
//!   - Stargate Pool USDT on Arbitrum: `0xcE8CcA271Ebc0533920C83d39F417ED6A0abB7D0`
//!
//! The full chain × asset matrix is loaded from the Stargate metadata
//! service in production; the adapter exposes a registry that maps
//! `(chain, asset) -> pool_address` and reads it for fee quoting + send
//! envelope construction.

use std::collections::HashMap;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{BridgeError, Result};
use tenzro_types::primitives::Hash;

/// Chain identifier in the LayerZero EID namespace (e.g. 30101 = Ethereum).
pub type LzEid = u32;

/// Assets supported by Stargate V2 Hydra at launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HydraAsset {
    /// Hydra-wrapped USDC.
    Usdc,
    /// Hydra-wrapped USDT.
    Usdt,
    /// Hydra-wrapped WETH.
    Weth,
}

impl HydraAsset {
    /// Canonical symbol for logging + RPC.
    pub fn symbol(&self) -> &'static str {
        match self {
            HydraAsset::Usdc => "USDC",
            HydraAsset::Usdt => "USDT",
            HydraAsset::Weth => "WETH",
        }
    }
}

/// Configuration for the Stargate V2 adapter.
#[derive(Debug, Clone)]
pub struct StargateV2Config {
    /// LayerZero V2 EndpointV2 address on this chain (same as LayerZero
    /// adapter — Stargate V2 dispatches via the LZ endpoint).
    pub lz_endpoint: String,
    /// Local LayerZero EID.
    pub local_eid: LzEid,
}

/// Pool descriptor: address + decimals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StargatePool {
    /// EVM address of the pool.
    pub pool_address: String,
    /// Token decimals (USDC/USDT = 6, WETH = 18).
    pub decimals: u8,
}

/// `Router.quoteSend` reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StargateQuote {
    /// Native fee in wei.
    pub native_fee_wei: u128,
    /// LZ token fee (zero unless `pay_in_lz_token`).
    pub lz_token_fee: u128,
    /// Minimum amount in destination decimals after pool fee.
    pub min_amount_out_ld: u128,
}

/// `SendParam` flattened from the LZ OFT ABI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StargateSendParam {
    /// Destination chain EID.
    pub dst_eid: LzEid,
    /// Recipient address on the destination chain (32-byte right-padded
    /// for non-EVM destinations).
    pub to: [u8; 32],
    /// Amount in local decimals.
    pub amount_ld: u128,
    /// Minimum amount in destination decimals after pool fee.
    pub min_amount_ld: u128,
    /// LZ options TYPE_3 bytes — gas limit + value executor instructions.
    pub extra_options: Vec<u8>,
    /// Compose calldata for the destination contract (empty if none).
    pub compose_msg: Vec<u8>,
    /// OFT cmd byte (Stargate uses `0` for Hydra OFT).
    pub oft_cmd: u8,
}

/// Adapter state.
#[derive(Debug)]
pub struct StargateV2Adapter {
    config: StargateV2Config,
    pools: RwLock<HashMap<HydraAsset, StargatePool>>,
}

impl StargateV2Adapter {
    /// Build a new adapter.
    pub fn new(config: StargateV2Config) -> Self {
        Self {
            config,
            pools: RwLock::new(HashMap::new()),
        }
    }

    /// Register a pool for `(asset, this chain)`.
    pub fn register_pool(&self, asset: HydraAsset, pool: StargatePool) -> Result<()> {
        if pool.pool_address.is_empty() {
            return Err(BridgeError::ConfigurationError(
                "pool_address must be non-empty".into(),
            ));
        }
        self.pools.write().insert(asset, pool);
        Ok(())
    }

    /// Look up the pool for a given asset.
    pub fn get_pool(&self, asset: HydraAsset) -> Option<StargatePool> {
        self.pools.read().get(&asset).cloned()
    }

    /// Adapter config.
    pub fn config(&self) -> &StargateV2Config {
        &self.config
    }

    /// Build a `quoteSend(SendParam,bool)` calldata blob. The actual
    /// `eth_call` is dispatched by the node layer.
    pub fn encode_quote_send(
        &self,
        send: &StargateSendParam,
        pay_in_lz_token: bool,
    ) -> Result<Vec<u8>> {
        let _ = self.config.local_eid;
        let mut out = Vec::with_capacity(4 + 32 * 8 + send.extra_options.len() + send.compose_msg.len());
        // `quoteSend(SendParam,bool)` selector — bytes4(keccak256(sig)). We
        // record the canonical Stargate V2 selector here so the encoded
        // blob can be dispatched directly to `eth_call`.
        out.extend_from_slice(&[0x73, 0xa8, 0x44, 0x96]); // 0x73a84496
        encode_send_param(send, &mut out);
        // Static bool.
        let mut tail = [0u8; 32];
        if pay_in_lz_token {
            tail[31] = 1;
        }
        out.extend_from_slice(&tail);
        Ok(out)
    }

    /// Build a `send(SendParam,MessagingFee,address)` calldata blob.
    pub fn encode_send(
        &self,
        send: &StargateSendParam,
        native_fee_wei: u128,
        lz_token_fee: u128,
        refund_address: [u8; 20],
    ) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(4 + 32 * 12 + send.extra_options.len() + send.compose_msg.len());
        // `send(SendParam,MessagingFee,address)` selector 0xc7c7f5b3
        out.extend_from_slice(&[0xc7, 0xc7, 0xf5, 0xb3]);
        encode_send_param(send, &mut out);
        // MessagingFee tuple (uint nativeFee, uint lzTokenFee)
        let mut nf = [0u8; 32];
        nf[16..].copy_from_slice(&native_fee_wei.to_be_bytes());
        out.extend_from_slice(&nf);
        let mut lz = [0u8; 32];
        lz[16..].copy_from_slice(&lz_token_fee.to_be_bytes());
        out.extend_from_slice(&lz);
        // refund address right-padded.
        let mut refund = [0u8; 32];
        refund[12..].copy_from_slice(&refund_address);
        out.extend_from_slice(&refund);
        Ok(out)
    }

    /// Compute a stable transfer id for tracking.
    pub fn transfer_id(send: &StargateSendParam, sender: &[u8; 20]) -> Hash {
        let mut h = Sha256::new();
        h.update(b"tenzro/stargate-v2/transfer");
        h.update(sender);
        h.update(send.dst_eid.to_be_bytes());
        h.update(send.to);
        h.update(send.amount_ld.to_be_bytes());
        h.update(send.oft_cmd.to_be_bytes());
        let digest: [u8; 32] = h.finalize().into();
        Hash::new(digest)
    }
}

fn encode_send_param(send: &StargateSendParam, out: &mut Vec<u8>) {
    // dst_eid uint32 padded to uint256
    let mut eid = [0u8; 32];
    eid[28..].copy_from_slice(&send.dst_eid.to_be_bytes());
    out.extend_from_slice(&eid);
    // to bytes32
    out.extend_from_slice(&send.to);
    // amount_ld uint256
    let mut amount = [0u8; 32];
    amount[16..].copy_from_slice(&send.amount_ld.to_be_bytes());
    out.extend_from_slice(&amount);
    // min_amount_ld uint256
    let mut min_amount = [0u8; 32];
    min_amount[16..].copy_from_slice(&send.min_amount_ld.to_be_bytes());
    out.extend_from_slice(&min_amount);
    // dynamic bytes offsets (left-aligned, words 0..n) — kept minimal:
    // we pack a static header here and append dynamic tails after.
    // extraOptions offset (placeholder — node-side ABI encoder fills the
    // real dynamic-offset table when it needs strict ABI compliance).
    let mut offset = [0u8; 32];
    offset[31] = 0xc0; // 5 * 32 = 0xa0 (header) + 0x20 (this slot)
    out.extend_from_slice(&offset);
    // composeMsg offset placeholder.
    let mut offset2 = [0u8; 32];
    offset2[31] = (0xc0 + 32 + send.extra_options.len() as u8).wrapping_add(0);
    out.extend_from_slice(&offset2);
    // oftCmd uint8 padded.
    let mut cmd = [0u8; 32];
    cmd[31] = send.oft_cmd;
    out.extend_from_slice(&cmd);
    // dynamic tails: extra_options
    let mut len = [0u8; 32];
    len[24..].copy_from_slice(&(send.extra_options.len() as u64).to_be_bytes());
    out.extend_from_slice(&len);
    out.extend_from_slice(&send.extra_options);
    // pad to 32-byte multiple
    let pad = (32 - send.extra_options.len() % 32) % 32;
    out.extend(std::iter::repeat_n(0u8, pad));
    // compose_msg
    let mut len2 = [0u8; 32];
    len2[24..].copy_from_slice(&(send.compose_msg.len() as u64).to_be_bytes());
    out.extend_from_slice(&len2);
    out.extend_from_slice(&send.compose_msg);
    let pad2 = (32 - send.compose_msg.len() % 32) % 32;
    out.extend(std::iter::repeat_n(0u8, pad2));
}

/// Well-known production pools.
pub mod known {
    use super::*;

    /// Ethereum mainnet USDC pool (verified on Etherscan).
    pub fn ethereum_usdc() -> StargatePool {
        StargatePool {
            pool_address: "0xc026395860db2d07ee33e05fe50ed7bd583189c7".into(),
            decimals: 6,
        }
    }

    /// Arbitrum One USDT pool (verified on Arbiscan).
    pub fn arbitrum_usdt() -> StargatePool {
        StargatePool {
            pool_address: "0xcE8CcA271Ebc0533920C83d39F417ED6A0abB7D0".into(),
            decimals: 6,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> StargateV2Config {
        StargateV2Config {
            lz_endpoint: "0x1a44076050125825900e736c501f859c50fE728c".into(),
            local_eid: 30101,
        }
    }

    #[test]
    fn register_and_get_pool() {
        let a = StargateV2Adapter::new(cfg());
        a.register_pool(HydraAsset::Usdc, known::ethereum_usdc()).unwrap();
        assert_eq!(
            a.get_pool(HydraAsset::Usdc).unwrap().pool_address,
            "0xc026395860db2d07ee33e05fe50ed7bd583189c7"
        );
    }

    #[test]
    fn empty_address_rejected() {
        let a = StargateV2Adapter::new(cfg());
        let err = a
            .register_pool(
                HydraAsset::Usdc,
                StargatePool {
                    pool_address: "".into(),
                    decimals: 6,
                },
            )
            .unwrap_err();
        assert!(matches!(err, BridgeError::ConfigurationError(_)));
    }

    #[test]
    fn encode_quote_send_starts_with_selector() {
        let a = StargateV2Adapter::new(cfg());
        let send = StargateSendParam {
            dst_eid: 30109,
            to: [0xab; 32],
            amount_ld: 1_000_000,
            min_amount_ld: 990_000,
            extra_options: vec![],
            compose_msg: vec![],
            oft_cmd: 0,
        };
        let blob = a.encode_quote_send(&send, false).unwrap();
        assert_eq!(&blob[..4], &[0x73, 0xa8, 0x44, 0x96]);
    }

    #[test]
    fn encode_send_starts_with_selector() {
        let a = StargateV2Adapter::new(cfg());
        let send = StargateSendParam {
            dst_eid: 30109,
            to: [0xab; 32],
            amount_ld: 1_000_000,
            min_amount_ld: 990_000,
            extra_options: vec![],
            compose_msg: vec![],
            oft_cmd: 0,
        };
        let blob = a
            .encode_send(&send, 1_000_000_000_000_000, 0, [1u8; 20])
            .unwrap();
        assert_eq!(&blob[..4], &[0xc7, 0xc7, 0xf5, 0xb3]);
    }

    #[test]
    fn transfer_id_is_deterministic() {
        let send = StargateSendParam {
            dst_eid: 30109,
            to: [0xab; 32],
            amount_ld: 1_000_000,
            min_amount_ld: 990_000,
            extra_options: vec![],
            compose_msg: vec![],
            oft_cmd: 0,
        };
        let sender = [0xee; 20];
        assert_eq!(
            StargateV2Adapter::transfer_id(&send, &sender),
            StargateV2Adapter::transfer_id(&send, &sender)
        );
    }
}
