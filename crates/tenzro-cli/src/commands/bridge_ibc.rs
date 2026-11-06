//! Relaying IBC from a Cosmos chain to Tenzro: the Tendermint light client's
//! updates (`tenzro bridge light-client --cosmos-rpc`) and the IBC messages
//! that carry a proof of the Cosmos chain's IBC store (`tenzro bridge ibc`),
//! both read from a CometBFT RPC node.

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, ValueEnum};
use serde_json::{Value, json};
use tenzro_bridge::route::ibc::{ack_key, receipt_key};
use tenzro_bridge::route::ibc_core::{channel_path, connection_path};
use tenzro_bridge::route::tendermint::cometbft_rpc;
use tenzro_bridge::route::{BridgeRoute, LightClientAnchor};
#[cfg(test)]
use tenzro_types::bridge_route::IbcRoute;
use tenzro_types::bridge_route::{BridgeRouteAdapter, IBC_TRANSFER_PORT, IbcVersion};
use tenzro_types::bridge_transfer::{BridgeOp, IbcMsg};

use crate::output;
use crate::rpc::RpcClient;

/// A CometBFT RPC node of the route's chain.
pub(crate) struct CometBft {
    client: reqwest::Client,
    url: String,
}

impl CometBft {
    pub(crate) fn new(url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: url.trim_end_matches('/').to_string(),
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let resp: Value = self
            .client
            .post(&self.url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await
            .with_context(|| format!("{method} at {}", self.url))?
            .json()
            .await?;
        if let Some(e) = resp.get("error") {
            bail!("{method}: {e}");
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| anyhow!("{method}: no result"))
    }

    async fn latest_height(&self) -> Result<u64> {
        self.call("status", json!({})).await?["sync_info"]["latest_block_height"]
            .as_str()
            .and_then(|h| h.parse().ok())
            .ok_or_else(|| anyhow!("status: no latest height"))
    }

    async fn commit(&self, height: u64) -> Result<Value> {
        self.call("commit", json!({ "height": height.to_string() }))
            .await
    }

    async fn validators(
        &self,
        height: u64,
    ) -> Result<Vec<tenzro_bridge::route::tendermint::Validator>> {
        let mut all = Vec::new();
        for page in 1.. {
            let r = self
                .call("validators", json!({ "height": height.to_string(), "page": page.to_string(), "per_page": "100" }))
                .await?;
            let list = r["validators"].as_array().cloned().unwrap_or_default();
            all.extend(list);
            let total: usize = r["total"]
                .as_str()
                .and_then(|t| t.parse().ok())
                .unwrap_or(0);
            if all.len() >= total {
                break;
            }
        }
        Ok(cometbft_rpc::validators(&all)?)
    }

    /// The proof of `key` in the IBC store for the header at `height`.
    pub(crate) async fn entry_proof(&self, key: &[u8], height: u64) -> Result<Vec<u8>> {
        let query = self
            .call(
                "abci_query",
                json!({ "path": "store/ibc/key", "data": hex::encode(key), "height": (height - 1).to_string(), "prove": true }),
            )
            .await?;
        Ok(cometbft_rpc::entry_proof(&query, key, height)?.encode())
    }
}

async fn route(rpc: &RpcClient, chain: &str) -> Result<(BridgeRoute, Value)> {
    let info: Value = rpc
        .call(
            "tenzro_getBridgeRoute",
            json!({ "adapter": BridgeRouteAdapter::Ibc.as_str(), "source_chain": chain }),
        )
        .await?;
    let record: BridgeRoute =
        serde_json::from_value(info["record"].clone()).context("the route record")?;
    Ok((record, info))
}

/// The next update the route's Tendermint light client needs: the bootstrap
/// from its anchor, or the header at `target` (default: the chain's latest)
/// from the height it trusts.
pub(crate) async fn light_client_update(
    rpc: &RpcClient,
    chain: &str,
    cosmos: &CometBft,
    target: Option<u64>,
) -> Result<Vec<u8>> {
    let (route, info) = route(rpc, chain).await?;
    let Some(LightClientAnchor::Tendermint { trusted_height, .. }) = route.light_client else {
        bail!("the route does not follow a Tendermint light client");
    };
    match info["light_client_head"]["finalized"].as_u64() {
        None => Ok(cometbft_rpc::bootstrap(
            &cosmos.commit(trusted_height).await?,
        )?),
        Some(trusted) => {
            let target = match target {
                Some(t) => t,
                None => cosmos.latest_height().await?,
            };
            if target <= trusted {
                bail!("the light client already trusts height {trusted}");
            }
            let commit = cosmos.commit(target).await?;
            let validators = cosmos.validators(target).await?;
            let trusted_next = cosmos.validators(trusted + 1).await?;
            Ok(cometbft_rpc::update(
                trusted,
                &commit,
                &validators,
                &trusted_next,
            )?)
        }
    }
}

/// An IBC message from the Cosmos chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum IbcMessageKind {
    /// The Cosmos connection end is INIT: open Tenzro's (classic)
    ConnectionOpenTry,
    /// The Cosmos connection end is OPEN: open Tenzro's (classic)
    ConnectionOpenConfirm,
    /// The Cosmos channel end is INIT: open Tenzro's (classic)
    ChannelOpenTry,
    /// The Cosmos channel end is OPEN: open Tenzro's (classic)
    ChannelOpenConfirm,
    /// The Cosmos chain acknowledged an outbound packet
    Acknowledge,
    /// An outbound packet timed out unreceived
    Timeout,
}

/// The IBC store key on the Cosmos chain a message of `kind` proves.
pub fn proven_key(
    route: &BridgeRoute,
    kind: IbcMessageKind,
    sequence: Option<u64>,
) -> Result<Vec<u8>> {
    let ibc = route
        .ibc
        .as_ref()
        .ok_or_else(|| anyhow!("the route has no IBC settings"))?;
    let classic = |id: &Option<String>| -> Result<String> {
        match (ibc.version, id) {
            (IbcVersion::Classic, Some(id)) => Ok(id.clone()),
            _ => bail!("an IBC v2 route has no handshake"),
        }
    };
    let seq = || sequence.ok_or_else(|| anyhow!("--sequence is required for this message"));
    Ok(match kind {
        IbcMessageKind::ConnectionOpenTry | IbcMessageKind::ConnectionOpenConfirm => {
            connection_path(&classic(&ibc.counterparty_connection_id)?)
        }
        IbcMessageKind::ChannelOpenTry | IbcMessageKind::ChannelOpenConfirm => {
            channel_path(&classic(&ibc.counterparty_channel_id)?)
        }
        IbcMessageKind::Acknowledge => ack_key(
            ibc.version,
            IBC_TRANSFER_PORT,
            ibc.counterparty_packet_id(),
            seq()?,
        ),
        IbcMessageKind::Timeout => receipt_key(
            ibc.version,
            IBC_TRANSFER_PORT,
            ibc.counterparty_packet_id(),
            seq()?,
        ),
    })
}

/// Relay an IBC message from the Cosmos chain of an IBC route, with the proof
/// of the Cosmos chain's IBC store read from its CometBFT RPC node at a
/// height the route's light client already verified
#[derive(Debug, Parser)]
pub struct BridgeIbcCmd {
    /// External chain of the IBC route
    #[arg(long)]
    chain: String,
    /// The message
    #[arg(long, value_enum)]
    message: IbcMessageKind,
    /// The Cosmos chain's CometBFT RPC endpoint
    #[arg(long)]
    cosmos_rpc: String,
    /// The header height whose app hash the proof reaches (default: the
    /// height the route's light client stands at)
    #[arg(long)]
    height: Option<u64>,
    /// Acknowledge and timeout: the outbound packet's sequence
    #[arg(long)]
    sequence: Option<u64>,
    /// Acknowledge: the acknowledgement the Cosmos chain wrote (hex)
    #[arg(long)]
    acknowledgement: Option<String>,
    #[command(flatten)]
    signer: super::signer::Signer,
}

impl BridgeIbcCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Bridge IBC");
        let rpc = RpcClient::new(self.signer.rpc_url());
        let chain = self.chain.to_ascii_lowercase();
        let (route, info) = route(&rpc, &chain).await?;
        let height = match self.height {
            Some(h) => h,
            None => info["light_client_head"]["finalized"]
                .as_u64()
                .ok_or_else(|| anyhow!("the route's light client is not bootstrapped"))?,
        };
        let key = proven_key(&route, self.message, self.sequence)?;
        let proof = CometBft::new(&self.cosmos_rpc)
            .entry_proof(&key, height)
            .await?;
        output::print_field("Proven key", &String::from_utf8_lossy(&key));
        output::print_field("Height", &height.to_string());
        let sequence = || {
            self.sequence
                .ok_or_else(|| anyhow!("--sequence is required"))
        };
        let msg = match self.message {
            IbcMessageKind::ConnectionOpenTry => IbcMsg::ConnectionOpenTry { proof },
            IbcMessageKind::ConnectionOpenConfirm => IbcMsg::ConnectionOpenConfirm { proof },
            IbcMessageKind::ChannelOpenTry => IbcMsg::ChannelOpenTry { proof },
            IbcMessageKind::ChannelOpenConfirm => IbcMsg::ChannelOpenConfirm { proof },
            IbcMessageKind::Acknowledge => IbcMsg::Acknowledge {
                sequence: sequence()?,
                acknowledgement: hex::decode(
                    self.acknowledgement
                        .as_deref()
                        .ok_or_else(|| anyhow!("--acknowledgement is required"))?
                        .trim_start_matches("0x"),
                )
                .map_err(|_| anyhow!("--acknowledgement must be hex"))?,
                proof,
            },
            IbcMessageKind::Timeout => IbcMsg::Timeout {
                sequence: sequence()?,
                proof,
            },
        };
        super::bridge::relay(
            &self.signer,
            BridgeOp::Ibc {
                source_chain: chain,
                msg,
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ibc_route(version: IbcVersion) -> BridgeRoute {
        let mut r: BridgeRoute = serde_json::from_value(json!({
            "adapter": "ibc", "family": "cosmos", "source_chain": "osmosis",
            "source_chain_id": "1", "local_selector": "2",
            "peer": vec![1u8; 32], "ramp": vec![2u8; 32], "local_endpoint": vec![3u8; 32], "remote_token": vec![4u8; 32],
            "verifiers": { "set_index": 0, "size": 0, "members": [], "threshold": 0 },
            "blessing": null, "light_client": null,
            "mint_limit": { "per_mint": "1", "per_epoch": "1" },
            "outflow": { "capacity": "2", "rate": "1" },
            "lane_limits": null, "ibc": null,
        }))
        .unwrap();
        r.ibc = Some(IbcRoute {
            version,
            counterparty_client_id: "08-wasm-3".into(),
            counterparty_connection_id: (version == IbcVersion::Classic)
                .then(|| "connection-12".into()),
            counterparty_channel_id: (version == IbcVersion::Classic).then(|| "channel-141".into()),
            packet_timeout_secs: 600,
        });
        r
    }

    #[test]
    fn each_message_proves_the_cosmos_entry_it_names() {
        let classic = ibc_route(IbcVersion::Classic);
        assert_eq!(
            proven_key(&classic, IbcMessageKind::ConnectionOpenTry, None).unwrap(),
            b"connections/connection-12"
        );
        assert_eq!(
            proven_key(&classic, IbcMessageKind::ChannelOpenConfirm, None).unwrap(),
            b"channelEnds/ports/transfer/channels/channel-141"
        );
        assert_eq!(
            proven_key(&classic, IbcMessageKind::Acknowledge, Some(7)).unwrap(),
            b"acks/ports/transfer/channels/channel-141/sequences/7"
        );
        let v2 = ibc_route(IbcVersion::V2);
        let mut receipt = b"08-wasm-3".to_vec();
        receipt.push(2);
        receipt.extend_from_slice(&7u64.to_be_bytes());
        assert_eq!(
            proven_key(&v2, IbcMessageKind::Timeout, Some(7)).unwrap(),
            receipt
        );
        assert!(proven_key(&v2, IbcMessageKind::ConnectionOpenTry, None).is_err());
        assert!(proven_key(&v2, IbcMessageKind::Timeout, None).is_err());
    }
}
