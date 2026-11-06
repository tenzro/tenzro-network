//! `tenzro bridge attest`: build a delivery a route's verifiers sign, and
//! collect their signatures into it.
//!
//! A verifier reads the source transaction from its own provider of the
//! external chain, never from Tenzro or the relayer, and only at that chain's
//! finality:
//!
//! - **Solana**: the transaction at finalized commitment; the delivery
//!   carries the router's message and the execution record of the
//!   transaction's success.
//! - **EVM chains**: the on-ramp's message log from the transaction's
//!   receipt, in a block at or below the chain's finalized block. On a route
//!   that follows Ethereum's beacon chain, the delivery also carries the
//!   message proof: the finality update, the chain of headers from the
//!   message's block to the finalized block, the block body's branch to its
//!   receipts root, and the receipt's trie proof.
//!
//! For the other direction, `--outbound-sequence` reads Tenzro's outbound
//! record for a contract chain and the digest the committee signs so the
//! bridge contract there executes it ([`outbound_digest`]).
//!
//! `--handover <set>` reads committee `set` as the chain drew it and the
//! digest the committee a bridge contract trusts (`--from-set`) signs to
//! hand the contract over to it ([`committee_handover_digest`]); the contract
//! accepts it only for a higher set index than the one it holds, and stops
//! trusting each committee at its expiry.
//!
//! The first step writes the unsigned delivery and the digest to sign; the
//! verifier's hardware signer signs the digest with both keys: the
//! secp256k1 key (`--signature`) and the ML-DSA-65 key (`--pq-signature`,
//! context `tenzro/bridge/route-attestation/ml-dsa-65`). The second step adds
//! a signature to the delivery, checking it belongs to a member of the
//! route's committees, and prints the delivery once every committee holds its
//! threshold of members signed on both legs. Outbound records and handovers
//! are verified by the external chain's bridge contract and take the
//! secp256k1 signature only.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use serde_json::{Value, json};
use tenzro_bridge::route::attestation::{
    Delivery, attestation_digest, committee_handover_digest, outbound_digest,
};
use tenzro_bridge::route::ethereum_light_client::beacon_api;
use tenzro_bridge::route::evm;
use tenzro_bridge::route::{BridgeRoute, ChainFamily, LightClientAnchor};

use crate::output;
use crate::rpc::RpcClient;

/// Build a delivery for a route's verifiers to sign, or add a verifier's
/// signature to one (two steps)
#[derive(Debug, Parser)]
pub struct BridgeAttestCmd {
    /// Route transport: ccip, ibc, deposit or contract
    #[arg(long, required_unless_present = "request_in")]
    adapter: Option<String>,
    /// External chain the message comes from
    #[arg(long, required_unless_present = "request_in")]
    chain: Option<String>,
    /// The source transaction: a Solana signature (base58) or an EVM
    /// transaction hash
    #[arg(long, required_unless_present_any = ["request_in", "outbound_sequence", "handover"])]
    tx: Option<String>,
    /// This verifier's own RPC endpoint on the external chain
    #[arg(long, required_unless_present_any = ["request_in", "outbound_sequence", "handover"])]
    source_rpc: Option<String>,
    /// A beacon node's Beacon API, for routes that follow Ethereum's beacon
    /// chain
    #[arg(long)]
    beacon: Option<String>,
    /// The message's sequence, when the transaction sent more than one
    #[arg(long)]
    sequence: Option<u64>,
    /// The delivery's nonce, as the relayer assigned it
    #[arg(long, required_unless_present_any = ["request_in", "outbound_sequence", "handover"])]
    nonce: Option<u64>,
    /// Unix ms after which the delivery is refused, as the relayer set it
    #[arg(long, required_unless_present_any = ["request_in", "outbound_sequence", "handover"])]
    expiry_ms: Option<i64>,
    /// Attest Tenzro's outbound record with this sequence instead, for the
    /// bridge contract on the external chain to execute
    #[arg(long, conflicts_with_all = ["tx", "request_in", "handover"])]
    outbound_sequence: Option<u64>,
    /// Hand the route's bridge contract over to this drawn committee
    /// instead, signed by the committee the contract trusts (`--from-set`)
    #[arg(long, conflicts_with_all = ["tx", "request_in"], requires = "from_set")]
    handover: Option<u32>,
    /// The committee the bridge contract trusts now, whose members sign the
    /// handover
    #[arg(long, requires = "handover")]
    from_set: Option<u32>,
    /// Where to write the unsigned delivery
    #[arg(long, conflicts_with = "request_in")]
    request_out: Option<PathBuf>,
    /// A delivery written by the first step, to add a signature to
    #[arg(long)]
    request_in: Option<PathBuf>,
    /// A verifier's 65-byte signature over the digest (hex)
    #[arg(long, requires = "request_in")]
    signature: Option<String>,
    /// A verifier's 3309-byte ML-DSA-65 signature over the digest (hex), for
    /// a delivery
    #[arg(long, requires = "request_in")]
    pq_signature: Option<String>,
    /// Tenzro RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

fn hex_bytes(s: &str, what: &str) -> Result<Vec<u8>> {
    hex::decode(s.trim_start_matches("0x")).with_context(|| format!("{what} is not hex"))
}

fn quantity(v: &Value, what: &str) -> Result<u64> {
    let s = v.as_str().ok_or_else(|| anyhow!("{what} is missing"))?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16)
        .with_context(|| format!("{what} is not a quantity"))
}

async fn json_rpc(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: Value,
) -> Result<Value> {
    let resp: Value = client
        .post(url)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
        .send()
        .await
        .with_context(|| format!("{method} at {url}"))?
        .json()
        .await?;
    if let Some(e) = resp.get("error") {
        bail!("{method}: {e}");
    }
    resp.get("result")
        .cloned()
        .filter(|r| !r.is_null())
        .ok_or_else(|| anyhow!("{method}: no result"))
}

async fn beacon_get(client: &reqwest::Client, base: &str, path: &str) -> Result<Value> {
    let url = format!("{}{path}", base.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .header("accept", "application/json")
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("{url}: {}", resp.status());
    }
    Ok(resp.json().await?)
}

/// The route's record and Tenzro's chain id, from the node.
async fn route_and_chain(
    rpc: &RpcClient,
    adapter: &str,
    chain: &str,
) -> Result<(BridgeRoute, u64)> {
    let route: Value = rpc
        .call(
            "tenzro_getBridgeRoute",
            json!({ "adapter": adapter, "source_chain": chain }),
        )
        .await?;
    let record: BridgeRoute = serde_json::from_value(route["record"].clone())
        .context("the node returned no route record")?;
    let id: Value = rpc.call("eth_chainId", json!([])).await?;
    Ok((record, quantity(&id, "chain id")?))
}

/// The router's message and the execution record, read at finalized
/// commitment from `source_rpc`.
async fn solana_message(
    client: &reqwest::Client,
    route: &BridgeRoute,
    source_rpc: &str,
    tx: &str,
    sequence: Option<u64>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let t = json_rpc(
        client,
        source_rpc,
        "getTransaction",
        json!([tx, { "commitment": "finalized", "encoding": "json", "maxSupportedTransactionVersion": 0 }]),
    )
    .await?;
    let (messages, execution) = tenzro_bridge::route::solana::attest_transaction(route, &t)?;
    let m = pick(messages, |m| m.sequence, sequence)?;
    Ok((m.encode(), execution.encode()))
}

fn pick<T>(mut items: Vec<T>, seq: impl Fn(&T) -> u64, wanted: Option<u64>) -> Result<T> {
    match wanted {
        Some(s) => {
            let i = items
                .iter()
                .position(|m| seq(m) == s)
                .ok_or_else(|| anyhow!("no message with sequence {s}"))?;
            Ok(items.swap_remove(i))
        }
        None if items.len() == 1 => Ok(items.remove(0)),
        None => bail!(
            "the transaction sent {} messages; name one with --sequence",
            items.len()
        ),
    }
}

/// The on-ramp's message (the log data) and, on a route that follows the
/// beacon chain, its message proof.
async fn evm_message(
    client: &reqwest::Client,
    route: &BridgeRoute,
    source_rpc: &str,
    beacon: Option<&str>,
    tx: &str,
    sequence: Option<u64>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let receipt = json_rpc(client, source_rpc, "eth_getTransactionReceipt", json!([tx])).await?;
    if quantity(&receipt["status"], "status")? != 1 {
        bail!("the transaction failed");
    }
    let ramp = &route.ramp[12..];
    let version = evm::lane_version(route)?;
    let logs = receipt["logs"].as_array().cloned().unwrap_or_default();
    let mut found = Vec::new();
    for (i, log) in logs.iter().enumerate() {
        let address = hex_bytes(log["address"].as_str().unwrap_or_default(), "log address")?;
        let topics = log["topics"]
            .as_array()
            .map(|t| {
                t.iter()
                    .filter_map(|x| x.as_str())
                    .map(|x| hex_bytes(x, "topic"))
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default()
            .into_iter()
            .map(|t| {
                <[u8; 32]>::try_from(t.as_slice())
                    .map_err(|_| anyhow!("a log topic is not 32 bytes"))
            })
            .collect::<Result<Vec<_>>>()?;
        let data = hex_bytes(log["data"].as_str().unwrap_or_default(), "log data")?;
        if address == ramp && evm::onramp_log_matches(version, &topics, &data, route) {
            let mut r = tenzro_bridge::route::canonical::Reader::new(&data);
            let seq = evm::read_onramp_message(route, &mut r)?.sequence;
            found.push((i as u32, seq, data));
        }
    }
    if found.is_empty() {
        bail!("the transaction holds no message of the route's on-ramp to Tenzro");
    }
    let (log_index, _, body) = pick(found, |f| f.1, sequence)?;
    let block_number = quantity(&receipt["blockNumber"], "blockNumber")?;

    match &route.light_client {
        Some(LightClientAnchor::EthereumSyncCommittee { .. }) => {
            let beacon = beacon
                .ok_or_else(|| anyhow!("the route follows the beacon chain: give --beacon"))?;
            let finality = beacon_get(
                client,
                beacon,
                "/eth/v1/beacon/light_client/finality_update",
            )
            .await?;
            let genesis = beacon_get(client, beacon, "/eth/v1/beacon/genesis").await?;
            let spec = beacon_get(client, beacon, "/eth/v1/config/spec").await?;
            let genesis_time: u64 = genesis["data"]["genesis_time"]
                .as_str()
                .unwrap_or("0")
                .parse()?;
            let seconds: u64 = spec["data"]["SECONDS_PER_SLOT"]
                .as_str()
                .unwrap_or("12")
                .parse()?;
            let block = json_rpc(
                client,
                source_rpc,
                "eth_getBlockByNumber",
                json!([format!("0x{block_number:x}"), false]),
            )
            .await?;
            let slot = (quantity(&block["timestamp"], "timestamp")?.saturating_sub(genesis_time))
                / seconds.max(1);
            let beacon_block =
                beacon_get(client, beacon, &format!("/eth/v2/beacon/blocks/{slot}")).await?;
            let payload_hash =
                beacon_block["data"]["message"]["body"]["execution_payload"]["block_hash"]
                    .as_str()
                    .unwrap_or_default();
            if !payload_hash.eq_ignore_ascii_case(receipt["blockHash"].as_str().unwrap_or_default())
            {
                bail!("the beacon block at slot {slot} does not carry the transaction's block");
            }
            let own_root = beacon_get(client, beacon, &format!("/eth/v1/beacon/headers/{slot}"))
                .await?["data"]["root"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let finalized = &finality["data"]["finalized_header"]["beacon"];
            let finalized_slot: u64 = finalized["slot"].as_str().unwrap_or("0").parse()?;
            if finalized_slot < slot {
                bail!("slot {slot} is not final yet (finalized {finalized_slot}); try again later");
            }
            let mut descendants = Vec::new();
            let finalized_root = beacon_get(
                client,
                beacon,
                &format!("/eth/v1/beacon/headers/{finalized_slot}"),
            )
            .await?["data"]["root"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            if finalized_root != own_root {
                let mut root = finalized["parent_root"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string();
                while root != own_root {
                    let h = beacon_get(client, beacon, &format!("/eth/v1/beacon/headers/{root}"))
                        .await?;
                    let s: u64 = h["data"]["header"]["message"]["slot"]
                        .as_str()
                        .unwrap_or("0")
                        .parse()?;
                    if s <= slot {
                        bail!("the finalized chain does not pass through slot {slot}");
                    }
                    root = h["data"]["header"]["message"]["parent_root"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    descendants.push(h);
                }
                descendants.reverse();
            }
            let receipts = json_rpc(
                client,
                source_rpc,
                "eth_getBlockReceipts",
                json!([format!("0x{block_number:x}")]),
            )
            .await?;
            let receipts = receipts.as_array().cloned().unwrap_or_default();
            let tx_index = quantity(&receipt["transactionIndex"], "transactionIndex")? as u32;
            let proof = beacon_api::message_proof(
                &finality,
                &beacon_block,
                &descendants,
                &receipts,
                tx_index,
                log_index,
            )?;
            Ok((body, proof))
        }
        None => {
            let finalized = json_rpc(
                client,
                source_rpc,
                "eth_getBlockByNumber",
                json!(["finalized", false]),
            )
            .await?;
            if block_number > quantity(&finalized["number"], "finalized number")? {
                bail!("block {block_number} is not final yet; try again later");
            }
            Ok((body, Vec::new()))
        }
        Some(_) => bail!("this route's light client is not the beacon chain's"),
    }
}

fn delivery_of(request: &Value) -> Result<Delivery> {
    let sigs = |k: &str| -> Result<Vec<([u8; 20], [u8; 65])>> {
        request[k]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|e| {
                let a: [u8; 20] = hex_bytes(e[0].as_str().unwrap_or_default(), "address")?
                    .try_into()
                    .map_err(|_| anyhow!("address"))?;
                let s: [u8; 65] = hex_bytes(e[1].as_str().unwrap_or_default(), "signature")?
                    .try_into()
                    .map_err(|_| anyhow!("signature"))?;
                Ok((a, s))
            })
            .collect()
    };
    let pq_sigs = |k: &str| -> Result<Vec<([u8; 20], Vec<u8>)>> {
        request[k]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|e| {
                let a: [u8; 20] = hex_bytes(e[0].as_str().unwrap_or_default(), "address")?
                    .try_into()
                    .map_err(|_| anyhow!("address"))?;
                Ok((a, hex_bytes(e[1].as_str().unwrap_or_default(), "pq signature")?))
            })
            .collect()
    };
    Ok(Delivery {
        dest_chain_id: request["dest_chain_id"]
            .as_u64()
            .ok_or_else(|| anyhow!("dest_chain_id"))?,
        nonce: request["nonce"].as_u64().ok_or_else(|| anyhow!("nonce"))?,
        expiry_ms: request["expiry_ms"]
            .as_i64()
            .ok_or_else(|| anyhow!("expiry_ms"))?,
        body: hex_bytes(request["body"].as_str().unwrap_or_default(), "body")?,
        proof: hex_bytes(request["proof"].as_str().unwrap_or_default(), "proof")?,
        committee: sigs("committee")?,
        committee_pq: pq_sigs("committee_pq")?,
        blessing: sigs("blessing")?,
        blessing_pq: pq_sigs("blessing_pq")?,
    })
}

/// Committee `set_index` of the route as the node publishes it.
async fn committee_set(
    rpc: &RpcClient,
    adapter: &str,
    chain: &str,
    set_index: u32,
) -> Result<Value> {
    let route: Value = rpc
        .call(
            "tenzro_getBridgeRoute",
            json!({ "adapter": adapter, "source_chain": chain }),
        )
        .await?;
    route["committee_sets"]
        .as_array()
        .and_then(|sets| {
            sets.iter()
                .find(|s| s["set_index"].as_u64() == Some(u64::from(set_index)))
        })
        .cloned()
        .ok_or_else(|| anyhow!("the route holds no drawn committee {set_index} among its latest"))
}

fn addresses(set: &Value) -> Result<Vec<[u8; 20]>> {
    set["members"]
        .as_array()
        .ok_or_else(|| anyhow!("malformed committee"))?
        .iter()
        .map(|m| {
            hex_bytes(m.as_str().unwrap_or_default(), "member")?
                .try_into()
                .map_err(|_| anyhow!("a member is a 20-byte address"))
        })
        .collect()
}

/// The handover digest a request names, recomputed.
fn handover_digest_of(chain_id: u64, route: &BridgeRoute, request: &Value) -> Result<[u8; 32]> {
    let set = &request["handover"];
    Ok(committee_handover_digest(
        chain_id,
        route,
        u32::try_from(set["set_index"].as_u64().unwrap_or_default())?,
        &addresses(set)?,
        u32::try_from(set["threshold"].as_u64().unwrap_or_default())?,
        set["expires_at_secs"].as_u64().unwrap_or_default(),
    ))
}

impl BridgeAttestCmd {
    /// Committee `set_index` and the digest committee `from_set` signs to hand
    /// the bridge contract over to it.
    async fn build_handover(&self, rpc: &RpcClient, set_index: u32, from_set: u32) -> Result<()> {
        let (adapter, chain) = (
            self.adapter.as_deref().unwrap_or_default(),
            self.chain.as_deref().unwrap_or_default(),
        );
        if set_index <= from_set {
            bail!(
                "a bridge contract is handed over only to a higher set index than the one it trusts"
            );
        }
        let (route, chain_id) = route_and_chain(rpc, adapter, chain).await?;
        let to = committee_set(rpc, adapter, chain, set_index).await?;
        let from = committee_set(rpc, adapter, chain, from_set).await?;
        let mut request = json!({
            "kind": "handover",
            "adapter": adapter,
            "chain": chain,
            "route": route.storage_key(),
            "from": from,
            "handover": to,
            "committee": [],
            "blessing": [],
        });
        let digest = handover_digest_of(chain_id, &route, &request)?;
        if format!("0x{}", hex::encode(digest))
            != to["handover_digest"].as_str().unwrap_or_default()
        {
            bail!("the node's handover digest differs from the one computed here");
        }
        request["digest"] = json!(hex::encode(digest));
        let out = self
            .request_out
            .clone()
            .ok_or_else(|| anyhow!("give --request-out"))?;
        std::fs::write(&out, serde_json::to_vec_pretty(&request)?)?;
        output::print_success("Committee read as the chain drew it");
        output::print_field("Route", &route.storage_key());
        output::print_field("Hand over to set", &set_index.to_string());
        output::print_field("Expires at (Unix s)", &to["expires_at_secs"].to_string());
        output::print_field("Digest to sign", &format!("0x{}", hex::encode(digest)));
        output::print_field("Request", &out.display().to_string());
        Ok(())
    }

    /// The outbound record `sequence` and the digest the committee signs for
    /// the external chain's bridge contract.
    async fn build_outbound(&self, rpc: &RpcClient, sequence: u64) -> Result<()> {
        let (adapter, chain) = (
            self.adapter.as_deref().unwrap_or_default(),
            self.chain.as_deref().unwrap_or_default(),
        );
        let (route, chain_id) = route_and_chain(rpc, adapter, chain).await?;
        let out: Value = rpc
            .call(
                "tenzro_getBridgeOutbound",
                json!({ "adapter": adapter, "source_chain": chain, "sequence": sequence }),
            )
            .await?;
        let record = hex_bytes(out["message"].as_str().unwrap_or_default(), "record")?;
        let digest = outbound_digest(chain_id, &route, &record);
        let request = json!({
            "kind": "outbound",
            "adapter": adapter,
            "chain": chain,
            "route": route.storage_key(),
            "sequence": sequence,
            "dest_chain_id": chain_id,
            "record": hex::encode(&record),
            "digest": hex::encode(digest),
            "committee": [],
            "blessing": [],
        });
        let out = self
            .request_out
            .clone()
            .ok_or_else(|| anyhow!("give --request-out"))?;
        std::fs::write(&out, serde_json::to_vec_pretty(&request)?)?;
        output::print_success("Outbound record read from Tenzro");
        output::print_field("Route", &route.storage_key());
        output::print_field("Digest to sign", &format!("0x{}", hex::encode(digest)));
        output::print_field("Request", &out.display().to_string());
        Ok(())
    }

    async fn build(&self, rpc: &RpcClient) -> Result<()> {
        if let Some(sequence) = self.outbound_sequence {
            return self.build_outbound(rpc, sequence).await;
        }
        if let (Some(set_index), Some(from_set)) = (self.handover, self.from_set) {
            return self.build_handover(rpc, set_index, from_set).await;
        }
        let (adapter, chain) = (
            self.adapter.as_deref().unwrap_or_default(),
            self.chain.as_deref().unwrap_or_default(),
        );
        let (route, chain_id) = route_and_chain(rpc, adapter, chain).await?;
        let client = reqwest::Client::new();
        let source_rpc = self.source_rpc.as_deref().unwrap_or_default();
        let tx = self.tx.as_deref().unwrap_or_default();
        let (body, proof) = match route.family {
            ChainFamily::Solana => {
                solana_message(&client, &route, source_rpc, tx, self.sequence).await?
            }
            ChainFamily::Evm => {
                evm_message(
                    &client,
                    &route,
                    source_rpc,
                    self.beacon.as_deref(),
                    tx,
                    self.sequence,
                )
                .await?
            }
            other => bail!(
                "attesting {} routes is not supported by this command",
                other.as_str()
            ),
        };
        let delivery = Delivery {
            dest_chain_id: chain_id,
            nonce: self.nonce.unwrap_or_default(),
            expiry_ms: self.expiry_ms.unwrap_or_default(),
            body,
            proof,
            committee: Vec::new(),
            committee_pq: Vec::new(),
            blessing: Vec::new(),
            blessing_pq: Vec::new(),
        };
        let digest = attestation_digest(&route, &delivery);
        let request = json!({
            "adapter": adapter,
            "chain": chain,
            "route": route.storage_key(),
            "dest_chain_id": delivery.dest_chain_id,
            "nonce": delivery.nonce,
            "expiry_ms": delivery.expiry_ms,
            "body": hex::encode(&delivery.body),
            "proof": hex::encode(&delivery.proof),
            "digest": hex::encode(digest),
            "committee": [],
            "committee_pq": [],
            "blessing": [],
            "blessing_pq": [],
        });
        let out = self
            .request_out
            .clone()
            .ok_or_else(|| anyhow!("give --request-out"))?;
        std::fs::write(&out, serde_json::to_vec_pretty(&request)?)?;
        output::print_success(
            "Delivery built from this verifier's own reading of the source chain",
        );
        output::print_field("Route", &route.storage_key());
        output::print_field("Digest to sign", &format!("0x{}", hex::encode(digest)));
        output::print_field("Request", &out.display().to_string());
        Ok(())
    }

    async fn add_signature(&self, rpc: &RpcClient, path: &PathBuf) -> Result<()> {
        let mut request: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        let adapter = request["adapter"].as_str().unwrap_or_default().to_string();
        let chain = request["chain"].as_str().unwrap_or_default().to_string();
        let (route, chain_id) = route_and_chain(rpc, &adapter, &chain).await?;
        let outbound = request["kind"] == "outbound";
        let handover = request["kind"] == "handover";
        let digest = if outbound {
            outbound_digest(
                chain_id,
                &route,
                &hex_bytes(request["record"].as_str().unwrap_or_default(), "record")?,
            )
        } else if handover {
            handover_digest_of(chain_id, &route, &request)?
        } else {
            attestation_digest(&route, &delivery_of(&request)?)
        };
        if hex::encode(digest) != request["digest"].as_str().unwrap_or_default() {
            bail!("the route changed since the delivery was built; build it again");
        }
        // A handover is signed by the committee the contract trusts, as drawn.
        let signing_set = if handover {
            let from_set =
                u32::try_from(request["from"]["set_index"].as_u64().unwrap_or_default())?;
            let from = committee_set(rpc, &adapter, &chain, from_set).await?;
            Some((
                addresses(&from)?,
                u32::try_from(from["threshold"].as_u64().unwrap_or_default())?,
            ))
        } else {
            None
        };
        if let Some(sig) = &self.signature {
            let sig: [u8; 65] = hex_bytes(sig, "signature")?
                .try_into()
                .map_err(|_| anyhow!("a signature is 65 bytes"))?;
            let signer = tenzro_bridge::secp256k1_multisig::recover_address(&digest, &sig)
                .ok_or_else(|| anyhow!("the signature does not recover"))?;
            let committee = if let Some((members, _)) = &signing_set {
                if !members.contains(&signer) {
                    bail!(
                        "0x{} is not a member of the committee handing over",
                        hex::encode(signer)
                    );
                }
                "committee"
            } else if route.verifiers.addresses().contains(&signer) {
                "committee"
            } else if route
                .blessing
                .as_ref()
                .is_some_and(|b| b.addresses().contains(&signer))
            {
                "blessing"
            } else {
                bail!(
                    "0x{} is not a member of the route's committees",
                    hex::encode(signer)
                );
            };
            let list = request[committee]
                .as_array_mut()
                .ok_or_else(|| anyhow!("malformed request"))?;
            let entry = json!([hex::encode(signer), hex::encode(sig)]);
            if !list.iter().any(|e| e[0] == entry[0]) {
                list.push(entry);
            }
            std::fs::write(path, serde_json::to_vec_pretty(&request)?)?;
        }
        if let Some(pq) = &self.pq_signature {
            if outbound || handover {
                bail!("outbound records and handovers are verified by the external chain and take the secp256k1 signature only");
            }
            let pq = hex_bytes(pq, "pq signature")?;
            let seat = |q: &tenzro_bridge::route::VerifierQuorum| {
                q.members
                    .iter()
                    .find(|m| {
                        tenzro_crypto::pq::ml_dsa_verify(
                            &m.pq_public_key,
                            tenzro_bridge::route::attestation::ROUTE_ATTESTATION_PQ_CONTEXT,
                            &digest,
                            &pq,
                        )
                        .is_ok()
                    })
                    .map(|m| m.address)
            };
            let (committee, signer) = if let Some(a) = seat(&route.verifiers) {
                ("committee_pq", a)
            } else if let Some(a) = route.blessing.as_ref().and_then(seat) {
                ("blessing_pq", a)
            } else {
                bail!("the ML-DSA-65 signature is not by any member of the route's committees");
            };
            let list = request[committee]
                .as_array_mut()
                .ok_or_else(|| anyhow!("malformed request"))?;
            let entry = json!([hex::encode(signer), hex::encode(&pq)]);
            if !list.iter().any(|e| e[0] == entry[0]) {
                list.push(entry);
            }
            std::fs::write(path, serde_json::to_vec_pretty(&request)?)?;
        }
        let count = |k: &str| request[k].as_array().map_or(0, |a| a.len());
        let have = |n: usize, t: u32| n >= t as usize;
        if let Some((_, threshold)) = signing_set {
            output::print_field(
                "Committee",
                &format!("{} of {}", count("committee"), threshold),
            );
            if have(count("committee"), threshold) {
                output::print_success(
                    "The trusted committee's threshold signed; any relayer submits the handover to the bridge contract",
                );
                output::print_field("Set index", &request["handover"]["set_index"].to_string());
                output::print_field(
                    "Members",
                    &serde_json::to_string(&request["handover"]["members"])?,
                );
                output::print_field("Threshold", &request["handover"]["threshold"].to_string());
                output::print_field(
                    "Expires at (Unix s)",
                    &request["handover"]["expires_at_secs"].to_string(),
                );
                output::print_field("Signatures", &serde_json::to_string(&request["committee"])?);
            }
            return Ok(());
        }
        if outbound {
            output::print_field(
                "Committee",
                &format!("{} of {}", count("committee"), route.verifiers.threshold),
            );
            if have(count("committee"), route.verifiers.threshold) {
                output::print_success(
                    "The committee's threshold signed; submit the record and signatures to the bridge contract",
                );
                output::print_field(
                    "Record",
                    &format!("0x{}", request["record"].as_str().unwrap_or_default()),
                );
                output::print_field("Signatures", &serde_json::to_string(&request["committee"])?);
            }
            return Ok(());
        }
        let delivery = delivery_of(&request)?;
        let dual = |q: &tenzro_bridge::route::VerifierQuorum,
                    sigs: &[([u8; 20], [u8; 65])],
                    pq: &[([u8; 20], Vec<u8>)]| {
            tenzro_bridge::route::attestation::dual_signers(q, &digest, sigs, pq).len()
        };
        let signed = dual(&route.verifiers, &delivery.committee, &delivery.committee_pq);
        let blessed = route
            .blessing
            .as_ref()
            .map(|b| dual(b, &delivery.blessing, &delivery.blessing_pq));
        let complete = have(signed, route.verifiers.threshold)
            && route
                .blessing
                .as_ref()
                .zip(blessed)
                .is_none_or(|(b, n)| have(n, b.threshold));
        output::print_field(
            "Committee (both legs)",
            &format!("{} of {}", signed, route.verifiers.threshold),
        );
        if let (Some(b), Some(n)) = (&route.blessing, blessed) {
            output::print_field("Blessing (both legs)", &format!("{} of {}", n, b.threshold));
        }
        if complete {
            output::print_success(
                "Every committee holds its threshold; deliver with `tenzro bridge deliver`",
            );
            output::print_field("Delivery", &format!("0x{}", hex::encode(delivery.encode())));
        }
        Ok(())
    }

    pub async fn execute(&self) -> Result<()> {
        output::print_header("Bridge Attest");
        let rpc = RpcClient::new(&self.rpc);
        match &self.request_in {
            Some(path) => self.add_signature(&rpc, path).await,
            None => self.build(&rpc).await,
        }
    }
}
