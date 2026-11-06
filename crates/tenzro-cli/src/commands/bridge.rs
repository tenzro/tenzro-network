//! Bridge commands for the Tenzro CLI.
//!
//! TNZO moves between Tenzro and external chains only over governed routes:
//! a CCIP-compatible envelope for Ethereum, Base, Arbitrum and Solana, IBC
//! for Cosmos chains, Bitcoin deposits and contract routes to Stellar, Sui,
//! Aptos and TON. These commands list the routes, send TNZO out
//! over one (holder-signed), and hand the node a committee-attested inbound
//! delivery.

use crate::output;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// Bridge commands
#[derive(Debug, Subcommand)]
pub enum BridgeCommand {
    /// List every governed route with its caps, epoch usage and supply
    Routes(BridgeRoutesCmd),
    /// Show one route by transport and external chain
    Route(BridgeRouteCmd),
    /// Send TNZO to an external chain, or withdraw a deposit asset over its
    /// deposit route (signed in hardware by the holder)
    Send(BridgeSendCmd),
    /// Deliver a committee-attested inbound transfer
    Deliver(BridgeDeliverCmd),
    /// Relay a light-client update (bootstrap or committee handover) for a route
    LightClient(BridgeLightClientCmd),
    /// Relay an IBC message (a classic handshake step, or a packet's
    /// acknowledgement or timeout) from the Cosmos chain of an IBC route
    Ibc(super::bridge_ibc::BridgeIbcCmd),
    /// Build a delivery for a route's verifiers to sign from the source
    /// chain, or add a verifier's signature to one
    Attest(super::bridge_attest::BridgeAttestCmd),
    /// Print the Bitcoin deposit descriptor for a set of signers
    Descriptor(super::bridge_withdrawal::BridgeDescriptorCmd),
    /// Sign a Bitcoin route's withdrawal
    Withdrawal(super::bridge_withdrawal::BridgeWithdrawalCmd),
    /// Draw a route's committees from the bonded attestors with a bridge
    /// signer, once a draw is due
    DrawCommittee(BridgeDrawCommitteeCmd),
    /// Report a committee member that signed two deliveries with one nonce
    ReportEquivocation(BridgeReportEquivocationCmd),
    /// Report a committee member that signed a handover to a committee the chain did not draw
    ReportWrongHandover(BridgeReportWrongHandoverCmd),
    /// Show the network-wide exit limits: each unit's cap per epoch and what
    /// has left this epoch, the exit delay rule and the cap-raise bound
    Outflow(BridgeOutflowCmd),
    /// Show a queued exit
    Exit(BridgeExitCmd),
    /// Release a queued exit whose delay has passed
    ReleaseExit(BridgeReleaseExitCmd),
    /// Cancel a queued exit and return its value to the sender
    CancelExit(BridgeCancelExitCmd),
}

impl BridgeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Routes(cmd) => cmd.execute().await,
            Self::Route(cmd) => cmd.execute().await,
            Self::Send(cmd) => cmd.execute().await,
            Self::Deliver(cmd) => cmd.execute().await,
            Self::LightClient(cmd) => cmd.execute().await,
            Self::Ibc(cmd) => cmd.execute().await,
            Self::Attest(cmd) => cmd.execute().await,
            Self::Descriptor(cmd) => cmd.execute().await,
            Self::Withdrawal(cmd) => cmd.execute().await,
            Self::DrawCommittee(cmd) => cmd.execute().await,
            Self::ReportEquivocation(cmd) => cmd.execute().await,
            Self::ReportWrongHandover(cmd) => cmd.execute().await,
            Self::Outflow(cmd) => cmd.execute().await,
            Self::Exit(cmd) => cmd.execute().await,
            Self::ReleaseExit(cmd) => cmd.execute().await,
            Self::CancelExit(cmd) => cmd.execute().await,
        }
    }
}

fn print_route(route: &serde_json::Value) {
    let s = |k: &str| {
        route
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    output::print_field("Route", &s("key"));
    output::print_field("Transport", &s("adapter"));
    output::print_field("Family", &s("family"));
    output::print_field("Chain", &s("source_chain"));
    if let Some(version) = route["lane"]["version"].as_str() {
        output::print_field("CCIP on-ramp", version);
    }
    let limit = &route["mint_limit"];
    output::print_field("Per transfer", limit["per_mint"].as_str().unwrap_or(""));
    output::print_field(
        "Remaining this epoch",
        limit["remaining_this_epoch"].as_str().unwrap_or("unset"),
    );
    output::print_field("Locked", route["supply"]["locked"].as_str().unwrap_or("0"));
    output::print_field(
        "Outstanding",
        route["supply"]["bridged"].as_str().unwrap_or("0"),
    );
    output::print_field("Mode", route["mode"].as_str().unwrap_or(""));
    if let Some(refusal) = route["open_refusal"].as_str() {
        output::print_field("Cannot open", refusal);
    }
    if let Some(head) = route.get("light_client_head").filter(|h| !h.is_null()) {
        output::print_field(
            "Light client",
            &format!(
                "{} finalized {} (period {})",
                head["kind"].as_str().unwrap_or(""),
                head["finalized"],
                head["period"]
            ),
        );
    } else if route.get("light_client").is_some_and(|l| !l.is_null()) {
        output::print_field("Light client", "not bootstrapped; deliveries refused");
    }
    if let Some(v) = route.get("violation").and_then(|v| v.as_str()) {
        output::print_field("Not enforced", v);
    }
}

/// List every governed route
#[derive(Debug, Parser)]
pub struct BridgeRoutesCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BridgeRoutesCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Bridge Routes");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_listBridgeRoutes", serde_json::json!({}))
            .await?;
        let routes = result["routes"].as_array().cloned().unwrap_or_default();
        if routes.is_empty() {
            output::print_info("No governed routes are installed.");
        }
        for route in &routes {
            print_route(route);
            println!();
        }
        Ok(())
    }
}

/// Show one route
#[derive(Debug, Parser)]
pub struct BridgeRouteCmd {
    /// Route transport: ccip, ibc, deposit or contract
    #[arg(long)]
    adapter: String,
    /// External chain (e.g. "ethereum", "base", "arbitrum", "solana")
    #[arg(long)]
    chain: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BridgeRouteCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Bridge Route");
        let rpc = RpcClient::new(&self.rpc);
        let route: serde_json::Value = rpc
            .call(
                "tenzro_getBridgeRoute",
                serde_json::json!({ "adapter": self.adapter, "source_chain": self.chain }),
            )
            .await?;
        print_route(&route);
        Ok(())
    }
}

/// Send TNZO to an external chain over its governed route: a `Bridge`
/// transaction signed in hardware as the client account, the holder. The
/// amount locks in the route's vault and the route queues the message its
/// committee attests on the external chain.
#[derive(Debug, Parser)]
pub struct BridgeSendCmd {
    /// Destination chain, served by exactly one governed route
    #[arg(long)]
    target_chain: String,
    /// Recipient on the destination chain (hex); for Bitcoin, the output
    /// script to pay
    #[arg(long)]
    recipient: String,
    /// Amount in the smallest unit (decimal): TNZO wei, or the deposit
    /// asset's unit over a deposit route, or the carried asset's unit
    #[arg(long)]
    amount: String,
    /// A carried asset's symbol (USDC, OUSD): burns its representation here
    /// and the route's vault releases the token on the destination chain
    #[arg(long)]
    asset: Option<String>,
    #[command(flatten)]
    signer: super::signer::Signer,
}

impl BridgeSendCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Bridge Send");
        let recipient = hex::decode(self.recipient.trim_start_matches("0x"))
            .map_err(|_| anyhow::anyhow!("--recipient must be hex"))?;
        let amount: u128 = self
            .amount
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("--amount must be a decimal integer"))?;
        let op = tenzro_types::bridge_transfer::BridgeOp::Outbound {
            target_chain: self.target_chain.to_ascii_lowercase(),
            recipient,
            amount,
            asset: self.asset.as_ref().map(|a| a.to_ascii_uppercase()),
        };
        op.validate().map_err(|e| anyhow::anyhow!(e))?;
        self.signer
            .send_tx(
                tenzro_types::transaction::TransactionType::Bridge { op },
                "Bridge",
            )
            .await
    }
}

/// Deliver a committee-attested inbound transfer: a `Bridge` transaction
/// the relayer signs in hardware and pays the gas of
#[derive(Debug, Parser)]
pub struct BridgeDeliverCmd {
    /// Route transport: ccip, ibc, deposit or contract
    #[arg(long)]
    adapter: String,
    /// External chain the delivery comes from
    #[arg(long)]
    from_chain: String,
    /// The attested delivery (hex)
    #[arg(long)]
    delivery: String,
    #[command(flatten)]
    signer: super::signer::Signer,
}

/// The gas a relayed bridge operation may use: its base plus its payload.
pub(crate) fn relay_gas(payload_len: usize) -> u64 {
    200_000 + 16 * payload_len as u64
}

fn adapter(name: &str) -> Result<tenzro_types::bridge_route::BridgeRouteAdapter> {
    tenzro_types::bridge_route::BridgeRouteAdapter::parse(name).ok_or_else(|| {
        anyhow::anyhow!(
            "'{name}' is not a route transport ({})",
            tenzro_types::bridge_route::BridgeRouteAdapter::names()
        )
    })
}

/// Sign `op` as the relayer's own account and submit it.
pub(crate) async fn relay(
    signer: &super::signer::Signer,
    op: tenzro_types::bridge_transfer::BridgeOp,
) -> Result<()> {
    op.validate().map_err(|e| anyhow::anyhow!(e))?;
    let gas = relay_gas(op.payload_len());
    signer
        .send_tx_with_gas(
            tenzro_types::transaction::TransactionType::Bridge { op },
            "Bridge",
            gas,
        )
        .await
}

impl BridgeDeliverCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Bridge Deliver");
        let delivery = hex::decode(self.delivery.trim_start_matches("0x"))
            .map_err(|_| anyhow::anyhow!("--delivery must be hex"))?;
        relay(
            &self.signer,
            tenzro_types::bridge_transfer::BridgeOp::Inbound {
                adapter: adapter(&self.adapter)?,
                source_chain: self.from_chain.to_ascii_lowercase(),
                delivery,
            },
        )
        .await
    }
}

/// Relay a light-client update for a route
#[derive(Debug, Parser)]
pub struct BridgeLightClientCmd {
    /// Route transport: ccip, ibc, deposit or contract
    #[arg(long)]
    adapter: String,
    /// External chain the light client follows
    #[arg(long)]
    chain: String,
    /// The update (hex): the bootstrap from the route's anchor, or a
    /// committee handover
    #[arg(long, conflicts_with_all = ["beacon", "cosmos_rpc"], required_unless_present_any = ["beacon", "cosmos_rpc"])]
    update: Option<String>,
    /// A beacon node's Beacon API base URL: read the route's light-client
    /// state, fetch the update it needs next (the bootstrap from its anchor,
    /// or the handover of its current period) and relay it
    #[arg(long, conflicts_with = "cosmos_rpc")]
    beacon: Option<String>,
    /// A CometBFT RPC endpoint of the route's Cosmos chain: relay the
    /// bootstrap from the route's anchor, or the header at `--height`
    /// (default: the latest) from the height the light client trusts
    #[arg(long)]
    cosmos_rpc: Option<String>,
    /// With `--cosmos-rpc`: the header height to move the light client to
    #[arg(long, requires = "cosmos_rpc")]
    height: Option<u64>,
    #[command(flatten)]
    signer: super::signer::Signer,
}

impl BridgeLightClientCmd {
    /// The next update the route's light client needs, fetched from a beacon
    /// node and encoded as the light client takes it (hex).
    async fn update_from_beacon(
        &self,
        rpc: &crate::rpc::RpcClient,
        beacon: &str,
    ) -> Result<String> {
        use tenzro_bridge::route::ethereum_light_client::beacon_api;
        use tenzro_types::bridge_route::LightClientAnchor;
        let route: serde_json::Value = rpc
            .call(
                "tenzro_getBridgeRoute",
                serde_json::json!({ "adapter": self.adapter, "source_chain": self.chain }),
            )
            .await?;
        let anchor: LightClientAnchor = serde_json::from_value(route["light_client"].clone())
            .map_err(|_| anyhow::anyhow!("the route has no light client"))?;
        let LightClientAnchor::EthereumSyncCommittee {
            trusted_block_root, ..
        } = anchor
        else {
            anyhow::bail!(
                "--beacon relays a beacon-chain light client; this route follows another kind"
            );
        };
        let base = beacon.trim_end_matches('/');
        let client = reqwest::Client::new();
        let get = |url: String| {
            let client = client.clone();
            async move {
                let resp = client
                    .get(&url)
                    .header("accept", "application/json")
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    anyhow::bail!("{url}: {}", resp.status());
                }
                Ok::<serde_json::Value, anyhow::Error>(resp.json().await?)
            }
        };
        let bytes = match route["light_client_head"].as_object() {
            None => {
                let url = format!(
                    "{base}/eth/v1/beacon/light_client/bootstrap/0x{}",
                    hex::encode(trusted_block_root)
                );
                beacon_api::bootstrap(&get(url).await?)?
            }
            Some(head) => {
                // With the next committee known, the update that finalizes a
                // header of the next period moves it over; without, the
                // current period's update proves the next committee.
                let current = head.get("period").and_then(|v| v.as_u64()).unwrap_or(0);
                let next_known = head
                    .get("next_known")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let period = current + u64::from(next_known);
                let url = format!(
                    "{base}/eth/v1/beacon/light_client/updates?start_period={period}&count=1"
                );
                let updates = get(url).await?;
                let first = updates.as_array().and_then(|a| a.first()).ok_or_else(|| {
                    anyhow::anyhow!("the beacon node has no update for period {period}")
                })?;
                beacon_api::handover(first)?
            }
        };
        Ok(format!("0x{}", hex::encode(bytes)))
    }

    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Bridge Light Client");
        let rpc = RpcClient::new(self.signer.rpc_url());
        let update = match (&self.update, &self.beacon, &self.cosmos_rpc) {
            (Some(update), ..) => update.clone(),
            (None, Some(beacon), _) => self.update_from_beacon(&rpc, beacon).await?,
            (None, None, Some(cosmos)) => {
                let cosmos = super::bridge_ibc::CometBft::new(cosmos);
                let bytes = super::bridge_ibc::light_client_update(
                    &rpc,
                    &self.chain.to_ascii_lowercase(),
                    &cosmos,
                    self.height,
                )
                .await?;
                format!("0x{}", hex::encode(bytes))
            }
            (None, None, None) => anyhow::bail!("give --update, --beacon or --cosmos-rpc"),
        };
        let update = hex::decode(update.trim_start_matches("0x"))
            .map_err(|_| anyhow::anyhow!("--update must be hex"))?;
        relay(
            &self.signer,
            tenzro_types::bridge_transfer::BridgeOp::LightClientUpdate {
                adapter: adapter(&self.adapter)?,
                source_chain: self.chain.to_ascii_lowercase(),
                update,
            },
        )
        .await
    }
}

/// Draw a route's committees from the bonded attestors with a bridge signer
#[derive(Debug, clap::Parser)]
pub struct BridgeDrawCommitteeCmd {
    /// Route transport: ccip, ibc, deposit or contract
    #[arg(long)]
    adapter: String,
    /// External chain of the route
    #[arg(long)]
    chain: String,
    #[command(flatten)]
    signer: super::signer::Signer,
}

impl BridgeDrawCommitteeCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Draw Bridge Committee");
        relay(
            &self.signer,
            tenzro_types::bridge_transfer::BridgeOp::DrawCommittee {
                adapter: adapter(&self.adapter)?,
                source_chain: self.chain.clone(),
            },
        )
        .await
    }
}

/// Show the network-wide exit limits
#[derive(Debug, clap::Parser)]
pub struct BridgeOutflowCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BridgeOutflowCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getBridgeOutflow", serde_json::json!({}))
            .await?;
        output::print_json(&result)
    }
}

/// Show a queued exit
#[derive(Debug, clap::Parser)]
pub struct BridgeExitCmd {
    /// The exit's id
    #[arg(long)]
    id: u64,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BridgeExitCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getBridgeExit", serde_json::json!({ "id": self.id }))
            .await?;
        output::print_json(&result)
    }
}

/// Release a queued exit whose delay has passed
#[derive(Debug, clap::Parser)]
pub struct BridgeReleaseExitCmd {
    /// The exit's id
    #[arg(long)]
    id: u64,
    #[command(flatten)]
    signer: super::signer::Signer,
}

impl BridgeReleaseExitCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Release Bridge Exit");
        relay(
            &self.signer,
            tenzro_types::bridge_transfer::BridgeOp::ReleaseExit { id: self.id },
        )
        .await
    }
}

/// Cancel a queued exit and return its value to the sender
#[derive(Debug, clap::Parser)]
pub struct BridgeCancelExitCmd {
    /// The exit's id
    #[arg(long)]
    id: u64,
    #[command(flatten)]
    signer: super::signer::Signer,
}

impl BridgeCancelExitCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Cancel Bridge Exit");
        relay(
            &self.signer,
            tenzro_types::bridge_transfer::BridgeOp::CancelExit { id: self.id },
        )
        .await
    }
}

/// Report a committee member that signed two deliveries with one nonce
#[derive(Debug, clap::Parser)]
pub struct BridgeReportEquivocationCmd {
    /// Route transport: ccip, ibc, deposit or contract
    #[arg(long)]
    adapter: String,
    /// External chain of the route
    #[arg(long)]
    chain: String,
    /// The member's 20-byte signing address (hex)
    #[arg(long)]
    member: String,
    /// One delivery the member signed (hex)
    #[arg(long)]
    first: String,
    /// Another delivery with the same nonce the member signed (hex)
    #[arg(long)]
    second: String,
    #[command(flatten)]
    signer: super::signer::Signer,
}

impl BridgeReportEquivocationCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Report Bridge Equivocation");
        let bytes =
            |h: &str| hex::decode(h.trim_start_matches("0x")).map_err(|e| anyhow::anyhow!(e));
        relay(
            &self.signer,
            tenzro_types::bridge_transfer::BridgeOp::ReportEquivocation {
                adapter: adapter(&self.adapter)?,
                source_chain: self.chain.clone(),
                member: bytes(&self.member)?,
                first: bytes(&self.first)?,
                second: bytes(&self.second)?,
            },
        )
        .await
    }
}

/// Report a committee member that signed a handover to a committee the chain did not draw
#[derive(Debug, clap::Parser)]
pub struct BridgeReportWrongHandoverCmd {
    /// Route transport: ccip, ibc, deposit or contract
    #[arg(long)]
    adapter: String,
    /// External chain of the route
    #[arg(long)]
    chain: String,
    /// The committee the signer sat on
    #[arg(long)]
    signed_by_set: u32,
    /// The set index the handover names
    #[arg(long)]
    set_index: u32,
    /// The handover's member addresses (20-byte hex each), in order
    #[arg(long, value_delimiter = ',', required = true)]
    members: Vec<String>,
    /// The handover's threshold
    #[arg(long)]
    threshold: u32,
    /// The handover's expiry, Unix seconds
    #[arg(long)]
    expires_at: u64,
    /// The member's 65-byte signature over the handover digest (hex)
    #[arg(long)]
    signature: String,
    #[command(flatten)]
    signer: super::signer::Signer,
}

impl BridgeReportWrongHandoverCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Report Bridge Handover");
        let bytes =
            |h: &str| hex::decode(h.trim_start_matches("0x")).map_err(|e| anyhow::anyhow!(e));
        let mut members = Vec::with_capacity(20 * self.members.len());
        for m in &self.members {
            let a = bytes(m)?;
            if a.len() != 20 {
                anyhow::bail!("member {m} is not a 20-byte address");
            }
            members.extend(a);
        }
        relay(
            &self.signer,
            tenzro_types::bridge_transfer::BridgeOp::ReportWrongHandover {
                adapter: adapter(&self.adapter)?,
                source_chain: self.chain.clone(),
                signed_by_set: self.signed_by_set,
                set_index: self.set_index,
                members,
                threshold: self.threshold,
                expires_at_secs: self.expires_at,
                signature: bytes(&self.signature)?,
            },
        )
        .await
    }
}
