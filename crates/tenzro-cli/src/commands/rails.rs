//! `tenzro rails` — where a payment can settle, and where a given charge should.
//!
//! Supporting x402 on a rail and that rail being able to carry a micropayment
//! are different properties. Base speaks x402 fluently and still cannot carry a
//! one-cent charge without roughly ten percent overhead. This command shows
//! both, so an operator picking a settlement asset can see which rails carry it
//! and what the smallest worthwhile payment on each is.

use crate::output;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// Settlement rails and micropayment routing.
#[derive(Debug, Subcommand)]
pub enum RailsCommand {
    /// List every network a payment can settle on.
    List(ListCmd),
    /// Ask where a specific charge would settle.
    Route(RouteCmd),
}

impl RailsCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::List(c) => c.execute().await,
            Self::Route(c) => c.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct ListCmd {
    /// Show only rails that can settle an x402 payment.
    #[arg(long)]
    x402_only: bool,
    /// Show only rails carrying this asset (e.g. USDC, RLUSD, pUSD).
    #[arg(long)]
    asset: Option<String>,
    #[arg(long)]
    json: bool,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call("tenzro_settlementNetworks", serde_json::json!({}))
            .await?;
        if self.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }

        output::print_header("Settlement rails");
        output::print_field("Primary", result["primary"].as_str().unwrap_or("?"));
        output::print_field(
            "Micro-settlement floor",
            result["micro_settlement_floor_wei"].as_str().unwrap_or("?"),
        );
        println!();

        for n in result["networks"].as_array().unwrap_or(&vec![]) {
            if self.x402_only && !n["x402"].as_bool().unwrap_or(false) {
                continue;
            }
            if let Some(want) = &self.asset {
                let carries = n["native_stablecoins"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .any(|s| s.as_str().is_some_and(|s| s.eq_ignore_ascii_case(want)))
                    })
                    .unwrap_or(false)
                    || n["native_asset"]
                        .as_str()
                        .is_some_and(|s| s.eq_ignore_ascii_case(want));
                if !carries {
                    continue;
                }
            }
            let assets: Vec<&str> = n["native_stablecoins"]
                .as_array()
                .map(|a| a.iter().filter_map(|s| s.as_str()).collect())
                .unwrap_or_default();
            output::print_field(
                n["name"].as_str().unwrap_or("?"),
                &format!(
                    "{} — {}, min {} µUSD{}{}",
                    n["caip2"].as_str().unwrap_or("?"),
                    n["family"].as_str().unwrap_or("?"),
                    n["min_payment_micro_usd"],
                    if n["x402"].as_bool().unwrap_or(false) {
                        ", x402"
                    } else {
                        ""
                    },
                    if assets.is_empty() {
                        String::new()
                    } else {
                        format!(" [{}]", assets.join(", "))
                    }
                ),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct RouteCmd {
    /// Charge to route, in TNZO wei.
    amount_wei: String,
    /// Asset the payee wants to hold. Omit for TNZO on the home chain.
    #[arg(long)]
    asset: Option<String>,
    /// TNZO price in micro-USD, needed to compare against a rail's fee.
    /// Without it the node settles on the home chain rather than guessing.
    #[arg(long)]
    tnzo_micro_usd: Option<u64>,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RouteCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_settlementNetworks",
                serde_json::json!({
                    "amount_wei": self.amount_wei,
                    "asset": self.asset,
                    "tnzo_micro_usd": self.tnzo_micro_usd,
                }),
            )
            .await?;

        let route = &result["route"];
        output::print_header("Routing decision");
        output::print_field("Amount (wei)", &self.amount_wei);
        output::print_field("Decision", route["kind"].as_str().unwrap_or("?"));
        output::print_field(
            "Settles now",
            if route["settles_now"].as_bool().unwrap_or(false) {
                "yes"
            } else {
                "no"
            },
        );
        match route["kind"].as_str() {
            Some("accumulate") => output::print_warning(
                "Below the micro-settlement floor — hold it in a micropayment channel. \
                 Settling it alone would cost more than it moves.",
            ),
            Some("no_viable_rail") => output::print_warning(
                "No rail carries this asset at this size. Accumulate, or have the payee \
                 accept another asset.",
            ),
            _ => output::print_field(
                "Rail",
                route["detail"]["caip2"].as_str().unwrap_or("tenzro:1337"),
            ),
        }
        Ok(())
    }
}

/// Interaction receipts — the accounting layer.
#[derive(Debug, Subcommand)]
pub enum InteractionCommand {
    /// Read an anchored interaction and its attestation digest.
    Get(GetInteractionCmd),
    /// Check a receipt you were handed against what the node anchored.
    Verify(VerifyInteractionCmd),
    /// Record an anchored settlement on other chains, in parallel.
    Mirror(MirrorInteractionCmd),
}

impl InteractionCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Get(c) => c.execute().await,
            Self::Verify(c) => c.execute().await,
            Self::Mirror(c) => c.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct GetInteractionCmd {
    /// Interaction id.
    interaction_id: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl GetInteractionCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let r: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_getInteraction",
                serde_json::json!({ "interaction_id": self.interaction_id }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&r)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct VerifyInteractionCmd {
    /// Path to the receipt JSON you were handed.
    receipt_json: String,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl VerifyInteractionCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let raw = std::fs::read_to_string(&self.receipt_json)?;
        let interaction: serde_json::Value = serde_json::from_str(&raw)?;
        let r: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_verifyInteraction",
                serde_json::json!({ "interaction": interaction }),
            )
            .await?;

        output::print_header("Receipt verification");
        let ok = r["verified"].as_bool().unwrap_or(false);
        output::print_field("Verified", if ok { "yes" } else { "NO" });
        output::print_field("Reason", r["reason"].as_str().unwrap_or("?"));
        output::print_field(
            "Submitted digest",
            r["submitted_digest"].as_str().unwrap_or("?"),
        );
        if let Some(a) = r["anchored_digest"].as_str() {
            output::print_field("Anchored digest", a);
        }
        if !ok {
            output::print_warning(
                "The receipt does not match what this node anchored. Either it was altered after \
                 issue, or it was anchored on a different node.",
            );
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct MirrorInteractionCmd {
    /// Interaction id, already anchored.
    interaction_id: String,
    /// Chains to mirror onto — CAIP-2 ids or adapter chain names.
    /// Repeat the flag for several.
    #[arg(long = "chain", required = true)]
    chains: Vec<String>,
    /// Write only the digest rather than the full settlement bytes.
    ///
    /// Cheaper, and it proves a payload you already hold is the one that
    /// settled — but it cannot say *what* settled, so it does not survive the
    /// Tenzro Ledger losing state.
    #[arg(long)]
    digest_only: bool,
    /// Whether the primary settlement committed.
    #[arg(long, default_value_t = true)]
    primary_committed: bool,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl MirrorInteractionCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        let targets: Vec<serde_json::Value> = self
            .chains
            .iter()
            .map(|c| serde_json::json!({ "chain": c, "self_contained": !self.digest_only }))
            .collect();
        let r: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_mirrorSettlement",
                serde_json::json!({
                    "interaction_id": self.interaction_id,
                    "targets": targets,
                    "primary_committed": self.primary_committed,
                }),
            )
            .await?;

        output::print_header("Settlement mirror");
        output::print_field("Interaction", &self.interaction_id);
        output::print_field("Digest", r["attestation_digest"].as_str().unwrap_or("?"));
        output::print_field(
            "Fully mirrored",
            if r["fully_mirrored"].as_bool().unwrap_or(false) {
                "yes"
            } else {
                "no"
            },
        );
        println!();
        for o in r["outcomes"].as_array().unwrap_or(&vec![]) {
            let state = o["state"].as_str().unwrap_or("?");
            output::print_field(
                o["chain"].as_str().unwrap_or("?"),
                &format!(
                    "{state} ({}){}",
                    o["durability"].as_str().unwrap_or("?"),
                    o["reference"]
                        .as_str()
                        .map(|s| format!(" — {s}"))
                        .or_else(|| o["reason"].as_str().map(|s| format!(" — {s}")))
                        .unwrap_or_default()
                ),
            );
        }
        println!();
        if r["durable_beyond_primary"].as_bool().unwrap_or(false) {
            output::print_field("Durability", "survives the Tenzro Ledger losing state");
        } else {
            output::print_warning(
                "This settlement does NOT survive the Tenzro Ledger losing state. A digest-only \
                 mirror proves a payload matches but cannot say what settled; mirror at least one \
                 chain with the full settlement bytes.",
            );
        }
        Ok(())
    }
}
