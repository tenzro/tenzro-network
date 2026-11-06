//! Provider management commands for the Tenzro CLI

use crate::output::{self};
use anyhow::Result;
use clap::{Parser, Subcommand};

/// Provider management commands
#[derive(Debug, Subcommand)]
pub enum ProviderCommand {
    #[command(flatten)]
    Rpc(ProviderRpcCommand),
    /// Show provider status
    Status(ProviderStatusCmd),
    /// List models being served
    Models(ProviderModelsCmd),
    /// List all providers discovered on the network
    List(ProviderListCmd),
    /// Price one request at every provider serving a model, cheapest first
    Quote(ProviderQuoteCmd),
    /// Show a provider's standing, price cards, and settled volume and latency
    Scorecard(ProviderScorecardCmd),
    /// A provider's settlement statement for a window, by UTC day or month
    Statement(ProviderStatementCmd),
    /// Provider pricing management
    #[command(subcommand)]
    Pricing(PricingCommand),
    /// Compute bond (admission collateral) management
    #[command(subcommand)]
    Bond(BondCommand),
}

impl ProviderCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Rpc(cmd) => cmd.execute().await,
            Self::Status(cmd) => cmd.execute().await,
            Self::Models(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Quote(cmd) => cmd.execute().await,
            Self::Scorecard(cmd) => cmd.execute().await,
            Self::Statement(cmd) => cmd.execute().await,
            Self::Pricing(cmd) => cmd.execute().await,
            Self::Bond(cmd) => cmd.execute().await,
        }
    }
}

/// Show a provider's standing on chain, its announced price cards, and the
/// count, value and p50/p95 latency of its settlements over 24 hours and 7
/// days as the queried node recorded them
#[derive(Debug, Parser)]
pub struct ProviderScorecardCmd {
    /// The provider's account address
    provider: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProviderScorecardCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getProviderScorecard",
                serde_json::json!({ "provider": self.provider }),
            )
            .await?;
        output::print_json(&result)
    }
}

/// A provider's settlement statement over a window: every call the queried
/// node recorded as settled to the provider, with its settlement transaction,
/// payment reference and delivery receipts, summed by UTC day or month, by
/// model and work class, and by payer. Fees, burn and the treasury leg are
/// TNZO; gross and net are in the payment's asset. With --verify, each settled
/// line is re-read from the chain (the payment record and the settlement
/// transaction's receipt) and every summary and total is recomputed; any
/// difference is reported and the command exits non-zero.
#[derive(Debug, Parser)]
pub struct ProviderStatementCmd {
    /// The provider's account address
    #[arg(long)]
    provider: String,
    /// Start of the window, inclusive: a UTC date (YYYY-MM-DD) or unix milliseconds
    #[arg(long)]
    from: String,
    /// End of the window, exclusive: a UTC date (YYYY-MM-DD) or unix milliseconds
    #[arg(long)]
    to: String,
    /// Period the statement is cut into: day or month
    #[arg(long, default_value = "day")]
    period: String,
    /// Output format: json or csv
    #[arg(long, default_value = "json")]
    format: String,
    /// With csv, one row per call instead of the summary rows
    #[arg(long)]
    lines: bool,
    /// Recompute the statement from chain data and exit non-zero on any difference
    #[arg(long)]
    verify: bool,
    /// Node to read the chain from when verifying [default: --rpc]
    #[arg(long)]
    verify_rpc: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Another node the provider served through, such as a platform it
    /// moved from; its lines join the statement. Repeat for each.
    #[arg(long = "also-rpc")]
    also_rpc: Vec<String>,
}

/// A UTC date or unix milliseconds, as unix milliseconds.
fn window_edge(s: &str) -> Result<u64> {
    if let Ok(ms) = s.parse::<u64>() {
        return Ok(ms);
    }
    let day = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|_| {
        anyhow::anyhow!("'{s}' is neither a date (YYYY-MM-DD) nor unix milliseconds")
    })?;
    let ms = day
        .and_hms_opt(0, 0, 0)
        .expect("midnight exists")
        .and_utc()
        .timestamp_millis();
    u64::try_from(ms).map_err(|_| anyhow::anyhow!("'{s}' is before 1970"))
}

/// What the chain holds for one settled line, read from `rpc`.
async fn chain_facts(
    rpc: &crate::rpc::RpcClient,
    line: &tenzro_types::statement::Line,
) -> Result<Option<tenzro_types::statement::ChainFacts>> {
    let (Some(pay_ref), Some(tx_hash)) = (&line.pay_ref, &line.tx_hash) else {
        return Ok(None);
    };
    let record: serde_json::Value = rpc
        .call(
            "tenzro_getPayment",
            serde_json::json!({ "pay_ref": pay_ref }),
        )
        .await?;
    if record.is_null() {
        return Ok(None);
    }
    let receipt: serde_json::Value = rpc
        .call(
            "eth_getTransactionReceipt",
            serde_json::json!([format!("0x{}", tx_hash.trim_start_matches("0x"))]),
        )
        .await?;
    tenzro_types::statement::ChainFacts::from_rpc(&record, &receipt)
        .map(Some)
        .map_err(anyhow::Error::msg)
}

impl ProviderStatementCmd {
    pub async fn execute(&self) -> Result<()> {
        use tenzro_types::statement::{Line, Period, build, lines_csv, summary_csv, verify};
        let period: Period = self.period.parse().map_err(anyhow::Error::msg)?;
        let (from_ms, to_ms) = (window_edge(&self.from)?, window_edge(&self.to)?);
        if from_ms >= to_ms {
            anyhow::bail!("--from must be before --to");
        }
        if self.format != "json" && self.format != "csv" {
            anyhow::bail!("--format is json or csv");
        }
        let mut sources = Vec::new();
        let mut complete = true;
        for endpoint in std::iter::once(&self.rpc).chain(&self.also_rpc) {
            let rpc = crate::rpc::RpcClient::new(endpoint);
            let mut lines = Vec::new();
            let mut cursor = serde_json::Value::Null;
            loop {
                let page: serde_json::Value = rpc
                    .call(
                        "tenzro_listSettlements",
                        serde_json::json!({
                            "provider": self.provider, "from_ms": from_ms, "to_ms": to_ms,
                            "limit": 200, "cursor": cursor,
                        }),
                    )
                    .await?;
                for e in page["settlements"].as_array().into_iter().flatten() {
                    lines.push(Line::from_settlement(e).map_err(anyhow::Error::msg)?);
                }
                // The node keeps a bounded record; once it has dropped entries
                // the window may be missing calls.
                if page["recorded"].as_u64() > page["kept"].as_u64() {
                    complete = false;
                }
                match &page["cursor"] {
                    serde_json::Value::Null => break,
                    c => cursor = c.clone(),
                }
            }
            sources.push((endpoint.clone(), lines));
        }
        let lines = if sources.len() == 1 {
            sources.pop().map(|(_, l)| l).unwrap_or_default()
        } else {
            tenzro_types::statement::merge_sources(sources)
        };
        let provider = format!(
            "0x{}",
            tenzro_types::statement::account_hex(&serde_json::json!(self.provider))
        );
        let statement = build(&provider, from_ms, to_ms, period, complete, lines);

        match (self.format.as_str(), self.lines) {
            ("csv", true) => print!("{}", lines_csv(&statement)),
            ("csv", false) => print!("{}", summary_csv(&statement)),
            _ => println!("{}", serde_json::to_string_pretty(&statement)?),
        }

        if self.verify {
            let chain = crate::rpc::RpcClient::new(self.verify_rpc.as_deref().unwrap_or(&self.rpc));
            let mut facts = std::collections::BTreeMap::new();
            for line in statement.lines.iter().filter(|l| l.settled()) {
                if let Some(f) = chain_facts(&chain, line).await?
                    && let Some(r) = &line.pay_ref
                {
                    facts.insert(r.clone(), f);
                }
            }
            let differences = verify(&statement, &facts);
            if !differences.is_empty() {
                for d in &differences {
                    eprintln!("{d}");
                }
                anyhow::bail!(
                    "the statement differs from the chain in {} place(s)",
                    differences.len()
                );
            }
            eprintln!(
                "Verified: {} settled line(s) match their payment records and receipts on chain, \
                 and every summary and total is recomputed from them.",
                facts.len()
            );
        }
        Ok(())
    }
}

/// Compute bond (admission collateral) subcommands.
///
/// Providers post a compute bond before they serve. The bond is held in a
/// deterministic vault derived from the provider DID and is returnable after
/// a cooldown; run
/// `tenzro provider bond params` for the node's minimum and cooldown length.
///
/// `post` / `increase` / `withdraw` / `finalize` submit native transactions —
/// the vault transfer and the on-chain marker land in the same block. `get` /
/// `list` / `params` read the off-chain model the admission check consults.
#[derive(Debug, Subcommand)]
pub enum BondCommand {
    /// Post a new compute bond
    Post(BondPostCmd),
    /// Top up an existing bond
    Increase(BondIncreaseCmd),
    /// Get a single provider's bond state
    Get(BondGetCmd),
    /// List every compute bond on chain
    List(BondListCmd),
    /// Initiate withdrawal, starting the cooldown
    Withdraw(BondWithdrawCmd),
    /// Release the vault back to the provider once the cooldown has elapsed
    Finalize(BondFinalizeCmd),
    /// Show the admission dials: minimum bond and cooldown length
    Params(BondParamsCmd),
}

impl BondCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Post(cmd) => cmd.execute().await,
            Self::Increase(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Withdraw(cmd) => cmd.execute().await,
            Self::Finalize(cmd) => cmd.execute().await,
            Self::Params(cmd) => cmd.execute().await,
        }
    }
}

use tenzro_types::constants::bond_gas::{
    COMPUTE_BOND_FINALIZE as BOND_FINALIZE_GAS, COMPUTE_BOND_INCREASE as BOND_INCREASE_GAS,
    COMPUTE_BOND_POST as BOND_POST_GAS, COMPUTE_BOND_WITHDRAW as BOND_WITHDRAW_GAS,
};

fn extract_tx_hash(result: &serde_json::Value) -> String {
    result
        .get("tx_hash")
        .or_else(|| result.get("transaction_hash"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| result.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "<unknown>".to_string())
}

/// Sign a compute-bond transaction in hardware as the client account under
/// `key_namespace` and submit it pre-signed.
///
/// The bond RPCs are read-only; every mutation goes through consensus so the
/// vault transfer and the on-chain marker land in the same block.
async fn submit_bond_tx(
    rpc: &crate::rpc::RpcClient,
    key_namespace: &str,
    gas_limit: u64,
    tx_type: serde_json::Value,
) -> Result<String> {
    let result: serde_json::Value =
        crate::keystore::send_as_client(rpc, key_namespace, [0u8; 32], tx_type, gas_limit).await?;
    Ok(extract_tx_hash(&result))
}

fn print_compute_bond_state(state: &serde_json::Value) {
    if let Some(v) = state.get("provider_did").and_then(|v| v.as_str()) {
        output::print_field("Provider DID", v);
    }
    if let Some(v) = state.get("provider_address").and_then(|v| v.as_str()) {
        output::print_field("Provider Address", &output::format_address(v));
    }
    if let Some(v) = state.get("amount").and_then(|v| v.as_str()) {
        output::print_field("Amount (wei)", v);
    }
    if let Some(v) = state.get("status").and_then(|v| v.as_str()) {
        let active = v == "Active";
        output::print_status("Status", v, active);
    }
    if let Some(v) = state.get("cooldown_until").and_then(|v| v.as_u64()) {
        output::print_field("Cooldown Until (ms)", &v.to_string());
    }
    if let Some(v) = state.get("vault").and_then(|v| v.as_str()) {
        output::print_field("Vault", v);
    }
    if let Some(v) = state.get("effective_amount").and_then(|v| v.as_str()) {
        output::print_field("Effective for Registration", v);
    }
    if let Some(v) = state.get("is_eligible").and_then(|v| v.as_bool()) {
        output::print_field("Registration-Eligible", &v.to_string());
    }
}

#[derive(Debug, Parser)]
pub struct BondPostCmd {
    /// Provider DID (e.g. did:tenzro:machine:...)
    #[arg(long)]
    did: String,

    /// Provider wallet address (32-byte hex; with or without 0x)
    #[arg(long)]
    address: String,

    /// Bond amount in TNZO (decimal, e.g. "100" for 100 TNZO)
    #[arg(long)]
    amount: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BondPostCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Post Compute Bond");
        let amount_wei = crate::units::tnzo_to_wei_string(&self.amount)?;
        output::print_field("Provider DID", &self.did);
        output::print_field("Provider Address", &output::format_address(&self.address));
        output::print_field(
            "Amount",
            &format!("{} TNZO ({} wei)", self.amount, amount_wei),
        );
        println!();

        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Posting compute bond...");
        let tx_hash = submit_bond_tx(
            &rpc,
            "client",
            BOND_POST_GAS,
            serde_json::json!({
                "PostComputeBond": {
                    "provider_did": self.did,
                    "amount": amount_wei,
                }
            }),
        )
        .await?;
        spinner.finish_and_clear();
        output::print_success("PostComputeBond transaction submitted");
        println!();
        output::print_field("Transaction Hash", &tx_hash);
        output::print_info(
            "Run `tenzro provider bond get` once the block finalizes to see the bond state.",
        );
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct BondIncreaseCmd {
    /// Provider DID
    #[arg(long)]
    did: String,

    /// Provider wallet address (32-byte hex; must match the bond's payout address)
    #[arg(long)]
    address: String,

    /// Additional amount in TNZO
    #[arg(long)]
    amount: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BondIncreaseCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Increase Compute Bond");
        let amount_wei = crate::units::tnzo_to_wei_string(&self.amount)?;
        output::print_field("Provider DID", &self.did);
        output::print_field(
            "Top-up",
            &format!("{} TNZO ({} wei)", self.amount, amount_wei),
        );
        println!();

        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Increasing compute bond...");
        let tx_hash = submit_bond_tx(
            &rpc,
            "client",
            BOND_INCREASE_GAS,
            serde_json::json!({
                "IncreaseComputeBond": {
                    "provider_did": self.did,
                    "amount": amount_wei,
                }
            }),
        )
        .await?;
        spinner.finish_and_clear();
        output::print_success("IncreaseComputeBond transaction submitted");
        println!();
        output::print_field("Transaction Hash", &tx_hash);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct BondGetCmd {
    /// Provider DID
    #[arg(long)]
    did: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BondGetCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Compute Bond");
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Fetching compute bond...");
        let state: serde_json::Value = rpc
            .call(
                "tenzro_getComputeBond",
                serde_json::json!([{ "provider_did": self.did }]),
            )
            .await?;
        spinner.finish_and_clear();
        if state.is_null() {
            output::print_warning(&format!("No compute bond found for {}", self.did));
            return Ok(());
        }
        print_compute_bond_state(&state);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct BondListCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BondListCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Compute Bonds");
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Listing compute bonds...");
        let result: serde_json::Value = rpc
            .call("tenzro_listComputeBonds", serde_json::json!([]))
            .await?;
        spinner.finish_and_clear();
        let bonds = result
            .get("bonds")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if bonds.is_empty() {
            output::print_info("No compute bonds posted yet");
            return Ok(());
        }
        let headers = vec![
            "Provider DID",
            "Address",
            "Amount (wei)",
            "Status",
            "Eligible",
        ];
        let mut rows = Vec::new();
        for b in &bonds {
            rows.push(vec![
                b.get("provider_did")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                output::format_address(
                    b.get("provider_address")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                ),
                b.get("amount")
                    .and_then(|v| v.as_str())
                    .unwrap_or("0")
                    .to_string(),
                b.get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string(),
                b.get("is_eligible")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                    .to_string(),
            ]);
        }
        output::print_table(&headers, &rows);
        println!();
        output::print_field("Total", &bonds.len().to_string());
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct BondWithdrawCmd {
    /// Provider DID
    #[arg(long)]
    did: String,

    /// Provider wallet address (32-byte hex; must match the bond's payout address)
    #[arg(long)]
    address: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BondWithdrawCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Withdraw Compute Bond");
        output::print_info(
            "Active → Cooldown starts the unbonding window. The vault stays funded — and stays slashable — until the cooldown elapses.",
        );
        println!();

        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Submitting withdrawal...");
        let tx_hash = submit_bond_tx(
            &rpc,
            "client",
            BOND_WITHDRAW_GAS,
            serde_json::json!({
                "WithdrawComputeBond": { "provider_did": self.did }
            }),
        )
        .await?;
        spinner.finish_and_clear();
        output::print_success("WithdrawComputeBond transaction submitted");
        println!();
        output::print_field("Transaction Hash", &tx_hash);
        output::print_info(
            "Run `tenzro provider bond finalize` once the cooldown deadline passes to reclaim the vault.",
        );
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct BondParamsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BondParamsCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Compute Bond Parameters");
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Fetching bond parameters...");
        let params: serde_json::Value = rpc
            .call("tenzro_computeBondParams", serde_json::json!([]))
            .await?;
        spinner.finish_and_clear();
        if let Some(v) = params.get("min_bond_wei").and_then(|v| v.as_str()) {
            output::print_field("Minimum Bond (wei)", v);
        }
        if let Some(v) = params.get("cooldown_ms").and_then(|v| v.as_u64()) {
            output::print_field(
                "Cooldown",
                &format!("{} ms ({:.1} days)", v, v as f64 / 86_400_000.0),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct BondFinalizeCmd {
    /// Provider DID
    #[arg(long)]
    did: String,

    /// Provider wallet address (32-byte hex; must match the bond's payout address)
    #[arg(long)]
    address: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BondFinalizeCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Finalize Compute Bond Withdrawal");
        output::print_info(
            "Releases the vault balance back to the provider wallet. The cooldown deadline is checked against the block timestamp.",
        );
        println!();

        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Submitting finalization...");
        let tx_hash = submit_bond_tx(
            &rpc,
            "client",
            BOND_FINALIZE_GAS,
            serde_json::json!({
                "FinalizeComputeBondWithdrawal": { "provider_did": self.did }
            }),
        )
        .await?;
        spinner.finish_and_clear();
        output::print_success("FinalizeComputeBondWithdrawal transaction submitted");
        println!();
        output::print_field("Transaction Hash", &tx_hash);
        Ok(())
    }
}

/// Provider pricing management
#[derive(Debug, Subcommand)]
pub enum PricingCommand {
    /// Set one of this node's price cards
    Set(PricingSetCmd),
    /// Show this node's price cards
    Show(PricingShowCmd),
    /// Publish this node's card for a model as a registry entry, signed by the operator account
    Post(PricingPostCmd),
    /// Show the card a provider publishes for a model (read-only)
    Card(PricingCardCmd),
}

impl PricingCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Set(cmd) => cmd.execute().await,
            Self::Show(cmd) => cmd.execute().await,
            Self::Post(cmd) => cmd.execute().await,
            Self::Card(cmd) => cmd.execute().await,
        }
    }
}

/// Show the card a provider publishes for a model, with its registry entry.
#[derive(Debug, Parser)]
pub struct PricingCardCmd {
    /// The provider's account (hex)
    #[arg(long)]
    pub provider: String,

    /// Catalog id of the model or service
    #[arg(long)]
    pub model: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

impl PricingCardCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let card: serde_json::Value = rpc
            .call(
                "tenzro_getPriceCard",
                serde_json::json!({ "provider": self.provider, "model_id": self.model }),
            )
            .await?;
        if card.is_null() {
            output::print_warning("This provider publishes no card for that model.");
            return Ok(());
        }
        output::print_json(&card)
    }
}

/// Publish this node's card for a model as a registry entry.
///
/// The entry is put by the operator's account (the client account under
/// `--key-namespace`), which owns it and locks the registry bond on its
/// first put. The node supplies the card body, with the model's weights
/// hash.
#[derive(Debug, Parser)]
pub struct PricingPostCmd {
    /// Catalog id of the model
    #[arg(long)]
    pub model: String,

    /// The operator account's hardware key namespace
    #[arg(long, default_value = "client")]
    pub key_namespace: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

impl PricingPostCmd {
    pub async fn execute(&self) -> Result<()> {
        let id = post_card(&self.rpc, &self.model, &self.key_namespace).await?;
        output::print_success("Price card published");
        output::print_field("Registry id", &id);
        Ok(())
    }
}

/// Have the node build its card for `model` as a registry entry under the
/// operator account, and put it in a `Registry` transaction signed by that
/// account. Returns the entry's id; the id and transaction are printed as a
/// `Posted` field.
async fn post_card(rpc_url: &str, model: &str, key_namespace: &str) -> Result<String> {
    let rpc = crate::rpc::RpcClient::new(rpc_url);
    let (account, _) = crate::keystore::client_account(key_namespace)?;
    let built: serde_json::Value = rpc
        .call(
            "tenzro_priceCardToPublish",
            serde_json::json!({ "model_id": model, "provider": account }),
        )
        .await?;
    let entry = &built["entry"];
    if entry.is_null() {
        anyhow::bail!("the published card already says the same; nothing to post");
    }
    let id = entry["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("the node returned no entry id"))?
        .to_string();
    let tx_type = serde_json::json!({ "Registry": { "op": { "put": {
        "id": id,
        "kind": entry["kind"],
        "anchor": "0".repeat(64),
        "data": entry["data"],
    } } } });
    let to: [u8; 32] = hex::decode(account.trim_start_matches("0x"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("the operator account is 32 bytes"))?;
    let tx = crate::keystore::send_as_client(&rpc, key_namespace, to, tx_type, 300_000).await?;
    output::print_field(
        "Posted",
        &serde_json::json!({ "id": id, "tx": tx }).to_string(),
    );
    Ok(id)
}

/// Show provider status
#[derive(Debug, Parser)]
pub struct ProviderStatusCmd {
    /// Provider address (optional, uses default wallet if not specified)
    #[arg(long)]
    address: Option<String>,

    /// Show detailed statistics
    #[arg(long)]
    detailed: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProviderStatusCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Provider Status");

        let spinner = output::create_spinner("Fetching provider information...");

        let rpc = RpcClient::new(&self.rpc);

        // Fetch node info which includes provider status
        let node_info: serde_json::Value = rpc
            .call("tenzro_getNodeStatus", serde_json::json!([]))
            .await?;

        spinner.finish_and_clear();

        if let Some(addr) = &self.address {
            output::print_field("Address", &output::format_address(addr));
        }

        println!();

        if let Some(provider_id) = node_info.get("provider_id").and_then(|v| v.as_str()) {
            output::print_field("Provider ID", provider_id);
        }
        if let Some(role) = node_info.get("role").and_then(|v| v.as_str()) {
            output::print_field("Type", role);
        }
        if let Some(status) = node_info.get("status").and_then(|v| v.as_str()) {
            let is_active = status.contains("Active") || status.contains("Running");
            output::print_status("Status", status, is_active);
        } else {
            output::print_status("Status", "Active - accepting requests", true);
        }

        println!();

        if self.detailed {
            // Fetch detailed provider stats from node
            let stats: serde_json::Value = rpc
                .call(
                    "tenzro_getProviderStats",
                    serde_json::json!([{
                        "address": self.address.as_deref()
                    }]),
                )
                .await
                .unwrap_or(serde_json::json!({}));

            println!();
            output::print_header("Performance Statistics");
            println!();
            if let Some(v) = stats.get("total_requests").and_then(|v| v.as_u64()) {
                output::print_field("Total Requests", &format!("{}", v));
            }
            if let Some(v) = stats.get("successful").and_then(|v| v.as_u64()) {
                let total = stats
                    .get("total_requests")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1);
                let pct = if total > 0 {
                    (v as f64 / total as f64) * 100.0
                } else {
                    0.0
                };
                output::print_field("Successful", &format!("{} ({:.1}%)", v, pct));
            }
            if let Some(v) = stats.get("avg_latency").and_then(|v| v.as_str()) {
                output::print_field("Avg Latency", v);
            }
            if let Some(v) = stats.get("total_earnings").and_then(|v| v.as_str()) {
                output::print_field("Total Earnings", v);
            }
            if let Some(v) = stats.get("total_rewards").and_then(|v| v.as_str()) {
                output::print_field("Total Rewards", v);
            }

            println!();
            output::print_header("Capacity");
            println!();
            if let Some(v) = stats.get("max_concurrent").and_then(|v| v.as_u64()) {
                output::print_field("Max Concurrent", &format!("{} requests", v));
            }
            if let Some(v) = stats.get("current_active").and_then(|v| v.as_u64()) {
                output::print_field("Current Active", &format!("{} requests", v));
            }
            if let Some(v) = stats.get("utilization").and_then(|v| v.as_str()) {
                output::print_field("Utilization", v);
            }

            if let Some(activity) = stats.get("recent_activity").and_then(|v| v.as_array())
                && !activity.is_empty()
            {
                println!();
                output::print_header("Recent Activity");
                let headers = vec!["Time", "Request ID", "Model", "Status", "Earned"];
                let mut rows = Vec::new();
                for item in activity {
                    rows.push(vec![
                        item.get("time")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        item.get("request_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        item.get("model")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        item.get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        item.get("earned")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
            }
        }

        Ok(())
    }
}

/// List models being served
#[derive(Debug, Parser)]
pub struct ProviderModelsCmd {
    /// Provider address (optional, uses default wallet if not specified)
    #[arg(long)]
    address: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProviderModelsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Served Models");

        let spinner = output::create_spinner("Fetching served models...");

        let rpc = RpcClient::new(&self.rpc);

        // `tenzro_listModels` takes an object, not a single-element array.
        // Passing the array meant the filter never bound, the node answered
        // with its whole CATALOGUE, and this command printed every model
        // Tenzro knows about as "served" — hundreds of rows, all of them
        // `unknown`, because the response has no `status`/`model_id`/`earned`
        // fields to read either. Ask the node what it serves, and read the
        // shape it actually returns.
        let models: Vec<serde_json::Value> = rpc
            .call(
                "tenzro_listModels",
                serde_json::json!({ "serving_only": true }),
            )
            .await?;

        spinner.finish_and_clear();

        if let Some(addr) = &self.address {
            output::print_field("Provider", &output::format_address(addr));
            println!();
        }

        // Serving here, not merely catalogued or resident: `availability`
        // is "local" only for a model this node offers.
        let served: Vec<&serde_json::Value> = models
            .iter()
            .filter(|m| {
                m.get("availability").and_then(|v| v.as_str()) == Some("local")
                    || m.get("served_here").and_then(|v| v.as_bool()) == Some(true)
            })
            .collect();

        if served.is_empty() {
            output::print_info(
                "This node is not serving any model. `tenzro model serve <id>` offers one.",
            );
            return Ok(());
        }

        let headers = vec![
            "Model ID",
            "Name",
            "Weights",
            "Context",
            "In flight",
            "Quant",
        ];
        let mut rows = Vec::new();

        for model in &served {
            let load = model.get("load");
            rows.push(vec![
                model
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string(),
                model
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string(),
                // Offered and warm, or offered and paged out until first use.
                if model
                    .get("loaded")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    "resident".to_string()
                } else {
                    "cold".to_string()
                },
                model
                    .get("context_length")
                    .and_then(|v| v.as_u64())
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                load.and_then(|l| l.get("active_requests"))
                    .and_then(|v| v.as_u64())
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                model
                    .get("quantization")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-")
                    .to_string(),
            ]);
        }
        output::print_table(&headers, &rows);

        println!();
        output::print_field("Models served", &served.len().to_string());

        Ok(())
    }
}

/// Set one of this node's price cards.
///
/// A card prices registered units, or units at a tier, as `unit=price` or
/// `unit@tier=price`, each price per `10^per_exp` units given as
/// `unit=price/exp`. Prices are in billionths of a dollar (`--denom nano_usd`,
/// settled in TNZO at the chain's rate) or TNZO base units (`--denom wei`).
/// Without `--model` the card applies to every model without its own.
///
///   tenzro provider pricing set --denom nano_usd \
///     --line input_tokens=200000000/6 --line output_tokens=1000000000/6
#[derive(Debug, Parser)]
pub struct PricingSetCmd {
    /// Catalog id of the model the card is for
    #[arg(long)]
    pub model: Option<String>,

    /// What the prices are in: nano_usd or wei
    #[arg(long, default_value = "nano_usd")]
    pub denom: String,

    /// A priced line, `unit[@tier]=price[/per_exp]`; repeat for each
    #[arg(long = "line", required = true)]
    pub lines: Vec<String>,

    /// Least one call is charged, in the card's denomination
    #[arg(long, default_value = "0")]
    pub min_charge: String,

    /// Post the card on chain after setting it, signed by the operator
    /// account under `--key-namespace`, so receipts and disputes can name it
    #[arg(long)]
    pub post: bool,

    /// The operator account's hardware key namespace, for `--post`
    #[arg(long, default_value = "client")]
    pub key_namespace: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

/// Parse `unit[@tier]=price[/per_exp]`.
fn parse_line(line: &str) -> Result<(String, serde_json::Value)> {
    let (key, rest) = line
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("'{line}' is not unit=price"))?;
    let (price, per_exp) = match rest.split_once('/') {
        Some((p, e)) => (
            p,
            e.parse::<u8>()
                .map_err(|_| anyhow::anyhow!("'{e}' is not a power of ten"))?,
        ),
        None => (rest, 0),
    };
    let price: u128 = price
        .parse()
        .map_err(|_| anyhow::anyhow!("'{price}' is not a non-negative integer price"))?;
    Ok((
        key.to_string(),
        serde_json::json!({ "price": price.to_string(), "per_exp": per_exp }),
    ))
}

impl PricingSetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        if self.denom != "nano_usd" && self.denom != "wei" {
            anyhow::bail!("--denom is nano_usd or wei");
        }
        let mut lines = serde_json::Map::new();
        for l in &self.lines {
            let (k, v) = parse_line(l)?;
            lines.insert(k, v);
        }
        let card = serde_json::json!({
            "denom": self.denom,
            "lines": lines,
            "min_charge": self.min_charge,
        });

        output::print_header("Set Price Card");
        println!();
        output::print_field("Model", self.model.as_deref().unwrap_or("(default card)"));
        output::print_field("Denomination", &self.denom);
        for l in &self.lines {
            output::print_field("Line", l);
        }
        println!();

        let spinner = output::create_spinner("Updating pricing...");
        let rpc = RpcClient::new(&self.rpc);
        // The setter replaces every card, so read them and replace only this one.
        let mut cards: serde_json::Value = rpc
            .call("tenzro_getProviderPricing", serde_json::json!([]))
            .await?;
        match &self.model {
            Some(m) => cards["models"][m] = card,
            None => cards["default"] = card,
        }
        let _: serde_json::Value = rpc.call("tenzro_setProviderPricing", cards).await?;
        spinner.finish_and_clear();
        if self.post {
            let model = self.model.as_deref().ok_or_else(|| {
                anyhow::anyhow!("--post needs --model: a card is anchored per model")
            })?;
            post_card(&self.rpc, model, &self.key_namespace).await?;
        }
        output::print_success("Price card updated");
        Ok(())
    }
}

/// Show this node's price cards
#[derive(Debug, Parser)]
pub struct PricingShowCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

impl PricingShowCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Provider Price Cards");
        let spinner = output::create_spinner("Fetching pricing...");
        let rpc = RpcClient::new(&self.rpc);
        let cards: serde_json::Value = rpc
            .call("tenzro_getProviderPricing", serde_json::json!([]))
            .await?;
        spinner.finish_and_clear();

        let show = |name: &str, card: &serde_json::Value| {
            println!();
            output::print_field("Card", name);
            output::print_field("Denomination", card["denom"].as_str().unwrap_or("nano_usd"));
            if let Some(lines) = card["lines"].as_object() {
                for (k, r) in lines {
                    let per = r["per_exp"].as_u64().unwrap_or(0);
                    let price = r["price"]
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| r["price"].to_string());
                    output::print_field(k, &format!("{price} per 10^{per}"));
                }
            }
            output::print_field("Minimum charge", &card["min_charge"].to_string());
        };
        show("default", &cards["default"]);
        if let Some(models) = cards["models"].as_object() {
            for (m, c) in models {
                show(m, c);
            }
        }
        Ok(())
    }
}

/// List all providers discovered on the Tenzro Network
#[derive(Debug, Parser)]
pub struct ProviderListCmd {
    /// Filter by provider type (ai, tee, storage, compute, general)
    #[arg(long, name = "type")]
    provider_type: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProviderListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Network Providers");

        let spinner = output::create_spinner("Discovering network providers...");

        let rpc = RpcClient::new(&self.rpc);

        // Every page, following the cursor the node returns.
        let mut providers: Vec<serde_json::Value> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page: serde_json::Value = rpc
                .call(
                    "tenzro_listProviders",
                    serde_json::json!({
                        "provider_type": self.provider_type,
                        "limit": 200,
                        "cursor": cursor,
                    }),
                )
                .await?;
            if let Some(entries) = page.get("providers").and_then(|p| p.as_array()) {
                providers.extend(entries.iter().cloned());
            }
            cursor = page
                .get("next_cursor")
                .and_then(|c| c.as_str())
                .map(str::to_string);
            if cursor.is_none() {
                break;
            }
        }

        spinner.finish_and_clear();

        if let Some(ref pt) = self.provider_type {
            output::print_field("Filter", &format!("type = {}", pt));
            println!();
        }

        if providers.is_empty() {
            output::print_info("No providers discovered on the network yet.");
            output::print_info("Providers broadcast announcements every 60s via gossip.");
            return Ok(());
        }

        let headers = vec![
            "Endpoint ID",
            "Address",
            "Type",
            "Region",
            "Models",
            "Load",
            "Capabilities",
            "Status",
        ];
        let mut rows = Vec::new();

        for p in &providers {
            let peer_id = p
                .get("endpoint_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let peer_id_short = if peer_id.len() > 16 {
                format!("{}...{}", &peer_id[..8], &peer_id[peer_id.len() - 6..])
            } else {
                peer_id.to_string()
            };

            let address = p
                .get("provider_address")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let addr_short = output::format_address(address);

            let provider_type = p
                .get("provider_type")
                .and_then(|v| v.as_str())
                .unwrap_or("general");

            let models = p
                .get("served_models")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|m| m.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();

            let capabilities = p
                .get("capabilities")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|m| m.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();

            let status = p
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let is_local = p.get("is_local").and_then(|v| v.as_bool()).unwrap_or(false);
            let status_display = if is_local {
                format!("{} (local)", status)
            } else {
                status.to_string()
            };

            let region = p
                .get("region")
                .and_then(|v| v.as_str())
                .unwrap_or("-")
                .to_string();
            // In flight over admission ceiling, summed across its models.
            let load = p
                .get("model_load")
                .and_then(|v| v.as_array())
                .map(|loads| {
                    let sum =
                        |k: &str| loads.iter().filter_map(|l| l.get(k)?.as_u64()).sum::<u64>();
                    format!("{}/{}", sum("in_flight"), sum("max_concurrent"))
                })
                .unwrap_or_else(|| "-".to_string());

            rows.push(vec![
                peer_id_short,
                addr_short,
                provider_type.to_string(),
                region,
                models,
                load,
                capabilities,
                status_display,
            ]);
        }

        output::print_table(&headers, &rows);

        println!();
        output::print_field("Total Providers", &providers.len().to_string());
        let local_count = providers
            .iter()
            .filter(|p| p.get("is_local").and_then(|v| v.as_bool()).unwrap_or(false))
            .count();
        if local_count > 0 {
            output::print_field("Local Node", "included");
        }

        Ok(())
    }
}

/// Price one request at every provider serving a model.
#[derive(Debug, Parser)]
pub struct ProviderQuoteCmd {
    /// Model id
    #[arg(long)]
    model: String,
    /// Prompt tokens
    #[arg(long, default_value_t = 0)]
    input_tokens: u32,
    /// Completion tokens
    #[arg(long, default_value_t = 0)]
    output_tokens: u32,
    /// Verification level: none, receipt, optimistic or tee
    #[arg(long, default_value = "none")]
    verification: String,
    /// Only this provider (address)
    #[arg(long)]
    provider: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProviderQuoteCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let quote: serde_json::Value = rpc
            .call(
                "tenzro_quoteInference",
                serde_json::json!({
                    "model": self.model,
                    "units": { "input_tokens": self.input_tokens, "output_tokens": self.output_tokens },
                    "verification": self.verification,
                    "provider": self.provider,
                }),
            )
            .await?;
        output::print_json(&quote)
    }
}

/// Provider commands that call one node RPC each and print its answer
#[derive(Debug, clap::Subcommand)]
pub enum ProviderRpcCommand {
    /// Call tenzro_slaGetParams (sla get params) and print the node's answer
    SlaParams(ProviderSlaParamsRpcCmd),
    /// Call tenzro_slaIssueProbe (sla issue probe) and print the node's answer
    SlaProbe(ProviderSlaProbeRpcCmd),
    /// Call tenzro_slaListOutstandingProbes (sla list outstanding probes) and print the node's answer
    SlaProbes(ProviderSlaProbesRpcCmd),
    /// Call tenzro_computeGetClaim (compute get claim) and print the node's answer
    ComputeClaim(ProviderComputeClaimRpcCmd),
    /// Call tenzro_computeListClaims (compute list claims) and print the node's answer
    ComputeClaims(ProviderComputeClaimsRpcCmd),
    /// Call tenzro_computePriceFeed (compute price feed) and print the node's answer
    ComputePriceFeed(ProviderComputePriceFeedRpcCmd),
    /// Call tenzro_slaVerdict (sla verdict) and print the node's answer
    SlaVerdict(ProviderSlaVerdictRpcCmd),
}

impl ProviderRpcCommand {
    pub async fn execute(&self) -> anyhow::Result<()> {
        match self {
            Self::SlaParams(cmd) => cmd.execute().await,
            Self::SlaProbe(cmd) => cmd.execute().await,
            Self::SlaProbes(cmd) => cmd.execute().await,
            Self::ComputeClaim(cmd) => cmd.execute().await,
            Self::ComputeClaims(cmd) => cmd.execute().await,
            Self::ComputePriceFeed(cmd) => cmd.execute().await,
            Self::SlaVerdict(cmd) => cmd.execute().await,
        }
    }
}

/// Call tenzro_slaGetParams (sla get params)
#[derive(Debug, clap::Parser)]
pub struct ProviderSlaParamsRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProviderSlaParamsRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_slaGetParams", serde_json::json!([]))
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_slaIssueProbe (sla issue probe)
#[derive(Debug, clap::Parser)]
pub struct ProviderSlaProbeRpcCmd {
    /// provider did
    #[arg(long)]
    provider_did: String,
    /// epoch
    #[arg(long)]
    epoch: u64,
    /// round
    #[arg(long)]
    round: u64,
    /// deadline ms
    #[arg(long)]
    deadline_ms: u64,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProviderSlaProbeRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_slaIssueProbe", serde_json::json!([{ "provider_did": self.provider_did, "epoch": self.epoch, "round": self.round, "deadline_ms": self.deadline_ms }])).await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_slaListOutstandingProbes (sla list outstanding probes)
#[derive(Debug, clap::Parser)]
pub struct ProviderSlaProbesRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProviderSlaProbesRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_slaListOutstandingProbes", serde_json::json!([]))
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_computeGetClaim (compute get claim)
#[derive(Debug, clap::Parser)]
pub struct ProviderComputeClaimRpcCmd {
    /// claim id
    #[arg(long)]
    claim_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProviderComputeClaimRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_computeGetClaim",
                serde_json::json!({ "claim_id": self.claim_id }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_computeListClaims (compute list claims)
#[derive(Debug, clap::Parser)]
pub struct ProviderComputeClaimsRpcCmd {
    /// party
    #[arg(long)]
    party: Option<String>,
    /// limit
    #[arg(long)]
    limit: Option<u64>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProviderComputeClaimsRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_computeListClaims",
                serde_json::json!({ "party": self.party, "limit": self.limit }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_computePriceFeed (compute price feed)
#[derive(Debug, clap::Parser)]
pub struct ProviderComputePriceFeedRpcCmd {
    /// model id
    #[arg(long)]
    model_id: Option<String>,
    /// region
    #[arg(long)]
    region: Option<String>,
    /// attested only
    #[arg(long)]
    attested_only: Option<bool>,
    /// limit
    #[arg(long)]
    limit: Option<u64>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProviderComputePriceFeedRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_computePriceFeed", serde_json::json!({ "model_id": self.model_id, "region": self.region, "attested_only": self.attested_only, "limit": self.limit })).await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_slaVerdict (sla verdict)
#[derive(Debug, clap::Parser)]
pub struct ProviderSlaVerdictRpcCmd {
    /// provider did
    #[arg(long)]
    provider_did: String,
    /// epoch
    #[arg(long)]
    epoch: u64,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProviderSlaVerdictRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_slaVerdict",
                serde_json::json!({ "provider_did": self.provider_did, "epoch": self.epoch }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}
