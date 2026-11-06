//! Wallet management commands for the Tenzro CLI

use crate::output::{self};
use anyhow::Result;
use clap::{Parser, Subcommand};

/// Wallet management commands
#[derive(Debug, Subcommand)]
pub enum WalletCommand {
    #[command(flatten)]
    Rpc(WalletRpcCommand),
    /// Check wallet balance
    Balance(WalletBalanceCmd),
    /// Send tokens or stablecoins
    Send(WalletSendCmd),
    /// Get transaction history for an address
    History(WalletHistoryCmd),
    /// Get token balance for a specific ERC-20 token
    TokenBalance(WalletTokenBalanceCmd),
    /// Show the self-custody client account this machine's hardware keys (node never signs for it)
    CreateLocal(WalletCreateLocalCmd),
    /// Opt-in outflow limits on an account: a cap per window, a hold and a guardian
    #[command(subcommand)]
    Outflow(crate::commands::wallet_outflow::OutflowCommand),
}

impl WalletCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Rpc(cmd) => cmd.execute().await,
            Self::Balance(cmd) => cmd.execute().await,
            Self::Send(cmd) => cmd.execute().await,
            Self::History(cmd) => cmd.execute().await,
            Self::TokenBalance(cmd) => cmd.execute().await,
            Self::CreateLocal(cmd) => cmd.execute().await,
            Self::Outflow(cmd) => cmd.execute().await,
        }
    }
}

/// Check wallet balance
#[derive(Debug, Parser)]
pub struct WalletBalanceCmd {
    /// Wallet address (optional; defaults to the configured wallet, then this machine's client account)
    #[arg(long)]
    address: Option<String>,

    /// Show detailed asset breakdown
    #[arg(long)]
    detailed: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WalletBalanceCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::{RpcClient, format_tnzo, parse_hex_u128};

        output::print_header("Wallet Balances");

        let spinner = output::create_spinner("Fetching balances...");

        let rpc = RpcClient::new(&self.rpc);

        if let Some(addr) = &self.address {
            // Fetch balance for specific address
            let balance_hex: String = rpc
                .call("eth_getBalance", serde_json::json!([addr, "latest"]))
                .await?;
            let balance_wei = parse_hex_u128(&balance_hex);

            spinner.finish_and_clear();

            println!();
            output::print_field("Address", &output::format_address(addr));
            println!();

            if self.detailed {
                // Detailed view with all assets
                let headers = vec!["Asset", "Symbol", "Balance", "USD Value"];
                let rows = vec![vec![
                    "Tenzro Network Token".to_string(),
                    "TNZO".to_string(),
                    format_tnzo(balance_wei),
                    "N/A".to_string(),
                ]];
                output::print_table(&headers, &rows);
            } else {
                // Simple view
                output::print_field("TNZO Balance", &format_tnzo(balance_wei));
            }
        } else {
            // The configured wallet address first, then this machine's client account
            let cfg = crate::config::load_config();
            if let Some(addr) = cfg.wallet_address {
                let balance_hex: String = rpc
                    .call("eth_getBalance", serde_json::json!([&addr, "latest"]))
                    .await?;
                let balance_wei = parse_hex_u128(&balance_hex);

                spinner.finish_and_clear();
                println!();
                output::print_field("Address", &output::format_address(&addr));
                output::print_field("TNZO Balance", &format_tnzo(balance_wei));
            } else {
                let (addr, _) = crate::keystore::client_account("client")?;
                let balance_hex: String = rpc
                    .call("eth_getBalance", serde_json::json!([&addr, "latest"]))
                    .await?;
                spinner.finish_and_clear();
                println!();
                output::print_field("Address", &output::format_address(&addr));
                output::print_field("TNZO Balance", &format_tnzo(parse_hex_u128(&balance_hex)));
            }
        }

        Ok(())
    }
}

/// Send tokens
#[derive(Debug, Parser)]
pub struct WalletSendCmd {
    /// Recipient address
    to: String,

    /// Amount to send
    amount: String,

    /// Asset to send (TNZO, USDC, USDT)
    #[arg(long, default_value = "TNZO")]
    asset: String,

    /// The signing account's hardware key namespace (a-z, 0-9, '-', '_').
    /// Each namespace is its own account.
    #[arg(long, default_value = "client")]
    key_namespace: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// The full recipient address, repeated, to proceed when the recipient is
    /// new to this account or resembles one it trusts. Without it a terminal
    /// asks for the address to be typed; a script must pass it.
    #[arg(long)]
    confirm_address: Option<String>,

    /// The amount again, in TNZO, to proceed with a transfer at or above the
    /// governed step-up amount (`wallet.step_up_threshold_tnzo`).
    #[arg(long)]
    confirm_amount: Option<String>,
}

/// Evaluate the governed sending ceiling and step-up amount for `amount_wei`
/// against what this account already sent in the window.
pub(crate) async fn transfer_policy_check(
    rpc: &crate::rpc::RpcClient,
    from_hex: &str,
    amount_wei: u128,
    confirm_amount: Option<&str>,
) -> Result<()> {
    use tenzro_types::transfer_policy as tp;
    async fn governed(rpc: &crate::rpc::RpcClient, key: &str) -> Option<u64> {
        let v: serde_json::Value = rpc
            .call("tenzro_getNetworkParams", serde_json::json!({ "key": key }))
            .await
            .ok()?;
        v.get("value")?.as_str()?.parse().ok()
    }
    let policy = tp::TransferPolicy::from_governed(
        governed(rpc, tp::DAILY_CEILING_PARAM).await,
        governed(rpc, tp::STEP_UP_THRESHOLD_PARAM).await,
        governed(rpc, tp::WINDOW_PARAM).await,
    );
    let head: String = rpc.call("eth_blockNumber", serde_json::json!([])).await?;
    let head = u64::from_str_radix(head.trim_start_matches("0x"), 16).unwrap_or(0);
    let window_blocks = policy.window_ms / tenzro_types::constants::BLOCK_TIME_MS;
    let from_floor = head.saturating_sub(window_blocks);
    let history: serde_json::Value = rpc
        .call(
            "tenzro_getTransactionHistory",
            serde_json::json!({ "address": from_hex, "limit": 500 }),
        )
        .await?;
    let me = crate::keystore::address32(from_hex)?;
    let mut sent = 0u128;
    for tx in history
        .get("transactions")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let from = tx
            .get("from")
            .and_then(|v| v.as_str())
            .and_then(|s| crate::keystore::address32(s).ok());
        let height = tx.get("block_height").and_then(|v| v.as_u64()).unwrap_or(0);
        let value = tx
            .get("value")
            .and_then(|v| v.as_str())
            .and_then(|s| match s.strip_prefix("0x") {
                Some(h) => u128::from_str_radix(h, 16).ok(),
                None => s.parse().ok(),
            })
            .unwrap_or(0);
        if from == Some(me) && height >= from_floor {
            sent = sent.saturating_add(value);
        }
    }
    match tp::evaluate_transfer(amount_wei, sent, &policy) {
        tp::TransferDecision::Allow => Ok(()),
        tp::TransferDecision::Refuse { reason } => anyhow::bail!("{reason}; nothing was signed"),
        tp::TransferDecision::StepUp { reason } => {
            output::print_warning(&reason);
            match confirm_amount {
                Some(c) if tp::amount_confirmation_matches(amount_wei, c) => Ok(()),
                _ => anyhow::bail!(
                    "confirm the amount with --confirm-amount; nothing was signed"
                ),
            }
        }
    }
}

/// What this account has paid or been paid, read from the node, and the
/// governed look-alike thresholds, checked against `to`.
pub(crate) async fn recipient_check(
    rpc: &crate::rpc::RpcClient,
    from_hex: &str,
    to: [u8; 32],
) -> Result<tenzro_types::recipient_guard::RecipientAssessment> {
    use tenzro_types::primitives::Address;
    use tenzro_types::recipient_guard as rg;
    async fn governed(rpc: &crate::rpc::RpcClient, key: &str) -> Option<u64> {
        let v: serde_json::Value = rpc
            .call("tenzro_getNetworkParams", serde_json::json!({ "key": key }))
            .await
            .ok()?;
        v.get("value")?.as_str()?.parse().ok()
    }
    let params = rg::LookalikeParams::from_governed(
        governed(rpc, rg::PREFIX_BYTES_PARAM).await,
        governed(rpc, rg::SUFFIX_BYTES_PARAM).await,
    );
    let history: serde_json::Value = rpc
        .call(
            "tenzro_getTransactionHistory",
            serde_json::json!({ "address": from_hex, "limit": 500 }),
        )
        .await?;
    let me = crate::keystore::address32(from_hex)?;
    let (mut trusted, mut senders) = (Vec::new(), Vec::new());
    for tx in history
        .get("transactions")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let field = |k: &str| {
            tx.get(k)
                .and_then(|v| v.as_str())
                .and_then(|s| crate::keystore::address32(s).ok())
        };
        match (field("from"), field("to")) {
            (Some(f), Some(t)) if f == me => trusted.push(Address::new(t)),
            (Some(f), Some(t)) if t == me => senders.push(Address::new(f)),
            _ => {}
        }
    }
    senders.retain(|a| !trusted.contains(a));
    Ok(rg::assess_recipient(
        &Address::new(to),
        &trusted,
        &senders,
        &params,
    ))
}

/// Show the findings and require the full address typed back before a
/// transfer to a recipient that needs it.
pub(crate) fn require_recipient_confirmation(
    assessment: &tenzro_types::recipient_guard::RecipientAssessment,
    confirm: Option<&str>,
) -> Result<()> {
    use std::io::IsTerminal;
    if !assessment.requires_full_address_confirmation() {
        return Ok(());
    }
    for line in assessment.describe() {
        output::print_warning(&line);
    }
    let typed = match confirm {
        Some(c) => c.to_string(),
        None if std::io::stdin().is_terminal() => {
            println!("Type the full recipient address to continue:");
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line
        }
        None => anyhow::bail!(
            "this recipient needs the full address confirmed: pass --confirm-address 0x{}",
            assessment.full_address
        ),
    };
    if !tenzro_types::recipient_guard::confirmation_matches(assessment, &typed) {
        anyhow::bail!("the address typed does not match the recipient; nothing was signed");
    }
    Ok(())
}

impl WalletSendCmd {
    /// A TNZO transfer signed in hardware as the client account and submitted
    /// pre-signed; the node never signs for it.
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Send Transaction");
        if self.asset != "TNZO" {
            anyhow::bail!(
                "wallet send moves TNZO; {} moves through its own contract",
                self.asset
            );
        }
        let amount_float: f64 = self.amount.parse()?;
        let amount_wei = (amount_float * 10f64.powi(18)) as u128;
        let to = crate::keystore::address32(&self.to)?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let (from_hex, _) = crate::keystore::client_account(&self.key_namespace)?;
        let assessment = recipient_check(&rpc, &from_hex, to).await?;
        require_recipient_confirmation(&assessment, self.confirm_address.as_deref())?;
        transfer_policy_check(&rpc, &from_hex, amount_wei, self.confirm_amount.as_deref()).await?;
        let tx_type = serde_json::json!({ "Transfer": { "amount": amount_wei.to_string() } });
        let result =
            crate::keystore::send_as_client(&rpc, &self.key_namespace, to, tx_type, 21_000).await?;
        output::print_success("Transfer signed in hardware and submitted");
        output::print_field(
            "Transaction Hash",
            &result
                .as_str()
                .map_or_else(|| result.to_string(), str::to_string),
        );
        Ok(())
    }
}

/// Get transaction history for an address
#[derive(Debug, Parser)]
pub struct WalletHistoryCmd {
    /// Wallet address (hex)
    address: String,
    /// Maximum transactions to return
    #[arg(long, default_value = "20")]
    limit: u32,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WalletHistoryCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Transaction History");
        let spinner = output::create_spinner("Fetching history...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc
            .call(
                "tenzro_getTransactionHistory",
                serde_json::json!({
                    "address": self.address,
                    "limit": self.limit,
                }),
            )
            .await?;

        spinner.finish_and_clear();

        if let Some(txs) = result.get("transactions").and_then(|v| v.as_array()) {
            if txs.is_empty() {
                output::print_info("No transactions found.");
            } else {
                let headers = vec!["Hash", "From", "To", "Value", "Status"];
                let mut rows = Vec::new();
                for tx in txs {
                    let hash = tx.get("hash").and_then(|v| v.as_str()).unwrap_or("");
                    let hash_short = if hash.len() > 18 {
                        format!("{}...", &hash[..18])
                    } else {
                        hash.to_string()
                    };
                    rows.push(vec![
                        hash_short,
                        tx.get("from")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        tx.get("to")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        tx.get("value")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0")
                            .to_string(),
                        tx.get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
                println!(
                    "Showing {} of {} transactions",
                    txs.len(),
                    result
                        .get("total")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(txs.len() as u64)
                );
            }
        } else {
            output::print_json(&result)?;
        }

        Ok(())
    }
}

/// Get token balance for a specific ERC-20 token
#[derive(Debug, Parser)]
pub struct WalletTokenBalanceCmd {
    /// Wallet address (hex)
    address: String,
    /// Token symbol or contract address
    #[arg(long)]
    token: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WalletTokenBalanceCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Token Balance");
        let spinner = output::create_spinner("Fetching balance...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc
            .call(
                "tenzro_tokenBalance",
                serde_json::json!({
                    "address": self.address,
                    "token": self.token,
                }),
            )
            .await?;

        spinner.finish_and_clear();

        output::print_field("Address", &self.address);
        output::print_field("Token", &self.token);
        output::print_field(
            "Balance",
            result
                .get("balance")
                .and_then(|v| v.as_str())
                .unwrap_or("0"),
        );
        if let Some(decimals) = result.get("decimals").and_then(|v| v.as_u64()) {
            output::print_field("Decimals", &decimals.to_string());
        }

        Ok(())
    }
}

/// Show this machine's self-custody client account, keyed by its hardware
#[derive(Debug, Parser)]
pub struct WalletCreateLocalCmd {
    /// The client identity's hardware key namespace (a-z, 0-9, '-', '_').
    /// Each namespace is its own account.
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// Enroll the account's ML-DSA-65 key on this node now. An account signs
    /// nothing until it has enrolled one, and needs funds for the gas of the
    /// enrolment; without this flag the first transaction it sends enrolls it
    #[arg(long)]
    rpc: Option<String>,
}

impl WalletCreateLocalCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Self-Custody Client Account");

        // The account's keys are derived from the TPM or Secure Enclave, which
        // is also what opening it does: there is no file to write and no
        // password to choose, because nothing is stored.
        let (account, public) = crate::keystore::client_account(&self.key_namespace)?;

        output::print_success("Self-custody account keyed by this machine's hardware");
        println!();
        output::print_field("Key namespace", &self.key_namespace);
        output::print_field("Account", &account);
        output::print_field("P-256 public key", &hex::encode(&public.p256));
        println!();
        output::print_warning(
            "The account's keys are derived inside this machine's hardware for each \
             signature and never stored, so there is nothing to back up and nothing \
             to lose to a stolen disk. They are also bound to this machine: clearing \
             the chip, or replacing the board, retires the account.",
        );
        println!();
        for line in tenzro_types::account_outflow_ui::creation_offer() {
            output::print_info(&line);
        }

        println!();
        match &self.rpc {
            Some(url) => {
                let rpc = crate::rpc::RpcClient::new(url);
                match crate::keystore::enroll_client_pq_key(&rpc, &self.key_namespace).await {
                    Ok(_) => output::print_success("ML-DSA-65 key enrolled for the account"),
                    Err(e) => output::print_warning(&format!(
                        "The ML-DSA-65 key is not enrolled yet ({e}). The account needs funds for the \
                         gas of the enrolment; run `tenzro pq-hybrid enroll` once it has them."
                    )),
                }
            }
            None => output::print_info(
                "The account signs nothing until its ML-DSA-65 key is enrolled: the first \
                 transaction it sends enrolls it, or run `tenzro pq-hybrid enroll`.",
            ),
        }

        Ok(())
    }
}

/// Wallet commands that call one node RPC each and print its answer
#[derive(Debug, clap::Subcommand)]
pub enum WalletRpcCommand {
    /// Call tenzro_getBalance (get balance) and print the node's answer
    NativeBalance(WalletNativeBalanceRpcCmd),
    /// Call tenzro_getNonce (get nonce) and print the node's answer
    Nonce(WalletNonceRpcCmd),
    /// Call tenzro_getSettlementPreference (get settlement preference) and print the node's answer
    SettlementPreference(WalletSettlementPreferenceRpcCmd),
    /// Choose the asset you are paid in, signed by your hardware key (tenzro_setSettlementPreference)
    SetSettlementPreference(WalletSetSettlementPreferenceRpcCmd),
}

impl WalletRpcCommand {
    pub async fn execute(&self) -> anyhow::Result<()> {
        match self {
            Self::NativeBalance(cmd) => cmd.execute().await,
            Self::Nonce(cmd) => cmd.execute().await,
            Self::SettlementPreference(cmd) => cmd.execute().await,
            Self::SetSettlementPreference(cmd) => cmd.execute().await,
        }
    }
}

/// Call tenzro_getBalance (get balance)
#[derive(Debug, clap::Parser)]
pub struct WalletNativeBalanceRpcCmd {
    /// address
    #[arg(long)]
    address: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WalletNativeBalanceRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getBalance", serde_json::json!([self.address]))
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getNonce (get nonce)
#[derive(Debug, clap::Parser)]
pub struct WalletNonceRpcCmd {
    /// address
    #[arg(long)]
    address: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WalletNonceRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getNonce", serde_json::json!([self.address]))
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getSettlementPreference (get settlement preference)
#[derive(Debug, clap::Parser)]
pub struct WalletSettlementPreferenceRpcCmd {
    /// payee did
    #[arg(long)]
    payee_did: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WalletSettlementPreferenceRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getSettlementPreference",
                serde_json::json!({ "payee_did": self.payee_did }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Choose the asset a payee is paid in. The payee's hardware key signs the
/// change; it must be one of the DID's authentication keys.
#[derive(Debug, clap::Parser)]
pub struct WalletSetSettlementPreferenceRpcCmd {
    /// `keep_inbound` or `tnzo`
    #[arg(long)]
    asset: String,
    /// The payee DID (defaults to the configured identity)
    #[arg(long)]
    payee_did: Option<String>,
    /// The hardware key namespace of the signing account
    #[arg(long, default_value = "client")]
    key_namespace: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WalletSetSettlementPreferenceRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let payee_did = self
            .payee_did
            .clone()
            .unwrap_or_else(crate::keystore::active_did);
        let timestamp_ms = chrono::Utc::now().timestamp_millis();
        let preimage = tenzro_types::settlement::settlement_preference_preimage(
            &payee_did,
            &self.asset,
            timestamp_ms,
        );
        let (public_key, signature) = crate::keystore::sign_composite(
            &self.key_namespace,
            tenzro_crypto::composite::SignatureContext::AccountOwner,
            &preimage,
        )?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_setSettlementPreference",
                serde_json::json!({
                    "payee_did": payee_did,
                    "asset": self.asset,
                    "timestamp_ms": timestamp_ms,
                    "public_key": public_key,
                    "signature": signature,
                }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}
