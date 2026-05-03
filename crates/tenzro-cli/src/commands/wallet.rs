//! Wallet management commands for the Tenzro CLI

use clap::{Parser, Subcommand};
use anyhow::Result;
use tenzro_wallet::{WalletProvisioner, ProvisioningConfig};
use crate::output::{self};

/// Wallet management commands
#[derive(Debug, Subcommand)]
pub enum WalletCommand {
    /// Create a new MPC wallet
    Create(WalletCreateCmd),
    /// Import a wallet from seed phrase or private key
    Import(WalletImportCmd),
    /// Check wallet balance
    Balance(WalletBalanceCmd),
    /// Send tokens or stablecoins
    Send(WalletSendCmd),
    /// List all wallets
    List(WalletListCmd),
    /// Create a new account (keypair) on the node
    CreateAccount(WalletCreateAccountCmd),
    /// Request testnet TNZO from faucet
    Faucet(WalletFaucetCmd),
    /// Get transaction history for an address
    History(WalletHistoryCmd),
    /// Get token balance for a specific ERC-20 token
    TokenBalance(WalletTokenBalanceCmd),
}

impl WalletCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Create(cmd) => cmd.execute().await,
            Self::Import(cmd) => cmd.execute().await,
            Self::Balance(cmd) => cmd.execute().await,
            Self::Send(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::CreateAccount(cmd) => cmd.execute().await,
            Self::Faucet(cmd) => cmd.execute().await,
            Self::History(cmd) => cmd.execute().await,
            Self::TokenBalance(cmd) => cmd.execute().await,
        }
    }
}

/// Create a new MPC wallet
#[derive(Debug, Parser)]
pub struct WalletCreateCmd {
    /// Wallet name
    #[arg(long)]
    name: Option<String>,

    /// Threshold (e.g., 2 for 2-of-3)
    #[arg(long, default_value = "2")]
    threshold: usize,

    /// Total shares
    #[arg(long, default_value = "3")]
    total_shares: usize,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WalletCreateCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Creating New MPC Wallet");

        let spinner = output::create_spinner("Generating MPC wallet...");

        // Create provisioning config
        let config = ProvisioningConfig::new(self.threshold, self.total_shares)?;
        let provisioner = WalletProvisioner::with_config(config)?;

        // Provision wallet
        let wallet = provisioner.provision_wallet()?;

        // Register wallet with node
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_createWallet", serde_json::json!([{
            "address": wallet.address.to_string(),
            "threshold": wallet.threshold,
            "total_shares": wallet.total_shares,
            "key_type": format!("{:?}", wallet.key_type)
        }])).await?;

        spinner.finish_and_clear();

        output::print_success("Wallet created successfully!");
        println!();
        output::print_field("Wallet ID", &wallet.wallet_id.to_string());
        output::print_field("Address", &wallet.address.to_string());
        output::print_field("Threshold", &format!("{}-of-{}", wallet.threshold, wallet.total_shares));
        output::print_field("Key Type", &format!("{:?}", wallet.key_type));

        if let Some(name) = &self.name {
            output::print_field("Name", name);
        }

        if let Some(tx_hash) = result.get("transaction_hash").and_then(|v| v.as_str()) {
            output::print_field("Transaction Hash", tx_hash);
        }

        println!();
        output::print_warning("IMPORTANT: Your wallet key shares are encrypted and stored locally.");
        output::print_warning("Make sure to backup your wallet configuration file.");

        Ok(())
    }
}

/// Import a wallet from a private key via the node's tenzro_importIdentity RPC
#[derive(Debug, Parser)]
pub struct WalletImportCmd {
    /// Private key (hex-encoded, with or without 0x prefix)
    source: String,

    /// Key type: ed25519 or secp256k1
    #[arg(long, default_value = "ed25519")]
    key_type: String,

    /// Display name for the identity
    #[arg(long)]
    name: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WalletImportCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        use crate::config;

        output::print_header("Import Wallet from Private Key");

        // Prompt for wallet password
        let password = dialoguer::Password::new()
            .with_prompt("Wallet password (for key encryption)")
            .with_confirmation("Confirm password", "Passwords do not match")
            .interact()?;

        let display_name = self.name.clone().unwrap_or_else(|| "CLI User".to_string());

        let spinner = output::create_spinner("Importing identity and wallet on-chain...");

        // Normalize the private key hex
        let key_hex = if self.source.starts_with("0x") {
            self.source.clone()
        } else {
            format!("0x{}", self.source)
        };

        // Call tenzro_importIdentity RPC on the node
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_importIdentity", serde_json::json!([{
            "private_key": key_hex,
            "key_type": self.key_type,
            "display_name": display_name,
            "password": password
        }]))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to import identity: {}", e))?;

        spinner.finish_and_clear();

        // Extract identity from response
        let identity = result.get("identity").cloned().unwrap_or_default();
        let did = identity.get("did").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();

        // Extract wallet from response
        let wallet = result.get("wallet").cloned().unwrap_or_default();
        let wallet_id = wallet.get("wallet_id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let wallet_address = wallet.get("address").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();

        output::print_success("Wallet imported successfully!");
        println!();
        output::print_field("DID", &did);
        output::print_field("Wallet ID", &wallet_id);
        output::print_field("Address", &wallet_address);
        if let Some(threshold) = wallet.get("threshold").and_then(|v| v.as_str()) {
            output::print_field("Threshold", threshold);
        }
        output::print_field("Key Type", &self.key_type);

        // Save to config
        let mut cfg = config::load_config();
        cfg.endpoint = Some(self.rpc.clone());
        cfg.wallet_id = Some(wallet_id);
        cfg.wallet_address = Some(wallet_address);
        cfg.did = Some(did);
        cfg.display_name = Some(display_name);

        config::save_config(&cfg)?;

        println!();
        output::print_success(&format!("Configuration saved to: {}", config::config_path().display()));
        output::print_warning("IMPORTANT: Your wallet key shares are encrypted and stored on the node.");

        Ok(())
    }
}

/// Check wallet balance
#[derive(Debug, Parser)]
pub struct WalletBalanceCmd {
    /// Wallet address (optional, shows all wallets if not specified)
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
        use crate::rpc::{RpcClient, parse_hex_u128, format_tnzo};

        output::print_header("Wallet Balances");

        let spinner = output::create_spinner("Fetching balances...");

        let rpc = RpcClient::new(&self.rpc);

        if let Some(addr) = &self.address {
            // Fetch balance for specific address
            let balance_hex: String = rpc.call("eth_getBalance", serde_json::json!([addr, "latest"])).await?;
            let balance_wei = parse_hex_u128(&balance_hex);

            spinner.finish_and_clear();

            println!();
            output::print_field("Address", &output::format_address(addr));
            println!();

            if self.detailed {
                // Detailed view with all assets
                let headers = vec!["Asset", "Symbol", "Balance", "USD Value"];
                let rows = vec![
                    vec![
                        "Tenzro Network Token".to_string(),
                        "TNZO".to_string(),
                        format_tnzo(balance_wei),
                        "N/A".to_string(),
                    ],
                ];
                output::print_table(&headers, &rows);
            } else {
                // Simple view
                output::print_field("TNZO Balance", &format_tnzo(balance_wei));
            }
        } else {
            // Try the configured wallet address first, then list all accounts
            let cfg = crate::config::load_config();
            if let Some(addr) = cfg.wallet_address {
                let balance_hex: String = rpc.call("eth_getBalance", serde_json::json!([&addr, "latest"])).await?;
                let balance_wei = parse_hex_u128(&balance_hex);

                spinner.finish_and_clear();
                println!();
                output::print_field("Address", &output::format_address(&addr));
                output::print_field("TNZO Balance", &format_tnzo(balance_wei));
            } else {
                // Fetch all accounts and show balances for each
                let accounts: Vec<serde_json::Value> = rpc.call("tenzro_listAccounts", serde_json::json!([]))
                    .await
                    .unwrap_or_default();

                spinner.finish_and_clear();

                if accounts.is_empty() {
                    output::print_info("No wallets found. Create one with: tenzro-cli wallet create");
                } else {
                    let mut headers = vec!["Address", "Balance (TNZO)"];
                    if self.detailed {
                        headers.push("Type");
                    }
                    let mut rows = Vec::new();
                    for account in &accounts {
                        let addr = account.get("address").and_then(|v| v.as_str()).unwrap_or("unknown");
                        let balance = match rpc.call::<String>("eth_getBalance", serde_json::json!([addr, "latest"])).await {
                            Ok(hex) => format_tnzo(parse_hex_u128(&hex)),
                            Err(_) => "N/A".to_string(),
                        };
                        let mut row = vec![
                            output::format_address(addr),
                            balance,
                        ];
                        if self.detailed {
                            row.push(account.get("wallet_type").and_then(|v| v.as_str()).unwrap_or("MPC").to_string());
                        }
                        rows.push(row);
                    }
                    output::print_table(&headers.iter().map(|s| s.to_string()).collect::<Vec<_>>().iter().map(|s| s.as_str()).collect::<Vec<_>>(), &rows);
                }
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

    /// Sender address (if multiple wallets)
    #[arg(long)]
    from: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WalletSendCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Send Transaction");

        // Parse amount
        let amount_float: f64 = self.amount.parse()?;
        let decimals = 18;
        let amount_wei = (amount_float * 10f64.powi(decimals)) as u64;

        // Resolve sender address (from --from or stored config)
        let cfg = crate::config::load_config();
        let from_address = self.from.clone()
            .or_else(|| cfg.wallet_address.clone())
            .ok_or_else(|| anyhow::anyhow!("--from address is required (or run `tenzro-cli wallet import` first)"))?;

        // Authentication is ambient: the node identifies the signing wallet
        // from the OAuth/DPoP bearer token (TENZRO_BEARER_JWT +
        // TENZRO_DPOP_PROOF env vars, forwarded by RpcClient::call). The
        // node enforces that the bearer's authorized wallet matches `from`.

        // Show transaction details
        println!();
        output::print_field("From", &output::format_address(&from_address));
        output::print_field("To", &output::format_address(&self.to));
        output::print_field("Amount", &format!("{} {}", self.amount, self.asset));
        output::print_field("Network Fee", "~0.001 TNZO");
        println!();

        // Confirm with user
        use dialoguer::Confirm;
        let confirmed = Confirm::new()
            .with_prompt("Do you want to send this transaction?")
            .default(false)
            .interact()?;

        if !confirmed {
            output::print_warning("Transaction cancelled");
            return Ok(());
        }

        let spinner = output::create_spinner("Querying nonce and chain ID...");

        let rpc = RpcClient::new(&self.rpc);

        // Query nonce for the sender (eth_getTransactionCount matches the Python skill)
        let nonce_result = rpc.call::<serde_json::Value>(
            "eth_getTransactionCount",
            serde_json::json!([&from_address, "latest"]),
        ).await;
        let nonce: u64 = match nonce_result {
            Ok(val) => u64::from_str_radix(
                val.as_str().unwrap_or("0x0").trim_start_matches("0x"),
                16,
            ).unwrap_or(0),
            Err(_) => 0,
        };

        // Query chain ID
        let chain_id_result = rpc.call::<serde_json::Value>("eth_chainId", serde_json::json!([])).await;
        let chain_id: u64 = match chain_id_result {
            Ok(val) => u64::from_str_radix(
                val.as_str().unwrap_or("0x539").trim_start_matches("0x"),
                16,
            ).unwrap_or(1337),
            Err(_) => 1337,
        };

        spinner.set_message("Signing and submitting transaction...");

        // Atomic sign + submit: the node computes Transaction::hash() with
        // the canonical preimage (including timestamp) and verifies the
        // Ed25519 signature before accepting — see node/src/rpc.rs
        // `handle_sign_and_send_transaction`.
        let result: serde_json::Value = rpc.call(
            "tenzro_signAndSendTransaction",
            serde_json::json!({
                "from": from_address,
                "to": self.to,
                "value": amount_wei,
                "gas_limit": 21000u64,
                "gas_price": 1_000_000_000u64,
                "nonce": nonce,
                "chain_id": chain_id,
            }),
        ).await?;

        let tx_hash = result
            .get("tx_hash")
            .or_else(|| result.get("transaction_hash"))
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>")
            .to_string();

        spinner.set_message("Waiting for confirmation...");

        // Get transaction receipt (best-effort)
        let receipt: serde_json::Value = rpc
            .call("eth_getTransactionReceipt", serde_json::json!([&tx_hash]))
            .await
            .unwrap_or(serde_json::json!({"blockNumber": "0x0"}));

        spinner.finish_and_clear();

        output::print_success("Transaction sent successfully!");
        println!();
        output::print_field("Transaction Hash", &tx_hash);

        if let Some(block_hex) = receipt.get("blockNumber").and_then(|v| v.as_str()) {
            let block_num = crate::rpc::parse_hex_u64(block_hex);
            if block_num > 0 {
                output::print_field("Block", &format!("#{}", block_num));
            }
        }

        Ok(())
    }
}

/// List all wallets
#[derive(Debug, Parser)]
pub struct WalletListCmd {
    /// Show detailed information
    #[arg(long)]
    detailed: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WalletListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Wallets");

        let spinner = output::create_spinner("Loading wallets...");

        let rpc = RpcClient::new(&self.rpc);

        // Fetch accounts from node
        let accounts: Vec<serde_json::Value> = rpc.call("tenzro_listAccounts", serde_json::json!([]))
            .await
            .unwrap_or_default();

        spinner.finish_and_clear();

        if accounts.is_empty() {
            output::print_info("No wallets found. Create one with: tenzro-cli wallet create");
            return Ok(());
        }

        if self.detailed {
            for account in &accounts {
                println!();
                if let Some(v) = account.get("name").and_then(|v| v.as_str()) {
                    output::print_field("Name", v);
                }
                if let Some(v) = account.get("address").and_then(|v| v.as_str()) {
                    output::print_field("Address", v);
                }
                if let Some(v) = account.get("wallet_type").and_then(|v| v.as_str()) {
                    output::print_field("Type", v);
                }
                if let Some(v) = account.get("balance").and_then(|v| v.as_str()) {
                    output::print_field("Balance", v);
                }
            }
            println!();
        } else {
            let headers = vec!["Name", "Address", "Type", "Balance"];
            let mut rows = Vec::new();
            for account in &accounts {
                rows.push(vec![
                    account.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed").to_string(),
                    account.get("address").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                    account.get("wallet_type").and_then(|v| v.as_str()).unwrap_or("MPC 2-of-3").to_string(),
                    account.get("balance").and_then(|v| v.as_str()).unwrap_or("0 TNZO").to_string(),
                ]);
            }
            output::print_table(&headers, &rows);
        }

        println!("Total: {} wallets", accounts.len());

        Ok(())
    }
}

/// Create a new account (keypair) on the node
#[derive(Debug, Parser)]
pub struct WalletCreateAccountCmd {
    /// Key type: ed25519 or secp256k1
    #[arg(long, default_value = "ed25519")]
    key_type: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WalletCreateAccountCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Create Account");
        let spinner = output::create_spinner("Creating account...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_createAccount", serde_json::json!({
            "key_type": self.key_type,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Account created!");
        output::print_field("Address", result.get("address").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Key Type", &self.key_type);

        Ok(())
    }
}

/// Request testnet TNZO from faucet
#[derive(Debug, Parser)]
pub struct WalletFaucetCmd {
    /// Wallet address (hex)
    address: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WalletFaucetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Request Faucet Tokens");
        let spinner = output::create_spinner("Requesting tokens...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_requestFaucet", serde_json::json!({
            "address": self.address,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Tokens received!");
        output::print_field("Address", &self.address);
        output::print_field("Amount", result.get("amount").and_then(|v| v.as_str()).unwrap_or("100 TNZO"));
        if let Some(tx) = result.get("transaction_hash").and_then(|v| v.as_str()) {
            output::print_field("Transaction", tx);
        }

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

        let result: serde_json::Value = rpc.call("tenzro_getTransactionHistory", serde_json::json!({
            "address": self.address,
            "limit": self.limit,
        })).await?;

        spinner.finish_and_clear();

        if let Some(txs) = result.get("transactions").and_then(|v| v.as_array()) {
            if txs.is_empty() {
                output::print_info("No transactions found.");
            } else {
                let headers = vec!["Hash", "From", "To", "Value", "Status"];
                let mut rows = Vec::new();
                for tx in txs {
                    let hash = tx.get("hash").and_then(|v| v.as_str()).unwrap_or("");
                    let hash_short = if hash.len() > 18 { format!("{}...", &hash[..18]) } else { hash.to_string() };
                    rows.push(vec![
                        hash_short,
                        tx.get("from").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        tx.get("to").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        tx.get("value").and_then(|v| v.as_str()).unwrap_or("0").to_string(),
                        tx.get("status").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
                println!("Showing {} of {} transactions", txs.len(), result.get("total").and_then(|v| v.as_u64()).unwrap_or(txs.len() as u64));
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

        let result: serde_json::Value = rpc.call("tenzro_tokenBalance", serde_json::json!({
            "address": self.address,
            "token": self.token,
        })).await?;

        spinner.finish_and_clear();

        output::print_field("Address", &self.address);
        output::print_field("Token", &self.token);
        output::print_field("Balance", result.get("balance").and_then(|v| v.as_str()).unwrap_or("0"));
        if let Some(decimals) = result.get("decimals").and_then(|v| v.as_u64()) {
            output::print_field("Decimals", &decimals.to_string());
        }

        Ok(())
    }
}
