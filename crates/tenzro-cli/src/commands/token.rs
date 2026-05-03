//! Token management commands for the Tenzro CLI
//!
//! Create, query, and manage tokens across VMs on the Tenzro Ledger.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// Token management commands
#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Create a new ERC-20 token via the token factory
    Create(TokenCreateCmd),
    /// Get information about a token
    Info(TokenInfoCmd),
    /// List registered tokens
    List(TokenListCmd),
    /// Get token balance across all VMs
    Balance(TokenBalanceCmd),
    /// Wrap native TNZO to a VM representation
    Wrap(TokenWrapCmd),
    /// Transfer tokens between VMs
    Transfer(TokenTransferCmd),
    /// Swap tokens via DEX
    Swap(TokenSwapCmd),
}

impl TokenCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Create(cmd) => cmd.execute().await,
            Self::Info(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Balance(cmd) => cmd.execute().await,
            Self::Wrap(cmd) => cmd.execute().await,
            Self::Transfer(cmd) => cmd.execute().await,
            Self::Swap(cmd) => cmd.execute().await,
        }
    }
}

/// Create a new ERC-20 token
#[derive(Debug, Parser)]
pub struct TokenCreateCmd {
    /// Token name (e.g. "My Token")
    #[arg(long)]
    name: String,
    /// Token symbol (e.g. "MTK")
    #[arg(long)]
    symbol: String,
    /// Creator address (hex)
    #[arg(long)]
    creator: String,
    /// Initial supply (in smallest units)
    #[arg(long)]
    supply: String,
    /// Token decimals (default: 18)
    #[arg(long, default_value = "18")]
    decimals: u8,
    /// Make token mintable
    #[arg(long)]
    mintable: bool,
    /// Make token burnable
    #[arg(long)]
    burnable: bool,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TokenCreateCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Create Token");
        let spinner = output::create_spinner("Creating token...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_createToken", serde_json::json!({
            "name": self.name,
            "symbol": self.symbol,
            "creator": self.creator,
            "initial_supply": self.supply,
            "decimals": self.decimals,
            "mintable": self.mintable,
            "burnable": self.burnable,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Token created successfully!");
        output::print_field("Token ID", result.get("token_id").and_then(|v| v.as_str()).unwrap_or("unknown"));
        output::print_field("Name", result.get("name").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Symbol", result.get("symbol").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Decimals", &result.get("decimals").and_then(|v| v.as_u64()).unwrap_or(18).to_string());
        output::print_field("Supply", result.get("initial_supply").and_then(|v| v.as_str()).unwrap_or("0"));
        output::print_field("EVM Address", result.get("evm_address").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// Get information about a token
#[derive(Debug, Parser)]
pub struct TokenInfoCmd {
    /// Token symbol (e.g. "TNZO")
    #[arg(long)]
    symbol: Option<String>,
    /// EVM contract address
    #[arg(long)]
    address: Option<String>,
    /// Token ID (hex)
    #[arg(long)]
    id: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TokenInfoCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Token Info");
        let spinner = output::create_spinner("Querying token...");
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::Map::new();
        if let Some(ref s) = self.symbol { params.insert("symbol".into(), serde_json::json!(s)); }
        if let Some(ref a) = self.address { params.insert("evm_address".into(), serde_json::json!(a)); }
        if let Some(ref i) = self.id { params.insert("token_id".into(), serde_json::json!(i)); }

        let result: serde_json::Value = rpc.call("tenzro_getToken", serde_json::Value::Object(params)).await?;

        spinner.finish_and_clear();

        output::print_field("Token ID", result.get("token_id").and_then(|v| v.as_str()).unwrap_or("unknown"));
        output::print_field("Name", result.get("name").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Symbol", result.get("symbol").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Decimals", &result.get("decimals").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
        output::print_field("Total Supply", result.get("total_supply").and_then(|v| v.as_str()).unwrap_or("0"));
        output::print_field("Type", result.get("token_type").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("EVM Address", result.get("evm_address").and_then(|v| v.as_str()).unwrap_or("N/A"));
        output::print_field("SVM Mint", result.get("svm_mint").and_then(|v| v.as_str()).unwrap_or("N/A"));
        output::print_field("Creator", result.get("creator").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// List registered tokens
#[derive(Debug, Parser)]
pub struct TokenListCmd {
    /// Filter by VM type: evm, svm, daml, native
    #[arg(long)]
    vm: Option<String>,
    /// Maximum tokens to list
    #[arg(long, default_value = "50")]
    limit: u32,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TokenListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Registered Tokens");
        let spinner = output::create_spinner("Loading tokens...");
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({ "limit": self.limit });
        if let Some(ref vm) = self.vm {
            params["vm_type"] = serde_json::json!(vm);
        }

        let result: serde_json::Value = rpc.call("tenzro_listTokens", params).await?;

        spinner.finish_and_clear();

        if let Some(tokens) = result.get("tokens").and_then(|v| v.as_array()) {
            if tokens.is_empty() {
                output::print_info("No tokens registered.");
            } else {
                let headers = vec!["Symbol", "Name", "Decimals", "Supply", "EVM Address"];
                let mut rows = Vec::new();
                for t in tokens {
                    rows.push(vec![
                        t.get("symbol").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        t.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        t.get("decimals").and_then(|v| v.as_u64()).map(|v| v.to_string()).unwrap_or_default(),
                        t.get("total_supply").and_then(|v| v.as_str()).unwrap_or("0").to_string(),
                        t.get("evm_address").and_then(|v| v.as_str()).unwrap_or("N/A").to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
            }
        }

        Ok(())
    }
}

/// Get token balance across all VMs
#[derive(Debug, Parser)]
pub struct TokenBalanceCmd {
    /// Address to query (hex)
    address: String,
    /// Token symbol (default: TNZO)
    #[arg(long, default_value = "TNZO")]
    token: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TokenBalanceCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Token Balance (Cross-VM)");
        let spinner = output::create_spinner("Querying balances...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_getTokenBalance", serde_json::json!({
            "address": self.address,
            "token": self.token,
        })).await?;

        spinner.finish_and_clear();

        output::print_field("Address", &self.address);

        if let Some(native) = result.get("native") {
            output::print_field("Native (18 dec)", native.get("display").and_then(|v| v.as_str()).unwrap_or("0"));
        }
        if let Some(evm) = result.get("evm_wtnzo") {
            output::print_field("EVM wTNZO (18 dec)", evm.get("balance").and_then(|v| v.as_str()).unwrap_or("0"));
        }
        if let Some(svm) = result.get("svm_wtnzo") {
            output::print_field("SVM wTNZO (9 dec)", svm.get("balance").and_then(|v| v.as_str()).unwrap_or("0"));
        }
        if let Some(daml) = result.get("daml_holding") {
            output::print_field("DAML Holding", daml.get("amount").and_then(|v| v.as_str()).unwrap_or("0"));
        }

        Ok(())
    }
}

/// Wrap native TNZO to a VM representation
#[derive(Debug, Parser)]
pub struct TokenWrapCmd {
    /// Address (hex)
    #[arg(long)]
    address: String,
    /// Amount in native units
    #[arg(long)]
    amount: String,
    /// Target VM: evm, svm, or daml
    #[arg(long)]
    vm: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TokenWrapCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Wrap TNZO");
        let spinner = output::create_spinner("Wrapping...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_wrapTnzo", serde_json::json!({
            "address": self.address,
            "amount": self.amount,
            "to_vm": self.vm,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("TNZO wrapped successfully!");
        output::print_field("Target VM", result.get("target_vm").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Representation", result.get("representation").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or(""));
        if let Some(note) = result.get("note").and_then(|v| v.as_str()) {
            output::print_info(note);
        }

        Ok(())
    }
}

/// Transfer tokens between VMs (cross-VM transfer)
#[derive(Debug, Parser)]
pub struct TokenTransferCmd {
    /// Token symbol (e.g. "TNZO")
    #[arg(long, default_value = "TNZO")]
    token: String,
    /// Amount in native units
    #[arg(long)]
    amount: String,
    /// Source VM
    #[arg(long)]
    from_vm: String,
    /// Destination VM
    #[arg(long)]
    to_vm: String,
    /// Source address (hex)
    #[arg(long)]
    from: String,
    /// Destination address (hex)
    #[arg(long)]
    to: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TokenTransferCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Cross-VM Token Transfer");
        let spinner = output::create_spinner("Transferring...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_crossVmTransfer", serde_json::json!({
            "token": self.token,
            "amount": self.amount,
            "from_vm": self.from_vm,
            "to_vm": self.to_vm,
            "from_address": self.from,
            "to_address": self.to,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Transfer completed!");
        output::print_field("Token", result.get("token").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Amount", result.get("amount").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("From VM", result.get("from_vm").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("To VM", result.get("to_vm").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or(""));

        Ok(())
    }
}

/// Swap tokens via DEX
#[derive(Debug, Parser)]
pub struct TokenSwapCmd {
    /// Token to sell (symbol)
    #[arg(long)]
    from_token: String,
    /// Token to buy (symbol)
    #[arg(long)]
    to_token: String,
    /// Amount to swap
    #[arg(long)]
    amount: String,
    /// Sender address (hex)
    #[arg(long)]
    sender: String,
    /// Slippage tolerance (percentage, e.g. "0.5")
    #[arg(long, default_value = "0.5")]
    slippage: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TokenSwapCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Token Swap");
        let spinner = output::create_spinner("Executing swap...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_swapToken", serde_json::json!({
            "from_token": self.from_token,
            "to_token": self.to_token,
            "amount": self.amount,
            "sender": self.sender,
            "slippage": self.slippage,
        })).await?;
        spinner.finish_and_clear();
        output::print_success("Swap executed!");
        output::print_field("From", &format!("{} {}", self.amount, self.from_token));
        output::print_field("To", &format!("{} {}", result.get("received_amount").and_then(|v| v.as_str()).unwrap_or("?"), self.to_token));
        if let Some(v) = result.get("tx_hash").and_then(|v| v.as_str()) { output::print_field("Tx Hash", v); }
        Ok(())
    }
}
